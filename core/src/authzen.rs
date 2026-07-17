use std::{
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::Instant,
};

use async_trait::async_trait;
use authzen_rs::{
    Decision, EvaluationRequest, EvaluationsRequest, EvaluationsResponse,
    server::PolicyDecisionPoint,
};
use axum::{
    Json, Router,
    extract::State,
    http::{HeaderMap, header},
    routing::{get, post},
};
use serde_json::{Map, Value, json};
use uuid::Uuid;

use crate::{
    AppState,
    error::{ApiError, Result},
    policy,
};

pub(crate) fn routes() -> Router<Arc<AppState>> {
    Router::new()
        .route("/.well-known/authzen-configuration", get(metadata))
        .route("/access/v1/evaluation", post(evaluate_one))
        .route("/access/v1/evaluations", post(evaluate_many))
}

async fn metadata(State(state): State<Arc<AppState>>) -> Json<Value> {
    let base = state.config.server.public_url.trim_end_matches('/');
    Json(
        json!({ "policy_decision_point": base, "access_evaluation_endpoint": format!("{base}/access/v1/evaluation"), "access_evaluations_endpoint": format!("{base}/access/v1/evaluations") }),
    )
}

#[derive(Clone, sqlx::FromRow)]
struct Caller {
    service_account_id: Uuid,
    application_id: Uuid,
    organization_id: Uuid,
}

#[derive(Clone)]
struct CrabouncerPdp {
    state: Arc<AppState>,
    caller: Caller,
    base_request_id: String,
    next_index: Option<Arc<AtomicUsize>>,
}

impl CrabouncerPdp {
    fn single(state: Arc<AppState>, caller: Caller, request_id: String) -> Self {
        Self {
            state,
            caller,
            base_request_id: request_id,
            next_index: None,
        }
    }

    fn batch(state: Arc<AppState>, caller: Caller, request_id: String) -> Self {
        Self {
            state,
            caller,
            base_request_id: request_id,
            next_index: Some(Arc::new(AtomicUsize::new(0))),
        }
    }

    fn request_id(&self) -> String {
        match &self.next_index {
            Some(index) => format!(
                "{}:{}",
                self.base_request_id,
                index.fetch_add(1, Ordering::Relaxed)
            ),
            None => self.base_request_id.clone(),
        }
    }
}

#[async_trait]
impl PolicyDecisionPoint for CrabouncerPdp {
    type Error = ApiError;

    async fn evaluate(&self, request: EvaluationRequest) -> Result<Decision> {
        let request_id = self.request_id();
        run_evaluation(&self.state, &self.caller, &request_id, request)
            .await
            .inspect_err(|error| {
                tracing::error!(%error, %request_id, "AuthZEN evaluation failed");
            })
    }
}

async fn caller(state: &AppState, headers: &HeaderMap) -> Result<Caller> {
    let token = headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .ok_or_else(ApiError::unauthorized)?;
    let claims = state
        .keys
        .verify(token, &state.config.tokens.issuer, "authzen")?;
    if claims.kind != "service"
        || claims.token_use != "access"
        || !claims
            .scope
            .split_whitespace()
            .any(|v| v == "authzen:evaluate")
    {
        return Err(ApiError::forbidden());
    }
    let account_id = claims
        .service_account_id
        .as_deref()
        .and_then(|v| Uuid::parse_str(v).ok())
        .ok_or_else(ApiError::unauthorized)?;
    let application_id = claims
        .application_id
        .as_deref()
        .and_then(|v| Uuid::parse_str(v).ok())
        .ok_or_else(ApiError::unauthorized)?;
    let row = sqlx::query_as::<_, Caller>("SELECT s.id AS service_account_id, a.id AS application_id, a.organization_id FROM service_accounts s JOIN applications a ON a.id = s.application_id JOIN organizations o ON o.id = a.organization_id WHERE s.id = $1 AND a.id = $2 AND s.enabled AND a.enabled AND o.status = 'active'")
        .bind(account_id).bind(application_id).fetch_optional(&state.pool).await?.ok_or_else(ApiError::unauthorized)?;
    if claims.organization_id != row.organization_id.to_string() {
        return Err(ApiError::unauthorized());
    }
    Ok(row)
}

async fn evaluate_one(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(request): Json<EvaluationRequest>,
) -> Result<Json<Decision>> {
    request
        .validate()
        .map_err(|error| ApiError::bad_request(error.to_string()))?;
    let caller = caller(&state, &headers).await?;
    let request_id = request_id(&headers);
    let pdp = CrabouncerPdp::single(state, caller, request_id);
    Ok(Json(pdp.evaluate(request).await?))
}

async fn evaluate_many(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(batch): Json<EvaluationsRequest>,
) -> Result<Json<EvaluationsResponse>> {
    batch
        .validate()
        .map_err(|error| ApiError::bad_request(error.to_string()))?;
    let caller = caller(&state, &headers).await?;
    let base_request_id = request_id(&headers);
    if batch.evaluations().len() > 100 {
        return Err(ApiError::bad_request("at most 100 evaluations are allowed"));
    }
    let pdp = CrabouncerPdp::batch(state, caller, base_request_id);
    Ok(Json(pdp.evaluations(batch).await?))
}

async fn run_evaluation(
    state: &AppState,
    caller: &Caller,
    request_id: &str,
    request: EvaluationRequest,
) -> Result<Decision> {
    let started = Instant::now();
    let request_subject = request
        .subject()
        .ok_or_else(|| ApiError::bad_request("subject is required"))?;
    let subject = if request_subject.subject_type() == Some("User") {
        request_subject.id().and_then(|id| Uuid::parse_str(id).ok())
    } else {
        None
    };
    let authoritative = if let Some(user_id) = subject {
        sqlx::query_as::<_, (String, String)>("SELECT email, role::text FROM users WHERE id = $1 AND organization_id = $2 AND status = 'active'").bind(user_id).bind(caller.organization_id).fetch_optional(&state.pool).await?.map(|(email, role)| json!({ "email": email, "role": role }))
    } else {
        None
    };
    let evaluation = if authoritative.is_none() {
        json!({ "decision": false, "reason": "subject_not_found", "policies": [], "errors": [] })
    } else {
        let release: Option<(String, Value, Value)> = sqlx::query_as("SELECT r.schema_source, r.policies, r.entities FROM active_policy_releases ar JOIN policy_releases r ON r.id = ar.release_id WHERE ar.application_id = $1").bind(caller.application_id).fetch_optional(&state.pool).await?;
        match release {
            Some((schema, policies, entities)) => policy::evaluate(
                &schema,
                &policies,
                &entities,
                &request,
                caller.organization_id,
                authoritative,
            )?,
            None => {
                json!({ "decision": false, "reason": "no_active_release", "policies": [], "errors": [] })
            }
        }
    };
    let allowed = evaluation["decision"].as_bool().unwrap_or(false);
    let reason = evaluation["reason"]
        .as_str()
        .unwrap_or("no_permit")
        .to_owned();
    let mut logged = serde_json::to_value(&request).unwrap_or(Value::Null);
    redact(&mut logged, &state.config.audit.redacted_fields);
    sqlx::query("INSERT INTO decision_logs (id, organization_id, application_id, service_account_id, request_id, request, decision, reason, diagnostics, duration_us) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)")
        .bind(Uuid::now_v7()).bind(caller.organization_id).bind(caller.application_id).bind(caller.service_account_id).bind(request_id).bind(logged).bind(allowed).bind(&reason).bind(&evaluation).bind(started.elapsed().as_micros() as i64).execute(&state.pool).await?;
    let _ = sqlx::query(
        "DELETE FROM decision_logs WHERE created_at < now() - make_interval(days => $1)",
    )
    .bind(state.config.audit.decision_retention_days as i32)
    .execute(&state.pool)
    .await;
    let mut context = Map::new();
    context.insert("request_id".into(), Value::String(request_id.into()));
    context.insert("reason".into(), Value::String(reason));
    Ok(Decision::new(allowed).with_context(context))
}

fn request_id(headers: &HeaderMap) -> String {
    headers
        .get("x-request-id")
        .and_then(|v| v.to_str().ok())
        .filter(|v| !v.is_empty())
        .map(str::to_owned)
        .unwrap_or_else(|| Uuid::now_v7().to_string())
}

fn redact(value: &mut Value, fields: &[String]) {
    match value {
        Value::Object(map) => {
            let names = map.keys().cloned().collect::<Vec<_>>();
            for name in names {
                if fields.iter().any(|field| field.eq_ignore_ascii_case(&name)) {
                    map.insert(name, Value::String("[REDACTED]".into()));
                } else if let Some(value) = map.get_mut(&name) {
                    redact(value, fields);
                }
            }
        }
        Value::Array(values) => {
            for value in values {
                redact(value, fields);
            }
        }
        _ => {}
    }
}
