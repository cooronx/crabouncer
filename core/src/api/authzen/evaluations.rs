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
use axum::{Json, extract::State, http::HeaderMap};
use serde_json::{Map, Value, json};
use uuid::Uuid;

use crate::{
    AppState,
    db::{AuthzenCaller, DecisionLog, PolicyRelease},
    error::{ApiError, Result},
    iam, policy,
};

#[derive(Clone)]
struct CrabouncerPdp {
    state: Arc<AppState>,
    caller: AuthzenCaller,
    base_request_id: String,
    next_index: Option<Arc<AtomicUsize>>,
}

impl CrabouncerPdp {
    fn single(state: Arc<AppState>, caller: AuthzenCaller, request_id: String) -> Self {
        Self {
            state,
            caller,
            base_request_id: request_id,
            next_index: None,
        }
    }

    fn batch(state: Arc<AppState>, caller: AuthzenCaller, request_id: String) -> Self {
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

pub(super) async fn evaluate_one(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(request): Json<EvaluationRequest>,
) -> Result<Json<Decision>> {
    request
        .validate()
        .map_err(|error| ApiError::bad_request(error.to_string()))?;
    let caller = super::service_caller(&state, &headers, "authzen:evaluate").await?;
    let request_id = super::request_id(&headers);
    let pdp = CrabouncerPdp::single(state, caller, request_id);
    Ok(Json(pdp.evaluate(request).await?))
}

pub(super) async fn evaluate_many(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(batch): Json<EvaluationsRequest>,
) -> Result<Json<EvaluationsResponse>> {
    batch
        .validate()
        .map_err(|error| ApiError::bad_request(error.to_string()))?;
    let caller = super::service_caller(&state, &headers, "authzen:evaluate").await?;
    let base_request_id = super::request_id(&headers);
    if batch.evaluations().len() > 100 {
        return Err(ApiError::bad_request("at most 100 evaluations are allowed"));
    }
    let pdp = CrabouncerPdp::batch(state, caller, base_request_id);
    Ok(Json(pdp.evaluations(batch).await?))
}

async fn run_evaluation(
    state: &AppState,
    caller: &AuthzenCaller,
    request_id: &str,
    request: EvaluationRequest,
) -> Result<Decision> {
    let started = Instant::now();
    let request_subject = request
        .subject()
        .ok_or_else(|| ApiError::bad_request("subject is required"))?;
    let resource_type = request
        .resource()
        .and_then(authzen_rs::Resource::resource_type)
        .ok_or_else(|| ApiError::bad_request("resource.type is required"))?;
    iam::validate_business_resource_type(resource_type)?;
    let subject = if request_subject.subject_type() == Some("User") {
        request_subject.id().and_then(|id| Uuid::parse_str(id).ok())
    } else {
        None
    };
    let identity = if let Some(user_id) = subject {
        state
            .db
            .authorization_identity(caller.application_id, caller.organization_id, user_id)
            .await?
    } else {
        None
    };
    let mut iam_snapshot = iam::IamSnapshot::default();
    let mut evaluation = if let Some(identity) = identity {
        let release: Option<PolicyRelease> = state
            .db
            .active_policy_release(caller.application_id)
            .await?;
        match release {
            Some(release) => {
                let projection = iam::project_identity(
                    &identity,
                    caller.organization_id,
                    caller.application_id,
                    request_subject.properties(),
                    iam::schema_is_iam_ready(&release.schema_source),
                );
                iam_snapshot = projection.snapshot;
                policy::evaluate(
                    &release.schema_source,
                    &release.policies,
                    &release.entities,
                    &request,
                    caller.organization_id,
                    Some(policy::SubjectAuthority::EntityGraph(projection.entities)),
                )?
            }
            None => {
                json!({ "decision": false, "reason": "no_active_release", "policies": [], "errors": [] })
            }
        }
    } else {
        json!({ "decision": false, "reason": "subject_not_found", "policies": [], "errors": [] })
    };
    if let Some(diagnostics) = evaluation.as_object_mut() {
        diagnostics.insert("iam".into(), json!(iam_snapshot));
    }
    let allowed = evaluation["decision"].as_bool().unwrap_or(false);
    let reason = evaluation["reason"]
        .as_str()
        .unwrap_or("no_permit")
        .to_owned();
    let mut logged = serde_json::to_value(&request).unwrap_or(Value::Null);
    super::redact(&mut logged, &state.config.audit.redacted_fields);
    state
        .db
        .record_decision(DecisionLog {
            organization_id: caller.organization_id,
            application_id: caller.application_id,
            service_account_id: caller.service_account_id,
            request_id: request_id.into(),
            request: logged,
            decision: allowed,
            reason: reason.clone(),
            diagnostics: evaluation,
            duration_us: started.elapsed().as_micros() as i64,
            retention_days: state.config.audit.decision_retention_days,
        })
        .await?;
    let mut context = Map::new();
    context.insert("request_id".into(), Value::String(request_id.into()));
    context.insert("reason".into(), Value::String(reason));
    Ok(Decision::new(allowed).with_context(context))
}
