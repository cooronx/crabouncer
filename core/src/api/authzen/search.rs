use std::{collections::HashMap, sync::Arc, time::Instant};

use authzen_rs::{
    Action, ActionSearchRequest, EvaluationRequest, PageRequest, PageResponse, Resource,
    ResourceSearchRequest, SearchResponse, Subject, SubjectSearchRequest,
};
use axum::{Json, extract::State, http::HeaderMap};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use serde::Serialize;
use serde_json::{Map, Value, json};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::{
    AppState,
    db::{AuthorizationIdentity, AuthzenCaller, PolicyRelease, SearchLog, StoredResource},
    error::{ApiError, Result},
    iam, policy,
    security::{self, SearchPageClaims},
};

const DEFAULT_LIMIT: usize = 50;
const MAX_LIMIT: usize = 100;
const SCAN_LIMIT: usize = 1_000;
const PAGE_TTL_SECONDS: i64 = 300;
const LOGGED_RESULT_IDS: usize = 20;

struct PageState {
    release: PolicyRelease,
    iam_ready: bool,
    query_hash: String,
    cursor: String,
    limit: usize,
}

struct SearchExecution<T> {
    response: SearchResponse<T>,
    release_id: Option<Uuid>,
    evaluated_count: usize,
    result_ids: Vec<String>,
}

pub(super) async fn search_subjects(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(request): Json<SubjectSearchRequest>,
) -> Result<Json<SearchResponse<Subject>>> {
    let caller = super::service_caller(&state, &headers, "authzen:evaluate").await?;
    let request_id = super::request_id(&headers);
    let started = Instant::now();
    let mut query = serde_json::to_value(&request).unwrap_or(Value::Null);
    super::redact(&mut query, &state.config.audit.redacted_fields);
    let execution = execute_subject_search(&state, &caller, &request).await;
    record_search(
        &state, &caller, request_id, "subject", query, started, &execution,
    )
    .await?;
    Ok(Json(execution?.response))
}

pub(super) async fn search_resources(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(request): Json<ResourceSearchRequest>,
) -> Result<Json<SearchResponse<Resource>>> {
    let caller = super::service_caller(&state, &headers, "authzen:evaluate").await?;
    let request_id = super::request_id(&headers);
    let started = Instant::now();
    let mut query = serde_json::to_value(&request).unwrap_or(Value::Null);
    super::redact(&mut query, &state.config.audit.redacted_fields);
    let execution = execute_resource_search(&state, &caller, &request).await;
    record_search(
        &state, &caller, request_id, "resource", query, started, &execution,
    )
    .await?;
    Ok(Json(execution?.response))
}

pub(super) async fn search_actions(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(request): Json<ActionSearchRequest>,
) -> Result<Json<SearchResponse<Action>>> {
    let caller = super::service_caller(&state, &headers, "authzen:evaluate").await?;
    let request_id = super::request_id(&headers);
    let started = Instant::now();
    let mut query = serde_json::to_value(&request).unwrap_or(Value::Null);
    super::redact(&mut query, &state.config.audit.redacted_fields);
    let execution = execute_action_search(&state, &caller, &request).await;
    record_search(
        &state, &caller, request_id, "action", query, started, &execution,
    )
    .await?;
    Ok(Json(execution?.response))
}

async fn execute_subject_search(
    state: &AppState,
    caller: &AuthzenCaller,
    request: &SubjectSearchRequest,
) -> Result<SearchExecution<Subject>> {
    request
        .validate()
        .map_err(|error| ApiError::bad_request(error.to_string()))?;
    let query = request
        .subject()
        .ok_or_else(|| ApiError::bad_request("subject is required"))?;
    if query.subject_type() != Some("User") {
        return Err(ApiError::new(
            axum::http::StatusCode::BAD_REQUEST,
            "unsupported_subject_type",
            "subject search currently supports only User",
        ));
    }
    let action = request
        .action()
        .ok_or_else(|| ApiError::bad_request("action is required"))?;
    let resource = request
        .resource()
        .ok_or_else(|| ApiError::bad_request("resource is required"))?;
    let resource_type = resource
        .resource_type()
        .ok_or_else(|| ApiError::bad_request("resource.type is required"))?;
    iam::validate_business_resource_type(resource_type)?;
    let Some(page) = resolve_page(
        state,
        caller,
        "subject",
        request.page(),
        request_hash(request),
    )
    .await?
    else {
        return Ok(empty_execution());
    };
    let cursor = if page.cursor.is_empty() {
        None
    } else {
        Some(
            Uuid::parse_str(&page.cursor)
                .map_err(|_| ApiError::bad_request("search page token has an invalid cursor"))?,
        )
    };
    let candidates = state
        .db
        .active_subjects_after(caller.organization_id, cursor, (SCAN_LIMIT + 1) as i64)
        .await?;
    let context = request.context().cloned().unwrap_or_default();
    let candidate_ids = candidates
        .iter()
        .take(SCAN_LIMIT)
        .map(|candidate| candidate.id)
        .collect::<Vec<_>>();
    let identities = state
        .db
        .authorization_identities(
            caller.application_id,
            caller.organization_id,
            &candidate_ids,
        )
        .await?
        .into_iter()
        .map(|identity| (identity.user_id, identity))
        .collect::<HashMap<_, _>>();
    let mut results = Vec::new();
    let mut result_ids = Vec::new();
    let mut evaluated = 0;
    let mut last_key = page.cursor.clone();

    for candidate in candidates.iter().take(SCAN_LIMIT) {
        evaluated += 1;
        last_key = candidate.id.to_string();
        let Some(identity) = identities.get(&candidate.id) else {
            continue;
        };
        let properties = Map::from_iter([
            ("email".into(), Value::String(identity.email.clone())),
            (
                "role".into(),
                Value::String(identity.organization_role.clone()),
            ),
            (
                "organization_id".into(),
                Value::String(caller.organization_id.to_string()),
            ),
        ]);
        if !properties_match(query.properties(), &properties) {
            continue;
        }
        let mut subject = Subject::new("User", candidate.id.to_string());
        subject.properties_mut().extend(properties.clone());
        let evaluation = EvaluationRequest::new(subject.clone(), action.clone(), resource.clone())
            .with_context(context.clone());
        let projection = iam::project_identity(
            identity,
            caller.organization_id,
            caller.application_id,
            &properties,
            page.iam_ready,
        );
        if is_allowed(
            &page.release,
            &evaluation,
            caller.organization_id,
            projection.entities,
        )? {
            result_ids.push(candidate.id.to_string());
            results.push(subject);
            if results.len() == page.limit {
                break;
            }
        }
    }
    let has_more = evaluated < candidates.len();
    let response = paged_response(
        state, caller, "subject", &page, &last_key, has_more, results,
    )?;
    Ok(SearchExecution {
        response,
        release_id: Some(page.release.id),
        evaluated_count: evaluated,
        result_ids,
    })
}

async fn execute_resource_search(
    state: &AppState,
    caller: &AuthzenCaller,
    request: &ResourceSearchRequest,
) -> Result<SearchExecution<Resource>> {
    request
        .validate()
        .map_err(|error| ApiError::bad_request(error.to_string()))?;
    let query = request
        .resource()
        .ok_or_else(|| ApiError::bad_request("resource is required"))?;
    let resource_type = query
        .resource_type()
        .ok_or_else(|| ApiError::bad_request("resource.type is required"))?;
    iam::validate_business_resource_type(resource_type)?;
    let Some(page) = resolve_page(
        state,
        caller,
        "resource",
        request.page(),
        request_hash(request),
    )
    .await?
    else {
        return Ok(empty_execution());
    };
    let subject = request
        .subject()
        .ok_or_else(|| ApiError::bad_request("subject is required"))?;
    let Some(identity) = authoritative_identity(state, caller, subject).await? else {
        return Ok(SearchExecution {
            response: SearchResponse::new(Vec::new())
                .with_page(PageResponse::new("").with_count(0)),
            release_id: Some(page.release.id),
            evaluated_count: 0,
            result_ids: Vec::new(),
        });
    };
    let action = request
        .action()
        .ok_or_else(|| ApiError::bad_request("action is required"))?;
    let candidates = state
        .db
        .resources_after(
            caller.application_id,
            resource_type,
            &page.cursor,
            (SCAN_LIMIT + 1) as i64,
        )
        .await?;
    let context = request.context().cloned().unwrap_or_default();
    let projection = iam::project_identity(
        &identity,
        caller.organization_id,
        caller.application_id,
        subject.properties(),
        page.iam_ready,
    );
    let mut results = Vec::new();
    let mut result_ids = Vec::new();
    let mut evaluated = 0;
    let mut last_key = page.cursor.clone();

    for candidate in candidates.iter().take(SCAN_LIMIT) {
        evaluated += 1;
        last_key = candidate.resource_id.clone();
        let properties = candidate
            .properties
            .as_object()
            .cloned()
            .unwrap_or_default();
        if !properties_match(query.properties(), &properties) {
            continue;
        }
        let resource = stored_resource(candidate);
        let evaluation = EvaluationRequest::new(subject.clone(), action.clone(), resource.clone())
            .with_context(context.clone());
        if is_allowed(
            &page.release,
            &evaluation,
            caller.organization_id,
            projection.entities.clone(),
        )? {
            result_ids.push(format!(
                "{}::{}",
                candidate.resource_type, candidate.resource_id
            ));
            results.push(resource);
            if results.len() == page.limit {
                break;
            }
        }
    }
    let has_more = evaluated < candidates.len();
    let response = paged_response(
        state, caller, "resource", &page, &last_key, has_more, results,
    )?;
    Ok(SearchExecution {
        response,
        release_id: Some(page.release.id),
        evaluated_count: evaluated,
        result_ids,
    })
}

async fn execute_action_search(
    state: &AppState,
    caller: &AuthzenCaller,
    request: &ActionSearchRequest,
) -> Result<SearchExecution<Action>> {
    request
        .validate()
        .map_err(|error| ApiError::bad_request(error.to_string()))?;
    let resource = request
        .resource()
        .ok_or_else(|| ApiError::bad_request("resource is required"))?;
    let resource_type = resource
        .resource_type()
        .ok_or_else(|| ApiError::bad_request("resource.type is required"))?;
    iam::validate_business_resource_type(resource_type)?;
    let Some(page) = resolve_page(
        state,
        caller,
        "action",
        request.page(),
        request_hash(request),
    )
    .await?
    else {
        return Ok(empty_execution());
    };
    let subject = request
        .subject()
        .ok_or_else(|| ApiError::bad_request("subject is required"))?;
    let Some(identity) = authoritative_identity(state, caller, subject).await? else {
        return Ok(SearchExecution {
            response: SearchResponse::new(Vec::new())
                .with_page(PageResponse::new("").with_count(0)),
            release_id: Some(page.release.id),
            evaluated_count: 0,
            result_ids: Vec::new(),
        });
    };
    let subject_type = subject
        .subject_type()
        .ok_or_else(|| ApiError::bad_request("subject.type is required"))?;
    let actions =
        policy::applicable_actions(&page.release.schema_source, subject_type, resource_type)?
            .into_iter()
            .filter(|action| action > &page.cursor)
            .take(SCAN_LIMIT + 1)
            .collect::<Vec<_>>();
    let context = request.context().cloned().unwrap_or_default();
    let projection = iam::project_identity(
        &identity,
        caller.organization_id,
        caller.application_id,
        subject.properties(),
        page.iam_ready,
    );
    let mut results = Vec::new();
    let mut result_ids = Vec::new();
    let mut evaluated = 0;
    let mut last_key = page.cursor.clone();

    for name in actions.iter().take(SCAN_LIMIT) {
        evaluated += 1;
        last_key = name.clone();
        let action = Action::new(name);
        let evaluation = EvaluationRequest::new(subject.clone(), action.clone(), resource.clone())
            .with_context(context.clone());
        if is_allowed(
            &page.release,
            &evaluation,
            caller.organization_id,
            projection.entities.clone(),
        )? {
            result_ids.push(name.clone());
            results.push(action);
            if results.len() == page.limit {
                break;
            }
        }
    }
    let has_more = evaluated < actions.len();
    let response = paged_response(state, caller, "action", &page, &last_key, has_more, results)?;
    Ok(SearchExecution {
        response,
        release_id: Some(page.release.id),
        evaluated_count: evaluated,
        result_ids,
    })
}

async fn resolve_page(
    state: &AppState,
    caller: &AuthzenCaller,
    search_kind: &str,
    request: Option<&PageRequest>,
    query_hash: String,
) -> Result<Option<PageState>> {
    let limit = request
        .and_then(PageRequest::limit)
        .unwrap_or(DEFAULT_LIMIT as u64);
    if limit == 0 || limit > MAX_LIMIT as u64 {
        return Err(ApiError::bad_request(
            "page.limit must be between 1 and 100",
        ));
    }
    let token = request
        .and_then(PageRequest::token)
        .filter(|token| !token.is_empty());
    if let Some(token) = token {
        let claims = state
            .keys
            .verify_search_page(token, &state.config.tokens.issuer)?;
        if claims.version != 1
            || claims.search_kind != search_kind
            || claims.application_id != caller.application_id.to_string()
            || claims.query_hash != query_hash
        {
            return Err(ApiError::bad_request(
                "search page token does not match this query",
            ));
        }
        let release_id = Uuid::parse_str(&claims.release_id)
            .map_err(|_| ApiError::bad_request("search page token has an invalid release"))?;
        let release = state
            .db
            .policy_release(caller.application_id, release_id)
            .await?
            .ok_or_else(|| ApiError::bad_request("search page token release was not found"))?;
        let iam_ready = iam::schema_is_iam_ready(&release.schema_source);
        return Ok(Some(PageState {
            release,
            iam_ready,
            query_hash,
            cursor: claims.last_key,
            limit: limit as usize,
        }));
    }
    Ok(state
        .db
        .active_policy_release(caller.application_id)
        .await?
        .map(|release| {
            let iam_ready = iam::schema_is_iam_ready(&release.schema_source);
            PageState {
                release,
                iam_ready,
                query_hash,
                cursor: String::new(),
                limit: limit as usize,
            }
        }))
}

fn paged_response<T>(
    state: &AppState,
    caller: &AuthzenCaller,
    search_kind: &str,
    page: &PageState,
    last_key: &str,
    has_more: bool,
    results: Vec<T>,
) -> Result<SearchResponse<T>> {
    let next_token = if has_more {
        let now = security::now();
        state.keys.issue_search_page(
            &state.config.tokens.key_id,
            &SearchPageClaims {
                iss: state.config.tokens.issuer.clone(),
                aud: "authzen-search".into(),
                exp: (now + PAGE_TTL_SECONDS) as usize,
                iat: now as usize,
                version: 1,
                search_kind: search_kind.into(),
                application_id: caller.application_id.to_string(),
                query_hash: page.query_hash.clone(),
                release_id: page.release.id.to_string(),
                last_key: last_key.into(),
            },
        )?
    } else {
        String::new()
    };
    let count = results.len() as u64;
    Ok(SearchResponse::new(results).with_page(PageResponse::new(next_token).with_count(count)))
}

fn request_hash(request: &impl Serialize) -> String {
    let mut value = serde_json::to_value(request).unwrap_or(Value::Null);
    let empty_page = if let Some(page) = value.get_mut("page").and_then(Value::as_object_mut) {
        page.remove("token");
        page.is_empty()
    } else {
        false
    };
    if empty_page {
        value.as_object_mut().map(|request| request.remove("page"));
    }
    URL_SAFE_NO_PAD.encode(Sha256::digest(
        serde_json::to_vec(&value).unwrap_or_default(),
    ))
}

fn properties_match(query: &Map<String, Value>, candidate: &Map<String, Value>) -> bool {
    query
        .iter()
        .all(|(name, value)| candidate.get(name) == Some(value))
}

fn stored_resource(candidate: &StoredResource) -> Resource {
    let mut resource = Resource::new(&candidate.resource_type, &candidate.resource_id);
    if let Some(properties) = candidate.properties.as_object() {
        resource.properties_mut().extend(properties.clone());
    }
    resource
}

async fn authoritative_identity(
    state: &AppState,
    caller: &AuthzenCaller,
    subject: &Subject,
) -> Result<Option<AuthorizationIdentity>> {
    if subject.subject_type() != Some("User") {
        return Ok(None);
    }
    let Some(user_id) = subject.id().and_then(|id| Uuid::parse_str(id).ok()) else {
        return Ok(None);
    };
    Ok(state
        .db
        .authorization_identity(caller.application_id, caller.organization_id, user_id)
        .await?)
}

fn is_allowed(
    release: &PolicyRelease,
    request: &EvaluationRequest,
    organization_id: Uuid,
    authoritative_entities: Vec<Value>,
) -> Result<bool> {
    Ok(policy::evaluate(
        &release.schema_source,
        &release.policies,
        &release.entities,
        request,
        organization_id,
        Some(authoritative_entities),
    )?["decision"]
        .as_bool()
        .unwrap_or(false))
}

fn empty_execution<T>() -> SearchExecution<T> {
    SearchExecution {
        response: SearchResponse::new(Vec::new()).with_page(PageResponse::new("").with_count(0)),
        release_id: None,
        evaluated_count: 0,
        result_ids: Vec::new(),
    }
}

async fn record_search<T>(
    state: &AppState,
    caller: &AuthzenCaller,
    request_id: String,
    search_kind: &'static str,
    query: Value,
    started: Instant,
    execution: &Result<SearchExecution<T>>,
) -> Result<()> {
    let (release_id, evaluated_count, result_count, result_ids, outcome, error) = match execution {
        Ok(execution) => (
            execution.release_id,
            execution.evaluated_count,
            execution.response.results().len(),
            execution
                .result_ids
                .iter()
                .take(LOGGED_RESULT_IDS)
                .cloned()
                .collect::<Vec<_>>(),
            "success",
            None,
        ),
        Err(error) => (None, 0, 0, Vec::new(), "error", Some(error.to_string())),
    };
    state
        .db
        .record_search(SearchLog {
            organization_id: caller.organization_id,
            application_id: caller.application_id,
            service_account_id: caller.service_account_id,
            request_id,
            search_kind,
            query,
            release_id,
            evaluated_count,
            result_count,
            result_ids: json!(result_ids),
            duration_us: started.elapsed().as_micros() as i64,
            outcome,
            error,
            retention_days: state.config.audit.decision_retention_days,
        })
        .await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn page_hash_ignores_only_the_continuation_token() {
        let first = ResourceSearchRequest::new(
            Subject::new("User", "alice"),
            Action::new("read"),
            Resource::query("Document"),
        )
        .with_page(PageRequest::new().with_limit(10));
        let next = first
            .clone()
            .with_page(PageRequest::new().with_limit(10).with_token("token"));
        let changed = first.clone().with_page(PageRequest::new().with_limit(20));
        assert_eq!(request_hash(&first), request_hash(&next));
        assert_ne!(request_hash(&first), request_hash(&changed));

        let default_first = ResourceSearchRequest::new(
            Subject::new("User", "alice"),
            Action::new("read"),
            Resource::query("Document"),
        );
        let default_next = default_first
            .clone()
            .with_page(PageRequest::new().with_token("token"));
        assert_eq!(request_hash(&default_first), request_hash(&default_next));
    }

    #[test]
    fn property_filters_are_exact_subsets() {
        let query = Map::from_iter([("status".into(), json!("active"))]);
        let candidate = Map::from_iter([
            ("status".into(), json!("active")),
            ("title".into(), json!("Roadmap")),
        ]);
        assert!(properties_match(&query, &candidate));
    }
}
