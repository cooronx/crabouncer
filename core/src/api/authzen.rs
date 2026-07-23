mod evaluations;
mod metadata;

use std::sync::Arc;

use axum::{
    Router,
    http::{HeaderMap, header},
    routing::{get, post},
};
use uuid::Uuid;

use crate::{
    AppState,
    db::AuthzenCaller,
    error::{ApiError, Result},
};

pub(super) fn routes() -> Router<Arc<AppState>> {
    Router::new()
        .route(
            "/.well-known/authzen-configuration",
            get(metadata::metadata),
        )
        .route("/access/v1/evaluation", post(evaluations::evaluate_one))
        .route("/access/v1/evaluations", post(evaluations::evaluate_many))
}

pub(crate) async fn service_caller(
    state: &AppState,
    headers: &HeaderMap,
    required_scope: &str,
) -> Result<AuthzenCaller> {
    let token = headers
        .get(header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("Bearer "))
        .ok_or_else(ApiError::unauthorized)?;
    let claims = state
        .keys
        .verify(token, &state.config.tokens.issuer, "authzen")?;
    if claims.kind != "service"
        || claims.token_use != "access"
        || !claims
            .scope
            .split_whitespace()
            .any(|scope| scope == required_scope)
    {
        return Err(ApiError::forbidden());
    }
    let account_id = claims
        .service_account_id
        .as_deref()
        .and_then(|value| Uuid::parse_str(value).ok())
        .ok_or_else(ApiError::unauthorized)?;
    let application_id = claims
        .application_id
        .as_deref()
        .and_then(|value| Uuid::parse_str(value).ok())
        .ok_or_else(ApiError::unauthorized)?;
    let caller = state
        .db
        .authzen_caller(account_id, application_id)
        .await?
        .ok_or_else(ApiError::unauthorized)?;
    if claims.organization_id != caller.organization_id.to_string() {
        return Err(ApiError::unauthorized());
    }
    Ok(caller)
}

pub(crate) fn request_id(headers: &HeaderMap) -> String {
    headers
        .get("x-request-id")
        .and_then(|value| value.to_str().ok())
        .filter(|value| !value.is_empty())
        .map(str::to_owned)
        .unwrap_or_else(|| Uuid::now_v7().to_string())
}
