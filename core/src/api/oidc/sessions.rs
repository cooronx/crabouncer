use std::sync::Arc;

use axum::{
    Json,
    extract::State,
    http::{HeaderMap, StatusCode, header},
    response::IntoResponse,
};
use cookie::{Cookie, SameSite};
use serde_json::{Value, json};
use uuid::Uuid;

use crate::{
    AppState,
    db::UserProfile,
    error::{ApiError, Result},
    security,
};

pub(super) async fn userinfo(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> Result<Json<Value>> {
    let token = bearer(&headers)?;
    let claims = state
        .keys
        .verify_issuer(token, &state.config.tokens.issuer)?;
    if claims.kind != "user" || claims.token_use != "access" {
        return Err(ApiError::forbidden());
    }
    let id = Uuid::parse_str(&claims.sub).map_err(|_| ApiError::unauthorized())?;
    let row: UserProfile = state
        .db
        .active_user_profile(id)
        .await?
        .ok_or_else(ApiError::unauthorized)?;
    Ok(Json(
        json!({ "sub": claims.sub, "organization_id": claims.organization_id, "email": row.email, "name": row.display_name }),
    ))
}

pub(super) async fn logout(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> impl IntoResponse {
    if let Some(raw) = cookie_value(&headers, "crabouncer_session") {
        let _ = state.db.delete_session(security::token_hash(&raw)).await;
    }
    let cookie = Cookie::build(("crabouncer_session", ""))
        .path("/")
        .http_only(true)
        .secure(state.config.server.cookie_secure)
        .same_site(SameSite::Lax)
        .max_age(cookie::time::Duration::ZERO)
        .build();
    (
        [(header::SET_COOKIE, cookie.to_string())],
        StatusCode::NO_CONTENT,
    )
}

fn bearer(headers: &HeaderMap) -> Result<&str> {
    headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .ok_or_else(ApiError::unauthorized)
}

fn cookie_value(headers: &HeaderMap, name: &str) -> Option<String> {
    headers
        .get(header::COOKIE)?
        .to_str()
        .ok()?
        .split(';')
        .filter_map(|part| Cookie::parse(part.trim()).ok())
        .find(|cookie| cookie.name() == name)
        .map(|cookie| cookie.value().to_owned())
}
