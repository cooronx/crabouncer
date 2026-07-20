use std::sync::Arc;

use axum::{
    Extension, Json,
    extract::{Path, State},
    http::{HeaderMap, StatusCode, header},
};
use cookie::{Cookie, SameSite};
use serde::Deserialize;
use serde_json::json;
use time::{Duration, OffsetDateTime};

use crate::{
    AppState,
    db::{Actor, LoginUser, NewSession},
    error::{ApiError, Result},
    security,
};

use super::access::SESSION_COOKIE;

#[derive(Deserialize)]
pub(super) struct Login {
    email: String,
    password: String,
}

pub(super) async fn login(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(body): Json<Login>,
) -> Result<impl axum::response::IntoResponse> {
    let email = body.email.trim().to_lowercase();
    let user: Option<LoginUser> = state.db.login_user(&email).await?;
    let Some(user) = user else {
        return Err(ApiError::unauthorized());
    };
    if !security::password_matches(&body.password, &user.password_hash) {
        return Err(ApiError::unauthorized());
    }
    let session = security::random_token();
    let csrf = security::random_token();
    let expires =
        OffsetDateTime::now_utc() + Duration::seconds(state.config.tokens.session_ttl_seconds);
    state
        .db
        .create_session(NewSession {
            token_hash: security::token_hash(&session),
            csrf_hash: security::token_hash(&csrf),
            user_id: user.id,
            expires_at: expires,
            ip: client_ip(&headers).map(str::to_owned),
            user_agent: headers
                .get(header::USER_AGENT)
                .and_then(|value| value.to_str().ok())
                .map(str::to_owned),
        })
        .await?;
    let cookie = Cookie::build((SESSION_COOKIE, session))
        .path("/")
        .http_only(true)
        .secure(state.config.server.cookie_secure)
        .same_site(SameSite::Lax)
        .max_age(cookie::time::Duration::seconds(
            state.config.tokens.session_ttl_seconds,
        ))
        .build();
    Ok((
        [(header::SET_COOKIE, cookie.to_string())],
        Json(json!({ "csrf_token": csrf })),
    ))
}

pub(super) async fn logout(
    State(state): State<Arc<AppState>>,
    Extension(current): Extension<Actor>,
) -> Result<impl axum::response::IntoResponse> {
    state.db.delete_session(current.session_hash).await?;
    let cookie = Cookie::build((SESSION_COOKIE, ""))
        .path("/")
        .http_only(true)
        .secure(state.config.server.cookie_secure)
        .same_site(SameSite::Lax)
        .max_age(cookie::time::Duration::ZERO)
        .build();
    Ok((
        [(header::SET_COOKIE, cookie.to_string())],
        StatusCode::NO_CONTENT,
    ))
}

pub(super) async fn me(Extension(current): Extension<Actor>) -> Json<Actor> {
    Json(current)
}

#[derive(Deserialize)]
pub(super) struct Activate {
    password: String,
}

pub(super) async fn activate(
    State(state): State<Arc<AppState>>,
    Path(token): Path<String>,
    Json(body): Json<Activate>,
) -> Result<StatusCode> {
    let hash = security::password_hash(&body.password).map_err(ApiError::bad_request)?;
    state
        .db
        .activate_user(security::token_hash(&token), hash)
        .await?
        .ok_or_else(|| ApiError::bad_request("activation token is invalid or expired"))?;
    Ok(StatusCode::NO_CONTENT)
}

fn client_ip(headers: &HeaderMap) -> Option<&str> {
    headers
        .get("x-forwarded-for")
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.split(',').next())
        .map(str::trim)
}
