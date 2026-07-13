mod applications;
mod cedar;
mod organizations;
mod users;

use std::sync::Arc;

use axum::{
    Json, Router,
    extract::State,
    http::{HeaderMap, HeaderValue, StatusCode, header},
    response::{IntoResponse, Response},
    routing::{get, post, put},
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use sqlx::{FromRow, PgPool};
use time::{Duration, OffsetDateTime};
use tower_http::{
    request_id::{MakeRequestUuid, PropagateRequestIdLayer, SetRequestIdLayer},
    trace::TraceLayer,
};
use uuid::Uuid;

use crate::{
    identity::password,
    infra::config::Config,
    session::{cookie, service},
};

pub(crate) struct AppState {
    pub(crate) pool: PgPool,
    pub(crate) config: Config,
}

pub(crate) fn router(state: Arc<AppState>) -> Router {
    let request_id_header = header::HeaderName::from_static("x-request-id");
    Router::new()
        .route("/health", get(health))
        .route("/api/v1/session", post(login).delete(logout))
        .route("/api/v1/me", get(me))
        .route("/api/v1/me/password", put(change_password))
        .merge(users::routes())
        .merge(organizations::routes())
        .merge(applications::routes())
        .merge(cedar::routes())
        .with_state(state)
        .layer(TraceLayer::new_for_http())
        .layer(PropagateRequestIdLayer::new(request_id_header.clone()))
        .layer(SetRequestIdLayer::new(request_id_header, MakeRequestUuid))
}

async fn health() -> Json<Value> {
    Json(json!({ "status": "ok" }))
}

#[derive(Debug)]
pub(crate) struct ApiError {
    status: StatusCode,
    code: &'static str,
    detail: String,
    errors: Option<Value>,
}

impl ApiError {
    pub(crate) fn new(status: StatusCode, code: &'static str, detail: impl Into<String>) -> Self {
        Self {
            status,
            code,
            detail: detail.into(),
            errors: None,
        }
    }

    pub(crate) fn bad_request(detail: impl Into<String>) -> Self {
        Self::new(StatusCode::BAD_REQUEST, "invalid_request", detail)
    }

    pub(crate) fn forbidden() -> Self {
        Self::new(
            StatusCode::FORBIDDEN,
            "forbidden",
            "You do not have permission to perform this action",
        )
    }

    pub(crate) fn not_found(resource: &'static str) -> Self {
        Self::new(
            StatusCode::NOT_FOUND,
            "not_found",
            format!("{resource} was not found"),
        )
    }

    pub(crate) fn conflict(code: &'static str, detail: impl Into<String>) -> Self {
        Self::new(StatusCode::CONFLICT, code, detail)
    }

    pub(crate) fn validation(detail: impl Into<String>, errors: Value) -> Self {
        Self {
            status: StatusCode::UNPROCESSABLE_ENTITY,
            code: "cedar_validation_failed",
            detail: detail.into(),
            errors: Some(errors),
        }
    }
}

impl From<sqlx::Error> for ApiError {
    fn from(error: sqlx::Error) -> Self {
        tracing::error!(%error, "database operation failed");
        if let Some(database) = error.as_database_error()
            && database.is_unique_violation()
        {
            return Self::conflict(
                "conflict",
                "A resource with the same unique value already exists",
            );
        }
        Self::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            "internal_error",
            "An internal error occurred",
        )
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let title = self.status.canonical_reason().unwrap_or("Error");
        let mut body = json!({
            "title": title,
            "status": self.status.as_u16(),
            "detail": self.detail,
            "code": self.code,
        });
        if let Some(errors) = self.errors {
            body["errors"] = errors;
        }
        (
            self.status,
            [(header::CONTENT_TYPE, "application/problem+json")],
            Json(body),
        )
            .into_response()
    }
}

pub(crate) type Result<T> = std::result::Result<T, ApiError>;

#[derive(Deserialize)]
struct LoginRequest {
    username: String,
    password: String,
}

#[derive(FromRow)]
struct LoginUser {
    id: Uuid,
    password_hash: String,
    status: String,
}

async fn login(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(request): Json<LoginRequest>,
) -> Result<Response> {
    let user = sqlx::query_as::<_, LoginUser>(
        "SELECT u.id, c.password_hash, u.status FROM users u \
         JOIN password_credentials c ON c.user_id = u.id WHERE u.username = $1",
    )
    .bind(request.username.trim())
    .fetch_optional(&state.pool)
    .await?;
    let Some(user) = user else {
        return Err(unauthorized());
    };
    if user.status != "active" || !password::verify(&request.password, &user.password_hash) {
        return Err(unauthorized());
    }

    let session_token = service::random_token();
    let csrf_token = service::random_token();
    let expires_at =
        OffsetDateTime::now_utc() + Duration::seconds(state.config.session_ttl_seconds);
    let user_agent = headers
        .get(header::USER_AGENT)
        .and_then(|value| value.to_str().ok());
    sqlx::query(
        "INSERT INTO sessions (id_hash, csrf_hash, user_id, expires_at, user_agent) \
         VALUES ($1, $2, $3, $4, $5)",
    )
    .bind(service::hash_token(&session_token))
    .bind(service::hash_token(&csrf_token))
    .bind(user.id)
    .bind(expires_at)
    .bind(user_agent)
    .execute(&state.pool)
    .await?;

    let profile = load_user(&state.pool, user.id).await?;
    let mut response = Json(json!({ "user": profile, "csrf_token": csrf_token })).into_response();
    response.headers_mut().insert(
        header::SET_COOKIE,
        HeaderValue::from_str(&cookie::session(
            session_token,
            state.config.cookie_secure,
            state.config.session_ttl_seconds,
        ))
        .map_err(|_| {
            ApiError::new(
                StatusCode::INTERNAL_SERVER_ERROR,
                "internal_error",
                "Could not create session cookie",
            )
        })?,
    );
    Ok(response)
}

fn unauthorized() -> ApiError {
    ApiError::new(
        StatusCode::UNAUTHORIZED,
        "unauthorized",
        "Invalid credentials or expired session",
    )
}

#[derive(Clone, FromRow)]
pub(crate) struct Actor {
    pub(crate) id: Uuid,
    pub(crate) is_system_admin: bool,
    pub(crate) must_change_password: bool,
    csrf_hash: Vec<u8>,
    session_hash: Vec<u8>,
}

pub(crate) async fn actor(
    state: &AppState,
    headers: &HeaderMap,
    mutation: bool,
    allow_password_change: bool,
) -> Result<Actor> {
    let token = cookie_value(headers, cookie::NAME).ok_or_else(unauthorized)?;
    let session_hash = service::hash_token(&token);
    let actor = sqlx::query_as::<_, Actor>(
        "SELECT u.id, u.is_system_admin, u.must_change_password, s.csrf_hash, s.id_hash AS session_hash \
         FROM sessions s JOIN users u ON u.id = s.user_id \
         WHERE s.id_hash = $1 AND s.expires_at > now() AND u.status = 'active'",
    )
    .bind(&session_hash)
    .fetch_optional(&state.pool)
    .await?
    .ok_or_else(unauthorized)?;
    if actor.must_change_password && !allow_password_change {
        return Err(ApiError::new(
            StatusCode::FORBIDDEN,
            "password_change_required",
            "The bootstrap password must be changed before continuing",
        ));
    }
    if mutation {
        let csrf = headers
            .get("x-csrf-token")
            .and_then(|value| value.to_str().ok())
            .ok_or_else(|| {
                ApiError::new(
                    StatusCode::FORBIDDEN,
                    "invalid_csrf_token",
                    "A valid CSRF token is required",
                )
            })?;
        if !service::token_matches(csrf, &actor.csrf_hash) {
            return Err(ApiError::new(
                StatusCode::FORBIDDEN,
                "invalid_csrf_token",
                "A valid CSRF token is required",
            ));
        }
    }
    Ok(actor)
}

fn cookie_value(headers: &HeaderMap, name: &str) -> Option<String> {
    headers
        .get(header::COOKIE)?
        .to_str()
        .ok()?
        .split(';')
        .find_map(|part| {
            let (key, value) = part.trim().split_once('=')?;
            (key == name).then(|| value.to_owned())
        })
}

async fn logout(State(state): State<Arc<AppState>>, headers: HeaderMap) -> Result<Response> {
    let current = actor(&state, &headers, true, true).await?;
    sqlx::query("DELETE FROM sessions WHERE id_hash = $1")
        .bind(current.session_hash)
        .execute(&state.pool)
        .await?;
    let mut response = StatusCode::NO_CONTENT.into_response();
    response.headers_mut().insert(
        header::SET_COOKIE,
        HeaderValue::from_str(&cookie::expired(state.config.cookie_secure)).map_err(|_| {
            ApiError::new(
                StatusCode::INTERNAL_SERVER_ERROR,
                "internal_error",
                "Could not clear session cookie",
            )
        })?,
    );
    Ok(response)
}

async fn me(State(state): State<Arc<AppState>>, headers: HeaderMap) -> Result<Json<UserView>> {
    let current = actor(&state, &headers, false, true).await?;
    Ok(Json(load_user(&state.pool, current.id).await?))
}

#[derive(Deserialize)]
struct ChangePasswordRequest {
    current_password: String,
    new_password: String,
}

async fn change_password(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(request): Json<ChangePasswordRequest>,
) -> Result<Response> {
    let current = actor(&state, &headers, true, true).await?;
    password::validate(&request.new_password).map_err(ApiError::bad_request)?;
    let old_hash: String =
        sqlx::query_scalar("SELECT password_hash FROM password_credentials WHERE user_id = $1")
            .bind(current.id)
            .fetch_one(&state.pool)
            .await?;
    if !password::verify(&request.current_password, &old_hash) {
        return Err(unauthorized());
    }
    let new_hash = password::hash(&request.new_password).map_err(ApiError::bad_request)?;
    let new_session = service::random_token();
    let new_csrf = service::random_token();
    let expires_at =
        OffsetDateTime::now_utc() + Duration::seconds(state.config.session_ttl_seconds);
    let mut tx = state.pool.begin().await?;
    sqlx::query(
        "UPDATE password_credentials SET password_hash = $2, updated_at = now() WHERE user_id = $1",
    )
    .bind(current.id)
    .bind(new_hash)
    .execute(&mut *tx)
    .await?;
    sqlx::query("UPDATE users SET must_change_password = false, updated_at = now() WHERE id = $1")
        .bind(current.id)
        .execute(&mut *tx)
        .await?;
    sqlx::query("DELETE FROM sessions WHERE user_id = $1")
        .bind(current.id)
        .execute(&mut *tx)
        .await?;
    sqlx::query(
        "INSERT INTO sessions (id_hash, csrf_hash, user_id, expires_at) VALUES ($1, $2, $3, $4)",
    )
    .bind(service::hash_token(&new_session))
    .bind(service::hash_token(&new_csrf))
    .bind(current.id)
    .bind(expires_at)
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;
    let mut response = Json(json!({ "csrf_token": new_csrf })).into_response();
    response.headers_mut().insert(
        header::SET_COOKIE,
        HeaderValue::from_str(&cookie::session(
            new_session,
            state.config.cookie_secure,
            state.config.session_ttl_seconds,
        ))
        .map_err(|_| {
            ApiError::new(
                StatusCode::INTERNAL_SERVER_ERROR,
                "internal_error",
                "Could not create session cookie",
            )
        })?,
    );
    Ok(response)
}

#[derive(Debug, Serialize, FromRow)]
pub(crate) struct UserView {
    pub(crate) id: Uuid,
    pub(crate) username: String,
    pub(crate) email: Option<String>,
    pub(crate) display_name: String,
    pub(crate) status: String,
    pub(crate) is_system_admin: bool,
    pub(crate) must_change_password: bool,
    pub(crate) created_at: OffsetDateTime,
    pub(crate) updated_at: OffsetDateTime,
}

pub(crate) async fn load_user(pool: &PgPool, id: Uuid) -> Result<UserView> {
    sqlx::query_as("SELECT id, username, email, display_name, status, is_system_admin, must_change_password, created_at, updated_at FROM users WHERE id = $1")
        .bind(id).fetch_optional(pool).await?.ok_or_else(|| ApiError::not_found("User"))
}

#[derive(Deserialize)]
pub(crate) struct Page {
    page: Option<i64>,
    page_size: Option<i64>,
    q: Option<String>,
}

impl Page {
    pub(crate) fn values(&self) -> Result<(i64, i64, i64)> {
        let page = self.page.unwrap_or(1);
        let size = self.page_size.unwrap_or(20);
        if page < 1 || !(1..=100).contains(&size) {
            return Err(ApiError::bad_request(
                "page must be positive and page_size must be between 1 and 100",
            ));
        }
        Ok((page, size, (page - 1) * size))
    }
    pub(crate) fn query(&self) -> Option<String> {
        self.q.as_ref().map(|q| format!("%{}%", q.trim()))
    }
}

pub(crate) fn page_json<T: Serialize>(
    items: Vec<T>,
    page: i64,
    page_size: i64,
    total: i64,
) -> Json<Value> {
    Json(json!({ "items": items, "page": page, "page_size": page_size, "total": total }))
}

pub(crate) async fn organization_role(
    pool: &PgPool,
    actor: &Actor,
    organization_id: Uuid,
) -> Result<String> {
    if actor.is_system_admin {
        return Ok("system_admin".into());
    }
    sqlx::query_scalar(
        "SELECT role FROM organization_memberships WHERE organization_id = $1 AND user_id = $2",
    )
    .bind(organization_id)
    .bind(actor.id)
    .fetch_optional(pool)
    .await?
    .ok_or_else(ApiError::forbidden)
}

pub(crate) fn require_role(role: &str, allowed: &[&str]) -> Result<()> {
    if allowed.contains(&role) {
        Ok(())
    } else {
        Err(ApiError::forbidden())
    }
}

pub(crate) fn hash_secret(secret: &str) -> Vec<u8> {
    Sha256::digest(secret.as_bytes()).to_vec()
}
