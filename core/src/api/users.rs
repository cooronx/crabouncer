use std::sync::Arc;

use axum::{
    Json, Router,
    extract::{Path, Query, State},
    http::{HeaderMap, StatusCode},
    routing::{get, post},
};
use serde::Deserialize;
use serde_json::Value;
use uuid::Uuid;

use super::{ApiError, AppState, Page, Result, UserView, actor, load_user, page_json};
use crate::identity::password;

pub(super) fn routes() -> Router<Arc<AppState>> {
    Router::new()
        .route("/api/v1/users", post(create).get(list))
        .route("/api/v1/users/{id}", get(get_one).patch(update))
        .route("/api/v1/users/{id}/status", axum::routing::put(set_status))
        .route(
            "/api/v1/users/{id}/password",
            axum::routing::put(reset_password),
        )
}

#[derive(Deserialize)]
struct CreateUser {
    username: String,
    email: Option<String>,
    display_name: String,
    password: String,
}

async fn create(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(body): Json<CreateUser>,
) -> Result<(StatusCode, Json<UserView>)> {
    let current = actor(&state, &headers, true, false).await?;
    if !current.is_system_admin {
        return Err(ApiError::forbidden());
    }
    validate_text("username", &body.username)?;
    validate_text("display_name", &body.display_name)?;
    password::validate(&body.password).map_err(ApiError::bad_request)?;
    let id = Uuid::now_v7();
    let hash = password::hash(&body.password).map_err(ApiError::bad_request)?;
    let mut tx = state.pool.begin().await?;
    let inserted = sqlx::query(
        "INSERT INTO users (id, username, email, display_name) VALUES ($1, $2, $3, $4)",
    )
    .bind(id)
    .bind(body.username.trim())
    .bind(
        body.email
            .as_ref()
            .map(|v| v.trim())
            .filter(|v| !v.is_empty()),
    )
    .bind(body.display_name.trim())
    .execute(&mut *tx)
    .await;
    if let Err(error) = inserted {
        if error
            .as_database_error()
            .is_some_and(|e| e.is_unique_violation())
        {
            return Err(ApiError::conflict(
                "username_already_exists",
                "Username already exists",
            ));
        }
        return Err(error.into());
    }
    sqlx::query("INSERT INTO password_credentials (user_id, password_hash) VALUES ($1, $2)")
        .bind(id)
        .bind(hash)
        .execute(&mut *tx)
        .await?;
    tx.commit().await?;
    Ok((StatusCode::CREATED, Json(load_user(&state.pool, id).await?)))
}

async fn list(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Query(page): Query<Page>,
) -> Result<Json<Value>> {
    let current = actor(&state, &headers, false, false).await?;
    if !current.is_system_admin {
        return Err(ApiError::forbidden());
    }
    let (number, size, offset) = page.values()?;
    let query = page.query();
    let items = sqlx::query_as::<_, UserView>("SELECT id, username, email, display_name, status, is_system_admin, must_change_password, created_at, updated_at FROM users WHERE ($1::text IS NULL OR username ILIKE $1 OR display_name ILIKE $1) ORDER BY created_at DESC, id DESC LIMIT $2 OFFSET $3")
        .bind(&query).bind(size).bind(offset).fetch_all(&state.pool).await?;
    let total: i64 = sqlx::query_scalar("SELECT count(*) FROM users WHERE ($1::text IS NULL OR username ILIKE $1 OR display_name ILIKE $1)")
        .bind(&query).fetch_one(&state.pool).await?;
    Ok(page_json(items, number, size, total))
}

async fn get_one(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
) -> Result<Json<UserView>> {
    let current = actor(&state, &headers, false, false).await?;
    if !current.is_system_admin && current.id != id {
        return Err(ApiError::not_found("User"));
    }
    Ok(Json(load_user(&state.pool, id).await?))
}

#[derive(Deserialize)]
struct UpdateUser {
    username: Option<String>,
    email: Option<String>,
    display_name: Option<String>,
}

async fn update(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
    Json(body): Json<UpdateUser>,
) -> Result<Json<UserView>> {
    let current = actor(&state, &headers, true, false).await?;
    if !current.is_system_admin && current.id != id {
        return Err(ApiError::not_found("User"));
    }
    if let Some(value) = &body.username {
        validate_text("username", value)?;
    }
    if let Some(value) = &body.display_name {
        validate_text("display_name", value)?;
    }
    sqlx::query("UPDATE users SET username = COALESCE($2, username), email = CASE WHEN $3 THEN $4 ELSE email END, display_name = COALESCE($5, display_name), updated_at = now() WHERE id = $1")
        .bind(id).bind(body.username.as_ref().map(|v| v.trim()))
        .bind(body.email.is_some()).bind(body.email.as_ref().map(|v| v.trim()).filter(|v| !v.is_empty()))
        .bind(body.display_name.as_ref().map(|v| v.trim())).execute(&state.pool).await?;
    Ok(Json(load_user(&state.pool, id).await?))
}

#[derive(Deserialize)]
struct StatusRequest {
    status: String,
}

async fn set_status(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
    Json(body): Json<StatusRequest>,
) -> Result<Json<UserView>> {
    let current = actor(&state, &headers, true, false).await?;
    if !current.is_system_admin {
        return Err(ApiError::forbidden());
    }
    if !matches!(body.status.as_str(), "active" | "disabled") {
        return Err(ApiError::bad_request("status must be active or disabled"));
    }
    let target = load_user(&state.pool, id).await?;
    if target.is_system_admin && body.status == "disabled" {
        return Err(ApiError::conflict(
            "system_admin_cannot_be_disabled",
            "System administrator cannot be disabled",
        ));
    }
    if body.status == "disabled" {
        let owned: i64 = sqlx::query_scalar("SELECT count(*) FROM organization_memberships WHERE user_id = $1 AND role = 'owner' AND organization_id NOT IN (SELECT id FROM organizations WHERE is_system)")
            .bind(id).fetch_one(&state.pool).await?;
        if owned > 0 {
            return Err(ApiError::conflict(
                "user_owns_organizations",
                "Transfer owned organizations before disabling this user",
            ));
        }
    }
    let mut tx = state.pool.begin().await?;
    sqlx::query("UPDATE users SET status = $2, updated_at = now() WHERE id = $1")
        .bind(id)
        .bind(&body.status)
        .execute(&mut *tx)
        .await?;
    if body.status == "disabled" {
        sqlx::query("DELETE FROM sessions WHERE user_id = $1")
            .bind(id)
            .execute(&mut *tx)
            .await?;
    }
    tx.commit().await?;
    Ok(Json(load_user(&state.pool, id).await?))
}

#[derive(Deserialize)]
struct PasswordRequest {
    password: String,
}

async fn reset_password(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
    Json(body): Json<PasswordRequest>,
) -> Result<StatusCode> {
    let current = actor(&state, &headers, true, false).await?;
    if !current.is_system_admin {
        return Err(ApiError::forbidden());
    }
    load_user(&state.pool, id).await?;
    let hash = password::hash(&body.password).map_err(ApiError::bad_request)?;
    let mut tx = state.pool.begin().await?;
    sqlx::query(
        "UPDATE password_credentials SET password_hash = $2, updated_at = now() WHERE user_id = $1",
    )
    .bind(id)
    .bind(hash)
    .execute(&mut *tx)
    .await?;
    sqlx::query("DELETE FROM sessions WHERE user_id = $1")
        .bind(id)
        .execute(&mut *tx)
        .await?;
    tx.commit().await?;
    Ok(StatusCode::NO_CONTENT)
}

fn validate_text(field: &str, value: &str) -> Result<()> {
    if value.trim().is_empty() {
        Err(ApiError::bad_request(format!("{field} must not be empty")))
    } else {
        Ok(())
    }
}
