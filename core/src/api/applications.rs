use std::sync::Arc;

use axum::{
    Json, Router,
    extract::{Path, Query, State},
    http::{HeaderMap, StatusCode},
    routing::{get, post, put},
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sqlx::FromRow;
use time::OffsetDateTime;
use url::Url;
use uuid::Uuid;

use super::organizations::ensure_operable;
use super::{
    ApiError, AppState, Page, Result, actor, hash_secret, organization_role, page_json,
    require_role,
};
use crate::session::service;

pub(super) fn routes() -> Router<Arc<AppState>> {
    Router::new()
        .route(
            "/api/v1/organizations/{organization_id}/applications",
            post(create).get(list),
        )
        .route("/api/v1/applications/{id}", get(get_one).patch(update))
        .route("/api/v1/applications/{id}/secret", post(reset_secret))
        .route(
            "/api/v1/applications/{id}/roles",
            post(create_role).get(list_roles),
        )
        .route(
            "/api/v1/applications/{id}/roles/{role_id}",
            get(get_role).patch(update_role).delete(delete_role),
        )
        .route(
            "/api/v1/applications/{id}/roles/{role_id}/users/{user_id}",
            put(assign_role).delete(unassign_role),
        )
        .route(
            "/api/v1/applications/{id}/users/{user_id}/roles",
            get(user_roles),
        )
}

#[derive(Serialize, FromRow)]
pub(crate) struct ApplicationView {
    pub(crate) id: Uuid,
    pub(crate) organization_id: Uuid,
    name: String,
    client_id: String,
    redirect_uris: Value,
    allowed_scopes: Value,
    access_token_ttl: i32,
    enabled: bool,
    created_at: OffsetDateTime,
    updated_at: OffsetDateTime,
}

pub(crate) async fn load_application(state: &AppState, id: Uuid) -> Result<ApplicationView> {
    sqlx::query_as("SELECT id, organization_id, name, client_id, redirect_uris, allowed_scopes, access_token_ttl, enabled, created_at, updated_at FROM applications WHERE id = $1")
        .bind(id).fetch_optional(&state.pool).await?.ok_or_else(|| ApiError::not_found("Application"))
}

async fn authorize_application(
    state: &AppState,
    headers: &HeaderMap,
    id: Uuid,
    mutation: bool,
) -> Result<ApplicationView> {
    let current = actor(state, headers, mutation, false).await?;
    let app = load_application(state, id).await?;
    let role = organization_role(&state.pool, &current, app.organization_id).await?;
    require_role(&role, &["system_admin", "owner", "admin"])?;
    ensure_operable(state, app.organization_id).await?;
    Ok(app)
}

#[derive(Deserialize)]
struct CreateApplication {
    name: String,
    redirect_uris: Vec<String>,
    allowed_scopes: Vec<String>,
    access_token_ttl: Option<i32>,
}

async fn create(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(organization_id): Path<Uuid>,
    Json(body): Json<CreateApplication>,
) -> Result<(StatusCode, Json<Value>)> {
    let current = actor(&state, &headers, true, false).await?;
    let role = organization_role(&state.pool, &current, organization_id).await?;
    require_role(&role, &["system_admin", "owner", "admin"])?;
    ensure_operable(&state, organization_id).await?;
    validate_application(
        &body.name,
        &body.redirect_uris,
        &body.allowed_scopes,
        body.access_token_ttl.unwrap_or(900),
    )?;
    let id = Uuid::now_v7();
    let client_id = service::random_token();
    let secret = service::random_token();
    sqlx::query("INSERT INTO applications (id, organization_id, name, client_id, client_secret_hash, redirect_uris, allowed_scopes, access_token_ttl) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)")
        .bind(id).bind(organization_id).bind(body.name.trim()).bind(&client_id).bind(hash_secret(&secret))
        .bind(json!(body.redirect_uris)).bind(json!(body.allowed_scopes)).bind(body.access_token_ttl.unwrap_or(900)).execute(&state.pool).await?;
    let app = load_application(&state, id).await?;
    Ok((
        StatusCode::CREATED,
        Json(json!({ "application": app, "client_secret": secret })),
    ))
}

async fn list(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(organization_id): Path<Uuid>,
    Query(page): Query<Page>,
) -> Result<Json<Value>> {
    let current = actor(&state, &headers, false, false).await?;
    let role = organization_role(&state.pool, &current, organization_id).await?;
    require_role(&role, &["system_admin", "owner", "admin"])?;
    ensure_operable(&state, organization_id).await?;
    let (number, size, offset) = page.values()?;
    let query = page.query();
    let items = sqlx::query_as::<_, ApplicationView>("SELECT id, organization_id, name, client_id, redirect_uris, allowed_scopes, access_token_ttl, enabled, created_at, updated_at FROM applications WHERE organization_id = $1 AND ($2::text IS NULL OR name ILIKE $2) ORDER BY created_at DESC, id DESC LIMIT $3 OFFSET $4")
        .bind(organization_id).bind(&query).bind(size).bind(offset).fetch_all(&state.pool).await?;
    let total = sqlx::query_scalar("SELECT count(*) FROM applications WHERE organization_id = $1 AND ($2::text IS NULL OR name ILIKE $2)").bind(organization_id).bind(&query).fetch_one(&state.pool).await?;
    Ok(page_json(items, number, size, total))
}

async fn get_one(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
) -> Result<Json<ApplicationView>> {
    Ok(Json(
        authorize_application(&state, &headers, id, false).await?,
    ))
}

#[derive(Deserialize)]
struct UpdateApplication {
    name: Option<String>,
    redirect_uris: Option<Vec<String>>,
    allowed_scopes: Option<Vec<String>>,
    access_token_ttl: Option<i32>,
    enabled: Option<bool>,
}

async fn update(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
    Json(body): Json<UpdateApplication>,
) -> Result<Json<ApplicationView>> {
    let old = authorize_application(&state, &headers, id, true).await?;
    let name = body.name.as_deref().unwrap_or(&old.name);
    let redirects = body
        .redirect_uris
        .unwrap_or_else(|| strings_from_json(&old.redirect_uris));
    let scopes = body
        .allowed_scopes
        .unwrap_or_else(|| strings_from_json(&old.allowed_scopes));
    let ttl = body.access_token_ttl.unwrap_or(old.access_token_ttl);
    validate_application(name, &redirects, &scopes, ttl)?;
    sqlx::query("UPDATE applications SET name = $2, redirect_uris = $3, allowed_scopes = $4, access_token_ttl = $5, enabled = COALESCE($6, enabled), updated_at = now() WHERE id = $1")
        .bind(id).bind(name.trim()).bind(json!(redirects)).bind(json!(scopes)).bind(ttl).bind(body.enabled).execute(&state.pool).await?;
    Ok(Json(load_application(&state, id).await?))
}

fn strings_from_json(value: &Value) -> Vec<String> {
    value
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .map(str::to_owned)
        .collect()
}

async fn reset_secret(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
) -> Result<Json<Value>> {
    authorize_application(&state, &headers, id, true).await?;
    let secret = service::random_token();
    sqlx::query(
        "UPDATE applications SET client_secret_hash = $2, updated_at = now() WHERE id = $1",
    )
    .bind(id)
    .bind(hash_secret(&secret))
    .execute(&state.pool)
    .await?;
    Ok(Json(json!({ "client_secret": secret })))
}

fn validate_application(
    name: &str,
    redirect_uris: &[String],
    scopes: &[String],
    ttl: i32,
) -> Result<()> {
    if name.trim().is_empty() {
        return Err(ApiError::bad_request("name must not be empty"));
    }
    if !(60..=86400).contains(&ttl) {
        return Err(ApiError::bad_request(
            "access_token_ttl must be between 60 and 86400 seconds",
        ));
    }
    for uri in redirect_uris {
        let parsed = Url::parse(uri)
            .map_err(|_| ApiError::bad_request("redirect_uris must contain absolute URIs"))?;
        if parsed.fragment().is_some() {
            return Err(ApiError::bad_request(
                "redirect URIs must not contain fragments",
            ));
        }
    }
    if scopes
        .iter()
        .any(|scope| !matches!(scope.as_str(), "openid" | "profile" | "email"))
    {
        return Err(ApiError::bad_request(
            "allowed_scopes may only contain openid, profile, and email",
        ));
    }
    Ok(())
}

#[derive(Serialize, FromRow)]
struct RoleView {
    id: Uuid,
    organization_id: Uuid,
    application_id: Uuid,
    name: String,
    display_name: String,
    created_at: OffsetDateTime,
    updated_at: OffsetDateTime,
}

#[derive(Deserialize)]
struct CreateRole {
    name: String,
    display_name: String,
}

async fn create_role(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
    Json(body): Json<CreateRole>,
) -> Result<(StatusCode, Json<RoleView>)> {
    let app = authorize_application(&state, &headers, id, true).await?;
    if body.name.trim().is_empty() || body.display_name.trim().is_empty() {
        return Err(ApiError::bad_request(
            "name and display_name must not be empty",
        ));
    }
    let role_id = Uuid::now_v7();
    sqlx::query("INSERT INTO roles (id, organization_id, application_id, name, display_name) VALUES ($1, $2, $3, $4, $5)")
        .bind(role_id).bind(app.organization_id).bind(id).bind(body.name.trim()).bind(body.display_name.trim()).execute(&state.pool).await?;
    Ok((
        StatusCode::CREATED,
        Json(load_role(&state, id, role_id).await?),
    ))
}

async fn list_roles(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
    Query(page): Query<Page>,
) -> Result<Json<Value>> {
    authorize_application(&state, &headers, id, false).await?;
    let (number, size, offset) = page.values()?;
    let query = page.query();
    let items = sqlx::query_as::<_, RoleView>("SELECT id, organization_id, application_id, name, display_name, created_at, updated_at FROM roles WHERE application_id = $1 AND ($2::text IS NULL OR name ILIKE $2 OR display_name ILIKE $2) ORDER BY created_at DESC, id DESC LIMIT $3 OFFSET $4")
        .bind(id).bind(&query).bind(size).bind(offset).fetch_all(&state.pool).await?;
    let total = sqlx::query_scalar("SELECT count(*) FROM roles WHERE application_id = $1 AND ($2::text IS NULL OR name ILIKE $2 OR display_name ILIKE $2)").bind(id).bind(&query).fetch_one(&state.pool).await?;
    Ok(page_json(items, number, size, total))
}

async fn get_role(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path((id, role_id)): Path<(Uuid, Uuid)>,
) -> Result<Json<RoleView>> {
    authorize_application(&state, &headers, id, false).await?;
    Ok(Json(load_role(&state, id, role_id).await?))
}

#[derive(Deserialize)]
struct UpdateRole {
    name: Option<String>,
    display_name: Option<String>,
}

async fn update_role(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path((id, role_id)): Path<(Uuid, Uuid)>,
    Json(body): Json<UpdateRole>,
) -> Result<Json<RoleView>> {
    authorize_application(&state, &headers, id, true).await?;
    if body.name.as_deref().is_some_and(|v| v.trim().is_empty())
        || body
            .display_name
            .as_deref()
            .is_some_and(|v| v.trim().is_empty())
    {
        return Err(ApiError::bad_request(
            "name and display_name must not be empty",
        ));
    }
    let result = sqlx::query("UPDATE roles SET name = COALESCE($3, name), display_name = COALESCE($4, display_name), updated_at = now() WHERE application_id = $1 AND id = $2")
        .bind(id).bind(role_id).bind(body.name.as_ref().map(|v| v.trim())).bind(body.display_name.as_ref().map(|v| v.trim())).execute(&state.pool).await?;
    if result.rows_affected() == 0 {
        return Err(ApiError::not_found("Role"));
    }
    Ok(Json(load_role(&state, id, role_id).await?))
}

async fn delete_role(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path((id, role_id)): Path<(Uuid, Uuid)>,
) -> Result<StatusCode> {
    authorize_application(&state, &headers, id, true).await?;
    let result = sqlx::query("DELETE FROM roles WHERE application_id = $1 AND id = $2")
        .bind(id)
        .bind(role_id)
        .execute(&state.pool)
        .await?;
    if result.rows_affected() == 0 {
        return Err(ApiError::not_found("Role"));
    }
    Ok(StatusCode::NO_CONTENT)
}

async fn assign_role(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path((id, role_id, user_id)): Path<(Uuid, Uuid, Uuid)>,
) -> Result<StatusCode> {
    let app = authorize_application(&state, &headers, id, true).await?;
    load_role(&state, id, role_id).await?;
    let eligible: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM organization_memberships m JOIN users u ON u.id = m.user_id WHERE m.organization_id = $1 AND m.user_id = $2 AND u.status = 'active')")
        .bind(app.organization_id).bind(user_id).fetch_one(&state.pool).await?;
    if !eligible {
        return Err(ApiError::bad_request(
            "user must be an active member of the application's organization",
        ));
    }
    sqlx::query("INSERT INTO user_roles (user_id, role_id) VALUES ($1, $2) ON CONFLICT DO NOTHING")
        .bind(user_id)
        .bind(role_id)
        .execute(&state.pool)
        .await?;
    Ok(StatusCode::NO_CONTENT)
}

async fn unassign_role(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path((id, role_id, user_id)): Path<(Uuid, Uuid, Uuid)>,
) -> Result<StatusCode> {
    authorize_application(&state, &headers, id, true).await?;
    load_role(&state, id, role_id).await?;
    sqlx::query("DELETE FROM user_roles WHERE user_id = $1 AND role_id = $2")
        .bind(user_id)
        .bind(role_id)
        .execute(&state.pool)
        .await?;
    Ok(StatusCode::NO_CONTENT)
}

async fn user_roles(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path((id, user_id)): Path<(Uuid, Uuid)>,
) -> Result<Json<Vec<RoleView>>> {
    authorize_application(&state, &headers, id, false).await?;
    let roles = sqlx::query_as("SELECT r.id, r.organization_id, r.application_id, r.name, r.display_name, r.created_at, r.updated_at FROM roles r JOIN user_roles ur ON ur.role_id = r.id WHERE r.application_id = $1 AND ur.user_id = $2 ORDER BY r.name")
        .bind(id).bind(user_id).fetch_all(&state.pool).await?;
    Ok(Json(roles))
}

async fn load_role(state: &AppState, application_id: Uuid, id: Uuid) -> Result<RoleView> {
    sqlx::query_as("SELECT id, organization_id, application_id, name, display_name, created_at, updated_at FROM roles WHERE application_id = $1 AND id = $2")
        .bind(application_id).bind(id).fetch_optional(&state.pool).await?.ok_or_else(|| ApiError::not_found("Role"))
}
