use std::{str::FromStr, sync::Arc};

use axum::{
    Json, Router,
    extract::{Path, Query, State},
    http::{HeaderMap, StatusCode},
    routing::{get, post, put},
};
use cedar_policy::{PolicySet, Schema, ValidationMode, Validator};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sqlx::FromRow;
use time::OffsetDateTime;
use uuid::Uuid;

use super::applications::load_application;
use super::organizations::ensure_operable;
use super::{ApiError, AppState, Page, Result, actor, organization_role, page_json, require_role};

pub(super) fn routes() -> Router<Arc<AppState>> {
    Router::new()
        .route(
            "/api/v1/applications/{id}/schema",
            get(get_schema).put(update_schema),
        )
        .route(
            "/api/v1/applications/{id}/policies",
            post(create_policy).get(list_policies),
        )
        .route(
            "/api/v1/applications/{id}/policies/{policy_id}",
            get(get_policy).patch(update_policy).delete(delete_policy),
        )
        .route(
            "/api/v1/applications/{id}/policies/{policy_id}/publish",
            post(publish_policy),
        )
        .route(
            "/api/v1/applications/{id}/policies/{policy_id}/enabled",
            put(set_policy_enabled),
        )
}

async fn authorize(
    state: &AppState,
    headers: &HeaderMap,
    app_id: Uuid,
    mutation: bool,
) -> Result<()> {
    let current = actor(state, headers, mutation, false).await?;
    let app = load_application(state, app_id).await?;
    let role = organization_role(&state.pool, &current, app.organization_id).await?;
    require_role(&role, &["system_admin", "owner", "admin"])?;
    ensure_operable(state, app.organization_id).await
}

#[derive(Serialize, FromRow)]
struct SchemaView {
    application_id: Uuid,
    source: String,
    version: i64,
    updated_at: OffsetDateTime,
}

async fn get_schema(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
) -> Result<Json<SchemaView>> {
    authorize(&state, &headers, id, false).await?;
    let schema = sqlx::query_as("SELECT application_id, source, version, updated_at FROM cedar_schemas WHERE application_id = $1")
        .bind(id).fetch_optional(&state.pool).await?.ok_or_else(|| ApiError::not_found("Cedar schema"))?;
    Ok(Json(schema))
}

#[derive(Deserialize)]
struct SchemaRequest {
    source: String,
}

async fn update_schema(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
    Json(body): Json<SchemaRequest>,
) -> Result<Json<SchemaView>> {
    authorize(&state, &headers, id, true).await?;
    let schema = parse_schema(&body.source)?;
    let policies: Vec<(Uuid, String)> = sqlx::query_as("SELECT id, published_source FROM cedar_policies WHERE application_id = $1 AND published_source IS NOT NULL")
        .bind(id).fetch_all(&state.pool).await?;
    let mut all_errors = Vec::new();
    for (policy_id, source) in policies {
        if let Err(error) = validate_policy(&schema, &source) {
            all_errors.push(json!({ "policy_id": policy_id, "message": error }));
        }
    }
    if !all_errors.is_empty() {
        return Err(ApiError::validation(
            "Schema is incompatible with published policies",
            json!(all_errors),
        ));
    }
    sqlx::query("INSERT INTO cedar_schemas (application_id, source, version) VALUES ($1, $2, 1) ON CONFLICT (application_id) DO UPDATE SET source = EXCLUDED.source, version = cedar_schemas.version + 1, updated_at = now()")
        .bind(id).bind(body.source).execute(&state.pool).await?;
    let schema = sqlx::query_as("SELECT application_id, source, version, updated_at FROM cedar_schemas WHERE application_id = $1")
        .bind(id).fetch_one(&state.pool).await?;
    Ok(Json(schema))
}

#[derive(Serialize, FromRow)]
struct PolicyView {
    id: Uuid,
    application_id: Uuid,
    name: String,
    draft_source: String,
    published_source: Option<String>,
    enabled: bool,
    version: i64,
    created_at: OffsetDateTime,
    updated_at: OffsetDateTime,
}

#[derive(Deserialize)]
struct CreatePolicy {
    name: String,
    source: String,
}

async fn create_policy(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
    Json(body): Json<CreatePolicy>,
) -> Result<(StatusCode, Json<PolicyView>)> {
    authorize(&state, &headers, id, true).await?;
    if body.name.trim().is_empty() {
        return Err(ApiError::bad_request("name must not be empty"));
    }
    parse_policy(&body.source)?;
    let policy_id = Uuid::now_v7();
    sqlx::query("INSERT INTO cedar_policies (id, application_id, name, draft_source) VALUES ($1, $2, $3, $4)")
        .bind(policy_id).bind(id).bind(body.name.trim()).bind(body.source).execute(&state.pool).await?;
    Ok((
        StatusCode::CREATED,
        Json(load_policy(&state, id, policy_id).await?),
    ))
}

async fn list_policies(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
    Query(page): Query<Page>,
) -> Result<Json<Value>> {
    authorize(&state, &headers, id, false).await?;
    let (number, size, offset) = page.values()?;
    let query = page.query();
    let items = sqlx::query_as::<_, PolicyView>("SELECT id, application_id, name, draft_source, published_source, enabled, version, created_at, updated_at FROM cedar_policies WHERE application_id = $1 AND ($2::text IS NULL OR name ILIKE $2) ORDER BY created_at DESC, id DESC LIMIT $3 OFFSET $4")
        .bind(id).bind(&query).bind(size).bind(offset).fetch_all(&state.pool).await?;
    let total = sqlx::query_scalar("SELECT count(*) FROM cedar_policies WHERE application_id = $1 AND ($2::text IS NULL OR name ILIKE $2)").bind(id).bind(&query).fetch_one(&state.pool).await?;
    Ok(page_json(items, number, size, total))
}

async fn get_policy(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path((id, policy_id)): Path<(Uuid, Uuid)>,
) -> Result<Json<PolicyView>> {
    authorize(&state, &headers, id, false).await?;
    Ok(Json(load_policy(&state, id, policy_id).await?))
}

#[derive(Deserialize)]
struct UpdatePolicy {
    name: Option<String>,
    source: Option<String>,
}

async fn update_policy(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path((id, policy_id)): Path<(Uuid, Uuid)>,
    Json(body): Json<UpdatePolicy>,
) -> Result<Json<PolicyView>> {
    authorize(&state, &headers, id, true).await?;
    if body.name.as_deref().is_some_and(|v| v.trim().is_empty()) {
        return Err(ApiError::bad_request("name must not be empty"));
    }
    if let Some(source) = &body.source {
        parse_policy(source)?;
    }
    let result = sqlx::query("UPDATE cedar_policies SET name = COALESCE($3, name), draft_source = COALESCE($4, draft_source), updated_at = now() WHERE application_id = $1 AND id = $2")
        .bind(id).bind(policy_id).bind(body.name.as_ref().map(|v| v.trim())).bind(body.source).execute(&state.pool).await?;
    if result.rows_affected() == 0 {
        return Err(ApiError::not_found("Policy"));
    }
    Ok(Json(load_policy(&state, id, policy_id).await?))
}

async fn publish_policy(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path((id, policy_id)): Path<(Uuid, Uuid)>,
) -> Result<Json<PolicyView>> {
    authorize(&state, &headers, id, true).await?;
    let policy = load_policy(&state, id, policy_id).await?;
    let source: Option<String> =
        sqlx::query_scalar("SELECT source FROM cedar_schemas WHERE application_id = $1")
            .bind(id)
            .fetch_optional(&state.pool)
            .await?;
    let source = source.ok_or_else(|| {
        ApiError::conflict(
            "schema_required",
            "Create a Cedar schema before publishing policies",
        )
    })?;
    let schema = parse_schema(&source)?;
    validate_policy(&schema, &policy.draft_source).map_err(|message| {
        ApiError::validation(
            "Policy does not conform to the current schema",
            json!([{ "message": message }]),
        )
    })?;
    sqlx::query("UPDATE cedar_policies SET published_source = draft_source, version = version + 1, updated_at = now() WHERE id = $1").bind(policy_id).execute(&state.pool).await?;
    Ok(Json(load_policy(&state, id, policy_id).await?))
}

#[derive(Deserialize)]
struct EnabledRequest {
    enabled: bool,
}

async fn set_policy_enabled(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path((id, policy_id)): Path<(Uuid, Uuid)>,
    Json(body): Json<EnabledRequest>,
) -> Result<Json<PolicyView>> {
    authorize(&state, &headers, id, true).await?;
    let policy = load_policy(&state, id, policy_id).await?;
    if body.enabled && policy.published_source.is_none() {
        return Err(ApiError::conflict(
            "policy_not_published",
            "Publish the policy before enabling it",
        ));
    }
    sqlx::query("UPDATE cedar_policies SET enabled = $2, updated_at = now() WHERE id = $1")
        .bind(policy_id)
        .bind(body.enabled)
        .execute(&state.pool)
        .await?;
    Ok(Json(load_policy(&state, id, policy_id).await?))
}

async fn delete_policy(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path((id, policy_id)): Path<(Uuid, Uuid)>,
) -> Result<StatusCode> {
    authorize(&state, &headers, id, true).await?;
    let result = sqlx::query("DELETE FROM cedar_policies WHERE application_id = $1 AND id = $2")
        .bind(id)
        .bind(policy_id)
        .execute(&state.pool)
        .await?;
    if result.rows_affected() == 0 {
        return Err(ApiError::not_found("Policy"));
    }
    Ok(StatusCode::NO_CONTENT)
}

async fn load_policy(state: &AppState, app_id: Uuid, id: Uuid) -> Result<PolicyView> {
    sqlx::query_as("SELECT id, application_id, name, draft_source, published_source, enabled, version, created_at, updated_at FROM cedar_policies WHERE application_id = $1 AND id = $2")
        .bind(app_id).bind(id).fetch_optional(&state.pool).await?.ok_or_else(|| ApiError::not_found("Policy"))
}

fn parse_schema(source: &str) -> Result<Schema> {
    Schema::from_json_str(source).map_err(|error| {
        ApiError::validation(
            "Cedar schema could not be parsed",
            json!([{ "message": error.to_string() }]),
        )
    })
}

fn parse_policy(source: &str) -> Result<PolicySet> {
    PolicySet::from_str(source).map_err(|error| {
        ApiError::validation(
            "Cedar policy could not be parsed",
            json!([{ "message": error.to_string() }]),
        )
    })
}

fn validate_policy(schema: &Schema, source: &str) -> std::result::Result<(), String> {
    let policies = PolicySet::from_str(source).map_err(|error| error.to_string())?;
    let result = Validator::new(schema.clone()).validate(&policies, ValidationMode::Strict);
    if result.validation_passed() {
        Ok(())
    } else {
        Err(result
            .validation_errors()
            .map(ToString::to_string)
            .collect::<Vec<_>>()
            .join("; "))
    }
}
