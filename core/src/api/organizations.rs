use std::sync::Arc;

use axum::{
    Json, Router,
    extract::{Path, Query, State},
    http::{HeaderMap, StatusCode},
    routing::{get, post, put},
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sqlx::FromRow;
use time::OffsetDateTime;
use uuid::Uuid;

use super::{ApiError, AppState, Page, Result, actor, organization_role, page_json, require_role};

pub(super) fn routes() -> Router<Arc<AppState>> {
    Router::new()
        .route("/api/v1/organizations", post(create).get(list))
        .route(
            "/api/v1/organizations/{id}",
            get(get_one).patch(update).delete(delete_organization),
        )
        .route("/api/v1/organizations/{id}/status", put(set_status))
        .route("/api/v1/organizations/{id}/owner", put(transfer_owner))
        .route(
            "/api/v1/organizations/{id}/members",
            get(list_members).post(add_member),
        )
        .route(
            "/api/v1/organizations/{id}/members/{user_id}",
            put(update_member).delete(remove_member),
        )
}

#[derive(Serialize, FromRow)]
struct OrganizationView {
    id: Uuid,
    name: String,
    display_name: String,
    status: String,
    is_system: bool,
    created_at: OffsetDateTime,
    updated_at: OffsetDateTime,
}

async fn load(state: &AppState, id: Uuid) -> Result<OrganizationView> {
    sqlx::query_as("SELECT id, name, display_name, status, is_system, created_at, updated_at FROM organizations WHERE id = $1")
        .bind(id).fetch_optional(&state.pool).await?.ok_or_else(|| ApiError::not_found("Organization"))
}

#[derive(Deserialize)]
struct CreateOrganization {
    name: String,
    display_name: String,
    owner_user_id: Uuid,
}

async fn create(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(body): Json<CreateOrganization>,
) -> Result<(StatusCode, Json<OrganizationView>)> {
    let current = actor(&state, &headers, true, false).await?;
    if !current.is_system_admin {
        return Err(ApiError::forbidden());
    }
    if body.name.trim().is_empty() || body.display_name.trim().is_empty() {
        return Err(ApiError::bad_request(
            "name and display_name must not be empty",
        ));
    }
    let eligible: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM users WHERE id = $1 AND status = 'active')",
    )
    .bind(body.owner_user_id)
    .fetch_one(&state.pool)
    .await?;
    if !eligible {
        return Err(ApiError::bad_request(
            "owner_user_id must reference an active user",
        ));
    }
    let id = Uuid::now_v7();
    let mut tx = state.pool.begin().await?;
    sqlx::query("INSERT INTO organizations (id, name, display_name) VALUES ($1, $2, $3)")
        .bind(id)
        .bind(body.name.trim())
        .bind(body.display_name.trim())
        .execute(&mut *tx)
        .await?;
    sqlx::query("INSERT INTO organization_memberships (organization_id, user_id, role) VALUES ($1, $2, 'owner')")
        .bind(id).bind(body.owner_user_id).execute(&mut *tx).await?;
    tx.commit().await?;
    Ok((StatusCode::CREATED, Json(load(&state, id).await?)))
}

async fn list(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Query(page): Query<Page>,
) -> Result<Json<Value>> {
    let current = actor(&state, &headers, false, false).await?;
    let (number, size, offset) = page.values()?;
    let query = page.query();
    let items = sqlx::query_as::<_, OrganizationView>("SELECT DISTINCT o.id, o.name, o.display_name, o.status, o.is_system, o.created_at, o.updated_at FROM organizations o LEFT JOIN organization_memberships m ON m.organization_id = o.id WHERE ($1 OR m.user_id = $2) AND ($3::text IS NULL OR o.name ILIKE $3 OR o.display_name ILIKE $3) ORDER BY o.created_at DESC, o.id DESC LIMIT $4 OFFSET $5")
        .bind(current.is_system_admin).bind(current.id).bind(&query).bind(size).bind(offset).fetch_all(&state.pool).await?;
    let total: i64 = sqlx::query_scalar("SELECT count(DISTINCT o.id) FROM organizations o LEFT JOIN organization_memberships m ON m.organization_id = o.id WHERE ($1 OR m.user_id = $2) AND ($3::text IS NULL OR o.name ILIKE $3 OR o.display_name ILIKE $3)")
        .bind(current.is_system_admin).bind(current.id).bind(&query).fetch_one(&state.pool).await?;
    Ok(page_json(items, number, size, total))
}

async fn get_one(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
) -> Result<Json<OrganizationView>> {
    let current = actor(&state, &headers, false, false).await?;
    organization_role(&state.pool, &current, id).await?;
    Ok(Json(load(&state, id).await?))
}

#[derive(Deserialize)]
struct UpdateOrganization {
    name: Option<String>,
    display_name: Option<String>,
}

async fn update(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
    Json(body): Json<UpdateOrganization>,
) -> Result<Json<OrganizationView>> {
    let current = actor(&state, &headers, true, false).await?;
    let role = organization_role(&state.pool, &current, id).await?;
    require_role(&role, &["system_admin", "owner"])?;
    let organization = load(&state, id).await?;
    ensure_operable(&state, id).await?;
    if organization.is_system && body.name.as_deref().is_some_and(|name| name != "system") {
        return Err(ApiError::conflict(
            "system_organization_immutable",
            "System organization name cannot be changed",
        ));
    }
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
    sqlx::query("UPDATE organizations SET name = COALESCE($2, name), display_name = COALESCE($3, display_name), updated_at = now() WHERE id = $1")
        .bind(id).bind(body.name.as_ref().map(|v| v.trim())).bind(body.display_name.as_ref().map(|v| v.trim())).execute(&state.pool).await?;
    Ok(Json(load(&state, id).await?))
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
) -> Result<Json<OrganizationView>> {
    let current = actor(&state, &headers, true, false).await?;
    let role = organization_role(&state.pool, &current, id).await?;
    let organization = load(&state, id).await?;
    if organization.is_system {
        return Err(ApiError::conflict(
            "system_organization_immutable",
            "System organization cannot be disabled",
        ));
    }
    if !matches!(body.status.as_str(), "active" | "disabled") {
        return Err(ApiError::bad_request("status must be active or disabled"));
    }
    if organization.status == "deleted" && !current.is_system_admin {
        return Err(ApiError::forbidden());
    }
    require_role(&role, &["system_admin", "owner"])?;
    sqlx::query("UPDATE organizations SET status = $2, updated_at = now() WHERE id = $1")
        .bind(id)
        .bind(body.status)
        .execute(&state.pool)
        .await?;
    Ok(Json(load(&state, id).await?))
}

async fn delete_organization(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
) -> Result<StatusCode> {
    let current = actor(&state, &headers, true, false).await?;
    let role = organization_role(&state.pool, &current, id).await?;
    require_role(&role, &["system_admin", "owner"])?;
    let organization = load(&state, id).await?;
    ensure_operable(&state, id).await?;
    if organization.is_system {
        return Err(ApiError::conflict(
            "system_organization_immutable",
            "System organization cannot be deleted",
        ));
    }
    sqlx::query("UPDATE organizations SET status = 'deleted', updated_at = now() WHERE id = $1")
        .bind(id)
        .execute(&state.pool)
        .await?;
    Ok(StatusCode::NO_CONTENT)
}

#[derive(Deserialize)]
struct TransferOwner {
    user_id: Uuid,
}

async fn transfer_owner(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
    Json(body): Json<TransferOwner>,
) -> Result<StatusCode> {
    let current = actor(&state, &headers, true, false).await?;
    let role = organization_role(&state.pool, &current, id).await?;
    require_role(&role, &["system_admin", "owner"])?;
    if load(&state, id).await?.is_system {
        return Err(ApiError::conflict(
            "system_organization_immutable",
            "System organization ownership cannot be transferred",
        ));
    }
    let eligible: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM organization_memberships m JOIN users u ON u.id = m.user_id WHERE m.organization_id = $1 AND m.user_id = $2 AND u.status = 'active')")
        .bind(id).bind(body.user_id).fetch_one(&state.pool).await?;
    if !eligible {
        return Err(ApiError::bad_request(
            "new owner must be an active organization member",
        ));
    }
    let mut tx = state.pool.begin().await?;
    sqlx::query("UPDATE organization_memberships SET role = 'member' WHERE organization_id = $1 AND role = 'owner'").bind(id).execute(&mut *tx).await?;
    sqlx::query("UPDATE organization_memberships SET role = 'owner' WHERE organization_id = $1 AND user_id = $2").bind(id).bind(body.user_id).execute(&mut *tx).await?;
    tx.commit().await?;
    Ok(StatusCode::NO_CONTENT)
}

#[derive(Serialize, FromRow)]
struct MemberView {
    user_id: Uuid,
    username: String,
    display_name: String,
    status: String,
    role: String,
    created_at: OffsetDateTime,
}

async fn list_members(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
    Query(page): Query<Page>,
) -> Result<Json<Value>> {
    let current = actor(&state, &headers, false, false).await?;
    organization_role(&state.pool, &current, id).await?;
    ensure_operable(&state, id).await?;
    let (number, size, offset) = page.values()?;
    let query = page.query();
    let items = sqlx::query_as::<_, MemberView>("SELECT u.id AS user_id, u.username, u.display_name, u.status, m.role, m.created_at FROM organization_memberships m JOIN users u ON u.id = m.user_id WHERE m.organization_id = $1 AND ($2::text IS NULL OR u.username ILIKE $2 OR u.display_name ILIKE $2) ORDER BY m.created_at DESC, u.id DESC LIMIT $3 OFFSET $4")
        .bind(id).bind(&query).bind(size).bind(offset).fetch_all(&state.pool).await?;
    let total = sqlx::query_scalar("SELECT count(*) FROM organization_memberships m JOIN users u ON u.id = m.user_id WHERE m.organization_id = $1 AND ($2::text IS NULL OR u.username ILIKE $2 OR u.display_name ILIKE $2)")
        .bind(id).bind(&query).fetch_one(&state.pool).await?;
    Ok(page_json(items, number, size, total))
}

#[derive(Deserialize)]
struct MemberRequest {
    user_id: Uuid,
    role: Option<String>,
}

async fn add_member(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
    Json(body): Json<MemberRequest>,
) -> Result<(StatusCode, Json<MemberView>)> {
    let current = actor(&state, &headers, true, false).await?;
    let actor_role = organization_role(&state.pool, &current, id).await?;
    ensure_operable(&state, id).await?;
    let role = body.role.as_deref().unwrap_or("member");
    authorize_member_role(&actor_role, role)?;
    if role == "owner" {
        return Err(ApiError::bad_request("use the ownership transfer endpoint"));
    }
    let active: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM users WHERE id = $1 AND status = 'active')",
    )
    .bind(body.user_id)
    .fetch_one(&state.pool)
    .await?;
    if !active {
        return Err(ApiError::bad_request(
            "user_id must reference an active user",
        ));
    }
    sqlx::query(
        "INSERT INTO organization_memberships (organization_id, user_id, role) VALUES ($1, $2, $3)",
    )
    .bind(id)
    .bind(body.user_id)
    .bind(role)
    .execute(&state.pool)
    .await?;
    let member = load_member(&state, id, body.user_id).await?;
    Ok((StatusCode::CREATED, Json(member)))
}

#[derive(Deserialize)]
struct UpdateMember {
    role: String,
}

async fn update_member(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path((id, user_id)): Path<(Uuid, Uuid)>,
    Json(body): Json<UpdateMember>,
) -> Result<Json<MemberView>> {
    let current = actor(&state, &headers, true, false).await?;
    let actor_role = organization_role(&state.pool, &current, id).await?;
    ensure_operable(&state, id).await?;
    authorize_member_role(&actor_role, &body.role)?;
    if body.role == "owner" {
        return Err(ApiError::bad_request("use the ownership transfer endpoint"));
    }
    let existing = load_member(&state, id, user_id).await?;
    if existing.role == "owner" {
        return Err(ApiError::conflict(
            "owner_cannot_be_modified",
            "Transfer ownership first",
        ));
    }
    sqlx::query(
        "UPDATE organization_memberships SET role = $3 WHERE organization_id = $1 AND user_id = $2",
    )
    .bind(id)
    .bind(user_id)
    .bind(&body.role)
    .execute(&state.pool)
    .await?;
    Ok(Json(load_member(&state, id, user_id).await?))
}

async fn remove_member(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path((id, user_id)): Path<(Uuid, Uuid)>,
) -> Result<StatusCode> {
    let current = actor(&state, &headers, true, false).await?;
    let actor_role = organization_role(&state.pool, &current, id).await?;
    ensure_operable(&state, id).await?;
    let target = load_member(&state, id, user_id).await?;
    if target.role == "owner" {
        return Err(ApiError::conflict(
            "owner_cannot_be_removed",
            "Transfer ownership first",
        ));
    }
    if actor_role == "admin" && target.role != "member" {
        return Err(ApiError::forbidden());
    }
    require_role(&actor_role, &["system_admin", "owner", "admin"])?;
    let mut tx = state.pool.begin().await?;
    sqlx::query("DELETE FROM user_roles ur USING roles r WHERE ur.role_id = r.id AND ur.user_id = $1 AND r.organization_id = $2").bind(user_id).bind(id).execute(&mut *tx).await?;
    sqlx::query("DELETE FROM organization_memberships WHERE organization_id = $1 AND user_id = $2")
        .bind(id)
        .bind(user_id)
        .execute(&mut *tx)
        .await?;
    tx.commit().await?;
    Ok(StatusCode::NO_CONTENT)
}

async fn load_member(state: &AppState, id: Uuid, user_id: Uuid) -> Result<MemberView> {
    sqlx::query_as("SELECT u.id AS user_id, u.username, u.display_name, u.status, m.role, m.created_at FROM organization_memberships m JOIN users u ON u.id = m.user_id WHERE m.organization_id = $1 AND m.user_id = $2")
        .bind(id).bind(user_id).fetch_optional(&state.pool).await?.ok_or_else(|| ApiError::not_found("Organization member"))
}

fn authorize_member_role(actor_role: &str, target_role: &str) -> Result<()> {
    if !matches!(target_role, "admin" | "member") {
        return Err(ApiError::bad_request("role must be admin or member"));
    }
    if target_role == "admin" {
        require_role(actor_role, &["system_admin", "owner"])
    } else {
        require_role(actor_role, &["system_admin", "owner", "admin"])
    }
}

pub(crate) async fn ensure_operable(state: &AppState, id: Uuid) -> Result<()> {
    if load(state, id).await?.status == "active" {
        Ok(())
    } else {
        Err(ApiError::conflict(
            "organization_not_active",
            "Organization is not active",
        ))
    }
}
