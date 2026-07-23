use std::sync::Arc;

use axum::{
    Extension, Json,
    extract::{Path, State},
    http::StatusCode,
};
use serde::Deserialize;
use uuid::Uuid;

use crate::{
    AppState,
    db::{
        Actor, ApplicationRole, ApplicationRoleAssignment, EffectiveRole, NewApplicationRole,
        UpdateApplicationRole, UserAccess,
    },
    error::{ApiError, Result},
    iam,
};

use super::{
    access::{can_manage, can_view},
    applications::{manage_application, view_application},
    groups::load_group,
    validation,
};

async fn load_role(state: &AppState, id: Uuid) -> Result<ApplicationRole> {
    state
        .db
        .application_role(id)
        .await?
        .ok_or_else(|| ApiError::not_found("Application role"))
}

pub(super) async fn list_roles(
    State(state): State<Arc<AppState>>,
    Extension(current): Extension<Actor>,
    Path(application_id): Path<Uuid>,
) -> Result<Json<Vec<ApplicationRole>>> {
    view_application(&state, &current, application_id).await?;
    Ok(Json(state.db.application_roles(application_id).await?))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct CreateRole {
    key: String,
    display_name: String,
}

pub(super) async fn create_role(
    State(state): State<Arc<AppState>>,
    Extension(current): Extension<Actor>,
    Path(application_id): Path<Uuid>,
    Json(body): Json<CreateRole>,
) -> Result<(StatusCode, Json<ApplicationRole>)> {
    let application = manage_application(&state, &current, application_id).await?;
    let key = validation::immutable_key(&body.key)?;
    let display_name = body.display_name.trim().to_owned();
    validation::name(&display_name, "display_name")?;
    let role = state
        .db
        .create_application_role(NewApplicationRole {
            id: Uuid::now_v7(),
            application_id,
            organization_id: application.organization_id,
            key,
            display_name,
            actor_user_id: current.id,
        })
        .await?;
    Ok((StatusCode::CREATED, Json(role)))
}

pub(super) async fn get_role(
    State(state): State<Arc<AppState>>,
    Extension(current): Extension<Actor>,
    Path(id): Path<Uuid>,
) -> Result<Json<ApplicationRole>> {
    let role = load_role(&state, id).await?;
    can_view(&current, role.organization_id)?;
    Ok(Json(role))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct PatchRole {
    display_name: Option<String>,
    enabled: Option<bool>,
}

pub(super) async fn update_role(
    State(state): State<Arc<AppState>>,
    Extension(current): Extension<Actor>,
    Path(id): Path<Uuid>,
    Json(body): Json<PatchRole>,
) -> Result<Json<ApplicationRole>> {
    let role = load_role(&state, id).await?;
    can_manage(&current, role.organization_id)?;
    let display_name = body
        .display_name
        .map(|display_name| display_name.trim().to_owned());
    if let Some(display_name) = &display_name {
        validation::name(display_name, "display_name")?;
    }
    let role = state
        .db
        .update_application_role(UpdateApplicationRole {
            id,
            display_name,
            enabled: body.enabled,
            actor_user_id: current.id,
        })
        .await?
        .ok_or_else(|| ApiError::not_found("Application role"))?;
    Ok(Json(role))
}

pub(super) async fn list_assignments(
    State(state): State<Arc<AppState>>,
    Extension(current): Extension<Actor>,
    Path(id): Path<Uuid>,
) -> Result<Json<Vec<ApplicationRoleAssignment>>> {
    let role = load_role(&state, id).await?;
    can_view(&current, role.organization_id)?;
    Ok(Json(state.db.application_role_assignments(id).await?))
}

pub(super) async fn assign_user(
    State(state): State<Arc<AppState>>,
    Extension(current): Extension<Actor>,
    Path((role_id, user_id)): Path<(Uuid, Uuid)>,
) -> Result<StatusCode> {
    let role = load_role(&state, role_id).await?;
    can_manage(&current, role.organization_id)?;
    ensure_schema_ready(&state, role.application_id).await?;
    let user = load_user_access(&state, user_id).await?;
    ensure_same_organization(user.organization_id, role.organization_id, "User and role")?;
    state
        .db
        .assign_role_to_user(&role, user_id, current.id)
        .await?;
    Ok(StatusCode::NO_CONTENT)
}

pub(super) async fn unassign_user(
    State(state): State<Arc<AppState>>,
    Extension(current): Extension<Actor>,
    Path((role_id, user_id)): Path<(Uuid, Uuid)>,
) -> Result<StatusCode> {
    let role = load_role(&state, role_id).await?;
    can_manage(&current, role.organization_id)?;
    let user = load_user_access(&state, user_id).await?;
    ensure_same_organization(user.organization_id, role.organization_id, "User and role")?;
    state
        .db
        .unassign_role_from_user(&role, user_id, current.id)
        .await?;
    Ok(StatusCode::NO_CONTENT)
}

pub(super) async fn assign_group(
    State(state): State<Arc<AppState>>,
    Extension(current): Extension<Actor>,
    Path((role_id, group_id)): Path<(Uuid, Uuid)>,
) -> Result<StatusCode> {
    let role = load_role(&state, role_id).await?;
    can_manage(&current, role.organization_id)?;
    ensure_schema_ready(&state, role.application_id).await?;
    let group = load_group(&state, group_id).await?;
    ensure_same_organization(
        group.organization_id,
        role.organization_id,
        "Group and role",
    )?;
    state
        .db
        .assign_role_to_group(&role, &group, current.id)
        .await?;
    Ok(StatusCode::NO_CONTENT)
}

pub(super) async fn unassign_group(
    State(state): State<Arc<AppState>>,
    Extension(current): Extension<Actor>,
    Path((role_id, group_id)): Path<(Uuid, Uuid)>,
) -> Result<StatusCode> {
    let role = load_role(&state, role_id).await?;
    can_manage(&current, role.organization_id)?;
    let group = load_group(&state, group_id).await?;
    ensure_same_organization(
        group.organization_id,
        role.organization_id,
        "Group and role",
    )?;
    state
        .db
        .unassign_role_from_group(&role, &group, current.id)
        .await?;
    Ok(StatusCode::NO_CONTENT)
}

pub(super) async fn effective_roles(
    State(state): State<Arc<AppState>>,
    Extension(current): Extension<Actor>,
    Path((application_id, user_id)): Path<(Uuid, Uuid)>,
) -> Result<Json<Vec<EffectiveRole>>> {
    let application = view_application(&state, &current, application_id).await?;
    let user = load_user_access(&state, user_id).await?;
    ensure_same_organization(
        user.organization_id,
        application.organization_id,
        "User and application",
    )?;
    if current.id != user_id {
        can_manage(&current, application.organization_id)?;
    }
    Ok(Json(
        state.db.effective_roles(application_id, user_id).await?,
    ))
}

async fn load_user_access(state: &AppState, user_id: Uuid) -> Result<UserAccess> {
    state
        .db
        .user_access(user_id)
        .await?
        .ok_or_else(|| ApiError::not_found("User"))
}

async fn ensure_schema_ready(state: &AppState, application_id: Uuid) -> Result<()> {
    let release = state
        .db
        .active_policy_release(application_id)
        .await?
        .ok_or_else(schema_not_role_ready)?;
    iam::validate_schema_contract(&release.schema_source).map_err(|_| schema_not_role_ready())
}

fn ensure_same_organization(actual: Uuid, expected: Uuid, subject: &'static str) -> Result<()> {
    if actual == expected {
        Ok(())
    } else {
        Err(ApiError::bad_request(format!(
            "{subject} must belong to the same organization"
        )))
    }
}

fn schema_not_role_ready() -> ApiError {
    ApiError::conflict(
        "schema_not_role_ready",
        "The active policy release does not satisfy the User, Group, and Role schema contract",
    )
}
