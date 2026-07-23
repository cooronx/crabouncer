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
    db::{self, Actor, Group, GroupMember, NewGroup, UpdateGroup, UserAccess},
    error::{ApiError, Result},
};

use super::{
    access::{can_manage, can_view},
    validation,
};

async fn load_group(state: &AppState, id: Uuid) -> Result<Group> {
    state
        .db
        .group(id)
        .await?
        .ok_or_else(|| ApiError::not_found("Group"))
}

pub(super) async fn list_groups(
    State(state): State<Arc<AppState>>,
    Extension(current): Extension<Actor>,
    Path(organization_id): Path<Uuid>,
) -> Result<Json<Vec<Group>>> {
    can_view(&current, organization_id)?;
    Ok(Json(state.db.groups(organization_id).await?))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct CreateGroup {
    key: String,
    display_name: String,
    kind: String,
}

pub(super) async fn create_group(
    State(state): State<Arc<AppState>>,
    Extension(current): Extension<Actor>,
    Path(organization_id): Path<Uuid>,
    Json(body): Json<CreateGroup>,
) -> Result<(StatusCode, Json<Group>)> {
    can_manage(&current, organization_id)?;
    if state.db.organization(organization_id).await?.is_none() {
        return Err(ApiError::not_found("Organization"));
    }
    let key = validation::immutable_key(&body.key)?;
    let display_name = body.display_name.trim().to_owned();
    validation::name(&display_name, "display_name")?;
    let kind = normalize_kind(&body.kind)?;
    let group = state
        .db
        .create_group(NewGroup {
            id: Uuid::now_v7(),
            organization_id,
            key,
            display_name,
            kind,
            actor_user_id: current.id,
        })
        .await?;
    Ok((StatusCode::CREATED, Json(group)))
}

pub(super) async fn get_group(
    State(state): State<Arc<AppState>>,
    Extension(current): Extension<Actor>,
    Path(id): Path<Uuid>,
) -> Result<Json<Group>> {
    let group = load_group(&state, id).await?;
    can_view(&current, group.organization_id)?;
    Ok(Json(group))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct PatchGroup {
    display_name: Option<String>,
    enabled: Option<bool>,
}

pub(super) async fn update_group(
    State(state): State<Arc<AppState>>,
    Extension(current): Extension<Actor>,
    Path(id): Path<Uuid>,
    Json(body): Json<PatchGroup>,
) -> Result<Json<Group>> {
    let group = load_group(&state, id).await?;
    can_manage(&current, group.organization_id)?;
    let display_name = body
        .display_name
        .map(|display_name| display_name.trim().to_owned());
    if let Some(display_name) = &display_name {
        validation::name(display_name, "display_name")?;
    }
    let group = state
        .db
        .update_group(UpdateGroup {
            id,
            display_name,
            enabled: body.enabled,
            actor_user_id: current.id,
        })
        .await?
        .ok_or_else(|| ApiError::not_found("Group"))?;
    Ok(Json(group))
}

pub(super) async fn list_group_members(
    State(state): State<Arc<AppState>>,
    Extension(current): Extension<Actor>,
    Path(id): Path<Uuid>,
) -> Result<Json<Vec<GroupMember>>> {
    let group = load_group(&state, id).await?;
    can_view(&current, group.organization_id)?;
    Ok(Json(state.db.group_members(id).await?))
}

pub(super) async fn add_group_member(
    State(state): State<Arc<AppState>>,
    Extension(current): Extension<Actor>,
    Path((group_id, user_id)): Path<(Uuid, Uuid)>,
) -> Result<StatusCode> {
    let group = load_group(&state, group_id).await?;
    can_manage(&current, group.organization_id)?;
    let user: UserAccess = state
        .db
        .user_access(user_id)
        .await?
        .ok_or_else(|| ApiError::not_found("User"))?;
    if user.organization_id != group.organization_id {
        return Err(ApiError::bad_request(
            "User and group must belong to the same organization",
        ));
    }

    if group.kind == "physical"
        && let Some(existing) = state.db.physical_group_for_user(user_id).await?
        && existing.id != group.id
    {
        return Err(physical_group_conflict());
    }

    match state
        .db
        .add_group_member(group_id, user_id, current.id)
        .await
    {
        Ok(_) => Ok(StatusCode::NO_CONTENT),
        Err(db::Error::Conflict) if group.kind == "physical" => Err(physical_group_conflict()),
        Err(error) => Err(error.into()),
    }
}

pub(super) async fn remove_group_member(
    State(state): State<Arc<AppState>>,
    Extension(current): Extension<Actor>,
    Path((group_id, user_id)): Path<(Uuid, Uuid)>,
) -> Result<StatusCode> {
    let group = load_group(&state, group_id).await?;
    can_manage(&current, group.organization_id)?;
    let user: UserAccess = state
        .db
        .user_access(user_id)
        .await?
        .ok_or_else(|| ApiError::not_found("User"))?;
    if user.organization_id != group.organization_id {
        return Err(ApiError::bad_request(
            "User and group must belong to the same organization",
        ));
    }
    state
        .db
        .remove_group_member(group_id, user_id, current.id)
        .await?;
    Ok(StatusCode::NO_CONTENT)
}

pub(super) async fn list_user_groups(
    State(state): State<Arc<AppState>>,
    Extension(current): Extension<Actor>,
    Path(user_id): Path<Uuid>,
) -> Result<Json<Vec<Group>>> {
    let user: UserAccess = state
        .db
        .user_access(user_id)
        .await?
        .ok_or_else(|| ApiError::not_found("User"))?;
    can_view(&current, user.organization_id)?;
    Ok(Json(state.db.user_groups(user_id).await?))
}

fn normalize_kind(value: &str) -> Result<String> {
    let kind = value.trim().to_lowercase();
    if matches!(kind.as_str(), "physical" | "virtual") {
        Ok(kind)
    } else {
        Err(ApiError::bad_request("kind must be physical or virtual"))
    }
}

fn physical_group_conflict() -> ApiError {
    ApiError::conflict(
        "physical_group_conflict",
        "User already belongs to a physical group",
    )
}
