use std::sync::Arc;

use axum::{
    Extension, Json,
    extract::{Path, State},
    http::StatusCode,
};
use serde::Deserialize;
use serde_json::{Value, json};
use uuid::Uuid;

use crate::{
    AppState,
    db::{
        Actor, AuditEvent, NewPolicyRelease, PolicyReleaseResult, PolicySnapshot, Release,
        UpdateWorkspace as DatabaseUpdateWorkspace, Workspace,
    },
    error::{ApiError, Result},
    iam, policy,
};

use super::{
    access::audit_event,
    applications::{manage_application, view_application},
};

pub(super) async fn get_workspace(
    State(state): State<Arc<AppState>>,
    Extension(current): Extension<Actor>,
    Path(id): Path<Uuid>,
) -> Result<Json<Workspace>> {
    view_application(&state, &current, id).await?;
    Ok(Json(state.db.workspace(id).await?))
}

#[derive(Deserialize)]
pub(super) struct WorkspaceInput {
    schema_source: String,
    policies: Value,
    entities: Value,
}

pub(super) async fn update_workspace(
    State(state): State<Arc<AppState>>,
    Extension(current): Extension<Actor>,
    Path(id): Path<Uuid>,
    Json(body): Json<WorkspaceInput>,
) -> Result<StatusCode> {
    let application = manage_application(&state, &current, id).await?;
    if !body.policies.is_array() || !body.entities.is_array() {
        return Err(ApiError::bad_request(
            "policies and entities must be arrays",
        ));
    }
    iam::reject_reserved_entities(&body.entities)?;
    state
        .db
        .update_workspace(DatabaseUpdateWorkspace {
            application_id: id,
            schema_source: body.schema_source,
            policies: body.policies,
            entities: body.entities,
        })
        .await?;
    audit_event(
        &state,
        &current,
        Some(application.organization_id),
        "policy_workspace.update",
        "application",
        id,
    )
    .await?;
    Ok(StatusCode::NO_CONTENT)
}

pub(super) async fn validate_workspace(
    State(state): State<Arc<AppState>>,
    Extension(current): Extension<Actor>,
    Path(id): Path<Uuid>,
) -> Result<Json<Value>> {
    let application = view_application(&state, &current, id).await?;
    let snapshot: PolicySnapshot = state.db.policy_snapshot(id).await?;
    validate_policy_candidate(
        &state,
        id,
        application.organization_id,
        &snapshot.schema_source,
        &snapshot.policies,
        &snapshot.entities,
    )
    .await?;
    if let Some(active) = state.db.active_policy_release(id).await? {
        policy::validate_schema_evolution(&active.schema_source, &snapshot.schema_source)?;
    }
    Ok(Json(json!({ "valid": true })))
}

pub(super) async fn simulate_workspace(
    State(state): State<Arc<AppState>>,
    Extension(current): Extension<Actor>,
    Path(id): Path<Uuid>,
    Json(request): Json<authzen_rs::EvaluationRequest>,
) -> Result<Json<Value>> {
    let application = view_application(&state, &current, id).await?;
    let snapshot: PolicySnapshot = state.db.policy_snapshot(id).await?;
    Ok(Json(policy::evaluate(
        &snapshot.schema_source,
        &snapshot.policies,
        &snapshot.entities,
        &request,
        application.organization_id,
        None,
    )?))
}

pub(super) async fn list_releases(
    State(state): State<Arc<AppState>>,
    Extension(current): Extension<Actor>,
    Path(id): Path<Uuid>,
) -> Result<Json<Vec<Release>>> {
    view_application(&state, &current, id).await?;
    Ok(Json(state.db.releases(id).await?))
}

pub(super) async fn publish_release(
    State(state): State<Arc<AppState>>,
    Extension(current): Extension<Actor>,
    Path(id): Path<Uuid>,
) -> Result<(StatusCode, Json<Value>)> {
    let application = manage_application(&state, &current, id).await?;
    let snapshot: PolicySnapshot = state.db.policy_snapshot(id).await?;
    validate_policy_candidate(
        &state,
        id,
        application.organization_id,
        &snapshot.schema_source,
        &snapshot.policies,
        &snapshot.entities,
    )
    .await?;
    if let Some(active) = state.db.active_policy_release(id).await? {
        policy::validate_schema_evolution(&active.schema_source, &snapshot.schema_source)?;
    }
    let release_id = Uuid::now_v7();
    let release: PolicyReleaseResult = state
        .db
        .publish_policy_release(NewPolicyRelease {
            id: release_id,
            application_id: id,
            created_by: current.id,
            snapshot,
            audit: AuditEvent {
                organization_id: Some(application.organization_id),
                actor_user_id: current.id,
                action: "policy_release.publish".into(),
                target_type: "policy_release".into(),
                target_id: Some(release_id.to_string()),
                details: json!({}),
            },
        })
        .await?;
    Ok((
        StatusCode::CREATED,
        Json(json!({
            "id": release.id,
            "version": release.version,
            "active": true,
        })),
    ))
}

pub(super) async fn activate_release(
    State(state): State<Arc<AppState>>,
    Extension(current): Extension<Actor>,
    Path((id, release_id)): Path<(Uuid, Uuid)>,
) -> Result<StatusCode> {
    let application = manage_application(&state, &current, id).await?;
    let release = state
        .db
        .policy_release(id, release_id)
        .await?
        .ok_or_else(|| ApiError::not_found("Release"))?;
    validate_policy_candidate(
        &state,
        id,
        application.organization_id,
        &release.schema_source,
        &release.policies,
        &release.entities,
    )
    .await?;
    for resource in state.db.all_resources(id).await? {
        policy::validate_stored_resource(
            &release.schema_source,
            &resource.resource_type,
            &resource.resource_id,
            &resource.properties,
        )?;
    }
    if !state
        .db
        .activate_policy_release(id, release_id, current.id)
        .await?
    {
        return Err(ApiError::not_found("Release"));
    }
    audit_event(
        &state,
        &current,
        Some(application.organization_id),
        "policy_release.activate",
        "policy_release",
        release_id,
    )
    .await?;
    Ok(StatusCode::NO_CONTENT)
}

async fn validate_policy_candidate(
    state: &AppState,
    application_id: Uuid,
    organization_id: Uuid,
    schema_source: &str,
    policies: &Value,
    entities: &Value,
) -> Result<()> {
    policy::validate_workspace(schema_source, policies, entities)?;
    let references = policy::iam_policy_references(policies)?;
    let missing_groups = state
        .db
        .missing_group_keys(organization_id, &references.group_keys)
        .await?;
    let missing_roles = state
        .db
        .missing_application_role_keys(application_id, &references.role_keys)
        .await?;
    if !missing_groups.is_empty() || !missing_roles.is_empty() {
        return Err(ApiError::validation(
            "Cedar policies reference unknown managed entities",
            json!({
                "groups": missing_groups,
                "roles": missing_roles,
            }),
        ));
    }
    if !references.is_empty()
        || state
            .db
            .application_has_role_assignments(application_id)
            .await?
    {
        iam::validate_schema_contract(schema_source)?;
    }
    Ok(())
}
