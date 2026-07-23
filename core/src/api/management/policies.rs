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
    access::{audit_event, can_manage},
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
    request
        .validate()
        .map_err(|error| ApiError::bad_request(error.to_string()))?;
    let subject = request
        .subject()
        .ok_or_else(|| ApiError::bad_request("subject is required"))?;
    if subject.subject_type() != Some("User") {
        return Err(ApiError::bad_request(
            "Policy simulation requires a User subject",
        ));
    }
    let user_id = subject
        .id()
        .and_then(|id| Uuid::parse_str(id).ok())
        .ok_or_else(|| ApiError::bad_request("subject.id must be a User UUID"))?;
    if current.id != user_id {
        can_manage(&current, application.organization_id)?;
    }
    let resource_type = request
        .resource()
        .and_then(authzen_rs::Resource::resource_type)
        .ok_or_else(|| ApiError::bad_request("resource.type is required"))?;
    iam::validate_business_resource_type(resource_type)?;
    let snapshot: PolicySnapshot = state.db.policy_snapshot(id).await?;
    let Some(identity) = state
        .db
        .authorization_identity(id, application.organization_id, user_id)
        .await?
    else {
        return Ok(Json(
            json!({ "decision": false, "reason": "subject_not_found", "policies": [], "errors": [] }),
        ));
    };
    let projection = iam::project_identity(
        &identity,
        application.organization_id,
        id,
        subject.properties(),
        iam::schema_is_iam_ready(&snapshot.schema_source),
    );
    Ok(Json(policy::evaluate(
        &snapshot.schema_source,
        &snapshot.policies,
        &snapshot.entities,
        &request,
        application.organization_id,
        Some(projection.entities),
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
    let iam_ready = validate_policy_candidate(
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
            iam_ready,
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
    let iam_ready = validate_policy_candidate(
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
        .activate_policy_release(
            id,
            release_id,
            current.id,
            iam_ready,
            AuditEvent {
                organization_id: Some(application.organization_id),
                actor_user_id: current.id,
                action: "policy_release.activate".into(),
                target_type: "policy_release".into(),
                target_id: Some(release_id.to_string()),
                details: json!({}),
            },
        )
        .await?
    {
        return Err(ApiError::not_found("Release"));
    }
    Ok(StatusCode::NO_CONTENT)
}

async fn validate_policy_candidate(
    state: &AppState,
    application_id: Uuid,
    organization_id: Uuid,
    schema_source: &str,
    policies: &Value,
    entities: &Value,
) -> Result<bool> {
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
    let contract = iam::validate_schema_contract(schema_source);
    let iam_ready = contract.is_ok();
    if !references.is_empty()
        || state
            .db
            .application_has_role_assignments(application_id)
            .await?
    {
        contract?;
    }
    Ok(iam_ready)
}
