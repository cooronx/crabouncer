use std::sync::Arc;

use axum::{
    Extension, Json, Router,
    extract::{Path, State},
    http::StatusCode,
    routing::{get, post},
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
    policy,
};

use super::{
    access::audit_event,
    applications::{manage_application, view_application},
};

pub(super) fn routes() -> Router<Arc<AppState>> {
    Router::new()
        .route(
            "/api/v1/applications/{id}/workspace",
            get(get_workspace).put(update_workspace),
        )
        .route(
            "/api/v1/applications/{id}/workspace/validate",
            post(validate_workspace),
        )
        .route(
            "/api/v1/applications/{id}/workspace/simulate",
            post(simulate_workspace),
        )
        .route(
            "/api/v1/applications/{id}/releases",
            get(list_releases).post(publish_release),
        )
        .route(
            "/api/v1/applications/{id}/releases/{release_id}/activate",
            post(activate_release),
        )
}

async fn get_workspace(
    State(state): State<Arc<AppState>>,
    Extension(current): Extension<Actor>,
    Path(id): Path<Uuid>,
) -> Result<Json<Workspace>> {
    view_application(&state, &current, id).await?;
    Ok(Json(state.db.workspace(id).await?))
}

#[derive(Deserialize)]
struct WorkspaceInput {
    schema_source: String,
    policies: Value,
    entities: Value,
}

async fn update_workspace(
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

async fn validate_workspace(
    State(state): State<Arc<AppState>>,
    Extension(current): Extension<Actor>,
    Path(id): Path<Uuid>,
) -> Result<Json<Value>> {
    view_application(&state, &current, id).await?;
    let snapshot: PolicySnapshot = state.db.policy_snapshot(id).await?;
    policy::validate_workspace(
        &snapshot.schema_source,
        &snapshot.policies,
        &snapshot.entities,
    )?;
    Ok(Json(json!({ "valid": true })))
}

async fn simulate_workspace(
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

async fn list_releases(
    State(state): State<Arc<AppState>>,
    Extension(current): Extension<Actor>,
    Path(id): Path<Uuid>,
) -> Result<Json<Vec<Release>>> {
    view_application(&state, &current, id).await?;
    Ok(Json(state.db.releases(id).await?))
}

async fn publish_release(
    State(state): State<Arc<AppState>>,
    Extension(current): Extension<Actor>,
    Path(id): Path<Uuid>,
) -> Result<(StatusCode, Json<Value>)> {
    let application = manage_application(&state, &current, id).await?;
    let snapshot: PolicySnapshot = state.db.policy_snapshot(id).await?;
    policy::validate_workspace(
        &snapshot.schema_source,
        &snapshot.policies,
        &snapshot.entities,
    )?;
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

async fn activate_release(
    State(state): State<Arc<AppState>>,
    Extension(current): Extension<Actor>,
    Path((id, release_id)): Path<(Uuid, Uuid)>,
) -> Result<StatusCode> {
    let application = manage_application(&state, &current, id).await?;
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
