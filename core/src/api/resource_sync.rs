use std::sync::Arc;

use axum::{Json, Router, extract::State, http::HeaderMap, routing::post};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, json};

use crate::{
    AppState,
    db::{PolicyRelease, ResourceWriteStatus, ServiceAuditEvent},
    error::{ApiError, Result},
    policy,
};

const MAX_OPERATIONS: usize = 500;

pub(super) fn routes() -> Router<Arc<AppState>> {
    Router::new().route("/resource-sync/v1/resources", post(sync_resources))
}

#[derive(Deserialize)]
struct SyncRequest {
    operations: Vec<SyncOperation>,
}

#[derive(Deserialize)]
#[serde(tag = "operation", rename_all = "snake_case")]
enum SyncOperation {
    Upsert {
        #[serde(rename = "type")]
        resource_type: String,
        id: String,
        #[serde(default)]
        properties: Map<String, Value>,
    },
    Delete {
        #[serde(rename = "type")]
        resource_type: String,
        id: String,
    },
}

#[derive(Serialize)]
struct SyncResponse {
    request_id: String,
    results: Vec<SyncResult>,
}

#[derive(Serialize)]
struct SyncResult {
    index: usize,
    status: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    message: Option<String>,
}

async fn sync_resources(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(body): Json<SyncRequest>,
) -> Result<Json<SyncResponse>> {
    if body.operations.is_empty() || body.operations.len() > MAX_OPERATIONS {
        return Err(ApiError::bad_request(
            "operations must contain between 1 and 500 items",
        ));
    }
    let caller = super::authzen::service_caller(&state, &headers, "resources:sync").await?;
    let request_id = super::authzen::request_id(&headers);
    let release: PolicyRelease = state
        .db
        .active_policy_release(caller.application_id)
        .await?
        .ok_or_else(|| {
            ApiError::conflict(
                "no_active_release",
                "An active policy release is required before resources can be synchronized",
            )
        })?;

    let operation_count = body.operations.len();
    let mut results = Vec::with_capacity(operation_count);
    for (index, operation) in body.operations.into_iter().enumerate() {
        results.push(apply_operation(&state, &caller, &release, index, operation).await);
    }
    let successful = results
        .iter()
        .filter(|result| result.message.is_none())
        .count();
    state
        .db
        .record_service_audit(ServiceAuditEvent {
            organization_id: caller.organization_id,
            actor_service_account_id: caller.service_account_id,
            action: "resource_sync.batch".into(),
            target_type: "application".into(),
            target_id: Some(caller.application_id.to_string()),
            details: json!({
                "request_id": request_id,
                "operation_count": operation_count,
                "successful_count": successful,
                "failed_count": operation_count - successful,
            }),
        })
        .await?;

    Ok(Json(SyncResponse {
        request_id,
        results,
    }))
}

async fn apply_operation(
    state: &AppState,
    caller: &crate::db::AuthzenCaller,
    release: &PolicyRelease,
    index: usize,
    operation: SyncOperation,
) -> SyncResult {
    match operation {
        SyncOperation::Upsert {
            resource_type,
            id,
            properties,
        } => {
            let properties = match policy::validate_synced_resource(
                &release.schema_source,
                &resource_type,
                &id,
                &properties,
                caller.organization_id,
            ) {
                Ok(properties) => properties,
                Err(error) => return failed(index, "invalid", error),
            };
            match state
                .db
                .upsert_resource(caller.application_id, &resource_type, &id, &properties)
                .await
            {
                Ok(ResourceWriteStatus::Upserted) => succeeded(index, "upserted"),
                Ok(ResourceWriteStatus::Unchanged) => succeeded(index, "unchanged"),
                Err(error) => failed(index, "error", ApiError::from(error)),
            }
        }
        SyncOperation::Delete { resource_type, id } => {
            if let Err(error) = policy::validate_resource_identity(&resource_type, &id) {
                return failed(index, "invalid", error);
            }
            match state
                .db
                .delete_resource(caller.application_id, &resource_type, &id)
                .await
            {
                Ok(true) => succeeded(index, "deleted"),
                Ok(false) => succeeded(index, "not_found"),
                Err(error) => failed(index, "error", ApiError::from(error)),
            }
        }
    }
}

fn succeeded(index: usize, status: &'static str) -> SyncResult {
    SyncResult {
        index,
        status,
        message: None,
    }
}

fn failed(index: usize, status: &'static str, error: ApiError) -> SyncResult {
    SyncResult {
        index,
        status,
        message: Some(error.to_string()),
    }
}
