use std::sync::Arc;

use axum::{
    Extension, Json, Router,
    extract::{Path, Query, State},
    routing::get,
};
use serde::Deserialize;
use serde_json::Value;
use uuid::Uuid;

use crate::{AppState, db::Actor, error::Result};

use super::access::can_view;

pub(super) fn routes() -> Router<Arc<AppState>> {
    Router::new()
        .route(
            "/api/v1/organizations/{id}/decision-logs",
            get(list_decision_logs),
        )
        .route(
            "/api/v1/organizations/{id}/audit-logs",
            get(list_audit_logs),
        )
}

#[derive(Deserialize, Default)]
struct LogQuery {
    limit: Option<i64>,
}

async fn list_decision_logs(
    State(state): State<Arc<AppState>>,
    Extension(current): Extension<Actor>,
    Path(id): Path<Uuid>,
    Query(query): Query<LogQuery>,
) -> Result<Json<Vec<Value>>> {
    can_view(&current, id)?;
    let limit = query.limit.unwrap_or(100).clamp(1, 500);
    Ok(Json(state.db.decision_logs(id, limit).await?))
}

async fn list_audit_logs(
    State(state): State<Arc<AppState>>,
    Extension(current): Extension<Actor>,
    Path(id): Path<Uuid>,
    Query(query): Query<LogQuery>,
) -> Result<Json<Vec<Value>>> {
    can_view(&current, id)?;
    let limit = query.limit.unwrap_or(100).clamp(1, 500);
    Ok(Json(state.db.audit_logs(id, limit).await?))
}
