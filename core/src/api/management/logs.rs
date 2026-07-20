use std::sync::Arc;

use axum::{
    Extension, Json,
    extract::{Path, Query, State},
};
use serde::Deserialize;
use serde_json::Value;
use uuid::Uuid;

use crate::{AppState, db::Actor, error::Result};

use super::access::can_view;

#[derive(Deserialize, Default)]
pub(super) struct LogQuery {
    limit: Option<i64>,
}

pub(super) async fn list_decision_logs(
    State(state): State<Arc<AppState>>,
    Extension(current): Extension<Actor>,
    Path(id): Path<Uuid>,
    Query(query): Query<LogQuery>,
) -> Result<Json<Vec<Value>>> {
    can_view(&current, id)?;
    let limit = query.limit.unwrap_or(100).clamp(1, 500);
    Ok(Json(state.db.decision_logs(id, limit).await?))
}

pub(super) async fn list_audit_logs(
    State(state): State<Arc<AppState>>,
    Extension(current): Extension<Actor>,
    Path(id): Path<Uuid>,
    Query(query): Query<LogQuery>,
) -> Result<Json<Vec<Value>>> {
    can_view(&current, id)?;
    let limit = query.limit.unwrap_or(100).clamp(1, 500);
    Ok(Json(state.db.audit_logs(id, limit).await?))
}
