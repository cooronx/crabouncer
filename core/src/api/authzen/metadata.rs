use std::sync::Arc;

use axum::{Json, extract::State};
use serde_json::{Value, json};

use crate::AppState;

pub(super) async fn metadata(State(state): State<Arc<AppState>>) -> Json<Value> {
    let base = state.config.server.public_url.trim_end_matches('/');
    Json(json!({
        "policy_decision_point": base,
        "access_evaluation_endpoint": format!("{base}/access/v1/evaluation"),
        "access_evaluations_endpoint": format!("{base}/access/v1/evaluations"),
        "search_subject_endpoint": format!("{base}/access/v1/search/subject"),
        "search_resource_endpoint": format!("{base}/access/v1/search/resource"),
        "search_action_endpoint": format!("{base}/access/v1/search/action")
    }))
}
