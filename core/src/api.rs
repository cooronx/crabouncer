mod authzen;
mod management;
mod oidc;
mod resource_sync;

use std::sync::Arc;

use axum::{Router, routing::get};

use crate::AppState;

pub(crate) fn routes(state: Arc<AppState>) -> Router {
    Router::new()
        .route("/health", get(|| async { "ok" }))
        .merge(management::routes(state.clone()))
        .merge(oidc::routes())
        .merge(authzen::routes())
        .merge(resource_sync::routes())
        .with_state(state)
}
