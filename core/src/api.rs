mod authzen;
mod management;
mod oidc;

use std::sync::Arc;

use axum::{Router, routing::get};

use crate::AppState;

pub(crate) fn routes(state: Arc<AppState>) -> Router {
    Router::new()
        .route("/health", get(|| async { "ok" }))
        .merge(management::routes(state.clone()))
        .merge(oidc::routes())
        .merge(authzen::routes())
        .with_state(state)
}
