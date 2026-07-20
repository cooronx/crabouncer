mod evaluations;
mod metadata;

use std::sync::Arc;

use axum::{
    Router,
    routing::{get, post},
};

use crate::AppState;

pub(super) fn routes() -> Router<Arc<AppState>> {
    Router::new()
        .route(
            "/.well-known/authzen-configuration",
            get(metadata::metadata),
        )
        .route("/access/v1/evaluation", post(evaluations::evaluate_one))
        .route("/access/v1/evaluations", post(evaluations::evaluate_many))
}
