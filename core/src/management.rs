mod access;
mod applications;
mod logs;
mod organizations;
mod policies;
mod sessions;
mod validation;

use std::sync::Arc;

use axum::{Router, middleware};

use crate::AppState;

pub(crate) use access::session_actor;

pub(crate) fn routes(state: Arc<AppState>) -> Router<Arc<AppState>> {
    let protected =
        protected_routes().route_layer(middleware::from_fn_with_state(state, access::authenticate));

    Router::new()
        .merge(sessions::public_routes())
        .merge(protected)
}

fn protected_routes() -> Router<Arc<AppState>> {
    Router::new()
        .merge(sessions::protected_routes())
        .merge(organizations::routes())
        .merge(applications::routes())
        .merge(policies::routes())
        .merge(logs::routes())
}
