mod authorization;
mod metadata;
mod sessions;
mod tokens;

use std::sync::Arc;

use axum::{
    Router,
    routing::{get, post},
};

use crate::AppState;

pub(super) fn routes() -> Router<Arc<AppState>> {
    Router::new()
        .route(
            "/.well-known/openid-configuration",
            get(metadata::discovery),
        )
        .route("/.well-known/jwks.json", get(metadata::jwks))
        .route("/oauth2/authorize", get(authorization::authorize))
        .route("/oauth2/token", post(tokens::token))
        .route("/oauth2/userinfo", get(sessions::userinfo))
        .route("/oauth2/logout", post(sessions::logout))
}
