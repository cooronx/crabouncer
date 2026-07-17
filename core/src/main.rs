mod authzen;
mod config;
mod db;
mod error;
mod management;
mod oidc;
mod policy;
mod security;

use std::sync::Arc;

use axum::{Router, routing::get};
use config::Config;
use sqlx::{PgPool, postgres::PgPoolOptions};
use tower_http::{
    request_id::{MakeRequestUuid, PropagateRequestIdLayer, SetRequestIdLayer},
    trace::TraceLayer,
};
use tracing_subscriber::EnvFilter;

pub(crate) struct AppState {
    pool: PgPool,
    db: db::Database,
    config: Config,
    keys: security::SigningKeys,
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| "info,tower_http=info".into()),
        )
        .init();
    if let Err(error) = run().await {
        tracing::error!(%error, "server stopped");
        std::process::exit(1);
    }
}

async fn run() -> Result<(), Box<dyn std::error::Error>> {
    let config = Config::load()?;
    let pool = PgPoolOptions::new()
        .max_connections(config.database.max_connections)
        .connect(&config.database.url)
        .await?;
    sqlx::migrate!().run(&pool).await?;
    let keys = security::SigningKeys::load(&config.tokens)?;
    security::bootstrap(&pool, &config).await?;
    let bind = config.server.bind;
    let db = db::Database::new(pool.clone());
    let state = Arc::new(AppState {
        pool,
        db,
        config,
        keys,
    });
    let request_id = axum::http::HeaderName::from_static("x-request-id");
    let app = Router::new()
        .route("/health", get(|| async { "ok" }))
        .merge(management::routes())
        .merge(oidc::routes())
        .merge(authzen::routes())
        .with_state(state)
        .layer(PropagateRequestIdLayer::new(request_id.clone()))
        .layer(SetRequestIdLayer::new(request_id, MakeRequestUuid))
        .layer(TraceLayer::new_for_http());
    let listener = tokio::net::TcpListener::bind(bind).await?;
    tracing::info!(%bind, "Crabouncer listening");
    axum::serve(listener, app).await?;
    Ok(())
}
