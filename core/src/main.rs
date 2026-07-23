mod api;
mod config;
mod db;
mod error;
mod iam;
mod policy;
mod security;

use std::sync::Arc;

use config::Config;
use tower_http::{
    request_id::{MakeRequestUuid, PropagateRequestIdLayer, SetRequestIdLayer},
    trace::TraceLayer,
};
use tracing_subscriber::EnvFilter;

pub(crate) struct AppState {
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
    let db = db::Database::connect(&config.database.url, config.database.max_connections).await?;
    db.migrate().await?;
    let keys = security::SigningKeys::load(&config.tokens)?;
    security::bootstrap(&db, &config).await?;
    let bind = config.server.bind;
    let state = Arc::new(AppState { db, config, keys });
    let request_id = axum::http::HeaderName::from_static("x-request-id");
    let app = api::routes(state)
        .layer(PropagateRequestIdLayer::new(request_id.clone()))
        .layer(SetRequestIdLayer::new(request_id, MakeRequestUuid))
        .layer(TraceLayer::new_for_http());
    let listener = tokio::net::TcpListener::bind(bind).await?;
    tracing::info!(%bind, "Crabouncer listening");
    axum::serve(listener, app).await?;
    Ok(())
}
