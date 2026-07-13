mod api;
mod application;
mod authorization;
mod identity;
mod infra;
mod session;

use std::sync::Arc;

use infra::{config::Config, database};
use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()))
        .init();

    if let Err(error) = run().await {
        tracing::error!(%error, "server stopped");
        std::process::exit(1);
    }
}

async fn run() -> Result<(), Box<dyn std::error::Error>> {
    let config = Config::load()?;
    let pool = database::connect(&config.database_url).await?;
    sqlx::migrate!().run(&pool).await?;
    database::bootstrap(&pool, &config.bootstrap_password).await?;

    let state = Arc::new(api::AppState {
        pool,
        config: config.clone(),
    });
    let listener = tokio::net::TcpListener::bind(config.bind).await?;
    tracing::info!(address = %config.bind, "listening");
    axum::serve(listener, api::router(state)).await?;
    Ok(())
}
