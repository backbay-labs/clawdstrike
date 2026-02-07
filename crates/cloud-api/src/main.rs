#![cfg_attr(test, allow(clippy::expect_used, clippy::unwrap_used))]
// Scaffold crate: many types/services are defined but not yet fully wired into routes.
#![allow(dead_code)]

mod auth;
mod config;
mod db;
mod error;
mod models;
mod routes;
mod services;
mod state;

use std::process::ExitCode;

use tower_http::cors::CorsLayer;
use tower_http::trace::TraceLayer;
use tracing_subscriber::EnvFilter;

use crate::config::Config;
use crate::services::alerter::AlerterService;
use crate::services::metering::MeteringService;
use crate::services::retention::RetentionService;
use crate::services::tenant_provisioner::TenantProvisioner;
use crate::state::AppState;

#[tokio::main]
async fn main() -> ExitCode {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()))
        .init();

    if let Err(e) = run().await {
        tracing::error!(error = %e, "Fatal error");
        return ExitCode::FAILURE;
    }
    ExitCode::SUCCESS
}

async fn run() -> Result<(), Box<dyn std::error::Error>> {
    let config = Config::from_env()?;
    tracing::info!(addr = %config.listen_addr, "Starting ClawdStrike Cloud API");

    // Connect to PostgreSQL
    let pool = db::create_pool(&config.database_url).await?;
    tracing::info!("Connected to PostgreSQL");

    // Connect to NATS
    let nats = async_nats::connect(&config.nats_url).await?;
    tracing::info!(url = %config.nats_url, "Connected to NATS");

    // Initialize services
    let provisioner = TenantProvisioner::new(pool.clone(), config.nats_url.clone());
    let metering = MeteringService::new(pool.clone());
    let alerter = AlerterService::new(pool.clone());
    let retention = RetentionService::new(pool.clone());

    let state = AppState {
        config: config.clone(),
        db: pool,
        nats,
        provisioner,
        metering,
        alerter,
        retention,
    };

    let app = routes::router(state)
        .layer(TraceLayer::new_for_http())
        .layer(CorsLayer::permissive());

    let listener = tokio::net::TcpListener::bind(config.listen_addr).await?;
    tracing::info!(addr = %config.listen_addr, "Listening");

    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await?;

    tracing::info!("Shut down cleanly");
    Ok(())
}

async fn shutdown_signal() {
    tokio::signal::ctrl_c()
        .await
        .ok();
    tracing::info!("Received shutdown signal");
}
