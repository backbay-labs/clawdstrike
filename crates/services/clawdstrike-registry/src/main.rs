#![cfg_attr(test, allow(clippy::expect_used, clippy::unwrap_used))]

use std::net::SocketAddr;

use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

mod api;
mod attestation;
mod auth;
mod config;
mod db;
mod error;
mod index;
mod keys;
mod oidc;
mod state;
mod storage;

use config::Config;
use state::AppState;

fn bind_addr(host: &str, port: u16) -> anyhow::Result<SocketAddr> {
    Ok(format!("{host}:{port}").parse()?)
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::registry()
        .with(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "clawdstrike_registry=info,tower_http=info".into()),
        )
        .with(tracing_subscriber::fmt::layer())
        .init();

    let config = Config::from_env()?;
    let port = config.port;
    let host = config.host.clone();

    let state = AppState::new(config)?;

    let app = api::create_router(state);

    let addr = bind_addr(&host, port)?;
    tracing::info!(%addr, "Starting clawdstrike-registry");

    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, app.into_make_service()).await?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bind_addr_parses_valid_input() {
        let addr = bind_addr("127.0.0.1", 3100).unwrap();
        assert_eq!(addr.to_string(), "127.0.0.1:3100");
    }

    #[test]
    fn bind_addr_rejects_invalid_host() {
        let err = bind_addr("bad host", 3100).unwrap_err();
        assert!(err.to_string().contains("invalid"));
    }
}
