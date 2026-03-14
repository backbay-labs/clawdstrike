use std::net::SocketAddr;

use clawdstrike_brokerd::{api::create_router, config::Config, state::AppState};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt::init();

    let config = Config::from_env()?;
    let listen = config.listen.parse::<SocketAddr>()?;
    let state = AppState::from_config(config)?;
    let listener = tokio::net::TcpListener::bind(listen).await?;

    tracing::info!(addr = %listen, "clawdstrike-brokerd listening");
    axum::serve(listener, create_router(state)).await?;
    Ok(())
}
