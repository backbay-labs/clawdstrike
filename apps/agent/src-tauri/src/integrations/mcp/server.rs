//! MCP JSON-RPC server lifecycle (bind, serve, shutdown).

use super::rpc::handle_rpc;
use crate::session::SessionManager;
use crate::settings::Settings;
use anyhow::{Context, Result};
use axum::extract::DefaultBodyLimit;
use axum::{routing::post, Router};
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::TcpListener;
use tokio::sync::{broadcast, RwLock};

/// MCP server for AI tool integrations.
pub struct McpServer {
    port: u16,
    settings: Arc<RwLock<Settings>>,
    session_manager: Arc<SessionManager>,
    auth_token: String,
}

impl McpServer {
    /// Create a new MCP server.
    pub fn new(
        port: u16,
        settings: Arc<RwLock<Settings>>,
        session_manager: Arc<SessionManager>,
        auth_token: String,
    ) -> Self {
        Self {
            port,
            settings,
            session_manager,
            auth_token,
        }
    }

    /// Start the MCP server.
    pub async fn start(self, mut shutdown_rx: broadcast::Receiver<()>) -> Result<()> {
        let state = McpState {
            settings: self.settings,
            session_manager: self.session_manager,
            http_client: reqwest::Client::new(),
            auth_token: self.auth_token,
        };

        let app = Router::new()
            .route("/", post(handle_rpc))
            .route("/rpc", post(handle_rpc))
            .route("/mcp", post(handle_rpc))
            .layer(DefaultBodyLimit::max(128 * 1024))
            .with_state(Arc::new(state));

        let addr = SocketAddr::from(([127, 0, 0, 1], self.port));
        let listener = TcpListener::bind(addr)
            .await
            .with_context(|| format!("Failed to bind MCP server to {}", addr))?;

        tracing::info!("MCP server listening on {}", addr);

        axum::serve(listener, app)
            .with_graceful_shutdown(async move {
                let _ = shutdown_rx.recv().await;
                tracing::info!("MCP server shutting down");
            })
            .await
            .with_context(|| "MCP server error")?;

        Ok(())
    }
}

/// Shared state for MCP handlers.
pub(super) struct McpState {
    pub(super) settings: Arc<RwLock<Settings>>,
    pub(super) session_manager: Arc<SessionManager>,
    pub(super) http_client: reqwest::Client,
    pub(super) auth_token: String,
}

/// Get MCP server configuration for Claude Code/Cursor.
#[cfg(test)]
pub(super) fn get_mcp_config(port: u16) -> serde_json::Value {
    serde_json::json!({
        "mcpServers": {
            "clawdstrike": {
                "url": format!("http://127.0.0.1:{}", port),
                "tools": ["policy_check"]
            }
        }
    })
}
