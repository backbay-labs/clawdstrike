//! Application state management

use std::sync::Arc;
use tokio::sync::RwLock;

use crate::marketplace_discovery::MarketplaceDiscoveryManager;

/// Daemon connection information
#[derive(Debug, Clone, Default)]
pub struct DaemonConnection {
    pub url: String,
    pub connected: bool,
    pub version: Option<String>,
    pub policy_hash: Option<String>,
}

/// Application state shared across commands
pub struct AppState {
    pub daemon: Arc<RwLock<DaemonConnection>>,
    pub http_client: reqwest::Client,
    pub marketplace_discovery: MarketplaceDiscoveryManager,
}

impl AppState {
    pub fn new() -> Self {
        Self {
            daemon: Arc::new(RwLock::new(DaemonConnection {
                url: "http://localhost:9876".to_string(),
                ..Default::default()
            })),
            http_client: reqwest::Client::builder()
                .timeout(std::time::Duration::from_secs(10))
                .build()
                .expect("Failed to create HTTP client"),
            marketplace_discovery: MarketplaceDiscoveryManager::new(),
        }
    }
}

impl Default for AppState {
    fn default() -> Self {
        Self::new()
    }
}
