//! Marketplace discovery commands (optional P2P CID gossip).

use tauri::{AppHandle, State};

use crate::marketplace_discovery::{
    MarketplaceDiscoveryAnnouncement, MarketplaceDiscoveryConfig, MarketplaceDiscoveryStatus,
};
use crate::state::AppState;

#[tauri::command]
pub async fn marketplace_discovery_start(
    app: AppHandle,
    config: Option<MarketplaceDiscoveryConfig>,
    state: State<'_, AppState>,
) -> Result<MarketplaceDiscoveryStatus, String> {
    state
        .marketplace_discovery
        .start(app, config.unwrap_or_default())
        .await
}

#[tauri::command]
pub async fn marketplace_discovery_stop(state: State<'_, AppState>) -> Result<(), String> {
    state.marketplace_discovery.stop().await
}

#[tauri::command]
pub async fn marketplace_discovery_status(
    state: State<'_, AppState>,
) -> Result<MarketplaceDiscoveryStatus, String> {
    Ok(state.marketplace_discovery.status().await)
}

#[tauri::command]
pub async fn marketplace_discovery_announce(
    announcement: MarketplaceDiscoveryAnnouncement,
    state: State<'_, AppState>,
) -> Result<(), String> {
    state.marketplace_discovery.announce(announcement).await
}

