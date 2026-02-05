//! Daemon connection commands

use serde::{Deserialize, Serialize};
use tauri::State;

use crate::state::AppState;

#[derive(Debug, Serialize, Deserialize)]
pub struct DaemonInfo {
    pub connected: bool,
    pub version: Option<String>,
    pub policy_hash: Option<String>,
    pub uptime_secs: Option<u64>,
}

#[derive(Debug, Deserialize)]
struct HealthResponse {
    version: Option<String>,
    policy_hash: Option<String>,
    uptime_secs: Option<u64>,
}

/// Test connection to a daemon URL
#[tauri::command]
pub async fn test_connection(url: String, state: State<'_, AppState>) -> Result<DaemonInfo, String> {
    let health_url = format!("{}/health", url.trim_end_matches('/'));

    let response = state
        .http_client
        .get(&health_url)
        .send()
        .await
        .map_err(|e| format!("Connection failed: {}", e))?;

    if !response.status().is_success() {
        return Err(format!("Daemon returned status {}", response.status()));
    }

    let health: HealthResponse = response
        .json()
        .await
        .map_err(|e| format!("Failed to parse response: {}", e))?;

    // Update connection state
    {
        let mut daemon = state.daemon.write().await;
        daemon.url = url;
        daemon.connected = true;
        daemon.version = health.version.clone();
        daemon.policy_hash = health.policy_hash.clone();
    }

    Ok(DaemonInfo {
        connected: true,
        version: health.version,
        policy_hash: health.policy_hash,
        uptime_secs: health.uptime_secs,
    })
}

/// Get current daemon connection status
#[tauri::command]
pub async fn get_daemon_status(state: State<'_, AppState>) -> Result<DaemonInfo, String> {
    let daemon = state.daemon.read().await;

    if !daemon.connected {
        return Ok(DaemonInfo {
            connected: false,
            version: None,
            policy_hash: None,
            uptime_secs: None,
        });
    }

    // Check if still connected
    let health_url = format!("{}/health", daemon.url.trim_end_matches('/'));
    drop(daemon); // Release read lock

    match state.http_client.get(&health_url).send().await {
        Ok(response) if response.status().is_success() => {
            let health: HealthResponse = response
                .json()
                .await
                .map_err(|e| format!("Failed to parse response: {}", e))?;

            Ok(DaemonInfo {
                connected: true,
                version: health.version,
                policy_hash: health.policy_hash,
                uptime_secs: health.uptime_secs,
            })
        }
        _ => {
            // Mark as disconnected
            let mut daemon = state.daemon.write().await;
            daemon.connected = false;

            Ok(DaemonInfo {
                connected: false,
                version: None,
                policy_hash: None,
                uptime_secs: None,
            })
        }
    }
}
