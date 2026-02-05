//! Policy check commands

use serde::{Deserialize, Serialize};
use tauri::State;

use crate::state::AppState;

#[derive(Debug, Serialize, Deserialize)]
pub struct CheckRequest {
    pub policy_ref: String,
    pub action_type: String,
    pub target: String,
    pub content: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct CheckResponse {
    pub allowed: bool,
    pub guard: Option<String>,
    pub severity: Option<String>,
    pub message: Option<String>,
    pub suggestion: Option<String>,
}

#[derive(Debug, Deserialize)]
struct ApiCheckResponse {
    allowed: bool,
    guard: Option<String>,
    severity: Option<String>,
    message: Option<String>,
}

/// Check an action against a policy
#[tauri::command]
pub async fn policy_check(
    _policy_ref: String,
    action_type: String,
    target: String,
    content: Option<String>,
    state: State<'_, AppState>,
) -> Result<CheckResponse, String> {
    let daemon = state.daemon.read().await;

    if !daemon.connected {
        return Err("Not connected to daemon".to_string());
    }

    let check_url = format!("{}/api/v1/check", daemon.url.trim_end_matches('/'));

    let body = serde_json::json!({
        "action_type": action_type,
        "target": target,
        "content": content,
    });

    let response = state
        .http_client
        .post(&check_url)
        .json(&body)
        .send()
        .await
        .map_err(|e| format!("Request failed: {}", e))?;

    if !response.status().is_success() {
        let status = response.status();
        let text = response.text().await.unwrap_or_default();
        return Err(format!("Check failed with status {}: {}", status, text));
    }

    let check: ApiCheckResponse = response
        .json()
        .await
        .map_err(|e| format!("Failed to parse response: {}", e))?;

    Ok(CheckResponse {
        allowed: check.allowed,
        guard: check.guard,
        severity: check.severity,
        message: check.message.clone(),
        suggestion: if !check.allowed {
            check.message.map(|m| format!("Consider: {}", m))
        } else {
            None
        },
    })
}
