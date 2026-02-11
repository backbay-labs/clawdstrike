//! Policy-related commands for editor + tester surfaces.

use serde::{Deserialize, Serialize};
use tauri::State;

use crate::state::AppState;

#[allow(dead_code)]
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

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicySource {
    pub kind: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub path_exists: Option<bool>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicySchemaInfo {
    pub current: String,
    pub supported: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyLoadResponse {
    pub name: String,
    pub version: String,
    pub description: String,
    pub policy_hash: String,
    pub yaml: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source: Option<PolicySource>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub schema: Option<PolicySchemaInfo>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidationIssue {
    pub path: String,
    pub code: String,
    pub message: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyValidateResponse {
    pub valid: bool,
    pub errors: Vec<ValidationIssue>,
    pub warnings: Vec<ValidationIssue>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub normalized_version: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicySaveResponse {
    pub success: bool,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub policy_hash: Option<String>,
}

async fn daemon_base_url(state: &State<'_, AppState>) -> Result<String, String> {
    let daemon = state.daemon.read().await;
    if !daemon.connected {
        return Err("Not connected to daemon".to_string());
    }
    Ok(daemon.url.trim_end_matches('/').to_string())
}

/// Check a legacy action against active policy.
#[tauri::command]
pub async fn policy_check(
    _policy_ref: String,
    action_type: String,
    target: String,
    content: Option<String>,
    state: State<'_, AppState>,
) -> Result<CheckResponse, String> {
    let base_url = daemon_base_url(&state).await?;
    let check_url = format!("{}/api/v1/check", base_url);
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

/// Load current daemon policy.
#[tauri::command]
pub async fn policy_load(state: State<'_, AppState>) -> Result<PolicyLoadResponse, String> {
    let base_url = daemon_base_url(&state).await?;
    let response = state
        .http_client
        .get(format!("{}/api/v1/policy", base_url))
        .send()
        .await
        .map_err(|e| format!("Request failed: {}", e))?;

    if !response.status().is_success() {
        let status = response.status();
        let text = response.text().await.unwrap_or_default();
        return Err(format!("Policy load failed with status {}: {}", status, text));
    }

    response
        .json::<PolicyLoadResponse>()
        .await
        .map_err(|e| format!("Failed to parse policy response: {}", e))
}

/// Validate policy YAML without activating it.
#[tauri::command]
pub async fn policy_validate(
    yaml: String,
    state: State<'_, AppState>,
) -> Result<PolicyValidateResponse, String> {
    let base_url = daemon_base_url(&state).await?;
    let response = state
        .http_client
        .post(format!("{}/api/v1/policy/validate", base_url))
        .json(&serde_json::json!({ "yaml": yaml }))
        .send()
        .await
        .map_err(|e| format!("Request failed: {}", e))?;

    if !response.status().is_success() {
        let status = response.status();
        let text = response.text().await.unwrap_or_default();
        return Err(format!(
            "Policy validation failed with status {}: {}",
            status, text
        ));
    }

    response
        .json::<PolicyValidateResponse>()
        .await
        .map_err(|e| format!("Failed to parse validation response: {}", e))
}

/// Evaluate a canonical PolicyEvent.
#[tauri::command]
pub async fn policy_eval_event(
    event: serde_json::Value,
    state: State<'_, AppState>,
) -> Result<serde_json::Value, String> {
    let base_url = daemon_base_url(&state).await?;
    let response = state
        .http_client
        .post(format!("{}/api/v1/eval", base_url))
        .json(&event)
        .send()
        .await
        .map_err(|e| format!("Request failed: {}", e))?;

    if !response.status().is_success() {
        let status = response.status();
        let text = response.text().await.unwrap_or_default();
        return Err(format!("Policy eval failed with status {}: {}", status, text));
    }

    response
        .json::<serde_json::Value>()
        .await
        .map_err(|e| format!("Failed to parse eval response: {}", e))
}

/// Save/activate a new policy YAML.
#[tauri::command]
pub async fn policy_save(
    yaml: String,
    state: State<'_, AppState>,
) -> Result<PolicySaveResponse, String> {
    let base_url = daemon_base_url(&state).await?;
    let response = state
        .http_client
        .put(format!("{}/api/v1/policy", base_url))
        .json(&serde_json::json!({ "yaml": yaml }))
        .send()
        .await
        .map_err(|e| format!("Request failed: {}", e))?;

    if !response.status().is_success() {
        let status = response.status();
        let text = response.text().await.unwrap_or_default();
        return Err(format!("Policy save failed with status {}: {}", status, text));
    }

    response
        .json::<PolicySaveResponse>()
        .await
        .map_err(|e| format!("Failed to parse policy save response: {}", e))
}
