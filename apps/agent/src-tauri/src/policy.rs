//! Shared policy-check gate for hook/API/MCP paths.

use crate::settings::Settings;
use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;

fn truncate_bytes(s: &str, max_bytes: usize) -> (String, bool) {
    if s.len() <= max_bytes {
        return (s.to_string(), false);
    }
    let mut end = max_bytes;
    while end > 0 && !s.is_char_boundary(end) {
        end -= 1;
    }
    (format!("{}...[truncated]", &s[..end]), true)
}

/// Policy check request payload.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct PolicyCheckInput {
    pub action_type: String,
    pub target: String,
    #[serde(default)]
    pub content: Option<String>,
    #[serde(default)]
    pub args: Option<HashMap<String, Value>>,
}

/// Policy check response payload.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct PolicyCheckOutput {
    pub allowed: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub guard: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub severity: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub details: Option<Value>,
}

/// Route policy checks through one runtime gate.
pub async fn evaluate_policy_check(
    settings: Arc<RwLock<Settings>>,
    http_client: &reqwest::Client,
    input: PolicyCheckInput,
    session_id: Option<String>,
) -> Result<PolicyCheckOutput> {
    let (enforced, daemon_url, api_key) = {
        let settings_guard = settings.read().await;
        (
            settings_guard.enabled,
            settings_guard.daemon_url(),
            settings_guard.api_key.clone(),
        )
    };

    if !enforced {
        tracing::info!(
            action_type = %input.action_type,
            target = %input.target,
            "Policy check bypassed because enforcement is disabled"
        );
        return Ok(PolicyCheckOutput {
            allowed: true,
            guard: Some("enforcement_disabled".to_string()),
            severity: Some("info".to_string()),
            message: Some("Policy enforcement disabled by operator".to_string()),
            details: Some(serde_json::json!({ "reason": "enforcement_disabled" })),
        });
    }

    let url = format!("{}/api/v1/check", daemon_url);
    let mut body = serde_json::json!({
        "action_type": input.action_type,
        "target": input.target,
        "content": input.content,
        "args": input.args,
    });
    if let Some(sid) = session_id {
        body["session_id"] = serde_json::Value::String(sid);
    }
    let mut request = http_client.post(&url).json(&body);

    if let Some(key) = api_key {
        request = request.header("Authorization", format!("Bearer {}", key));
    }

    let response = match request.send().await {
        Ok(resp) => resp,
        Err(err) => {
            tracing::warn!(
                action_type = %input.action_type,
                target = %input.target,
                error = %err,
                "hushd unreachable — denying action"
            );
            return Ok(PolicyCheckOutput {
                allowed: false,
                guard: Some("hushd_unreachable".to_string()),
                severity: Some("critical".to_string()),
                message: Some(format!(
                    "Policy daemon unreachable at {} — action denied (fail-closed)",
                    daemon_url
                )),
                details: Some(serde_json::json!({
                    "reason": "hushd_unreachable",
                    "provenance": { "mode": "offline_deny" },
                    "error": err.to_string(),
                })),
            });
        }
    };

    if !response.status().is_success() {
        let status = response.status();
        let body_text = response.text().await.unwrap_or_default();
        let (body_preview, body_truncated) = truncate_bytes(&body_text, 4 * 1024);

        let (guard, severity, reason_prefix) = match status.as_u16() {
            401 | 403 => (
                "hushd_auth_error",
                "critical",
                "Policy daemon authentication failed",
            ),
            429 => (
                "hushd_rate_limited",
                "high",
                "Policy daemon rate limit exceeded",
            ),
            400 => (
                "hushd_request_error",
                "high",
                "Policy daemon rejected request",
            ),
            _ => ("hushd_error", "critical", "Policy daemon returned error"),
        };

        tracing::warn!(
            action_type = %input.action_type,
            target = %input.target,
            http_status = %status,
            guard = guard,
            "hushd returned error — denying action"
        );
        return Ok(PolicyCheckOutput {
            allowed: false,
            guard: Some(guard.to_string()),
            severity: Some(severity.to_string()),
            message: Some(format!(
                "{} ({}) — action denied (fail-closed)",
                reason_prefix, status
            )),
            details: Some(serde_json::json!({
                "reason": guard,
                "provenance": { "mode": "offline_deny" },
                "http_status": status.as_u16(),
                "body": body_preview,
                "body_truncated": body_truncated,
            })),
        });
    }

    let payload: PolicyCheckOutput = response
        .json()
        .await
        .with_context(|| "Failed to parse daemon policy response")?;

    Ok(payload)
}
