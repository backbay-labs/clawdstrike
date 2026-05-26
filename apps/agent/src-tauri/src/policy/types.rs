//! Policy check request/response types and input normalization.

use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::HashMap;

pub(super) fn truncate_bytes(s: &str, max_bytes: usize) -> (String, bool) {
    if s.len() <= max_bytes {
        return (s.to_string(), false);
    }
    let mut end = max_bytes;
    while end > 0 && !s.is_char_boundary(end) {
        end -= 1;
    }
    (format!("{}...[truncated]", &s[..end]), true)
}

pub(super) fn normalize_policy_check_input(mut input: PolicyCheckInput) -> PolicyCheckInput {
    let action_type_raw = input.action_type.trim().to_ascii_lowercase();
    input.action_type = match action_type_raw.as_str() {
        // Friendly aliases used by local hooks/tools.
        "file" => {
            if input.content.is_some() {
                "file_write".to_string()
            } else {
                "file_access".to_string()
            }
        }
        "network" => "egress".to_string(),
        "exec" | "command" => "shell".to_string(),
        // Canonical hushd action types.
        "file_access" | "file_write" | "egress" | "shell" | "mcp_tool" | "patch" => action_type_raw,
        // Unknown: pass through as lowercase so casing differences don't bypass normalization.
        _ => action_type_raw,
    };

    // For egress checks we prefer `host:port` (what hushd expects). If callers pass a URL, parse it.
    if input.action_type == "egress" {
        let target = input.target.trim().to_string();
        // Always trim whitespace, even when the egress form is already `host:port`.
        input.target = target.clone();
        let lower = target.to_ascii_lowercase();
        // Only normalize explicit URL forms. Avoid surprising parses where `Url::parse` treats
        // `example.com:123` as a scheme and accidentally rewrites the target.
        if lower.starts_with("http://")
            || lower.starts_with("https://")
            || lower.starts_with("ws://")
            || lower.starts_with("wss://")
        {
            if let Ok(url) = reqwest::Url::parse(&target) {
                if let (Some(host), Some(port)) = (url.host_str(), url.port_or_known_default()) {
                    let host = host
                        .strip_prefix('[')
                        .and_then(|h| h.strip_suffix(']'))
                        .unwrap_or(host);
                    let host_port = if host.contains(':') {
                        format!("[{}]:{}", host, port)
                    } else {
                        format!("{}:{}", host, port)
                    };
                    input.target = host_port;
                }
            }
        }
    }

    input
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
    /// Legacy endpoint identifier field accepted from older integrations.
    #[serde(default)]
    pub agent_id: Option<String>,
    /// Canonical endpoint agent identifier.
    #[serde(default)]
    pub endpoint_agent_id: Option<String>,
    #[serde(default)]
    pub runtime_agent_id: Option<String>,
    #[serde(default)]
    pub runtime_agent_kind: Option<String>,
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
