//! Shared policy-check gate for hook/API/MCP paths.

use crate::settings::Settings;
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

fn normalize_policy_check_input(mut input: PolicyCheckInput) -> PolicyCheckInput {
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
        "file_access" | "file_write" | "egress" | "shell" | "mcp_tool" | "patch" => {
            action_type_raw
        }
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
) -> PolicyCheckOutput {
    let input = normalize_policy_check_input(input);
    let (enforced, daemon_url, api_key, include_error_body) = {
        let settings_guard = settings.read().await;
        (
            settings_guard.enabled,
            settings_guard.daemon_url(),
            settings_guard.api_key.clone(),
            settings_guard.debug_include_daemon_error_body,
        )
    };

    if !enforced {
        tracing::info!(
            action_type = %input.action_type,
            target = %input.target,
            "Policy check bypassed because enforcement is disabled"
        );
        return PolicyCheckOutput {
            allowed: true,
            guard: Some("enforcement_disabled".to_string()),
            severity: Some("info".to_string()),
            message: Some("Policy enforcement disabled by operator".to_string()),
            details: Some(serde_json::json!({ "reason": "enforcement_disabled" })),
        };
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
            return PolicyCheckOutput {
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
            };
        }
    };

    if !response.status().is_success() {
        let status = response.status();
        let (body_preview, body_truncated) = if include_error_body {
            let body_text = response.text().await.unwrap_or_default();
            let (preview, truncated) = truncate_bytes(&body_text, 4 * 1024);
            (Some(preview), Some(truncated))
        } else {
            (None, None)
        };

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
                "policy_request_error",
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

        let mut details = serde_json::json!({
            "reason": guard,
            "provenance": { "mode": "offline_deny" },
            "http_status": status.as_u16(),
        });
        if let Some(preview) = body_preview {
            details["body"] = serde_json::Value::String(preview);
        }
        if let Some(truncated) = body_truncated {
            details["body_truncated"] = serde_json::Value::Bool(truncated);
        }

        return PolicyCheckOutput {
            allowed: false,
            guard: Some(guard.to_string()),
            severity: Some(severity.to_string()),
            message: Some(format!(
                "{} ({}) — action denied (fail-closed)",
                reason_prefix, status
            )),
            details: Some(details),
        };
    }

    let status = response.status();
    let body_text = response.text().await.unwrap_or_default();

    match serde_json::from_str::<PolicyCheckOutput>(&body_text) {
        Ok(payload) => payload,
        Err(err) => {
            tracing::warn!(
                action_type = %input.action_type,
                target = %input.target,
                http_status = %status,
                error = %err,
                "hushd returned malformed policy response — denying action"
            );

            let (body_preview, body_truncated) = if include_error_body {
                let (preview, truncated) = truncate_bytes(&body_text, 4 * 1024);
                (Some(preview), Some(truncated))
            } else {
                (None, None)
            };

            let mut details = serde_json::json!({
                "reason": "hushd_parse_error",
                "provenance": { "mode": "offline_deny" },
                "http_status": status.as_u16(),
                "error": err.to_string(),
            });
            if let Some(preview) = body_preview {
                details["body"] = serde_json::Value::String(preview);
            }
            if let Some(truncated) = body_truncated {
                details["body_truncated"] = serde_json::Value::Bool(truncated);
            }

            PolicyCheckOutput {
                allowed: false,
                guard: Some("hushd_parse_error".to_string()),
                severity: Some("critical".to_string()),
                message: Some(
                    "Policy daemon returned malformed response — action denied (fail-closed)"
                        .to_string(),
                ),
                details: Some(details),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{http::StatusCode, routing::post, Router};
    use std::sync::Arc;
    use tokio::sync::RwLock;
    use tokio::net::TcpListener;

    #[test]
    fn normalizes_action_type_aliases() {
        let input = PolicyCheckInput {
            action_type: "exec".to_string(),
            target: "echo hi".to_string(),
            content: None,
            args: None,
        };
        let normalized = normalize_policy_check_input(input);
        assert_eq!(normalized.action_type, "shell");

        let input = PolicyCheckInput {
            action_type: "network".to_string(),
            target: "example.com".to_string(),
            content: None,
            args: None,
        };
        let normalized = normalize_policy_check_input(input);
        assert_eq!(normalized.action_type, "egress");
        assert_eq!(normalized.target, "example.com");

        let input = PolicyCheckInput {
            action_type: "MCP_TOOL".to_string(),
            target: "tool".to_string(),
            content: None,
            args: None,
        };
        let normalized = normalize_policy_check_input(input);
        assert_eq!(normalized.action_type, "mcp_tool");

        let input = PolicyCheckInput {
            action_type: "CUSTOM_ACTION".to_string(),
            target: "x".to_string(),
            content: None,
            args: None,
        };
        let normalized = normalize_policy_check_input(input);
        assert_eq!(normalized.action_type, "custom_action");
    }

    #[test]
    fn normalizes_file_alias_to_access_vs_write() {
        let input = PolicyCheckInput {
            action_type: "file".to_string(),
            target: "/tmp/a.txt".to_string(),
            content: None,
            args: None,
        };
        let normalized = normalize_policy_check_input(input);
        assert_eq!(normalized.action_type, "file_access");

        let input = PolicyCheckInput {
            action_type: "file".to_string(),
            target: "/tmp/a.txt".to_string(),
            content: Some("hello".to_string()),
            args: None,
        };
        let normalized = normalize_policy_check_input(input);
        assert_eq!(normalized.action_type, "file_write");
    }

    #[test]
    fn normalizes_egress_url_target_to_host_port() {
        let input = PolicyCheckInput {
            action_type: "egress".to_string(),
            target: "https://example.com/foo".to_string(),
            content: None,
            args: None,
        };
        let normalized = normalize_policy_check_input(input);
        assert_eq!(normalized.action_type, "egress");
        assert_eq!(normalized.target, "example.com:443");

        let input = PolicyCheckInput {
            action_type: "network".to_string(),
            target: "http://example.com:8080/path".to_string(),
            content: None,
            args: None,
        };
        let normalized = normalize_policy_check_input(input);
        assert_eq!(normalized.action_type, "egress");
        assert_eq!(normalized.target, "example.com:8080");
    }

    #[test]
    fn normalizes_egress_ipv6_url_target_to_bracketed_host_port() {
        let input = PolicyCheckInput {
            action_type: "egress".to_string(),
            target: "https://[::1]:8443/".to_string(),
            content: None,
            args: None,
        };
        let normalized = normalize_policy_check_input(input);
        assert_eq!(normalized.target, "[::1]:8443");
    }

    async fn start_test_check_server(status: StatusCode, body: &'static str) -> u16 {
        let app = Router::new().route(
            "/api/v1/check",
            post(move || async move { (status, body) }),
        );

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        port
    }

    #[tokio::test]
    async fn daemon_error_body_is_omitted_by_default() {
        let port =
            start_test_check_server(StatusCode::BAD_REQUEST, "SENSITIVE_INTERNAL_ERROR").await;

        let mut s = Settings::default();
        s.daemon_port = port;
        s.enabled = true;
        s.debug_include_daemon_error_body = false;
        let settings = Arc::new(RwLock::new(s));

        let out = evaluate_policy_check(
            settings,
            &reqwest::Client::new(),
            PolicyCheckInput {
                action_type: "file_access".to_string(),
                target: "/tmp/a.txt".to_string(),
                content: None,
                args: None,
            },
            None,
        )
        .await;

        assert!(!out.allowed);
        let details = out.details.expect("details should be present");
        assert!(details.get("http_status").is_some());
        assert!(details.get("body").is_none());
        assert!(details.get("body_truncated").is_none());
        assert_eq!(out.guard.as_deref(), Some("policy_request_error"));
    }

    #[tokio::test]
    async fn daemon_error_body_is_included_when_debug_enabled() {
        let port =
            start_test_check_server(StatusCode::BAD_REQUEST, "SENSITIVE_INTERNAL_ERROR").await;

        let mut s = Settings::default();
        s.daemon_port = port;
        s.enabled = true;
        s.debug_include_daemon_error_body = true;
        let settings = Arc::new(RwLock::new(s));

        let out = evaluate_policy_check(
            settings,
            &reqwest::Client::new(),
            PolicyCheckInput {
                action_type: "file_access".to_string(),
                target: "/tmp/a.txt".to_string(),
                content: None,
                args: None,
            },
            None,
        )
        .await;

        assert!(!out.allowed);
        let details = out.details.expect("details should be present");
        assert_eq!(details.get("http_status").and_then(|v| v.as_u64()), Some(400));
        assert_eq!(
            details.get("body").and_then(|v| v.as_str()),
            Some("SENSITIVE_INTERNAL_ERROR")
        );
        assert_eq!(
            details.get("body_truncated").and_then(|v| v.as_bool()),
            Some(false)
        );
    }
}
