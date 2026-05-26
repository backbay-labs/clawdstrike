//! Policy-check evaluation: routes a check through the local hushd daemon with fail-closed
//! semantics for offline/error scenarios.

use std::sync::Arc;
use tokio::sync::RwLock;

use crate::runtime_registry::{
    resolve_effective_endpoint_agent_id, resolve_runtime_for_policy_event,
};
use crate::settings::Settings;

use super::audit::enqueue_offline_audit_event;
use super::types::{
    normalize_policy_check_input, truncate_bytes, PolicyCheckInput, PolicyCheckOutput,
};

/// Route policy checks through one runtime gate.
pub async fn evaluate_policy_check(
    settings: Arc<RwLock<Settings>>,
    http_client: &reqwest::Client,
    input: PolicyCheckInput,
    session_id: Option<String>,
    audit_queue: Option<Arc<crate::daemon::AuditQueue>>,
) -> PolicyCheckOutput {
    let input = normalize_policy_check_input(input);
    let (enforced, daemon_url, api_key, include_error_body, endpoint_agent_id, runtime_identity) = {
        let mut settings_guard = settings.write().await;
        let endpoint_agent_id = resolve_effective_endpoint_agent_id(
            &mut settings_guard,
            input
                .endpoint_agent_id
                .as_deref()
                .or(input.agent_id.as_deref()),
        );
        let runtime_identity = match resolve_runtime_for_policy_event(
            &mut settings_guard,
            &endpoint_agent_id,
            input.runtime_agent_id.as_deref(),
            input.runtime_agent_kind.as_deref(),
        ) {
            Ok(value) => value,
            Err(message) => {
                drop(settings_guard);
                return PolicyCheckOutput {
                    allowed: false,
                    guard: Some("invalid_runtime_identity".to_string()),
                    severity: Some("high".to_string()),
                    message: Some(message),
                    details: Some(serde_json::json!({
                        "reason": "invalid_runtime_identity",
                        "provenance": { "mode": "input_validation" }
                    })),
                };
            }
        };
        if let Err(err) = settings_guard.save() {
            tracing::warn!(error = %err, "Failed to persist runtime registry updates");
        }
        (
            settings_guard.enabled,
            settings_guard.daemon_url(),
            settings_guard.api_key.clone(),
            settings_guard.debug_include_daemon_error_body,
            endpoint_agent_id,
            runtime_identity,
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

    let action_type = input.action_type.clone();
    let target = input.target.clone();
    let session_id_for_audit = session_id.clone();
    let url = format!("{}/api/v1/check", daemon_url);
    let mut body = serde_json::json!({
        "action_type": action_type.clone(),
        "target": target.clone(),
        "content": input.content,
        "args": input.args,
        "endpoint_agent_id": endpoint_agent_id.clone(),
    });
    if let Some(sid) = session_id.clone() {
        body["session_id"] = serde_json::Value::String(sid);
    }
    if let Some(runtime_identity) = runtime_identity.as_ref() {
        body["runtime_agent_id"] =
            serde_json::Value::String(runtime_identity.runtime_agent_id.clone());
        body["runtime_agent_kind"] =
            serde_json::Value::String(runtime_identity.runtime_agent_kind.clone());
    }
    let mut request = http_client.post(&url).json(&body);

    if let Some(key) = api_key {
        request = request.header("Authorization", format!("Bearer {}", key));
    }

    let response = match request.send().await {
        Ok(resp) => resp,
        Err(err) => {
            let details = serde_json::json!({
                "reason": "hushd_unreachable",
                "provenance": { "mode": "offline_deny" },
                "error": err.to_string(),
            });
            let message = format!(
                "Policy daemon unreachable at {} — action denied (fail-closed)",
                daemon_url
            );
            enqueue_offline_audit_event(
                audit_queue.as_ref(),
                &action_type,
                &target,
                "hushd_unreachable",
                "critical",
                &message,
                session_id_for_audit.as_deref(),
                &endpoint_agent_id,
                runtime_identity
                    .as_ref()
                    .map(|value| value.runtime_agent_id.as_str()),
                runtime_identity
                    .as_ref()
                    .map(|value| value.runtime_agent_kind.as_str()),
                Some(&details),
            )
            .await;
            tracing::warn!(
                action_type = %action_type,
                target = %target,
                error = %err,
                "hushd unreachable — denying action"
            );
            return PolicyCheckOutput {
                allowed: false,
                guard: Some("hushd_unreachable".to_string()),
                severity: Some("critical".to_string()),
                message: Some(message),
                details: Some(details),
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
            action_type = %action_type,
            target = %target,
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
        let message = format!(
            "{} ({}) — action denied (fail-closed)",
            reason_prefix, status
        );
        enqueue_offline_audit_event(
            audit_queue.as_ref(),
            &action_type,
            &target,
            guard,
            severity,
            &message,
            session_id_for_audit.as_deref(),
            &endpoint_agent_id,
            runtime_identity
                .as_ref()
                .map(|value| value.runtime_agent_id.as_str()),
            runtime_identity
                .as_ref()
                .map(|value| value.runtime_agent_kind.as_str()),
            Some(&details),
        )
        .await;

        return PolicyCheckOutput {
            allowed: false,
            guard: Some(guard.to_string()),
            severity: Some(severity.to_string()),
            message: Some(message),
            details: Some(details),
        };
    }

    let status = response.status();
    let body_text = response.text().await.unwrap_or_default();

    match serde_json::from_str::<PolicyCheckOutput>(&body_text) {
        Ok(payload) => payload,
        Err(err) => {
            tracing::warn!(
                action_type = %action_type,
                target = %target,
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
            let message = "Policy daemon returned malformed response — action denied (fail-closed)"
                .to_string();
            enqueue_offline_audit_event(
                audit_queue.as_ref(),
                &action_type,
                &target,
                "hushd_parse_error",
                "critical",
                &message,
                session_id_for_audit.as_deref(),
                &endpoint_agent_id,
                runtime_identity
                    .as_ref()
                    .map(|value| value.runtime_agent_id.as_str()),
                runtime_identity
                    .as_ref()
                    .map(|value| value.runtime_agent_kind.as_str()),
                Some(&details),
            )
            .await;

            PolicyCheckOutput {
                allowed: false,
                guard: Some("hushd_parse_error".to_string()),
                severity: Some("critical".to_string()),
                message: Some(message),
                details: Some(details),
            }
        }
    }
}
