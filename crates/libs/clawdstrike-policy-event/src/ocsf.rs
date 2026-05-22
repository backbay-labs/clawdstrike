//! Convert PolicyEvent to OCSF events.
//!
//! Uses `clawdstrike-ocsf` converters for OCSF-compliant output.

use clawdstrike_ocsf::convert::from_security_event::{security_event_to_ocsf, SecurityEventInput};

use crate::decision::{decision_allowed, decision_object_is_warn, severity_from_value};
use crate::event::{MappedGuardAction, PolicyEvent, PolicyEventData, PolicyEventType};

/// Convert a single PolicyEvent to an OCSF JSON value.
///
/// Returns the primary Detection Finding (class_uid 2004) as JSON.
/// Returns `None` for event types that cannot be mapped to OCSF.
#[must_use]
pub fn policy_event_to_ocsf(event: &PolicyEvent) -> Option<serde_json::Value> {
    let time_ms = event.timestamp.timestamp_millis();
    let (action, resource_type, resource_name, resource_path, resource_host, resource_port) =
        classify_event(event);

    let agent_id =
        crate::event::extract_metadata_string(event.metadata.as_ref(), &["agentId", "agent_id"])
            .unwrap_or_else(|| "unknown".to_string());

    let agent_name = crate::event::extract_metadata_string(
        event.metadata.as_ref(),
        &["agentName", "agent_name"],
    )
    .unwrap_or_else(|| "agent".to_string());

    let decision = parse_decision_metadata(event.metadata.as_ref());
    let allowed = decision.allowed;
    let is_warn = decision.is_warn;
    let outcome = if allowed { "success" } else { "failure" };
    let default_severity = if !allowed {
        "high"
    } else if is_warn {
        "medium"
    } else {
        "info"
    };
    let severity = decision.severity.as_deref().unwrap_or(default_severity);
    let guard = decision.guard.as_deref().unwrap_or("PolicyEvent");
    let reason = decision
        .message
        .unwrap_or_else(|| format!("{} observation", event.event_type));

    let input = SecurityEventInput {
        event_id: &event.event_id,
        time_ms,
        allowed,
        outcome,
        severity,
        guard,
        reason: &reason,
        product_version: env!("CARGO_PKG_VERSION"),
        action,
        resource_type,
        resource_name: &resource_name,
        resource_path: resource_path.as_deref(),
        resource_host: resource_host.as_deref(),
        resource_port,
        agent_id: &agent_id,
        agent_name: &agent_name,
        session_id: event.session_id.as_deref(),
        is_warn,
    };

    let event_set = security_event_to_ocsf(&input);
    serde_json::to_value(&event_set.detection_finding).ok()
}

struct DecisionMetadata {
    allowed: bool,
    is_warn: bool,
    guard: Option<String>,
    severity: Option<String>,
    message: Option<String>,
}

impl Default for DecisionMetadata {
    fn default() -> Self {
        Self {
            allowed: true,
            is_warn: false,
            guard: None,
            severity: None,
            message: None,
        }
    }
}

fn parse_decision_metadata(metadata: Option<&serde_json::Value>) -> DecisionMetadata {
    let mut out = DecisionMetadata::default();
    let obj = match metadata {
        Some(serde_json::Value::Object(obj)) => obj,
        _ => return out,
    };

    let decision_val = obj.get("verdict").or_else(|| obj.get("decision"));
    match decision_val {
        Some(serde_json::Value::String(s)) => match s.to_lowercase().as_str() {
            "deny" | "denied" | "block" | "blocked" => {
                out.allowed = false;
            }
            "warn" | "warning" | "warned" | "logged" => {
                out.allowed = true;
                out.is_warn = true;
            }
            _ => {
                out.allowed = true;
            }
        },
        Some(serde_json::Value::Object(decision_obj)) => {
            let allowed = decision_allowed(decision_obj);
            if allowed == Some(false) {
                out.allowed = false;
                out.is_warn = false;
            } else {
                out.allowed = allowed.unwrap_or(true);
                out.is_warn = decision_object_is_warn(decision_obj);
            }

            out.guard = decision_obj
                .get("guard")
                .and_then(|v| v.as_str())
                .map(|s| s.to_string());
            out.severity = decision_obj.get("severity").and_then(severity_from_value);
            out.message = decision_obj
                .get("message")
                .or_else(|| decision_obj.get("reason"))
                .and_then(|v| v.as_str())
                .map(|s| s.to_string());
        }
        _ => {}
    }

    if out.severity.is_none() {
        out.severity = obj.get("severity").and_then(severity_from_value);
    }
    if out.guard.is_none() {
        out.guard = obj
            .get("guard")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string());
    }
    if out.message.is_none() {
        out.message = obj
            .get("message")
            .or_else(|| obj.get("reason"))
            .and_then(|v| v.as_str())
            .map(|s| s.to_string());
    }

    out
}

/// Convert a MappedGuardAction + report into an OCSF JSON value.
///
/// This variant is useful when you already have a guard evaluation result.
#[must_use]
pub fn guard_decision_to_ocsf(
    event: &PolicyEvent,
    action: &MappedGuardAction,
    allowed: bool,
    guard: &str,
    severity: &str,
    message: &str,
    is_warn: bool,
) -> Option<serde_json::Value> {
    let time_ms = event.timestamp.timestamp_millis();
    let event_classification = classify_event(event);
    let action_classification = classify_action(action);
    let (action_str, resource_type, resource_name, resource_path, resource_host, resource_port) =
        if event_classification.0 == "custom" && event_classification.2 == event.event_type.as_str()
        {
            // Fall back to mapped action classification only when the raw event
            // path collapses to a generic custom marker.
            action_classification
        } else {
            event_classification
        };

    let agent_id =
        crate::event::extract_metadata_string(event.metadata.as_ref(), &["agentId", "agent_id"])
            .unwrap_or_else(|| "unknown".to_string());

    let agent_name = crate::event::extract_metadata_string(
        event.metadata.as_ref(),
        &["agentName", "agent_name"],
    )
    .unwrap_or_else(|| "agent".to_string());

    let outcome = if allowed { "success" } else { "failure" };

    let input = SecurityEventInput {
        event_id: &event.event_id,
        time_ms,
        allowed,
        outcome,
        severity,
        guard,
        reason: message,
        product_version: env!("CARGO_PKG_VERSION"),
        action: action_str,
        resource_type,
        resource_name: &resource_name,
        resource_path: resource_path.as_deref(),
        resource_host: resource_host.as_deref(),
        resource_port,
        agent_id: &agent_id,
        agent_name: &agent_name,
        session_id: event.session_id.as_deref(),
        is_warn,
    };

    let event_set = security_event_to_ocsf(&input);
    serde_json::to_value(&event_set.detection_finding).ok()
}

/// Batch convert events to OCSF JSONL.
pub fn policy_events_to_ocsf_jsonl(events: &[PolicyEvent]) -> anyhow::Result<String> {
    let mut lines = Vec::with_capacity(events.len());

    for event in events {
        if let Some(ocsf_json) = policy_event_to_ocsf(event) {
            let line = serde_json::to_string(&ocsf_json)?;
            lines.push(line);
        }
    }

    Ok(lines.join("\n"))
}

fn classify_event(
    event: &PolicyEvent,
) -> (
    &'static str,
    &'static str,
    String,
    Option<String>,
    Option<String>,
    Option<u16>,
) {
    match (&event.event_type, &event.data) {
        (PolicyEventType::FileRead, PolicyEventData::File(f)) => (
            "file_access",
            "file",
            f.path.clone(),
            Some(f.path.clone()),
            None,
            None,
        ),
        (PolicyEventType::FileWrite, PolicyEventData::File(f)) => (
            "file_write",
            "file",
            f.path.clone(),
            Some(f.path.clone()),
            None,
            None,
        ),
        (PolicyEventType::NetworkEgress, PolicyEventData::Network(n)) => (
            "egress",
            "network",
            n.host.clone(),
            None,
            Some(n.host.clone()),
            Some(n.port),
        ),
        (PolicyEventType::CommandExec, PolicyEventData::Command(c)) => {
            ("shell", "process", c.command.clone(), None, None, None)
        }
        (PolicyEventType::PatchApply, PolicyEventData::Patch(p)) => (
            "patch",
            "file",
            p.file_path.clone(),
            Some(p.file_path.clone()),
            None,
            None,
        ),
        (PolicyEventType::ToolCall, PolicyEventData::Tool(t)) => {
            let is_mcp = metadata_tool_kind_is_mcp(event.metadata.as_ref())
                || t.tool_name.starts_with("mcp__");
            (
                if is_mcp { "mcp_tool" } else { "custom" },
                "tool",
                t.tool_name.clone(),
                None,
                None,
                None,
            )
        }
        (PolicyEventType::SecretAccess, PolicyEventData::Secret(s)) => (
            "secret_access",
            "configuration",
            s.secret_name.clone(),
            None,
            None,
            None,
        ),
        (PolicyEventType::Custom, PolicyEventData::Custom(c))
            if c.custom_type == "endpoint.dns_lookup" =>
        {
            let query = c
                .extra
                .get("endpointEvent")
                .and_then(|event| event.get("query"))
                .and_then(serde_json::Value::as_str)
                .unwrap_or("dns_lookup")
                .to_string();
            (
                "dns_lookup",
                "network",
                query.clone(),
                None,
                Some(query),
                None,
            )
        }
        _ => (
            "custom",
            "configuration",
            event.event_type.as_str().to_string(),
            None,
            None,
            None,
        ),
    }
}

fn metadata_tool_kind_is_mcp(metadata: Option<&serde_json::Value>) -> bool {
    let Some(serde_json::Value::Object(obj)) = metadata else {
        return false;
    };

    let kind = obj
        .get("toolKind")
        .or_else(|| obj.get("tool_kind"))
        .and_then(|v| v.as_str());

    kind.map(|s| s.eq_ignore_ascii_case("mcp")).unwrap_or(false)
}

/// Classify a MappedGuardAction into OCSF resource fields.
///
/// Delegates to `classify_event` by converting the action back to the
/// corresponding event type/data — avoids duplicating the mapping logic.
fn classify_action(
    action: &MappedGuardAction,
) -> (
    &'static str,
    &'static str,
    String,
    Option<String>,
    Option<String>,
    Option<u16>,
) {
    use crate::event::{
        CommandEventData, CustomEventData, FileEventData, NetworkEventData, PatchEventData,
        ToolEventData,
    };

    let (event_type, data) = match action {
        MappedGuardAction::FileAccess { path } => (
            PolicyEventType::FileRead,
            PolicyEventData::File(FileEventData {
                path: path.clone(),
                operation: None,
                content_base64: None,
                content: None,
                content_hash: None,
            }),
        ),
        MappedGuardAction::FileWrite { path, .. } => (
            PolicyEventType::FileWrite,
            PolicyEventData::File(FileEventData {
                path: path.clone(),
                operation: None,
                content_base64: None,
                content: None,
                content_hash: None,
            }),
        ),
        MappedGuardAction::NetworkEgress { host, port } => (
            PolicyEventType::NetworkEgress,
            PolicyEventData::Network(NetworkEventData {
                host: host.clone(),
                port: *port,
                protocol: None,
                url: None,
            }),
        ),
        MappedGuardAction::ShellCommand { commandline } => (
            PolicyEventType::CommandExec,
            PolicyEventData::Command(CommandEventData {
                command: commandline.clone(),
                args: vec![],
            }),
        ),
        MappedGuardAction::Patch { file_path, .. } => (
            PolicyEventType::PatchApply,
            PolicyEventData::Patch(PatchEventData {
                file_path: file_path.clone(),
                patch_content: String::new(),
                patch_hash: None,
            }),
        ),
        MappedGuardAction::McpTool { tool_name, .. } => (
            PolicyEventType::ToolCall,
            PolicyEventData::Tool(ToolEventData {
                tool_name: tool_name.clone(),
                parameters: serde_json::Value::Null,
            }),
        ),
        MappedGuardAction::Custom { custom_type, .. } => (
            PolicyEventType::Custom,
            PolicyEventData::Custom(CustomEventData {
                custom_type: custom_type.clone(),
                extra: serde_json::Map::new(),
            }),
        ),
    };

    let stub = PolicyEvent {
        event_id: String::new(),
        event_type,
        timestamp: chrono::Utc::now(),
        session_id: None,
        data,
        metadata: None,
        context: None,
    };
    classify_event(&stub)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used, clippy::unwrap_used)]

    use super::*;
    use crate::event::{
        CustomEventData, FileEventData, NetworkEventData, SecretEventData, ToolEventData,
    };
    use chrono::Utc;

    #[test]
    fn file_read_produces_detection_finding() {
        let event = PolicyEvent {
            event_id: "evt-1".to_string(),
            event_type: PolicyEventType::FileRead,
            timestamp: Utc::now(),
            session_id: Some("sess-1".to_string()),
            data: PolicyEventData::File(FileEventData {
                path: "/etc/passwd".to_string(),
                operation: None,
                content_base64: None,
                content: None,
                content_hash: None,
            }),
            metadata: None,
            context: None,
        };

        let json = policy_event_to_ocsf(&event).unwrap();
        assert_eq!(json["class_uid"], 2004);
        assert_eq!(json["category_uid"], 2);
    }

    #[test]
    fn egress_produces_detection_finding() {
        let event = PolicyEvent {
            event_id: "evt-2".to_string(),
            event_type: PolicyEventType::NetworkEgress,
            timestamp: Utc::now(),
            session_id: None,
            data: PolicyEventData::Network(NetworkEventData {
                host: "api.github.com".to_string(),
                port: 443,
                protocol: None,
                url: None,
            }),
            metadata: None,
            context: None,
        };

        let json = policy_event_to_ocsf(&event).unwrap();
        assert_eq!(json["class_uid"], 2004);
    }

    #[test]
    fn endpoint_dns_lookup_projects_to_network_finding() {
        let event = PolicyEvent {
            event_id: "evt-dns".to_string(),
            event_type: PolicyEventType::Custom,
            timestamp: Utc::now(),
            session_id: None,
            data: PolicyEventData::Custom(CustomEventData {
                custom_type: "endpoint.dns_lookup".to_string(),
                extra: serde_json::json!({
                    "endpointEvent": {
                        "type": "dns_lookup",
                        "query": "packages.example.invalid",
                        "record_type": "A"
                    }
                })
                .as_object()
                .cloned()
                .unwrap(),
            }),
            metadata: None,
            context: None,
        };

        let json = policy_event_to_ocsf(&event).unwrap();
        assert_eq!(json["class_uid"], 2004);
        assert_eq!(json["resources"][0]["type"], "network");
        assert_eq!(json["resources"][0]["name"], "packages.example.invalid");
    }

    #[test]
    fn batch_ocsf_jsonl() {
        let events = vec![PolicyEvent {
            event_id: "evt-1".to_string(),
            event_type: PolicyEventType::FileRead,
            timestamp: Utc::now(),
            session_id: None,
            data: PolicyEventData::File(FileEventData {
                path: "/tmp/test".to_string(),
                operation: None,
                content_base64: None,
                content: None,
                content_hash: None,
            }),
            metadata: None,
            context: None,
        }];

        let jsonl = policy_events_to_ocsf_jsonl(&events).unwrap();
        assert!(!jsonl.is_empty());
        let parsed: serde_json::Value = serde_json::from_str(&jsonl).unwrap();
        assert_eq!(parsed["class_uid"], 2004);
    }

    #[test]
    fn object_form_decision_denied() {
        let event = PolicyEvent {
            event_id: "evt-obj".to_string(),
            event_type: PolicyEventType::FileRead,
            timestamp: Utc::now(),
            session_id: None,
            data: PolicyEventData::File(FileEventData {
                path: "/etc/shadow".to_string(),
                operation: None,
                content_base64: None,
                content: None,
                content_hash: None,
            }),
            metadata: Some(serde_json::json!({
                "decision": { "allowed": false, "guard": "ForbiddenPathGuard" }
            })),
            context: None,
        };

        let json = policy_event_to_ocsf(&event).unwrap();
        assert_eq!(json["class_uid"], 2004);
        // Object-form {allowed: false} → action_id 2 (Denied)
        assert_eq!(json["action_id"], 2);
        assert_eq!(json["disposition_id"], 2); // Blocked
        assert_eq!(
            json["finding_info"]["analytic"]["name"],
            "ForbiddenPathGuard"
        );
    }

    #[test]
    fn object_form_decision_allowed() {
        let event = PolicyEvent {
            event_id: "evt-obj-allow".to_string(),
            event_type: PolicyEventType::FileRead,
            timestamp: Utc::now(),
            session_id: None,
            data: PolicyEventData::File(FileEventData {
                path: "/tmp/test".to_string(),
                operation: None,
                content_base64: None,
                content: None,
                content_hash: None,
            }),
            metadata: Some(serde_json::json!({
                "decision": { "allowed": true }
            })),
            context: None,
        };

        let json = policy_event_to_ocsf(&event).unwrap();
        assert_eq!(json["class_uid"], 2004);
        // Object-form {allowed: true} → action_id 1 (Allowed)
        assert_eq!(json["action_id"], 1);
        assert_eq!(json["disposition_id"], 1); // Allowed
    }

    #[test]
    fn object_form_decision_warn_carries_message_and_severity() {
        let event = PolicyEvent {
            event_id: "evt-obj-warn".to_string(),
            event_type: PolicyEventType::FileRead,
            timestamp: Utc::now(),
            session_id: None,
            data: PolicyEventData::File(FileEventData {
                path: "/var/log/syslog".to_string(),
                operation: None,
                content_base64: None,
                content: None,
                content_hash: None,
            }),
            metadata: Some(serde_json::json!({
                "decision": {
                    "allowed": true,
                    "warn": true,
                    "guard": "ShellCommandGuard",
                    "severity": "warning",
                    "message": "Logged command"
                }
            })),
            context: None,
        };

        let json = policy_event_to_ocsf(&event).unwrap();
        assert_eq!(json["action_id"], 1); // Allowed
        assert_eq!(json["disposition_id"], 17); // Logged
        assert_eq!(json["severity_id"], 3); // Medium
        assert_eq!(
            json["finding_info"]["analytic"]["name"],
            "ShellCommandGuard"
        );
        assert_eq!(json["finding_info"]["desc"], "Logged command");
    }

    #[test]
    fn object_form_decision_warning_severity_maps_logged_without_warn_flag() {
        let event = PolicyEvent {
            event_id: "evt-obj-warn-severity".to_string(),
            event_type: PolicyEventType::FileRead,
            timestamp: Utc::now(),
            session_id: None,
            data: PolicyEventData::File(FileEventData {
                path: "/var/log/syslog".to_string(),
                operation: None,
                content_base64: None,
                content: None,
                content_hash: None,
            }),
            metadata: Some(serde_json::json!({
                "decision": {
                    "allowed": true,
                    "guard": "ShellCommandGuard",
                    "severity": "warning",
                    "message": "Logged command by severity"
                }
            })),
            context: None,
        };

        let json = policy_event_to_ocsf(&event).unwrap();
        assert_eq!(json["action_id"], 1); // Allowed
        assert_eq!(json["disposition_id"], 17); // Logged
        assert_eq!(json["severity_id"], 3); // Medium
        assert_eq!(
            json["finding_info"]["analytic"]["name"],
            "ShellCommandGuard"
        );
    }

    #[test]
    fn object_form_decision_denied_with_warn_flag_stays_blocked() {
        let event = PolicyEvent {
            event_id: "evt-obj-deny-warn".to_string(),
            event_type: PolicyEventType::FileRead,
            timestamp: Utc::now(),
            session_id: None,
            data: PolicyEventData::File(FileEventData {
                path: "/etc/shadow".to_string(),
                operation: None,
                content_base64: None,
                content: None,
                content_hash: None,
            }),
            metadata: Some(serde_json::json!({
                "decision": {
                    "allowed": false,
                    "warn": true,
                    "severity": "warning"
                }
            })),
            context: None,
        };

        let json = policy_event_to_ocsf(&event).unwrap();
        assert_eq!(json["action_id"], 2); // Denied
        assert_eq!(json["disposition_id"], 2); // Blocked
    }

    #[test]
    fn classify_tool_call_uses_metadata_tool_kind() {
        let event = PolicyEvent {
            event_id: "evt-tool".to_string(),
            event_type: PolicyEventType::ToolCall,
            timestamp: Utc::now(),
            session_id: None,
            data: PolicyEventData::Tool(crate::event::ToolEventData {
                tool_name: "read_file".to_string(),
                parameters: serde_json::json!({}),
            }),
            metadata: Some(serde_json::json!({ "toolKind": "mcp" })),
            context: None,
        };

        let (action, _, _, _, _, _) = classify_event(&event);
        assert_eq!(action, "mcp_tool");
    }

    #[test]
    fn classify_tool_call_non_mcp_uses_custom_action() {
        let event = PolicyEvent {
            event_id: "evt-tool-non-mcp".to_string(),
            event_type: PolicyEventType::ToolCall,
            timestamp: Utc::now(),
            session_id: None,
            data: PolicyEventData::Tool(crate::event::ToolEventData {
                tool_name: "read_file".to_string(),
                parameters: serde_json::json!({}),
            }),
            metadata: Some(serde_json::json!({ "toolKind": "native" })),
            context: None,
        };

        let (action, _, _, _, _, _) = classify_event(&event);
        assert_eq!(action, "custom");
    }

    #[test]
    fn guard_decision_denied() {
        let event = PolicyEvent {
            event_id: "evt-3".to_string(),
            event_type: PolicyEventType::FileRead,
            timestamp: Utc::now(),
            session_id: None,
            data: PolicyEventData::File(FileEventData {
                path: "/etc/shadow".to_string(),
                operation: None,
                content_base64: None,
                content: None,
                content_hash: None,
            }),
            metadata: None,
            context: None,
        };

        let action = MappedGuardAction::FileAccess {
            path: "/etc/shadow".to_string(),
        };

        let json = guard_decision_to_ocsf(
            &event,
            &action,
            false,
            "ForbiddenPathGuard",
            "critical",
            "Blocked /etc/shadow",
            false,
        )
        .unwrap();

        assert_eq!(json["class_uid"], 2004);
        assert_eq!(json["action_id"], 2); // Denied
        assert_eq!(json["disposition_id"], 2); // Blocked
    }

    #[test]
    fn guard_decision_uses_policy_event_data_for_secret_access_custom_action() {
        let event = PolicyEvent {
            event_id: "evt-secret".to_string(),
            event_type: PolicyEventType::SecretAccess,
            timestamp: Utc::now(),
            session_id: None,
            data: PolicyEventData::Secret(SecretEventData {
                secret_name: "OPENAI_API_KEY".to_string(),
                scope: "env".to_string(),
            }),
            metadata: None,
            context: None,
        };

        let action = MappedGuardAction::Custom {
            custom_type: "secret_access".to_string(),
            data: serde_json::json!({
                "type": "secret",
                "secretName": "OPENAI_API_KEY",
                "scope": "env"
            }),
        };

        let json = guard_decision_to_ocsf(
            &event,
            &action,
            false,
            "SecretGuard",
            "high",
            "blocked",
            false,
        )
        .unwrap();

        assert_eq!(json["resources"][0]["type"], "configuration");
        assert_eq!(json["resources"][0]["name"], "OPENAI_API_KEY");
    }

    #[test]
    fn guard_decision_uses_policy_event_data_for_non_mcp_tool_custom_action() {
        let event = PolicyEvent {
            event_id: "evt-tool".to_string(),
            event_type: PolicyEventType::ToolCall,
            timestamp: Utc::now(),
            session_id: None,
            data: PolicyEventData::Tool(ToolEventData {
                tool_name: "read_file".to_string(),
                parameters: serde_json::json!({"path":"/tmp/demo.txt"}),
            }),
            metadata: Some(serde_json::json!({"toolKind":"native"})),
            context: None,
        };

        let action = MappedGuardAction::Custom {
            custom_type: "tool_call".to_string(),
            data: serde_json::json!({
                "type": "tool",
                "toolName": "read_file",
                "parameters": {"path":"/tmp/demo.txt"}
            }),
        };

        let json = guard_decision_to_ocsf(
            &event,
            &action,
            false,
            "ToolGuard",
            "high",
            "blocked",
            false,
        )
        .unwrap();

        assert_eq!(json["resources"][0]["type"], "tool");
        assert_eq!(json["resources"][0]["name"], "read_file");
    }
}
