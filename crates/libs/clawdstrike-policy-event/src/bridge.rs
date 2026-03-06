//! Convert PolicyEvent to hunt-query TimelineEvent.

use hunt_query::query::EventSource;
use hunt_query::timeline::{NormalizedVerdict, TimelineEvent, TimelineEventKind};

use crate::decision::{decision_allowed, decision_object_is_warn, severity_from_value};
use crate::event::{PolicyEvent, PolicyEventData, PolicyEventType};

/// Convert a single PolicyEvent to a TimelineEvent.
#[must_use]
pub fn policy_event_to_timeline(event: &PolicyEvent) -> TimelineEvent {
    let (action_type, summary) = action_type_and_summary(event);
    let verdict = verdict_from_metadata(event.metadata.as_ref());

    TimelineEvent {
        event_id: None,
        timestamp: event.timestamp,
        source: EventSource::Receipt,
        kind: TimelineEventKind::GuardDecision,
        verdict,
        severity: extract_severity(event.metadata.as_ref()),
        summary,
        process: None,
        namespace: None,
        pod: None,
        action_type: Some(action_type.to_string()),
        signature_valid: None,
        raw: serde_json::to_value(event).ok(),
    }
}

/// Batch convert a slice of PolicyEvents to TimelineEvents.
#[must_use]
pub fn policy_events_to_timeline(events: &[PolicyEvent]) -> Vec<TimelineEvent> {
    events.iter().map(policy_event_to_timeline).collect()
}

fn action_type_and_summary(event: &PolicyEvent) -> (&'static str, String) {
    match (&event.event_type, &event.data) {
        (PolicyEventType::FileRead, PolicyEventData::File(f)) => {
            ("file", format!("file_read {}", f.path))
        }
        (PolicyEventType::FileWrite, PolicyEventData::File(f)) => {
            ("file", format!("file_write {}", f.path))
        }
        (PolicyEventType::NetworkEgress, PolicyEventData::Network(n)) => {
            ("egress", format!("network_egress {}:{}", n.host, n.port))
        }
        (PolicyEventType::CommandExec, PolicyEventData::Command(c)) => {
            ("shell", format!("command_exec {}", c.command))
        }
        (PolicyEventType::PatchApply, PolicyEventData::Patch(p)) => {
            ("patch", format!("patch_apply {}", p.file_path))
        }
        (PolicyEventType::ToolCall, PolicyEventData::Tool(t)) => {
            ("tool", format!("tool_call {}", t.tool_name))
        }
        (PolicyEventType::SecretAccess, PolicyEventData::Secret(s)) => {
            ("secret", format!("secret_access {}", s.secret_name))
        }
        (PolicyEventType::Custom, PolicyEventData::Custom(c)) => {
            ("custom", format!("custom {}", c.custom_type))
        }
        (
            PolicyEventType::RemoteSessionConnect
            | PolicyEventType::RemoteSessionDisconnect
            | PolicyEventType::RemoteSessionReconnect
            | PolicyEventType::InputInject
            | PolicyEventType::ClipboardTransfer
            | PolicyEventType::FileTransfer
            | PolicyEventType::RemoteAudio
            | PolicyEventType::RemoteDriveMapping
            | PolicyEventType::RemotePrinting
            | PolicyEventType::SessionShare,
            PolicyEventData::Cua(cua),
        ) => ("cua", format!("{} {}", event.event_type, cua.cua_action)),
        _ => ("unknown", format!("{}", event.event_type)),
    }
}

fn verdict_from_metadata(metadata: Option<&serde_json::Value>) -> NormalizedVerdict {
    let obj = match metadata {
        Some(serde_json::Value::Object(o)) => o,
        _ => return NormalizedVerdict::None,
    };

    let decision_val = obj.get("verdict").or_else(|| obj.get("decision"));

    match decision_val {
        // String form: "deny", "allowed", etc.
        Some(serde_json::Value::String(s)) => match s.to_lowercase().as_str() {
            "allow" | "allowed" | "pass" | "passed" => NormalizedVerdict::Allow,
            "deny" | "denied" | "block" | "blocked" => NormalizedVerdict::Deny,
            "warn" | "warning" | "warned" => NormalizedVerdict::Warn,
            _ => NormalizedVerdict::None,
        },
        // Object form: {"allowed": false, "guard": "..."} — decode the decision details.
        Some(serde_json::Value::Object(decision_obj)) => {
            let allowed = decision_allowed(decision_obj);
            if allowed == Some(false) {
                return NormalizedVerdict::Deny;
            }
            if decision_object_is_warn(decision_obj) {
                return NormalizedVerdict::Warn;
            }
            match allowed {
                Some(true) => NormalizedVerdict::Allow,
                Some(false) => unreachable!("handled above"),
                None => NormalizedVerdict::None,
            }
        }
        _ => NormalizedVerdict::None,
    }
}

fn extract_severity(metadata: Option<&serde_json::Value>) -> Option<String> {
    let obj = match metadata {
        Some(serde_json::Value::Object(o)) => o,
        _ => return None,
    };

    obj.get("severity")
        .and_then(severity_from_value)
        .or_else(|| {
            obj.get("decision")
                .or_else(|| obj.get("verdict"))
                .and_then(|v| v.as_object())
                .and_then(|d| d.get("severity"))
                .and_then(severity_from_value)
        })
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used, clippy::unwrap_used)]

    use super::*;
    use crate::event::{
        CommandEventData, CuaEventData, FileEventData, NetworkEventData, ToolEventData,
    };
    use chrono::Utc;

    fn file_read_event() -> PolicyEvent {
        PolicyEvent {
            event_id: "e1".to_string(),
            event_type: PolicyEventType::FileRead,
            timestamp: Utc::now(),
            session_id: None,
            data: PolicyEventData::File(FileEventData {
                path: "/etc/passwd".to_string(),
                operation: None,
                content_base64: None,
                content: None,
                content_hash: None,
            }),
            metadata: None,
            context: None,
        }
    }

    #[test]
    fn file_read_maps_to_guard_decision() {
        let te = policy_event_to_timeline(&file_read_event());
        assert_eq!(te.source, EventSource::Receipt);
        assert_eq!(te.kind, TimelineEventKind::GuardDecision);
        assert_eq!(te.action_type.as_deref(), Some("file"));
        assert!(te.summary.contains("file_read"));
        assert_eq!(te.verdict, NormalizedVerdict::None);
    }

    #[test]
    fn egress_maps_correctly() {
        let event = PolicyEvent {
            event_id: "e2".to_string(),
            event_type: PolicyEventType::NetworkEgress,
            timestamp: Utc::now(),
            session_id: None,
            data: PolicyEventData::Network(NetworkEventData {
                host: "evil.com".to_string(),
                port: 443,
                protocol: None,
                url: None,
            }),
            metadata: Some(serde_json::json!({ "verdict": "deny" })),
            context: None,
        };

        let te = policy_event_to_timeline(&event);
        assert_eq!(te.action_type.as_deref(), Some("egress"));
        assert_eq!(te.verdict, NormalizedVerdict::Deny);
    }

    #[test]
    fn command_maps_to_shell() {
        let event = PolicyEvent {
            event_id: "e3".to_string(),
            event_type: PolicyEventType::CommandExec,
            timestamp: Utc::now(),
            session_id: None,
            data: PolicyEventData::Command(CommandEventData {
                command: "rm".to_string(),
                args: vec!["-rf".to_string(), "/".to_string()],
            }),
            metadata: None,
            context: None,
        };

        let te = policy_event_to_timeline(&event);
        assert_eq!(te.action_type.as_deref(), Some("shell"));
        assert!(te.summary.contains("command_exec"));
    }

    #[test]
    fn tool_call_maps() {
        let event = PolicyEvent {
            event_id: "e4".to_string(),
            event_type: PolicyEventType::ToolCall,
            timestamp: Utc::now(),
            session_id: None,
            data: PolicyEventData::Tool(ToolEventData {
                tool_name: "fs_read".to_string(),
                parameters: serde_json::json!({}),
            }),
            metadata: None,
            context: None,
        };

        let te = policy_event_to_timeline(&event);
        assert_eq!(te.action_type.as_deref(), Some("tool"));
    }

    #[test]
    fn cua_maps_to_cua_action_type() {
        let event = PolicyEvent {
            event_id: "e5".to_string(),
            event_type: PolicyEventType::RemoteSessionConnect,
            timestamp: Utc::now(),
            session_id: None,
            data: PolicyEventData::Cua(CuaEventData {
                cua_action: "connect".to_string(),
                direction: None,
                continuity_prev_session_hash: None,
                postcondition_probe_hash: None,
                extra: serde_json::Map::new(),
            }),
            metadata: None,
            context: None,
        };

        let te = policy_event_to_timeline(&event);
        assert_eq!(te.action_type.as_deref(), Some("cua"));
    }

    #[test]
    fn batch_convert_preserves_order() {
        let events = vec![file_read_event(), file_read_event()];
        let timeline = policy_events_to_timeline(&events);
        assert_eq!(timeline.len(), 2);
    }

    #[test]
    fn verdict_from_metadata_allow() {
        let v = verdict_from_metadata(Some(&serde_json::json!({ "verdict": "allowed" })));
        assert_eq!(v, NormalizedVerdict::Allow);
    }

    #[test]
    fn verdict_from_metadata_warn() {
        let v = verdict_from_metadata(Some(&serde_json::json!({ "decision": "warn" })));
        assert_eq!(v, NormalizedVerdict::Warn);
    }

    #[test]
    fn verdict_from_metadata_none() {
        let v = verdict_from_metadata(None);
        assert_eq!(v, NormalizedVerdict::None);
    }

    #[test]
    fn verdict_from_metadata_object_denied() {
        let v = verdict_from_metadata(Some(&serde_json::json!({
            "decision": { "allowed": false, "guard": "ForbiddenPathGuard" }
        })));
        assert_eq!(v, NormalizedVerdict::Deny);
    }

    #[test]
    fn verdict_from_metadata_object_allowed() {
        let v = verdict_from_metadata(Some(&serde_json::json!({
            "decision": { "allowed": true }
        })));
        assert_eq!(v, NormalizedVerdict::Allow);
    }

    #[test]
    fn verdict_from_metadata_object_warn() {
        let v = verdict_from_metadata(Some(&serde_json::json!({
            "decision": { "allowed": true, "warn": true }
        })));
        assert_eq!(v, NormalizedVerdict::Warn);
    }

    #[test]
    fn verdict_from_metadata_object_warning_severity_is_warn() {
        let v = verdict_from_metadata(Some(&serde_json::json!({
            "decision": { "allowed": true, "severity": "warning" }
        })));
        assert_eq!(v, NormalizedVerdict::Warn);
    }

    #[test]
    fn verdict_from_metadata_object_warn_with_denied_is_denied() {
        let v = verdict_from_metadata(Some(&serde_json::json!({
            "decision": { "allowed": false, "warn": true, "severity": "warning" }
        })));
        assert_eq!(v, NormalizedVerdict::Deny);
    }

    #[test]
    fn verdict_from_metadata_object_missing_allowed_field() {
        let v = verdict_from_metadata(Some(&serde_json::json!({
            "decision": { "guard": "SomeGuard" }
        })));
        assert_eq!(v, NormalizedVerdict::None);
    }

    #[test]
    fn extract_severity_from_object_decision() {
        let s = extract_severity(Some(&serde_json::json!({
            "decision": { "severity": "high" }
        })));
        assert_eq!(s.as_deref(), Some("high"));
    }

    #[test]
    fn extract_severity_from_nested_severity_object() {
        let s = extract_severity(Some(&serde_json::json!({
            "decision": { "severity": { "level": "warning" } }
        })));
        assert_eq!(s.as_deref(), Some("warning"));
    }
}
