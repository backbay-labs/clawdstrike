//! Timeline event model and envelope parsing.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::fleet_projection::{fleet_event_to_timeline_event, looks_like_fleet_event_fact};
use crate::query::EventSource;

/// Classification of timeline events.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TimelineEventKind {
    ProcessExec,
    ProcessExit,
    ProcessKprobe,
    NetworkFlow,
    GuardDecision,
    ScanResult,
    JoinCompleted,
    PrincipalStateChanged,
    ResponseActionCreated,
    ResponseActionUpdated,
    DetectionFired,
}

impl std::fmt::Display for TimelineEventKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ProcessExec => write!(f, "process_exec"),
            Self::ProcessExit => write!(f, "process_exit"),
            Self::ProcessKprobe => write!(f, "process_kprobe"),
            Self::NetworkFlow => write!(f, "network_flow"),
            Self::GuardDecision => write!(f, "guard_decision"),
            Self::ScanResult => write!(f, "scan_result"),
            Self::JoinCompleted => write!(f, "join_completed"),
            Self::PrincipalStateChanged => write!(f, "principal_state_changed"),
            Self::ResponseActionCreated => write!(f, "response_action_created"),
            Self::ResponseActionUpdated => write!(f, "response_action_updated"),
            Self::DetectionFired => write!(f, "detection_fired"),
        }
    }
}

/// Normalized verdict across all event sources.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NormalizedVerdict {
    Allow,
    Deny,
    Warn,
    None,
    Forwarded,
    Dropped,
}

impl std::fmt::Display for NormalizedVerdict {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Allow => write!(f, "allow"),
            Self::Deny => write!(f, "deny"),
            Self::Warn => write!(f, "warn"),
            Self::None => write!(f, "none"),
            Self::Forwarded => write!(f, "forwarded"),
            Self::Dropped => write!(f, "dropped"),
        }
    }
}

/// A single event in the reconstructed timeline.
#[derive(Debug, Clone, Serialize)]
pub struct TimelineEvent {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub event_id: Option<String>,
    pub timestamp: DateTime<Utc>,
    pub source: EventSource,
    pub kind: TimelineEventKind,
    pub verdict: NormalizedVerdict,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub severity: Option<String>,
    pub summary: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub process: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub namespace: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pod: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub action_type: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signature_valid: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub raw: Option<Value>,
}

impl TimelineEventKind {
    pub fn parse(value: &str) -> Option<Self> {
        match value.trim().to_lowercase().as_str() {
            "process_exec" => Some(Self::ProcessExec),
            "process_exit" => Some(Self::ProcessExit),
            "process_kprobe" => Some(Self::ProcessKprobe),
            "network_flow" => Some(Self::NetworkFlow),
            "guard_decision" => Some(Self::GuardDecision),
            "scan_result" => Some(Self::ScanResult),
            "join_completed" => Some(Self::JoinCompleted),
            "principal_state_changed" => Some(Self::PrincipalStateChanged),
            "response_action_created" => Some(Self::ResponseActionCreated),
            "response_action_updated" => Some(Self::ResponseActionUpdated),
            "detection_fired" => Some(Self::DetectionFired),
            _ => None,
        }
    }
}

impl NormalizedVerdict {
    pub fn parse(value: &str) -> Option<Self> {
        match value.trim().to_lowercase().as_str() {
            "allow" => Some(Self::Allow),
            "deny" => Some(Self::Deny),
            "warn" => Some(Self::Warn),
            "none" => Some(Self::None),
            "forwarded" => Some(Self::Forwarded),
            "dropped" => Some(Self::Dropped),
            _ => None,
        }
    }
}

/// Parse a spine envelope JSON into a [`TimelineEvent`].
///
/// Dispatches on the `fact.schema` field to determine the event source and
/// extract source-specific fields.
pub fn parse_envelope(envelope: &Value, verify: bool) -> Option<TimelineEvent> {
    let fact = envelope.get("fact")?;

    if let Some(schema) = fact.get("schema").and_then(|s| s.as_str()) {
        // Only spine-schema facts participate in spine signature verification.
        // Fleet events carry their own evidence signature state and are not
        // spine-signed envelopes.
        let signature_valid = if verify {
            Some(spine::verify_envelope(envelope).unwrap_or(false))
        } else {
            None
        };

        // Parse timestamp from issued_at
        let issued_at = envelope.get("issued_at").and_then(|v| v.as_str())?;
        let timestamp = DateTime::parse_from_rfc3339(issued_at)
            .ok()?
            .with_timezone(&Utc);

        return match schema {
            "clawdstrike.sdr.fact.tetragon_event.v1" => {
                parse_tetragon(fact, timestamp, signature_valid, envelope.clone())
            }
            "clawdstrike.sdr.fact.hubble_flow.v1" => {
                parse_hubble(fact, timestamp, signature_valid, envelope.clone())
            }
            s if s.starts_with("clawdstrike.sdr.fact.receipt") => {
                parse_receipt(fact, timestamp, signature_valid, envelope.clone())
            }
            s if s.starts_with("clawdstrike.sdr.fact.scan") => {
                parse_scan(fact, timestamp, signature_valid, envelope.clone())
            }
            _ => None,
        };
    }

    if !looks_like_fleet_event_fact(fact) {
        return None;
    }

    parse_fleet_event(fact, None, envelope.clone())
}

/// Parse a Tetragon process event.
fn parse_tetragon(
    fact: &Value,
    timestamp: DateTime<Utc>,
    sig: Option<bool>,
    raw: Value,
) -> Option<TimelineEvent> {
    let event_type = fact
        .get("event_type")
        .and_then(|v| v.as_str())
        .unwrap_or("unknown");
    let binary = fact
        .get("process")
        .and_then(|p| p.get("binary"))
        .and_then(|b| b.as_str());
    let severity = fact
        .get("severity")
        .and_then(|s| s.as_str())
        .map(String::from);
    let ns = fact
        .get("process")
        .and_then(|p| p.get("pod"))
        .and_then(|p| p.get("namespace"))
        .and_then(|n| n.as_str())
        .map(String::from);
    let pod_name = fact
        .get("process")
        .and_then(|p| p.get("pod"))
        .and_then(|p| p.get("name"))
        .and_then(|n| n.as_str())
        .map(String::from);

    let kind = match event_type {
        "PROCESS_EXEC" => TimelineEventKind::ProcessExec,
        "PROCESS_EXIT" => TimelineEventKind::ProcessExit,
        "PROCESS_KPROBE" => TimelineEventKind::ProcessKprobe,
        _ => TimelineEventKind::ProcessExec,
    };

    let summary = format!("{} {}", event_type.to_lowercase(), binary.unwrap_or("?"));

    Some(TimelineEvent {
        event_id: None,
        timestamp,
        source: EventSource::Tetragon,
        kind,
        verdict: NormalizedVerdict::None,
        severity,
        summary,
        process: binary.map(String::from),
        namespace: ns,
        pod: pod_name,
        action_type: Some("process".to_string()),
        signature_valid: sig,
        raw: Some(raw),
    })
}

/// Parse a Hubble network flow event.
fn parse_hubble(
    fact: &Value,
    timestamp: DateTime<Utc>,
    sig: Option<bool>,
    raw: Value,
) -> Option<TimelineEvent> {
    let verdict_str = fact
        .get("verdict")
        .and_then(|v| v.as_str())
        .unwrap_or("UNKNOWN");
    let direction = fact
        .get("traffic_direction")
        .and_then(|v| v.as_str())
        .unwrap_or("unknown");
    let flow_summary = fact
        .get("summary")
        .and_then(|v| v.as_str())
        .unwrap_or("network flow");

    let verdict = match verdict_str {
        "FORWARDED" => NormalizedVerdict::Forwarded,
        "DROPPED" => NormalizedVerdict::Dropped,
        _ => NormalizedVerdict::None,
    };

    let ns = fact
        .get("source")
        .and_then(|s| s.get("namespace"))
        .and_then(|n| n.as_str())
        .map(String::from);
    let pod_name = fact
        .get("source")
        .and_then(|s| s.get("pod_name"))
        .and_then(|n| n.as_str())
        .map(String::from);

    let summary = format!("{} {}", direction.to_lowercase(), flow_summary);

    Some(TimelineEvent {
        event_id: None,
        timestamp,
        source: EventSource::Hubble,
        kind: TimelineEventKind::NetworkFlow,
        verdict,
        severity: None,
        summary,
        process: None,
        namespace: ns,
        pod: pod_name,
        action_type: Some(
            match direction {
                "EGRESS" => "egress",
                "INGRESS" => "ingress",
                _ => "network",
            }
            .to_string(),
        ),
        signature_valid: sig,
        raw: Some(raw),
    })
}

/// Parse a guard receipt event.
fn parse_receipt(
    fact: &Value,
    timestamp: DateTime<Utc>,
    sig: Option<bool>,
    raw: Value,
) -> Option<TimelineEvent> {
    let decision = fact
        .get("decision")
        .and_then(|v| v.as_str())
        .unwrap_or("unknown");
    let guard_name = fact
        .get("guard")
        .and_then(|v| v.as_str())
        .unwrap_or("unknown");
    let action = fact
        .get("action_type")
        .and_then(|v| v.as_str())
        .map(String::from);
    let severity = fact
        .get("severity")
        .and_then(|s| s.as_str())
        .map(String::from);
    let ns = fact
        .get("source")
        .and_then(|s| s.get("namespace"))
        .and_then(|n| n.as_str())
        .map(String::from);
    let pod_name = fact
        .get("source")
        .and_then(|s| s.get("pod_name").or_else(|| s.get("pod")))
        .and_then(|n| n.as_str())
        .map(String::from);

    let verdict = match decision.to_lowercase().as_str() {
        "allow" | "allowed" | "pass" | "passed" => NormalizedVerdict::Allow,
        "deny" | "denied" | "block" | "blocked" => NormalizedVerdict::Deny,
        "warn" | "warned" | "warning" => NormalizedVerdict::Warn,
        _ => NormalizedVerdict::None,
    };

    let summary = format!("{} decision={}", guard_name, decision);

    Some(TimelineEvent {
        event_id: None,
        timestamp,
        source: EventSource::Receipt,
        kind: TimelineEventKind::GuardDecision,
        verdict,
        severity,
        summary,
        process: None,
        namespace: ns,
        pod: pod_name,
        action_type: action,
        signature_valid: sig,
        raw: Some(raw),
    })
}

/// Parse a scan result event.
fn parse_scan(
    fact: &Value,
    timestamp: DateTime<Utc>,
    sig: Option<bool>,
    raw: Value,
) -> Option<TimelineEvent> {
    let scan_type = fact
        .get("scan_type")
        .and_then(|v| v.as_str())
        .unwrap_or("unknown");
    let status = fact
        .get("status")
        .and_then(|v| v.as_str())
        .unwrap_or("unknown");
    let severity = fact
        .get("severity")
        .and_then(|s| s.as_str())
        .map(String::from);

    let verdict = match status.to_lowercase().as_str() {
        "pass" | "passed" | "clean" => NormalizedVerdict::Allow,
        "fail" | "failed" | "dirty" => NormalizedVerdict::Deny,
        "warn" | "warning" => NormalizedVerdict::Warn,
        _ => NormalizedVerdict::None,
    };

    let summary = format!("scan {} status={}", scan_type, status);

    Some(TimelineEvent {
        event_id: None,
        timestamp,
        source: EventSource::Scan,
        kind: TimelineEventKind::ScanResult,
        verdict,
        severity,
        summary,
        process: None,
        namespace: None,
        pod: None,
        action_type: Some("scan".to_string()),
        signature_valid: sig,
        raw: Some(raw),
    })
}

fn parse_fleet_event(fact: &Value, sig: Option<bool>, raw: Value) -> Option<TimelineEvent> {
    let event = serde_json::from_value(fact.clone()).ok()?;
    fleet_event_to_timeline_event(event, sig, raw)
}

/// Merge multiple event lists into a single timeline, sorted by timestamp ascending.
pub fn merge_timeline(mut events: Vec<TimelineEvent>) -> Vec<TimelineEvent> {
    events.sort_by_key(|e| e.timestamp);
    events
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;
    use serde_json::json;

    #[test]
    fn timeline_event_kind_display() {
        assert_eq!(TimelineEventKind::ProcessExec.to_string(), "process_exec");
        assert_eq!(TimelineEventKind::ProcessExit.to_string(), "process_exit");
        assert_eq!(
            TimelineEventKind::ProcessKprobe.to_string(),
            "process_kprobe"
        );
        assert_eq!(TimelineEventKind::NetworkFlow.to_string(), "network_flow");
        assert_eq!(
            TimelineEventKind::GuardDecision.to_string(),
            "guard_decision"
        );
        assert_eq!(TimelineEventKind::ScanResult.to_string(), "scan_result");
    }

    #[test]
    fn normalized_verdict_display() {
        assert_eq!(NormalizedVerdict::Allow.to_string(), "allow");
        assert_eq!(NormalizedVerdict::Deny.to_string(), "deny");
        assert_eq!(NormalizedVerdict::Warn.to_string(), "warn");
        assert_eq!(NormalizedVerdict::None.to_string(), "none");
        assert_eq!(NormalizedVerdict::Forwarded.to_string(), "forwarded");
        assert_eq!(NormalizedVerdict::Dropped.to_string(), "dropped");
    }

    #[test]
    fn parse_tetragon_envelope() {
        let envelope = json!({
            "issued_at": "2025-06-15T12:00:00Z",
            "fact": {
                "schema": "clawdstrike.sdr.fact.tetragon_event.v1",
                "event_type": "PROCESS_EXEC",
                "process": {
                    "binary": "/usr/bin/curl",
                    "pod": {
                        "namespace": "default",
                        "name": "agent-pod-abc123"
                    }
                },
                "severity": "info"
            }
        });

        let event = parse_envelope(&envelope, false).unwrap();
        assert_eq!(event.source, EventSource::Tetragon);
        assert_eq!(event.kind, TimelineEventKind::ProcessExec);
        assert_eq!(event.verdict, NormalizedVerdict::None);
        assert_eq!(event.process.as_deref(), Some("/usr/bin/curl"));
        assert_eq!(event.namespace.as_deref(), Some("default"));
        assert_eq!(event.pod.as_deref(), Some("agent-pod-abc123"));
        assert_eq!(event.severity.as_deref(), Some("info"));
        assert_eq!(event.summary, "process_exec /usr/bin/curl");
        assert!(event.signature_valid.is_none());
        assert_eq!(
            event
                .raw
                .as_ref()
                .and_then(|v| v.get("fact"))
                .and_then(|v| v.get("schema"))
                .and_then(|v| v.as_str()),
            Some("clawdstrike.sdr.fact.tetragon_event.v1")
        );
    }

    #[test]
    fn parse_tetragon_process_exit() {
        let envelope = json!({
            "issued_at": "2025-06-15T12:01:00Z",
            "fact": {
                "schema": "clawdstrike.sdr.fact.tetragon_event.v1",
                "event_type": "PROCESS_EXIT",
                "process": {
                    "binary": "/usr/bin/ls"
                }
            }
        });

        let event = parse_envelope(&envelope, false).unwrap();
        assert_eq!(event.kind, TimelineEventKind::ProcessExit);
        assert_eq!(event.summary, "process_exit /usr/bin/ls");
    }

    #[test]
    fn parse_hubble_envelope() {
        let envelope = json!({
            "issued_at": "2025-06-15T12:05:00Z",
            "fact": {
                "schema": "clawdstrike.sdr.fact.hubble_flow.v1",
                "verdict": "FORWARDED",
                "traffic_direction": "EGRESS",
                "summary": "TCP 10.0.0.1:8080 -> 10.0.0.2:443",
                "source": {
                    "namespace": "production",
                    "pod_name": "web-server-xyz"
                }
            }
        });

        let event = parse_envelope(&envelope, false).unwrap();
        assert_eq!(event.source, EventSource::Hubble);
        assert_eq!(event.kind, TimelineEventKind::NetworkFlow);
        assert_eq!(event.verdict, NormalizedVerdict::Forwarded);
        assert_eq!(event.namespace.as_deref(), Some("production"));
        assert_eq!(event.pod.as_deref(), Some("web-server-xyz"));
        assert!(event.summary.contains("egress"));
    }

    #[test]
    fn parse_hubble_egress_action_type() {
        let envelope = json!({
            "issued_at": "2025-06-15T12:05:00Z",
            "fact": {
                "schema": "clawdstrike.sdr.fact.hubble_flow.v1",
                "verdict": "FORWARDED",
                "traffic_direction": "EGRESS",
                "summary": "TCP 10.0.0.1:8080 -> 93.184.216.34:443"
            }
        });

        let event = parse_envelope(&envelope, false).unwrap();
        assert_eq!(
            event.action_type.as_deref(),
            Some("egress"),
            "EGRESS traffic_direction should map to action_type 'egress'"
        );
    }

    #[test]
    fn parse_hubble_ingress_action_type() {
        let envelope = json!({
            "issued_at": "2025-06-15T12:05:00Z",
            "fact": {
                "schema": "clawdstrike.sdr.fact.hubble_flow.v1",
                "verdict": "FORWARDED",
                "traffic_direction": "INGRESS",
                "summary": "TCP 93.184.216.34:443 -> 10.0.0.1:8080"
            }
        });

        let event = parse_envelope(&envelope, false).unwrap();
        assert_eq!(
            event.action_type.as_deref(),
            Some("ingress"),
            "INGRESS traffic_direction should map to action_type 'ingress'"
        );
    }

    #[test]
    fn parse_hubble_unknown_direction_falls_back_to_network() {
        let envelope = json!({
            "issued_at": "2025-06-15T12:05:00Z",
            "fact": {
                "schema": "clawdstrike.sdr.fact.hubble_flow.v1",
                "verdict": "FORWARDED",
                "traffic_direction": "UNKNOWN",
                "summary": "flow"
            }
        });

        let event = parse_envelope(&envelope, false).unwrap();
        assert_eq!(
            event.action_type.as_deref(),
            Some("network"),
            "unknown traffic_direction should fall back to 'network'"
        );
    }

    #[test]
    fn parse_hubble_dropped() {
        let envelope = json!({
            "issued_at": "2025-06-15T12:06:00Z",
            "fact": {
                "schema": "clawdstrike.sdr.fact.hubble_flow.v1",
                "verdict": "DROPPED",
                "traffic_direction": "INGRESS",
                "summary": "blocked connection"
            }
        });

        let event = parse_envelope(&envelope, false).unwrap();
        assert_eq!(event.verdict, NormalizedVerdict::Dropped);
    }

    #[test]
    fn parse_receipt_envelope() {
        let envelope = json!({
            "issued_at": "2025-06-15T12:10:00Z",
            "fact": {
                "schema": "clawdstrike.sdr.fact.receipt.v1",
                "decision": "deny",
                "guard": "ForbiddenPathGuard",
                "action_type": "file",
                "severity": "critical"
            }
        });

        let event = parse_envelope(&envelope, false).unwrap();
        assert_eq!(event.source, EventSource::Receipt);
        assert_eq!(event.kind, TimelineEventKind::GuardDecision);
        assert_eq!(event.verdict, NormalizedVerdict::Deny);
        assert_eq!(event.action_type.as_deref(), Some("file"));
        assert_eq!(event.severity.as_deref(), Some("critical"));
        assert!(event.summary.contains("ForbiddenPathGuard"));
    }

    #[test]
    fn parse_receipt_envelope_preserves_source_metadata() {
        let envelope = json!({
            "issued_at": "2025-06-15T12:10:00Z",
            "fact": {
                "schema": "clawdstrike.sdr.fact.receipt.v1",
                "decision": "deny",
                "guard": "ForbiddenPathGuard",
                "action_type": "file",
                "source": {
                    "namespace": "prod",
                    "pod_name": "agent-worker-1"
                }
            }
        });

        let event = parse_envelope(&envelope, false).unwrap();
        assert_eq!(event.source, EventSource::Receipt);
        assert_eq!(event.namespace.as_deref(), Some("prod"));
        assert_eq!(event.pod.as_deref(), Some("agent-worker-1"));
    }

    #[test]
    fn parse_scan_envelope() {
        let envelope = json!({
            "issued_at": "2025-06-15T12:15:00Z",
            "fact": {
                "schema": "clawdstrike.sdr.fact.scan.v1",
                "scan_type": "vulnerability",
                "status": "fail",
                "severity": "high"
            }
        });

        let event = parse_envelope(&envelope, false).unwrap();
        assert_eq!(event.source, EventSource::Scan);
        assert_eq!(event.kind, TimelineEventKind::ScanResult);
        assert_eq!(event.verdict, NormalizedVerdict::Deny);
        assert_eq!(event.severity.as_deref(), Some("high"));
        assert!(event.summary.contains("vulnerability"));
    }

    #[test]
    fn parse_fleet_control_plane_envelope() {
        let envelope = json!({
            "issued_at": "2026-03-06T12:00:30Z",
            "issuer": "spiffe://tenant/acme",
            "fact": {
                "eventId": "evt-1",
                "tenantId": "00000000-0000-0000-0000-000000000001",
                "source": "response",
                "kind": "response_action_created",
                "occurredAt": "2026-03-06T12:00:00Z",
                "ingestedAt": "2026-03-06T12:00:01Z",
                "severity": "medium",
                "verdict": "warn",
                "summary": "response action created",
                "actionType": "set_posture",
                "evidence": {
                    "rawRef": "hunt-envelope:evt-1",
                    "signatureValid": true
                },
                "attributes": {
                    "process": "/usr/bin/curl",
                    "namespace": "default",
                    "pod": "agent-1"
                }
            }
        });

        let event = parse_envelope(&envelope, false).unwrap();
        assert_eq!(event.event_id.as_deref(), Some("evt-1"));
        assert_eq!(event.source, EventSource::Response);
        assert_eq!(event.kind, TimelineEventKind::ResponseActionCreated);
        assert_eq!(event.verdict, NormalizedVerdict::Warn);
        assert_eq!(event.severity.as_deref(), Some("medium"));
        assert_eq!(event.action_type.as_deref(), Some("set_posture"));
        assert_eq!(event.process.as_deref(), Some("/usr/bin/curl"));
        assert_eq!(event.namespace.as_deref(), Some("default"));
        assert_eq!(event.pod.as_deref(), Some("agent-1"));
        assert_eq!(event.signature_valid, Some(true));
    }

    #[test]
    fn parse_fleet_control_plane_envelope_preserves_evidence_signature_when_verify_enabled() {
        let envelope = json!({
            "issued_at": "2026-03-06T12:00:30Z",
            "issuer": "spiffe://tenant/acme",
            "fact": {
                "eventId": "evt-verify",
                "tenantId": "00000000-0000-0000-0000-000000000001",
                "source": "directory",
                "kind": "principal_state_changed",
                "occurredAt": "2026-03-06T12:00:00Z",
                "ingestedAt": "2026-03-06T12:00:01Z",
                "summary": "principal quarantined",
                "evidence": {
                    "rawRef": "hunt-envelope:evt-verify",
                    "signatureValid": true
                }
            }
        });

        let event = parse_envelope(&envelope, true).unwrap();
        assert_eq!(event.source, EventSource::Directory);
        assert_eq!(event.kind, TimelineEventKind::PrincipalStateChanged);
        assert_eq!(event.signature_valid, Some(true));
    }

    #[test]
    fn parse_missing_schema_non_fleet_fact_returns_none() {
        let envelope = json!({
            "issued_at": "2026-03-06T12:00:30Z",
            "fact": {
                "eventId": "evt-1",
                "tenantId": "00000000-0000-0000-0000-000000000001",
                "summary": "missing required fleet fields"
            }
        });

        assert!(parse_envelope(&envelope, false).is_none());
    }

    #[test]
    fn parse_unknown_schema_returns_none() {
        let envelope = json!({
            "issued_at": "2025-06-15T12:00:00Z",
            "fact": {
                "schema": "unknown.schema.v1"
            }
        });

        assert!(parse_envelope(&envelope, false).is_none());
    }

    #[test]
    fn parse_missing_fact_returns_none() {
        let envelope = json!({
            "issued_at": "2025-06-15T12:00:00Z"
        });

        assert!(parse_envelope(&envelope, false).is_none());
    }

    #[test]
    fn parse_missing_timestamp_returns_none() {
        let envelope = json!({
            "fact": {
                "schema": "clawdstrike.sdr.fact.tetragon_event.v1",
                "event_type": "PROCESS_EXEC",
                "process": { "binary": "/bin/sh" }
            }
        });

        assert!(parse_envelope(&envelope, false).is_none());
    }

    #[test]
    fn merge_timeline_sorts_by_timestamp() {
        let events = vec![
            TimelineEvent {
                event_id: None,
                timestamp: Utc.with_ymd_and_hms(2025, 6, 15, 14, 0, 0).unwrap(),
                source: EventSource::Tetragon,
                kind: TimelineEventKind::ProcessExec,
                verdict: NormalizedVerdict::None,
                severity: None,
                summary: "second".to_string(),
                process: None,
                namespace: None,
                pod: None,
                action_type: None,
                signature_valid: None,
                raw: None,
            },
            TimelineEvent {
                event_id: None,
                timestamp: Utc.with_ymd_and_hms(2025, 6, 15, 12, 0, 0).unwrap(),
                source: EventSource::Hubble,
                kind: TimelineEventKind::NetworkFlow,
                verdict: NormalizedVerdict::Forwarded,
                severity: None,
                summary: "first".to_string(),
                process: None,
                namespace: None,
                pod: None,
                action_type: None,
                signature_valid: None,
                raw: None,
            },
            TimelineEvent {
                event_id: None,
                timestamp: Utc.with_ymd_and_hms(2025, 6, 15, 16, 0, 0).unwrap(),
                source: EventSource::Receipt,
                kind: TimelineEventKind::GuardDecision,
                verdict: NormalizedVerdict::Deny,
                severity: None,
                summary: "third".to_string(),
                process: None,
                namespace: None,
                pod: None,
                action_type: None,
                signature_valid: None,
                raw: None,
            },
        ];

        let merged = merge_timeline(events);
        assert_eq!(merged.len(), 3);
        assert_eq!(merged[0].summary, "first");
        assert_eq!(merged[1].summary, "second");
        assert_eq!(merged[2].summary, "third");
    }

    #[test]
    fn merge_timeline_empty() {
        let events = merge_timeline(vec![]);
        assert!(events.is_empty());
    }

    #[test]
    fn timeline_event_serialization_skips_none_fields() {
        let event = TimelineEvent {
            event_id: None,
            timestamp: Utc.with_ymd_and_hms(2025, 6, 15, 12, 0, 0).unwrap(),
            source: EventSource::Tetragon,
            kind: TimelineEventKind::ProcessExec,
            verdict: NormalizedVerdict::None,
            severity: None,
            summary: "test".to_string(),
            process: None,
            namespace: None,
            pod: None,
            action_type: None,
            signature_valid: None,
            raw: None,
        };

        let json = serde_json::to_value(&event).unwrap();
        assert!(!json.as_object().unwrap().contains_key("severity"));
        assert!(!json.as_object().unwrap().contains_key("process"));
        assert!(!json.as_object().unwrap().contains_key("namespace"));
        assert!(!json.as_object().unwrap().contains_key("pod"));
        assert!(!json.as_object().unwrap().contains_key("action_type"));
        assert!(!json.as_object().unwrap().contains_key("signature_valid"));
        assert!(!json.as_object().unwrap().contains_key("raw"));
    }
}
