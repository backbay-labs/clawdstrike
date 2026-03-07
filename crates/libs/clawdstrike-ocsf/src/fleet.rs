use serde::{Deserialize, Serialize};
use serde_json::Value;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FleetEventSource {
    Receipt,
    Tetragon,
    Hubble,
    Scan,
    Response,
    Directory,
    Detection,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FleetEventKind {
    GuardDecision,
    ProcessExec,
    ProcessExit,
    ProcessKprobe,
    NetworkFlow,
    ScanResult,
    JoinCompleted,
    PrincipalStateChanged,
    ResponseActionCreated,
    ResponseActionUpdated,
    DetectionFired,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FleetEventSeverity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FleetEventVerdict {
    Allow,
    Deny,
    Warn,
    None,
    Forwarded,
    Dropped,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FleetEventPrincipal {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub principal_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub endpoint_agent_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub runtime_agent_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub principal_type: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FleetEventTarget {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kind: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FleetEventEvidence {
    pub raw_ref: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub envelope_hash: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub issuer: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub schema_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signature_valid: Option<bool>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FleetEventEnvelope {
    pub event_id: String,
    pub tenant_id: String,
    pub source: FleetEventSource,
    pub kind: FleetEventKind,
    pub occurred_at: String,
    pub ingested_at: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub severity: Option<FleetEventSeverity>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub verdict: Option<FleetEventVerdict>,
    pub summary: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub action_type: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub principal: Option<FleetEventPrincipal>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub session_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub grant_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub response_action_id: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub detection_ids: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub target: Option<FleetEventTarget>,
    pub evidence: FleetEventEvidence,
    #[serde(
        default = "default_empty_object",
        skip_serializing_if = "value_is_empty_object"
    )]
    pub attributes: Value,
}

pub fn default_empty_object() -> Value {
    Value::Object(Default::default())
}

pub fn value_is_empty_object(value: &Value) -> bool {
    matches!(value, Value::Object(map) if map.is_empty())
}

impl FleetEventSource {
    pub fn parse(value: &str) -> Option<Self> {
        match value.trim().to_lowercase().as_str() {
            "receipt" => Some(Self::Receipt),
            "tetragon" => Some(Self::Tetragon),
            "hubble" => Some(Self::Hubble),
            "scan" => Some(Self::Scan),
            "response" => Some(Self::Response),
            "directory" => Some(Self::Directory),
            "detection" => Some(Self::Detection),
            _ => None,
        }
    }
}

impl FleetEventKind {
    pub fn parse(value: &str) -> Option<Self> {
        match value.trim().to_lowercase().as_str() {
            "guard_decision" => Some(Self::GuardDecision),
            "process_exec" => Some(Self::ProcessExec),
            "process_exit" => Some(Self::ProcessExit),
            "process_kprobe" => Some(Self::ProcessKprobe),
            "network_flow" => Some(Self::NetworkFlow),
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fleet_event_envelope_serializes_expected_shape() {
        let event = FleetEventEnvelope {
            event_id: "evt-1".to_string(),
            tenant_id: "tenant-1".to_string(),
            source: FleetEventSource::Tetragon,
            kind: FleetEventKind::ProcessExec,
            occurred_at: "2026-03-06T12:00:00Z".to_string(),
            ingested_at: "2026-03-06T12:00:01Z".to_string(),
            severity: Some(FleetEventSeverity::Low),
            verdict: Some(FleetEventVerdict::Allow),
            summary: "process_exec /usr/bin/curl".to_string(),
            action_type: Some("process".to_string()),
            principal: Some(FleetEventPrincipal {
                principal_id: Some("principal-1".to_string()),
                endpoint_agent_id: Some("endpoint-1".to_string()),
                runtime_agent_id: None,
                principal_type: Some("agent".to_string()),
            }),
            session_id: Some("session-1".to_string()),
            grant_id: Some("grant-1".to_string()),
            response_action_id: None,
            detection_ids: vec!["finding-1".to_string()],
            target: Some(FleetEventTarget {
                kind: Some("process".to_string()),
                id: Some("1234".to_string()),
                name: Some("curl".to_string()),
            }),
            evidence: FleetEventEvidence {
                raw_ref: "hunt-envelope:evt-1".to_string(),
                envelope_hash: Some("abc123".to_string()),
                issuer: Some("spiffe://tenant/acme".to_string()),
                schema_name: Some("clawdstrike.sdr.fact.tetragon_event.v1".to_string()),
                signature_valid: Some(true),
            },
            attributes: serde_json::json!({"pid": 1001}),
        };

        let json = serde_json::to_value(&event).expect("serialize event");
        assert_eq!(json["eventId"], "evt-1");
        assert_eq!(json["source"], "tetragon");
        assert_eq!(json["kind"], "process_exec");
        assert_eq!(json["evidence"]["rawRef"], "hunt-envelope:evt-1");
    }

    #[test]
    fn fleet_event_envelope_omits_absent_attributes() {
        let event = FleetEventEnvelope {
            event_id: "evt-2".to_string(),
            tenant_id: "tenant-1".to_string(),
            source: FleetEventSource::Receipt,
            kind: FleetEventKind::GuardDecision,
            occurred_at: "2026-03-06T12:00:00Z".to_string(),
            ingested_at: "2026-03-06T12:00:01Z".to_string(),
            severity: None,
            verdict: None,
            summary: "receipt".to_string(),
            action_type: None,
            principal: None,
            session_id: None,
            grant_id: None,
            response_action_id: None,
            detection_ids: Vec::new(),
            target: None,
            evidence: FleetEventEvidence {
                raw_ref: "hunt-envelope:evt-2".to_string(),
                envelope_hash: None,
                issuer: None,
                schema_name: None,
                signature_valid: None,
            },
            attributes: default_empty_object(),
        };

        let json = serde_json::to_value(&event).expect("serialize event");
        assert!(json.get("attributes").is_none());
    }
}
