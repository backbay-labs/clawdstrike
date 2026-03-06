use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use uuid::Uuid;

use crate::query::{EventSource, HuntQuery, QueryVerdict};
use crate::timeline::{NormalizedVerdict, TimelineEvent, TimelineEventKind};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HuntEventSource {
    Receipt,
    Tetragon,
    Hubble,
    Scan,
    Response,
    Directory,
    Detection,
}

impl HuntEventSource {
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

    pub fn as_query_source(self) -> Option<EventSource> {
        match self {
            Self::Receipt => Some(EventSource::Receipt),
            Self::Tetragon => Some(EventSource::Tetragon),
            Self::Hubble => Some(EventSource::Hubble),
            Self::Scan => Some(EventSource::Scan),
            Self::Response | Self::Directory | Self::Detection => None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HuntEventKind {
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

impl HuntEventKind {
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

    pub fn as_timeline_kind(self) -> Option<TimelineEventKind> {
        match self {
            Self::GuardDecision => Some(TimelineEventKind::GuardDecision),
            Self::ProcessExec => Some(TimelineEventKind::ProcessExec),
            Self::ProcessExit => Some(TimelineEventKind::ProcessExit),
            Self::ProcessKprobe => Some(TimelineEventKind::ProcessKprobe),
            Self::NetworkFlow => Some(TimelineEventKind::NetworkFlow),
            Self::ScanResult => Some(TimelineEventKind::ScanResult),
            Self::JoinCompleted
            | Self::PrincipalStateChanged
            | Self::ResponseActionCreated
            | Self::ResponseActionUpdated
            | Self::DetectionFired => None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct HuntEvent {
    pub event_id: String,
    pub tenant_id: Uuid,
    pub source: HuntEventSource,
    pub kind: HuntEventKind,
    pub timestamp: DateTime<Utc>,
    pub verdict: NormalizedVerdict,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub severity: Option<String>,
    pub summary: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub action_type: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub process: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub namespace: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pod: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub session_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub endpoint_agent_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub runtime_agent_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub principal_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub grant_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub response_action_id: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub detection_ids: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub target_kind: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub target_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub target_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub envelope_hash: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub issuer: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub schema_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signature_valid: Option<bool>,
    pub raw_ref: String,
    #[serde(default, skip_serializing_if = "value_is_empty_object")]
    pub attributes: Value,
}

fn value_is_empty_object(value: &Value) -> bool {
    matches!(value, Value::Object(map) if map.is_empty())
}

impl HuntEvent {
    pub fn to_timeline_event(&self) -> Option<TimelineEvent> {
        Some(TimelineEvent {
            event_id: Some(self.event_id.clone()),
            timestamp: self.timestamp,
            source: self.source.as_query_source()?,
            kind: self.kind.as_timeline_kind()?,
            verdict: self.verdict,
            severity: self.severity.clone(),
            summary: self.summary.clone(),
            process: self.process.clone(),
            namespace: self.namespace.clone(),
            pod: self.pod.clone(),
            action_type: self.action_type.clone(),
            signature_valid: self.signature_valid,
            raw: Some(self.attributes.clone()),
        })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct HuntQueryRequest {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sources: Option<Vec<EventSource>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub verdict: Option<QueryVerdict>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub start: Option<DateTime<Utc>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub end: Option<DateTime<Utc>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub action_type: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub process: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub namespace: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pod: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub entity: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub principal_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub endpoint_agent_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub runtime_agent_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub limit: Option<usize>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cursor: Option<String>,
}

impl HuntQueryRequest {
    pub fn to_hunt_query(&self) -> HuntQuery {
        HuntQuery {
            sources: self.sources.clone().unwrap_or_default(),
            verdict: self.verdict,
            start: self.start,
            end: self.end,
            action_type: self.action_type.clone(),
            process: self.process.clone(),
            namespace: self.namespace.clone(),
            pod: self.pod.clone(),
            limit: self.limit.unwrap_or(100),
            entity: self.entity.clone(),
        }
    }

    pub fn limit_or_default(&self) -> usize {
        self.limit.unwrap_or(100).clamp(1, 500)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct HuntQueryResponse {
    pub events: Vec<HuntEvent>,
    pub total: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_cursor: Option<String>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum TimelineGroupedBy {
    Principal,
    Session,
    Endpoint,
    Runtime,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct HuntTimelineResponse {
    pub events: Vec<HuntEvent>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub entity: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub grouped_by: Option<TimelineGroupedBy>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct SavedHuntRecord {
    pub id: Uuid,
    pub tenant_id: Uuid,
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    pub query: HuntQueryRequest,
    pub created_by: String,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct CreateSavedHuntRequest {
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    pub query: HuntQueryRequest,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct UpdateSavedHuntRequest {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub query: Option<HuntQueryRequest>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct HuntJobRecord {
    pub id: Uuid,
    pub tenant_id: Uuid,
    pub job_type: String,
    pub status: String,
    pub request: Value,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result: Option<Value>,
    pub created_by: String,
    pub created_at: DateTime<Utc>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub completed_at: Option<DateTime<Utc>>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;

    #[test]
    fn request_converts_into_existing_query_primitives() {
        let request = HuntQueryRequest {
            sources: Some(vec![EventSource::Tetragon]),
            verdict: Some(QueryVerdict::Deny),
            start: Some(Utc.with_ymd_and_hms(2025, 3, 6, 12, 0, 0).unwrap()),
            end: Some(Utc.with_ymd_and_hms(2025, 3, 6, 13, 0, 0).unwrap()),
            action_type: Some("process".to_string()),
            process: Some("curl".to_string()),
            namespace: Some("default".to_string()),
            pod: Some("agent-pod".to_string()),
            entity: Some("agent-pod".to_string()),
            principal_id: Some("principal-1".to_string()),
            session_id: Some("session-1".to_string()),
            endpoint_agent_id: Some("endpoint-1".to_string()),
            runtime_agent_id: Some("runtime-1".to_string()),
            limit: Some(25),
            cursor: Some("cursor-1".to_string()),
        };

        let query = request.to_hunt_query();
        assert_eq!(query.sources, vec![EventSource::Tetragon]);
        assert_eq!(query.verdict, Some(QueryVerdict::Deny));
        assert_eq!(query.limit, 25);
        assert_eq!(query.process.as_deref(), Some("curl"));
        assert_eq!(query.entity.as_deref(), Some("agent-pod"));
    }

    #[test]
    fn hunt_event_projects_into_timeline_when_supported() {
        let event = HuntEvent {
            event_id: "evt-1".to_string(),
            tenant_id: Uuid::nil(),
            source: HuntEventSource::Tetragon,
            kind: HuntEventKind::ProcessExec,
            timestamp: Utc.with_ymd_and_hms(2025, 3, 6, 12, 0, 0).unwrap(),
            verdict: NormalizedVerdict::Allow,
            severity: Some("low".to_string()),
            summary: "process_exec /usr/bin/curl".to_string(),
            action_type: Some("process".to_string()),
            process: Some("/usr/bin/curl".to_string()),
            namespace: Some("default".to_string()),
            pod: Some("agent-pod".to_string()),
            session_id: Some("session-1".to_string()),
            endpoint_agent_id: Some("endpoint-1".to_string()),
            runtime_agent_id: Some("runtime-1".to_string()),
            principal_id: Some("principal-1".to_string()),
            grant_id: Some("grant-1".to_string()),
            response_action_id: None,
            detection_ids: vec!["finding-1".to_string()],
            target_kind: Some("process".to_string()),
            target_id: Some("123".to_string()),
            target_name: Some("curl".to_string()),
            envelope_hash: Some("abc123".to_string()),
            issuer: Some("spiffe://tenant/acme".to_string()),
            schema_name: Some("clawdstrike.sdr.fact.tetragon_event.v1".to_string()),
            signature_valid: Some(true),
            raw_ref: "hunt-envelope:evt-1".to_string(),
            attributes: serde_json::json!({"pid": 1001}),
        };

        let projected = event.to_timeline_event().expect("supported event");
        assert_eq!(projected.event_id.as_deref(), Some("evt-1"));
        assert_eq!(projected.kind, TimelineEventKind::ProcessExec);
        assert_eq!(projected.source, EventSource::Tetragon);
    }

    #[test]
    fn unsupported_sources_do_not_project_into_timeline() {
        let event = HuntEvent {
            event_id: "evt-2".to_string(),
            tenant_id: Uuid::nil(),
            source: HuntEventSource::Detection,
            kind: HuntEventKind::DetectionFired,
            timestamp: Utc.with_ymd_and_hms(2025, 3, 6, 12, 0, 0).unwrap(),
            verdict: NormalizedVerdict::Warn,
            severity: None,
            summary: "detection fired".to_string(),
            action_type: None,
            process: None,
            namespace: None,
            pod: None,
            session_id: None,
            endpoint_agent_id: None,
            runtime_agent_id: None,
            principal_id: None,
            grant_id: None,
            response_action_id: None,
            detection_ids: vec![],
            target_kind: None,
            target_id: None,
            target_name: None,
            envelope_hash: None,
            issuer: None,
            schema_name: None,
            signature_valid: None,
            raw_ref: "hunt-envelope:evt-2".to_string(),
            attributes: Value::Object(Default::default()),
        };

        assert!(event.to_timeline_event().is_none());
    }
}
