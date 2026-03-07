use chrono::{DateTime, Utc};
use clawdstrike_ocsf::fleet::{default_empty_object, value_is_empty_object, FleetEventEnvelope};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use uuid::Uuid;

use crate::fleet_projection::{
    fleet_event_kind_as_timeline_kind, fleet_event_source_as_query_source, fleet_severity_label,
    fleet_verdict_as_normalized,
};
use crate::query::{EventSource, HuntQuery, QueryVerdict};
use crate::timeline::{NormalizedVerdict, TimelineEvent};

pub use clawdstrike_ocsf::fleet::{
    FleetEventKind as HuntEventKind, FleetEventSource as HuntEventSource,
};

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
    #[serde(
        default = "default_empty_object",
        skip_serializing_if = "value_is_empty_object"
    )]
    pub attributes: Value,
}

impl HuntEvent {
    pub fn to_timeline_event(&self) -> TimelineEvent {
        TimelineEvent {
            event_id: Some(self.event_id.clone()),
            timestamp: self.timestamp,
            source: fleet_event_source_as_query_source(self.source),
            kind: fleet_event_kind_as_timeline_kind(self.kind),
            verdict: self.verdict,
            severity: self.severity.clone(),
            summary: self.summary.clone(),
            process: self.process.clone(),
            namespace: self.namespace.clone(),
            pod: self.pod.clone(),
            action_type: self.action_type.clone(),
            signature_valid: self.signature_valid,
            raw: Some(self.attributes.clone()),
        }
    }

    pub fn try_from_fleet_event(event: &FleetEventEnvelope) -> Result<Self, String> {
        let tenant_id = Uuid::parse_str(&event.tenant_id)
            .map_err(|_| "event.tenantId must be a UUID".to_string())?;
        let timestamp = DateTime::parse_from_rfc3339(&event.occurred_at)
            .map_err(|_| "event.occurredAt must be RFC3339".to_string())?
            .with_timezone(&Utc);
        let verdict = fleet_verdict_as_normalized(event.verdict);
        let severity = event.severity.map(fleet_severity_label);

        Ok(Self {
            event_id: event.event_id.clone(),
            tenant_id,
            source: event.source,
            kind: event.kind,
            timestamp,
            verdict,
            severity,
            summary: event.summary.clone(),
            action_type: event.action_type.clone(),
            process: event
                .attributes
                .get("process")
                .and_then(Value::as_str)
                .map(ToOwned::to_owned),
            namespace: event
                .attributes
                .get("namespace")
                .and_then(Value::as_str)
                .map(ToOwned::to_owned),
            pod: event
                .attributes
                .get("pod")
                .and_then(Value::as_str)
                .map(ToOwned::to_owned),
            session_id: event.session_id.clone(),
            endpoint_agent_id: event
                .principal
                .as_ref()
                .and_then(|principal| principal.endpoint_agent_id.clone()),
            runtime_agent_id: event
                .principal
                .as_ref()
                .and_then(|principal| principal.runtime_agent_id.clone()),
            principal_id: event
                .principal
                .as_ref()
                .and_then(|principal| principal.principal_id.clone()),
            grant_id: event.grant_id.clone(),
            response_action_id: event.response_action_id.clone(),
            detection_ids: event.detection_ids.clone(),
            target_kind: event.target.as_ref().and_then(|target| target.kind.clone()),
            target_id: event.target.as_ref().and_then(|target| target.id.clone()),
            target_name: event.target.as_ref().and_then(|target| target.name.clone()),
            envelope_hash: event.evidence.envelope_hash.clone(),
            issuer: event.evidence.issuer.clone(),
            schema_name: event.evidence.schema_name.clone(),
            signature_valid: event.evidence.signature_valid,
            raw_ref: event.evidence.raw_ref.clone(),
            attributes: event.attributes.clone(),
        })
    }
}

impl TryFrom<&FleetEventEnvelope> for HuntEvent {
    type Error = String;

    fn try_from(value: &FleetEventEnvelope) -> Result<Self, Self::Error> {
        Self::try_from_fleet_event(value)
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
    /// Builds the shared hunt-query primitive consumed by the generic query layer.
    ///
    /// Fleet-specific identifiers such as `principal_id`, `session_id`,
    /// `endpoint_agent_id`, `runtime_agent_id`, and `cursor` are intentionally
    /// applied by the control-api fleet read model instead of the generic
    /// `HuntQuery` type.
    pub fn to_core_hunt_query(&self) -> HuntQuery {
        HuntQuery {
            sources: self.sources.clone().unwrap_or_default(),
            verdict: self.verdict,
            start: self.start,
            end: self.end,
            action_type: self.action_type.clone(),
            process: self.process.clone(),
            namespace: self.namespace.clone(),
            pod: self.pod.clone(),
            limit: self.limit_or_default(),
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
    use crate::timeline::TimelineEventKind;
    use chrono::TimeZone;
    use clawdstrike_ocsf::fleet::{
        FleetEventEvidence, FleetEventKind, FleetEventPrincipal, FleetEventSeverity,
        FleetEventSource, FleetEventTarget, FleetEventVerdict,
    };

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

        let query = request.to_core_hunt_query();
        assert_eq!(query.sources, vec![EventSource::Tetragon]);
        assert_eq!(query.verdict, Some(QueryVerdict::Deny));
        assert_eq!(query.limit, 25);
        assert_eq!(query.process.as_deref(), Some("curl"));
        assert_eq!(query.entity.as_deref(), Some("agent-pod"));
    }

    #[test]
    fn request_conversion_clamps_limit_to_public_bounds() {
        let request = HuntQueryRequest {
            limit: Some(10_000),
            ..Default::default()
        };

        let query = request.to_core_hunt_query();
        assert_eq!(query.limit, 500);
        assert_eq!(request.limit_or_default(), 500);
    }

    #[test]
    fn fleet_specific_filters_remain_on_request_boundary() {
        let request = HuntQueryRequest {
            principal_id: Some("principal-1".to_string()),
            session_id: Some("session-1".to_string()),
            endpoint_agent_id: Some("endpoint-1".to_string()),
            runtime_agent_id: Some("runtime-1".to_string()),
            cursor: Some("cursor-1".to_string()),
            ..Default::default()
        };

        let query = request.to_core_hunt_query();
        assert!(query.entity.is_none());
        assert_eq!(request.principal_id.as_deref(), Some("principal-1"));
        assert_eq!(request.session_id.as_deref(), Some("session-1"));
        assert_eq!(request.endpoint_agent_id.as_deref(), Some("endpoint-1"));
        assert_eq!(request.runtime_agent_id.as_deref(), Some("runtime-1"));
        assert_eq!(request.cursor.as_deref(), Some("cursor-1"));
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

        let projected = event.to_timeline_event();
        assert_eq!(projected.event_id.as_deref(), Some("evt-1"));
        assert_eq!(projected.kind, TimelineEventKind::ProcessExec);
        assert_eq!(projected.source, EventSource::Tetragon);
    }

    #[test]
    fn control_plane_sources_project_into_timeline() {
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

        let projected = event.to_timeline_event();
        assert_eq!(projected.source, EventSource::Detection);
        assert_eq!(projected.kind, TimelineEventKind::DetectionFired);
        assert_eq!(projected.event_id.as_deref(), Some("evt-2"));
    }

    #[test]
    fn fleet_event_envelope_converts_into_hunt_event_projection() {
        let fleet_event = FleetEventEnvelope {
            event_id: "evt-3".to_string(),
            tenant_id: Uuid::nil().to_string(),
            source: FleetEventSource::Tetragon,
            kind: FleetEventKind::ProcessExec,
            occurred_at: "2026-03-06T12:00:00Z".to_string(),
            ingested_at: "2026-03-06T12:00:01Z".to_string(),
            severity: Some(FleetEventSeverity::High),
            verdict: Some(FleetEventVerdict::Deny),
            summary: "process_exec /usr/bin/curl".to_string(),
            action_type: Some("process".to_string()),
            principal: Some(FleetEventPrincipal {
                principal_id: Some("principal-1".to_string()),
                endpoint_agent_id: Some("endpoint-1".to_string()),
                runtime_agent_id: None,
                principal_type: Some("endpoint_agent".to_string()),
            }),
            session_id: Some("session-1".to_string()),
            grant_id: Some("grant-1".to_string()),
            response_action_id: Some("action-1".to_string()),
            detection_ids: vec!["finding-1".to_string()],
            target: Some(FleetEventTarget {
                kind: Some("process".to_string()),
                id: Some("123".to_string()),
                name: Some("curl".to_string()),
            }),
            evidence: FleetEventEvidence {
                raw_ref: "hunt-envelope:evt-3".to_string(),
                envelope_hash: Some("hash-1".to_string()),
                issuer: Some("spiffe://tenant/acme".to_string()),
                schema_name: Some("clawdstrike.sdr.fact.tetragon_event.v1".to_string()),
                signature_valid: Some(true),
            },
            attributes: serde_json::json!({
                "process": "/usr/bin/curl",
                "namespace": "default",
                "pod": "agent-pod"
            }),
        };

        let event = HuntEvent::try_from_fleet_event(&fleet_event).expect("convert fleet event");
        assert_eq!(event.source, HuntEventSource::Tetragon);
        assert_eq!(event.kind, HuntEventKind::ProcessExec);
        assert_eq!(event.verdict, NormalizedVerdict::Deny);
        assert_eq!(event.severity.as_deref(), Some("high"));
        assert_eq!(event.endpoint_agent_id.as_deref(), Some("endpoint-1"));
        assert_eq!(event.process.as_deref(), Some("/usr/bin/curl"));
    }

    #[test]
    fn hunt_event_omits_absent_attributes() {
        let event = HuntEvent {
            event_id: "evt-4".to_string(),
            tenant_id: Uuid::nil(),
            source: HuntEventSource::Receipt,
            kind: HuntEventKind::GuardDecision,
            timestamp: Utc.with_ymd_and_hms(2025, 3, 6, 12, 0, 0).unwrap(),
            verdict: NormalizedVerdict::None,
            severity: None,
            summary: "receipt".to_string(),
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
            detection_ids: Vec::new(),
            target_kind: None,
            target_id: None,
            target_name: None,
            envelope_hash: None,
            issuer: None,
            schema_name: None,
            signature_valid: None,
            raw_ref: "hunt-envelope:evt-4".to_string(),
            attributes: default_empty_object(),
        };

        let json = serde_json::to_value(&event).expect("serialize event");
        assert!(json.get("attributes").is_none());
    }
}
