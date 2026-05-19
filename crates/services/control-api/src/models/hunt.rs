use chrono::{DateTime, Utc};
use clawdstrike_ocsf::fleet::FleetEventEnvelope;
use hunt_correlate::service::{CorrelateRequest, IocMatchRequest};
use hunt_query::service::HuntEvent;
use serde::{Deserialize, Serialize};
use serde_json::Value;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct IngestHuntEventRequest {
    pub event: FleetEventEnvelope,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub raw_envelope: Option<Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EndpointEvidenceArchiveUploadRequest {
    pub archive_id: String,
    pub archive_hash: String,
    pub raw_ref: String,
    pub bundle_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub endpoint_agent_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub event_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub raw_artifact_approval_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub raw_artifact_approval_reason_hash: Option<String>,
    pub archive: Value,
    pub verification: Value,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub retention_days: Option<i32>,
    #[serde(default = "empty_object")]
    pub metadata: Value,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct EndpointEvidenceArchiveRecord {
    pub tenant_id: uuid::Uuid,
    pub archive_id: String,
    pub raw_ref: String,
    pub archive_hash: String,
    pub bundle_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub endpoint_agent_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub event_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub content_hash: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub graph_slice_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub raw_artifact_approval_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub raw_artifact_approval_reason_hash: Option<String>,
    pub uploaded_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub retention_days: i32,
    pub size_bytes: i64,
    pub verification: Value,
    pub metadata: Value,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct EndpointEvidenceArchiveDownload {
    pub record: EndpointEvidenceArchiveRecord,
    pub archive: Value,
}

fn empty_object() -> Value {
    Value::Object(Default::default())
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct StoredSearchCursor {
    pub timestamp: DateTime<Utc>,
    pub event_id: String,
}

impl StoredSearchCursor {
    pub fn encode(&self) -> String {
        format!("{}::{}", self.timestamp.to_rfc3339(), self.event_id)
    }

    pub fn decode(input: &str) -> Option<Self> {
        let (timestamp, event_id) = input.split_once("::")?;
        Some(Self {
            timestamp: DateTime::parse_from_rfc3339(timestamp)
                .ok()?
                .with_timezone(&Utc),
            event_id: event_id.to_string(),
        })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct AgentSecretTouchesRequest {
    #[serde(default, alias = "since", skip_serializing_if = "Option::is_none")]
    pub start: Option<DateTime<Utc>>,
    #[serde(default, alias = "until", skip_serializing_if = "Option::is_none")]
    pub end: Option<DateTime<Utc>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub agent_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub endpoint_agent_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub runtime_agent_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub principal_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub credential_kind: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub limit: Option<usize>,
}

impl AgentSecretTouchesRequest {
    pub fn limit_or_default(&self) -> usize {
        self.limit.unwrap_or(100).clamp(1, 500)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct AgentSecretTouchEndpointSummary {
    pub group_key: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub endpoint_agent_id: Option<String>,
    pub event_count: usize,
    pub first_seen: DateTime<Utc>,
    pub last_seen: DateTime<Utc>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub runtime_agent_ids: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub principal_ids: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub session_ids: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub credential_kinds: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub event_ids: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct AgentSecretTouchesResponse {
    pub events: Vec<HuntEvent>,
    pub secret_touch_count: usize,
    pub endpoint_count: usize,
    pub runtime_agent_count: usize,
    pub principal_count: usize,
    pub endpoints: Vec<AgentSecretTouchEndpointSummary>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CorrelateJobRequest {
    #[serde(flatten)]
    pub request: CorrelateRequest,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct IocJobRequest {
    #[serde(flatten)]
    pub request: IocMatchRequest,
}
