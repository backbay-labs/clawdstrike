use chrono::{DateTime, Utc};
use clawdstrike_ocsf::fleet::FleetEventEnvelope;
use hunt_correlate::service::{CorrelateRequest, IocMatchRequest};
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
