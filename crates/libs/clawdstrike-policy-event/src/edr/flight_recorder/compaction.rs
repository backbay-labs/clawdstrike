use chrono::{DateTime, Utc};
use serde::Serialize;

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EndpointFlightRecorderCompactionRecord {
    pub observation_id: String,
    pub timestamp: DateTime<Utc>,
    pub event_kind: String,
    pub age_seconds: u64,
    pub protected_by_receipt: bool,
    pub removed: bool,
    pub reason: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EndpointFlightRecorderCompactionReport {
    pub observation_count: usize,
    pub retained_count: usize,
    pub protected_count: usize,
    pub records: Vec<EndpointFlightRecorderCompactionRecord>,
}


