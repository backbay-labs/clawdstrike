use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
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

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EndpointFlightRecorderCompactionReport {
    pub observation_count: usize,
    pub retained_count: usize,
    pub protected_count: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub continuity_manifest: Option<EndpointFlightRecorderCompactionManifest>,
    pub records: Vec<EndpointFlightRecorderCompactionRecord>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EndpointFlightRecorderCompactionManifest {
    pub schema_version: u8,
    pub compacted_at: DateTime<Utc>,
    pub reason: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub manifest_hash: Option<String>,
    pub pre_compaction_head: Option<String>,
    pub pre_compaction_record_count: u64,
    pub post_compaction_head: Option<String>,
    pub post_compaction_record_count: u64,
    pub retained_observation_ids: Vec<String>,
    pub removed_records: Vec<EndpointFlightRecorderCompactionRecord>,
}
