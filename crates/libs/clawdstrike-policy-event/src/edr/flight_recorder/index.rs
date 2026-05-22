use std::collections::BTreeMap;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use super::super::causal::node::{CausalEdgeKind, CausalNodeKind};
use super::super::ENDPOINT_FLIGHT_RECORDER_GRAPH_EDGE_INDEX_SCHEMA_VERSION;
use super::super::ENDPOINT_FLIGHT_RECORDER_GRAPH_INDEX_SCHEMA_VERSION;
use super::super::ENDPOINT_FLIGHT_RECORDER_HISTORY_INDEX_SCHEMA_VERSION;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct EndpointFlightRecorderHistoryIndexEntry {
    #[serde(default)]
    pub schema_version: u8,
    pub observation_id: String,
    pub timestamp: DateTime<Utc>,
    pub event_kind: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub host_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub user_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub process_guid: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub parent_process_guid: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub process_image_hash: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub process_command_line_hash: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub agent_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub workload_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub approval_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tool_name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tool_call_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub credential_kind: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub event_target: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub event_target_hash: Option<String>,
    pub byte_offset: u64,
    pub byte_len: u64,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct EndpointFlightRecorderGraphNodeIndexEntry {
    #[serde(default)]
    pub schema_version: u8,
    pub node_id: String,
    pub kind: CausalNodeKind,
    pub label: String,
    pub first_seen: DateTime<Utc>,
    pub last_seen: DateTime<Utc>,
    #[serde(default)]
    pub attributes: BTreeMap<String, serde_json::Value>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct EndpointFlightRecorderGraphEdgeIndexEntry {
    #[serde(default)]
    pub schema_version: u8,
    pub edge_id: String,
    pub from: String,
    pub to: String,
    pub kind: CausalEdgeKind,
    pub timestamp: DateTime<Utc>,
    pub observation_id: String,
    #[serde(default)]
    pub attributes: BTreeMap<String, serde_json::Value>,
}
