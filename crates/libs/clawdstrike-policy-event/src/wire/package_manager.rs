//! Package manager (supply-chain runtime guard) event DTOs.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::edr::{
    DetectionFinding, EndpointObservation, EndpointProcess, HoneyArtifact, PackageManager,
};
use hush_core::SignedReceipt;

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct EdrPackageManagerEventsInput {
    #[serde(default)]
    pub events: Vec<EdrPackageManagerEvent>,
    #[serde(default, alias = "honey_artifacts")]
    pub honey_artifacts: Vec<HoneyArtifact>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct EdrPackageManagerEvent {
    #[serde(default, alias = "id", alias = "eventId")]
    pub event_id: Option<String>,
    #[serde(default, alias = "observedAt", alias = "timestamp")]
    pub observed_at: Option<chrono::DateTime<chrono::Utc>>,
    #[serde(default, alias = "hostId")]
    pub host_id: Option<String>,
    #[serde(default, alias = "userId")]
    pub user_id: Option<String>,
    #[serde(default, alias = "sessionId")]
    pub session_id: Option<String>,
    #[serde(default, alias = "agentId")]
    pub agent_id: Option<String>,
    #[serde(default, alias = "workloadId")]
    pub workload_id: Option<String>,
    #[serde(default, alias = "approvalId")]
    pub approval_id: Option<String>,
    #[serde(default, alias = "toolCallId", alias = "tool_call_id")]
    pub tool_call_id: Option<String>,
    #[serde(default)]
    pub process: Option<EndpointProcess>,
    #[serde(default)]
    pub metadata: BTreeMap<String, serde_json::Value>,
    pub manager: PackageManager,
    #[serde(default)]
    pub package: Option<String>,
    pub phase: String,
    pub script: String,
    #[serde(default, alias = "workingDirectory")]
    pub working_directory: Option<String>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EdrPackageManagerEventsResponse {
    pub event_count: usize,
    pub observation_count: usize,
    pub finding_count: usize,
    pub receipt_count: usize,
    pub observations: Vec<EndpointObservation>,
    pub findings: Vec<DetectionFinding>,
    pub receipts: Vec<SignedReceipt>,
    pub observation_receipts: Vec<SignedReceipt>,
    pub policy_decision_receipts: Vec<SignedReceipt>,
}
