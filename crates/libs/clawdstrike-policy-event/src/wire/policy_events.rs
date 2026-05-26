//! Policy event ingestion, replay, and impact DTOs.

use serde::{Deserialize, Serialize};

use crate::edr::{
    DetectionFinding, EndpointObservation, EndpointPolicySnapshot, HoneyArtifact,
};
use crate::event::PolicyEvent;
use crate::simulate::{DecisionInfo, SimulationResult};
use hush_core::SignedReceipt;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EdrPolicyEventsInput {
    #[serde(default)]
    pub events: Vec<PolicyEvent>,
    #[serde(default, alias = "honeyArtifacts")]
    pub honey_artifacts: Vec<HoneyArtifact>,
}

#[derive(Debug, Serialize)]
pub struct EdrPolicyEventsResponse {
    pub policy_event_count: usize,
    pub observation_count: usize,
    pub finding_count: usize,
    pub receipt_count: usize,
    pub observations: Vec<EndpointObservation>,
    pub findings: Vec<DetectionFinding>,
    pub receipts: Vec<SignedReceipt>,
    pub observation_receipts: Vec<SignedReceipt>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct EdrPolicyEventReplayInput {
    #[serde(default)]
    pub events: Vec<PolicyEvent>,
    #[serde(default)]
    pub track_posture: Option<bool>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EdrPolicyEventReplayReport {
    pub replay_id: String,
    pub replayed_at: chrono::DateTime<chrono::Utc>,
    pub mode: String,
    pub source: String,
    pub policy: EndpointPolicySnapshot,
    pub event_count: u64,
    pub allowed_count: u64,
    pub warn_count: u64,
    pub blocked_count: u64,
    pub track_posture: bool,
    pub event_stream_hash: String,
    pub result_hash: String,
    pub summary: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EdrPolicyEventReplayResponse {
    pub replay: EdrPolicyEventReplayReport,
    pub result: SimulationResult,
    pub receipt: SignedReceipt,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct EdrPolicyEventImpactInput {
    #[serde(default)]
    pub events: Vec<PolicyEvent>,
    #[serde(alias = "proposedPolicyYaml")]
    pub proposed_policy_yaml: String,
    #[serde(default)]
    pub track_posture: Option<bool>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EdrPolicyEventImpactSummary {
    pub total: u64,
    pub changed: u64,
    pub allow_to_warn: u64,
    pub allow_to_block: u64,
    pub warn_to_allow: u64,
    pub warn_to_block: u64,
    pub block_to_allow: u64,
    pub block_to_warn: u64,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EdrPolicyEventImpactEntry {
    pub event_id: String,
    pub current_outcome: String,
    pub proposed_outcome: String,
    pub changed: bool,
    pub current_decision: DecisionInfo,
    pub proposed_decision: DecisionInfo,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EdrPolicyEventImpactDriver {
    pub current_outcome: String,
    pub proposed_outcome: String,
    pub current_guard: Option<String>,
    pub proposed_guard: Option<String>,
    pub current_reason_code: String,
    pub proposed_reason_code: String,
    pub count: u64,
    pub sample_event_ids: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct EdrPolicyEventImpactDriverKey {
    pub current_outcome: String,
    pub proposed_outcome: String,
    pub current_guard: Option<String>,
    pub proposed_guard: Option<String>,
    pub current_reason_code: String,
    pub proposed_reason_code: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EdrPolicyEventImpactReport {
    pub impact_id: String,
    pub analyzed_at: chrono::DateTime<chrono::Utc>,
    pub mode: String,
    pub source: String,
    pub current_policy: EndpointPolicySnapshot,
    pub proposed_policy: EndpointPolicySnapshot,
    pub event_count: u64,
    pub changed_count: u64,
    pub allow_to_block_count: u64,
    pub track_posture: bool,
    pub event_stream_hash: String,
    pub current_result_hash: String,
    pub proposed_result_hash: String,
    pub impact_hash: String,
    pub summary: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EdrPolicyEventImpactResponse {
    pub impact: EdrPolicyEventImpactReport,
    pub summary: EdrPolicyEventImpactSummary,
    pub drivers: Vec<EdrPolicyEventImpactDriver>,
    pub changes: Vec<EdrPolicyEventImpactEntry>,
    pub current_result: SimulationResult,
    pub proposed_result: SimulationResult,
    pub receipt: SignedReceipt,
}
