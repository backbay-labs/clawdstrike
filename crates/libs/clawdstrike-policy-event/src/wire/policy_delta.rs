//! Policy delta DTOs — input, listing, artifact, and apply-record payloads.
//!
//! `EdrPolicyDeltaApplyEnforcementProof` is intentionally **not** here: its
//! fields reference agent-private types (`NetworkExtensionReloadRequestProof`,
//! `DaemonStatus`) and therefore live in the agent's `edr/dto.rs`.

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::edr::{
    EndpointDecisionAction, EndpointDecisionActor, EndpointPolicySimulationIdentityContext,
    EndpointPolicySimulationToolContext,
};
use hush_core::SignedReceipt;

use super::response_actions::EdrResponseActionActorInput;
use super::simulation::EdrDetectionCandidate;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EdrPolicyDeltaInput {
    #[serde(default, alias = "stagedDetectionId")]
    pub staged_detection_id: Option<String>,
    #[serde(default, alias = "ruleId")]
    pub rule_id: Option<String>,
    #[serde(default)]
    pub stage: Option<String>,
    #[serde(default, alias = "generatedBy", alias = "promotedBy")]
    pub generated_by: Option<String>,
    #[serde(default)]
    pub note: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct EdrPolicyDeltasQuery {
    #[serde(default)]
    pub limit: Option<usize>,
    #[serde(default)]
    pub stage: Option<String>,
    #[serde(default, alias = "ruleId")]
    pub rule_id: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EdrPolicyDeltaApplyInput {
    #[serde(default, alias = "dryRun")]
    pub dry_run: Option<bool>,
    #[serde(default, alias = "allowBasePolicyDrift")]
    pub allow_base_policy_drift: Option<bool>,
    #[serde(default, alias = "reloadDaemonPolicy")]
    pub reload_daemon_policy: Option<bool>,
    #[serde(default, alias = "restartDaemon")]
    pub restart_daemon: Option<bool>,
    #[serde(default, alias = "verifyProtectionState")]
    pub verify_protection_state: Option<bool>,
    #[serde(default, alias = "providerAckTimeoutMs")]
    pub provider_ack_timeout_ms: Option<u64>,
    #[serde(default, alias = "appliedBy", alias = "promotedBy")]
    pub applied_by: Option<String>,
    #[serde(default)]
    pub actor: Option<EdrResponseActionActorInput>,
    #[serde(default)]
    pub note: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct EdrPolicyDeltaTargetPolicy {
    pub base_policy_version: String,
    pub base_policy_hash: String,
    pub base_policy_epoch: u64,
    pub target_policy_epoch: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct EdrPolicyDeltaRollout {
    pub stage: String,
    pub action: EndpointDecisionAction,
    pub recommended_stage: String,
    pub promotion_gate: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cross_window_impact_hash: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cross_window_recommendation_hash: Option<String>,
    pub developer_breakage_score: u8,
    pub impact_level: String,
    pub would_block: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct EdrPolicyDeltaArtifact {
    pub schema_version: String,
    pub policy_delta_id: String,
    pub generated_at: chrono::DateTime<chrono::Utc>,
    pub generated_by: String,
    pub note: Option<String>,
    pub staged_detection_id: String,
    pub source_simulation_id: String,
    pub source_simulation_receipt_id: Option<String>,
    #[serde(default)]
    pub source_affected_identities: Vec<EndpointPolicySimulationIdentityContext>,
    #[serde(default)]
    pub source_affected_tools: Vec<EndpointPolicySimulationToolContext>,
    pub candidate: EdrDetectionCandidate,
    pub target_policy: EdrPolicyDeltaTargetPolicy,
    pub rollout: EdrPolicyDeltaRollout,
    pub policy_patch: Value,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct EdrPolicyDeltaRecord {
    pub policy_delta_id: String,
    pub generated_at: chrono::DateTime<chrono::Utc>,
    pub generated_by: String,
    pub rule_id: String,
    pub stage: String,
    pub action: EndpointDecisionAction,
    pub artifact_hash: String,
    pub artifact_path: Option<String>,
    pub artifact: EdrPolicyDeltaArtifact,
    pub receipt: SignedReceipt,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EdrPolicyDeltaResponse {
    pub path: Option<String>,
    pub record: EdrPolicyDeltaRecord,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EdrPolicyDeltasResponse {
    pub path: Option<String>,
    pub count: usize,
    pub policy_deltas: Vec<EdrPolicyDeltaRecord>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EdrPolicyDeltaApplyRecord {
    pub policy_delta_id: String,
    pub applied_at: chrono::DateTime<chrono::Utc>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub apply_status: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub failure_reason: Option<String>,
    pub applied_by: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub actor: Option<EndpointDecisionActor>,
    pub note: Option<String>,
    pub dry_run: bool,
    pub applied: bool,
    pub allow_base_policy_drift: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cross_window_impact_hash: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cross_window_recommendation_hash: Option<String>,
    pub policy_path: String,
    pub backup_path: Option<String>,
    pub expected_base_policy_hash: String,
    pub previous_policy_hash: String,
    pub new_policy_hash: String,
    pub previous_policy_epoch: u64,
    pub new_policy_epoch: u64,
}
