//! Detection finding ingestion and grouping DTOs.

use serde::{Deserialize, Serialize};

use crate::edr::{
    CausalGraph, DetectionFinding, EndpointObservation, HoneyArtifact,
};
use hush_core::SignedReceipt;

use super::policy_event_history::{
    EdrPolicyEventHistoryAffectedIdentities, EdrPolicyEventHistoryAffectedTool,
};

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EdrFindingsInput {
    #[serde(default)]
    pub observations: Vec<EndpointObservation>,
    #[serde(default, alias = "honeyArtifacts")]
    pub honey_artifacts: Vec<HoneyArtifact>,
}

#[derive(Debug)]
pub struct EdrEvaluatedFindings {
    pub findings: Vec<DetectionFinding>,
    pub receipts: Vec<SignedReceipt>,
}

#[derive(Debug, Serialize)]
pub struct EdrFindingsResponse {
    pub observation_count: usize,
    pub finding_count: usize,
    pub receipt_count: usize,
    pub findings: Vec<DetectionFinding>,
    pub receipts: Vec<SignedReceipt>,
    pub observation_receipts: Vec<SignedReceipt>,
}

#[derive(Debug, Deserialize)]
pub struct EdrFindingGroupsQuery {
    #[serde(default)]
    pub limit: Option<usize>,
    #[serde(default, alias = "maxDepth")]
    pub max_depth: Option<usize>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EdrFindingGroup {
    pub group_id: String,
    pub root_node_id: String,
    pub root_label: String,
    pub finding_count: usize,
    pub node_count: usize,
    pub edge_count: usize,
    pub rule_ids: Vec<String>,
    pub finding_ids: Vec<String>,
    pub findings: Vec<DetectionFinding>,
    pub affected_identity_count: usize,
    pub affected_tool_count: usize,
    pub affected_identities: EdrPolicyEventHistoryAffectedIdentities,
    pub affected_tools: Vec<EdrPolicyEventHistoryAffectedTool>,
    pub graph: CausalGraph,
    pub receipt: SignedReceipt,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EdrFindingGroupsResponse {
    pub group_count: usize,
    pub finding_count: usize,
    pub groups: Vec<EdrFindingGroup>,
}
