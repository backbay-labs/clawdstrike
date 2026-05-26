//! Policy simulation, replay, and detection candidate DTOs.

use serde::{Deserialize, Serialize};

use crate::edr::{
    CausalGraph, CausalNodeKind, EndpointDecisionAction, EndpointPolicySimulationReport,
    EndpointPolicySnapshot, EndpointSimulationImpactLevel,
};
use hush_core::SignedReceipt;

use super::response_actions::EdrGraphRootProcessSelectorInput;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EdrPolicySimulationInput {
    #[serde(default, alias = "rootNodeId")]
    pub root_node_id: Option<String>,
    #[serde(default)]
    pub process: Option<EdrGraphRootProcessSelectorInput>,
    #[serde(default, alias = "ruleId")]
    pub rule_id: Option<String>,
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default)]
    pub action: Option<EndpointDecisionAction>,
    #[serde(default, alias = "maxDepth")]
    pub max_depth: Option<usize>,
}

#[derive(Debug, Serialize)]
pub struct EdrPolicySimulationResponse {
    pub simulation: EndpointPolicySimulationReport,
    pub graph: CausalGraph,
    pub receipt: SignedReceipt,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EdrPolicyReplayInput {
    #[serde(default, alias = "rootNodeId")]
    pub root_node_id: Option<String>,
    #[serde(default)]
    pub process: Option<EdrGraphRootProcessSelectorInput>,
    #[serde(default)]
    pub action: Option<EndpointDecisionAction>,
    #[serde(default, alias = "ruleId")]
    pub rule_id: Option<String>,
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default, alias = "maxDepth")]
    pub max_depth: Option<usize>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EdrPolicyReplayReport {
    pub replay_id: String,
    pub replayed_at: chrono::DateTime<chrono::Utc>,
    pub mode: String,
    pub policy: EndpointPolicySnapshot,
    pub root_node_id: String,
    pub root_label: String,
    pub root_kind: CausalNodeKind,
    pub action: EndpointDecisionAction,
    pub graph_slice_id: String,
    pub observation_count: usize,
    pub node_count: usize,
    pub edge_count: usize,
    pub flight_recorder_observation_count: usize,
    pub would_enforce: bool,
    pub developer_breakage_score: u8,
    pub impact_level: EndpointSimulationImpactLevel,
    pub summary: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EdrPolicyReplayResponse {
    pub replay: EdrPolicyReplayReport,
    pub simulation: EndpointPolicySimulationReport,
    pub graph: CausalGraph,
    pub receipt: SignedReceipt,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EdrDetectionCandidateInput {
    #[serde(default, alias = "rootNodeId")]
    pub root_node_id: Option<String>,
    #[serde(default)]
    pub process: Option<EdrGraphRootProcessSelectorInput>,
    #[serde(default)]
    pub action: Option<EndpointDecisionAction>,
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default, alias = "maxDepth")]
    pub max_depth: Option<usize>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct EdrDetectionCandidate {
    pub rule_id: String,
    pub action: EndpointDecisionAction,
    pub description: String,
    pub root_node_id: String,
    pub root_label: String,
    pub root_kind: CausalNodeKind,
    pub graph_slice_id: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct EdrDetectionCandidateStage {
    pub stage: String,
    pub action: EndpointDecisionAction,
    pub promotion_gate: String,
    pub recommended: bool,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EdrDetectionCandidateResponse {
    pub candidate: EdrDetectionCandidate,
    pub recommended_stage: String,
    pub stage_plan: Vec<EdrDetectionCandidateStage>,
    pub simulation: EndpointPolicySimulationReport,
    pub graph: CausalGraph,
    pub receipt: SignedReceipt,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EdrStageDetectionInput {
    #[serde(default, alias = "rootNodeId")]
    pub root_node_id: Option<String>,
    #[serde(default)]
    pub process: Option<EdrGraphRootProcessSelectorInput>,
    #[serde(default)]
    pub action: Option<EndpointDecisionAction>,
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default, alias = "maxDepth")]
    pub max_depth: Option<usize>,
    #[serde(default, alias = "selectedStage")]
    pub stage: Option<String>,
    #[serde(default, alias = "crossWindowImpactHash")]
    pub cross_window_impact_hash: Option<String>,
    #[serde(default, alias = "crossWindowRecommendationHash")]
    pub cross_window_recommendation_hash: Option<String>,
    #[serde(default, alias = "stagedBy")]
    pub staged_by: Option<String>,
    #[serde(default)]
    pub note: Option<String>,
}

impl EdrStageDetectionInput {
    pub fn candidate_input(&self) -> EdrDetectionCandidateInput {
        EdrDetectionCandidateInput {
            root_node_id: self.root_node_id.clone(),
            process: self.process.clone(),
            action: self.action.clone(),
            description: self.description.clone(),
            max_depth: self.max_depth,
        }
    }
}

#[derive(Debug, Deserialize)]
pub struct EdrStagedDetectionsQuery {
    #[serde(default)]
    pub limit: Option<usize>,
    #[serde(default)]
    pub stage: Option<String>,
    #[serde(default, alias = "ruleId")]
    pub rule_id: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct EdrStagedDetectionRecord {
    pub staged_detection_id: String,
    pub staged_at: chrono::DateTime<chrono::Utc>,
    pub staged_by: String,
    pub stage: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cross_window_impact_hash: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cross_window_recommendation_hash: Option<String>,
    pub note: Option<String>,
    pub policy: EndpointPolicySnapshot,
    pub candidate: EdrDetectionCandidate,
    pub recommended_stage: String,
    pub stage_plan: Vec<EdrDetectionCandidateStage>,
    pub simulation: EndpointPolicySimulationReport,
    pub simulation_receipt: SignedReceipt,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EdrStageDetectionResponse {
    pub path: Option<String>,
    pub record: EdrStagedDetectionRecord,
    pub graph: CausalGraph,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EdrStagedDetectionsResponse {
    pub path: Option<String>,
    pub count: usize,
    pub staged_detections: Vec<EdrStagedDetectionRecord>,
}
