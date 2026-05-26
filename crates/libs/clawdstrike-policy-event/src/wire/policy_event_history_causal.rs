//! Causal-context subtypes for policy event history impact.
//!
//! Split out from [`super::policy_event_history`] so each file stays under
//! the wire crate's per-file line budget.

use std::collections::BTreeMap;

use serde::Serialize;

use crate::edr::{CausalGraph, CausalNodeKind, EndpointDecisionAction, EndpointSimulationImpactLevel};
use hush_core::SignedReceipt;

use super::policy_event_history::{
    EdrPolicyEventHistoryAffectedIdentities, EdrPolicyEventHistoryAffectedTool,
};

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EdrPolicyEventHistoryCausalImpact {
    pub changed_event_count: u64,
    pub context_count: usize,
    pub chain_count: usize,
    pub chain_driver_count: usize,
    pub promotion_suggestion_count: usize,
    pub affected_identity_count: usize,
    pub affected_tool_count: usize,
    pub blocking_change_count: u64,
    pub developer_breakage_score: u8,
    pub impact_level: EndpointSimulationImpactLevel,
    pub breakage_driver_count: usize,
    pub omitted_context_count: usize,
    pub missing_graph_context_count: usize,
    pub context_depth: usize,
    pub node_count: usize,
    pub edge_count: usize,
    pub node_kinds: BTreeMap<String, u64>,
    pub affected_identities: EdrPolicyEventHistoryAffectedIdentities,
    pub affected_tools: Vec<EdrPolicyEventHistoryAffectedTool>,
    pub top_breakage_drivers: Vec<EdrPolicyEventHistoryBreakageDriver>,
    pub contexts: Vec<EdrPolicyEventHistoryCausalContext>,
    pub chain_drivers: Vec<EdrPolicyEventHistoryCausalChainDriver>,
    pub promotion_suggestions: Vec<EdrPolicyEventHistoryPromotionSuggestion>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub receipt: Option<SignedReceipt>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EdrPolicyEventHistoryBreakageDriver {
    pub node_id: String,
    pub kind: CausalNodeKind,
    pub label: String,
    pub workflow_category: String,
    pub breakage_score: u8,
    pub reason: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EdrPolicyEventHistoryCausalContext {
    pub event_id: String,
    pub current_outcome: String,
    pub proposed_outcome: String,
    pub current_guard: Option<String>,
    pub proposed_guard: Option<String>,
    pub current_reason_code: String,
    pub proposed_reason_code: String,
    pub root_node_id: String,
    pub root_label: String,
    pub node_count: usize,
    pub edge_count: usize,
    pub chain_count: usize,
    pub chains: Vec<EdrPolicyEventHistoryCausalChain>,
    pub node_kinds: BTreeMap<String, u64>,
    pub graph: CausalGraph,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EdrPolicyEventHistoryCausalChain {
    pub target_node_id: String,
    pub target_label: String,
    pub target_kind: String,
    pub path_node_count: usize,
    pub path_edge_count: usize,
    pub nodes: Vec<EdrPolicyEventHistoryCausalChainNode>,
    pub edge_kinds: Vec<String>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EdrPolicyEventHistoryCausalChainNode {
    pub node_id: String,
    pub kind: String,
    pub label: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EdrPolicyEventHistoryCausalChainDriver {
    pub driver_id: String,
    pub current_outcome: String,
    pub proposed_outcome: String,
    pub current_guard: Option<String>,
    pub proposed_guard: Option<String>,
    pub current_reason_code: String,
    pub proposed_reason_code: String,
    pub target_kind: String,
    pub action: EndpointDecisionAction,
    pub edge_kinds: Vec<String>,
    pub count: u64,
    pub sample_event_ids: Vec<String>,
    pub sample_target_node_ids: Vec<String>,
    pub sample_target_labels: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct EdrPolicyEventHistoryCausalChainDriverKey {
    pub current_outcome: String,
    pub proposed_outcome: String,
    pub current_guard: Option<String>,
    pub proposed_guard: Option<String>,
    pub current_reason_code: String,
    pub proposed_reason_code: String,
    pub target_kind: String,
    pub action: String,
    pub edge_kinds: Vec<String>,
}

#[derive(Debug, Default)]
pub struct EdrPolicyEventHistoryCausalChainDriverBucket {
    pub count: u64,
    pub sample_event_ids: Vec<String>,
    pub sample_target_node_ids: Vec<String>,
    pub sample_target_labels: Vec<String>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EdrPolicyEventHistoryPromotionSuggestion {
    pub suggestion_id: String,
    pub event_id: String,
    pub target_node_id: String,
    pub target_label: String,
    pub target_kind: String,
    pub action: EndpointDecisionAction,
    pub selected_stage: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cross_window_impact_hash: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cross_window_recommendation_hash: Option<String>,
    pub reason: String,
    pub candidate_endpoint: String,
    pub candidate_request: EdrPolicyEventHistoryPromotionCandidateRequest,
    pub stage_endpoint: String,
    pub stage_request: EdrPolicyEventHistoryPromotionStageRequest,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EdrPolicyEventHistoryPromotionCandidateRequest {
    pub root_node_id: String,
    pub action: EndpointDecisionAction,
    pub max_depth: usize,
    pub description: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EdrPolicyEventHistoryPromotionStageRequest {
    pub root_node_id: String,
    pub action: EndpointDecisionAction,
    pub max_depth: usize,
    pub selected_stage: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cross_window_impact_hash: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cross_window_recommendation_hash: Option<String>,
    pub staged_by: String,
    pub note: String,
}
