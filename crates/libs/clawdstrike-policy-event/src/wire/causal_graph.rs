//! Causal graph query, subgraph, search, and slice-export DTOs.

use std::path::PathBuf;

use serde::{Deserialize, Serialize};

use crate::edr::{
    CausalGraph, CausalNodeKind, EndpointEvidenceBundleReference, EndpointObservation,
};
use hush_core::SignedReceipt;

use super::evidence_bundles::EdrEvidenceBundleArtifact;
use super::policy_event_history::{
    EdrPolicyEventHistoryAffectedIdentities, EdrPolicyEventHistoryAffectedTool,
};
use super::response_actions::EdrGraphRootProcessSelectorInput;

#[derive(Debug, Deserialize)]
pub struct EdrCausalGraphInput {
    #[serde(default)]
    pub observations: Vec<EndpointObservation>,
}

#[derive(Debug, Serialize)]
pub struct EdrCausalGraphResponse {
    pub observation_count: usize,
    pub node_count: usize,
    pub edge_count: usize,
    pub graph: CausalGraph,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EdrCausalSubgraphInput {
    #[serde(default, alias = "rootNodeId")]
    pub root_node_id: Option<String>,
    #[serde(default)]
    pub process: Option<EdrGraphRootProcessSelectorInput>,
    #[serde(default, alias = "maxDepth")]
    pub max_depth: Option<usize>,
}

#[derive(Debug, Serialize)]
pub struct EdrCausalSubgraphResponse {
    pub root_node_id: String,
    pub max_depth: usize,
    pub node_count: usize,
    pub edge_count: usize,
    pub affected_identity_count: usize,
    pub affected_tool_count: usize,
    pub affected_identities: EdrPolicyEventHistoryAffectedIdentities,
    pub affected_tools: Vec<EdrPolicyEventHistoryAffectedTool>,
    pub graph: CausalGraph,
    pub receipt: SignedReceipt,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EdrCausalContextInput {
    #[serde(default, alias = "rootNodeId")]
    pub root_node_id: Option<String>,
    #[serde(default)]
    pub process: Option<EdrGraphRootProcessSelectorInput>,
    #[serde(default, alias = "upstreamDepth")]
    pub upstream_depth: Option<usize>,
    #[serde(default, alias = "downstreamDepth")]
    pub downstream_depth: Option<usize>,
}

#[derive(Debug, Serialize)]
pub struct EdrCausalContextResponse {
    pub root_node_id: String,
    pub upstream_depth: usize,
    pub downstream_depth: usize,
    #[serde(rename = "contextExpansionStrategy")]
    pub context_expansion_strategy: String,
    #[serde(rename = "edgeIndexSource")]
    pub edge_index_source: String,
    #[serde(rename = "edgeIndexPath", skip_serializing_if = "Option::is_none")]
    pub edge_index_path: Option<PathBuf>,
    #[serde(rename = "edgeIndexCount")]
    pub edge_index_count: usize,
    pub node_count: usize,
    pub edge_count: usize,
    pub affected_identity_count: usize,
    pub affected_tool_count: usize,
    pub affected_identities: EdrPolicyEventHistoryAffectedIdentities,
    pub affected_tools: Vec<EdrPolicyEventHistoryAffectedTool>,
    pub graph: CausalGraph,
    pub receipt: SignedReceipt,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EdrGraphSearchInput {
    #[serde(default, alias = "nodeKind", alias = "kind")]
    pub node_kind: Option<CausalNodeKind>,
    #[serde(default, alias = "labelContains")]
    pub label_contains: Option<String>,
    #[serde(
        default,
        alias = "filePath",
        alias = "credentialPath",
        alias = "targetPath"
    )]
    pub path: Option<String>,
    #[serde(
        default,
        alias = "pathPrefix",
        alias = "filePathPrefix",
        alias = "credentialPathPrefix",
        alias = "targetPathPrefix"
    )]
    pub path_prefix: Option<String>,
    #[serde(
        default,
        alias = "pathPattern",
        alias = "filePathPattern",
        alias = "credentialPathPattern",
        alias = "targetPathPattern"
    )]
    pub path_pattern: Option<String>,
    #[serde(default, alias = "attributeKey")]
    pub attribute_key: Option<String>,
    #[serde(default, alias = "attributeValue")]
    pub attribute_value: Option<String>,
    #[serde(default, alias = "toolName")]
    pub tool_name: Option<String>,
    #[serde(default, alias = "hostId")]
    pub host_id: Option<String>,
    #[serde(default, alias = "sessionId")]
    pub session_id: Option<String>,
    #[serde(default, alias = "userId")]
    pub user_id: Option<String>,
    #[serde(default, alias = "agentId")]
    pub agent_id: Option<String>,
    #[serde(default, alias = "workloadId")]
    pub workload_id: Option<String>,
    #[serde(default, alias = "approvalId")]
    pub approval_id: Option<String>,
    #[serde(default, alias = "upstreamDepth")]
    pub upstream_depth: Option<usize>,
    #[serde(default, alias = "downstreamDepth")]
    pub downstream_depth: Option<usize>,
    #[serde(default)]
    pub limit: Option<usize>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EdrGraphSearchMatch {
    pub root_node_id: String,
    pub root_label: String,
    pub root_kind: CausalNodeKind,
    pub node_count: usize,
    pub edge_count: usize,
    pub affected_identity_count: usize,
    pub affected_tool_count: usize,
    pub affected_identities: EdrPolicyEventHistoryAffectedIdentities,
    pub affected_tools: Vec<EdrPolicyEventHistoryAffectedTool>,
    pub graph: CausalGraph,
    pub receipt: SignedReceipt,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EdrGraphSearchQueryPlan {
    pub strategy: String,
    pub indexed: bool,
    pub index_source: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub index_path: Option<PathBuf>,
    pub edge_index_source: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub edge_index_path: Option<PathBuf>,
    pub edge_index_count: usize,
    pub context_expansion_strategy: String,
    pub indexed_keys: Vec<String>,
    pub candidate_count: usize,
    pub scanned_node_count: usize,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EdrGraphSearchResponse {
    pub match_count: usize,
    pub total_match_count: usize,
    pub upstream_depth: usize,
    pub downstream_depth: usize,
    pub query_plan: EdrGraphSearchQueryPlan,
    pub matches: Vec<EdrGraphSearchMatch>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EdrGraphSliceExportInput {
    #[serde(default, alias = "rootNodeId")]
    pub root_node_id: Option<String>,
    #[serde(default)]
    pub process: Option<EdrGraphRootProcessSelectorInput>,
    #[serde(default, alias = "sliceKind")]
    pub slice_kind: Option<String>,
    #[serde(default, alias = "maxDepth")]
    pub max_depth: Option<usize>,
    #[serde(default, alias = "upstreamDepth")]
    pub upstream_depth: Option<usize>,
    #[serde(default, alias = "downstreamDepth")]
    pub downstream_depth: Option<usize>,
    #[serde(default)]
    pub reason: Option<String>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EdrGraphSliceExportResponse {
    pub root_node_id: String,
    pub slice_kind: String,
    pub node_count: usize,
    pub edge_count: usize,
    pub affected_identity_count: usize,
    pub affected_tool_count: usize,
    pub affected_identities: EdrPolicyEventHistoryAffectedIdentities,
    pub affected_tools: Vec<EdrPolicyEventHistoryAffectedTool>,
    pub graph: CausalGraph,
    pub bundle: EndpointEvidenceBundleReference,
    pub artifact: EdrEvidenceBundleArtifact,
    pub receipt: SignedReceipt,
}
