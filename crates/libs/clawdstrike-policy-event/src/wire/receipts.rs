//! Receipt query / upload / compaction DTOs.

use serde::{Deserialize, Serialize};

use hush_core::SignedReceipt;

#[derive(Debug, Deserialize)]
pub struct EdrReceiptQuery {
    #[serde(default, alias = "receiptId")]
    pub receipt_id: Option<String>,
    #[serde(default)]
    pub family: Option<String>,
    #[serde(default)]
    pub limit: Option<usize>,
    #[serde(default)]
    pub action: Option<String>,
    #[serde(default, alias = "findingId")]
    pub finding_id: Option<String>,
    #[serde(default, alias = "ruleId")]
    pub rule_id: Option<String>,
    #[serde(default, alias = "graphSliceId")]
    pub graph_slice_id: Option<String>,
    #[serde(default, alias = "rootNodeId")]
    pub root_node_id: Option<String>,
    #[serde(default, alias = "executionId")]
    pub execution_id: Option<String>,
    #[serde(default)]
    pub status: Option<String>,
    #[serde(default, alias = "actorEndpointId")]
    pub actor_endpoint_id: Option<String>,
    #[serde(default, alias = "actorUserId")]
    pub actor_user_id: Option<String>,
    #[serde(default, alias = "actorSessionId")]
    pub actor_session_id: Option<String>,
    #[serde(default, alias = "actorAgentId")]
    pub actor_agent_id: Option<String>,
    #[serde(default, alias = "actorWorkloadId")]
    pub actor_workload_id: Option<String>,
    #[serde(default, alias = "actorApprovalId")]
    pub actor_approval_id: Option<String>,
    #[serde(default, alias = "localSequence")]
    pub local_sequence: Option<u64>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EdrReceiptUploadInput {
    #[serde(default, alias = "receiptId")]
    pub receipt_id: Option<String>,
    #[serde(default)]
    pub family: Option<String>,
    #[serde(default)]
    pub limit: Option<usize>,
    #[serde(default)]
    pub action: Option<String>,
    #[serde(default, alias = "findingId")]
    pub finding_id: Option<String>,
    #[serde(default, alias = "ruleId")]
    pub rule_id: Option<String>,
    #[serde(default, alias = "graphSliceId")]
    pub graph_slice_id: Option<String>,
    #[serde(default, alias = "rootNodeId")]
    pub root_node_id: Option<String>,
    #[serde(default, alias = "executionId")]
    pub execution_id: Option<String>,
    #[serde(default)]
    pub status: Option<String>,
    #[serde(default, alias = "actorEndpointId")]
    pub actor_endpoint_id: Option<String>,
    #[serde(default, alias = "actorUserId")]
    pub actor_user_id: Option<String>,
    #[serde(default, alias = "actorSessionId")]
    pub actor_session_id: Option<String>,
    #[serde(default, alias = "actorAgentId")]
    pub actor_agent_id: Option<String>,
    #[serde(default, alias = "actorWorkloadId")]
    pub actor_workload_id: Option<String>,
    #[serde(default, alias = "actorApprovalId")]
    pub actor_approval_id: Option<String>,
    #[serde(default, alias = "localSequence")]
    pub local_sequence: Option<u64>,
    #[serde(default, alias = "dryRun")]
    pub dry_run: Option<bool>,
}

#[derive(Debug, Serialize)]
pub struct EdrReceiptsResponse {
    pub path: Option<String>,
    pub receipt_count: usize,
    pub receipts: Vec<SignedReceipt>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EdrReceiptUploadResponse {
    pub path: Option<String>,
    pub dry_run: bool,
    pub control_api_url: Option<String>,
    pub selected_count: usize,
    pub attempted: bool,
    pub accepted: bool,
    pub uploaded_count: usize,
    pub http_status: Option<u16>,
    pub response_hash: Option<String>,
    pub error_hash: Option<String>,
    pub skipped_reason: Option<String>,
    pub records: Vec<EdrReceiptUploadRecord>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EdrReceiptUploadRecord {
    pub receipt_id: Option<String>,
    pub timestamp: String,
    pub family: Option<String>,
    pub verdict: String,
    pub guard: String,
    pub policy_name: String,
    pub local_sequence: Option<u64>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EdrReceiptCompactionInput {
    #[serde(default, alias = "maxReceipts")]
    pub max_receipts: Option<usize>,
    #[serde(default, alias = "minAgeSeconds")]
    pub min_age_seconds: Option<u64>,
    #[serde(default, alias = "dryRun")]
    pub dry_run: Option<bool>,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EdrReceiptCompactionRecord {
    pub receipt_id: Option<String>,
    pub timestamp: String,
    pub age_seconds: u64,
    pub family: Option<String>,
    pub action: Option<String>,
    pub finding_id: Option<String>,
    pub rule_id: Option<String>,
    pub graph_slice_id: Option<String>,
    pub root_node_id: Option<String>,
    pub local_sequence: Option<u64>,
    pub removed: bool,
    pub reason: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EdrReceiptCompactionResponse {
    pub path: Option<String>,
    pub dry_run: bool,
    pub max_receipts: Option<usize>,
    pub min_age_seconds: u64,
    pub receipt_count: usize,
    pub candidate_count: usize,
    pub removed_count: usize,
    pub retained_count: usize,
    pub records: Vec<EdrReceiptCompactionRecord>,
}

#[derive(Clone, Copy, Debug, Default)]
pub struct EdrReceiptFilter<'a> {
    pub receipt_id: Option<&'a str>,
    pub family: Option<&'a str>,
    pub action: Option<&'a str>,
    pub finding_id: Option<&'a str>,
    pub rule_id: Option<&'a str>,
    pub graph_slice_id: Option<&'a str>,
    pub root_node_id: Option<&'a str>,
    pub execution_id: Option<&'a str>,
    pub status: Option<&'a str>,
    pub actor_endpoint_id: Option<&'a str>,
    pub actor_user_id: Option<&'a str>,
    pub actor_session_id: Option<&'a str>,
    pub actor_agent_id: Option<&'a str>,
    pub actor_workload_id: Option<&'a str>,
    pub actor_approval_id: Option<&'a str>,
    pub local_sequence: Option<u64>,
}
