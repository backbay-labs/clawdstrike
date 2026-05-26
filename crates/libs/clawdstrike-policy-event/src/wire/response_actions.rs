//! Response action proposal / execution / rollback / acknowledgement DTOs.
//!
//! `EdrControlAckPostbackRetryAttemptRecord` is **not** here: it references
//! agent-private `ControlResponseAckPostbackRoute`. The extension impl
//! `EdrResponseExecutionRecord::hydrate_attribution` and
//! `EdrEvidenceBundleArtifact::from_stored` likewise stay in the agent.

use serde::{Deserialize, Serialize};

use crate::edr::{
    CausalGraph, EndpointDecisionAction, EndpointGraphReference, EndpointResponseAcknowledgementReport,
    EndpointResponseExecutionReport, EndpointResponsePlan, EndpointResponseRollbackReport,
    EndpointSensorState,
};
use hush_core::SignedReceipt;

use super::evidence_bundles::EdrEvidenceBundleArtifact;
use super::policy_event_history::{
    EdrPolicyEventHistoryAffectedIdentities, EdrPolicyEventHistoryAffectedTool,
};

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EdrResponseActionInput {
    pub action: EndpointDecisionAction,
    #[serde(default, alias = "rootNodeId")]
    pub root_node_id: Option<String>,
    #[serde(default)]
    pub process: Option<EdrGraphRootProcessSelectorInput>,
    #[serde(default)]
    pub actor: Option<EdrResponseActionActorInput>,
    #[serde(default, alias = "ttlSeconds")]
    pub ttl_seconds: Option<u64>,
    #[serde(default)]
    pub reason: Option<String>,
    #[serde(default, alias = "dryRun")]
    pub dry_run: Option<bool>,
}

#[derive(Clone, Debug, Default, Deserialize)]
#[serde(default, rename_all = "camelCase", deny_unknown_fields)]
pub struct EdrGraphRootProcessSelectorInput {
    pub pid: Option<u32>,
    pub ppid: Option<u32>,
    pub process_guid: Option<String>,
    pub parent_process_guid: Option<String>,
    pub image: Option<String>,
    pub command_line: Option<String>,
    pub cwd: Option<String>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(default, rename_all = "camelCase", deny_unknown_fields)]
pub struct EdrResponseActionActorInput {
    pub endpoint_id: String,
    pub host_id: Option<String>,
    pub user_id: Option<String>,
    pub session_id: Option<String>,
    pub posture: Option<String>,
    pub agent_id: Option<String>,
    pub workload_id: Option<String>,
    pub approval_id: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct EdrResponseActionResponse {
    pub plan: EndpointResponsePlan,
    pub graph: CausalGraph,
    #[serde(rename = "affectedIdentityCount")]
    pub affected_identity_count: usize,
    #[serde(rename = "affectedToolCount")]
    pub affected_tool_count: usize,
    #[serde(rename = "affectedIdentities")]
    pub affected_identities: EdrPolicyEventHistoryAffectedIdentities,
    #[serde(rename = "affectedTools")]
    pub affected_tools: Vec<EdrPolicyEventHistoryAffectedTool>,
    pub receipt: SignedReceipt,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub execution: Option<EndpointResponseExecutionReport>,
    #[serde(
        rename = "evidenceBundleArtifact",
        skip_serializing_if = "Option::is_none"
    )]
    pub evidence_bundle_artifact: Option<EdrEvidenceBundleArtifact>,
    #[serde(rename = "executionReceipt", skip_serializing_if = "Option::is_none")]
    pub execution_receipt: Option<SignedReceipt>,
    #[serde(
        rename = "evidenceBundleReceipt",
        skip_serializing_if = "Option::is_none"
    )]
    pub evidence_bundle_receipt: Option<SignedReceipt>,
}

#[derive(Debug, Deserialize)]
pub struct EdrResponseExecutionQuery {
    #[serde(default)]
    pub limit: Option<usize>,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EdrResponseExecutionRecord {
    pub execution: EndpointResponseExecutionReport,
    pub expires_at: chrono::DateTime<chrono::Utc>,
    pub expired: bool,
    pub rollback_ref: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub affected_identity_count: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub affected_tool_count: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub affected_identities: Option<EdrPolicyEventHistoryAffectedIdentities>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub affected_tools: Option<Vec<EdrPolicyEventHistoryAffectedTool>>,
}

impl EdrResponseExecutionRecord {
    pub fn from_execution(execution: EndpointResponseExecutionReport) -> Self {
        let expires_at = execution.expires_at();
        let expired = chrono::Utc::now() > expires_at;
        let rollback_ref = execution.rollback_ref.clone();
        Self {
            execution,
            expires_at,
            expired,
            rollback_ref,
            affected_identity_count: None,
            affected_tool_count: None,
            affected_identities: None,
            affected_tools: None,
        }
    }
}

#[derive(Debug, Serialize)]
pub struct EdrResponseExecutionsResponse {
    pub path: Option<String>,
    pub execution_count: usize,
    pub executions: Vec<EdrResponseExecutionRecord>,
}

#[derive(Debug, Serialize)]
pub struct EdrResponseExecutionResponse {
    pub path: Option<String>,
    pub execution: EdrResponseExecutionRecord,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EdrResponseExecutionProofResponse {
    pub execution_path: Option<String>,
    pub receipt_path: Option<String>,
    pub execution: EdrResponseExecutionRecord,
    pub graph: EndpointGraphReference,
    pub affected_identity_count: usize,
    pub affected_tool_count: usize,
    pub affected_identities: EdrPolicyEventHistoryAffectedIdentities,
    pub affected_tools: Vec<EdrPolicyEventHistoryAffectedTool>,
    pub provider_state: EndpointSensorState,
    pub evidence_bundle_artifact: EdrEvidenceBundleArtifact,
    pub request_receipt: SignedReceipt,
    pub execution_receipt: SignedReceipt,
    pub evidence_bundle_receipt: SignedReceipt,
    pub transition_receipts: Vec<SignedReceipt>,
    pub rollback_receipts: Vec<SignedReceipt>,
    pub acknowledgement_receipts: Vec<SignedReceipt>,
}

#[derive(Debug, Serialize)]
pub struct EdrResponseExecutionExpireResponse {
    pub path: Option<String>,
    pub expired_count: usize,
    pub executions: Vec<EdrResponseExecutionRecord>,
    pub receipts: Vec<SignedReceipt>,
    pub rollback_count: usize,
    pub rollbacks: Vec<EndpointResponseRollbackReport>,
    pub rollback_receipts: Vec<SignedReceipt>,
    pub rollback_transitions: Vec<EdrResponseExecutionRecord>,
    pub rollback_transition_receipts: Vec<SignedReceipt>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EdrResponseExecutionCancelInput {
    #[serde(default)]
    pub reason: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct EdrResponseExecutionCancelResponse {
    pub path: Option<String>,
    pub execution: EdrResponseExecutionRecord,
    pub receipt: SignedReceipt,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EdrResponseExecutionRollbackInput {
    #[serde(default)]
    pub reason: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct EdrResponseExecutionRollbackResponse {
    pub path: Option<String>,
    pub execution: EdrResponseExecutionRecord,
    pub rollback_transition: EdrResponseExecutionRecord,
    pub rollback: EndpointResponseRollbackReport,
    pub receipt: SignedReceipt,
    pub transition_receipt: SignedReceipt,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EdrResponseExecutionAcknowledgeInput {
    #[serde(default, alias = "acknowledgedBy")]
    pub acknowledged_by: Option<String>,
    #[serde(default)]
    pub note: Option<String>,
    #[serde(default, alias = "controlApi", alias = "controlCorrelation")]
    pub control: Option<EdrResponseControlAcknowledgementInput>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct EdrResponseControlAcknowledgementInput {
    #[serde(default, alias = "responseActionID")]
    pub response_action_id: Option<String>,
    #[serde(default, alias = "deliveryID")]
    pub delivery_id: Option<String>,
    #[serde(default)]
    pub target_kind: Option<String>,
    #[serde(default)]
    pub target_id: Option<String>,
    #[serde(default)]
    pub ack_token: Option<String>,
    #[serde(default)]
    pub status: Option<String>,
    #[serde(default)]
    pub resulting_state: Option<String>,
    #[serde(default, alias = "url", alias = "baseUrl", alias = "controlApiUrl")]
    pub control_api_url: Option<String>,
    #[serde(
        default,
        alias = "apiKey",
        alias = "bearerToken",
        alias = "controlApiKey",
        alias = "controlApiToken",
        alias = "controlApiBearerToken"
    )]
    pub control_api_token: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct EdrResponseExecutionAcknowledgeResponse {
    pub path: Option<String>,
    pub execution: EdrResponseExecutionRecord,
    pub acknowledgement: EndpointResponseAcknowledgementReport,
    pub receipt: SignedReceipt,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        rename = "controlPostback"
    )]
    pub control_postback: Option<EdrResponseControlPostbackReport>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EdrResponseControlPostbackReport {
    pub control_api_url: String,
    pub response_action_id: String,
    pub accepted: bool,
    pub retry_queued: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub retry_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub next_retry_at: Option<chrono::DateTime<chrono::Utc>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub http_status: Option<u16>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub response_hash: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error_hash: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct EdrResponseAcknowledgementQuery {
    pub limit: Option<usize>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct EdrControlAckPostbackRetryInput {
    #[serde(default)]
    pub force: bool,
    #[serde(default)]
    pub limit: Option<usize>,
}

// `EdrControlAckPostbackRetryResponse` and `EdrControlAckPostbackRetryAttemptRecord`
// reference the agent-private `ControlResponseAckPostbackRoute` enum and remain
// in the agent's `edr/dto.rs`. Re-import them from there via the agent's
// existing `pub(crate) use crate::edr::dto::*` re-export.

#[derive(Debug, Serialize)]
pub struct EdrResponseAcknowledgementRecord {
    pub acknowledgement: EndpointResponseAcknowledgementReport,
}

impl EdrResponseAcknowledgementRecord {
    pub fn from_acknowledgement(
        acknowledgement: EndpointResponseAcknowledgementReport,
    ) -> Self {
        Self { acknowledgement }
    }
}

#[derive(Debug, Serialize)]
pub struct EdrResponseAcknowledgementsResponse {
    pub path: Option<String>,
    pub count: usize,
    pub acknowledgements: Vec<EdrResponseAcknowledgementRecord>,
}
