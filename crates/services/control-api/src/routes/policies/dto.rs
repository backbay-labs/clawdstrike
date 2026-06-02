//! Public request/response DTOs for the policy routes.

use super::*;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeployPolicyRequest {
    pub policy_yaml: String,
    pub description: Option<String>,
    #[serde(default)]
    pub break_glass: bool,
    pub break_glass_reason: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct DeployPolicyResponse {
    pub deployment_id: Uuid,
    pub tenant_slug: String,
    pub nats_subject: String,
    pub agent_count: i64,
    pub kv_write_failures: i64,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PreviewPolicyRequest {
    pub policy_yaml: String,
    pub description: Option<String>,
    pub agent_id: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct PreviewPolicyResponse {
    pub preview_id: Uuid,
    pub tenant_slug: String,
    pub status: String,
    pub would_deploy_version: i64,
    pub policy_yaml_sha256: String,
    pub distribution_policy_yaml: String,
    pub distribution_policy_sha256: String,
    pub deploy_allowed: bool,
    pub requires_deploy_approval: bool,
    pub agent_effective_policy: Option<PreviewEffectivePolicyResponse>,
}

#[derive(Debug, Serialize)]
pub struct PreviewEffectivePolicyResponse {
    pub agent_id: String,
    pub principal_id: Option<Uuid>,
    pub lifecycle_state: String,
    pub liveness_state: Option<String>,
    pub policy_epoch: i64,
    pub compiled_policy_yaml: String,
    pub compiled_policy_sha256: String,
    pub source_attachments: Vec<PreviewPolicyAttachmentResponse>,
    pub applied_overlays: Vec<String>,
}

#[derive(Debug, Serialize)]
pub struct PreviewPolicyAttachmentResponse {
    pub attachment_id: Uuid,
    pub target_kind: String,
    pub target_id: Uuid,
    pub priority: i32,
    pub policy_ref: Option<String>,
    pub checksum_sha256: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CreatePolicyProposalRequest {
    pub policy_yaml: String,
    pub description: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReviewPolicyProposalRequest {
    pub note: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AttachPolicyProposalImpactRequest {
    pub source: String,
    pub summary: String,
    pub simulation_receipt_id: Option<String>,
    pub simulation_receipt_sha256: Option<String>,
    pub simulation_receipt: Option<serde_json::Value>,
    pub simulation_receipt_public_key: Option<String>,
    #[serde(default)]
    pub simulation_receipts: Vec<PolicyProposalSimulationReceiptAttachment>,
    pub changed_verdict_count: i64,
    pub blocking_change_count: i64,
    pub developer_breakage_score: f64,
    pub affected_identity_count: i64,
    pub affected_tool_count: i64,
    pub recommendation: String,
    #[serde(default)]
    pub proof_hashes: Vec<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyProposalSimulationReceiptAttachment {
    pub receipt_id: Option<String>,
    pub receipt_sha256: Option<String>,
    pub receipt: serde_json::Value,
    pub public_key: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DispatchPolicyProposalFleetRuleDiffRequest {
    #[serde(default)]
    pub endpoint_agent_ids: Vec<String>,
    pub expires_at: Option<DateTime<Utc>>,
    pub reason: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CollectPolicyProposalFleetRuleDiffRequest {
    #[serde(default)]
    pub response_action_ids: Vec<Uuid>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DispatchPolicyProposalFleetRuleDiffResponse {
    pub proposal: PolicyProposalResponse,
    pub validation_plan_sha256: Option<String>,
    pub requested_endpoint_count: usize,
    pub dispatched_action_count: usize,
    pub dispatches: Vec<serde_json::Value>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CollectPolicyProposalFleetRuleDiffResponse {
    pub proposal: PolicyProposalResponse,
    pub validation_plan_sha256: Option<String>,
    pub collected_receipt_count: usize,
    pub collected_endpoint_count: usize,
    pub response_action_ids: Vec<Uuid>,
}

#[derive(Debug, Serialize)]
pub struct CreatePolicyProposalResponse {
    pub proposal: PolicyProposalResponse,
}

#[derive(Debug, Serialize)]
pub struct ApprovePolicyProposalResponse {
    pub proposal: PolicyProposalResponse,
    pub deployment: Option<DeployPolicyResponse>,
    pub approvals_remaining: i32,
}

#[derive(Debug, Serialize)]
pub struct PolicyProposalResponse {
    pub id: Uuid,
    pub tenant_id: Uuid,
    pub tenant_slug: String,
    pub policy_yaml: String,
    pub checksum_sha256: String,
    pub description: Option<String>,
    pub status: String,
    pub base_active_policy_version: i64,
    pub proposed_policy_version: i64,
    pub preview: serde_json::Value,
    pub required_approvals: i32,
    pub approval_count: i32,
    pub approvals_remaining: i32,
    pub approved_by: Vec<String>,
    pub approval_notes: serde_json::Value,
    pub impact: Option<serde_json::Value>,
    pub impact_attached_by: Option<String>,
    pub impact_attached_at: Option<DateTime<Utc>>,
    pub deployed_policy_version: Option<i64>,
    pub deployment_id: Option<Uuid>,
    pub submitted_by: String,
    pub reviewed_by: Option<String>,
    pub review_note: Option<String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub reviewed_at: Option<DateTime<Utc>>,
    pub deployed_at: Option<DateTime<Utc>>,
}

impl From<policy_distribution::EffectiveAgentPolicy> for PreviewEffectivePolicyResponse {
    fn from(policy: policy_distribution::EffectiveAgentPolicy) -> Self {
        Self {
            agent_id: policy.agent_id,
            principal_id: policy.principal_id,
            lifecycle_state: policy.lifecycle_state,
            liveness_state: policy.liveness_state,
            policy_epoch: policy.policy_epoch,
            compiled_policy_yaml: policy.policy_yaml,
            compiled_policy_sha256: policy.checksum_sha256,
            source_attachments: policy
                .source_attachments
                .into_iter()
                .map(PreviewPolicyAttachmentResponse::from)
                .collect(),
            applied_overlays: policy.applied_overlays,
        }
    }
}

impl From<policy_distribution::EffectivePolicyAttachment> for PreviewPolicyAttachmentResponse {
    fn from(attachment: policy_distribution::EffectivePolicyAttachment) -> Self {
        Self {
            attachment_id: attachment.attachment_id,
            target_kind: attachment.target_kind,
            target_id: attachment.target_id,
            priority: attachment.priority,
            policy_ref: attachment.policy_ref,
            checksum_sha256: attachment.checksum_sha256,
        }
    }
}
