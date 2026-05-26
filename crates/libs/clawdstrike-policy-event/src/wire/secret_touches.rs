//! Agent secret touch queries, hunt event publication, and evidence bundle
//! fleet publish DTOs.

use serde::{Deserialize, Serialize};

use crate::edr::CausalGraph;
use hush_core::SignedReceipt;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EdrAgentSecretTouchesInput {
    #[serde(default, alias = "sessionId")]
    pub session_id: Option<String>,
    #[serde(default, alias = "credentialKind")]
    pub credential_kind: Option<String>,
    #[serde(default, alias = "requireAgentContext")]
    pub require_agent_context: Option<bool>,
    #[serde(default, alias = "upstreamDepth")]
    pub upstream_depth: Option<usize>,
    #[serde(default, alias = "downstreamDepth")]
    pub downstream_depth: Option<usize>,
    #[serde(default)]
    pub limit: Option<usize>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EdrAgentSecretTouch {
    pub credential_node_id: String,
    pub credential_label: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub credential_kind: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    pub agent_node_ids: Vec<String>,
    pub agent_labels: Vec<String>,
    pub process_node_ids: Vec<String>,
    pub graph: CausalGraph,
    pub receipt: SignedReceipt,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EdrAgentSecretTouchesResponse {
    pub touch_count: usize,
    pub touches: Vec<EdrAgentSecretTouch>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EdrPublishedHuntEvent {
    pub event_id: String,
    pub raw_ref: String,
    pub credential_node_id: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EdrEvidenceBundleFleetPublishResponse {
    pub bundle_id: String,
    pub archive_id: String,
    pub archive_hash: String,
    pub published: bool,
    pub queued: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub control_upload: Option<EdrEvidenceBundleControlUploadReport>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub outbox_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_retry_at: Option<chrono::DateTime<chrono::Utc>>,
    pub event_id: String,
    pub raw_ref: String,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EdrEvidenceBundleControlUploadReport {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub control_api_url: Option<String>,
    pub attempted: bool,
    pub accepted: bool,
    pub raw_artifact_upload_allowed: bool,
    pub raw_artifact_approval_required: bool,
    pub raw_artifact_approval_provided: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub raw_artifact_approval_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub raw_artifact_approval_reason_hash: Option<String>,
    pub policy_source: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub skipped_reason: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub http_status: Option<u16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub response_hash: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error_hash: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    pub retry_queued: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub retry_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_retry_at: Option<chrono::DateTime<chrono::Utc>>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EdrAgentSecretTouchesFleetPublishResponse {
    pub touch_count: usize,
    pub published_count: usize,
    pub events: Vec<EdrPublishedHuntEvent>,
}
