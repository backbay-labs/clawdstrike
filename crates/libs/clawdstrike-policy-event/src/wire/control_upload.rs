//! Control plane upload retry / backfill DTOs.
//!
//! These cover the upload retry orchestration shared between the agent and
//! control-api: receipt / archive / hunt-event retries and backfill batches.

use serde::{Deserialize, Serialize};

use super::secret_touches::EdrEvidenceBundleControlUploadReport;

#[derive(Debug, Default, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct EdrRawArtifactApprovalInput {
    #[serde(default)]
    pub raw_artifact_approval_id: Option<String>,
    #[serde(default)]
    pub raw_artifact_approval_reason: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct EdrControlArchiveUploadRetryInput {
    #[serde(default)]
    pub force: bool,
    #[serde(default)]
    pub limit: Option<usize>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EdrControlArchiveUploadRetryAttemptRecord {
    pub retry_id: String,
    pub archive_id: String,
    pub archive_hash: String,
    pub raw_ref: String,
    pub bundle_id: String,
    pub control_api_url: String,
    pub delivered: bool,
    pub attempt_count: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_attempt_at: Option<chrono::DateTime<chrono::Utc>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub http_status: Option<u16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub response_hash: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error_hash: Option<String>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EdrControlArchiveUploadRetryResponse {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
    pub attempted: usize,
    pub delivered: usize,
    pub failed: usize,
    pub skipped: usize,
    pub pending: usize,
    pub attempts: Vec<EdrControlArchiveUploadRetryAttemptRecord>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct EdrControlReceiptUploadRetryInput {
    #[serde(default)]
    pub force: bool,
    #[serde(default)]
    pub limit: Option<usize>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EdrControlReceiptUploadRetryAttemptRecord {
    pub retry_id: String,
    pub receipt_id: Option<String>,
    pub receipt_hash: String,
    pub control_api_url: String,
    pub delivered: bool,
    pub attempt_count: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_attempt_at: Option<chrono::DateTime<chrono::Utc>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub http_status: Option<u16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub response_hash: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error_hash: Option<String>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EdrControlReceiptUploadRetryResponse {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
    pub attempted: usize,
    pub delivered: usize,
    pub failed: usize,
    pub skipped: usize,
    pub pending: usize,
    pub attempts: Vec<EdrControlReceiptUploadRetryAttemptRecord>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct EdrControlArchiveUploadBackfillInput {
    #[serde(default)]
    pub bundle_id: Option<String>,
    #[serde(default)]
    pub limit: Option<usize>,
    #[serde(default)]
    pub raw_artifact_approval_id: Option<String>,
    #[serde(default)]
    pub raw_artifact_approval_reason: Option<String>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EdrControlArchiveUploadBackfillRecord {
    pub bundle_id: String,
    pub archive_id: String,
    pub archive_hash: String,
    pub raw_ref: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub control_upload: Option<EdrEvidenceBundleControlUploadReport>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EdrControlArchiveUploadBackfillResponse {
    pub attempted: usize,
    pub delivered: usize,
    pub failed: usize,
    pub skipped: usize,
    pub records: Vec<EdrControlArchiveUploadBackfillRecord>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct EdrFleetHuntEventRetryInput {
    #[serde(default)]
    pub force: bool,
    #[serde(default)]
    pub limit: Option<usize>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EdrFleetHuntEventRetryAttemptRecord {
    pub outbox_id: String,
    pub event_id: String,
    pub raw_ref: String,
    pub delivered: bool,
    pub attempt_count: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_attempt_at: Option<chrono::DateTime<chrono::Utc>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error_hash: Option<String>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EdrFleetHuntEventRetryResponse {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
    pub attempted: usize,
    pub delivered: usize,
    pub failed: usize,
    pub skipped: usize,
    pub pending: usize,
    pub attempts: Vec<EdrFleetHuntEventRetryAttemptRecord>,
}
