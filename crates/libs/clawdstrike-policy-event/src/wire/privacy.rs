//! Privacy report and raw-artifact approval DTOs.

use serde::{Deserialize, Serialize};

use crate::edr::{
    EndpointObservation, EndpointTelemetryPrivacyMode, EndpointTelemetryPrivacyReport,
};
use hush_core::SignedReceipt;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EdrPrivacyReportInput {
    #[serde(default)]
    pub observations: Vec<EndpointObservation>,
    #[serde(default, alias = "privacyMode")]
    pub privacy_mode: Option<EndpointTelemetryPrivacyMode>,
    #[serde(default, alias = "rawArtifactApprovalId")]
    pub raw_artifact_approval_id: Option<String>,
    #[serde(default, alias = "rawArtifactApprovalReason")]
    pub raw_artifact_approval_reason: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct EdrPrivacyReportResponse {
    pub report: EndpointTelemetryPrivacyReport,
    pub privacy_policy: EdrPrivacyPolicyDecision,
    pub receipt: SignedReceipt,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EdrPrivacyPolicyDecision {
    pub requested_privacy_mode: EndpointTelemetryPrivacyMode,
    pub effective_privacy_mode: EndpointTelemetryPrivacyMode,
    pub raw_artifact_upload_requested: bool,
    pub raw_artifact_upload_allowed: bool,
    pub raw_artifact_approval_required: bool,
    pub raw_artifact_approval_provided: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub raw_artifact_approval_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub raw_artifact_approval_reason_hash: Option<String>,
    pub policy_source: String,
    pub denied_reason: Option<String>,
}

#[derive(Clone, Debug)]
pub struct EdrRawArtifactApproval {
    pub approval_id: String,
    pub reason_hash: String,
}

#[derive(Clone, Debug)]
pub struct EdrRawArtifactUploadPolicy {
    pub allowed: bool,
    pub source: String,
}
