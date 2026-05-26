//! Raw evidence-bundle archive upload envelope.
//!
//! Generated when the agent finalizes a fleet event evidence archive and the
//! local raw-artifact upload policy allows shipping it to the Control API.
//!
//! Wire path: `POST /api/v1/hunt/evidence-bundle-archives`.
//!
//! Before this crate, the agent built the envelope inline as
//! [`serde_json::Value`] and the Control API parsed it into a typed
//! `EndpointEvidenceArchiveUploadRequest`. The struct definition now lives
//! here so both sides share a single source of truth.

use serde::{Deserialize, Serialize};
use serde_json::Value;

/// Body of an archive upload request.
///
/// Note that several identifier fields (`endpointAgentId`, `eventId`,
/// `rawArtifactApprovalId`, `rawArtifactApprovalReasonHash`) are optional on
/// the Control API side but the agent always populates them today.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ControlArchiveUploadRequest {
    /// Stable archive identifier (hash-derived) reused as the storage key.
    pub archive_id: String,
    /// Hex-prefixed content hash of the archive bytes.
    pub archive_hash: String,
    /// Path or URI reference where the raw archive bytes can be retrieved.
    pub raw_ref: String,
    /// Evidence-bundle identifier embedded inside the archive.
    pub bundle_id: String,
    /// Endpoint agent identifier the archive belongs to.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub endpoint_agent_id: Option<String>,
    /// Event identifier correlated with the archive.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub event_id: Option<String>,
    /// Raw-artifact approval token covering this upload.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub raw_artifact_approval_id: Option<String>,
    /// Hash of the operator's reason text for granting the approval.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub raw_artifact_approval_reason_hash: Option<String>,
    /// The archive payload itself (opaque JSON document).
    pub archive: Value,
    /// Verification metadata (signatures, merkle proofs) for the archive.
    pub verification: Value,
    /// Optional retention override in days. Only the Control API populates
    /// this today, but it round-trips so future agents may set it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub retention_days: Option<i32>,
    /// Free-form upload metadata (`source`, `uploadPath`, `generatedAt`,
    /// `receiptCount`, etc). Defaults to `{}` when omitted.
    #[serde(default = "empty_object")]
    pub metadata: Value,
}

fn empty_object() -> Value {
    Value::Object(Default::default())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn archive_request_round_trips_with_camel_case() {
        let req = ControlArchiveUploadRequest {
            archive_id: "arch-1".to_string(),
            archive_hash: "0xabc".to_string(),
            raw_ref: "ref://1".to_string(),
            bundle_id: "bundle-1".to_string(),
            endpoint_agent_id: Some("endpoint-1".to_string()),
            event_id: Some("evt-1".to_string()),
            raw_artifact_approval_id: Some("approval-1".to_string()),
            raw_artifact_approval_reason_hash: Some("0xdef".to_string()),
            archive: serde_json::json!({"bundle": "data"}),
            verification: serde_json::json!({"sig": "v"}),
            retention_days: None,
            metadata: serde_json::json!({"source": "clawdstrike-agent"}),
        };
        let bytes = serde_json::to_vec(&req).unwrap();
        let s = String::from_utf8(bytes).unwrap();
        assert!(s.contains("\"archiveId\""));
        assert!(s.contains("\"endpointAgentId\""));
        assert!(s.contains("\"rawArtifactApprovalReasonHash\""));
        let back: ControlArchiveUploadRequest = serde_json::from_str(&s).unwrap();
        assert_eq!(back.archive_id, req.archive_id);
        assert_eq!(back.archive, req.archive);
    }

    #[test]
    fn archive_request_defaults_metadata_to_empty_object() {
        let raw = serde_json::json!({
            "archiveId": "a",
            "archiveHash": "h",
            "rawRef": "r",
            "bundleId": "b",
            "archive": {},
            "verification": {},
        });
        let req: ControlArchiveUploadRequest = serde_json::from_value(raw).unwrap();
        assert!(req.metadata.is_object());
    }
}
