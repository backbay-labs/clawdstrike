//! Marketplace fact schemas for Spine-backed provenance verification.
//!
//! Defines `policy_attestation.v1`, `review_attestation.v1`, and
//! `revocation.v1` typed facts that enable decentralized marketplace
//! provenance verification via Spine inclusion proofs, replacing the
//! centralized notary model.

use serde::{Deserialize, Serialize};
use serde_json::Value;

/// Schema identifier for curator policy attestation facts.
pub const POLICY_ATTESTATION_SCHEMA: &str = "clawdstrike.marketplace.policy_attestation.v1";

/// Schema identifier for community review attestation facts.
pub const REVIEW_ATTESTATION_SCHEMA: &str = "clawdstrike.marketplace.review_attestation.v1";

/// Schema identifier for policy revocation facts.
pub const REVOCATION_SCHEMA: &str = "clawdstrike.marketplace.revocation.v1";

/// Curator attestation fact for a policy bundle in the marketplace.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyAttestation {
    pub schema: String,
    pub fact_id: String,
    /// Policy bundle ID (UUID from SignedPolicyBundle).
    pub bundle_id: String,
    /// SHA-256 hash of the canonical JSON bundle content.
    pub bundle_hash: String,
    /// Feed identifier (e.g., "clawdstrike-official").
    pub feed_id: String,
    /// Feed sequence number at time of attestation.
    pub feed_seq: u64,
    /// Entry identifier within the feed.
    pub entry_id: String,
    /// SHA-256 hash of the canonical policy JSON.
    pub policy_hash: String,
    /// Curator public key (hex).
    pub curator_public_key: String,
    /// Type of attestation (e.g., "curator_approval").
    pub attestation_type: String,
    /// Optional validity window start (ISO-8601).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub valid_from: Option<String>,
    /// Optional validity window end (ISO-8601).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub valid_until: Option<String>,
    /// Optional metadata (review notes, etc.).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub metadata: Option<Value>,
}

/// Community review attestation for a policy bundle.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReviewAttestation {
    pub schema: String,
    pub fact_id: String,
    /// SHA-256 hash of the reviewed bundle.
    pub bundle_hash: String,
    /// Reviewer identity: `"aegis:ed25519:<hex>"`
    pub reviewer: String,
    /// Review verdict: `"approve"`, `"reject"`, `"needs-changes"`.
    pub verdict: String,
    /// Optional review notes.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub review_notes: Option<String>,
    /// Optional conditions for approval.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub conditions: Vec<String>,
}

/// Revocation fact for a marketplace policy bundle.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyRevocation {
    pub schema: String,
    pub fact_id: String,
    /// SHA-256 hash of the revoked bundle.
    pub bundle_hash: String,
    /// Reason for revocation.
    pub reason: String,
    /// ISO-8601 timestamp of revocation.
    pub revoked_at: String,
    /// Optional bundle hash of the replacement.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub superseded_by: Option<String>,
}

impl PolicyAttestation {
    /// Convert to a `serde_json::Value` for embedding in a Spine envelope fact.
    pub fn to_fact_value(&self) -> Result<Value, serde_json::Error> {
        serde_json::to_value(self)
    }
}

impl ReviewAttestation {
    /// Convert to a `serde_json::Value` for embedding in a Spine envelope fact.
    pub fn to_fact_value(&self) -> Result<Value, serde_json::Error> {
        serde_json::to_value(self)
    }
}

impl PolicyRevocation {
    /// Convert to a `serde_json::Value` for embedding in a Spine envelope fact.
    pub fn to_fact_value(&self) -> Result<Value, serde_json::Error> {
        serde_json::to_value(self)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_policy_attestation() -> PolicyAttestation {
        PolicyAttestation {
            schema: POLICY_ATTESTATION_SCHEMA.to_string(),
            fact_id: "pa_test_001".to_string(),
            bundle_id: "550e8400-e29b-41d4-a716-446655440000".to_string(),
            bundle_hash: "0xaabbccdd00112233aabbccdd00112233aabbccdd00112233aabbccdd00112233"
                .to_string(),
            feed_id: "clawdstrike-official".to_string(),
            feed_seq: 42,
            entry_id: "strict-security-v2".to_string(),
            policy_hash: "0x1122334455667788112233445566778811223344556677881122334455667788"
                .to_string(),
            curator_public_key: "aabbccdd00112233aabbccdd00112233aabbccdd00112233aabbccdd00112233"
                .to_string(),
            attestation_type: "curator_approval".to_string(),
            valid_from: Some("2026-02-07T00:00:00Z".to_string()),
            valid_until: None,
            metadata: None,
        }
    }

    fn sample_review_attestation() -> ReviewAttestation {
        ReviewAttestation {
            schema: REVIEW_ATTESTATION_SCHEMA.to_string(),
            fact_id: "ra_test_001".to_string(),
            bundle_hash: "0xaabbccdd00112233aabbccdd00112233aabbccdd00112233aabbccdd00112233"
                .to_string(),
            reviewer:
                "aegis:ed25519:aabbccdd00112233aabbccdd00112233aabbccdd00112233aabbccdd00112233"
                    .to_string(),
            verdict: "approve".to_string(),
            review_notes: Some("Reviewed and approved".to_string()),
            conditions: vec!["no-network-egress".to_string()],
        }
    }

    fn sample_policy_revocation() -> PolicyRevocation {
        PolicyRevocation {
            schema: REVOCATION_SCHEMA.to_string(),
            fact_id: "pr_test_001".to_string(),
            bundle_hash: "0xaabbccdd00112233aabbccdd00112233aabbccdd00112233aabbccdd00112233"
                .to_string(),
            reason: "Security vulnerability discovered".to_string(),
            revoked_at: "2026-02-07T12:00:00Z".to_string(),
            superseded_by: Some(
                "0x1122334455667788112233445566778811223344556677881122334455667788".to_string(),
            ),
        }
    }

    #[test]
    fn policy_attestation_serde_roundtrip() {
        let pa = sample_policy_attestation();
        let json = serde_json::to_string(&pa).unwrap();
        let restored: PolicyAttestation = serde_json::from_str(&json).unwrap();
        assert_eq!(restored.schema, POLICY_ATTESTATION_SCHEMA);
        assert_eq!(restored.bundle_id, pa.bundle_id);
        assert_eq!(restored.feed_seq, 42);
        assert_eq!(restored.attestation_type, "curator_approval");
    }

    #[test]
    fn review_attestation_serde_roundtrip() {
        let ra = sample_review_attestation();
        let json = serde_json::to_string(&ra).unwrap();
        let restored: ReviewAttestation = serde_json::from_str(&json).unwrap();
        assert_eq!(restored.schema, REVIEW_ATTESTATION_SCHEMA);
        assert_eq!(restored.verdict, "approve");
        assert_eq!(restored.conditions.len(), 1);
    }

    #[test]
    fn policy_revocation_serde_roundtrip() {
        let pr = sample_policy_revocation();
        let json = serde_json::to_string(&pr).unwrap();
        let restored: PolicyRevocation = serde_json::from_str(&json).unwrap();
        assert_eq!(restored.schema, REVOCATION_SCHEMA);
        assert_eq!(restored.reason, "Security vulnerability discovered");
        assert!(restored.superseded_by.is_some());
    }

    #[test]
    fn policy_attestation_rejects_unknown_fields() {
        let pa = sample_policy_attestation();
        let mut value = serde_json::to_value(&pa).unwrap();
        value["rogue_field"] = serde_json::json!("bad");
        let result = serde_json::from_value::<PolicyAttestation>(value);
        assert!(result.is_err(), "should reject unknown fields");
    }

    #[test]
    fn review_attestation_rejects_unknown_fields() {
        let ra = sample_review_attestation();
        let mut value = serde_json::to_value(&ra).unwrap();
        value["rogue_field"] = serde_json::json!("bad");
        let result = serde_json::from_value::<ReviewAttestation>(value);
        assert!(result.is_err(), "should reject unknown fields");
    }

    #[test]
    fn policy_revocation_rejects_unknown_fields() {
        let pr = sample_policy_revocation();
        let mut value = serde_json::to_value(&pr).unwrap();
        value["rogue_field"] = serde_json::json!("bad");
        let result = serde_json::from_value::<PolicyRevocation>(value);
        assert!(result.is_err(), "should reject unknown fields");
    }

    #[test]
    fn policy_attestation_optional_fields_omitted() {
        let pa = PolicyAttestation {
            valid_from: None,
            valid_until: None,
            metadata: None,
            ..sample_policy_attestation()
        };
        let json = serde_json::to_string(&pa).unwrap();
        assert!(!json.contains("valid_from"));
        assert!(!json.contains("valid_until"));
        assert!(!json.contains("metadata"));
    }

    #[test]
    fn policy_attestation_to_fact_value() {
        let pa = sample_policy_attestation();
        let val = pa.to_fact_value().unwrap();
        assert_eq!(
            val.get("schema").and_then(|v| v.as_str()).unwrap(),
            POLICY_ATTESTATION_SCHEMA
        );
    }

    #[test]
    fn review_attestation_to_fact_value() {
        let ra = sample_review_attestation();
        let val = ra.to_fact_value().unwrap();
        assert_eq!(
            val.get("schema").and_then(|v| v.as_str()).unwrap(),
            REVIEW_ATTESTATION_SCHEMA
        );
    }

    #[test]
    fn policy_revocation_to_fact_value() {
        let pr = sample_policy_revocation();
        let val = pr.to_fact_value().unwrap();
        assert_eq!(
            val.get("schema").and_then(|v| v.as_str()).unwrap(),
            REVOCATION_SCHEMA
        );
    }
}
