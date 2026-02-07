//! Integration tests for marketplace fact schemas.
//!
//! Tests the full lifecycle: build typed fact -> wrap in SignedEnvelope ->
//! verify envelope -> extract fact -> deserialize back to typed struct.

#![allow(clippy::expect_used, clippy::unwrap_used)]

use hush_core::Keypair;
use serde_json::json;
use spine::{
    build_signed_envelope, now_rfc3339, verify_envelope, PolicyAttestation, PolicyRevocation,
    ReviewAttestation, POLICY_ATTESTATION_SCHEMA, REVIEW_ATTESTATION_SCHEMA, REVOCATION_SCHEMA,
};

fn sample_policy_attestation() -> PolicyAttestation {
    PolicyAttestation {
        schema: POLICY_ATTESTATION_SCHEMA.to_string(),
        fact_id: "pa_integration_001".to_string(),
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
        fact_id: "ra_integration_001".to_string(),
        bundle_hash: "0xaabbccdd00112233aabbccdd00112233aabbccdd00112233aabbccdd00112233"
            .to_string(),
        reviewer: "aegis:ed25519:aabbccdd00112233aabbccdd00112233aabbccdd00112233aabbccdd00112233"
            .to_string(),
        verdict: "approve".to_string(),
        review_notes: Some("LGTM".to_string()),
        conditions: vec![],
    }
}

fn sample_policy_revocation() -> PolicyRevocation {
    PolicyRevocation {
        schema: REVOCATION_SCHEMA.to_string(),
        fact_id: "pr_integration_001".to_string(),
        bundle_hash: "0xaabbccdd00112233aabbccdd00112233aabbccdd00112233aabbccdd00112233"
            .to_string(),
        reason: "CVE-2026-0001".to_string(),
        revoked_at: "2026-02-07T12:00:00Z".to_string(),
        superseded_by: None,
    }
}

#[tokio::test]
async fn test_policy_attestation_envelope_roundtrip() {
    let kp = Keypair::generate();
    let pa = sample_policy_attestation();

    let fact_value = pa.to_fact_value().unwrap();
    let envelope = build_signed_envelope(&kp, 1, None, fact_value, now_rfc3339()).unwrap();

    assert!(verify_envelope(&envelope).unwrap());

    let fact = envelope.get("fact").unwrap();
    let restored: PolicyAttestation = serde_json::from_value(fact.clone()).unwrap();

    assert_eq!(restored.schema, POLICY_ATTESTATION_SCHEMA);
    assert_eq!(restored.bundle_id, pa.bundle_id);
    assert_eq!(restored.feed_id, "clawdstrike-official");
    assert_eq!(restored.feed_seq, 42);
}

#[tokio::test]
async fn test_review_attestation_envelope_roundtrip() {
    let kp = Keypair::generate();
    let ra = sample_review_attestation();

    let fact_value = ra.to_fact_value().unwrap();
    let envelope = build_signed_envelope(&kp, 1, None, fact_value, now_rfc3339()).unwrap();

    assert!(verify_envelope(&envelope).unwrap());

    let fact = envelope.get("fact").unwrap();
    let restored: ReviewAttestation = serde_json::from_value(fact.clone()).unwrap();

    assert_eq!(restored.schema, REVIEW_ATTESTATION_SCHEMA);
    assert_eq!(restored.verdict, "approve");
}

#[tokio::test]
async fn test_policy_revocation_envelope_roundtrip() {
    let kp = Keypair::generate();
    let pr = sample_policy_revocation();

    let fact_value = pr.to_fact_value().unwrap();
    let envelope = build_signed_envelope(&kp, 1, None, fact_value, now_rfc3339()).unwrap();

    assert!(verify_envelope(&envelope).unwrap());

    let fact = envelope.get("fact").unwrap();
    let restored: PolicyRevocation = serde_json::from_value(fact.clone()).unwrap();

    assert_eq!(restored.schema, REVOCATION_SCHEMA);
    assert_eq!(restored.reason, "CVE-2026-0001");
}

#[tokio::test]
async fn test_policy_attestation_rejects_unknown_fields() {
    let pa = sample_policy_attestation();
    let mut value = pa.to_fact_value().unwrap();
    value["unknown_field"] = json!("bad");
    let result = serde_json::from_value::<PolicyAttestation>(value);
    assert!(result.is_err());
}

#[tokio::test]
async fn test_review_attestation_rejects_unknown_fields() {
    let ra = sample_review_attestation();
    let mut value = ra.to_fact_value().unwrap();
    value["unknown_field"] = json!("bad");
    let result = serde_json::from_value::<ReviewAttestation>(value);
    assert!(result.is_err());
}

#[tokio::test]
async fn test_policy_revocation_rejects_unknown_fields() {
    let pr = sample_policy_revocation();
    let mut value = pr.to_fact_value().unwrap();
    value["unknown_field"] = json!("bad");
    let result = serde_json::from_value::<PolicyRevocation>(value);
    assert!(result.is_err());
}

#[tokio::test]
async fn test_attestation_and_revocation_chain() {
    let kp = Keypair::generate();

    // First: curator attestation
    let pa = sample_policy_attestation();
    let e1 = build_signed_envelope(&kp, 1, None, pa.to_fact_value().unwrap(), now_rfc3339()).unwrap();
    assert!(verify_envelope(&e1).unwrap());
    let h1 = e1.get("envelope_hash").and_then(|v| v.as_str()).unwrap().to_string();

    // Second: community review, chained
    let ra = sample_review_attestation();
    let e2 = build_signed_envelope(&kp, 2, Some(h1.clone()), ra.to_fact_value().unwrap(), now_rfc3339()).unwrap();
    assert!(verify_envelope(&e2).unwrap());
    let h2 = e2.get("envelope_hash").and_then(|v| v.as_str()).unwrap().to_string();

    // Third: revocation, chained
    let pr = sample_policy_revocation();
    let e3 = build_signed_envelope(&kp, 3, Some(h2.clone()), pr.to_fact_value().unwrap(), now_rfc3339()).unwrap();
    assert!(verify_envelope(&e3).unwrap());

    // Verify chain links
    assert_eq!(e2.get("prev_envelope_hash").and_then(|v| v.as_str()).unwrap(), h1);
    assert_eq!(e3.get("prev_envelope_hash").and_then(|v| v.as_str()).unwrap(), h2);
}
