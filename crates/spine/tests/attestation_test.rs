//! Integration tests for node attestation and runtime proof fact schemas.
//!
//! Tests the full lifecycle: build typed fact -> wrap in SignedEnvelope ->
//! verify envelope -> extract fact -> deserialize back to typed struct.

#![allow(clippy::expect_used, clippy::unwrap_used)]

use hush_core::Keypair;
use serde_json::json;
use spine::{
    build_signed_envelope, now_rfc3339, verify_envelope, AttestationChain, ExecutionEvidence,
    KubernetesMetadata, NodeAttestation, RuntimeProof, SystemAttestation, TrustBundle,
    WorkloadIdentity, ENFORCEMENT_TIERS, NODE_ATTESTATION_SCHEMA, RUNTIME_PROOF_SCHEMA,
};

fn sample_node_attestation(node_id: &str) -> NodeAttestation {
    NodeAttestation {
        schema: NODE_ATTESTATION_SCHEMA.to_string(),
        fact_id: "na_integration_001".to_string(),
        node_id: node_id.to_string(),
        system_attestation: SystemAttestation {
            spiffe_id: Some(
                "spiffe://aegis.local/ns/clawdstrike/sa/checkpointer".to_string(),
            ),
            svid_cert_hash: Some(
                "0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef".to_string(),
            ),
            trust_domain: Some("aegis.local".to_string()),
            kubernetes: Some(KubernetesMetadata {
                namespace: "clawdstrike".to_string(),
                pod: Some("checkpointer-0".to_string()),
                node: Some("ip-10-0-1-42.ec2.internal".to_string()),
                service_account: Some("checkpointer".to_string()),
                container_image: Some(
                    "ghcr.io/backbay-labs/spine-checkpointer:v0.1.0".to_string(),
                ),
                container_image_digest: Some("sha256:abcdef1234567890".to_string()),
            }),
            binary: Some("/usr/local/bin/spine-checkpointer".to_string()),
            binary_hash_ima: Some("sha256:1234567890abcdef".to_string()),
        },
        transports: None,
        issued_at: "2026-02-07T00:00:00Z".to_string(),
    }
}

fn sample_runtime_proof() -> RuntimeProof {
    RuntimeProof {
        schema: RUNTIME_PROOF_SCHEMA.to_string(),
        fact_id: "rp_integration_001".to_string(),
        proof_type: "execution".to_string(),
        timestamp: "2026-02-07T00:00:01Z".to_string(),
        execution: ExecutionEvidence {
            binary: "/usr/bin/curl".to_string(),
            binary_hash_ima: Some("sha256:fedcba0987654321".to_string()),
            arguments: Some("https://example.com".to_string()),
            pid: 12345,
            uid: Some(1000),
            exec_id: "abc123def456".to_string(),
            parent_exec_id: Some("parent789".to_string()),
            capabilities: Some("NET_RAW".to_string()),
            namespaces: None,
        },
        identity: WorkloadIdentity {
            spiffe_id: "spiffe://aegis.local/ns/default/sa/agent".to_string(),
            svid_serial: Some("123456".to_string()),
            trust_domain: "aegis.local".to_string(),
        },
        kubernetes: KubernetesMetadata {
            namespace: "default".to_string(),
            pod: Some("agent-pod-0".to_string()),
            node: Some("worker-1".to_string()),
            service_account: Some("agent".to_string()),
            container_image: None,
            container_image_digest: None,
        },
        network_enforcement: None,
        attestation_chain: AttestationChain {
            tetragon_exec_id: "abc123def456".to_string(),
            spire_svid_hash: Some("0xdeadbeef".to_string()),
            clawdstrike_receipt_hash: None,
            aegisnet_envelope_hash: None,
        },
    }
}

#[tokio::test]
async fn test_node_attestation_roundtrip() {
    let kp = Keypair::generate();
    let issuer = spine::issuer_from_keypair(&kp);
    let na = sample_node_attestation(&issuer);

    // Convert to fact value and wrap in signed envelope
    let fact_value = na.to_fact_value().unwrap();
    let envelope = build_signed_envelope(&kp, 1, None, fact_value, now_rfc3339()).unwrap();

    // Verify the envelope signature
    assert!(verify_envelope(&envelope).unwrap());

    // Extract the fact and deserialize back
    let fact = envelope.get("fact").unwrap();
    let restored: NodeAttestation = serde_json::from_value(fact.clone()).unwrap();

    assert_eq!(restored.schema, NODE_ATTESTATION_SCHEMA);
    assert_eq!(restored.node_id, issuer);
    assert_eq!(
        restored.system_attestation.spiffe_id,
        na.system_attestation.spiffe_id
    );
    assert_eq!(
        restored
            .system_attestation
            .kubernetes
            .as_ref()
            .unwrap()
            .namespace,
        "clawdstrike"
    );
}

#[tokio::test]
async fn test_runtime_proof_roundtrip() {
    let kp = Keypair::generate();
    let rp = sample_runtime_proof();

    // Convert to fact value and wrap in signed envelope
    let fact_value = rp.to_fact_value().unwrap();
    let envelope = build_signed_envelope(&kp, 1, None, fact_value, now_rfc3339()).unwrap();

    // Verify the envelope signature
    assert!(verify_envelope(&envelope).unwrap());

    // Extract the fact and deserialize back
    let fact = envelope.get("fact").unwrap();
    let restored: RuntimeProof = serde_json::from_value(fact.clone()).unwrap();

    assert_eq!(restored.schema, RUNTIME_PROOF_SCHEMA);
    assert_eq!(restored.execution.binary, "/usr/bin/curl");
    assert_eq!(restored.execution.pid, 12345);
    assert_eq!(restored.identity.spiffe_id, rp.identity.spiffe_id);
    assert_eq!(
        restored.attestation_chain.tetragon_exec_id,
        "abc123def456"
    );
}

#[tokio::test]
async fn test_node_attestation_rejects_unknown_fields() {
    let kp = Keypair::generate();
    let issuer = spine::issuer_from_keypair(&kp);
    let na = sample_node_attestation(&issuer);

    let mut value = na.to_fact_value().unwrap();
    value["rogue_field"] = json!("should_be_rejected");

    let result = serde_json::from_value::<NodeAttestation>(value);
    assert!(
        result.is_err(),
        "NodeAttestation should reject unknown fields (deny_unknown_fields)"
    );
}

#[tokio::test]
async fn test_runtime_proof_rejects_unknown_fields() {
    let rp = sample_runtime_proof();

    let mut value = rp.to_fact_value().unwrap();
    value["rogue_field"] = json!("should_be_rejected");

    let result = serde_json::from_value::<RuntimeProof>(value);
    assert!(
        result.is_err(),
        "RuntimeProof should reject unknown fields (deny_unknown_fields)"
    );
}

#[tokio::test]
async fn test_trust_bundle_require_attested_issuers() {
    // require_attested_issuers: true without receipt signers should fail
    let bundle_bad = TrustBundle {
        schema: None,
        allowed_log_ids: vec![],
        allowed_witness_node_ids: vec![],
        allowed_receipt_signer_node_ids: vec![],
        allowed_kernel_loader_signer_node_ids: vec![],
        required_receipt_enforcement_tiers: vec![],
        require_kernel_loader_signatures: false,
        witness_quorum: 1,
        require_attested_issuers: true,
    };
    assert!(
        bundle_bad.validate().is_err(),
        "require_attested_issuers without receipt signers should fail validation"
    );

    // require_attested_issuers: true with receipt signers should succeed
    let bundle_ok = TrustBundle {
        schema: None,
        allowed_log_ids: vec![],
        allowed_witness_node_ids: vec![],
        allowed_receipt_signer_node_ids: vec!["signer-a".into()],
        allowed_kernel_loader_signer_node_ids: vec![],
        required_receipt_enforcement_tiers: vec![],
        require_kernel_loader_signatures: false,
        witness_quorum: 1,
        require_attested_issuers: true,
    };
    assert!(
        bundle_ok.validate().is_ok(),
        "require_attested_issuers with receipt signers should pass"
    );

    // require_attested_issuers: false (default) should work with empty everything
    let bundle_default = TrustBundle {
        schema: None,
        allowed_log_ids: vec![],
        allowed_witness_node_ids: vec![],
        allowed_receipt_signer_node_ids: vec![],
        allowed_kernel_loader_signer_node_ids: vec![],
        required_receipt_enforcement_tiers: vec![],
        require_kernel_loader_signatures: false,
        witness_quorum: 1,
        require_attested_issuers: false,
    };
    assert!(
        bundle_default.validate().is_ok(),
        "default (false) require_attested_issuers should be backward-compatible"
    );
}

#[tokio::test]
async fn test_enforcement_tier_ordering() {
    assert_eq!(ENFORCEMENT_TIERS.len(), 4);
    assert_eq!(ENFORCEMENT_TIERS[0], "best_effort");
    assert_eq!(ENFORCEMENT_TIERS[1], "daemon_enforced");
    assert_eq!(ENFORCEMENT_TIERS[2], "linux_kernel_enforced");
    assert_eq!(ENFORCEMENT_TIERS[3], "linux_kernel_attested");

    // Verify tier allowlist filtering works
    let bundle = TrustBundle {
        schema: None,
        allowed_log_ids: vec![],
        allowed_witness_node_ids: vec![],
        allowed_receipt_signer_node_ids: vec![],
        allowed_kernel_loader_signer_node_ids: vec![],
        required_receipt_enforcement_tiers: vec![
            "daemon_enforced".into(),
            "linux_kernel_enforced".into(),
            "linux_kernel_attested".into(),
        ],
        require_kernel_loader_signatures: false,
        witness_quorum: 1,
        require_attested_issuers: false,
    };
    bundle.validate().unwrap();

    // best_effort should be rejected
    assert!(!bundle.receipt_enforcement_tier_allowed("best_effort"));
    // The three configured tiers should be accepted
    assert!(bundle.receipt_enforcement_tier_allowed("daemon_enforced"));
    assert!(bundle.receipt_enforcement_tier_allowed("linux_kernel_enforced"));
    assert!(bundle.receipt_enforcement_tier_allowed("linux_kernel_attested"));
}

#[tokio::test]
async fn test_node_attestation_envelope_chain() {
    let kp = Keypair::generate();
    let issuer = spine::issuer_from_keypair(&kp);

    // First envelope: node attestation
    let na = sample_node_attestation(&issuer);
    let fact1 = na.to_fact_value().unwrap();
    let e1 = build_signed_envelope(&kp, 1, None, fact1, now_rfc3339()).unwrap();
    assert!(verify_envelope(&e1).unwrap());
    let h1 = e1
        .get("envelope_hash")
        .and_then(|v| v.as_str())
        .unwrap()
        .to_string();

    // Second envelope: runtime proof, chained after node attestation
    let rp = sample_runtime_proof();
    let fact2 = rp.to_fact_value().unwrap();
    let e2 = build_signed_envelope(&kp, 2, Some(h1.clone()), fact2, now_rfc3339()).unwrap();
    assert!(verify_envelope(&e2).unwrap());

    // Verify chain link
    assert_eq!(
        e2.get("prev_envelope_hash")
            .and_then(|v| v.as_str())
            .unwrap(),
        h1
    );
}

#[tokio::test]
async fn test_trust_bundle_backward_compatible_json() {
    // JSON without require_attested_issuers field should still deserialize
    let json = r#"{
        "allowed_log_ids": ["log-1"],
        "allowed_witness_node_ids": ["w-1"],
        "witness_quorum": 1
    }"#;
    let bundle: TrustBundle = serde_json::from_str(json).unwrap();
    assert!(!bundle.require_attested_issuers);
    bundle.validate().unwrap();
}
