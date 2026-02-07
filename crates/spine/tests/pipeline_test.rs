//! Full pipeline integration tests:
//! create envelope -> build checkpoint -> generate inclusion proof -> verify

#![allow(clippy::expect_used, clippy::unwrap_used)]

use hush_core::{Keypair, MerkleTree};
use serde_json::json;
use spine::{
    build_signed_envelope, checkpoint_hash, checkpoint_statement, issuer_from_keypair, now_rfc3339,
    sign_checkpoint_statement, verify_envelope, verify_witness_signature, TrustBundle,
};

/// Create keypair, sign a fact, verify signature roundtrips.
#[tokio::test]
async fn test_envelope_sign_and_verify() {
    let kp = Keypair::generate();
    let fact = json!({
        "schema": "clawdstrike.sdr.fact.tetragon_event.v1",
        "event_type": "process_exec",
        "severity": "medium",
        "node_name": "worker-1",
        "process": { "binary": "/usr/bin/curl", "pid": 1234 },
    });

    let envelope = build_signed_envelope(&kp, 1, None, fact.clone(), now_rfc3339()).unwrap();

    // Verify the envelope signature is valid
    assert!(verify_envelope(&envelope).unwrap());

    // Verify all expected fields are present
    assert_eq!(
        envelope.get("schema").and_then(|v| v.as_str()).unwrap(),
        "aegis.spine.envelope.v1"
    );
    assert!(envelope.get("envelope_hash").is_some());
    assert!(envelope.get("signature").is_some());
    assert_eq!(
        envelope.get("issuer").and_then(|v| v.as_str()).unwrap(),
        issuer_from_keypair(&kp)
    );
    assert_eq!(envelope.get("seq").and_then(|v| v.as_u64()).unwrap(), 1);
    assert!(envelope.get("prev_envelope_hash").unwrap().is_null());
    assert_eq!(envelope.get("fact").unwrap(), &fact);

    // Verify tampered envelope fails
    let mut tampered = envelope.clone();
    tampered["fact"]["severity"] = json!("critical");
    assert!(!verify_envelope(&tampered).unwrap());
}

/// Create N envelopes, build Merkle tree checkpoint, verify root.
#[tokio::test]
async fn test_checkpoint_merkle_construction() {
    let kp = Keypair::generate();
    let n = 10;

    // Build a chain of signed envelopes
    let mut envelopes = Vec::new();
    let mut prev_hash: Option<String> = None;

    for seq in 1..=n {
        let fact = json!({
            "type": "test_event",
            "seq": seq,
        });
        let envelope =
            build_signed_envelope(&kp, seq, prev_hash.clone(), fact, now_rfc3339()).unwrap();
        prev_hash = envelope
            .get("envelope_hash")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string());
        envelopes.push(envelope);
    }

    assert_eq!(envelopes.len(), n as usize);

    // Serialize each envelope to bytes for the Merkle tree leaves
    let leaves: Vec<Vec<u8>> = envelopes
        .iter()
        .map(|e| serde_json::to_vec(e).unwrap())
        .collect();

    let tree = MerkleTree::from_leaves(&leaves).unwrap();

    // Build a checkpoint statement using the Merkle root
    let merkle_root = tree.root().to_hex_prefixed();
    let stmt = checkpoint_statement("test-log", 1, None, merkle_root.clone(), n, now_rfc3339());

    assert_eq!(stmt["log_id"], "test-log");
    assert_eq!(stmt["checkpoint_seq"], 1);
    assert_eq!(stmt["merkle_root"], merkle_root);
    assert_eq!(stmt["tree_size"], n);

    // Checkpoint hash should be deterministic
    let h1 = checkpoint_hash(&stmt).unwrap();
    let h2 = checkpoint_hash(&stmt).unwrap();
    assert_eq!(h1, h2);
}

/// Build checkpoint from envelopes, generate proof for one envelope, verify proof against root.
#[tokio::test]
async fn test_inclusion_proof_roundtrip() {
    let kp = Keypair::generate();
    let n = 8;

    // Build envelopes
    let mut envelopes = Vec::new();
    let mut prev_hash: Option<String> = None;
    for seq in 1..=n {
        let fact = json!({"event": seq});
        let envelope =
            build_signed_envelope(&kp, seq, prev_hash.clone(), fact, now_rfc3339()).unwrap();
        prev_hash = envelope
            .get("envelope_hash")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string());
        envelopes.push(envelope);
    }

    // Build Merkle tree from envelope bytes
    let leaves: Vec<Vec<u8>> = envelopes
        .iter()
        .map(|e| serde_json::to_vec(e).unwrap())
        .collect();
    let tree = MerkleTree::from_leaves(&leaves).unwrap();
    let root = tree.root();

    // Generate inclusion proof for each envelope and verify
    for (idx, leaf) in leaves.iter().enumerate() {
        let proof = tree.inclusion_proof(idx).unwrap();
        assert!(
            proof.verify(leaf, &root),
            "inclusion proof failed for envelope at index {idx}"
        );
    }

    // Verify proof fails for wrong data
    let proof = tree.inclusion_proof(3).unwrap();
    assert!(!proof.verify(b"not-an-envelope", &root));

    // Build checkpoint statement from root
    let stmt = checkpoint_statement(
        "test-log",
        1,
        None,
        root.to_hex_prefixed(),
        n,
        now_rfc3339(),
    );

    // Sign the checkpoint and verify
    let witness = sign_checkpoint_statement(&kp, &stmt).unwrap();
    let witness_id = witness
        .get("witness_node_id")
        .and_then(|v| v.as_str())
        .unwrap();
    let sig = witness.get("signature").and_then(|v| v.as_str()).unwrap();
    assert!(verify_witness_signature(&stmt, witness_id, sig).unwrap());
}

/// Create checkpoint, have 2 witnesses co-sign, verify both signatures.
#[tokio::test]
async fn test_multi_witness_checkpoint() {
    let curator_kp = Keypair::generate();
    let witness_kp_1 = Keypair::generate();
    let witness_kp_2 = Keypair::generate();

    // Build a simple envelope for the tree
    let fact = json!({"type": "multi_witness_test"});
    let envelope = build_signed_envelope(&curator_kp, 1, None, fact, now_rfc3339()).unwrap();
    let leaf = serde_json::to_vec(&envelope).unwrap();
    let tree = MerkleTree::from_leaves(&[leaf]).unwrap();

    // Build checkpoint statement
    let stmt = checkpoint_statement(
        "multi-witness-log",
        1,
        None,
        tree.root().to_hex_prefixed(),
        1,
        now_rfc3339(),
    );

    // Both witnesses sign the same checkpoint
    let w1_sig = sign_checkpoint_statement(&witness_kp_1, &stmt).unwrap();
    let w2_sig = sign_checkpoint_statement(&witness_kp_2, &stmt).unwrap();

    // Verify witness 1
    let w1_id = w1_sig
        .get("witness_node_id")
        .and_then(|v| v.as_str())
        .unwrap();
    let w1_sig_hex = w1_sig.get("signature").and_then(|v| v.as_str()).unwrap();
    assert!(verify_witness_signature(&stmt, w1_id, w1_sig_hex).unwrap());

    // Verify witness 2
    let w2_id = w2_sig
        .get("witness_node_id")
        .and_then(|v| v.as_str())
        .unwrap();
    let w2_sig_hex = w2_sig.get("signature").and_then(|v| v.as_str()).unwrap();
    assert!(verify_witness_signature(&stmt, w2_id, w2_sig_hex).unwrap());

    // Cross-verify: witness 1's signature should fail with witness 2's ID
    assert!(!verify_witness_signature(&stmt, w2_id, w1_sig_hex).unwrap());
    assert!(!verify_witness_signature(&stmt, w1_id, w2_sig_hex).unwrap());

    // Both witnesses signed the same checkpoint hash
    assert_eq!(w1_sig.get("checkpoint_hash"), w2_sig.get("checkpoint_hash"));
}

/// Create trust bundle with 2 curators, verify envelope from trusted curator passes, untrusted fails.
#[tokio::test]
async fn test_trust_bundle_verification() {
    let trusted_kp_1 = Keypair::generate();
    let trusted_kp_2 = Keypair::generate();
    let untrusted_kp = Keypair::generate();

    let trusted_issuer_1 = issuer_from_keypair(&trusted_kp_1);
    let trusted_issuer_2 = issuer_from_keypair(&trusted_kp_2);
    let untrusted_issuer = issuer_from_keypair(&untrusted_kp);

    // Build a trust bundle with two trusted receipt signers
    let bundle = TrustBundle {
        schema: Some("spine.trust.v1".into()),
        allowed_log_ids: vec![],
        allowed_witness_node_ids: vec![trusted_issuer_1.clone(), trusted_issuer_2.clone()],
        allowed_receipt_signer_node_ids: vec![trusted_issuer_1.clone(), trusted_issuer_2.clone()],
        allowed_kernel_loader_signer_node_ids: vec![],
        required_receipt_enforcement_tiers: vec![],
        require_kernel_loader_signatures: false,
        witness_quorum: 2,
    };

    bundle.validate().unwrap();

    // Trusted issuers pass the check
    assert!(bundle.receipt_signer_allowed(&trusted_issuer_1));
    assert!(bundle.receipt_signer_allowed(&trusted_issuer_2));
    assert!(bundle.witness_allowed(&trusted_issuer_1));
    assert!(bundle.witness_allowed(&trusted_issuer_2));

    // Untrusted issuer fails the check
    assert!(!bundle.receipt_signer_allowed(&untrusted_issuer));
    assert!(!bundle.witness_allowed(&untrusted_issuer));

    // Build envelopes from trusted and untrusted keys — both are cryptographically valid
    let trusted_envelope = build_signed_envelope(
        &trusted_kp_1,
        1,
        None,
        json!({"type": "trusted_event"}),
        now_rfc3339(),
    )
    .unwrap();
    let untrusted_envelope = build_signed_envelope(
        &untrusted_kp,
        1,
        None,
        json!({"type": "untrusted_event"}),
        now_rfc3339(),
    )
    .unwrap();

    // Both envelopes are cryptographically valid
    assert!(verify_envelope(&trusted_envelope).unwrap());
    assert!(verify_envelope(&untrusted_envelope).unwrap());

    // But only the trusted envelope's issuer passes the trust bundle
    let trusted_env_issuer = trusted_envelope
        .get("issuer")
        .and_then(|v| v.as_str())
        .unwrap();
    let untrusted_env_issuer = untrusted_envelope
        .get("issuer")
        .and_then(|v| v.as_str())
        .unwrap();
    assert!(bundle.receipt_signer_allowed(trusted_env_issuer));
    assert!(!bundle.receipt_signer_allowed(untrusted_env_issuer));

    // Witness co-signing: trusted witness passes, untrusted does not
    let tree = MerkleTree::from_leaves(&[serde_json::to_vec(&trusted_envelope).unwrap()]).unwrap();
    let stmt = checkpoint_statement(
        "trust-test-log",
        1,
        None,
        tree.root().to_hex_prefixed(),
        1,
        now_rfc3339(),
    );

    let trusted_witness = sign_checkpoint_statement(&trusted_kp_1, &stmt).unwrap();
    let tw_id = trusted_witness
        .get("witness_node_id")
        .and_then(|v| v.as_str())
        .unwrap();
    assert!(bundle.witness_allowed(tw_id));

    let untrusted_witness = sign_checkpoint_statement(&untrusted_kp, &stmt).unwrap();
    let uw_id = untrusted_witness
        .get("witness_node_id")
        .and_then(|v| v.as_str())
        .unwrap();
    assert!(!bundle.witness_allowed(uw_id));
}
