#![cfg(target_arch = "wasm32")]

use wasm_bindgen_test::*;
use hush_wasm::*;

// Tests can run in both browser and Node.js
// Use `wasm-pack test --node` for Node.js or `wasm-pack test --headless --chrome` for browser

#[wasm_bindgen_test]
fn test_hash_sha256() {
    let hash = hash_sha256(b"hello");
    assert_eq!(
        hash,
        "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"
    );
}

#[wasm_bindgen_test]
fn test_hash_sha256_empty() {
    let hash = hash_sha256(b"");
    assert_eq!(hash.len(), 64); // 32 bytes = 64 hex chars
}

#[wasm_bindgen_test]
fn test_hash_keccak256() {
    let hash = hash_keccak256(b"hello");
    // Keccak-256 of "hello" - returns with 0x prefix
    assert!(hash.starts_with("0x"));
    assert_eq!(hash.len(), 66); // 0x + 64 hex chars
}

// ============================================================================
// Ed25519 Signature Verification Tests
// ============================================================================

#[wasm_bindgen_test]
fn test_verify_ed25519_valid() {
    // Test with known good signature (RFC 8032 test vector 1)
    let pubkey_hex = "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a";
    let message = b"";
    let sig_hex = "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b";

    let result = verify_ed25519(pubkey_hex, message, sig_hex);
    assert!(result.is_ok());
    assert!(result.unwrap());
}

#[wasm_bindgen_test]
fn test_verify_ed25519_invalid_signature() {
    let pubkey_hex = "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a";
    let message = b"wrong message";
    let sig_hex = "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b";

    let result = verify_ed25519(pubkey_hex, message, sig_hex);
    assert!(result.is_ok());
    assert!(!result.unwrap()); // Should be false for wrong message
}

#[wasm_bindgen_test]
fn test_verify_ed25519_invalid_pubkey() {
    let result = verify_ed25519("invalid", b"test", &"0".repeat(128));
    assert!(result.is_err());
}

// ============================================================================
// Receipt Verification Tests
// ============================================================================

#[wasm_bindgen_test]
fn test_verify_receipt_parses() {
    // Create a valid signed receipt JSON structure
    // Note: signature won't match since we're using a dummy sig, but it should parse
    let receipt_json = r#"{
        "receipt": {
            "version": "1.0.0",
            "receipt_id": "test-001",
            "timestamp": "2026-01-01T00:00:00Z",
            "content_hash": "0x0000000000000000000000000000000000000000000000000000000000000000",
            "verdict": {"passed": true}
        },
        "signatures": {
            "signer": "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b"
        }
    }"#;

    // Should parse and return a result (even if signature doesn't match)
    let result = verify_receipt(receipt_json, "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a", None);
    assert!(result.is_ok());
}

#[wasm_bindgen_test]
fn test_verify_receipt_invalid_json() {
    let result = verify_receipt("not valid json", "abc123", None);
    assert!(result.is_err());
}

#[wasm_bindgen_test]
fn test_hash_receipt() {
    let receipt_json = r#"{
        "version": "1.0.0",
        "timestamp": "2026-01-01T00:00:00Z",
        "content_hash": "0x0000000000000000000000000000000000000000000000000000000000000000",
        "verdict": {"passed": true}
    }"#;

    let hash = hash_receipt(receipt_json, "sha256");
    assert!(hash.is_ok());
    let hash = hash.unwrap();
    assert!(hash.starts_with("0x"));
    assert_eq!(hash.len(), 66);
}

#[wasm_bindgen_test]
fn test_get_canonical_json() {
    let receipt_json = r#"{
        "version": "1.0.0",
        "timestamp": "2026-01-01T00:00:00Z",
        "content_hash": "0x0000000000000000000000000000000000000000000000000000000000000000",
        "verdict": {"passed": true}
    }"#;

    let canonical = get_canonical_json(receipt_json);
    assert!(canonical.is_ok());
    let canonical = canonical.unwrap();

    // Canonical JSON should be deterministic
    let canonical2 = get_canonical_json(receipt_json).unwrap();
    assert_eq!(canonical, canonical2);
}

// ============================================================================
// Merkle Tree Tests
// ============================================================================

#[wasm_bindgen_test]
fn test_compute_merkle_root() {
    // Two leaf hashes
    let leaves_json = r#"[
        "0x0000000000000000000000000000000000000000000000000000000000000001",
        "0x0000000000000000000000000000000000000000000000000000000000000002"
    ]"#;

    let result = compute_merkle_root(leaves_json);
    assert!(result.is_ok());
    let root = result.unwrap();
    assert!(root.starts_with("0x"));
    assert_eq!(root.len(), 66);
}

#[wasm_bindgen_test]
fn test_compute_merkle_root_single_leaf() {
    let leaves_json = r#"["0x0000000000000000000000000000000000000000000000000000000000000001"]"#;

    let result = compute_merkle_root(leaves_json);
    assert!(result.is_ok());
}

#[wasm_bindgen_test]
fn test_compute_merkle_root_empty_fails() {
    let leaves_json = r#"[]"#;

    let result = compute_merkle_root(leaves_json);
    assert!(result.is_err());
}

#[wasm_bindgen_test]
fn test_generate_merkle_proof() {
    let leaves_json = r#"[
        "0x0000000000000000000000000000000000000000000000000000000000000001",
        "0x0000000000000000000000000000000000000000000000000000000000000002"
    ]"#;

    let proof = generate_merkle_proof(leaves_json, 0);
    assert!(proof.is_ok());

    let proof_json = proof.unwrap();
    // Should be valid JSON
    assert!(proof_json.contains("tree_size"));
    assert!(proof_json.contains("leaf_index"));
}

#[wasm_bindgen_test]
fn test_verify_merkle_proof() {
    let leaves_json = r#"[
        "0x0000000000000000000000000000000000000000000000000000000000000001",
        "0x0000000000000000000000000000000000000000000000000000000000000002"
    ]"#;

    // Compute root and proof
    let root = compute_merkle_root(leaves_json).unwrap();
    let proof_json = generate_merkle_proof(leaves_json, 0).unwrap();
    let leaf_hex = "0x0000000000000000000000000000000000000000000000000000000000000001";

    // Verify the proof
    let valid = verify_merkle_proof(leaf_hex, &proof_json, &root);
    assert!(valid.is_ok());
    assert!(valid.unwrap());
}

#[wasm_bindgen_test]
fn test_verify_merkle_proof_wrong_leaf() {
    let leaves_json = r#"[
        "0x0000000000000000000000000000000000000000000000000000000000000001",
        "0x0000000000000000000000000000000000000000000000000000000000000002"
    ]"#;

    let root = compute_merkle_root(leaves_json).unwrap();
    let proof_json = generate_merkle_proof(leaves_json, 0).unwrap();

    // Wrong leaf should fail verification
    let wrong_leaf = "0x0000000000000000000000000000000000000000000000000000000000000099";
    let valid = verify_merkle_proof(wrong_leaf, &proof_json, &root);
    assert!(valid.is_ok());
    assert!(!valid.unwrap());
}

// ============================================================================
// Integration Test: Full Attestation Workflow
// ============================================================================

#[wasm_bindgen_test]
fn test_version() {
    let v = version();
    assert!(!v.is_empty());
    assert!(v.contains('.'));
}

#[wasm_bindgen_test]
fn test_hash_sha256_prefixed() {
    let hash = hash_sha256_prefixed(b"hello");
    assert!(hash.starts_with("0x"));
    assert_eq!(hash.len(), 66);
}

#[wasm_bindgen_test]
fn test_full_workflow() {
    // 1. Hash some content
    let content_hash = hash_sha256(b"important task output");
    assert_eq!(content_hash.len(), 64);

    // 2. Create leaves and compute Merkle root
    let content_hash_prefixed = format!("0x{}", content_hash);
    let leaves_json = format!(r#"["{}"]"#, content_hash_prefixed);
    let root = compute_merkle_root(&leaves_json);
    assert!(root.is_ok());
    let root = root.unwrap();
    assert!(root.starts_with("0x"));

    // 3. Generate proof
    let proof = generate_merkle_proof(&leaves_json, 0);
    assert!(proof.is_ok());
    let proof_json = proof.unwrap();

    // 4. Verify proof
    let valid = verify_merkle_proof(&content_hash_prefixed, &proof_json, &root);
    assert!(valid.is_ok());
    assert!(valid.unwrap());

    // 5. Verify Ed25519 with known test vector
    let pubkey = "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a";
    let sig = "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b";
    let sig_valid = verify_ed25519(pubkey, b"", sig);
    assert!(sig_valid.is_ok());
    assert!(sig_valid.unwrap());
}
