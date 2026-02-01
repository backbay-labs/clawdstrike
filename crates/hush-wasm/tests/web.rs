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
