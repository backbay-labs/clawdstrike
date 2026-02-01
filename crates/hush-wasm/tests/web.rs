#![cfg(target_arch = "wasm32")]

use wasm_bindgen_test::*;
use hush_wasm::*;

wasm_bindgen_test_configure!(run_in_browser);

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
