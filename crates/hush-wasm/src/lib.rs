//! WebAssembly bindings for hush-core cryptographic primitives
//!
//! This crate provides browser-side verification of hushclaw attestations.

use wasm_bindgen::prelude::*;
use hush_core::{sha256, keccak256};

/// Initialize the WASM module (call once at startup)
#[wasm_bindgen(start)]
pub fn init() {
    console_error_panic_hook::set_once();
}

/// Get version information about this WASM module
#[wasm_bindgen]
pub fn version() -> String {
    env!("CARGO_PKG_VERSION").to_string()
}

/// Compute SHA-256 hash of data.
///
/// # Arguments
/// * `data` - The bytes to hash
///
/// # Returns
/// Hex-encoded hash (64 characters, no 0x prefix)
#[wasm_bindgen]
pub fn hash_sha256(data: &[u8]) -> String {
    sha256(data).to_hex()
}

/// Compute SHA-256 hash with 0x prefix.
///
/// # Arguments
/// * `data` - The bytes to hash
///
/// # Returns
/// Hex-encoded hash with 0x prefix (66 characters)
#[wasm_bindgen]
pub fn hash_sha256_prefixed(data: &[u8]) -> String {
    sha256(data).to_hex_prefixed()
}

/// Compute Keccak-256 hash of data (Ethereum-compatible).
///
/// # Arguments
/// * `data` - The bytes to hash
///
/// # Returns
/// Hex-encoded hash with 0x prefix (66 characters)
#[wasm_bindgen]
pub fn hash_keccak256(data: &[u8]) -> String {
    keccak256(data).to_hex_prefixed()
}
