//! WebAssembly bindings for hush-core cryptographic primitives
//!
//! This crate provides browser and Node.js verification of hushclaw attestations.
//! It enables trustless verification where users can independently verify
//! that SignedReceipts are validly signed and Merkle proofs are correct.

use wasm_bindgen::prelude::*;

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
