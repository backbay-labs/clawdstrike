#![cfg_attr(test, allow(clippy::expect_used, clippy::unwrap_used))]

//! WebAssembly bindings for hush-core cryptographic primitives
//!
//! This crate provides browser-side verification of clawdstrike attestations.

use hush_core::{
    keccak256, receipt::PublicKeySet, sha256, Hash, MerkleProof, MerkleTree, PublicKey, Receipt,
    Signature, SignedReceipt,
};
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

// ============================================================================
// Signature Verification
// ============================================================================

/// Verify an Ed25519 signature over a message.
///
/// # Arguments
/// * `public_key_hex` - Hex-encoded public key (32 bytes, with or without 0x prefix)
/// * `message` - The message bytes that were signed
/// * `signature_hex` - Hex-encoded signature (64 bytes, with or without 0x prefix)
///
/// # Returns
/// `true` if the signature is valid, `false` otherwise
#[wasm_bindgen]
pub fn verify_ed25519(
    public_key_hex: &str,
    message: &[u8],
    signature_hex: &str,
) -> Result<bool, JsError> {
    let pubkey = PublicKey::from_hex(public_key_hex).map_err(|e| JsError::new(&e.to_string()))?;
    let sig = Signature::from_hex(signature_hex).map_err(|e| JsError::new(&e.to_string()))?;

    Ok(pubkey.verify(message, &sig))
}

// ============================================================================
// Receipt Verification
// ============================================================================

/// Verify a signed Receipt.
///
/// # Arguments
/// * `receipt_json` - JSON-serialized SignedReceipt
/// * `signer_pubkey_hex` - Hex-encoded signer public key
/// * `cosigner_pubkey_hex` - Optional hex-encoded co-signer public key
///
/// # Returns
/// JavaScript object with verification result:
/// ```json
/// {
///   "valid": true,
///   "signer_valid": true,
///   "cosigner_valid": null,
///   "errors": []
/// }
/// ```
#[wasm_bindgen]
pub fn verify_receipt(
    receipt_json: &str,
    signer_pubkey_hex: &str,
    cosigner_pubkey_hex: Option<String>,
) -> Result<JsValue, JsError> {
    let signed: SignedReceipt = serde_json::from_str(receipt_json)
        .map_err(|e| JsError::new(&format!("Invalid receipt JSON: {}", e)))?;

    let signer_pk =
        PublicKey::from_hex(signer_pubkey_hex).map_err(|e| JsError::new(&e.to_string()))?;

    let cosigner_pk = match cosigner_pubkey_hex {
        Some(hex) => Some(PublicKey::from_hex(&hex).map_err(|e| JsError::new(&e.to_string()))?),
        None => None,
    };

    let keys = match cosigner_pk {
        Some(pk) => PublicKeySet::new(signer_pk).with_cosigner(pk),
        None => PublicKeySet::new(signer_pk),
    };

    let result = signed.verify(&keys);

    serde_wasm_bindgen::to_value(&result)
        .map_err(|e| JsError::new(&format!("Serialization failed: {}", e)))
}

/// Hash a Receipt to get its canonical hash.
///
/// # Arguments
/// * `receipt_json` - JSON-serialized Receipt (unsigned)
/// * `algorithm` - "sha256" or "keccak256"
///
/// # Returns
/// Hex-encoded hash with 0x prefix
#[wasm_bindgen]
pub fn hash_receipt(receipt_json: &str, algorithm: &str) -> Result<String, JsError> {
    let receipt: Receipt = serde_json::from_str(receipt_json)
        .map_err(|e| JsError::new(&format!("Invalid receipt JSON: {}", e)))?;

    let hash = match algorithm {
        "sha256" => receipt.hash_sha256(),
        "keccak256" => receipt.hash_keccak256(),
        _ => {
            return Err(JsError::new(
                "Invalid algorithm: use 'sha256' or 'keccak256'",
            ))
        }
    }
    .map_err(|e| JsError::new(&e.to_string()))?;

    Ok(hash.to_hex_prefixed())
}

/// Get the canonical JSON representation of a receipt.
/// This is the exact bytes that are signed.
///
/// # Arguments
/// * `receipt_json` - JSON-serialized Receipt
///
/// # Returns
/// Canonical JSON string (sorted keys, no extra whitespace)
#[wasm_bindgen]
pub fn get_canonical_json(receipt_json: &str) -> Result<String, JsError> {
    let receipt: Receipt = serde_json::from_str(receipt_json)
        .map_err(|e| JsError::new(&format!("Invalid receipt JSON: {}", e)))?;

    receipt
        .to_canonical_json()
        .map_err(|e| JsError::new(&e.to_string()))
}

// ============================================================================
// Merkle Tree Operations
// ============================================================================

/// Verify a Merkle inclusion proof.
///
/// # Arguments
/// * `leaf_hash_hex` - Hex-encoded leaf hash (with or without 0x prefix)
/// * `proof_json` - JSON-serialized MerkleProof
/// * `root_hex` - Hex-encoded expected root hash (with or without 0x prefix)
///
/// # Returns
/// `true` if the proof is valid, `false` otherwise
#[wasm_bindgen]
pub fn verify_merkle_proof(
    leaf_hash_hex: &str,
    proof_json: &str,
    root_hex: &str,
) -> Result<bool, JsError> {
    let leaf = Hash::from_hex(leaf_hash_hex).map_err(|e| JsError::new(&e.to_string()))?;
    let root = Hash::from_hex(root_hex).map_err(|e| JsError::new(&e.to_string()))?;
    let proof: MerkleProof = serde_json::from_str(proof_json)
        .map_err(|e| JsError::new(&format!("Invalid proof JSON: {}", e)))?;

    Ok(proof.verify_hash(leaf, &root))
}

/// Compute Merkle root from leaf hashes.
///
/// # Arguments
/// * `leaf_hashes_json` - JSON array of hex-encoded leaf hashes
///
/// # Returns
/// Hex-encoded Merkle root (with 0x prefix)
#[wasm_bindgen]
pub fn compute_merkle_root(leaf_hashes_json: &str) -> Result<String, JsError> {
    let hashes_hex: Vec<String> = serde_json::from_str(leaf_hashes_json)
        .map_err(|e| JsError::new(&format!("Invalid JSON: {}", e)))?;

    let hashes: Vec<Hash> = hashes_hex
        .iter()
        .map(|h| Hash::from_hex(h))
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| JsError::new(&e.to_string()))?;

    let tree = MerkleTree::from_hashes(hashes).map_err(|e| JsError::new(&e.to_string()))?;

    Ok(tree.root().to_hex_prefixed())
}

/// Generate a Merkle proof for a specific leaf index.
///
/// # Arguments
/// * `leaf_hashes_json` - JSON array of hex-encoded leaf hashes
/// * `leaf_index` - Index of the leaf to prove (0-based)
///
/// # Returns
/// JSON-serialized MerkleProof
#[wasm_bindgen]
pub fn generate_merkle_proof(leaf_hashes_json: &str, leaf_index: usize) -> Result<String, JsError> {
    let hashes_hex: Vec<String> = serde_json::from_str(leaf_hashes_json)
        .map_err(|e| JsError::new(&format!("Invalid JSON: {}", e)))?;

    let hashes: Vec<Hash> = hashes_hex
        .iter()
        .map(|h| Hash::from_hex(h))
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| JsError::new(&e.to_string()))?;

    let tree = MerkleTree::from_hashes(hashes).map_err(|e| JsError::new(&e.to_string()))?;

    let proof = tree
        .inclusion_proof(leaf_index)
        .map_err(|e| JsError::new(&e.to_string()))?;

    serde_json::to_string(&proof).map_err(|e| JsError::new(&format!("Serialization failed: {}", e)))
}
