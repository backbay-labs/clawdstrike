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

#[cfg(test)]
mod tests {
    use super::*;
    use hush_core::{sha256 as core_sha256, Keypair, Receipt, SignedReceipt, Verdict};

    #[test]
    fn sha256_known_input() {
        // SHA-256 of empty string
        let result = hash_sha256(b"");
        assert_eq!(
            result,
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );

        // SHA-256 of "hello"
        let result = hash_sha256(b"hello");
        assert_eq!(
            result,
            "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"
        );
    }

    #[test]
    fn sha256_prefixed() {
        let result = hash_sha256_prefixed(b"hello");
        assert!(result.starts_with("0x"));
        assert_eq!(result.len(), 66); // "0x" + 64 hex chars
        assert_eq!(
            result,
            "0x2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"
        );
    }

    #[test]
    fn keccak256_known_input() {
        // Keccak-256 of empty string (Ethereum standard)
        let result = hash_keccak256(b"");
        assert_eq!(
            result,
            "0xc5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470"
        );
    }

    #[test]
    fn verify_ed25519_roundtrip() {
        let keypair = Keypair::generate();
        let message = b"test message for ed25519 verification";
        let signature = keypair.sign(message);

        let pk_hex = keypair.public_key().to_hex();
        let sig_hex = signature.to_hex();

        let valid = verify_ed25519(&pk_hex, message, &sig_hex).unwrap();
        assert!(valid);
    }

    #[test]
    fn verify_ed25519_wrong_message() {
        let keypair = Keypair::generate();
        let signature = keypair.sign(b"original message");

        let pk_hex = keypair.public_key().to_hex();
        let sig_hex = signature.to_hex();

        let valid = verify_ed25519(&pk_hex, b"wrong message", &sig_hex).unwrap();
        assert!(!valid);
    }

    #[test]
    fn canonicalize_json_deterministic() {
        // Test the underlying canonicalization via hush-core (wasm wrappers use JsError).
        use hush_core::canonical::canonicalize;

        let v1: serde_json::Value = serde_json::from_str(r#"{"b":2,"a":1}"#).unwrap();
        let v2: serde_json::Value = serde_json::from_str(r#"{"a":1,"b":2}"#).unwrap();

        let canon1 = canonicalize(&v1).unwrap();
        let canon2 = canonicalize(&v2).unwrap();
        assert_eq!(canon1, canon2);
        // Keys should be sorted
        assert_eq!(canon1, r#"{"a":1,"b":2}"#);
    }

    #[test]
    fn compute_merkle_root_and_verify_proof() {
        // Create leaf hashes
        let h1 = core_sha256(b"leaf1").to_hex_prefixed();
        let h2 = core_sha256(b"leaf2").to_hex_prefixed();
        let h3 = core_sha256(b"leaf3").to_hex_prefixed();
        let h4 = core_sha256(b"leaf4").to_hex_prefixed();

        let leaves_json = serde_json::to_string(&vec![&h1, &h2, &h3, &h4]).unwrap();

        // Compute root
        let root = compute_merkle_root(&leaves_json).unwrap();
        assert!(root.starts_with("0x"));

        // Generate proof for leaf 0
        let proof_json = generate_merkle_proof(&leaves_json, 0).unwrap();

        // Verify proof
        let valid = verify_merkle_proof(&h1, &proof_json, &root).unwrap();
        assert!(valid);

        // Verify wrong leaf fails
        let invalid = verify_merkle_proof(&h2, &proof_json, &root).unwrap();
        assert!(!invalid);
    }

    #[test]
    fn merkle_proof_different_indices() {
        let h1 = core_sha256(b"a").to_hex_prefixed();
        let h2 = core_sha256(b"b").to_hex_prefixed();
        let leaves_json = serde_json::to_string(&vec![&h1, &h2]).unwrap();

        let root = compute_merkle_root(&leaves_json).unwrap();

        // Proof for index 1
        let proof_json = generate_merkle_proof(&leaves_json, 1).unwrap();
        let valid = verify_merkle_proof(&h2, &proof_json, &root).unwrap();
        assert!(valid);
    }

    #[test]
    fn verify_receipt_roundtrip() {
        // Test using hush-core directly (wasm wrapper returns JsValue).
        use hush_core::receipt::PublicKeySet;

        let keypair = Keypair::generate();
        let content_hash = core_sha256(b"test content");
        let receipt = Receipt::new(content_hash, Verdict::pass());
        let signed = SignedReceipt::sign(receipt, &keypair).unwrap();

        let keys = PublicKeySet::new(keypair.public_key());
        let result = signed.verify(&keys);
        assert!(result.valid);
        assert!(result.signer_valid);
    }

    #[test]
    fn hash_receipt_sha256_and_keccak256() {
        // Test via hush-core directly (wasm wrapper uses JsError).
        let content_hash = core_sha256(b"test");
        let receipt = Receipt::new(content_hash, Verdict::pass());

        let sha_hash = receipt.hash_sha256().unwrap();
        assert_eq!(sha_hash.to_hex_prefixed().len(), 66);

        let keccak_hash = receipt.hash_keccak256().unwrap();
        assert_eq!(keccak_hash.to_hex_prefixed().len(), 66);

        // Different algorithms should produce different hashes
        assert_ne!(sha_hash, keccak_hash);
    }

    #[test]
    fn receipt_canonical_json_deterministic() {
        // Test the canonical JSON of a receipt (mirrors hash_receipt logic).
        let content_hash = core_sha256(b"test");
        let receipt = Receipt::new(content_hash, Verdict::pass());

        let canon1 = receipt.to_canonical_json().unwrap();
        let canon2 = receipt.to_canonical_json().unwrap();
        assert_eq!(canon1, canon2);
        assert!(!canon1.is_empty());
    }
}
