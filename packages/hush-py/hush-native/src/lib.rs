//! Native Rust bindings for hush Python SDK.
//!
//! Provides optimized implementations of cryptographic operations.

use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;

/// Verify a signed receipt using native Rust implementation.
#[pyfunction]
fn verify_receipt_native(
    receipt_json: &str,
    signature_hex: &str,
    public_key_hex: &str,
) -> PyResult<bool> {
    use hush_core::signing::{PublicKey, Signature};

    let public_key = PublicKey::from_hex(public_key_hex)
        .map_err(|e| PyValueError::new_err(format!("Invalid public key: {}", e)))?;

    let signature = Signature::from_hex(signature_hex)
        .map_err(|e| PyValueError::new_err(format!("Invalid signature: {}", e)))?;

    Ok(public_key.verify(receipt_json.as_bytes(), &signature))
}

/// Compute SHA-256 hash using native implementation.
#[pyfunction]
fn sha256_native(data: &[u8]) -> PyResult<Vec<u8>> {
    use hush_core::hashing::sha256;
    Ok(sha256(data).as_bytes().to_vec())
}

/// Compute Keccak-256 hash using native implementation.
#[pyfunction]
fn keccak256_native(data: &[u8]) -> PyResult<Vec<u8>> {
    use hush_core::hashing::keccak256;
    Ok(keccak256(data).as_bytes().to_vec())
}

/// Compute Merkle root from leaf hashes.
#[pyfunction]
fn merkle_root_native(leaves: Vec<Vec<u8>>) -> PyResult<Vec<u8>> {
    use hush_core::hashing::Hash;
    use hush_core::merkle::MerkleTree;

    if leaves.is_empty() {
        return Err(PyValueError::new_err("Cannot compute root of empty tree"));
    }

    // Convert Vec<Vec<u8>> to Vec<Hash>
    let leaf_hashes: Vec<Hash> = leaves
        .iter()
        .map(|l| {
            let arr: [u8; 32] = l
                .as_slice()
                .try_into()
                .map_err(|_| PyValueError::new_err("Leaf must be 32 bytes"))?;
            Ok(Hash::from_bytes(arr))
        })
        .collect::<PyResult<Vec<_>>>()?;

    let tree = MerkleTree::from_hashes(leaf_hashes)
        .map_err(|e| PyValueError::new_err(format!("Failed to build tree: {}", e)))?;

    Ok(tree.root().as_bytes().to_vec())
}

/// Verify Ed25519 signature using native implementation.
#[pyfunction]
fn verify_ed25519_native(message: &[u8], signature: &[u8], public_key: &[u8]) -> PyResult<bool> {
    use hush_core::signing::{PublicKey, Signature};

    if public_key.len() != 32 {
        return Err(PyValueError::new_err("Public key must be 32 bytes"));
    }
    if signature.len() != 64 {
        return Err(PyValueError::new_err("Signature must be 64 bytes"));
    }

    let mut pk_bytes = [0u8; 32];
    pk_bytes.copy_from_slice(public_key);

    let mut sig_bytes = [0u8; 64];
    sig_bytes.copy_from_slice(signature);

    let pk = PublicKey::from_bytes(&pk_bytes)
        .map_err(|e| PyValueError::new_err(format!("Invalid public key: {}", e)))?;
    let sig = Signature::from_bytes(&sig_bytes);

    Ok(pk.verify(message, &sig))
}

/// Generate Merkle inclusion proof using native implementation.
/// Returns (tree_size, leaf_index, audit_path_hex_list).
#[pyfunction]
fn generate_merkle_proof_native(
    leaves: Vec<Vec<u8>>,
    index: usize,
) -> PyResult<(usize, usize, Vec<String>)> {
    use hush_core::hashing::Hash;
    use hush_core::merkle::MerkleTree;

    if leaves.is_empty() {
        return Err(PyValueError::new_err(
            "Cannot generate proof for empty tree",
        ));
    }
    if index >= leaves.len() {
        return Err(PyValueError::new_err(format!(
            "Index {} out of range for {} leaves",
            index,
            leaves.len()
        )));
    }

    // Convert to Hash type
    let leaf_hashes: Vec<Hash> = leaves
        .iter()
        .map(|l| {
            let arr: [u8; 32] = l
                .as_slice()
                .try_into()
                .map_err(|_| PyValueError::new_err("Leaf must be 32 bytes"))?;
            Ok(Hash::from_bytes(arr))
        })
        .collect::<PyResult<Vec<_>>>()?;

    let tree = MerkleTree::from_hashes(leaf_hashes)
        .map_err(|e| PyValueError::new_err(format!("Failed to build tree: {}", e)))?;

    let proof = tree
        .inclusion_proof(index)
        .map_err(|e| PyValueError::new_err(format!("Failed to generate proof: {}", e)))?;

    let audit_path_hex: Vec<String> = proof
        .audit_path
        .iter()
        .map(|h| format!("0x{}", h.to_hex()))
        .collect();

    Ok((proof.tree_size, proof.leaf_index, audit_path_hex))
}

/// Canonicalize JSON string using native RFC 8785 implementation.
#[pyfunction]
fn canonicalize_native(json_str: &str) -> PyResult<String> {
    use hush_core::canonicalize_json;

    let value: serde_json::Value = serde_json::from_str(json_str)
        .map_err(|e| PyValueError::new_err(format!("Invalid JSON: {}", e)))?;

    canonicalize_json(&value)
        .map_err(|e| PyValueError::new_err(format!("Canonicalization failed: {}", e)))
}

/// Check if native backend is available.
#[pyfunction]
fn is_native_available() -> bool {
    true
}

/// Python module definition.
#[pymodule]
fn hush_native(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(verify_receipt_native, m)?)?;
    m.add_function(wrap_pyfunction!(sha256_native, m)?)?;
    m.add_function(wrap_pyfunction!(keccak256_native, m)?)?;
    m.add_function(wrap_pyfunction!(merkle_root_native, m)?)?;
    m.add_function(wrap_pyfunction!(verify_ed25519_native, m)?)?;
    m.add_function(wrap_pyfunction!(generate_merkle_proof_native, m)?)?;
    m.add_function(wrap_pyfunction!(canonicalize_native, m)?)?;
    m.add_function(wrap_pyfunction!(is_native_available, m)?)?;
    Ok(())
}
