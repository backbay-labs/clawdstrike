#![cfg_attr(test, allow(clippy::expect_used, clippy::unwrap_used))]

//! Native Rust bindings for hush Python SDK.
//!
//! Provides optimized implementations of cryptographic operations.

use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;
use pyo3::types::PyModule;

use std::collections::HashMap;
use std::sync::{Mutex, OnceLock};

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};

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

fn json_value_to_py(py: Python<'_>, value: &serde_json::Value) -> PyResult<Py<PyAny>> {
    let json_str = serde_json::to_string(value)
        .map_err(|e| PyValueError::new_err(format!("Failed to serialize JSON: {}", e)))?;
    let json = PyModule::import(py, "json")?;
    let obj = json.call_method1("loads", (json_str,))?;
    Ok(obj.unbind())
}

static DEFAULT_JAILBREAK_DETECTOR: OnceLock<clawdstrike::JailbreakDetector> = OnceLock::new();

/// Detect jailbreak attempts using the native Rust detector.
///
/// Returns a Python dict (JSON-serializable).
#[pyfunction]
#[pyo3(signature = (text, session_id=None, config_json=None))]
fn detect_jailbreak_native(
    py: Python<'_>,
    text: &str,
    session_id: Option<&str>,
    config_json: Option<&str>,
) -> PyResult<Py<PyAny>> {
    use clawdstrike::{JailbreakDetector, JailbreakGuardConfig};

    let result = if let Some(cfg_json) = config_json {
        let cfg: JailbreakGuardConfig = serde_json::from_str(cfg_json).map_err(|e| {
            PyValueError::new_err(format!("Invalid JailbreakGuardConfig JSON: {}", e))
        })?;
        let detector = JailbreakDetector::with_config(cfg);
        futures::executor::block_on(detector.detect(text, session_id))
    } else {
        let detector = DEFAULT_JAILBREAK_DETECTOR.get_or_init(JailbreakDetector::new);
        futures::executor::block_on(detector.detect(text, session_id))
    };

    let v = serde_json::to_value(&result)
        .map_err(|e| PyValueError::new_err(format!("Failed to serialize result: {}", e)))?;
    json_value_to_py(py, &v)
}

/// Sanitize model output for secret/PII leakage.
///
/// `config_json` is an optional JSON serialization of `clawdstrike::OutputSanitizerConfig`.
#[pyfunction]
#[pyo3(signature = (text, config_json=None))]
fn sanitize_output_native(
    py: Python<'_>,
    text: &str,
    config_json: Option<&str>,
) -> PyResult<Py<PyAny>> {
    use clawdstrike::{OutputSanitizer, OutputSanitizerConfig};

    let cfg: OutputSanitizerConfig = match config_json {
        Some(cfg_json) => serde_json::from_str(cfg_json).map_err(|e| {
            PyValueError::new_err(format!("Invalid OutputSanitizerConfig JSON: {}", e))
        })?,
        None => OutputSanitizerConfig::default(),
    };

    let sanitizer = OutputSanitizer::with_config(cfg);
    let result = sanitizer.sanitize_sync(text);
    let v = serde_json::to_value(&result)
        .map_err(|e| PyValueError::new_err(format!("Failed to serialize result: {}", e)))?;
    json_value_to_py(py, &v)
}

static WATERMARKERS: OnceLock<Mutex<HashMap<String, std::sync::Arc<clawdstrike::PromptWatermarker>>>> =
    OnceLock::new();

fn watermark_key(config_json: &str) -> Result<String, String> {
    let v: serde_json::Value =
        serde_json::from_str(config_json).map_err(|e| format!("invalid JSON: {}", e))?;
    hush_core::canonicalize_json(&v).map_err(|e| e.to_string())
}

fn get_or_create_watermarker(
    config_json: &str,
) -> Result<std::sync::Arc<clawdstrike::PromptWatermarker>, String> {
    let key = watermark_key(config_json)?;
    let cfg: clawdstrike::WatermarkConfig =
        serde_json::from_str(config_json).map_err(|e| format!("invalid WatermarkConfig: {}", e))?;

    let map = WATERMARKERS.get_or_init(|| Mutex::new(HashMap::new()));
    let mut guard = map.lock().map_err(|_| "watermarker lock poisoned".to_string())?;
    if !guard.contains_key(&key) {
        let wm = clawdstrike::PromptWatermarker::new(cfg).map_err(|e| format!("{:?}", e))?;
        guard.insert(key.clone(), std::sync::Arc::new(wm));
    }

    guard
        .get(&key)
        .cloned()
        .ok_or_else(|| "watermarker missing".to_string())
}

/// Return the public key hex for a watermark configuration.
#[pyfunction]
fn watermark_public_key_native(config_json: &str) -> PyResult<String> {
    let wm = get_or_create_watermarker(config_json)
        .map_err(|e| PyValueError::new_err(format!("Failed to init watermarker: {}", e)))?;
    Ok(wm.public_key())
}

/// Watermark a prompt using the native Rust implementation.
///
/// `config_json` is a JSON serialization of `clawdstrike::WatermarkConfig`.
#[pyfunction]
#[pyo3(signature = (prompt, config_json, application_id = "unknown", session_id = "unknown"))]
fn watermark_prompt_native(
    py: Python<'_>,
    prompt: &str,
    config_json: &str,
    application_id: &str,
    session_id: &str,
) -> PyResult<Py<PyAny>> {
    let wm = get_or_create_watermarker(config_json)
        .map_err(|e| PyValueError::new_err(format!("Failed to init watermarker: {}", e)))?;

    let payload = wm.generate_payload(application_id, session_id);
    let out = wm
        .watermark(prompt, Some(payload))
        .map_err(|e| PyValueError::new_err(format!("Watermarking failed: {:?}", e)))?;

    let encoded_data_b64 = URL_SAFE_NO_PAD.encode(&out.watermark.encoded_data);
    let v = serde_json::json!({
        "original": out.original,
        "watermarked": out.watermarked,
        "watermark": {
            "payload": out.watermark.payload,
            "encoding": out.watermark.encoding,
            "encodedDataBase64Url": encoded_data_b64,
            "signature": out.watermark.signature,
            "publicKey": out.watermark.public_key,
            "fingerprint": out.watermark.fingerprint(),
        }
    });
    json_value_to_py(py, &v)
}

/// Extract (and verify) a watermark from text.
///
/// `config_json` is a JSON serialization of `clawdstrike::WatermarkVerifierConfig`.
#[pyfunction]
fn extract_watermark_native(
    py: Python<'_>,
    text: &str,
    config_json: &str,
) -> PyResult<Py<PyAny>> {
    use clawdstrike::{WatermarkExtractor, WatermarkVerifierConfig};

    let cfg: WatermarkVerifierConfig = serde_json::from_str(config_json).map_err(|e| {
        PyValueError::new_err(format!("Invalid WatermarkVerifierConfig JSON: {}", e))
    })?;
    let extractor = WatermarkExtractor::new(cfg);
    let r = extractor.extract(text);

    let watermark = match r.watermark {
        Some(wm) => serde_json::json!({
            "payload": wm.payload,
            "encoding": wm.encoding,
            "encodedDataBase64Url": URL_SAFE_NO_PAD.encode(&wm.encoded_data),
            "signature": wm.signature,
            "publicKey": wm.public_key,
            "fingerprint": wm.fingerprint(),
        }),
        None => serde_json::Value::Null,
    };

    let v = serde_json::json!({
        "found": r.found,
        "verified": r.verified,
        "errors": r.errors,
        "watermark": watermark,
    });

    json_value_to_py(py, &v)
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
    m.add_function(wrap_pyfunction!(detect_jailbreak_native, m)?)?;
    m.add_function(wrap_pyfunction!(sanitize_output_native, m)?)?;
    m.add_function(wrap_pyfunction!(watermark_public_key_native, m)?)?;
    m.add_function(wrap_pyfunction!(watermark_prompt_native, m)?)?;
    m.add_function(wrap_pyfunction!(extract_watermark_native, m)?)?;
    m.add_function(wrap_pyfunction!(is_native_available, m)?)?;
    Ok(())
}
