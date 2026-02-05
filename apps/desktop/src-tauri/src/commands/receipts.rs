//! Receipt verification commands

use serde::{Deserialize, Serialize};
use tauri::State;

use crate::state::AppState;

#[derive(Debug, Serialize, Deserialize)]
pub struct ReceiptVerification {
    pub valid: bool,
    pub signature_valid: bool,
    pub merkle_valid: Option<bool>,
    pub timestamp_valid: bool,
    pub errors: Vec<String>,
}

const MAX_FUTURE_SKEW_SECS: i64 = 5 * 60;

#[derive(Clone, Debug)]
enum ReceiptPayload {
    HushSignedReceipt(hush_core::SignedReceipt),
    Detached {
        payload: serde_json::Value,
        signature: hush_core::Signature,
    },
}

fn payload_timestamp(payload: &ReceiptPayload, raw: &serde_json::Value) -> Option<String> {
    match payload {
        ReceiptPayload::HushSignedReceipt(signed) => Some(signed.receipt.timestamp.clone()),
        ReceiptPayload::Detached { payload, .. } => payload
            .get("timestamp")
            .and_then(|v| v.as_str())
            .or_else(|| raw.get("timestamp").and_then(|v| v.as_str()))
            .map(str::to_string),
    }
}

fn payload_content_hash(
    payload: &ReceiptPayload,
    raw: &serde_json::Value,
) -> Option<hush_core::Hash> {
    match payload {
        ReceiptPayload::HushSignedReceipt(signed) => Some(signed.receipt.content_hash),
        ReceiptPayload::Detached { payload, .. } => payload
            .get("content_hash")
            .and_then(|v| v.as_str())
            .or_else(|| raw.get("content_hash").and_then(|v| v.as_str()))
            .and_then(|s| hush_core::Hash::from_hex(s).ok()),
    }
}

fn validate_timestamp(ts: Option<&str>, errors: &mut Vec<String>) -> bool {
    let Some(ts) = ts else {
        errors.push("Missing timestamp".to_string());
        return false;
    };

    let parsed = match chrono::DateTime::parse_from_rfc3339(ts) {
        Ok(v) => v.with_timezone(&chrono::Utc),
        Err(e) => {
            errors.push(format!("Invalid timestamp (RFC3339 required): {e}"));
            return false;
        }
    };

    let max_allowed = chrono::Utc::now() + chrono::Duration::seconds(MAX_FUTURE_SKEW_SECS);
    if parsed > max_allowed {
        errors.push(format!(
            "Timestamp is too far in the future (>{MAX_FUTURE_SKEW_SECS}s skew): {ts}"
        ));
        return false;
    }

    true
}

fn parse_hush_signed_receipt(raw: &serde_json::Value) -> Result<hush_core::SignedReceipt, String> {
    let receipt = raw
        .get("receipt")
        .ok_or_else(|| "Missing receipt field".to_string())?;
    let signatures = raw
        .get("signatures")
        .ok_or_else(|| "Missing signatures field".to_string())?;

    let mut obj = serde_json::Map::new();
    obj.insert("receipt".to_string(), receipt.clone());
    obj.insert("signatures".to_string(), signatures.clone());
    serde_json::from_value(serde_json::Value::Object(obj))
        .map_err(|e| format!("Invalid hush SignedReceipt JSON: {e}"))
}

fn parse_detached_payload(raw: &serde_json::Value) -> Result<ReceiptPayload, String> {
    let sig_hex = raw
        .get("signature")
        .and_then(|v| v.as_str())
        .ok_or_else(|| "Missing signature field".to_string())?;
    let signature = hush_core::Signature::from_hex(sig_hex)
        .map_err(|e| format!("Invalid signature (hex required): {e}"))?;

    // If a nested `receipt` object exists, treat that as the signed payload; otherwise, the entire
    // object is treated as the signed payload.
    let mut payload = raw
        .get("receipt")
        .filter(|v| v.is_object())
        .cloned()
        .unwrap_or_else(|| raw.clone());

    // Strip common envelope-only fields from the payload before canonicalization.
    if let Some(obj) = payload.as_object_mut() {
        for k in ["signature", "public_key", "merkle_root", "merkle_proof"] {
            obj.remove(k);
        }
    }

    Ok(ReceiptPayload::Detached { payload, signature })
}

fn parse_receipt_payload(raw: &serde_json::Value) -> Result<ReceiptPayload, String> {
    if raw.get("receipt").is_some() && raw.get("signatures").is_some() {
        return Ok(ReceiptPayload::HushSignedReceipt(
            parse_hush_signed_receipt(raw)?,
        ));
    }

    if raw.get("signature").is_some() {
        return parse_detached_payload(raw);
    }

    Err("Unsupported receipt format (expected {receipt,signatures} or {signature,...})".to_string())
}

fn resolve_public_key(
    raw: &serde_json::Value,
    daemon_key: Option<hush_core::PublicKey>,
    errors: &mut Vec<String>,
) -> Option<hush_core::PublicKey> {
    if let Some(pk) = daemon_key {
        return Some(pk);
    }

    let Some(pk_str) = raw.get("public_key").and_then(|v| v.as_str()) else {
        return None;
    };

    match hush_core::PublicKey::from_hex(pk_str) {
        Ok(pk) => Some(pk),
        Err(e) => {
            errors.push(format!("Invalid embedded public_key (hex required): {e}"));
            None
        }
    }
}

fn verify_signature(
    payload: &ReceiptPayload,
    public_key: Option<&hush_core::PublicKey>,
    errors: &mut Vec<String>,
) -> bool {
    let Some(public_key) = public_key else {
        errors.push(
            "Missing public key (connect to daemon or include public_key in the receipt envelope)"
                .to_string(),
        );
        return false;
    };

    match payload {
        ReceiptPayload::HushSignedReceipt(signed) => {
            let keys = hush_core::receipt::PublicKeySet::new(public_key.clone());
            let result = signed.verify(&keys);
            if !result.valid {
                errors.extend(result.errors);
            }
            result.valid
        }
        ReceiptPayload::Detached { payload, signature } => {
            let canonical = match hush_core::canonicalize_json(payload) {
                Ok(v) => v,
                Err(e) => {
                    errors.push(format!("Failed to canonicalize payload: {e}"));
                    return false;
                }
            };
            if !public_key.verify(canonical.as_bytes(), signature) {
                errors.push("Invalid signer signature".to_string());
                return false;
            }
            true
        }
    }
}

fn parse_merkle_root(root: &str) -> Result<hush_core::Hash, String> {
    let root = root.trim();
    let root = root.strip_prefix("sha256:").unwrap_or(root);
    hush_core::Hash::from_hex(root).map_err(|e| format!("Invalid merkle_root: {e}"))
}

fn verify_merkle(
    raw: &serde_json::Value,
    payload: &ReceiptPayload,
    errors: &mut Vec<String>,
) -> Option<bool> {
    let Some(root_str) = raw.get("merkle_root").and_then(|v| v.as_str()) else {
        return None;
    };
    let Some(proof_value) = raw.get("merkle_proof") else {
        return None;
    };

    let root = match parse_merkle_root(root_str) {
        Ok(v) => v,
        Err(e) => {
            errors.push(e);
            return Some(false);
        }
    };

    let proof: hush_core::MerkleProof = match serde_json::from_value(proof_value.clone()) {
        Ok(v) => v,
        Err(e) => {
            errors.push(format!(
                "Invalid merkle_proof (hush-core MerkleProof required): {e}"
            ));
            return Some(false);
        }
    };

    let leaf_hash = match payload_content_hash(payload, raw) {
        Some(v) => v,
        None => {
            errors.push("Missing content_hash required for merkle proof verification".to_string());
            return Some(false);
        }
    };

    let ok = proof.verify(leaf_hash.as_bytes(), &root);
    if !ok {
        errors.push("Merkle proof verification failed".to_string());
    }
    Some(ok)
}

fn verify_receipt_value(
    raw: serde_json::Value,
    daemon_public_key: Option<hush_core::PublicKey>,
) -> ReceiptVerification {
    let mut errors = Vec::new();

    let payload = match parse_receipt_payload(&raw) {
        Ok(v) => v,
        Err(e) => {
            return ReceiptVerification {
                valid: false,
                signature_valid: false,
                merkle_valid: None,
                timestamp_valid: false,
                errors: vec![e],
            };
        }
    };

    let public_key = resolve_public_key(&raw, daemon_public_key, &mut errors);
    let signature_valid = verify_signature(&payload, public_key.as_ref(), &mut errors);
    let timestamp = payload_timestamp(&payload, &raw);
    let timestamp_valid = validate_timestamp(timestamp.as_deref(), &mut errors);
    let merkle_valid = verify_merkle(&raw, &payload, &mut errors);

    let mut valid = signature_valid && timestamp_valid;
    if merkle_valid == Some(false) {
        valid = false;
    }

    ReceiptVerification {
        valid,
        signature_valid,
        merkle_valid,
        timestamp_valid,
        errors,
    }
}

async fn try_fetch_daemon_public_key(
    state: &AppState,
) -> Result<Option<hush_core::PublicKey>, String> {
    let daemon = state.daemon.read().await;
    if !daemon.connected {
        return Ok(None);
    }
    let base = daemon.url.clone();
    drop(daemon);

    let url = format!("{}/api/v1/policy/bundle", base.trim_end_matches('/'));
    let resp = state
        .http_client
        .get(url)
        .send()
        .await
        .map_err(|e| format!("Failed to fetch daemon policy bundle: {e}"))?;
    if !resp.status().is_success() {
        return Ok(None);
    }

    let value: serde_json::Value = resp
        .json()
        .await
        .map_err(|e| format!("Failed to parse daemon policy bundle: {e}"))?;

    let pk = match value.get("public_key").and_then(|v| v.as_str()) {
        Some(v) => v,
        None => return Ok(None),
    };

    let pk = hush_core::PublicKey::from_hex(pk)
        .map_err(|e| format!("Invalid daemon public_key: {e}"))?;
    Ok(Some(pk))
}

/// Verify a signed receipt.
#[tauri::command]
pub async fn verify_receipt(
    receipt: serde_json::Value,
    state: State<'_, AppState>,
) -> Result<ReceiptVerification, String> {
    let daemon_key = match try_fetch_daemon_public_key(state.inner()).await {
        Ok(v) => v,
        Err(_) => None,
    };

    Ok(verify_receipt_value(receipt, daemon_key))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    fn canonicalize_to_value(map: BTreeMap<&str, serde_json::Value>) -> serde_json::Value {
        let obj: serde_json::Map<String, serde_json::Value> =
            map.into_iter().map(|(k, v)| (k.to_string(), v)).collect();
        serde_json::Value::Object(obj)
    }

    fn make_signed_receipt_json(
        keypair: &hush_core::Keypair,
        timestamp: &str,
        content_hash: hush_core::Hash,
    ) -> serde_json::Value {
        let mut receipt = hush_core::Receipt::new(content_hash, hush_core::Verdict::pass())
            .with_id("test-receipt");
        receipt.timestamp = timestamp.to_string();
        let signed = hush_core::SignedReceipt::sign(receipt, keypair).unwrap();

        let mut map = BTreeMap::new();
        map.insert("receipt", serde_json::to_value(&signed.receipt).unwrap());
        map.insert(
            "signatures",
            serde_json::to_value(&signed.signatures).unwrap(),
        );
        map.insert(
            "public_key",
            serde_json::Value::String(keypair.public_key().to_hex()),
        );
        canonicalize_to_value(map)
    }

    #[test]
    fn signed_receipt_verifies_with_embedded_key() {
        let keypair = hush_core::Keypair::generate();
        let content_hash = hush_core::sha256(b"test");
        let raw = make_signed_receipt_json(&keypair, "2026-01-01T00:00:00Z", content_hash);

        let out = verify_receipt_value(raw, None);
        assert!(out.signature_valid);
        assert!(out.timestamp_valid);
        assert!(out.valid);
    }

    #[test]
    fn signed_receipt_wrong_key_fails() {
        let keypair = hush_core::Keypair::generate();
        let wrong = hush_core::Keypair::generate();
        let content_hash = hush_core::sha256(b"test");

        let mut raw = make_signed_receipt_json(&keypair, "2026-01-01T00:00:00Z", content_hash);
        raw.as_object_mut().unwrap().insert(
            "public_key".to_string(),
            serde_json::Value::String(wrong.public_key().to_hex()),
        );

        let out = verify_receipt_value(raw, None);
        assert!(!out.signature_valid);
        assert!(!out.valid);
        assert!(out
            .errors
            .iter()
            .any(|e| e.contains("Invalid signer signature")));
    }

    #[test]
    fn detached_envelope_verifies() {
        let keypair = hush_core::Keypair::generate();
        let payload = serde_json::json!({
            "version": hush_core::receipt::RECEIPT_SCHEMA_VERSION,
            "receipt_id": "r-1",
            "timestamp": "2026-01-01T00:00:00Z",
            "content_hash": hush_core::sha256(b"payload"),
            "verdict": { "passed": true },
        });

        let canonical = hush_core::canonicalize_json(&payload).unwrap();
        let sig = keypair.sign(canonical.as_bytes());

        let raw = serde_json::json!({
            "signature": sig.to_hex(),
            "public_key": keypair.public_key().to_hex(),
            "receipt": payload,
        });

        let out = verify_receipt_value(raw, None);
        assert!(out.signature_valid);
        assert!(out.timestamp_valid);
        assert!(out.valid);
    }

    #[test]
    fn future_timestamp_rejected() {
        let keypair = hush_core::Keypair::generate();
        let content_hash = hush_core::sha256(b"test");
        let raw = make_signed_receipt_json(&keypair, "3000-01-01T00:00:00Z", content_hash);

        let out = verify_receipt_value(raw, None);
        assert!(out.signature_valid);
        assert!(!out.timestamp_valid);
        assert!(!out.valid);
    }

    #[test]
    fn merkle_proof_checked_when_present() {
        let keypair = hush_core::Keypair::generate();

        let leaf0 = hush_core::sha256(b"leaf0");
        let leaf1 = hush_core::sha256(b"leaf1");
        let tree = hush_core::MerkleTree::from_leaves(&[
            leaf0.as_bytes().to_vec(),
            leaf1.as_bytes().to_vec(),
        ])
        .unwrap();
        let proof = tree.inclusion_proof(0).unwrap();

        let mut raw = make_signed_receipt_json(&keypair, "2026-01-01T00:00:00Z", leaf0);
        raw.as_object_mut().unwrap().insert(
            "merkle_root".to_string(),
            serde_json::Value::String(format!("sha256:{}", tree.root().to_hex())),
        );
        raw.as_object_mut().unwrap().insert(
            "merkle_proof".to_string(),
            serde_json::to_value(&proof).unwrap(),
        );

        let out = verify_receipt_value(raw, None);
        assert_eq!(out.merkle_valid, Some(true));
        assert!(out.valid);
    }
}
