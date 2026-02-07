//! Spine envelope: signed fact messages on the attestation log.
//!
//! Adapted from `aegisnet::spine`, using [`hush_core`] for crypto.

use hush_core::{canonicalize_json, sha256, sha256_hex, Hash, Keypair};
use serde_json::{json, Value};

use crate::error::{Error, Result};

/// Schema identifier for v1 envelopes.
pub const ENVELOPE_SCHEMA_V1: &str = "aegis.spine.envelope.v1";

/// Current UTC time as RFC 3339 string (second precision).
pub fn now_rfc3339() -> String {
    chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true)
}

/// Derive a spine issuer identifier from a keypair.
///
/// Format: `aegis:ed25519:<hex-pubkey>`
pub fn issuer_from_keypair(keypair: &Keypair) -> String {
    format!("aegis:ed25519:{}", keypair.public_key().to_hex())
}

/// Extract the hex public key from a `aegis:ed25519:<hex>` issuer string.
pub fn parse_issuer_pubkey_hex(issuer: &str) -> Result<String> {
    let prefix = "aegis:ed25519:";
    let rest = issuer
        .strip_prefix(prefix)
        .filter(|s| !s.is_empty())
        .ok_or_else(|| Error::InvalidIssuer(issuer.to_string()))?;
    Ok(rest.to_string())
}

/// Canonical JSON bytes of a value (for hashing / signing).
fn canonical_json_bytes(value: &Value) -> Result<Vec<u8>> {
    let canonical = canonicalize_json(value)?;
    Ok(canonical.into_bytes())
}

/// Compute the bytes that are signed for an envelope.
///
/// The envelope must **not** contain `envelope_hash` or `signature` fields.
pub fn envelope_signing_bytes(envelope_without_hash_and_sig: &Value) -> Result<Vec<u8>> {
    canonical_json_bytes(envelope_without_hash_and_sig)
}

/// Compute the `0x`-prefixed SHA-256 hash hex string of an unsigned envelope.
pub fn compute_envelope_hash_hex(envelope_without_hash_and_sig: &Value) -> Result<String> {
    let bytes = envelope_signing_bytes(envelope_without_hash_and_sig)?;
    Ok(sha256_hex(&bytes))
}

/// Compute the SHA-256 [`Hash`] of an unsigned envelope.
pub fn compute_envelope_hash(envelope_without_hash_and_sig: &Value) -> Result<Hash> {
    let bytes = envelope_signing_bytes(envelope_without_hash_and_sig)?;
    Ok(sha256(&bytes))
}

/// Sign an unsigned envelope, returning `(envelope_hash_hex, signature_hex)`.
///
/// Both values are `0x`-prefixed.
pub fn sign_envelope(
    keypair: &Keypair,
    envelope_without_hash_and_sig: &Value,
) -> Result<(String, String)> {
    let bytes = envelope_signing_bytes(envelope_without_hash_and_sig)?;
    let envelope_hash = sha256_hex(&bytes);
    let signature = keypair.sign(&bytes).to_hex_prefixed();
    Ok((envelope_hash, signature))
}

/// Build a complete signed envelope.
pub fn build_signed_envelope(
    keypair: &Keypair,
    seq: u64,
    prev_envelope_hash: Option<String>,
    fact: Value,
    issued_at: String,
) -> Result<Value> {
    let issuer = issuer_from_keypair(keypair);

    let unsigned = json!({
        "schema": ENVELOPE_SCHEMA_V1,
        "issuer": issuer,
        "seq": seq,
        "prev_envelope_hash": prev_envelope_hash,
        "issued_at": issued_at,
        "capability_token": Value::Null,
        "fact": fact,
    });

    let (envelope_hash, signature) = sign_envelope(keypair, &unsigned)?;

    let mut signed = unsigned;
    signed["envelope_hash"] = json!(envelope_hash);
    signed["signature"] = json!(signature);
    Ok(signed)
}

/// Extract the `envelope_hash` string from a raw JSON payload.
pub fn extract_envelope_hash(payload: &[u8]) -> Result<String> {
    let v: Value = serde_json::from_slice(payload)?;
    let hash = v
        .get("envelope_hash")
        .and_then(|h| h.as_str())
        .ok_or(Error::MissingField("envelope_hash"))?;
    Ok(hash.to_string())
}

/// Verify an envelope signature.
///
/// Strips `envelope_hash` and `signature` from the value, recomputes the
/// canonical bytes, and checks the Ed25519 signature against the issuer key.
pub fn verify_envelope(envelope: &Value) -> Result<bool> {
    let issuer = envelope
        .get("issuer")
        .and_then(|v| v.as_str())
        .ok_or(Error::MissingField("issuer"))?;
    let sig_hex = envelope
        .get("signature")
        .and_then(|v| v.as_str())
        .ok_or(Error::MissingField("signature"))?;

    let pubkey_hex = parse_issuer_pubkey_hex(issuer)?;
    let pubkey = hush_core::PublicKey::from_hex(&pubkey_hex)?;
    let signature = hush_core::Signature::from_hex(sig_hex)?;

    // Reconstruct the unsigned envelope by removing hash + sig.
    let mut unsigned = envelope.clone();
    if let Some(obj) = unsigned.as_object_mut() {
        obj.remove("envelope_hash");
        obj.remove("signature");
    }

    let bytes = envelope_signing_bytes(&unsigned)?;
    Ok(pubkey.verify(&bytes, &signature))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn envelope_roundtrip() {
        let kp = Keypair::generate();
        let fact = json!({"type": "policy.update", "data": {"version": 2}});
        let envelope = build_signed_envelope(&kp, 1, None, fact.clone(), now_rfc3339()).unwrap();

        assert_eq!(
            envelope.get("schema").and_then(|v| v.as_str()).unwrap(),
            ENVELOPE_SCHEMA_V1
        );
        assert!(envelope.get("envelope_hash").is_some());
        assert!(envelope.get("signature").is_some());
        assert!(verify_envelope(&envelope).unwrap());
    }

    #[test]
    fn envelope_chain() {
        let kp = Keypair::generate();
        let e1 =
            build_signed_envelope(&kp, 1, None, json!({"type": "init"}), now_rfc3339()).unwrap();
        let h1 = e1
            .get("envelope_hash")
            .and_then(|v| v.as_str())
            .unwrap()
            .to_string();

        let e2 = build_signed_envelope(
            &kp,
            2,
            Some(h1.clone()),
            json!({"type": "step"}),
            now_rfc3339(),
        )
        .unwrap();

        assert_eq!(
            e2.get("prev_envelope_hash")
                .and_then(|v| v.as_str())
                .unwrap(),
            h1
        );
        assert!(verify_envelope(&e2).unwrap());
    }

    #[test]
    fn verify_rejects_tampered_fact() {
        let kp = Keypair::generate();
        let mut envelope =
            build_signed_envelope(&kp, 1, None, json!({"ok": true}), now_rfc3339()).unwrap();

        // tamper
        envelope["fact"] = json!({"ok": false});
        assert!(!verify_envelope(&envelope).unwrap());
    }

    #[test]
    fn issuer_roundtrip() {
        let kp = Keypair::generate();
        let issuer = issuer_from_keypair(&kp);
        let hex = parse_issuer_pubkey_hex(&issuer).unwrap();
        assert_eq!(hex, kp.public_key().to_hex());
    }

    #[test]
    fn parse_issuer_rejects_bad_prefix() {
        assert!(parse_issuer_pubkey_hex("bad:prefix:abc").is_err());
        assert!(parse_issuer_pubkey_hex("aegis:ed25519:").is_err());
    }

    #[test]
    fn extract_envelope_hash_from_json() {
        let payload = serde_json::to_vec(&json!({"envelope_hash": "0xdeadbeef"})).unwrap();
        assert_eq!(extract_envelope_hash(&payload).unwrap(), "0xdeadbeef");
    }
}
