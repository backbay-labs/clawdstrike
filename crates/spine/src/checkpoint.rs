//! Checkpoint statements and witness co-signatures.
//!
//! Adapted from `aegisnet::checkpoint`, using [`hush_core`] for crypto.

use hush_core::{canonicalize_json, sha256, Hash, Keypair, PublicKey, Signature};
use serde_json::{json, Value};

use crate::envelope::parse_issuer_pubkey_hex;
use crate::error::{Error, Result};

/// Schema identifier for v1 checkpoint statements.
pub const CHECKPOINT_STATEMENT_SCHEMA_V1: &str = "aegis.spine.checkpoint_statement.v1";

/// Build an unsigned checkpoint statement.
pub fn checkpoint_statement(
    log_id: &str,
    checkpoint_seq: u64,
    prev_checkpoint_hash: Option<String>,
    merkle_root: String,
    tree_size: u64,
    issued_at: String,
) -> Value {
    json!({
        "schema": CHECKPOINT_STATEMENT_SCHEMA_V1,
        "log_id": log_id,
        "checkpoint_seq": checkpoint_seq,
        "prev_checkpoint_hash": prev_checkpoint_hash,
        "merkle_root": merkle_root,
        "tree_size": tree_size,
        "issued_at": issued_at,
    })
}

/// Compute the SHA-256 hash of a canonical checkpoint statement.
pub fn checkpoint_hash(statement: &Value) -> Result<Hash> {
    let canonical = canonicalize_json(statement)?;
    Ok(sha256(canonical.as_bytes()))
}

/// Build the domain-separated message that witnesses sign.
///
/// Format: `b"AegisNetCheckpointHashV1" || 0x00 || checkpoint_hash`
pub fn checkpoint_witness_message(cp_hash: &Hash) -> Vec<u8> {
    let tag = b"AegisNetCheckpointHashV1";
    let mut msg = Vec::with_capacity(tag.len() + 1 + 32);
    msg.extend_from_slice(tag);
    msg.push(0x00);
    msg.extend_from_slice(cp_hash.as_bytes());
    msg
}

/// Sign a checkpoint statement, returning a witness-signature JSON object.
pub fn sign_checkpoint_statement(keypair: &Keypair, statement: &Value) -> Result<Value> {
    let hash = checkpoint_hash(statement)?;
    let msg = checkpoint_witness_message(&hash);
    let signature = keypair.sign(&msg).to_hex_prefixed();
    let witness_node_id = crate::envelope::issuer_from_keypair(keypair);

    Ok(json!({
        "schema": "aegis.spine.witness_signature.v1",
        "witness_node_id": witness_node_id,
        "checkpoint_hash": hash.to_hex_prefixed(),
        "signature": signature,
    }))
}

/// Verify a witness signature against a checkpoint statement.
pub fn verify_witness_signature(
    statement: &Value,
    witness_node_id: &str,
    signature_hex: &str,
) -> Result<bool> {
    let pubkey_hex = parse_issuer_pubkey_hex(witness_node_id)?;
    let pubkey = PublicKey::from_hex(&pubkey_hex)?;
    let signature =
        Signature::from_hex(signature_hex).map_err(|_| Error::InvalidWitnessSignature)?;

    let hash = checkpoint_hash(statement)?;
    let msg = checkpoint_witness_message(&hash);
    Ok(pubkey.verify(&msg, &signature))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::envelope::{issuer_from_keypair, now_rfc3339};

    #[test]
    fn checkpoint_sign_verify() {
        let kp = Keypair::generate();
        let root = hush_core::sha256(b"some-tree-root").to_hex_prefixed();
        let stmt = checkpoint_statement("log-1", 1, None, root, 42, now_rfc3339());

        let witness = sign_checkpoint_statement(&kp, &stmt).unwrap();
        let witness_id = witness
            .get("witness_node_id")
            .and_then(|v| v.as_str())
            .unwrap();
        let sig = witness.get("signature").and_then(|v| v.as_str()).unwrap();

        assert!(verify_witness_signature(&stmt, witness_id, sig).unwrap());
    }

    #[test]
    fn checkpoint_rejects_wrong_witness() {
        let kp = Keypair::generate();
        let other_kp = Keypair::generate();
        let root = hush_core::sha256(b"root").to_hex_prefixed();
        let stmt = checkpoint_statement("log-1", 1, None, root, 10, now_rfc3339());

        let witness = sign_checkpoint_statement(&kp, &stmt).unwrap();
        let sig = witness.get("signature").and_then(|v| v.as_str()).unwrap();

        // Use the wrong node ID (different key)
        let wrong_id = issuer_from_keypair(&other_kp);
        assert!(!verify_witness_signature(&stmt, &wrong_id, sig).unwrap());
    }

    #[test]
    fn checkpoint_rejects_tampered_statement() {
        let kp = Keypair::generate();
        let root = hush_core::sha256(b"root").to_hex_prefixed();
        let stmt = checkpoint_statement("log-1", 1, None, root, 10, now_rfc3339());

        let witness = sign_checkpoint_statement(&kp, &stmt).unwrap();
        let witness_id = witness
            .get("witness_node_id")
            .and_then(|v| v.as_str())
            .unwrap();
        let sig = witness.get("signature").and_then(|v| v.as_str()).unwrap();

        // Tamper with the statement
        let tampered =
            checkpoint_statement("log-1", 1, None, "0xbad".to_string(), 10, now_rfc3339());
        assert!(!verify_witness_signature(&tampered, witness_id, sig).unwrap());
    }

    #[test]
    fn checkpoint_hash_is_deterministic() {
        let root = hush_core::sha256(b"root").to_hex_prefixed();
        let stmt = checkpoint_statement(
            "log-1",
            1,
            None,
            root,
            10,
            "2026-01-01T00:00:00Z".to_string(),
        );
        let h1 = checkpoint_hash(&stmt).unwrap();
        let h2 = checkpoint_hash(&stmt).unwrap();
        assert_eq!(h1, h2);
    }
}
