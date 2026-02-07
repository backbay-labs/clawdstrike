//! NATS subscription for AegisNet checkpoint envelopes.
//!
//! Subscribes to the checkpoint subject on NATS and feeds incoming
//! envelopes into the attestation batcher.

use futures::StreamExt;

use crate::batcher::{AttestationBatcher, PendingAttestation};
use crate::config::AnchorConfig;
use crate::eas_client::EasClient;
use crate::error::{Error, Result};
use std::time::Instant;

/// Parse a 0x-prefixed hex string into a 32-byte array.
fn parse_hex_bytes32(hex_str: &str) -> Result<[u8; 32]> {
    let stripped = hex_str.strip_prefix("0x").unwrap_or(hex_str);
    let bytes =
        hex::decode(stripped).map_err(|e| Error::Parse(format!("Invalid hex string: {e}")))?;
    if bytes.len() != 32 {
        return Err(Error::Parse(format!(
            "Expected 32 bytes, got {}",
            bytes.len()
        )));
    }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&bytes);
    Ok(arr)
}

/// Extract a u64 from a JSON value, returning an error if missing or invalid.
fn extract_u64(value: &serde_json::Value, field: &str) -> Result<u64> {
    value
        .get(field)
        .and_then(|v| v.as_u64())
        .ok_or_else(|| Error::Parse(format!("Missing or invalid field: {field}")))
}

/// Extract a hex bytes32 from a JSON value, returning an error if missing or invalid.
fn extract_hex_bytes32(value: &serde_json::Value, field: &str) -> Result<[u8; 32]> {
    let hex_str = value
        .get(field)
        .and_then(|v| v.as_str())
        .ok_or_else(|| Error::Parse(format!("Missing or invalid field: {field}")))?;
    parse_hex_bytes32(hex_str)
}

/// Parse a NATS message payload into a `PendingAttestation`.
pub fn parse_checkpoint_envelope(payload: &[u8]) -> Result<PendingAttestation> {
    let envelope: serde_json::Value = serde_json::from_slice(payload)
        .map_err(|e| Error::Parse(format!("Invalid JSON envelope: {e}")))?;

    let fact = envelope
        .get("fact")
        .ok_or_else(|| Error::Parse("Missing 'fact' field in envelope".into()))?;

    Ok(PendingAttestation {
        checkpoint_hash: extract_hex_bytes32(fact, "checkpoint_hash")?,
        checkpoint_seq: extract_u64(fact, "checkpoint_seq")?,
        tree_size: extract_u64(fact, "tree_size")?,
        log_operator_key: extract_hex_bytes32(fact, "log_operator_key")?,
        witness_key: extract_hex_bytes32(fact, "witness_key")?,
        received_at: Instant::now(),
    })
}

/// Run the NATS subscription loop, feeding checkpoint envelopes into the
/// batcher and submitting batches via the EAS client.
pub async fn run_subscription(config: &AnchorConfig, client: &EasClient) -> Result<()> {
    let nats_client = async_nats::connect(&config.nats.url)
        .await
        .map_err(|e| Error::Nats(format!("Failed to connect to NATS: {e}")))?;

    let mut subscriber = nats_client
        .subscribe(config.nats.subject.clone())
        .await
        .map_err(|e| Error::Nats(format!("Failed to subscribe: {e}")))?;

    tracing::info!(
        subject = %config.nats.subject,
        nats_url = %config.nats.url,
        "Subscribed to checkpoint envelopes"
    );

    let batch_interval = std::time::Duration::from_secs(config.batching.batch_interval_secs);
    let mut batcher = AttestationBatcher::new(config.batching.max_batch_size, batch_interval);

    loop {
        let timeout = batcher.time_until_flush();
        let msg = tokio::time::timeout(timeout, subscriber.next()).await;

        match msg {
            Ok(Some(nats_msg)) => match parse_checkpoint_envelope(&nats_msg.payload) {
                Ok(attestation) => {
                    tracing::debug!(
                        seq = attestation.checkpoint_seq,
                        tree_size = attestation.tree_size,
                        "Received checkpoint envelope"
                    );
                    batcher.add(attestation);
                }
                Err(e) => {
                    tracing::warn!(error = %e, "Failed to parse checkpoint envelope");
                    continue;
                }
            },
            Ok(None) => {
                tracing::info!("NATS subscription closed");
                break;
            }
            Err(_) => {
                // Timeout — check if we should flush
            }
        }

        if batcher.should_flush() && !batcher.is_empty() {
            let batch = batcher.drain();
            let count = batch.len();
            match client.submit_batch(&batch).await {
                Ok(result) => {
                    tracing::info!(
                        count = result.count,
                        tx_hash = %result.tx_hash,
                        "Submitted attestation batch"
                    );
                }
                Err(e) => {
                    tracing::error!(count = count, error = %e, "Failed to submit batch");
                    // In production, we would re-queue the batch items.
                    // For now, log and continue.
                }
            }
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_valid_checkpoint_envelope() {
        let payload = serde_json::json!({
            "schema": "aegis.spine.envelope.v1",
            "issuer": "aegis:ed25519:abcdef",
            "seq": 42,
            "fact": {
                "checkpoint_hash": "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                "checkpoint_seq": 100,
                "tree_size": 5000,
                "log_operator_key": "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
                "witness_key": "0xcccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
            }
        });
        let bytes = serde_json::to_vec(&payload).unwrap_or_else(|e| panic!("json: {e}"));
        let att = parse_checkpoint_envelope(&bytes);
        assert!(att.is_ok(), "parse failed: {att:?}");
        let att = att.unwrap_or_else(|e| panic!("parse failed: {e}"));
        assert_eq!(att.checkpoint_seq, 100);
        assert_eq!(att.tree_size, 5000);
        assert_eq!(att.checkpoint_hash, [0xAA; 32]);
        assert_eq!(att.log_operator_key, [0xBB; 32]);
        assert_eq!(att.witness_key, [0xCC; 32]);
    }

    #[test]
    fn parse_envelope_without_0x_prefix() {
        let payload = serde_json::json!({
            "fact": {
                "checkpoint_hash": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                "checkpoint_seq": 1,
                "tree_size": 10,
                "log_operator_key": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
                "witness_key": "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
            }
        });
        let bytes = serde_json::to_vec(&payload).unwrap_or_else(|e| panic!("json: {e}"));
        let att = parse_checkpoint_envelope(&bytes).unwrap_or_else(|e| panic!("parse failed: {e}"));
        assert_eq!(att.checkpoint_hash, [0xAA; 32]);
    }

    #[test]
    fn parse_envelope_missing_fact() {
        let payload = serde_json::json!({
            "schema": "aegis.spine.envelope.v1"
        });
        let bytes = serde_json::to_vec(&payload).unwrap_or_else(|e| panic!("json: {e}"));
        let err = parse_checkpoint_envelope(&bytes).expect_err("should fail without fact");
        assert!(err.to_string().contains("fact"));
    }

    #[test]
    fn parse_envelope_missing_checkpoint_hash() {
        let payload = serde_json::json!({
            "fact": {
                "checkpoint_seq": 1,
                "tree_size": 10,
                "log_operator_key": "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
                "witness_key": "0xcccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
            }
        });
        let bytes = serde_json::to_vec(&payload).unwrap_or_else(|e| panic!("json: {e}"));
        let err =
            parse_checkpoint_envelope(&bytes).expect_err("should fail without checkpoint_hash");
        assert!(err.to_string().contains("checkpoint_hash"));
    }

    #[test]
    fn parse_envelope_invalid_hex() {
        let payload = serde_json::json!({
            "fact": {
                "checkpoint_hash": "0xZZZZ",
                "checkpoint_seq": 1,
                "tree_size": 10,
                "log_operator_key": "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
                "witness_key": "0xcccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
            }
        });
        let bytes = serde_json::to_vec(&payload).unwrap_or_else(|e| panic!("json: {e}"));
        let err = parse_checkpoint_envelope(&bytes).expect_err("should fail with invalid hex");
        assert!(err.to_string().contains("hex"));
    }

    #[test]
    fn parse_envelope_wrong_length_hash() {
        let payload = serde_json::json!({
            "fact": {
                "checkpoint_hash": "0xaabb",
                "checkpoint_seq": 1,
                "tree_size": 10,
                "log_operator_key": "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
                "witness_key": "0xcccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
            }
        });
        let bytes = serde_json::to_vec(&payload).unwrap_or_else(|e| panic!("json: {e}"));
        let err = parse_checkpoint_envelope(&bytes).expect_err("should fail with wrong length");
        assert!(err.to_string().contains("32 bytes"));
    }

    #[test]
    fn parse_hex_bytes32_valid() {
        let result =
            parse_hex_bytes32("0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
        assert!(result.is_ok());
        assert_eq!(result.unwrap_or([0; 32]), [0xAA; 32]);
    }

    #[test]
    fn parse_hex_bytes32_no_prefix() {
        let result =
            parse_hex_bytes32("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb");
        assert!(result.is_ok());
        assert_eq!(result.unwrap_or([0; 32]), [0xBB; 32]);
    }

    #[test]
    fn parse_invalid_json_payload() {
        let err = parse_checkpoint_envelope(b"not json").expect_err("should fail");
        assert!(err.to_string().contains("JSON"));
    }
}
