//! JetStream consumer for Spine eval-receipt envelopes.
//!
//! Subscribes to `<prefix>.receipts.>` on JetStream, verifies each signed
//! envelope, checks hash-chain integrity per issuer, and logs to the audit
//! trail. Chain-break warnings are logged but do not reject messages (offline
//! receipts may arrive out of order).

use std::collections::HashMap;

use serde_json::Value;
use tokio::sync::watch;

/// Run the audit consumer loop until the shutdown receiver signals.
///
/// `subject_filter` is the JetStream subject to subscribe to, e.g.
/// `"spine.receipts.>"`.
pub async fn run(
    nats: async_nats::Client,
    subject_filter: &str,
    stream_name: &str,
    consumer_name: &str,
    mut shutdown_rx: watch::Receiver<bool>,
) {
    let js = async_nats::jetstream::new(nats);

    // Ensure the stream exists (idempotent).
    if let Err(e) =
        spine::nats_transport::ensure_stream(&js, stream_name, vec![subject_filter.to_string()], 1)
            .await
    {
        tracing::error!(error = %e, "Failed to ensure spine receipts stream for audit consumer");
        return;
    }

    // Create or get a durable pull consumer.
    let consumer = match js
        .create_consumer_on_stream(
            async_nats::jetstream::consumer::pull::Config {
                durable_name: Some(consumer_name.to_string()),
                filter_subject: subject_filter.to_string(),
                ..Default::default()
            },
            stream_name,
        )
        .await
    {
        Ok(c) => c,
        Err(e) => {
            tracing::error!(error = %e, "Failed to create JetStream consumer for audit");
            return;
        }
    };

    // Track last seen envelope_hash per issuer for chain integrity checks.
    let mut last_hash_by_issuer: HashMap<String, String> = HashMap::new();

    tracing::info!(
        subject = subject_filter,
        stream = stream_name,
        consumer = consumer_name,
        "Audit consumer started"
    );

    loop {
        // Fetch a batch of messages (max 10 at a time, 5s timeout).
        let messages = match consumer.fetch().max_messages(10).messages().await {
            Ok(m) => m,
            Err(e) => {
                tracing::warn!(error = %e, "Failed to fetch messages from JetStream");
                // Check shutdown before retrying.
                if *shutdown_rx.borrow() {
                    break;
                }
                tokio::time::sleep(std::time::Duration::from_secs(1)).await;
                continue;
            }
        };

        use futures::StreamExt;
        let mut messages = std::pin::pin!(messages);

        loop {
            tokio::select! {
                msg = messages.next() => {
                    let msg = match msg {
                        Some(Ok(m)) => m,
                        Some(Err(e)) => {
                            tracing::warn!(error = %e, "Error reading JetStream message");
                            continue;
                        }
                        None => break, // batch exhausted
                    };

                    process_envelope(&msg.payload, &mut last_hash_by_issuer);

                    if let Err(e) = msg.ack().await {
                        tracing::warn!(error = %e, "Failed to ack JetStream message");
                    }
                }
                _ = shutdown_rx.changed() => {
                    if *shutdown_rx.borrow() {
                        tracing::info!("Audit consumer shutting down");
                        return;
                    }
                }
            }
        }

        // Check shutdown between batches.
        if *shutdown_rx.borrow() {
            break;
        }
    }

    tracing::info!("Audit consumer stopped");
}

/// Process a single raw envelope payload.
fn process_envelope(payload: &[u8], last_hash_by_issuer: &mut HashMap<String, String>) {
    let raw: Value = match serde_json::from_slice(payload) {
        Ok(v) => v,
        Err(e) => {
            tracing::warn!(error = %e, "Failed to parse envelope JSON");
            return;
        }
    };

    // Detect replay wrapper: { "replayed": true, "envelope": { ... } }
    // Unwrap the inner envelope so we verify the original signature.
    let (envelope, replayed) = if raw.get("replayed").and_then(|v| v.as_bool()) == Some(true) {
        match raw.get("envelope") {
            Some(inner) => (inner.clone(), true),
            None => {
                tracing::warn!("Replay wrapper missing inner envelope, skipping");
                return;
            }
        }
    } else {
        (raw, false)
    };

    // Verify signature and hash integrity.
    match spine::verify_envelope(&envelope) {
        Ok(true) => {}
        Ok(false) => {
            tracing::warn!("Envelope signature verification failed, skipping");
            return;
        }
        Err(e) => {
            tracing::warn!(error = %e, "Envelope verification error, skipping");
            return;
        }
    }

    // Extract envelope metadata.
    let issuer = envelope
        .get("issuer")
        .and_then(|v| v.as_str())
        .unwrap_or("unknown");
    let seq = envelope.get("seq").and_then(|v| v.as_u64()).unwrap_or(0);
    let envelope_hash = envelope
        .get("envelope_hash")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    let prev_hash = envelope.get("prev_envelope_hash").and_then(|v| v.as_str());

    // Chain integrity check: verify prev_envelope_hash matches our last recorded hash for this issuer.
    if let Some(prev) = prev_hash {
        if let Some(expected) = last_hash_by_issuer.get(issuer) {
            if expected != prev {
                tracing::warn!(
                    issuer = issuer,
                    seq = seq,
                    expected_prev = %expected,
                    actual_prev = prev,
                    "Chain break detected for issuer (may be caused by out-of-order delivery)"
                );
            }
        }
    }

    // Update last hash for this issuer.
    if !envelope_hash.is_empty() {
        last_hash_by_issuer.insert(issuer.to_string(), envelope_hash.to_string());
    }

    // Extract the fact payload.
    let fact = envelope.get("fact").cloned().unwrap_or(Value::Null);
    let fact_type = fact
        .get("type")
        .and_then(|v| v.as_str())
        .unwrap_or("unknown");

    tracing::info!(
        issuer = issuer,
        seq = seq,
        fact_type = fact_type,
        replayed = replayed,
        "Audit consumer processed envelope"
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use hush_core::Keypair;
    use serde_json::json;
    use spine::envelope::{build_signed_envelope, now_rfc3339};

    #[test]
    fn process_valid_envelope() {
        let kp = Keypair::generate();
        let envelope = build_signed_envelope(
            &kp,
            1,
            None,
            json!({"type": "policy.eval", "decision": {"allowed": true}}),
            now_rfc3339(),
        )
        .unwrap();

        let payload = serde_json::to_vec(&envelope).unwrap();
        let mut last_hashes = HashMap::new();
        process_envelope(&payload, &mut last_hashes);

        let issuer = envelope
            .get("issuer")
            .and_then(|v| v.as_str())
            .unwrap()
            .to_string();
        let hash = envelope
            .get("envelope_hash")
            .and_then(|v| v.as_str())
            .unwrap()
            .to_string();

        assert_eq!(last_hashes.get(&issuer), Some(&hash));
    }

    #[test]
    fn chain_integrity_tracking() {
        let kp = Keypair::generate();
        let e1 = build_signed_envelope(&kp, 1, None, json!({"type": "policy.eval"}), now_rfc3339())
            .unwrap();
        let h1 = e1
            .get("envelope_hash")
            .and_then(|v| v.as_str())
            .unwrap()
            .to_string();

        let e2 = build_signed_envelope(
            &kp,
            2,
            Some(h1.clone()),
            json!({"type": "policy.eval"}),
            now_rfc3339(),
        )
        .unwrap();

        let mut last_hashes = HashMap::new();

        // Process first envelope
        process_envelope(&serde_json::to_vec(&e1).unwrap(), &mut last_hashes);

        let issuer = e1
            .get("issuer")
            .and_then(|v| v.as_str())
            .unwrap()
            .to_string();
        assert_eq!(last_hashes.get(&issuer), Some(&h1));

        // Process second envelope — should chain correctly
        process_envelope(&serde_json::to_vec(&e2).unwrap(), &mut last_hashes);

        let h2 = e2
            .get("envelope_hash")
            .and_then(|v| v.as_str())
            .unwrap()
            .to_string();
        assert_eq!(last_hashes.get(&issuer), Some(&h2));
    }

    #[test]
    fn rejects_invalid_envelope() {
        let payload = serde_json::to_vec(&json!({
            "issuer": "bad",
            "envelope_hash": "fake",
            "signature": "fake",
            "fact": {}
        }))
        .unwrap();

        let mut last_hashes = HashMap::new();
        // Should not crash; should log warning and skip.
        process_envelope(&payload, &mut last_hashes);
        // No hash should be recorded for invalid envelopes.
        assert!(last_hashes.is_empty());
    }

    #[test]
    fn rejects_garbage_json() {
        let payload = b"not valid json";
        let mut last_hashes = HashMap::new();
        process_envelope(payload, &mut last_hashes);
        assert!(last_hashes.is_empty());
    }
}
