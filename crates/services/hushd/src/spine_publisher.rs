//! Spine envelope publisher for eval receipt attestation.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use anyhow::Result;
use serde_json::{json, Value};
use tokio::sync::Mutex;

use hush_core::Keypair;
use spine::envelope::{build_signed_envelope, now_rfc3339};

/// Publishes signed eval-receipt envelopes to a NATS JetStream stream.
///
/// Each envelope is hash-chained to the previous one via `prev_envelope_hash`,
/// forming a tamper-evident log of policy evaluation decisions.
pub struct SpinePublisher {
    js: async_nats::jetstream::Context,
    keypair: Keypair,
    seq: AtomicU64,
    prev_hash: Mutex<Option<String>>,
    subject_prefix: String,
}

fn sanitize_stream_component(input: &str) -> String {
    input
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '-' || c == '_' {
                c
            } else {
                '-'
            }
        })
        .collect()
}

fn receipts_stream_name(subject_prefix: &str) -> String {
    format!("{}-receipts", sanitize_stream_component(subject_prefix))
}

impl SpinePublisher {
    /// Create a new publisher and ensure the receipts stream exists.
    pub async fn new(
        js: async_nats::jetstream::Context,
        keypair: Keypair,
        subject_prefix: String,
    ) -> Result<Self> {
        spine::nats_transport::ensure_stream(
            &js,
            &receipts_stream_name(&subject_prefix),
            vec![format!("{subject_prefix}.receipts.>")],
            1,
        )
        .await
        .map_err(|e| anyhow::anyhow!("Failed to ensure spine receipts stream: {e}"))?;

        Ok(Self {
            js,
            keypair,
            seq: AtomicU64::new(1),
            prev_hash: Mutex::new(None),
            subject_prefix,
        })
    }

    /// Get a reference to the JetStream context for reuse by other handlers.
    pub fn jetstream(&self) -> &async_nats::jetstream::Context {
        &self.js
    }

    /// Get the subject prefix.
    pub fn subject_prefix(&self) -> &str {
        &self.subject_prefix
    }

    /// Publish an eval receipt as a signed envelope to JetStream.
    pub async fn publish_eval_receipt(
        &self,
        decision: &Value,
        event: &Value,
        policy_ref: &str,
        session_id: Option<&str>,
    ) -> Result<()> {
        // Hold the lock for the entire build→publish→update cycle to prevent
        // concurrent calls from reading the same prev_hash (broken chain).
        let mut prev_hash_guard = self.prev_hash.lock().await;

        let seq = self.seq.fetch_add(1, Ordering::SeqCst);

        let fact = json!({
            "type": "policy.eval",
            "decision": decision,
            "event_type": event.get("eventType").or_else(|| event.get("event_type")),
            "event_id": event.get("eventId").or_else(|| event.get("event_id")),
            "policy_ref": policy_ref,
            "session_id": session_id,
        });

        let envelope = build_signed_envelope(
            &self.keypair,
            seq,
            prev_hash_guard.clone(),
            fact,
            now_rfc3339(),
        )
        .map_err(|e| anyhow::anyhow!("Failed to build signed envelope: {e}"))?;

        let hash = envelope
            .get("envelope_hash")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string())
            .ok_or_else(|| anyhow::anyhow!("envelope missing envelope_hash"))?;

        let subject = format!("{}.receipts.eval", self.subject_prefix);
        let payload = serde_json::to_vec(&envelope)?;
        self.js
            .publish(subject, payload.into())
            .await
            .map_err(|e| anyhow::anyhow!("Failed to publish eval receipt: {e}"))?
            .await
            .map_err(|e| anyhow::anyhow!("JetStream ack error: {e}"))?;

        *prev_hash_guard = Some(hash);

        Ok(())
    }
}

/// Connect to NATS using the spine config and return an `Arc<SpinePublisher>`.
///
/// Returns `None` if spine is not enabled.
pub async fn init_spine_publisher(
    config: &crate::config::SpineConfig,
    signing_keypair: &Keypair,
) -> Result<Option<Arc<SpinePublisher>>> {
    if !config.enabled {
        return Ok(None);
    }

    let nats_url = config
        .nats_url
        .as_deref()
        .unwrap_or("nats://127.0.0.1:4222");

    let auth = spine::nats_transport::NatsAuthConfig {
        creds_file: config.creds_file.clone(),
        token: config.token.clone(),
        nkey_seed: config.nkey_seed.clone(),
    };

    let client = spine::nats_transport::connect_with_auth(nats_url, Some(&auth))
        .await
        .map_err(|e| anyhow::anyhow!("Failed to connect to NATS for spine: {e}"))?;

    let js = spine::nats_transport::jetstream(client);

    let keypair = if let Some(ref path) = config.keypair_path {
        let key_hex = std::fs::read_to_string(path)?.trim().to_string();
        Keypair::from_hex(&key_hex)?
    } else {
        signing_keypair.clone()
    };

    let publisher = SpinePublisher::new(js, keypair, config.subject_prefix.clone()).await?;

    tracing::info!(
        nats_url = nats_url,
        prefix = %config.subject_prefix,
        "Spine publisher initialized"
    );

    Ok(Some(Arc::new(publisher)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use hush_core::Keypair;

    #[test]
    fn sequence_counter_increments() {
        let seq = AtomicU64::new(1);
        assert_eq!(seq.fetch_add(1, Ordering::SeqCst), 1);
        assert_eq!(seq.fetch_add(1, Ordering::SeqCst), 2);
        assert_eq!(seq.fetch_add(1, Ordering::SeqCst), 3);
    }

    #[test]
    fn fact_json_structure() {
        let decision = json!({"allowed": true});
        let event = json!({"eventType": "file_read", "eventId": "evt-1"});

        let fact = json!({
            "type": "policy.eval",
            "decision": &decision,
            "event_type": event.get("eventType").or_else(|| event.get("event_type")),
            "event_id": event.get("eventId").or_else(|| event.get("event_id")),
            "policy_ref": "default",
            "session_id": Some("sess-1"),
        });

        assert_eq!(fact["type"], "policy.eval");
        assert_eq!(fact["event_type"], "file_read");
        assert_eq!(fact["event_id"], "evt-1");
        assert_eq!(fact["policy_ref"], "default");
    }

    #[test]
    fn envelope_chain_linking() {
        let kp = Keypair::generate();
        let fact1 = json!({"type": "policy.eval", "decision": {"allowed": true}});
        let fact2 = json!({"type": "policy.eval", "decision": {"allowed": false}});

        let e1 = build_signed_envelope(&kp, 1, None, fact1, now_rfc3339()).unwrap();
        let h1 = e1
            .get("envelope_hash")
            .and_then(|v| v.as_str())
            .unwrap()
            .to_string();

        let e2 = build_signed_envelope(&kp, 2, Some(h1.clone()), fact2, now_rfc3339()).unwrap();
        assert_eq!(
            e2.get("prev_envelope_hash")
                .and_then(|v| v.as_str())
                .unwrap(),
            h1
        );

        assert!(spine::verify_envelope(&e1).unwrap());
        assert!(spine::verify_envelope(&e2).unwrap());
    }

    #[test]
    fn receipts_stream_name_is_jetstream_safe() {
        assert_eq!(
            receipts_stream_name("tenant-desktop-dev.clawdstrike"),
            "tenant-desktop-dev-clawdstrike-receipts"
        );
    }
}
