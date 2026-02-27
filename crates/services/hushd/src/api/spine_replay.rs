//! Receipts replay endpoint — re-publishes signed envelopes to Spine JetStream.

use axum::{extract::State, Json};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::api::v1::V1Error;
use crate::state::AppState;

#[derive(Debug, Deserialize)]
pub struct ReplayRequest {
    pub envelopes: Vec<Value>,
}

#[derive(Debug, Serialize)]
pub struct ReplayResponse {
    pub accepted: usize,
    pub rejected: usize,
    pub errors: Vec<String>,
}

/// POST /api/v1/receipts/replay
///
/// Accepts an array of signed envelopes, verifies each, tags with `replayed: true`,
/// and re-publishes to the Spine JetStream receipts stream.
pub async fn replay_receipts(
    State(state): State<AppState>,
    Json(req): Json<ReplayRequest>,
) -> Result<Json<ReplayResponse>, V1Error> {
    // Gate: spine must be enabled.
    if state.spine_publisher.is_none() {
        return Err(V1Error::bad_request(
            "SPINE_DISABLED",
            "Spine publisher is not enabled".to_string(),
        ));
    }

    let nats_url = state
        .config
        .spine
        .nats_url
        .as_deref()
        .unwrap_or("nats://127.0.0.1:4222");

    let subject = format!("{}.receipts.eval", state.config.spine.subject_prefix);

    let mut accepted = 0usize;
    let mut rejected = 0usize;
    let mut errors = Vec::new();

    for envelope in &req.envelopes {
        // Verify the envelope signature and hash integrity.
        match spine::verify_envelope(envelope) {
            Ok(true) => {}
            Ok(false) => {
                rejected += 1;
                errors.push("Envelope signature verification failed".to_string());
                continue;
            }
            Err(e) => {
                rejected += 1;
                errors.push(format!("Envelope verification error: {e}"));
                continue;
            }
        }

        // Wrap the original envelope in a replay container so the signature
        // remains valid — downstream consumers verify the inner envelope.
        let wrapper = serde_json::json!({
            "replayed": true,
            "envelope": envelope,
        });

        match serde_json::to_vec(&wrapper) {
            Ok(payload) => {
                // Replay is a low-frequency admin operation, so a one-off NATS
                // connection per request is acceptable.
                match connect_and_publish(nats_url, &state.config.spine, &subject, payload).await {
                    Ok(()) => accepted += 1,
                    Err(e) => {
                        rejected += 1;
                        errors.push(format!("Publish failed: {e}"));
                    }
                }
            }
            Err(e) => {
                rejected += 1;
                errors.push(format!("Serialization error: {e}"));
            }
        }
    }

    Ok(Json(ReplayResponse {
        accepted,
        rejected,
        errors,
    }))
}

/// Connect to NATS and publish a single message to JetStream.
async fn connect_and_publish(
    nats_url: &str,
    config: &crate::config::SpineConfig,
    subject: &str,
    payload: Vec<u8>,
) -> anyhow::Result<()> {
    let auth = spine::nats_transport::NatsAuthConfig {
        creds_file: config.creds_file.clone(),
        token: config.token.clone(),
        nkey_seed: config.nkey_seed.clone(),
    };

    let client = spine::nats_transport::connect_with_auth(nats_url, Some(&auth))
        .await
        .map_err(|e| anyhow::anyhow!("NATS connect error: {e}"))?;

    let js = spine::nats_transport::jetstream(client);
    js.publish(subject.to_string(), payload.into())
        .await
        .map_err(|e| anyhow::anyhow!("JetStream publish error: {e}"))?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use hush_core::Keypair;
    use serde_json::json;
    use spine::envelope::{build_signed_envelope, now_rfc3339};

    #[test]
    fn valid_envelope_passes_verification() {
        let kp = Keypair::generate();
        let envelope =
            build_signed_envelope(&kp, 1, None, json!({"type": "policy.eval"}), now_rfc3339())
                .unwrap();
        assert!(spine::verify_envelope(&envelope).unwrap());
    }

    #[test]
    fn tampered_envelope_fails_verification() {
        let kp = Keypair::generate();
        let mut envelope =
            build_signed_envelope(&kp, 1, None, json!({"type": "policy.eval"}), now_rfc3339())
                .unwrap();
        envelope["fact"] = json!({"type": "tampered"});
        assert!(spine::verify_envelope(&envelope).is_err());
    }

    #[test]
    fn replay_wraps_envelope_preserving_signature() {
        let kp = Keypair::generate();
        let envelope =
            build_signed_envelope(&kp, 1, None, json!({"type": "policy.eval"}), now_rfc3339())
                .unwrap();
        let wrapper = json!({
            "replayed": true,
            "envelope": envelope,
        });
        assert_eq!(wrapper["replayed"], true);
        // Inner envelope is untouched — signature remains valid.
        assert!(spine::verify_envelope(&wrapper["envelope"]).unwrap());
    }
}
