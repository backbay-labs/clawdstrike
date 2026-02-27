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
    // Reuse the SpinePublisher's long-lived JetStream context instead of
    // creating a new NATS connection per request.
    let publisher = state.spine_publisher.as_ref().ok_or_else(|| {
        V1Error::bad_request(
            "SPINE_DISABLED",
            "Spine publisher is not enabled".to_string(),
        )
    })?;
    let js = publisher.jetstream();
    let subject = format!("{}.receipts.eval", publisher.subject_prefix());

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
                match js
                    .publish(subject.clone(), payload.into())
                    .await
                    .map_err(|e| anyhow::anyhow!("JetStream publish error: {e}"))
                {
                    Ok(ack_future) => match ack_future.await {
                        Ok(_) => accepted += 1,
                        Err(e) => {
                            rejected += 1;
                            errors.push(format!("JetStream ack error: {e}"));
                        }
                    },
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
