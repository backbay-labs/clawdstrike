//! Cloud approval synchronization over NATS.
//!
//! - Publishes local pending approvals to cloud (`approval.request` subjects).
//! - Subscribes to cloud operator resolutions and applies them to the local queue.

use anyhow::Result;
use serde_json::Value;
use std::sync::Arc;
use tokio::sync::broadcast;

use crate::approval::{ApprovalQueue, ApprovalResolution, ApprovalStatusResponse};
use crate::nats_client::NatsClient;
use crate::nats_subjects;

pub struct ApprovalSync {
    nats: Arc<NatsClient>,
    approval_queue: Arc<ApprovalQueue>,
    require_signed_responses: bool,
}

impl ApprovalSync {
    pub fn new(
        nats: Arc<NatsClient>,
        approval_queue: Arc<ApprovalQueue>,
        require_signed_responses: bool,
    ) -> Self {
        Self {
            nats,
            approval_queue,
            require_signed_responses,
        }
    }

    pub async fn start(&self, mut shutdown_rx: broadcast::Receiver<()>) {
        let subject = nats_subjects::approval_response_subject(
            self.nats.subject_prefix(),
            self.nats.agent_id(),
        );
        tracing::info!(subject = %subject, "Starting approval response subscriber");

        let mut subscriber = match self.nats.client().subscribe(subject.clone()).await {
            Ok(sub) => sub,
            Err(err) => {
                tracing::error!(error = %err, "Failed to subscribe to approval response subject");
                return;
            }
        };

        loop {
            tokio::select! {
                _ = shutdown_rx.recv() => {
                    tracing::info!("Approval sync shutting down");
                    break;
                }
                msg = crate::nats_client::subscriber_next(&mut subscriber) => {
                    let Some(msg) = msg else {
                        tracing::warn!("Approval response subscription ended unexpectedly");
                        break;
                    };

                    match parse_resolution_payload(&msg.payload, self.require_signed_responses) {
                        Ok(resolution) => {
                            if let Some(mapped) = map_resolution(&resolution.resolution) {
                                if let Err(err) = self.approval_queue.resolve(&resolution.request_id, mapped).await {
                                    tracing::debug!(
                                        request_id = %resolution.request_id,
                                        error = %err,
                                        "Approval resolution could not be applied locally"
                                    );
                                }
                            } else {
                                tracing::warn!(
                                    request_id = %resolution.request_id,
                                    resolution = %resolution.resolution,
                                    "Unknown approval resolution from cloud"
                                );
                            }
                        }
                        Err(err) => {
                            tracing::warn!(error = %err, "Failed to parse approval response payload");
                        }
                    }
                }
            }
        }
    }
}

/// Publish a local approval request to cloud for operator review.
pub async fn publish_approval_request(
    nats: &NatsClient,
    request: &ApprovalStatusResponse,
) -> Result<()> {
    let subject = nats_subjects::approval_request_subject(nats.subject_prefix(), nats.agent_id());
    let payload = serde_json::json!({
        "request_id": request.id.as_str(),
        "event_type": "approval.request",
        "event_data": {
            "tool": request.tool.as_str(),
            "resource": request.resource.as_str(),
            "guard": request.guard.as_str(),
            "reason": request.reason.as_str(),
            "severity": request.severity.as_str(),
            "created_at": request.created_at.to_rfc3339(),
            "expires_at": request.expires_at.to_rfc3339(),
        }
    });
    let bytes = serde_json::to_vec(&payload)?;
    nats.jetstream()
        .publish(subject, bytes.into())
        .await?
        .await?;
    Ok(())
}

#[derive(Debug)]
struct ApprovalResolutionPayload {
    request_id: String,
    resolution: String,
}

fn parse_resolution_payload(
    payload: &[u8],
    require_signed_responses: bool,
) -> Result<ApprovalResolutionPayload> {
    let raw: Value = serde_json::from_slice(payload)?;
    let decoded = decode_signed_or_plain_payload(raw, require_signed_responses)?;

    let request_id = decoded
        .get("request_id")
        .and_then(|v| v.as_str())
        .ok_or_else(|| anyhow::anyhow!("approval resolution missing request_id"))?
        .to_string();
    let resolution = decoded
        .get("resolution")
        .and_then(|v| v.as_str())
        .ok_or_else(|| anyhow::anyhow!("approval resolution missing resolution"))?
        .to_string();

    Ok(ApprovalResolutionPayload {
        request_id,
        resolution,
    })
}

fn decode_signed_or_plain_payload(raw: Value, require_signed_responses: bool) -> Result<Value> {
    let envelope = if raw.get("replayed").and_then(|v| v.as_bool()) == Some(true) {
        raw.get("envelope")
            .cloned()
            .ok_or_else(|| anyhow::anyhow!("replayed payload missing envelope"))?
    } else {
        raw
    };

    if envelope.get("fact").is_none() {
        if require_signed_responses {
            anyhow::bail!("approval resolution payload must be a signed envelope");
        }
        return Ok(envelope);
    }

    if !spine::verify_envelope(&envelope)? {
        anyhow::bail!("approval resolution signature verification failed");
    }

    envelope
        .get("fact")
        .cloned()
        .ok_or_else(|| anyhow::anyhow!("signed approval resolution missing fact"))
}

fn map_resolution(raw: &str) -> Option<ApprovalResolution> {
    match raw {
        "approved" | "allow_once" | "allow-once" => Some(ApprovalResolution::AllowOnce),
        "denied" | "deny" => Some(ApprovalResolution::Deny),
        "allow_session" | "allow-session" => Some(ApprovalResolution::AllowSession),
        "allow_always" | "allow-always" => Some(ApprovalResolution::AllowAlways),
        _ => None,
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use hush_core::Keypair;
    use spine::envelope::{build_signed_envelope, now_rfc3339};

    #[test]
    fn map_resolution_contract() {
        assert_eq!(
            map_resolution("approved"),
            Some(ApprovalResolution::AllowOnce)
        );
        assert_eq!(map_resolution("denied"), Some(ApprovalResolution::Deny));
        assert!(map_resolution("unknown").is_none());
    }

    #[test]
    fn parse_resolution_payload_accepts_plain_json() {
        let payload = serde_json::json!({
            "request_id": "req-1",
            "resolution": "approved"
        });
        let parsed =
            parse_resolution_payload(&serde_json::to_vec(&payload).unwrap(), false).unwrap();
        assert_eq!(parsed.request_id, "req-1");
        assert_eq!(parsed.resolution, "approved");
    }

    #[test]
    fn parse_resolution_payload_rejects_plain_json_when_signatures_required() {
        let payload = serde_json::json!({
            "request_id": "req-1",
            "resolution": "approved"
        });
        let err = parse_resolution_payload(&serde_json::to_vec(&payload).unwrap(), true).unwrap_err();
        assert!(err
            .to_string()
            .contains("must be a signed envelope"));
    }

    #[test]
    fn parse_resolution_payload_accepts_signed_envelope() {
        let kp = Keypair::generate();
        let envelope = build_signed_envelope(
            &kp,
            1,
            None,
            serde_json::json!({
                "request_id": "req-2",
                "resolution": "denied"
            }),
            now_rfc3339(),
        )
        .unwrap();
        let parsed = parse_resolution_payload(&serde_json::to_vec(&envelope).unwrap(), true).unwrap();
        assert_eq!(parsed.request_id, "req-2");
        assert_eq!(parsed.resolution, "denied");
    }
}
