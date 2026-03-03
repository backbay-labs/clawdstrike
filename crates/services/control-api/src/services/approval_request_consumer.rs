//! JetStream consumer for agent approval request ingestion.
//!
//! Subscribes to tenant-scoped approval request subjects and persists pending
//! requests into the cloud `approvals` table for operator review/resolution.

use serde_json::Value;
use tokio::sync::watch;

use crate::db::PgPool;
#[cfg(test)]
use crate::services::consumer_ack::ack_kind_for_processing_result;
use crate::services::consumer_ack::{acknowledge_after_processing, ProcessingError};

pub async fn run(
    nats: async_nats::Client,
    db: PgPool,
    subject_filter: &str,
    stream_subjects: &[String],
    stream_name: &str,
    consumer_name: &str,
    mut shutdown_rx: watch::Receiver<bool>,
) {
    let js = async_nats::jetstream::new(nats);

    if let Err(err) =
        spine::nats_transport::ensure_stream(&js, stream_name, stream_subjects.to_vec(), 1).await
    {
        tracing::error!(error = %err, "Failed to ensure approval request stream");
        return;
    }

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
        Err(err) => {
            tracing::error!(error = %err, "Failed to create approval request consumer");
            return;
        }
    };

    tracing::info!(
        subject = subject_filter,
        stream = stream_name,
        consumer = consumer_name,
        "Approval request consumer started"
    );

    loop {
        let messages = match consumer.fetch().max_messages(20).messages().await {
            Ok(m) => m,
            Err(err) => {
                tracing::warn!(error = %err, "Failed to fetch approval request messages");
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
                        Some(Err(err)) => {
                            tracing::warn!(error = %err, "Error reading approval request message");
                            continue;
                        }
                        None => break,
                    };

                    acknowledge_after_processing(
                        &msg,
                        process_approval_request_message(&db, &msg).await,
                        "approval request",
                    ).await;
                }
                _ = shutdown_rx.changed() => {
                    if *shutdown_rx.borrow() {
                        tracing::info!("Approval request consumer shutting down");
                        return;
                    }
                }
            }
        }

        if *shutdown_rx.borrow() {
            break;
        }
    }

    tracing::info!("Approval request consumer stopped");
}

async fn process_approval_request_message(
    db: &PgPool,
    msg: &async_nats::jetstream::Message,
) -> Result<(), ProcessingError> {
    let subject = msg.subject.to_string();
    let (tenant_slug, agent_id) = parse_approval_subject(&subject).ok_or_else(|| {
        ProcessingError::permanent(format!(
            "subject does not match approval request pattern: {subject}"
        ))
    })?;

    let payload = parse_request_payload(&msg.payload)?;

    let result = sqlx::query::query(
        r#"INSERT INTO approvals (tenant_id, agent_id, request_id, event_type, event_data, status)
           SELECT t.id, $2, $3, $4, $5, 'pending'
           FROM tenants AS t
           WHERE t.slug = $1
           ON CONFLICT (tenant_id, request_id) DO NOTHING"#,
    )
    .bind(tenant_slug)
    .bind(agent_id)
    .bind(payload.request_id)
    .bind(payload.event_type)
    .bind(payload.event_data)
    .execute(db)
    .await
    .map_err(|err| ProcessingError::retryable(err.to_string()))?;

    if result.rows_affected() == 0 {
        tracing::debug!(
            subject = %subject,
            "Approval request insert was a duplicate or tenant slug was not found"
        );
    }

    Ok(())
}

#[derive(Debug)]
struct ApprovalRequestPayload {
    request_id: String,
    event_type: String,
    event_data: Value,
}

fn parse_request_payload(payload: &[u8]) -> Result<ApprovalRequestPayload, ProcessingError> {
    let raw: Value = serde_json::from_slice(payload)
        .map_err(|err| ProcessingError::permanent(err.to_string()))?;
    let decoded = decode_signed_or_plain_payload(raw)?;

    let request_id = decoded
        .get("request_id")
        .and_then(|v| v.as_str())
        .ok_or_else(|| ProcessingError::permanent("approval request payload missing request_id"))?
        .to_string();

    let event_type = decoded
        .get("event_type")
        .and_then(|v| v.as_str())
        .unwrap_or("approval.request")
        .to_string();

    let event_data = decoded.get("event_data").cloned().unwrap_or_else(|| {
        serde_json::json!({
            "tool": decoded.get("tool").cloned().unwrap_or(Value::Null),
            "resource": decoded.get("resource").cloned().unwrap_or(Value::Null),
            "guard": decoded.get("guard").cloned().unwrap_or(Value::Null),
            "reason": decoded.get("reason").cloned().unwrap_or(Value::Null),
            "severity": decoded.get("severity").cloned().unwrap_or(Value::Null),
            "session_id": decoded.get("session_id").cloned().unwrap_or(Value::Null),
            "created_at": decoded.get("created_at").cloned().unwrap_or(Value::Null),
            "expires_at": decoded.get("expires_at").cloned().unwrap_or(Value::Null),
        })
    });

    Ok(ApprovalRequestPayload {
        request_id,
        event_type,
        event_data,
    })
}

fn decode_signed_or_plain_payload(raw: Value) -> Result<Value, ProcessingError> {
    let envelope = if raw.get("replayed").and_then(|v| v.as_bool()) == Some(true) {
        raw.get("envelope")
            .cloned()
            .ok_or_else(|| ProcessingError::permanent("replayed payload missing envelope"))?
    } else {
        raw
    };

    if envelope.get("fact").is_none() {
        return Ok(envelope);
    }

    match spine::verify_envelope(&envelope) {
        Ok(true) => {}
        Ok(false) => {
            return Err(ProcessingError::permanent(
                "signed approval request envelope verification failed",
            ))
        }
        Err(err) => {
            return Err(ProcessingError::permanent(format!(
                "signed approval request envelope verification error: {err}"
            )))
        }
    }

    envelope
        .get("fact")
        .cloned()
        .ok_or_else(|| ProcessingError::permanent("signed approval request missing fact"))
}

/// Parse `<tenant-prefix>.approval.request.<agent-id>` where
/// `<tenant-prefix>` is `tenant-<slug>.clawdstrike`.
fn parse_approval_subject(subject: &str) -> Option<(&str, &str)> {
    let (tenant_prefix, agent_id) = subject.rsplit_once(".approval.request.")?;
    if agent_id.is_empty() {
        return None;
    }

    let tenant_slug = tenant_prefix
        .strip_prefix("tenant-")?
        .strip_suffix(".clawdstrike")?;
    if tenant_slug.is_empty() {
        return None;
    }

    Some((tenant_slug, agent_id))
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;
    use hush_core::Keypair;
    use spine::envelope::{build_signed_envelope, now_rfc3339};

    #[test]
    fn parse_approval_subject_supports_dotted_slugs() {
        let parsed = parse_approval_subject("tenant-acme.dev.clawdstrike.approval.request.agent-1");
        assert_eq!(parsed, Some(("acme.dev", "agent-1")));
    }

    #[test]
    fn parse_request_payload_accepts_plain_payload() {
        let payload = serde_json::json!({
            "request_id": "req-1",
            "event_type": "approval.request",
            "event_data": { "tool": "shell.exec" }
        });
        let parsed = parse_request_payload(&serde_json::to_vec(&payload).unwrap()).unwrap();
        assert_eq!(parsed.request_id, "req-1");
        assert_eq!(parsed.event_type, "approval.request");
        assert_eq!(parsed.event_data["tool"], "shell.exec");
    }

    #[test]
    fn parse_request_payload_accepts_signed_envelope() {
        let kp = Keypair::generate();
        let envelope = build_signed_envelope(
            &kp,
            1,
            None,
            serde_json::json!({
                "request_id": "req-2",
                "event_type": "approval.request",
                "event_data": { "tool": "fs.write" }
            }),
            now_rfc3339(),
        )
        .unwrap();

        let parsed = parse_request_payload(&serde_json::to_vec(&envelope).unwrap()).unwrap();
        assert_eq!(parsed.request_id, "req-2");
        assert_eq!(parsed.event_data["tool"], "fs.write");
    }

    #[test]
    fn ack_kind_tracks_processing_outcome() {
        assert!(matches!(
            ack_kind_for_processing_result(&Ok::<(), ProcessingError>(())),
            async_nats::jetstream::AckKind::Ack
        ));
        assert!(matches!(
            ack_kind_for_processing_result(&Err(ProcessingError::retryable("boom"))),
            async_nats::jetstream::AckKind::Nak(None)
        ));
        assert!(matches!(
            ack_kind_for_processing_result(&Err(ProcessingError::permanent("bad subject"))),
            async_nats::jetstream::AckKind::Term
        ));
    }
}
