//! JetStream consumer for agent heartbeat telemetry.
//!
//! Subscribes to tenant-scoped heartbeat subjects and updates `agents.last_heartbeat_at`
//! so cloud fleet state tracks the same signal the agent is publishing.

use serde_json::Value;
use tokio::sync::watch;

use crate::db::PgPool;
#[cfg(test)]
use crate::services::consumer_ack::ack_kind_for_processing_result;
use crate::services::consumer_ack::{acknowledge_after_processing, ProcessingError};
use crate::services::policy_distribution;

/// Run the heartbeat consumer loop until the shutdown receiver signals.
///
/// `subject_filter` example:
/// `"tenant-*.clawdstrike.agent.heartbeat.*"`.
pub async fn run(
    nats: async_nats::Client,
    db: PgPool,
    subject_filter: &str,
    stream_subjects: &[String],
    stream_name: &str,
    consumer_name: &str,
    mut shutdown_rx: watch::Receiver<bool>,
) {
    let nats_client = nats.clone();
    let js = async_nats::jetstream::new(nats);

    if let Err(err) =
        spine::nats_transport::ensure_stream(&js, stream_name, stream_subjects.to_vec(), 1).await
    {
        tracing::error!(error = %err, "Failed to ensure heartbeat stream");
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
            tracing::error!(error = %err, "Failed to create heartbeat consumer");
            return;
        }
    };

    tracing::info!(
        subject = subject_filter,
        stream = stream_name,
        consumer = consumer_name,
        "Agent heartbeat consumer started"
    );

    loop {
        let messages = match consumer.fetch().max_messages(20).messages().await {
            Ok(m) => m,
            Err(err) => {
                tracing::warn!(error = %err, "Failed to fetch heartbeat messages");
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
                            tracing::warn!(error = %err, "Error reading heartbeat message");
                            continue;
                        }
                        None => break,
                    };

                    acknowledge_after_processing(
                        &msg,
                        process_heartbeat_message(&db, &nats_client, &msg).await,
                        "agent heartbeat",
                    ).await;
                }
                _ = shutdown_rx.changed() => {
                    if *shutdown_rx.borrow() {
                        tracing::info!("Agent heartbeat consumer shutting down");
                        return;
                    }
                }
            }
        }

        if *shutdown_rx.borrow() {
            break;
        }
    }

    tracing::info!("Agent heartbeat consumer stopped");
}

async fn process_heartbeat_message(
    db: &PgPool,
    nats: &async_nats::Client,
    msg: &async_nats::jetstream::Message,
) -> Result<(), ProcessingError> {
    let subject = msg.subject.to_string();
    let (tenant_slug, agent_id) = parse_heartbeat_subject(&subject).ok_or_else(|| {
        ProcessingError::permanent(format!(
            "subject does not match heartbeat pattern: {subject}"
        ))
    })?;

    let metadata = heartbeat_metadata(&msg.payload);
    let result = sqlx::query::query(
        r#"UPDATE agents AS a
           SET last_heartbeat_at = now(),
               status = 'active',
               metadata = COALESCE($3, a.metadata)
           FROM tenants AS t
           WHERE t.id = a.tenant_id
             AND t.slug = $1
             AND a.agent_id = $2
             AND a.status IN ('active', 'stale', 'dead')"#,
    )
    .bind(tenant_slug)
    .bind(agent_id)
    .bind(metadata)
    .execute(db)
    .await
    .map_err(|err| ProcessingError::retryable(err.to_string()))?;

    if result.rows_affected() == 0 {
        tracing::debug!(
            subject = %subject,
            "Heartbeat did not match an active/stale/dead agent row"
        );
        return Ok(());
    }

    if let Some(active_policy) =
        policy_distribution::fetch_active_policy_by_tenant_slug(db, tenant_slug)
            .await
            .map_err(|err| ProcessingError::retryable(err.to_string()))?
    {
        if let Err(err) =
            policy_distribution::reconcile_policy_for_agent(nats, &active_policy, agent_id).await
        {
            tracing::warn!(
                error = %err,
                tenant = %tenant_slug,
                agent_id = %agent_id,
                "Heartbeat policy reconciliation failed"
            );
        }
    }

    Ok(())
}

fn heartbeat_metadata(payload: &[u8]) -> Option<Value> {
    serde_json::from_slice(payload).ok()
}

/// Parse `<tenant-prefix>.agent.heartbeat.<agent-id>` where
/// `<tenant-prefix>` is `tenant-<slug>.clawdstrike`.
fn parse_heartbeat_subject(subject: &str) -> Option<(&str, &str)> {
    let (tenant_prefix, agent_id) = subject.rsplit_once(".agent.heartbeat.")?;
    let tenant_slug = tenant_prefix
        .strip_prefix("tenant-")?
        .strip_suffix(".clawdstrike")?;
    if tenant_slug.is_empty() || agent_id.is_empty() {
        return None;
    }

    Some((tenant_slug, agent_id))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_heartbeat_subject_valid() {
        let parsed = parse_heartbeat_subject("tenant-acme.clawdstrike.agent.heartbeat.agent-123");
        assert_eq!(parsed, Some(("acme", "agent-123")));
    }

    #[test]
    fn parse_heartbeat_subject_allows_dotted_slugs() {
        let parsed =
            parse_heartbeat_subject("tenant-acme.dev.clawdstrike.agent.heartbeat.agent-123");
        assert_eq!(parsed, Some(("acme.dev", "agent-123")));
    }

    #[test]
    fn parse_heartbeat_subject_rejects_invalid_shapes() {
        assert!(parse_heartbeat_subject("tenant-acme.clawdstrike.heartbeat.agent-123").is_none());
        assert!(parse_heartbeat_subject("clawdstrike.agent.heartbeat.agent-123").is_none());
        assert!(parse_heartbeat_subject("tenant-.clawdstrike.agent.heartbeat.agent-123").is_none());
        assert!(parse_heartbeat_subject("tenant-acme.clawdstrike.agent.heartbeat").is_none());
    }

    #[test]
    fn heartbeat_metadata_parses_json() {
        let payload = br#"{"posture":"standard","session_id":"sess-1"}"#;
        let json = heartbeat_metadata(payload).expect("metadata should parse");
        assert_eq!(
            json.get("posture").and_then(|v| v.as_str()),
            Some("standard")
        );
    }

    #[test]
    fn heartbeat_metadata_handles_non_json_payload() {
        assert!(heartbeat_metadata(b"not-json").is_none());
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
