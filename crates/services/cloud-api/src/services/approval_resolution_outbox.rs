//! Durable outbox for cloud -> agent approval resolution delivery.
//!
//! Resolving an approval updates DB state immediately and enqueues a publish task.
//! This worker retries pending deliveries until they are acknowledged by NATS.

use std::time::Duration;

use serde_json::Value;
use sqlx::executor::Executor;
use sqlx::row::Row;
use tokio::sync::watch;
use uuid::Uuid;

use crate::db::PgPool;

const CLAIM_DELAY_ON_CRASH_SECS: i64 = 300;
const MAX_BACKOFF_SECS: i64 = 300;

#[derive(Debug, Clone)]
pub struct OutboxEntry {
    pub id: i64,
    pub approval_id: Uuid,
    pub tenant_slug: String,
    pub agent_id: String,
    pub subject: String,
    pub payload: Value,
    pub attempts: i32,
}

pub async fn enqueue(
    executor: impl Executor<'_, Database = sqlx_postgres::Postgres>,
    approval_id: Uuid,
    tenant_id: Uuid,
    tenant_slug: &str,
    agent_id: &str,
    subject: &str,
    payload: &Value,
) -> Result<(), sqlx::error::Error> {
    sqlx::query::query(
        r#"INSERT INTO approval_resolution_outbox (
               approval_id,
               tenant_id,
               tenant_slug,
               agent_id,
               subject,
               payload,
               status,
               attempts,
               next_attempt_at
           )
           VALUES ($1, $2, $3, $4, $5, $6, 'pending', 0, now())
           ON CONFLICT (approval_id) DO UPDATE
           SET tenant_id = EXCLUDED.tenant_id,
               tenant_slug = EXCLUDED.tenant_slug,
               agent_id = EXCLUDED.agent_id,
               subject = EXCLUDED.subject,
               payload = EXCLUDED.payload,
               status = 'pending',
               attempts = 0,
               last_error = NULL,
               sent_at = NULL,
               next_attempt_at = now(),
               updated_at = now()"#,
    )
    .bind(approval_id)
    .bind(tenant_id)
    .bind(tenant_slug)
    .bind(agent_id)
    .bind(subject)
    .bind(payload)
    .execute(executor)
    .await?;

    Ok(())
}

pub async fn process_due_batch(
    nats: &async_nats::Client,
    db: &PgPool,
    batch_size: i64,
) -> Result<usize, sqlx::error::Error> {
    let js = async_nats::jetstream::new(nats.clone());
    let entries = claim_due_entries(db, batch_size).await?;
    if entries.is_empty() {
        return Ok(0);
    }

    let mut sent = 0usize;
    for entry in entries {
        let payload_bytes = match serde_json::to_vec(&entry.payload) {
            Ok(bytes) => bytes,
            Err(err) => {
                tracing::warn!(
                    outbox_id = entry.id,
                    approval_id = %entry.approval_id,
                    error = %err,
                    "Outbox payload serialization failed"
                );
                mark_failed(db, entry.id, entry.attempts, &format!("serialize: {err}")).await?;
                continue;
            }
        };

        let publish_result = js
            .publish(entry.subject.clone(), payload_bytes.into())
            .await;
        match publish_result {
            Ok(ack) => match ack.await {
                Ok(_) => {
                    mark_sent(db, entry.id).await?;
                    sent += 1;
                }
                Err(err) => {
                    tracing::warn!(
                        outbox_id = entry.id,
                        approval_id = %entry.approval_id,
                        tenant = %entry.tenant_slug,
                        agent_id = %entry.agent_id,
                        subject = %entry.subject,
                        attempts = entry.attempts,
                        error = %err,
                        "Approval resolution outbox publish ack failed"
                    );
                    mark_failed(db, entry.id, entry.attempts, &err.to_string()).await?;
                }
            },
            Err(err) => {
                tracing::warn!(
                    outbox_id = entry.id,
                    approval_id = %entry.approval_id,
                    tenant = %entry.tenant_slug,
                    agent_id = %entry.agent_id,
                    subject = %entry.subject,
                    attempts = entry.attempts,
                    error = %err,
                    "Failed to publish approval resolution outbox entry"
                );
                mark_failed(db, entry.id, entry.attempts, &err.to_string()).await?;
            }
        }
    }

    Ok(sent)
}

pub async fn process_due_for_approval(
    nats: &async_nats::Client,
    db: &PgPool,
    approval_id: Uuid,
) -> Result<bool, sqlx::error::Error> {
    let js = async_nats::jetstream::new(nats.clone());
    let Some(entry) = claim_entry_by_approval_id(db, approval_id).await? else {
        return Ok(false);
    };

    let payload_bytes = match serde_json::to_vec(&entry.payload) {
        Ok(bytes) => bytes,
        Err(err) => {
            mark_failed(db, entry.id, entry.attempts, &format!("serialize: {err}")).await?;
            return Ok(false);
        }
    };

    let publish_result = js
        .publish(entry.subject.clone(), payload_bytes.into())
        .await;
    match publish_result {
        Ok(ack) => match ack.await {
            Ok(_) => {
                mark_sent(db, entry.id).await?;
                Ok(true)
            }
            Err(err) => {
                mark_failed(db, entry.id, entry.attempts, &err.to_string()).await?;
                Ok(false)
            }
        },
        Err(err) => {
            mark_failed(db, entry.id, entry.attempts, &err.to_string()).await?;
            Ok(false)
        }
    }
}

pub async fn run(
    nats: async_nats::Client,
    db: PgPool,
    poll_interval: Duration,
    mut shutdown_rx: watch::Receiver<bool>,
) {
    tracing::info!(
        poll_secs = poll_interval.as_secs(),
        "Approval resolution outbox worker started"
    );

    loop {
        tokio::select! {
            _ = shutdown_rx.changed() => {
                if *shutdown_rx.borrow() {
                    tracing::info!("Approval resolution outbox worker shutting down");
                    break;
                }
            }
            _ = tokio::time::sleep(poll_interval) => {
                match process_due_batch(&nats, &db, 50).await {
                    Ok(sent) if sent > 0 => {
                        tracing::info!(sent, "Published approval resolutions from outbox");
                    }
                    Ok(_) => {}
                    Err(err) => {
                        tracing::warn!(error = %err, "Approval resolution outbox batch failed");
                    }
                }
            }
        }
    }
}

async fn claim_due_entries(
    db: &PgPool,
    batch_size: i64,
) -> Result<Vec<OutboxEntry>, sqlx::error::Error> {
    let rows = sqlx::query::query(
        r#"WITH due AS (
               SELECT id
               FROM approval_resolution_outbox
               WHERE status = 'pending'
                 AND next_attempt_at <= now()
               ORDER BY next_attempt_at ASC, id ASC
               LIMIT $1
               FOR UPDATE SKIP LOCKED
           )
           UPDATE approval_resolution_outbox AS o
           SET attempts = o.attempts + 1,
               next_attempt_at = now() + make_interval(secs => $2::int),
               updated_at = now()
           FROM due
           WHERE o.id = due.id
           RETURNING o.id,
                     o.approval_id,
                     o.tenant_slug,
                     o.agent_id,
                     o.subject,
                     o.payload,
                     o.attempts"#,
    )
    .bind(batch_size)
    .bind(CLAIM_DELAY_ON_CRASH_SECS)
    .fetch_all(db)
    .await?;

    rows.into_iter()
        .map(row_to_entry)
        .collect::<Result<Vec<_>, _>>()
}

async fn claim_entry_by_approval_id(
    db: &PgPool,
    approval_id: Uuid,
) -> Result<Option<OutboxEntry>, sqlx::error::Error> {
    let row = sqlx::query::query(
        r#"WITH due AS (
               SELECT id
               FROM approval_resolution_outbox
               WHERE approval_id = $1
                 AND status = 'pending'
                 AND next_attempt_at <= now()
               FOR UPDATE SKIP LOCKED
           )
           UPDATE approval_resolution_outbox AS o
           SET attempts = o.attempts + 1,
               next_attempt_at = now() + make_interval(secs => $2::int),
               updated_at = now()
           FROM due
           WHERE o.id = due.id
           RETURNING o.id,
                     o.approval_id,
                     o.tenant_slug,
                     o.agent_id,
                     o.subject,
                     o.payload,
                     o.attempts"#,
    )
    .bind(approval_id)
    .bind(CLAIM_DELAY_ON_CRASH_SECS)
    .fetch_optional(db)
    .await?;

    row.map(row_to_entry).transpose()
}

async fn mark_sent(db: &PgPool, id: i64) -> Result<(), sqlx::error::Error> {
    sqlx::query::query(
        r#"UPDATE approval_resolution_outbox
           SET status = 'sent',
               sent_at = now(),
               last_error = NULL,
               updated_at = now()
           WHERE id = $1"#,
    )
    .bind(id)
    .execute(db)
    .await?;
    Ok(())
}

async fn mark_failed(
    db: &PgPool,
    id: i64,
    attempts: i32,
    error: &str,
) -> Result<(), sqlx::error::Error> {
    let backoff_secs = compute_backoff_secs(attempts);
    sqlx::query::query(
        r#"UPDATE approval_resolution_outbox
           SET status = 'pending',
               last_error = $2,
               next_attempt_at = now() + make_interval(secs => $3::int),
               updated_at = now()
           WHERE id = $1"#,
    )
    .bind(id)
    .bind(error)
    .bind(backoff_secs)
    .execute(db)
    .await?;
    Ok(())
}

fn compute_backoff_secs(attempts: i32) -> i32 {
    let exp = attempts.max(1).saturating_sub(1) as u32;
    let backoff = 2_i64.saturating_pow(exp);
    backoff.clamp(1, MAX_BACKOFF_SECS) as i32
}

fn row_to_entry(row: sqlx_postgres::PgRow) -> Result<OutboxEntry, sqlx::error::Error> {
    Ok(OutboxEntry {
        id: row.try_get("id")?,
        approval_id: row.try_get("approval_id")?,
        tenant_slug: row.try_get("tenant_slug")?,
        agent_id: row.try_get("agent_id")?,
        subject: row.try_get("subject")?,
        payload: row.try_get("payload")?,
        attempts: row.try_get("attempts")?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn backoff_caps_at_max() {
        assert_eq!(compute_backoff_secs(1), 1);
        assert_eq!(compute_backoff_secs(2), 2);
        assert_eq!(compute_backoff_secs(3), 4);
        assert_eq!(compute_backoff_secs(6), 32);
        assert_eq!(compute_backoff_secs(9), 256);
        assert_eq!(compute_backoff_secs(10), 300);
        assert_eq!(compute_backoff_secs(20), 300);
    }
}
