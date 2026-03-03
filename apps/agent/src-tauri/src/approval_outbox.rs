//! Durable outbox for agent -> cloud approval request publishing.
//!
//! Requests are persisted to disk before publish attempts so transient NATS
//! outages do not permanently drop approval escalations.

use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::VecDeque;
use std::path::Path;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::{broadcast, Mutex};

use crate::approval::ApprovalStatusResponse;
use crate::approval_sync;
use crate::nats_client::NatsClient;

const MAX_QUEUE_SIZE: usize = 2048;
const FLUSH_INTERVAL_SECS: u64 = 5;
const MAX_BACKOFF_SECS: i64 = 300;

#[derive(Debug, Clone, Serialize, Deserialize)]
struct PendingApprovalRequest {
    request: ApprovalStatusResponse,
    queued_at: DateTime<Utc>,
    attempts: u32,
    next_attempt_at: DateTime<Utc>,
    last_error: Option<String>,
}

#[derive(Debug, Default, Serialize, Deserialize)]
struct PersistedOutbox {
    entries: VecDeque<PendingApprovalRequest>,
}

pub struct ApprovalRequestOutbox {
    path: PathBuf,
    entries: Mutex<VecDeque<PendingApprovalRequest>>,
    flush_lock: Mutex<()>,
}

impl ApprovalRequestOutbox {
    pub fn load_default() -> Self {
        Self::load(Self::default_path())
    }

    pub fn load(path: PathBuf) -> Self {
        let entries = match std::fs::read_to_string(&path) {
            Ok(raw) => match serde_json::from_str::<PersistedOutbox>(&raw) {
                Ok(parsed) => parsed.entries,
                Err(err) => {
                    tracing::warn!(
                        error = %err,
                        path = %path.display(),
                        "Failed to parse approval request outbox file; starting empty"
                    );
                    VecDeque::new()
                }
            },
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => VecDeque::new(),
            Err(err) => {
                tracing::warn!(
                    error = %err,
                    path = %path.display(),
                    "Failed to read approval request outbox file; starting empty"
                );
                VecDeque::new()
            }
        };

        Self {
            path,
            entries: Mutex::new(entries),
            flush_lock: Mutex::new(()),
        }
    }

    fn default_path() -> PathBuf {
        crate::settings::get_config_dir().join("approval-request-outbox.json")
    }

    pub async fn enqueue(&self, request: &ApprovalStatusResponse) -> Result<()> {
        let _flush_guard = self.flush_lock.lock().await;
        let mut entries = self.entries.lock().await;

        if entries.iter().any(|entry| entry.request.id == request.id) {
            return Ok(());
        }

        entries.push_back(PendingApprovalRequest {
            request: request.clone(),
            queued_at: Utc::now(),
            attempts: 0,
            next_attempt_at: Utc::now(),
            last_error: None,
        });
        while entries.len() > MAX_QUEUE_SIZE {
            entries.pop_front();
        }

        persist_entries(&self.path, &entries)
    }

    pub async fn flush_due(&self, nats: &NatsClient) -> Result<usize> {
        let _flush_guard = self.flush_lock.lock().await;
        let mut entries = self.entries.lock().await.clone();

        if entries.is_empty() {
            return Ok(0);
        }

        let mut sent = 0usize;
        let mut next_entries = VecDeque::with_capacity(entries.len());
        let now = Utc::now();

        while let Some(mut entry) = entries.pop_front() {
            if entry.next_attempt_at > now {
                next_entries.push_back(entry);
                continue;
            }

            match approval_sync::publish_approval_request(nats, &entry.request).await {
                Ok(()) => {
                    sent += 1;
                }
                Err(err) => {
                    entry.attempts = entry.attempts.saturating_add(1);
                    let backoff_secs = compute_backoff_secs(entry.attempts);
                    entry.next_attempt_at = now
                        .checked_add_signed(chrono::Duration::seconds(backoff_secs))
                        .unwrap_or(DateTime::<Utc>::MAX_UTC);
                    entry.last_error = Some(err.to_string());
                    next_entries.push_back(entry);
                    tracing::warn!(
                        error = %err,
                        "Failed to publish approval request; keeping entry in durable outbox"
                    );
                }
            }
        }

        persist_entries(&self.path, &next_entries)?;
        *self.entries.lock().await = next_entries;

        Ok(sent)
    }

    pub async fn len(&self) -> usize {
        self.entries.lock().await.len()
    }

    pub fn start(self: Arc<Self>, nats: Arc<NatsClient>, mut shutdown_rx: broadcast::Receiver<()>) {
        tokio::spawn(async move {
            loop {
                tokio::select! {
                    _ = shutdown_rx.recv() => {
                        tracing::info!("Approval request outbox worker shutting down");
                        break;
                    }
                    _ = tokio::time::sleep(std::time::Duration::from_secs(FLUSH_INTERVAL_SECS)) => {
                        match self.flush_due(nats.as_ref()).await {
                            Ok(sent) if sent > 0 => {
                                tracing::info!(sent, "Flushed approval request outbox entries");
                            }
                            Ok(_) => {}
                            Err(err) => {
                                tracing::warn!(error = %err, "Approval request outbox flush failed");
                            }
                        }
                    }
                }
            }
        });
    }
}

fn persist_entries(path: &Path, entries: &VecDeque<PendingApprovalRequest>) -> Result<()> {
    let serialized = serde_json::to_string_pretty(&PersistedOutbox {
        entries: entries.clone(),
    })
    .with_context(|| "Failed to serialize approval outbox")?;

    crate::security::fs::write_private_atomic(
        path,
        serialized.as_bytes(),
        "approval request outbox",
    )?;

    Ok(())
}

fn compute_backoff_secs(attempts: u32) -> i64 {
    let exp = attempts.saturating_sub(1);
    let backoff = 2_i64.saturating_pow(exp);
    backoff.clamp(1, MAX_BACKOFF_SECS)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use crate::approval::{ApprovalResolution, ApprovalStatus};

    fn sample_status(id: &str) -> ApprovalStatusResponse {
        ApprovalStatusResponse {
            id: id.to_string(),
            status: ApprovalStatus::Pending,
            resolution: Some(ApprovalResolution::AllowOnce),
            tool: "shell.exec".to_string(),
            resource: "/tmp/file".to_string(),
            guard: "ForbiddenPathGuard".to_string(),
            reason: "test".to_string(),
            severity: "high".to_string(),
            created_at: Utc::now(),
            expires_at: Utc::now(),
            resolved_at: None,
        }
    }

    #[tokio::test]
    async fn enqueue_deduplicates_by_request_id() {
        let path = std::env::temp_dir().join(format!(
            "approval-outbox-test-{}.json",
            uuid::Uuid::new_v4()
        ));
        let outbox = ApprovalRequestOutbox::load(path.clone());

        outbox.enqueue(&sample_status("req-1")).await.unwrap();
        outbox.enqueue(&sample_status("req-1")).await.unwrap();
        assert_eq!(outbox.len().await, 1);

        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn backoff_caps_and_grows_exponentially() {
        assert_eq!(compute_backoff_secs(1), 1);
        assert_eq!(compute_backoff_secs(2), 2);
        assert_eq!(compute_backoff_secs(3), 4);
        assert_eq!(compute_backoff_secs(9), 256);
        assert_eq!(compute_backoff_secs(10), 300);
        assert_eq!(compute_backoff_secs(25), 300);
    }
}
