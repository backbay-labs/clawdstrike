//! Persistent audit-event outbox.
//!
//! `AuditQueue` buffers audit events on disk while hushd is unreachable
//! and replays them in chronological order once connectivity is restored.
//! Flushes are chunked, idempotent, and survive crashes between batches.

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::{HashSet, VecDeque};
use std::fmt;
use std::path::{Path, PathBuf};
use std::time::Duration;
use tokio::sync::Mutex;

/// Queued audit events for offline mode.
/// Stores events that were generated while hushd was unreachable so they
/// can be uploaded when connectivity is restored.
pub struct AuditQueue {
    pub(super) path: PathBuf,
    pub(super) queue: Mutex<VecDeque<serde_json::Value>>,
    flush_lock: Mutex<()>,
    http_client: reqwest::Client,
}

#[derive(Debug, Default, Serialize, Deserialize)]
pub(super) struct PersistedAuditQueue {
    pub(super) entries: VecDeque<serde_json::Value>,
}

#[derive(Debug, Deserialize)]
struct FlushAuditBatchResponse {
    accepted: usize,
    duplicates: usize,
    rejected: usize,
    #[serde(default)]
    accepted_ids: Vec<String>,
    #[serde(default)]
    duplicate_ids: Vec<String>,
    #[serde(default)]
    rejected_ids: Vec<String>,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct AuditFlushOutcome {
    pub accepted: usize,
    pub duplicates: usize,
    pub rejected: usize,
    pub partial_rejection: bool,
}

#[derive(Debug, Clone)]
pub struct AuditFlushProgressError {
    pub outcome: AuditFlushOutcome,
    pub message: String,
}

impl fmt::Display for AuditFlushProgressError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} (accepted={}, duplicates={}, rejected={})",
            self.message, self.outcome.accepted, self.outcome.duplicates, self.outcome.rejected
        )
    }
}

impl std::error::Error for AuditFlushProgressError {}

pub(super) const MAX_AUDIT_QUEUE_LEN: usize = 10_000;
pub(super) const MAX_AUDIT_BATCH_LEN: usize = 5_000;

fn audit_flush_has_prior_progress(outcome: AuditFlushOutcome) -> bool {
    outcome.accepted > 0 || outcome.duplicates > 0 || outcome.rejected > 0
}

fn audit_flush_progress_error(
    outcome: AuditFlushOutcome,
    message: impl Into<String>,
) -> anyhow::Error {
    AuditFlushProgressError {
        outcome,
        message: message.into(),
    }
    .into()
}

fn audit_queue_path() -> PathBuf {
    crate::settings::get_config_dir().join("audit-outbox.json")
}

fn load_persisted_audit_queue(path: &Path) -> (VecDeque<serde_json::Value>, bool) {
    let raw = match std::fs::read_to_string(path) {
        Ok(raw) => raw,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return (VecDeque::new(), false),
        Err(err) => {
            tracing::warn!(
                error = %err,
                path = %path.display(),
                "Failed to read audit outbox file; starting with empty queue"
            );
            return (VecDeque::new(), false);
        }
    };

    match serde_json::from_str::<PersistedAuditQueue>(&raw) {
        Ok(parsed) => sanitize_persisted_audit_queue(path, parsed.entries),
        Err(err) => {
            tracing::warn!(
                error = %err,
                path = %path.display(),
                "Failed to parse audit outbox file; starting with empty queue"
            );
            (VecDeque::new(), false)
        }
    }
}

pub(super) fn persist_audit_queue(path: &Path, queue: &VecDeque<serde_json::Value>) -> Result<()> {
    let serialized = serde_json::to_string_pretty(&PersistedAuditQueue {
        entries: queue.clone(),
    })
    .with_context(|| "Failed to serialize audit outbox")?;
    crate::security::fs::write_private_atomic(path, serialized.as_bytes(), "audit outbox")?;
    Ok(())
}

fn non_empty_audit_string(value: Option<&serde_json::Value>) -> bool {
    value
        .and_then(|value| value.as_str())
        .map(str::trim)
        .is_some_and(|value| !value.is_empty())
}

fn normalize_audit_event_id(value: &serde_json::Value) -> Option<String> {
    match value {
        serde_json::Value::String(raw) => {
            let trimmed = raw.trim();
            if trimmed.is_empty() {
                None
            } else {
                Some(trimmed.to_string())
            }
        }
        serde_json::Value::Number(raw) => Some(raw.to_string()),
        _ => None,
    }
}

fn normalize_and_validate_audit_event(event: &mut serde_json::Value) -> Option<String> {
    let obj = event.as_object_mut()?;

    let id = obj
        .get("id")
        .and_then(normalize_audit_event_id)
        .unwrap_or_else(|| uuid::Uuid::new_v4().to_string());
    obj.insert("id".to_string(), serde_json::Value::String(id.clone()));

    if !non_empty_audit_string(obj.get("timestamp"))
        || !non_empty_audit_string(obj.get("event_type"))
        || !non_empty_audit_string(obj.get("action_type"))
        || !non_empty_audit_string(obj.get("decision"))
    {
        return None;
    }

    Some(id)
}

fn sanitize_persisted_audit_queue(
    path: &Path,
    entries: VecDeque<serde_json::Value>,
) -> (VecDeque<serde_json::Value>, bool) {
    let mut sanitized = VecDeque::new();
    let mut dropped_invalid = 0usize;
    let mut dropped_overflow = 0usize;
    let mut changed = false;

    for mut event in entries {
        let original = event.clone();
        if normalize_and_validate_audit_event(&mut event).is_none() {
            dropped_invalid += 1;
            changed = true;
            continue;
        }
        if event != original {
            changed = true;
        }
        if sanitized.len() >= MAX_AUDIT_QUEUE_LEN {
            sanitized.pop_front();
            dropped_overflow += 1;
            changed = true;
        }
        sanitized.push_back(event);
    }

    if dropped_invalid > 0 || dropped_overflow > 0 {
        tracing::warn!(
            path = %path.display(),
            dropped_invalid,
            dropped_overflow,
            retained = sanitized.len(),
            "Sanitized persisted audit outbox"
        );
    }

    (sanitized, changed)
}

fn drain_flush_batch(
    queue: &mut VecDeque<serde_json::Value>,
) -> (VecDeque<serde_json::Value>, usize) {
    let mut batch = VecDeque::new();
    let mut dropped_invalid = 0usize;

    while batch.len() < MAX_AUDIT_BATCH_LEN {
        let Some(mut event) = queue.pop_front() else {
            break;
        };
        if normalize_and_validate_audit_event(&mut event).is_some() {
            batch.push_back(event);
        } else {
            dropped_invalid += 1;
        }
    }

    (batch, dropped_invalid)
}

impl AuditQueue {
    pub(super) fn with_path(path: PathBuf) -> Self {
        let (queue, sanitized) = load_persisted_audit_queue(&path);
        if sanitized {
            if let Err(err) = persist_audit_queue(&path, &queue) {
                tracing::warn!(error = %err, "Failed to persist sanitized audit outbox");
            }
        }
        Self {
            path,
            queue: Mutex::new(queue),
            flush_lock: Mutex::new(()),
            http_client: reqwest::Client::builder()
                .timeout(Duration::from_secs(10))
                .build()
                .unwrap_or_else(|_| reqwest::Client::new()),
        }
    }

    pub fn new() -> Self {
        Self::with_path(audit_queue_path())
    }

    #[cfg(test)]
    pub fn new_test_isolated() -> Self {
        let path = std::env::temp_dir().join(format!(
            "clawdstrike-audit-outbox-test-{}.json",
            uuid::Uuid::new_v4()
        ));
        Self::with_path(path)
    }

    /// Enqueue an audit event to be uploaded later.
    pub async fn enqueue(&self, event: serde_json::Value) {
        let mut event = event;
        let Some(event_id) = normalize_and_validate_audit_event(&mut event) else {
            tracing::warn!("Dropping invalid audit event from offline outbox enqueue");
            return;
        };
        let mut queue = self.queue.lock().await;
        if queue.iter().any(|existing| {
            existing
                .get("id")
                .and_then(normalize_audit_event_id)
                .is_some_and(|id| id == event_id)
        }) {
            return;
        }
        if queue.len() >= MAX_AUDIT_QUEUE_LEN {
            queue.pop_front();
        }
        queue.push_back(event);
        if let Err(err) = persist_audit_queue(&self.path, &queue) {
            tracing::warn!(error = %err, "Failed to persist audit outbox after enqueue");
        }
    }

    async fn persist_current_queue(&self, context: &str) {
        let queue = self.queue.lock().await;
        if let Err(err) = persist_audit_queue(&self.path, &queue) {
            tracing::warn!(error = %err, context, "Failed to persist audit outbox");
        }
    }

    async fn requeue_failed_flush(&self, events: VecDeque<serde_json::Value>) {
        // Preserve chronological ordering: front=oldest, back=newest.
        // If over capacity, drop oldest entries to match `enqueue()` semantics.
        let mut queue = self.queue.lock().await;
        let new_events = std::mem::take(&mut *queue);
        let mut restored = events;
        restored.extend(new_events);
        while restored.len() > MAX_AUDIT_QUEUE_LEN {
            restored.pop_front();
        }
        *queue = restored;
        if let Err(err) = persist_audit_queue(&self.path, &queue) {
            tracing::warn!(error = %err, "Failed to persist audit outbox after requeue");
        }
    }

    async fn requeue_selected_flush(
        &self,
        events: VecDeque<serde_json::Value>,
        failed_ids: &HashSet<String>,
    ) {
        let selected = events
            .into_iter()
            .filter(|event| {
                event
                    .get("id")
                    .and_then(normalize_audit_event_id)
                    .is_some_and(|id| failed_ids.contains(&id))
            })
            .collect();
        self.requeue_failed_flush(selected).await;
    }

    /// Drain all queued events and upload them to hushd.
    pub async fn flush(
        &self,
        daemon_url: &str,
        api_key: Option<&str>,
    ) -> Result<AuditFlushOutcome> {
        // Serialize flushes so we never interleave drain/requeue in ways that can reorder or
        // duplicate audit uploads during rapid reconnects.
        let _flush_guard = self.flush_lock.lock().await;
        let url = format!("{}/api/v1/audit/batch", daemon_url);
        let mut outcome = AuditFlushOutcome::default();
        let mut dropped_invalid_total = 0usize;

        loop {
            let events = {
                let mut queue = self.queue.lock().await;
                let (events, dropped_invalid) = drain_flush_batch(&mut queue);
                dropped_invalid_total += dropped_invalid;
                events
            };

            if events.is_empty() {
                self.persist_current_queue("after draining audit outbox")
                    .await;
                if dropped_invalid_total > 0 {
                    tracing::warn!(
                        dropped_invalid = dropped_invalid_total,
                        "Dropped invalid audit events from offline outbox"
                    );
                }
                if outcome.accepted > 0 {
                    tracing::info!(
                        count = outcome.accepted,
                        "Flushed queued audit events to daemon"
                    );
                }
                return Ok(outcome);
            }

            let attempted = events.len();
            let events_vec: Vec<_> = events.iter().collect();
            let mut request = self.http_client.post(&url).json(&serde_json::json!({
                "events": events_vec,
            }));
            if let Some(key) = api_key {
                request = request.header("Authorization", format!("Bearer {}", key));
            }

            let response = match request.send().await {
                Ok(resp) => resp,
                Err(err) => {
                    self.requeue_failed_flush(events).await;
                    if audit_flush_has_prior_progress(outcome) {
                        return Err(audit_flush_progress_error(
                            outcome,
                            format!("Failed to flush audit queue to daemon: {}", err),
                        ));
                    }
                    return Err(err).with_context(|| "Failed to flush audit queue to daemon");
                }
            };

            let status = response.status();
            if !status.is_success() {
                let body = response.text().await.unwrap_or_default();
                self.requeue_failed_flush(events).await;
                if audit_flush_has_prior_progress(outcome) {
                    if body.trim().is_empty() {
                        return Err(audit_flush_progress_error(
                            outcome,
                            format!("Audit batch upload returned {}", status),
                        ));
                    }
                    return Err(audit_flush_progress_error(
                        outcome,
                        format!("Audit batch upload returned {}: {}", status, body.trim()),
                    ));
                }
                if body.trim().is_empty() {
                    anyhow::bail!("Audit batch upload returned {}", status);
                }
                anyhow::bail!("Audit batch upload returned {}: {}", status, body.trim());
            }

            let body = response.text().await.unwrap_or_default();
            match serde_json::from_str::<FlushAuditBatchResponse>(&body) {
                Ok(summary) => {
                    if summary.duplicates > 0 {
                        tracing::info!(
                            duplicates = summary.duplicates,
                            "Daemon reported duplicate audit outbox events already ingested"
                        );
                    }
                    if summary.rejected > 0 {
                        let rejected_ids: HashSet<_> = summary.rejected_ids.into_iter().collect();
                        let has_complete_rejected_ids = rejected_ids.len() == summary.rejected;
                        if has_complete_rejected_ids {
                            outcome.accepted += summary.accepted;
                            outcome.duplicates += summary.duplicates;
                            outcome.rejected += summary.rejected;
                            outcome.partial_rejection = true;
                            self.requeue_selected_flush(events, &rejected_ids).await;
                            tracing::warn!(
                                accepted = outcome.accepted,
                                duplicates = outcome.duplicates,
                                rejected = outcome.rejected,
                                "Daemon rejected some audit outbox events; rejected entries remain queued"
                            );
                            return Ok(outcome);
                        } else {
                            self.requeue_failed_flush(events).await;
                            tracing::warn!(
                                prior_accepted = outcome.accepted,
                                prior_duplicates = outcome.duplicates,
                                accepted = summary.accepted,
                                duplicates = summary.duplicates,
                                rejected = summary.rejected,
                                rejected_ids = rejected_ids.len(),
                                "Daemon response lacked complete rejected event IDs; requeueing entire batch"
                            );
                            let message = format!(
                                "Audit batch upload partially rejected after previously flushing {} accepted events; current batch status: accepted={}, duplicates={}, rejected={}",
                                outcome.accepted,
                                summary.accepted,
                                summary.duplicates,
                                summary.rejected
                            );
                            if audit_flush_has_prior_progress(outcome) {
                                return Err(audit_flush_progress_error(outcome, message));
                            }
                            anyhow::bail!("{}", message);
                        }
                    }
                    if !summary.accepted_ids.is_empty() || !summary.duplicate_ids.is_empty() {
                        tracing::debug!(
                            accepted_ids = summary.accepted_ids.len(),
                            duplicate_ids = summary.duplicate_ids.len(),
                            "Daemon returned audit batch event ID summaries"
                        );
                    }
                    outcome.accepted += summary.accepted;
                    outcome.duplicates += summary.duplicates;
                    // Persist after each acknowledged batch so a crash before the next loop
                    // iteration does not resurrect events the daemon already accepted.
                    self.persist_current_queue("after accepted audit batch confirmation")
                        .await;
                }
                Err(err) => {
                    self.requeue_failed_flush(events).await;
                    tracing::warn!(
                        error = %err,
                        attempted,
                        body = %body,
                        "Failed to parse audit batch response; requeued audit outbox batch"
                    );
                    if audit_flush_has_prior_progress(outcome) {
                        return Err(audit_flush_progress_error(
                            outcome,
                            format!("Failed to parse audit batch response: {}", err),
                        ));
                    }
                    anyhow::bail!("Failed to parse audit batch response: {}", err);
                }
            }
        }
    }

    /// Number of events currently queued.
    pub async fn len(&self) -> usize {
        self.queue.lock().await.len()
    }
}

#[cfg(test)]
#[path = "audit_queue_tests.rs"]
mod tests;
