use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use tokio::sync::{broadcast, mpsc, watch, RwLock};

use crate::siem::dlq::{DeadLetterEntry, DeadLetterQueue};
use crate::siem::exporter::{sleep_backoff, ExportResult, Exporter, ExporterConfig, ExporterError};
use crate::siem::filter::EventFilter;
use crate::siem::ratelimit::ExportRateLimiter;
use crate::siem::types::SecurityEvent;

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct ExporterHealth {
    pub running: bool,
    pub last_success_at: Option<DateTime<Utc>>,
    pub last_error_at: Option<DateTime<Utc>>,
    pub last_error: Option<String>,
    pub exported_total: u64,
    pub failed_total: u64,
    pub dlq_total: u64,
    pub dropped_total: u64,
    pub queue_depth: usize,
}

#[derive(Clone)]
pub struct ExporterHandle {
    pub name: String,
    pub tx: mpsc::Sender<SecurityEvent>,
    pub health: Arc<RwLock<ExporterHealth>>,
    pub dlq: Option<DeadLetterQueue>,
    pub filter: EventFilter,
}

pub struct ExporterManager {
    exporter_handles: Vec<ExporterHandle>,
    shutdown_tx: watch::Sender<bool>,
    task: tokio::task::JoinHandle<()>,
}

impl ExporterManager {
    pub fn start(
        rx: broadcast::Receiver<SecurityEvent>,
        exporter_handles: Vec<ExporterHandle>,
    ) -> Self {
        let task_handles = exporter_handles.clone();
        let (shutdown_tx, mut shutdown_rx) = watch::channel(false);

        let task = tokio::spawn(async move {
            let mut rx = rx;

            loop {
                tokio::select! {
                    _ = shutdown_rx.changed() => {
                        if *shutdown_rx.borrow() {
                            break;
                        }
                    }
                    res = rx.recv() => {
                        match res {
                            Ok(event) => fanout_event(&task_handles, event).await,
                            Err(broadcast::error::RecvError::Closed) => break,
                            Err(broadcast::error::RecvError::Lagged(_)) => continue,
                        }
                    }
                }
            }

            // Drain any remaining buffered broadcast messages best-effort.
            loop {
                match rx.try_recv() {
                    Ok(event) => fanout_event(&task_handles, event).await,
                    Err(broadcast::error::TryRecvError::Empty) => break,
                    Err(broadcast::error::TryRecvError::Closed) => break,
                    Err(broadcast::error::TryRecvError::Lagged(_)) => continue,
                }
            }
        });

        Self {
            exporter_handles,
            shutdown_tx,
            task,
        }
    }

    pub fn exporters(&self) -> &[ExporterHandle] {
        &self.exporter_handles
    }

    pub async fn shutdown(self) {
        let _ = self.shutdown_tx.send(true);
        let _ = self.task.await;
    }
}

async fn fanout_event(handles: &[ExporterHandle], event: SecurityEvent) {
    for handle in handles {
        if !handle.filter.matches(&event) {
            continue;
        }
        if let Err(err) = handle.tx.try_send(event.clone()) {
            // Backpressure: drop on full and optionally DLQ.
            let has_dlq = handle.dlq.is_some();
            {
                let mut health = handle.health.write().await;
                health.dropped_total = health.dropped_total.saturating_add(1);
                if has_dlq {
                    health.dlq_total = health.dlq_total.saturating_add(1);
                }
            }

            if let Some(dlq) = handle.dlq.clone() {
                let exporter = handle.name.clone();
                let event = event.clone();
                tokio::spawn(async move {
                    let _ = dlq
                        .enqueue(DeadLetterEntry {
                            exporter,
                            failed_at: Utc::now(),
                            attempts: 0,
                            error: format!("dropped before enqueue: {err}"),
                            retryable: true,
                            event,
                        })
                        .await;
                });
            }
        }
    }
}

pub fn spawn_exporter_worker(
    exporter: Box<dyn Exporter>,
    config: ExporterConfig,
    dlq: Option<DeadLetterQueue>,
    filter: EventFilter,
    queue_capacity: usize,
) -> ExporterHandle {
    let (tx, mut rx) = mpsc::channel::<SecurityEvent>(queue_capacity);
    let health = Arc::new(RwLock::new(ExporterHealth {
        running: true,
        ..ExporterHealth::default()
    }));

    let exporter_name = exporter.name().to_string();
    let exporter_name_for_task = exporter_name.clone();
    let health_task = health.clone();
    let dlq_task = dlq.clone();

    tokio::spawn(async move {
        let mut buffer: Vec<SecurityEvent> = Vec::with_capacity(config.batch_size);
        let mut ticker = tokio::time::interval(Duration::from_millis(config.flush_interval_ms));
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

        let rate_limiter = ExportRateLimiter::new(config.rate_limit.as_ref());

        loop {
            tokio::select! {
                maybe_event = rx.recv() => {
                    match maybe_event {
                        Some(event) => {
                            buffer.push(event);
                            {
                                let mut h = health_task.write().await;
                                h.queue_depth = rx.len() + buffer.len();
                            }
                            if buffer.len() >= config.batch_size {
                                flush_exporter_batch(
                                    exporter.as_ref(),
                                    &exporter_name_for_task,
                                    &config,
                                    &rate_limiter,
                                    &dlq_task,
                                    &health_task,
                                    &mut buffer
                                ).await;
                            }
                        }
                        None => break,
                    }
                }
                _ = ticker.tick() => {
                    if !buffer.is_empty() {
                        flush_exporter_batch(
                            exporter.as_ref(),
                            &exporter_name_for_task,
                            &config,
                            &rate_limiter,
                            &dlq_task,
                            &health_task,
                            &mut buffer
                        ).await;
                    } else {
                        let mut h = health_task.write().await;
                        h.queue_depth = rx.len();
                    }
                }
            }
        }

        // Flush remaining.
        if !buffer.is_empty() {
            flush_exporter_batch(
                exporter.as_ref(),
                &exporter_name_for_task,
                &config,
                &rate_limiter,
                &dlq_task,
                &health_task,
                &mut buffer,
            )
            .await;
        }

        let _ = exporter.shutdown().await;
        let mut h = health_task.write().await;
        h.running = false;
    });

    ExporterHandle {
        name: exporter_name,
        tx,
        health,
        dlq,
        filter,
    }
}

async fn flush_exporter_batch(
    exporter: &dyn Exporter,
    exporter_name: &str,
    config: &ExporterConfig,
    rate_limiter: &ExportRateLimiter,
    dlq: &Option<DeadLetterQueue>,
    health: &Arc<RwLock<ExporterHealth>>,
    buffer: &mut Vec<SecurityEvent>,
) {
    let events = std::mem::take(buffer);
    let batch_len = events.len();
    if batch_len == 0 {
        return;
    }

    let started_at = Utc::now();
    let res = export_with_retry(
        exporter,
        exporter_name,
        config,
        rate_limiter,
        dlq,
        health,
        events,
    )
    .await;

    match res {
        Ok(result) => {
            let mut h = health.write().await;
            h.exported_total = h.exported_total.saturating_add(result.exported as u64);
            h.failed_total = h.failed_total.saturating_add(result.failed as u64);
            if result.failed == 0 {
                h.last_success_at = Some(started_at);
                h.last_error = None;
            } else {
                h.last_error_at = Some(started_at);
                h.last_error = Some(format!("partial failure: {} events", result.failed));
            }
        }
        Err(err) => {
            let mut h = health.write().await;
            h.failed_total = h.failed_total.saturating_add(batch_len as u64);
            h.last_error_at = Some(started_at);
            h.last_error = Some(err);
        }
    }
}

async fn export_with_retry(
    exporter: &dyn Exporter,
    exporter_name: &str,
    config: &ExporterConfig,
    rate_limiter: &ExportRateLimiter,
    dlq: &Option<DeadLetterQueue>,
    health: &Arc<RwLock<ExporterHealth>>,
    events: Vec<SecurityEvent>,
) -> Result<ExportResult, String> {
    let mut attempt: u32 = 0;
    let mut remaining: Vec<SecurityEvent> = events;
    let mut permanent_failures: Vec<(SecurityEvent, String, bool, u32)> = Vec::new(); // (event, err, retryable, attempts)
    let mut exported_total: usize = 0;

    while attempt <= config.retry.max_retries && !remaining.is_empty() {
        rate_limiter.acquire().await;

        match exporter.export(remaining.clone()).await {
            Ok(result) => {
                if result.errors.is_empty() {
                    exported_total = exported_total.saturating_add(remaining.len());
                    return Ok(ExportResult {
                        exported: exported_total,
                        failed: permanent_failures.len(),
                        errors: Vec::new(),
                    });
                }

                let mut by_id: HashMap<String, SecurityEvent> = remaining
                    .into_iter()
                    .map(|e| (e.event_id.to_string(), e))
                    .collect();

                let mut to_retry: Vec<SecurityEvent> = Vec::new();
                for err in result.errors {
                    if let Some(event) = by_id.remove(&err.event_id) {
                        if err.retryable && attempt < config.retry.max_retries {
                            to_retry.push(event);
                        } else {
                            permanent_failures.push((event, err.error, err.retryable, attempt + 1));
                        }
                    }
                }

                // Anything left in the map was exported successfully.
                exported_total = exported_total.saturating_add(by_id.len());

                if to_retry.is_empty() {
                    enqueue_dlq(dlq, exporter_name, &permanent_failures, health).await;
                    return Ok(ExportResult {
                        exported: exported_total,
                        failed: permanent_failures.len(),
                        errors: Vec::new(),
                    });
                }

                remaining = to_retry;
            }
            Err(err) => {
                let retryable = exporter_error_retryable(&err);
                if retryable && attempt < config.retry.max_retries {
                    attempt += 1;
                    sleep_backoff(&config.retry, attempt).await;
                    continue;
                }

                for event in remaining {
                    permanent_failures.push((event, err.to_string(), retryable, attempt + 1));
                }
                enqueue_dlq(dlq, exporter_name, &permanent_failures, health).await;
                return Err(err.to_string());
            }
        }

        attempt += 1;
        if attempt <= config.retry.max_retries && !remaining.is_empty() {
            sleep_backoff(&config.retry, attempt).await;
        }
    }

    if !remaining.is_empty() {
        for event in remaining {
            permanent_failures.push((
                event,
                "retry budget exhausted".to_string(),
                true,
                config.retry.max_retries + 1,
            ));
        }
    }

    enqueue_dlq(dlq, exporter_name, &permanent_failures, health).await;

    Ok(ExportResult {
        exported: exported_total,
        failed: permanent_failures.len(),
        errors: Vec::new(),
    })
}

fn exporter_error_retryable(err: &ExporterError) -> bool {
    match err {
        ExporterError::Http { status, .. } => *status == 429 || (*status >= 500 && *status <= 599),
        ExporterError::Io(_) => true,
        ExporterError::Serialization(_) => false,
        ExporterError::Config(_) => false,
        ExporterError::Auth(_) => false,
        ExporterError::Other(_) => false,
    }
}

async fn enqueue_dlq(
    dlq: &Option<DeadLetterQueue>,
    exporter_name: &str,
    errors: &[(SecurityEvent, String, bool, u32)],
    health: &Arc<RwLock<ExporterHealth>>,
) {
    let Some(dlq) = dlq else { return };
    if !errors.is_empty() {
        let mut h = health.write().await;
        h.dlq_total = h.dlq_total.saturating_add(errors.len() as u64);
    }

    for (event, error, retryable, attempts) in errors {
        let _ = dlq
            .enqueue(DeadLetterEntry {
                exporter: exporter_name.to_string(),
                failed_at: Utc::now(),
                attempts: *attempts,
                error: error.clone(),
                retryable: *retryable,
                event: event.clone(),
            })
            .await;
    }
}
