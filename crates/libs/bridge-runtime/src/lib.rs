#![forbid(unsafe_code)]
#![cfg_attr(test, allow(clippy::expect_used, clippy::unwrap_used))]

use std::fs;
use std::path::Path;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use async_nats::connection::State as NatsConnectionState;
use async_nats::jetstream::context::Publish;
use axum::extract::State;
use axum::http::header::CONTENT_TYPE;
use axum::http::{HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::{Json, Router};
use hush_core::Keypair;
use rusqlite::{params, Connection};
use serde::Serialize;
use serde_json::Value;
use tokio::sync::Mutex as AsyncMutex;
use tracing::{debug, error, warn};

#[derive(Debug, Clone)]
pub struct ChainState {
    pub seq: u64,
    pub prev_hash: Option<String>,
}

impl Default for ChainState {
    fn default() -> Self {
        Self {
            seq: 1,
            prev_hash: None,
        }
    }
}

#[derive(Debug, Clone)]
pub struct OutboxConfig {
    pub path: String,
    pub max_pending: u64,
    pub retry_base_ms: u64,
    pub retry_max_ms: u64,
}

impl Default for OutboxConfig {
    fn default() -> Self {
        Self {
            path: "/tmp/bridge-outbox.db".to_string(),
            max_pending: 10_000,
            retry_base_ms: 500,
            retry_max_ms: 30_000,
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum PublishError {
    #[error("configuration error: {0}")]
    Config(String),
    #[error("spine error: {0}")]
    Spine(#[from] spine::Error),
    #[error("serialization error: {0}")]
    Json(#[from] serde_json::Error),
    #[error("publish error: {0}")]
    Publish(String),
    #[error("outbox error: {0}")]
    Outbox(String),
}

#[derive(Debug, Clone)]
pub struct OutboxEntry {
    pub id: i64,
    pub seq: u64,
    pub subject: String,
    pub payload: Vec<u8>,
    pub envelope_hash: String,
    pub attempts: u32,
}

#[derive(Debug, Clone)]
pub struct SqliteOutbox {
    config: OutboxConfig,
}

impl SqliteOutbox {
    pub async fn open(config: OutboxConfig) -> Result<Self, String> {
        let config_clone = config.clone();
        tokio::task::spawn_blocking(move || {
            let path = Path::new(&config_clone.path);
            if let Some(parent) = path.parent() {
                if !parent.as_os_str().is_empty() {
                    fs::create_dir_all(parent)
                        .map_err(|e| format!("failed to create outbox directory: {e}"))?;
                }
            }
            let mut conn = open_conn(&config_clone.path)
                .map_err(|e| format!("failed to open outbox sqlite db: {e}"))?;
            init_schema(&mut conn)
                .map_err(|e| format!("failed to initialize outbox schema: {e}"))?;
            Ok::<(), String>(())
        })
        .await
        .map_err(|e| format!("outbox init task failed: {e}"))??;

        Ok(Self { config })
    }

    pub async fn enqueue(
        &self,
        seq: u64,
        subject: &str,
        payload: &[u8],
        envelope_hash: &str,
    ) -> Result<(), String> {
        let config = self.config.clone();
        let subject = subject.to_string();
        let payload = payload.to_vec();
        let envelope_hash = envelope_hash.to_string();
        tokio::task::spawn_blocking(move || {
            let mut conn = open_conn(&config.path)
                .map_err(|e| format!("failed to open outbox sqlite db: {e}"))?;
            init_schema(&mut conn)
                .map_err(|e| format!("failed to initialize outbox schema: {e}"))?;

            let pending: i64 = conn
                .query_row("SELECT COUNT(*) FROM bridge_outbox", [], |row| {
                    row.get::<_, i64>(0)
                })
                .map_err(|e| format!("failed to count outbox rows: {e}"))?;
            if pending >= i64::try_from(config.max_pending).unwrap_or(i64::MAX) {
                return Err(format!(
                    "outbox max pending limit reached ({})",
                    config.max_pending
                ));
            }

            let now_ms = now_millis();
            let seq_i64 = i64::try_from(seq)
                .map_err(|_| format!("sequence value too large for sqlite INTEGER: {seq}"))?;
            let insert = conn.execute(
                "INSERT INTO bridge_outbox (
                    seq, subject, payload, envelope_hash, attempts, next_attempt_at_ms,
                    last_error, created_at_ms, updated_at_ms
                 ) VALUES (?1, ?2, ?3, ?4, 0, ?5, NULL, ?5, ?5)",
                params![seq_i64, subject, payload, envelope_hash, now_ms],
            );

            match insert {
                Ok(_) => Ok(()),
                Err(rusqlite::Error::SqliteFailure(sqlite_err, _))
                    if sqlite_err.code == rusqlite::ErrorCode::ConstraintViolation =>
                {
                    // Idempotent enqueue: if we already persisted this seq/hash we treat it as success.
                    Ok(())
                }
                Err(err) => Err(format!("failed to insert outbox row: {err}")),
            }
        })
        .await
        .map_err(|e| format!("outbox enqueue task failed: {e}"))?
    }

    pub async fn pending_count(&self) -> Result<u64, String> {
        let path = self.config.path.clone();
        tokio::task::spawn_blocking(move || {
            let conn =
                open_conn(&path).map_err(|e| format!("failed to open outbox sqlite db: {e}"))?;
            let count = conn
                .query_row("SELECT COUNT(*) FROM bridge_outbox", [], |row| {
                    row.get::<_, i64>(0)
                })
                .map_err(|e| format!("failed to count outbox rows: {e}"))?;
            u64::try_from(count).map_err(|_| format!("invalid negative sqlite count: {count}"))
        })
        .await
        .map_err(|e| format!("outbox pending count task failed: {e}"))?
    }

    pub async fn claim_due(&self, limit: usize) -> Result<Vec<OutboxEntry>, String> {
        let config = self.config.clone();
        tokio::task::spawn_blocking(move || {
            let mut conn = open_conn(&config.path)
                .map_err(|e| format!("failed to open outbox sqlite db: {e}"))?;
            init_schema(&mut conn)
                .map_err(|e| format!("failed to initialize outbox schema: {e}"))?;
            let tx = conn
                .transaction()
                .map_err(|e| format!("failed to start outbox transaction: {e}"))?;
            let now = now_millis();

            let mut stmt = tx
                .prepare(
                    "SELECT id, seq, subject, payload, envelope_hash, attempts
                     FROM bridge_outbox
                     WHERE next_attempt_at_ms <= ?1
                     ORDER BY seq ASC
                     LIMIT ?2",
                )
                .map_err(|e| format!("failed to prepare outbox due query: {e}"))?;

            let mapped = stmt
                .query_map(params![now, limit as i64], |row| {
                    let attempts: u32 = row.get(5)?;
                    let seq_i64: i64 = row.get(1)?;
                    let seq = u64::try_from(seq_i64).map_err(|_| {
                        rusqlite::Error::FromSqlConversionFailure(
                            1,
                            rusqlite::types::Type::Integer,
                            Box::new(std::io::Error::new(
                                std::io::ErrorKind::InvalidData,
                                "negative sequence value in outbox",
                            )),
                        )
                    })?;
                    Ok(OutboxEntry {
                        id: row.get(0)?,
                        seq,
                        subject: row.get(2)?,
                        payload: row.get(3)?,
                        envelope_hash: row.get(4)?,
                        attempts,
                    })
                })
                .map_err(|e| format!("failed to query due outbox rows: {e}"))?;

            let mut entries = Vec::new();
            for row in mapped {
                let mut entry = row.map_err(|e| format!("failed to decode outbox row: {e}"))?;
                let next_attempt = entry.attempts.saturating_add(1);
                let backoff =
                    compute_backoff_ms(config.retry_base_ms, config.retry_max_ms, next_attempt);
                tx.execute(
                    "UPDATE bridge_outbox
                     SET attempts = ?1,
                         next_attempt_at_ms = ?2,
                         updated_at_ms = ?3
                     WHERE id = ?4",
                    params![
                        next_attempt,
                        now.saturating_add(backoff as i64),
                        now,
                        entry.id
                    ],
                )
                .map_err(|e| format!("failed to claim outbox row {}: {e}", entry.id))?;
                entry.attempts = next_attempt;
                entries.push(entry);
            }
            drop(stmt);

            tx.commit()
                .map_err(|e| format!("failed to commit outbox claim transaction: {e}"))?;
            Ok(entries)
        })
        .await
        .map_err(|e| format!("outbox claim task failed: {e}"))?
    }

    pub async fn mark_sent(&self, id: i64) -> Result<(), String> {
        let path = self.config.path.clone();
        tokio::task::spawn_blocking(move || {
            let conn =
                open_conn(&path).map_err(|e| format!("failed to open outbox sqlite db: {e}"))?;
            conn.execute("DELETE FROM bridge_outbox WHERE id = ?1", params![id])
                .map_err(|e| format!("failed to delete outbox row {id}: {e}"))?;
            Ok(())
        })
        .await
        .map_err(|e| format!("outbox mark_sent task failed: {e}"))?
    }

    pub async fn mark_failed(&self, id: i64, error_message: &str) -> Result<(), String> {
        let path = self.config.path.clone();
        let error_message = error_message.to_string();
        tokio::task::spawn_blocking(move || {
            let conn =
                open_conn(&path).map_err(|e| format!("failed to open outbox sqlite db: {e}"))?;
            conn.execute(
                "UPDATE bridge_outbox
                 SET last_error = ?1,
                     updated_at_ms = ?2
                 WHERE id = ?3",
                params![error_message, now_millis(), id],
            )
            .map_err(|e| format!("failed to mark outbox row {id} failed: {e}"))?;
            Ok(())
        })
        .await
        .map_err(|e| format!("outbox mark_failed task failed: {e}"))?
    }
}

#[derive(Debug)]
pub struct BridgeMetrics {
    bridge: String,
    publish_failures_total: AtomicU64,
    webhook_5xx_total: AtomicU64,
    seq_current: AtomicU64,
    nats_connected: AtomicU64,
    outbox_pending: AtomicU64,
    publish_unhealthy: AtomicBool,
    last_publish_error: Mutex<Option<String>>,
}

impl BridgeMetrics {
    pub fn new(bridge: impl Into<String>) -> Self {
        Self {
            bridge: bridge.into(),
            publish_failures_total: AtomicU64::new(0),
            webhook_5xx_total: AtomicU64::new(0),
            seq_current: AtomicU64::new(0),
            nats_connected: AtomicU64::new(0),
            outbox_pending: AtomicU64::new(0),
            publish_unhealthy: AtomicBool::new(false),
            last_publish_error: Mutex::new(None),
        }
    }

    pub fn bridge_name(&self) -> &str {
        &self.bridge
    }

    pub fn inc_publish_failures(&self, error_message: &str) {
        self.publish_failures_total.fetch_add(1, Ordering::Relaxed);
        self.publish_unhealthy.store(true, Ordering::Relaxed);
        let mut guard = self
            .last_publish_error
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        *guard = Some(error_message.to_string());
    }

    pub fn inc_webhook_5xx(&self) {
        self.webhook_5xx_total.fetch_add(1, Ordering::Relaxed);
    }

    pub fn set_seq_current(&self, seq: u64) {
        self.seq_current.store(seq, Ordering::Relaxed);
    }

    pub fn set_nats_connected(&self, connected: bool) {
        self.nats_connected
            .store(if connected { 1 } else { 0 }, Ordering::Relaxed);
    }

    pub fn set_outbox_pending(&self, pending: u64) {
        self.outbox_pending.store(pending, Ordering::Relaxed);
    }

    pub fn clear_publish_unhealthy(&self) {
        self.publish_unhealthy.store(false, Ordering::Relaxed);
        let mut guard = self
            .last_publish_error
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        *guard = None;
    }

    pub fn outbox_pending(&self) -> u64 {
        self.outbox_pending.load(Ordering::Relaxed)
    }

    pub fn nats_connected(&self) -> bool {
        self.nats_connected.load(Ordering::Relaxed) == 1
    }

    pub fn is_publish_unhealthy(&self) -> bool {
        self.publish_unhealthy.load(Ordering::Relaxed)
    }

    pub fn readiness(&self, outbox_degraded_threshold: u64) -> ReadinessSnapshot {
        let nats_connected = self.nats_connected();
        let publish_path_healthy = !self.is_publish_unhealthy();
        let outbox_pending = self.outbox_pending();
        let outbox_healthy = outbox_pending <= outbox_degraded_threshold;
        let status = if nats_connected && publish_path_healthy && outbox_healthy {
            "ready"
        } else {
            "degraded"
        };

        let last_publish_error = self
            .last_publish_error
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clone();

        ReadinessSnapshot {
            bridge: self.bridge.clone(),
            status: status.to_string(),
            nats_connected,
            publish_path_healthy,
            outbox_pending,
            outbox_degraded_threshold,
            outbox_healthy,
            seq_current: self.seq_current.load(Ordering::Relaxed),
            publish_failures_total: self.publish_failures_total.load(Ordering::Relaxed),
            webhook_5xx_total: self.webhook_5xx_total.load(Ordering::Relaxed),
            last_publish_error,
        }
    }

    pub fn render_prometheus(&self, outbox_degraded_threshold: u64) -> String {
        let mut out = String::new();
        let bridge = escape_label_value(&self.bridge);
        let readiness = self.readiness(outbox_degraded_threshold);

        out.push_str("# HELP publish_failures_total Total publish failures.\n");
        out.push_str("# TYPE publish_failures_total counter\n");
        out.push_str(&format!(
            "publish_failures_total{{bridge=\"{}\"}} {}\n",
            bridge, readiness.publish_failures_total
        ));

        out.push_str("# HELP webhook_5xx_total Total webhook 5xx responses.\n");
        out.push_str("# TYPE webhook_5xx_total counter\n");
        out.push_str(&format!(
            "webhook_5xx_total{{bridge=\"{}\"}} {}\n",
            bridge, readiness.webhook_5xx_total
        ));

        out.push_str("# HELP seq_current Current chain sequence head.\n");
        out.push_str("# TYPE seq_current gauge\n");
        out.push_str(&format!(
            "seq_current{{bridge=\"{}\"}} {}\n",
            bridge, readiness.seq_current
        ));

        out.push_str("# HELP nats_connected Whether NATS connection is currently healthy (1/0).\n");
        out.push_str("# TYPE nats_connected gauge\n");
        out.push_str(&format!(
            "nats_connected{{bridge=\"{}\"}} {}\n",
            bridge,
            if readiness.nats_connected { 1 } else { 0 }
        ));

        out.push_str("# HELP outbox_pending Current number of queued outbox rows.\n");
        out.push_str("# TYPE outbox_pending gauge\n");
        out.push_str(&format!(
            "outbox_pending{{bridge=\"{}\"}} {}\n",
            bridge, readiness.outbox_pending
        ));

        out.push_str("# HELP bridge_ready Readiness status (1 ready, 0 degraded).\n");
        out.push_str("# TYPE bridge_ready gauge\n");
        out.push_str(&format!(
            "bridge_ready{{bridge=\"{}\"}} {}\n",
            bridge,
            if readiness.status == "ready" { 1 } else { 0 }
        ));

        out
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct ReadinessSnapshot {
    pub bridge: String,
    pub status: String,
    pub nats_connected: bool,
    pub publish_path_healthy: bool,
    pub outbox_pending: u64,
    pub outbox_degraded_threshold: u64,
    pub outbox_healthy: bool,
    pub seq_current: u64,
    pub publish_failures_total: u64,
    pub webhook_5xx_total: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_publish_error: Option<String>,
}

#[derive(Clone)]
struct AdminState {
    metrics: Arc<BridgeMetrics>,
    outbox_degraded_threshold: u64,
}

pub fn spawn_admin_server(
    listen_addr: String,
    metrics: Arc<BridgeMetrics>,
    outbox_degraded_threshold: u64,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let state = AdminState {
            metrics,
            outbox_degraded_threshold,
        };
        let app = Router::new()
            .route("/healthz", get(handle_healthz))
            .route("/readyz", get(handle_readyz))
            .route("/metrics", get(handle_metrics))
            .with_state(state);

        let listener = match tokio::net::TcpListener::bind(&listen_addr).await {
            Ok(listener) => listener,
            Err(err) => {
                error!(listen_addr = %listen_addr, error = %err, "failed to bind bridge admin server");
                return;
            }
        };

        if let Err(err) = axum::serve(listener, app).await {
            error!(listen_addr = %listen_addr, error = %err, "bridge admin server exited with error");
        }
    })
}

async fn handle_healthz() -> StatusCode {
    StatusCode::OK
}

async fn handle_readyz(State(state): State<AdminState>) -> impl IntoResponse {
    let readiness = state.metrics.readiness(state.outbox_degraded_threshold);
    let code = if readiness.status == "ready" {
        StatusCode::OK
    } else {
        StatusCode::SERVICE_UNAVAILABLE
    };
    (code, Json(readiness))
}

async fn handle_metrics(State(state): State<AdminState>) -> Response {
    let rendered = state
        .metrics
        .render_prometheus(state.outbox_degraded_threshold);
    (
        [(
            CONTENT_TYPE,
            HeaderValue::from_static("text/plain; version=0.0.4"),
        )],
        rendered,
    )
        .into_response()
}

pub fn validate_nats_subject(subject: &str) -> Result<(), String> {
    if subject.is_empty() || !subject.is_ascii() || subject.contains(' ') || subject.contains('\n')
    {
        return Err(format!("invalid NATS subject: {subject}"));
    }
    Ok(())
}

pub fn is_transient_nats_bootstrap_error(message: &str) -> bool {
    let lower = message.to_ascii_lowercase();
    lower.contains("failed to lookup address information")
        || lower.contains("temporary failure in name resolution")
        || lower.contains("name or service not known")
        || lower.contains("connection refused")
        || lower.contains("connection reset")
        || lower.contains("no route to host")
        || lower.contains("timed out")
}

pub async fn wait_for_nats_startup(nats_url: &str, timeout: Duration) -> Result<(), String> {
    let deadline = tokio::time::Instant::now() + timeout;
    let mut attempt: u32 = 0;
    let mut backoff = Duration::from_millis(250);

    loop {
        attempt = attempt.saturating_add(1);
        match spine::nats_transport::connect(nats_url).await {
            Ok(client) => {
                drop(client);
                if attempt > 1 {
                    warn!(attempt, "NATS became reachable during startup");
                }
                return Ok(());
            }
            Err(err) => {
                let transient = is_transient_nats_bootstrap_error(&err.to_string());
                if !transient || tokio::time::Instant::now() >= deadline {
                    return Err(format!(
                        "NATS startup readiness failed after {attempt} attempts: {err}"
                    ));
                }
                warn!(
                    attempt,
                    backoff_ms = backoff.as_millis() as u64,
                    error = %err,
                    "waiting for NATS startup readiness"
                );
                tokio::time::sleep(backoff).await;
                backoff = (backoff * 2).min(Duration::from_secs(5));
            }
        }
    }
}

pub struct PublishContext<'a> {
    pub chain_state: &'a AsyncMutex<ChainState>,
    pub keypair: &'a Keypair,
    pub nats_client: &'a async_nats::Client,
    pub js: &'a async_nats::jetstream::Context,
    pub outbox: Option<&'a SqliteOutbox>,
    pub metrics: &'a BridgeMetrics,
}

pub struct PublishRequest {
    pub subject: String,
    pub fact: Value,
    pub force_publish_failure: bool,
}

impl PublishRequest {
    pub fn new(subject: impl Into<String>, fact: Value) -> Self {
        Self {
            subject: subject.into(),
            fact,
            force_publish_failure: false,
        }
    }

    pub fn with_forced_failure(mut self, force_publish_failure: bool) -> Self {
        self.force_publish_failure = force_publish_failure;
        self
    }
}

pub async fn publish_fact(
    context: &PublishContext<'_>,
    request: PublishRequest,
) -> Result<u64, PublishError> {
    validate_nats_subject(&request.subject).map_err(PublishError::Config)?;
    context.metrics.set_nats_connected(
        context.nats_client.connection_state() == NatsConnectionState::Connected,
    );

    let mut state = context.chain_state.lock().await;
    let seq = state.seq;
    let prev_hash = state.prev_hash.clone();
    let envelope = spine::build_signed_envelope(
        context.keypair,
        seq,
        prev_hash,
        request.fact,
        spine::now_rfc3339(),
    )?;
    let envelope_hash = envelope
        .get("envelope_hash")
        .and_then(|v| v.as_str())
        .ok_or_else(|| PublishError::Config("signed envelope missing envelope_hash".to_string()))?
        .to_string();
    let payload = serde_json::to_vec(&envelope)?;

    let backlog_present = context.outbox.is_some() && context.metrics.outbox_pending() > 0;
    if backlog_present {
        enqueue_and_advance(
            state,
            seq,
            envelope_hash,
            context.outbox,
            &request.subject,
            &payload,
            context.metrics,
        )
        .await?;
        context
            .metrics
            .publish_unhealthy
            .store(true, Ordering::Relaxed);
        debug!(
            seq,
            subject = request.subject,
            "queued envelope because outbox backlog is pending"
        );
        return Ok(seq);
    }

    match publish_payload(
        context.js,
        &request.subject,
        &payload,
        &envelope_hash,
        request.force_publish_failure,
    )
    .await
    {
        Ok(()) => {
            state.seq = state.seq.saturating_add(1);
            state.prev_hash = Some(envelope_hash);
            context.metrics.set_seq_current(seq);
            context.metrics.set_nats_connected(
                context.nats_client.connection_state() == NatsConnectionState::Connected,
            );
            if let Some(outbox) = context.outbox {
                if let Ok(pending) = outbox.pending_count().await {
                    context.metrics.set_outbox_pending(pending);
                    if pending == 0 {
                        context.metrics.clear_publish_unhealthy();
                    }
                }
            } else {
                context.metrics.clear_publish_unhealthy();
            }
            Ok(seq)
        }
        Err(err) => {
            context.metrics.set_nats_connected(
                context.nats_client.connection_state() == NatsConnectionState::Connected,
            );
            context.metrics.inc_publish_failures(&err);
            if context.outbox.is_some() {
                enqueue_and_advance(
                    state,
                    seq,
                    envelope_hash,
                    context.outbox,
                    &request.subject,
                    &payload,
                    context.metrics,
                )
                .await?;
                debug!(
                    seq,
                    subject = request.subject,
                    "publish failed; queued envelope in durable outbox"
                );
                Ok(seq)
            } else {
                Err(PublishError::Publish(err))
            }
        }
    }
}

async fn enqueue_and_advance(
    mut state: tokio::sync::MutexGuard<'_, ChainState>,
    seq: u64,
    envelope_hash: String,
    outbox: Option<&SqliteOutbox>,
    subject: &str,
    payload: &[u8],
    metrics: &BridgeMetrics,
) -> Result<(), PublishError> {
    let Some(outbox) = outbox else {
        return Err(PublishError::Outbox(
            "outbox enqueue requested but outbox is not configured".to_string(),
        ));
    };

    outbox
        .enqueue(seq, subject, payload, &envelope_hash)
        .await
        .map_err(PublishError::Outbox)?;

    state.seq = state.seq.saturating_add(1);
    state.prev_hash = Some(envelope_hash);
    metrics.set_seq_current(seq);

    let pending = outbox.pending_count().await.map_err(PublishError::Outbox)?;
    metrics.set_outbox_pending(pending);
    Ok(())
}

pub fn spawn_outbox_worker(
    bridge_name: String,
    outbox: Arc<SqliteOutbox>,
    nats_client: async_nats::Client,
    js: async_nats::jetstream::Context,
    metrics: Arc<BridgeMetrics>,
    poll_interval: Duration,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        if let Ok(pending) = outbox.pending_count().await {
            metrics.set_outbox_pending(pending);
        }

        loop {
            metrics.set_nats_connected(
                nats_client.connection_state() == NatsConnectionState::Connected,
            );

            let claimed = match outbox.claim_due(64).await {
                Ok(rows) => rows,
                Err(err) => {
                    warn!(bridge = %bridge_name, error = %err, "failed to claim due outbox rows");
                    tokio::time::sleep(poll_interval).await;
                    continue;
                }
            };

            for row in claimed {
                match publish_payload(&js, &row.subject, &row.payload, &row.envelope_hash, false)
                    .await
                {
                    Ok(()) => {
                        if let Err(err) = outbox.mark_sent(row.id).await {
                            warn!(bridge = %bridge_name, row_id = row.id, error = %err, "failed to mark outbox row sent");
                        }
                    }
                    Err(err) => {
                        metrics.inc_publish_failures(&err);
                        if let Err(mark_err) = outbox.mark_failed(row.id, &err).await {
                            warn!(bridge = %bridge_name, row_id = row.id, error = %mark_err, "failed to mark outbox row failed");
                        }
                    }
                }
            }

            if let Ok(pending) = outbox.pending_count().await {
                metrics.set_outbox_pending(pending);
                if pending == 0 && metrics.nats_connected() {
                    metrics.clear_publish_unhealthy();
                }
            }

            tokio::time::sleep(poll_interval).await;
        }
    })
}

async fn publish_payload(
    js: &async_nats::jetstream::Context,
    subject: &str,
    payload: &[u8],
    envelope_hash: &str,
    force_publish_failure: bool,
) -> Result<(), String> {
    if force_publish_failure {
        return Err("forced publish failure".to_string());
    }

    let ack_future = js
        .send_publish(
            subject.to_string(),
            Publish::build()
                .payload(payload.to_vec().into())
                .message_id(envelope_hash),
        )
        .await
        .map_err(|e| format!("publish request failed: {e}"))?;
    ack_future
        .await
        .map_err(|e| format!("publish ack failed: {e}"))?;
    Ok(())
}

fn open_conn(path: &str) -> rusqlite::Result<Connection> {
    let conn = Connection::open(path)?;
    conn.execute_batch("PRAGMA journal_mode=WAL; PRAGMA synchronous=NORMAL;")?;
    Ok(conn)
}

fn init_schema(conn: &mut Connection) -> rusqlite::Result<()> {
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS bridge_outbox (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            seq INTEGER NOT NULL UNIQUE,
            subject TEXT NOT NULL,
            payload BLOB NOT NULL,
            envelope_hash TEXT NOT NULL UNIQUE,
            attempts INTEGER NOT NULL DEFAULT 0,
            next_attempt_at_ms INTEGER NOT NULL,
            last_error TEXT,
            created_at_ms INTEGER NOT NULL,
            updated_at_ms INTEGER NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_bridge_outbox_due
          ON bridge_outbox(next_attempt_at_ms, seq);",
    )?;
    Ok(())
}

fn compute_backoff_ms(base_ms: u64, max_ms: u64, attempts: u32) -> u64 {
    let shift = attempts.saturating_sub(1).min(16);
    let multiplier = 1u64 << shift;
    let candidate = base_ms.saturating_mul(multiplier);
    candidate.min(max_ms.max(base_ms))
}

fn now_millis() -> i64 {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_else(|_| Duration::from_secs(0));
    let millis = now.as_millis();
    if millis > i64::MAX as u128 {
        i64::MAX
    } else {
        millis as i64
    }
}

fn escape_label_value(value: &str) -> String {
    value
        .replace('\\', "\\\\")
        .replace('"', "\\\"")
        .replace('\n', "\\n")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validate_subject() {
        assert!(validate_nats_subject("clawdstrike.bridge.v1").is_ok());
        assert!(validate_nats_subject("").is_err());
        assert!(validate_nats_subject("bad subject").is_err());
    }

    #[test]
    fn backoff_caps() {
        assert_eq!(compute_backoff_ms(100, 1000, 1), 100);
        assert_eq!(compute_backoff_ms(100, 1000, 2), 200);
        assert_eq!(compute_backoff_ms(100, 1000, 20), 1000);
    }
}
