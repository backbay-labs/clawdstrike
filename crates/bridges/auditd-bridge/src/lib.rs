#![cfg_attr(test, allow(clippy::expect_used, clippy::unwrap_used))]

//! # auditd-bridge
//!
//! Tails the Linux auditd log and publishes runtime audit events as signed
//! Spine envelopes to NATS JetStream.

pub mod audit;
pub mod error;
pub mod mapper;

use std::sync::Arc;
use std::time::Duration;

use bridge_runtime::{
    publish_fact, spawn_admin_server, spawn_outbox_worker, BridgeMetrics, ChainState, OutboxConfig,
    PublishContext, PublishError, PublishRequest, SqliteOutbox,
};
use hush_core::Keypair;
use tokio::sync::Mutex;
use tracing::{debug, info, warn};

use crate::audit::{
    parse_audit_line, AuditEvent, AuditEventGrouper, AuditEventType, AuditLogTailer,
};
use crate::error::{Error, Result};
use crate::mapper::map_event;

/// NATS subject prefix for all auditd bridge envelopes.
const NATS_SUBJECT_PREFIX: &str = "clawdstrike.spine.envelope.auditd";

/// NATS JetStream stream name.
const STREAM_NAME: &str = "CLAWDSTRIKE_AUDITD";

/// Configuration for the bridge.
#[derive(Debug, Clone)]
pub struct BridgeConfig {
    /// Path to the audit log file (e.g. `/var/log/audit/audit.log`).
    pub audit_log_path: String,
    /// NATS server URL (e.g. `nats://localhost:4222`).
    pub nats_url: String,
    /// Hex-encoded Ed25519 seed for signing envelopes.
    /// If empty, a random keypair is generated.
    pub signing_key_hex: Option<String>,
    /// Event types to forward. If empty, all event types are forwarded.
    pub event_type_filter: Vec<AuditEventType>,
    /// Timeout in milliseconds for grouping multi-line audit records.
    pub group_timeout_ms: u64,
    /// Poll interval in milliseconds for tailing the audit log file.
    pub poll_interval_ms: u64,
    /// Number of JetStream replicas for the stream.
    pub stream_replicas: usize,
    /// Maximum bytes retained in the JetStream stream (0 = unlimited).
    pub stream_max_bytes: i64,
    /// Maximum age retained in the JetStream stream in seconds (0 = unlimited).
    pub stream_max_age_seconds: u64,
    /// Maximum consecutive handle_event errors before run() returns an error.
    pub max_consecutive_errors: u64,
    /// Path to SPIFFE SVID PEM file. When set, the bridge reads the workload
    /// SPIFFE ID and includes it in every published fact.
    pub svid_path: Option<String>,
    /// Admin HTTP listen address for /healthz, /readyz, /metrics.
    pub admin_listen_addr: String,
    /// Enable durable outbox enqueue/retry.
    pub outbox_enabled: bool,
    /// Outbox SQLite file path.
    pub outbox_path: Option<String>,
    /// Outbox worker flush interval.
    pub outbox_flush_interval_ms: u64,
    /// Maximum pending outbox rows before enqueue rejects.
    pub outbox_max_pending: u64,
    /// Initial outbox retry backoff.
    pub outbox_retry_base_ms: u64,
    /// Maximum outbox retry backoff.
    pub outbox_retry_max_ms: u64,
    /// Readiness degrades when outbox pending exceeds this threshold.
    pub readiness_outbox_degraded_threshold: u64,
    /// Test-only failpoint to force publish failures.
    pub force_publish_failures: bool,
}

impl Default for BridgeConfig {
    fn default() -> Self {
        Self {
            audit_log_path: "/var/log/audit/audit.log".to_string(),
            nats_url: "nats://localhost:4222".to_string(),
            signing_key_hex: None,
            event_type_filter: Vec::new(),
            group_timeout_ms: 500,
            poll_interval_ms: 250,
            stream_replicas: 1,
            stream_max_bytes: 1_073_741_824,
            stream_max_age_seconds: 86_400,
            max_consecutive_errors: 50,
            svid_path: None,
            admin_listen_addr: "0.0.0.0:2112".to_string(),
            outbox_enabled: false,
            outbox_path: Some("/tmp/auditd-bridge-outbox.db".to_string()),
            outbox_flush_interval_ms: 1000,
            outbox_max_pending: 10_000,
            outbox_retry_base_ms: 500,
            outbox_retry_max_ms: 30_000,
            readiness_outbox_degraded_threshold: 100,
            force_publish_failures: false,
        }
    }
}

/// The auditd-to-NATS bridge.
pub struct Bridge {
    keypair: Keypair,
    nats_client: async_nats::Client,
    js: async_nats::jetstream::Context,
    config: BridgeConfig,
    chain_state: Mutex<ChainState>,
    metrics: Arc<BridgeMetrics>,
    outbox: Option<Arc<SqliteOutbox>>,
    /// SPIFFE ID read from the workload SVID, if configured.
    spiffe_id: Option<String>,
}

impl Bridge {
    /// Create a new bridge from the given config.
    pub async fn new(config: BridgeConfig) -> Result<Self> {
        let keypair = match &config.signing_key_hex {
            Some(hex) if !hex.is_empty() => Keypair::from_hex(hex)?,
            _ => {
                info!("no signing key provided, generating ephemeral keypair");
                Keypair::generate()
            }
        };

        info!(
            issuer = %spine::issuer_from_keypair(&keypair),
            "bridge identity"
        );

        let nats_client = spine::nats_transport::connect(&config.nats_url).await?;
        let js = spine::nats_transport::jetstream(nats_client.clone());

        // Ensure the JetStream stream exists.
        let subjects = vec![format!("{NATS_SUBJECT_PREFIX}.>")];
        let max_bytes = (config.stream_max_bytes > 0).then_some(config.stream_max_bytes);
        let max_age = (config.stream_max_age_seconds > 0)
            .then(|| Duration::from_secs(config.stream_max_age_seconds));
        spine::nats_transport::ensure_stream_with_limits(
            &js,
            STREAM_NAME,
            subjects,
            config.stream_replicas,
            max_bytes,
            max_age,
        )
        .await?;

        // Read SPIFFE ID from SVID if configured.
        let spiffe_id = match &config.svid_path {
            Some(path) => match spine::spiffe::read_spiffe_id(path) {
                Ok(id) => {
                    info!(spiffe_id = %id, "loaded workload SPIFFE identity");
                    Some(id)
                }
                Err(e) => {
                    warn!(error = %e, path, "failed to read SPIFFE SVID, continuing without identity binding");
                    None
                }
            },
            None => None,
        };

        let metrics = Arc::new(BridgeMetrics::new("auditd-bridge"));
        metrics.set_nats_connected(
            nats_client.connection_state() == async_nats::connection::State::Connected,
        );

        let outbox = if config.outbox_enabled {
            let outbox_cfg = OutboxConfig {
                path: config
                    .outbox_path
                    .clone()
                    .unwrap_or_else(|| "/tmp/auditd-bridge-outbox.db".to_string()),
                max_pending: config.outbox_max_pending,
                retry_base_ms: config.outbox_retry_base_ms,
                retry_max_ms: config.outbox_retry_max_ms,
            };
            let outbox = Arc::new(
                SqliteOutbox::open(outbox_cfg)
                    .await
                    .map_err(Error::Config)?,
            );
            let pending = outbox.pending_count().await.map_err(Error::Config)?;
            metrics.set_outbox_pending(pending);
            Some(outbox)
        } else {
            None
        };

        Ok(Self {
            keypair,
            nats_client,
            js,
            config,
            chain_state: Mutex::new(ChainState::default()),
            metrics,
            outbox,
            spiffe_id,
        })
    }

    /// Run the bridge event loop.
    pub async fn run(&self) -> Result<()> {
        let admin_handle = spawn_admin_server(
            self.config.admin_listen_addr.clone(),
            self.metrics.clone(),
            self.config.readiness_outbox_degraded_threshold,
        );

        let outbox_worker = self.outbox.as_ref().map(|outbox| {
            spawn_outbox_worker(
                "auditd-bridge".to_string(),
                outbox.clone(),
                self.nats_client.clone(),
                self.js.clone(),
                self.metrics.clone(),
                Duration::from_millis(self.config.outbox_flush_interval_ms),
            )
        });

        let result = self.run_internal().await;

        admin_handle.abort();
        if let Some(handle) = outbox_worker {
            handle.abort();
        }

        result
    }

    async fn run_internal(&self) -> Result<()> {
        let (tx, mut rx) = tokio::sync::mpsc::channel::<String>(4096);

        let tailer = AuditLogTailer::new(&self.config.audit_log_path, self.config.poll_interval_ms);

        // Spawn the tailer as a background task.
        let tailer_handle = tokio::spawn(async move {
            if let Err(e) = tailer.run(tx).await {
                tracing::error!(error = %e, "audit log tailer failed");
            }
        });

        info!(
            path = %self.config.audit_log_path,
            "tailing audit log"
        );

        let mut grouper = AuditEventGrouper::new(self.config.group_timeout_ms);
        let mut consecutive_errors: u64 = 0;
        let mut backoff = Duration::from_millis(100);
        let max_backoff = Duration::from_secs(30);

        loop {
            self.metrics.set_nats_connected(
                self.nats_client.connection_state() == async_nats::connection::State::Connected,
            );

            // Use a timeout to periodically flush the grouper even without new lines.
            let line = tokio::time::timeout(
                Duration::from_millis(self.config.group_timeout_ms),
                rx.recv(),
            )
            .await;

            let mut channel_closed = false;
            let events = match line {
                Ok(Some(line)) => match parse_audit_line(&line) {
                    Ok(record) => grouper.add_record(record),
                    Err(e) => {
                        debug!(error = %e, "skipping unparseable audit line");
                        grouper.flush_expired()
                    }
                },
                Ok(None) => {
                    warn!("audit log tailer channel closed");
                    channel_closed = true;
                    // Ensure buffered multi-line events are emitted before exit.
                    grouper.flush_all()
                }
                Err(_) => grouper.flush_expired(),
            };

            for event in events {
                if let Err(e) = self.handle_event(&event).await {
                    consecutive_errors = consecutive_errors.saturating_add(1);
                    warn!(
                        error = %e,
                        consecutive_errors,
                        "failed to handle audit event"
                    );
                    if consecutive_errors >= self.config.max_consecutive_errors {
                        tailer_handle.abort();
                        return Err(Error::Config(format!(
                            "too many consecutive errors ({consecutive_errors}), giving up"
                        )));
                    }
                    tokio::time::sleep(backoff).await;
                    backoff = (backoff * 2).min(max_backoff);
                } else {
                    consecutive_errors = 0;
                    backoff = Duration::from_millis(100);
                }
            }

            if channel_closed {
                break;
            }
        }

        tailer_handle.abort();
        Ok(())
    }

    /// Handle a single grouped audit event: filter, map, sign, publish.
    async fn handle_event(&self, event: &AuditEvent) -> Result<()> {
        // Event type filter: if configured, only forward matching types.
        if !self.config.event_type_filter.is_empty()
            && !self.config.event_type_filter.contains(&event.primary_type)
        {
            debug!(
                event_type = event.primary_type.subject_suffix(),
                "skipping filtered event type"
            );
            return Ok(());
        }

        // Skip unknown events.
        if event.primary_type == AuditEventType::Unknown {
            debug!("skipping unknown event type");
            return Ok(());
        }

        // Map to fact JSON.
        let mut fact = match map_event(event) {
            Some(f) => f,
            None => {
                debug!("mapper returned None, skipping");
                return Ok(());
            }
        };

        // Inject SPIFFE workload identity into the fact if available.
        if let Some(ref spiffe_id) = self.spiffe_id {
            fact["spiffe_id"] = serde_json::Value::String(spiffe_id.clone());
        }

        let subject = format!("{NATS_SUBJECT_PREFIX}.{}.v1", event.subject_suffix());
        let publish_context = PublishContext {
            chain_state: &self.chain_state,
            keypair: &self.keypair,
            nats_client: &self.nats_client,
            js: &self.js,
            outbox: self.outbox.as_deref(),
            metrics: &self.metrics,
        };
        let publish_request = PublishRequest::new(subject.clone(), fact)
            .with_forced_failure(self.config.force_publish_failures);

        let seq = publish_fact(&publish_context, publish_request)
            .await
            .map_err(map_publish_error)?;

        debug!(
            subject,
            seq,
            event_type = event.primary_type.subject_suffix(),
            serial = event.serial,
            "published envelope"
        );

        Ok(())
    }

    /// Get the NATS JetStream context (for testing or advanced usage).
    pub fn jetstream(&self) -> &async_nats::jetstream::Context {
        &self.js
    }

    /// Get the keypair issuer string.
    pub fn issuer(&self) -> String {
        spine::issuer_from_keypair(&self.keypair)
    }
}

fn map_publish_error(err: PublishError) -> Error {
    match err {
        PublishError::Config(message) => Error::Config(message),
        PublishError::Spine(err) => Error::Spine(err),
        PublishError::Json(err) => Error::Json(err),
        PublishError::Publish(message) => Error::Nats(message),
        PublishError::Outbox(message) => Error::Config(message),
    }
}
