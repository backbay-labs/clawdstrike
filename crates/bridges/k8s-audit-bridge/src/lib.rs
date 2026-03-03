#![cfg_attr(test, allow(clippy::expect_used, clippy::unwrap_used))]

//! # k8s-audit-bridge
//!
//! Receives Kubernetes API server audit webhooks and publishes them as signed
//! Spine envelopes to NATS JetStream.

pub mod error;
pub mod mapper;
pub mod webhook;

use std::sync::Arc;
use std::time::Duration;

use axum::body::Bytes;
use axum::extract::State;
use axum::http::header::CONTENT_TYPE;
use axum::http::{HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use bridge_runtime::{
    publish_fact, spawn_outbox_worker, BridgeMetrics, ChainState, OutboxConfig, PublishContext,
    PublishError, PublishRequest, SqliteOutbox,
};
use hush_core::Keypair;
use tokio::sync::Mutex;
use tracing::{debug, error, info, warn};

use crate::error::{Error, Result};
use crate::mapper::map_event;
use crate::webhook::{parse_webhook_payload, AuditEvent, AuditVerb};

/// NATS subject prefix for all K8s audit bridge envelopes.
const NATS_SUBJECT_PREFIX: &str = "clawdstrike.spine.envelope.k8s_audit";

/// NATS JetStream stream name.
const STREAM_NAME: &str = "CLAWDSTRIKE_K8S_AUDIT";

/// Configuration for the bridge.
#[derive(Debug, Clone)]
pub struct BridgeConfig {
    /// HTTP listen address (e.g. `0.0.0.0:9877`).
    pub listen_addr: String,
    /// NATS server URL (e.g. `nats://localhost:4222`).
    pub nats_url: String,
    /// Hex-encoded Ed25519 seed for signing envelopes.
    /// If empty, a random keypair is generated.
    pub signing_key_hex: Option<String>,
    /// Only forward events from these namespaces.
    /// If empty, all namespaces are forwarded.
    pub namespace_allowlist: Vec<String>,
    /// Only forward these verbs.
    /// If empty, all verbs are forwarded.
    pub verb_filter: Vec<AuditVerb>,
    /// Only forward events for these resources.
    /// If empty, all resources are forwarded.
    pub resource_filter: Vec<String>,
    /// Number of JetStream replicas for the stream.
    pub stream_replicas: usize,
    /// Maximum bytes retained in the JetStream stream (0 = unlimited).
    pub stream_max_bytes: i64,
    /// Maximum age retained in the JetStream stream in seconds (0 = unlimited).
    pub stream_max_age_seconds: u64,
    /// Path to SPIFFE SVID PEM file. When set, the bridge reads the workload
    /// SPIFFE ID and includes it in every published fact.
    pub svid_path: Option<String>,
    /// Enable local durable outbox enqueue/retry on publish failures.
    pub outbox_enabled: bool,
    /// Optional SQLite path for outbox persistence.
    pub outbox_path: Option<String>,
    /// Outbox worker poll interval.
    pub outbox_flush_interval_ms: u64,
    /// Maximum pending rows before enqueue rejects.
    pub outbox_max_pending: u64,
    /// Initial retry backoff after failed publish.
    pub outbox_retry_base_ms: u64,
    /// Maximum retry backoff.
    pub outbox_retry_max_ms: u64,
    /// Readiness degrades when outbox pending exceeds this threshold.
    pub readiness_outbox_degraded_threshold: u64,
    /// Test-only flag to force publish failure path.
    pub force_publish_failures: bool,
}

impl Default for BridgeConfig {
    fn default() -> Self {
        Self {
            listen_addr: "0.0.0.0:9877".to_string(),
            nats_url: "nats://localhost:4222".to_string(),
            signing_key_hex: None,
            namespace_allowlist: Vec::new(),
            verb_filter: Vec::new(),
            resource_filter: Vec::new(),
            stream_replicas: 1,
            stream_max_bytes: 1_073_741_824,
            stream_max_age_seconds: 86_400,
            svid_path: None,
            outbox_enabled: false,
            outbox_path: Some("/tmp/k8s-audit-bridge-outbox.db".to_string()),
            outbox_flush_interval_ms: 1000,
            outbox_max_pending: 10_000,
            outbox_retry_base_ms: 500,
            outbox_retry_max_ms: 30_000,
            readiness_outbox_degraded_threshold: 100,
            force_publish_failures: false,
        }
    }
}

/// Shared bridge state passed to axum handlers via `Arc`.
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

        let metrics = Arc::new(BridgeMetrics::new("k8s-audit-bridge"));
        metrics.set_nats_connected(
            nats_client.connection_state() == async_nats::connection::State::Connected,
        );

        let outbox = if config.outbox_enabled {
            let outbox_cfg = OutboxConfig {
                path: config
                    .outbox_path
                    .clone()
                    .unwrap_or_else(|| "/tmp/k8s-audit-bridge-outbox.db".to_string()),
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

    /// Run the bridge HTTP server.
    pub async fn run(self) -> Result<()> {
        let listen_addr = self.config.listen_addr.clone();
        let bridge = Arc::new(self);

        let outbox_worker = bridge.outbox.as_ref().map(|outbox| {
            spawn_outbox_worker(
                "k8s-audit-bridge".to_string(),
                outbox.clone(),
                bridge.nats_client.clone(),
                bridge.js.clone(),
                bridge.metrics.clone(),
                Duration::from_millis(bridge.config.outbox_flush_interval_ms),
            )
        });

        let app = Router::new()
            .route("/webhook", post(handle_webhook))
            .route("/healthz", get(handle_healthz))
            .route("/readyz", get(handle_readyz))
            .route("/metrics", get(handle_metrics))
            .with_state(bridge.clone());

        info!(listen_addr = %listen_addr, "starting K8s audit webhook server");

        let listener = tokio::net::TcpListener::bind(&listen_addr)
            .await
            .map_err(|e| Error::Http(format!("failed to bind {listen_addr}: {e}")))?;

        let result = axum::serve(listener, app)
            .await
            .map_err(|e| Error::Http(format!("server error: {e}")));

        if let Some(handle) = outbox_worker {
            handle.abort();
        }

        result
    }

    /// Handle a single K8s audit event: filter, map, sign, publish.
    async fn handle_event(&self, event: &AuditEvent) -> Result<()> {
        // Verb filter: if configured, only forward matching verbs.
        if !self.config.verb_filter.is_empty() && !self.config.verb_filter.contains(&event.verb) {
            debug!(verb = event.verb.subject_suffix(), "skipping filtered verb");
            return Ok(());
        }

        // Skip unknown verbs.
        if event.verb == AuditVerb::Unknown {
            debug!("skipping unknown verb");
            return Ok(());
        }

        // Namespace filter.
        if !self.config.namespace_allowlist.is_empty() {
            let event_ns = event
                .object_ref
                .as_ref()
                .map(|r| r.namespace.as_str())
                .unwrap_or("");
            if !self
                .config
                .namespace_allowlist
                .iter()
                .any(|ns| ns.eq_ignore_ascii_case(event_ns))
            {
                debug!(
                    namespace = event_ns,
                    "skipping event outside namespace allowlist"
                );
                return Ok(());
            }
        }

        // Resource filter.
        if !self.config.resource_filter.is_empty() {
            let event_resource = event
                .object_ref
                .as_ref()
                .map(|r| r.resource.as_str())
                .unwrap_or("");
            if !self
                .config
                .resource_filter
                .iter()
                .any(|r| r.eq_ignore_ascii_case(event_resource))
            {
                debug!(resource = event_resource, "skipping filtered resource");
                return Ok(());
            }
        }

        // Map to fact JSON.
        let mut fact = map_event(event);

        // Inject SPIFFE workload identity into the fact if available.
        if let Some(ref spiffe_id) = self.spiffe_id {
            fact["spiffe_id"] = serde_json::Value::String(spiffe_id.clone());
        }

        let subject = format!("{NATS_SUBJECT_PREFIX}.{}.v1", event.verb.subject_suffix());

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
            verb = event.verb.subject_suffix(),
            audit_id = %event.audit_id,
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

/// Axum handler for the webhook endpoint.
async fn handle_webhook(State(bridge): State<Arc<Bridge>>, body: Bytes) -> impl IntoResponse {
    let events = match parse_webhook_payload(&body) {
        Ok(events) => events,
        Err(e) => {
            warn!(error = %e, "failed to parse webhook payload");
            return StatusCode::BAD_REQUEST;
        }
    };

    let mut errors = 0u64;
    let mut successes = 0u64;
    for event in &events {
        if let Err(e) = bridge.handle_event(event).await {
            error!(
                error = %e,
                audit_id = %event.audit_id,
                "failed to handle audit event"
            );
            errors += 1;
        } else {
            successes += 1;
        }
    }

    let status = decide_webhook_status(successes, errors);
    if status == StatusCode::SERVICE_UNAVAILABLE {
        warn!(errors, total = events.len(), "all events failed to process");
        bridge.metrics.inc_webhook_5xx();
    } else if errors > 0 {
        warn!(
            errors,
            successes,
            total = events.len(),
            "partial batch failure; returning 200 to avoid duplicate replay of already-published events"
        );
    }

    status
}

/// Decide webhook response status from per-batch processing outcomes.
///
/// If at least one event was already published, return 200 to prevent K8s from
/// retrying the entire batch and duplicating previously published envelopes.
fn decide_webhook_status(successes: u64, errors: u64) -> StatusCode {
    if errors == 0 || successes > 0 {
        StatusCode::OK
    } else {
        StatusCode::SERVICE_UNAVAILABLE
    }
}

/// Axum handler for health check.
async fn handle_healthz() -> impl IntoResponse {
    StatusCode::OK
}

/// Axum handler for readiness check.
async fn handle_readyz(State(bridge): State<Arc<Bridge>>) -> impl IntoResponse {
    let readiness = bridge
        .metrics
        .readiness(bridge.config.readiness_outbox_degraded_threshold);
    let code = if readiness.status == "ready" {
        StatusCode::OK
    } else {
        StatusCode::SERVICE_UNAVAILABLE
    };
    (code, Json(readiness))
}

/// Axum handler for Prometheus metrics.
async fn handle_metrics(State(bridge): State<Arc<Bridge>>) -> Response {
    let body = bridge
        .metrics
        .render_prometheus(bridge.config.readiness_outbox_degraded_threshold);
    (
        [(
            CONTENT_TYPE,
            HeaderValue::from_static("text/plain; version=0.0.4"),
        )],
        body,
    )
        .into_response()
}

#[cfg(test)]
mod tests {
    use super::decide_webhook_status;
    use axum::http::StatusCode;

    #[test]
    fn webhook_status_ok_when_all_events_succeed() {
        assert_eq!(decide_webhook_status(3, 0), StatusCode::OK);
    }

    #[test]
    fn webhook_status_ok_on_partial_success_to_avoid_batch_replay() {
        assert_eq!(decide_webhook_status(2, 1), StatusCode::OK);
    }

    #[test]
    fn webhook_status_503_when_entire_batch_fails() {
        assert_eq!(decide_webhook_status(0, 2), StatusCode::SERVICE_UNAVAILABLE);
    }
}
