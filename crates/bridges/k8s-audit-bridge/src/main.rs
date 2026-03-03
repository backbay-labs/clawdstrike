//! CLI entry point for the k8s-audit-bridge.

use std::time::Duration;

use clap::Parser;
use tracing::{error, warn};
use tracing_subscriber::EnvFilter;

use k8s_audit_bridge::{webhook::AuditVerb, Bridge, BridgeConfig};

/// K8s-audit-to-NATS bridge: publishes signed Spine envelopes from Kubernetes
/// API server audit events received via webhook.
#[derive(Parser, Debug)]
#[command(name = "k8s-audit-bridge", version, about)]
struct Cli {
    /// HTTP listen address for the webhook receiver.
    #[arg(long, default_value = "0.0.0.0:9877", env = "LISTEN_ADDR")]
    listen_addr: String,

    /// NATS server URL.
    #[arg(long, default_value = "nats://localhost:4222", env = "NATS_URL")]
    nats_url: String,

    /// Hex-encoded Ed25519 seed for envelope signing.
    /// If omitted, an ephemeral keypair is generated.
    #[arg(env = "SIGNING_KEY")]
    signing_key: Option<String>,

    /// Only forward events from these Kubernetes namespaces (comma-separated).
    /// If omitted, events from all namespaces are forwarded.
    #[arg(long, value_delimiter = ',', env = "NAMESPACE_ALLOWLIST")]
    namespace_allowlist: Vec<String>,

    /// Verb types to include (comma-separated).
    /// Valid: create, update, delete, patch, get, list, watch, exec
    /// If omitted, all verbs are forwarded.
    #[arg(long, value_delimiter = ',', env = "VERB_FILTER")]
    verb_filter: Vec<String>,

    /// Resource types to include (comma-separated).
    /// If omitted, all resources are forwarded.
    #[arg(long, value_delimiter = ',', env = "RESOURCE_FILTER")]
    resource_filter: Vec<String>,

    /// Number of JetStream replicas for the envelope stream.
    #[arg(long, default_value = "1", env = "STREAM_REPLICAS")]
    stream_replicas: usize,

    /// Maximum bytes retained for the K8s audit JetStream stream (0 = unlimited).
    #[arg(long, default_value = "1073741824", env = "STREAM_MAX_BYTES")]
    stream_max_bytes: i64,

    /// Maximum age retained for the K8s audit JetStream stream in seconds (0 = unlimited).
    #[arg(long, default_value = "86400", env = "STREAM_MAX_AGE_SECONDS")]
    stream_max_age_seconds: u64,

    /// Maximum startup wait for NATS connectivity before backing off and retrying.
    #[arg(long, default_value = "90", env = "NATS_STARTUP_TIMEOUT_SECS")]
    nats_startup_timeout_secs: u64,

    /// Path to SPIFFE SVID PEM file. When set, the bridge reads the workload
    /// SPIFFE ID and includes it in every published fact.
    #[arg(long, env = "SVID_PATH")]
    svid_path: Option<String>,

    /// Enable durable SQLite outbox retry queue.
    #[arg(long, default_value = "false", env = "OUTBOX_ENABLED")]
    outbox_enabled: bool,

    /// SQLite path for durable outbox state.
    #[arg(long, env = "OUTBOX_PATH")]
    outbox_path: Option<String>,

    /// Outbox worker flush interval in milliseconds.
    #[arg(long, default_value = "1000", env = "OUTBOX_FLUSH_INTERVAL_MS")]
    outbox_flush_interval_ms: u64,

    /// Maximum pending outbox rows before enqueue rejects.
    #[arg(long, default_value = "10000", env = "OUTBOX_MAX_PENDING")]
    outbox_max_pending: u64,

    /// Initial retry backoff in milliseconds.
    #[arg(long, default_value = "500", env = "OUTBOX_RETRY_BASE_MS")]
    outbox_retry_base_ms: u64,

    /// Maximum retry backoff in milliseconds.
    #[arg(long, default_value = "30000", env = "OUTBOX_RETRY_MAX_MS")]
    outbox_retry_max_ms: u64,

    /// Readiness degrades when outbox pending exceeds this threshold.
    #[arg(
        long,
        default_value = "100",
        env = "READINESS_OUTBOX_DEGRADED_THRESHOLD"
    )]
    readiness_outbox_degraded_threshold: u64,

    /// Test-only failpoint to force publish failures.
    #[arg(long, default_value = "false", env = "FORCE_PUBLISH_FAILURES")]
    force_publish_failures: bool,
}

fn parse_verbs(verbs: &[String]) -> Vec<AuditVerb> {
    verbs
        .iter()
        .filter_map(|v| match v.trim().to_lowercase().as_str() {
            "create" => Some(AuditVerb::Create),
            "update" => Some(AuditVerb::Update),
            "delete" => Some(AuditVerb::Delete),
            "patch" => Some(AuditVerb::Patch),
            "get" => Some(AuditVerb::Get),
            "list" => Some(AuditVerb::List),
            "watch" => Some(AuditVerb::Watch),
            "exec" => Some(AuditVerb::Exec),
            other => {
                eprintln!("warning: unknown verb '{other}', ignoring");
                None
            }
        })
        .collect()
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| EnvFilter::new("k8s_audit_bridge=info")),
        )
        .init();

    let cli = Cli::parse();

    let config = BridgeConfig {
        listen_addr: cli.listen_addr,
        nats_url: cli.nats_url,
        signing_key_hex: cli.signing_key,
        namespace_allowlist: cli.namespace_allowlist,
        verb_filter: parse_verbs(&cli.verb_filter),
        resource_filter: cli.resource_filter,
        stream_replicas: cli.stream_replicas,
        stream_max_bytes: cli.stream_max_bytes,
        stream_max_age_seconds: cli.stream_max_age_seconds,
        svid_path: cli.svid_path,
        outbox_enabled: cli.outbox_enabled,
        outbox_path: cli.outbox_path,
        outbox_flush_interval_ms: cli.outbox_flush_interval_ms,
        outbox_max_pending: cli.outbox_max_pending,
        outbox_retry_base_ms: cli.outbox_retry_base_ms,
        outbox_retry_max_ms: cli.outbox_retry_max_ms,
        readiness_outbox_degraded_threshold: cli.readiness_outbox_degraded_threshold,
        force_publish_failures: cli.force_publish_failures,
    };

    let mut backoff = Duration::from_secs(1);
    loop {
        let startup_timeout = Duration::from_secs(cli.nats_startup_timeout_secs);
        if let Err(e) =
            bridge_runtime::wait_for_nats_startup(&config.nats_url, startup_timeout).await
        {
            warn!(error = %e, "NATS startup readiness check failed, retrying");
            warn!(
                backoff_secs = backoff.as_secs(),
                "reconnecting after backoff"
            );
            tokio::time::sleep(backoff).await;
            backoff = (backoff * 2).min(Duration::from_secs(60));
            continue;
        }

        match Bridge::new(config.clone()).await {
            Ok(bridge) => {
                backoff = Duration::from_secs(1);
                match bridge.run().await {
                    Ok(()) => {
                        warn!("bridge server ended, reconnecting...");
                    }
                    Err(e) => {
                        error!(error = %e, "bridge error, reconnecting...");
                    }
                }
            }
            Err(e) => {
                error!(error = %e, "failed to create bridge");
            }
        }
        warn!(
            backoff_secs = backoff.as_secs(),
            "reconnecting after backoff"
        );
        tokio::time::sleep(backoff).await;
        backoff = (backoff * 2).min(Duration::from_secs(60));
    }
}
