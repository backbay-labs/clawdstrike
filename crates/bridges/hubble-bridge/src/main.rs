//! CLI entry point for the hubble-bridge.

use std::time::Duration;

use clap::Parser;
use tracing::{error, warn};
use tracing_subscriber::EnvFilter;

use hubble_bridge::{hubble::FlowVerdict, Bridge, BridgeConfig};

/// Hubble-to-NATS bridge: publishes signed Spine envelopes from Cilium
/// network flow events.
#[derive(Parser, Debug)]
#[command(name = "hubble-bridge", version, about)]
struct Cli {
    /// Hubble Relay gRPC endpoint.
    #[arg(
        long,
        default_value = "http://hubble-relay.kube-system.svc.cluster.local:4245",
        env = "HUBBLE_ENDPOINT"
    )]
    hubble_endpoint: String,

    /// NATS server URL.
    #[arg(long, default_value = "nats://localhost:4222", env = "NATS_URL")]
    nats_url: String,

    /// Hex-encoded Ed25519 seed for envelope signing.
    /// If omitted, an ephemeral keypair is generated.
    #[arg(env = "SIGNING_KEY")]
    signing_key: Option<String>,

    /// Only forward flows involving these Kubernetes namespaces (comma-separated).
    /// If omitted, flows from all namespaces are forwarded.
    #[arg(long, value_delimiter = ',', env = "NAMESPACE_ALLOWLIST")]
    namespace_allowlist: Vec<String>,

    /// Verdict types to include (comma-separated).
    /// Valid: forwarded, dropped, error, audit, redirected
    /// If omitted, all verdicts are forwarded.
    #[arg(long, value_delimiter = ',', env = "VERDICT_FILTER")]
    verdict_filter: Vec<String>,

    /// Number of JetStream replicas for the envelope stream.
    #[arg(long, default_value = "1", env = "STREAM_REPLICAS")]
    stream_replicas: usize,

    /// Maximum bytes retained for the Hubble JetStream stream (0 = unlimited).
    #[arg(long, default_value = "1073741824", env = "STREAM_MAX_BYTES")]
    stream_max_bytes: i64,

    /// Maximum age retained for the Hubble JetStream stream in seconds (0 = unlimited).
    #[arg(long, default_value = "86400", env = "STREAM_MAX_AGE_SECONDS")]
    stream_max_age_seconds: u64,

    /// Maximum startup wait for NATS connectivity before backing off and retrying.
    #[arg(long, default_value = "90", env = "NATS_STARTUP_TIMEOUT_SECS")]
    nats_startup_timeout_secs: u64,

    /// Path to SPIFFE SVID PEM file. When set, the bridge reads the workload
    /// SPIFFE ID and includes it in every published fact.
    #[arg(long, env = "SVID_PATH")]
    svid_path: Option<String>,

    /// Admin HTTP listen address for /healthz, /readyz, /metrics.
    #[arg(long, default_value = "0.0.0.0:2112", env = "ADMIN_LISTEN_ADDR")]
    admin_listen_addr: String,

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

fn parse_verdicts(verdicts: &[String]) -> Vec<FlowVerdict> {
    verdicts
        .iter()
        .filter_map(|v| match v.trim().to_lowercase().as_str() {
            "forwarded" => Some(FlowVerdict::Forwarded),
            "dropped" => Some(FlowVerdict::Dropped),
            "error" => Some(FlowVerdict::Error),
            "audit" => Some(FlowVerdict::Audit),
            "redirected" => Some(FlowVerdict::Redirected),
            other => {
                eprintln!("warning: unknown verdict '{other}', ignoring");
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
                .unwrap_or_else(|_| EnvFilter::new("hubble_bridge=info")),
        )
        .init();

    let cli = Cli::parse();

    let config = BridgeConfig {
        hubble_endpoint: cli.hubble_endpoint,
        nats_url: cli.nats_url,
        signing_key_hex: cli.signing_key,
        namespace_allowlist: cli.namespace_allowlist,
        verdict_filter: parse_verdicts(&cli.verdict_filter),
        stream_replicas: cli.stream_replicas,
        stream_max_bytes: cli.stream_max_bytes,
        stream_max_age_seconds: cli.stream_max_age_seconds,
        svid_path: cli.svid_path,
        admin_listen_addr: cli.admin_listen_addr,
        outbox_enabled: cli.outbox_enabled,
        outbox_path: cli.outbox_path,
        outbox_flush_interval_ms: cli.outbox_flush_interval_ms,
        outbox_max_pending: cli.outbox_max_pending,
        outbox_retry_base_ms: cli.outbox_retry_base_ms,
        outbox_retry_max_ms: cli.outbox_retry_max_ms,
        readiness_outbox_degraded_threshold: cli.readiness_outbox_degraded_threshold,
        force_publish_failures: cli.force_publish_failures,
        ..BridgeConfig::default()
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
                        warn!("bridge stream ended, reconnecting...");
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
