//! CLI entry point for the hubble-bridge.
//!
//! ```text
//! hubble-bridge \
//!   --hubble-endpoint http://hubble-relay.kube-system.svc.cluster.local:4245 \
//!   --nats-url nats://localhost:4222 \
//!   --signing-key 0xdeadbeef...
//! ```

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
        ..BridgeConfig::default()
    };

    let mut backoff = Duration::from_secs(1);
    loop {
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
