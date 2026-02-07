//! CLI entry point for the tetragon-bridge.
//!
//! ```text
//! tetragon-bridge \
//!   --tetragon-endpoint http://localhost:54321 \
//!   --nats-url nats://localhost:4222 \
//!   --signing-key 0xdeadbeef...
//! ```

use clap::Parser;
use tracing_subscriber::EnvFilter;

use tetragon_bridge::{tetragon::TetragonEventKind, Bridge, BridgeConfig};

/// Tetragon-to-NATS bridge: publishes signed Spine envelopes from Tetragon
/// runtime events.
#[derive(Parser, Debug)]
#[command(name = "tetragon-bridge", version, about)]
struct Cli {
    /// Tetragon gRPC endpoint.
    #[arg(
        long,
        default_value = "http://localhost:54321",
        env = "TETRAGON_ENDPOINT"
    )]
    tetragon_endpoint: String,

    /// NATS server URL.
    #[arg(long, default_value = "nats://localhost:4222", env = "NATS_URL")]
    nats_url: String,

    /// Hex-encoded Ed25519 seed for envelope signing.
    /// If omitted, an ephemeral keypair is generated.
    #[arg(long, env = "SIGNING_KEY")]
    signing_key: Option<String>,

    /// Only forward events from these Kubernetes namespaces (comma-separated).
    /// If omitted, events from all namespaces are forwarded.
    #[arg(long, value_delimiter = ',', env = "NAMESPACE_ALLOWLIST")]
    namespace_allowlist: Vec<String>,

    /// Event types to subscribe to (comma-separated).
    /// Valid: process_exec, process_exit, process_kprobe
    #[arg(
        long,
        value_delimiter = ',',
        default_value = "process_exec,process_exit,process_kprobe"
    )]
    event_types: Vec<String>,

    /// Number of JetStream replicas for the envelope stream.
    #[arg(long, default_value = "1", env = "STREAM_REPLICAS")]
    stream_replicas: usize,
}

fn parse_event_types(types: &[String]) -> Vec<TetragonEventKind> {
    types
        .iter()
        .filter_map(|t| match t.trim() {
            "process_exec" => Some(TetragonEventKind::ProcessExec),
            "process_exit" => Some(TetragonEventKind::ProcessExit),
            "process_kprobe" => Some(TetragonEventKind::ProcessKprobe),
            other => {
                eprintln!("warning: unknown event type '{other}', ignoring");
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
                .unwrap_or_else(|_| EnvFilter::new("tetragon_bridge=info")),
        )
        .init();

    let cli = Cli::parse();

    let config = BridgeConfig {
        tetragon_endpoint: cli.tetragon_endpoint,
        nats_url: cli.nats_url,
        signing_key_hex: cli.signing_key,
        namespace_allowlist: cli.namespace_allowlist,
        event_types: parse_event_types(&cli.event_types),
        stream_replicas: cli.stream_replicas,
    };

    let bridge = Bridge::new(config).await?;
    bridge.run().await?;

    Ok(())
}
