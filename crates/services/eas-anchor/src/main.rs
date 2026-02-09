//! EAS Anchor Service — batches AegisNet checkpoint hashes into
//! Ethereum Attestation Service attestations on Base L2.
//!
//! Usage:
//!   eas-anchor --config path/to/eas-anchor.toml
//!
//! The service subscribes to NATS checkpoint envelopes and periodically
//! submits batched `multiAttest()` transactions to the EAS contract on Base.

use std::path::PathBuf;

use clap::Parser;

use eas_anchor::config::AnchorConfig;
use eas_anchor::eas_client::EasClient;
use eas_anchor::error::Result;

/// EAS Anchor Service for ClawdStrike.
#[derive(Parser, Debug)]
#[command(name = "eas-anchor")]
#[command(about = "Batches Spine checkpoint hashes into EAS attestations on Base L2")]
struct Cli {
    /// Path to the TOML configuration file.
    #[arg(short, long, env = "EAS_ANCHOR_CONFIG")]
    config: PathBuf,
}

#[tokio::main]
async fn main() -> std::result::Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    let cli = Cli::parse();
    run(cli).await.map_err(|e| e.into())
}

async fn run(cli: Cli) -> Result<()> {
    let config = AnchorConfig::load(&cli.config)?;

    tracing::info!(
        chain_id = config.chain.chain_id,
        eas_contract = %config.chain.eas_contract,
        max_batch_size = config.batching.max_batch_size,
        batch_interval_secs = config.batching.batch_interval_secs,
        nats_url = %config.nats.url,
        nats_subject = %config.nats.subject,
        "Starting EAS anchor service"
    );

    let client = EasClient::new(&config)?;

    tracing::info!(
        eas_address = %client.eas_address(),
        checkpoint_schema = %client.checkpoint_schema_uid(),
        "EAS client initialized"
    );

    eas_anchor::nats_sub::run_subscription(&config, &client).await
}
