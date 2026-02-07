//! ClawdStrike Spine witness signer.
//!
//! NATS RPC service on `clawdstrike.spine.witness.sign.v1`. Receives checkpoint
//! statements, validates them, co-signs with own keypair, and returns witness
//! signatures.

use std::path::PathBuf;

use anyhow::{Context, Result};
use clap::Parser;
use futures::StreamExt;
use tokio::signal;
use tracing::info;
use tracing_subscriber::{fmt, EnvFilter};

use hush_core::Keypair;
use spine::{checkpoint, nats_transport as nats, TrustBundle};

#[derive(Parser, Debug)]
#[command(name = "spine-witness")]
#[command(about = "ClawdStrike Spine witness signer (co-signs checkpoint statements)")]
struct Args {
    /// NATS server URL
    #[arg(long, env = "NATS_URL", default_value = "nats://localhost:4222")]
    nats_url: String,

    /// NATS subject for checkpoint signature requests
    #[arg(long, default_value = "clawdstrike.spine.witness.sign.v1")]
    request_subject: String,

    /// Hex-encoded 32-byte Ed25519 seed for the witness key (env only)
    #[arg(env = "SPINE_WITNESS_SEED_HEX")]
    witness_seed_hex: String,

    /// Trust bundle JSON (optional; restricts which logs this witness will sign for)
    #[arg(long, env = "SPINE_TRUST_BUNDLE")]
    trust_bundle: Option<PathBuf>,
}

#[tokio::main]
async fn main() -> Result<()> {
    fmt()
        .with_env_filter(EnvFilter::from_default_env().add_directive("info".parse()?))
        .with_target(false)
        .init();

    let args = Args::parse();
    let witness_keypair = Keypair::from_hex(&spine::normalize_seed_hex(&args.witness_seed_hex))
        .context("invalid SPINE_WITNESS_SEED_HEX")?;
    let witness_node_id = spine::issuer_from_keypair(&witness_keypair);

    let trust_bundle = match &args.trust_bundle {
        Some(path) => Some(TrustBundle::load(path)?),
        None => None,
    };
    if let Some(tb) = trust_bundle.as_ref() {
        if !tb.witness_allowed(&witness_node_id) {
            anyhow::bail!("witness_node_id not allowed by trust bundle: {witness_node_id}");
        }
    }

    info!(
        "starting witness node_id={} nats={}",
        witness_node_id, args.nats_url
    );

    let client = nats::connect(&args.nats_url).await?;
    let mut sub = client
        .subscribe(args.request_subject.clone())
        .await
        .context("failed to subscribe")?;

    loop {
        tokio::select! {
            _ = signal::ctrl_c() => {
                break;
            }
            msg = sub.next() => {
                let Some(msg) = msg else { break; };
                let reply = match msg.reply.clone() {
                    Some(r) => r,
                    None => continue,
                };
                let statement: serde_json::Value = match serde_json::from_slice(&msg.payload) {
                    Ok(v) => v,
                    Err(_) => continue,
                };
                if statement.get("schema").and_then(|v| v.as_str())
                    != Some(checkpoint::CHECKPOINT_STATEMENT_SCHEMA_V1)
                {
                    continue;
                }
                let log_id = match statement.get("log_id").and_then(|v| v.as_str()) {
                    Some(v) => v,
                    None => continue,
                };
                if let Some(tb) = trust_bundle.as_ref() {
                    if !tb.log_id_allowed(log_id) {
                        continue;
                    }
                }
                let signed = match checkpoint::sign_checkpoint_statement(
                    &witness_keypair,
                    &statement,
                ) {
                    Ok(v) => v,
                    Err(_) => continue,
                };
                let payload = serde_json::to_vec(&signed)?;
                client.publish(reply, payload.into()).await?;
            }
        }
    }

    Ok(())
}
