//! E2E test binary: sign and publish posture commands to NATS as Spine envelopes.
//!
//! Usage:
//!   e2e-posture-cmd \
//!     --seed-hex /tmp/clawdstrike-approval.key \
//!     --nats-url nats://localhost:4222 \
//!     --subject "tenant-localdev.clawdstrike.posture.command.agent-xxx" \
//!     --command set_posture --posture restricted

use std::time::Duration;

use clap::{Parser, ValueEnum};

#[derive(Parser)]
#[command(about = "Send signed posture commands to agents via NATS")]
struct Cli {
    /// Path to a file containing the 32-byte signing seed as 64 hex chars.
    #[arg(long)]
    seed_hex: String,

    /// NATS server URL.
    #[arg(long, default_value = "nats://localhost:4222")]
    nats_url: String,

    /// NATS subject to publish the command on.
    #[arg(long)]
    subject: String,

    /// Posture command to send.
    #[arg(long)]
    command: PostureCommand,

    /// Target posture level (required for set_posture).
    #[arg(long)]
    posture: Option<String>,

    /// Reason string (optional, used with kill_switch).
    #[arg(long)]
    reason: Option<String>,

    /// Timeout in seconds for the NATS request-reply.
    #[arg(long, default_value = "10")]
    timeout_secs: u64,
}

#[derive(Clone, ValueEnum)]
enum PostureCommand {
    SetPosture,
    KillSwitch,
    RequestPolicyReload,
}

fn load_keypair(path: &str) -> anyhow::Result<hush_core::Keypair> {
    let contents = std::fs::read_to_string(path)
        .map_err(|e| anyhow::anyhow!("failed to read seed file {path}: {e}"))?;
    let hex_seed = contents.trim();
    let keypair = hush_core::Keypair::from_hex(hex_seed)
        .map_err(|e| anyhow::anyhow!("invalid seed hex in {path}: {e}"))?;
    Ok(keypair)
}

/// Build the envelope fact matching the agent's `PostureCommand` serde format:
/// `#[serde(tag = "command", rename_all = "snake_case")]`
fn build_fact(cli: &Cli) -> anyhow::Result<serde_json::Value> {
    match cli.command {
        PostureCommand::SetPosture => {
            let posture = cli
                .posture
                .as_deref()
                .ok_or_else(|| anyhow::anyhow!("--posture is required for set_posture"))?;
            Ok(serde_json::json!({
                "command": "set_posture",
                "posture": posture,
            }))
        }
        PostureCommand::KillSwitch => {
            let reason = cli.reason.as_deref();
            let mut fact = serde_json::json!({ "command": "kill_switch" });
            if let Some(r) = reason {
                fact["reason"] = serde_json::json!(r);
            }
            Ok(fact)
        }
        PostureCommand::RequestPolicyReload => Ok(serde_json::json!({
            "command": "request_policy_reload",
        })),
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    let keypair = load_keypair(&cli.seed_hex)?;
    let fact = build_fact(&cli)?;

    let envelope =
        spine::build_signed_envelope(&keypair, 0, None, fact, spine::now_rfc3339())
            .map_err(|e| anyhow::anyhow!("failed to build signed envelope: {e}"))?;

    let payload = serde_json::to_vec(&envelope)
        .map_err(|e| anyhow::anyhow!("failed to serialize envelope: {e}"))?;

    eprintln!("Connecting to {}...", cli.nats_url);
    let client = spine::nats_transport::connect(&cli.nats_url).await
        .map_err(|e| anyhow::anyhow!("NATS connection failed: {e}"))?;

    eprintln!("Publishing to subject: {}", cli.subject);
    eprintln!(
        "Envelope hash: {}",
        envelope
            .get("envelope_hash")
            .and_then(|v| v.as_str())
            .unwrap_or("(none)")
    );

    let timeout = Duration::from_secs(cli.timeout_secs);

    match tokio::time::timeout(
        timeout,
        client.request(cli.subject.clone(), payload.into()),
    )
    .await
    {
        Ok(Ok(response)) => {
            let body = String::from_utf8_lossy(&response.payload);
            println!("{body}");
        }
        Ok(Err(e)) => {
            eprintln!("No responders on subject — falling back to fire-and-forget publish...");
            eprintln!("  (error: {e})");
            client
                .publish(cli.subject, serde_json::to_vec(&envelope)?.into())
                .await
                .map_err(|e| anyhow::anyhow!("NATS publish error: {e}"))?;
            client.flush().await.map_err(|e| anyhow::anyhow!("NATS flush error: {e}"))?;
            println!("{{\"status\":\"published\",\"message\":\"command sent (no responder)\"}}");
        }
        Err(_) => {
            // request() already published the message — it just didn't get a reply.
            // Do NOT re-publish to avoid duplicate delivery (especially dangerous for
            // non-idempotent commands like kill_switch).
            eprintln!(
                "No reply within {}s — command was delivered but no subscriber responded.",
                cli.timeout_secs
            );
            eprintln!("This is expected if the agent is not listening on {}", cli.subject);
            println!("{{\"status\":\"delivered\",\"message\":\"command sent, no reply within timeout\"}}");
        }
    }

    Ok(())
}
