//! Audit monitor for the clawdstrike package registry transparency log.
//!
//! Polls the registry's transparency checkpoint endpoint and verifies
//! consistency proofs whenever the tree grows, alerting on any violation
//! of the append-only property.

use std::path::PathBuf;

use clap::Parser;
use clawdstrike::pkg::merkle::{verify_consistency_proof_full, ConsistencyProof};
use hush_core::{PublicKey, Signature};
use serde::{Deserialize, Serialize};

/// Clawdstrike transparency log audit monitor.
#[derive(Parser)]
#[command(name = "clawdstrike-audit-monitor")]
#[command(about = "Polls the registry transparency log and verifies consistency")]
struct Cli {
    /// Base URL of the clawdstrike registry (e.g., http://localhost:3100).
    #[arg(long)]
    registry_url: String,

    /// Poll interval in seconds.
    #[arg(long, default_value = "60")]
    interval: u64,

    /// Optional webhook URL to POST alerts to.
    #[arg(long)]
    webhook_url: Option<String>,

    /// Expected registry public key hex for signed checkpoint verification.
    #[arg(long, env = "CLAWDSTRIKE_REGISTRY_PUBLIC_KEY")]
    registry_public_key: String,

    /// Path to the state file for persisting the last-seen checkpoint.
    #[arg(long)]
    state_file: Option<PathBuf>,
}

/// The checkpoint response from the registry.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct CheckpointResponse {
    root: String,
    tree_size: u64,
    timestamp: String,
    registry_sig: String,
    registry_key: String,
}

/// The consistency proof response from the registry.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct ConsistencyProofResponse {
    old_size: u64,
    new_size: u64,
    proof_path: Vec<String>,
}

/// Persisted monitor state.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct MonitorState {
    tree_size: u64,
    root: String,
    last_checked: String,
}

fn checkpoint_signature_message(root: &str, tree_size: u64, timestamp: &str) -> String {
    format!("clawdstrike-checkpoint:v1:{root}:{tree_size}:{timestamp}")
}

fn verify_checkpoint_signature(
    checkpoint: &CheckpointResponse,
    expected_registry_key: &str,
) -> anyhow::Result<()> {
    if checkpoint.registry_key != expected_registry_key {
        anyhow::bail!("checkpoint registry key mismatch with configured trust anchor");
    }
    hush_core::Hash::from_hex(&checkpoint.root)?;
    chrono::DateTime::parse_from_rfc3339(&checkpoint.timestamp)?;
    let key = PublicKey::from_hex(expected_registry_key)?;
    let sig = Signature::from_hex(&checkpoint.registry_sig)?;
    let msg = checkpoint_signature_message(
        &checkpoint.root,
        checkpoint.tree_size,
        &checkpoint.timestamp,
    );
    if !key.verify(msg.as_bytes(), &sig) {
        anyhow::bail!("checkpoint signature verification failed");
    }
    Ok(())
}

fn default_state_file() -> PathBuf {
    dirs::home_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join(".clawdstrike")
        .join("audit-monitor")
        .join("state.json")
}

fn load_state(path: &PathBuf) -> Option<MonitorState> {
    let data = std::fs::read_to_string(path).ok()?;
    serde_json::from_str(&data).ok()
}

fn save_state(path: &PathBuf, state: &MonitorState) -> anyhow::Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let json = serde_json::to_string_pretty(state)?;
    std::fs::write(path, json)?;
    Ok(())
}

async fn send_webhook_alert(webhook_url: &str, message: &str) {
    let client = reqwest::Client::new();
    let payload = serde_json::json!({
        "alert": "transparency_log_violation",
        "message": message,
        "timestamp": chrono::Utc::now().to_rfc3339(),
    });
    match client.post(webhook_url).json(&payload).send().await {
        Ok(resp) => {
            eprintln!("[audit-monitor] Webhook POST status: {}", resp.status());
        }
        Err(e) => {
            eprintln!("[audit-monitor] Failed to send webhook alert: {e}");
        }
    }
}

async fn poll_cycle(
    client: &reqwest::Client,
    registry_url: &str,
    expected_registry_key: &str,
    state_file: &PathBuf,
    webhook_url: Option<&str>,
) -> anyhow::Result<()> {
    // 1. Fetch current checkpoint.
    let checkpoint_url = format!(
        "{}/api/v1/transparency/checkpoint",
        registry_url.trim_end_matches('/')
    );
    let checkpoint: CheckpointResponse = client
        .get(&checkpoint_url)
        .send()
        .await?
        .error_for_status()?
        .json()
        .await?;

    if let Err(e) = verify_checkpoint_signature(&checkpoint, expected_registry_key) {
        let msg = format!(
            "ALERT: Invalid checkpoint signature/key for tree_size={} root={}...: {e}",
            checkpoint.tree_size,
            &checkpoint.root[..std::cmp::min(16, checkpoint.root.len())]
        );
        eprintln!("[audit-monitor] {msg}");
        if let Some(url) = webhook_url {
            send_webhook_alert(url, &msg).await;
        }
        return Ok(());
    }

    eprintln!(
        "[audit-monitor] Checkpoint: tree_size={}, root={}...",
        checkpoint.tree_size,
        &checkpoint.root[..std::cmp::min(16, checkpoint.root.len())]
    );

    // 2. Load previous state.
    let prev = load_state(state_file);

    if let Some(ref prev_state) = prev {
        if checkpoint.tree_size == prev_state.tree_size {
            eprintln!(
                "[audit-monitor] No new entries (tree_size={})",
                checkpoint.tree_size
            );
            return Ok(());
        }

        if checkpoint.tree_size < prev_state.tree_size {
            let msg = format!(
                "ALERT: Tree shrunk! Previous size={}, current size={}",
                prev_state.tree_size, checkpoint.tree_size
            );
            eprintln!("[audit-monitor] {msg}");
            if let Some(url) = webhook_url {
                send_webhook_alert(url, &msg).await;
            }
            return Ok(());
        }

        // 3. Tree grew — verify consistency.
        let consistency_url = format!(
            "{}/api/v1/transparency/consistency?old_size={}",
            registry_url.trim_end_matches('/'),
            prev_state.tree_size
        );
        let proof_resp: ConsistencyProofResponse = client
            .get(&consistency_url)
            .send()
            .await?
            .error_for_status()?
            .json()
            .await?;

        let proof = ConsistencyProof {
            old_size: proof_resp.old_size,
            new_size: proof_resp.new_size,
            proof_path: proof_resp.proof_path,
        };

        let valid = verify_consistency_proof_full(&proof, &prev_state.root, &checkpoint.root);

        if valid {
            eprintln!(
                "[audit-monitor] Consistency verified: {} -> {} entries",
                prev_state.tree_size, checkpoint.tree_size
            );
        } else {
            let msg = format!(
                "ALERT: Consistency proof FAILED! old_size={}, new_size={}, old_root={}..., new_root={}...",
                prev_state.tree_size,
                checkpoint.tree_size,
                &prev_state.root[..std::cmp::min(16, prev_state.root.len())],
                &checkpoint.root[..std::cmp::min(16, checkpoint.root.len())]
            );
            eprintln!("[audit-monitor] {msg}");
            if let Some(url) = webhook_url {
                send_webhook_alert(url, &msg).await;
            }
            // Do not update state on failure so we retry next cycle.
            return Ok(());
        }
    } else {
        eprintln!(
            "[audit-monitor] First run, recording initial checkpoint (tree_size={})",
            checkpoint.tree_size
        );
    }

    // 4. Save new state.
    let new_state = MonitorState {
        tree_size: checkpoint.tree_size,
        root: checkpoint.root,
        last_checked: chrono::Utc::now().to_rfc3339(),
    };
    save_state(state_file, &new_state)?;

    Ok(())
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    let state_file = cli.state_file.unwrap_or_else(default_state_file);
    let client = reqwest::Client::new();

    eprintln!(
        "[audit-monitor] Starting: registry={}, interval={}s, state_file={}",
        cli.registry_url,
        cli.interval,
        state_file.display()
    );

    loop {
        if let Err(e) = poll_cycle(
            &client,
            &cli.registry_url,
            &cli.registry_public_key,
            &state_file,
            cli.webhook_url.as_deref(),
        )
        .await
        {
            eprintln!("[audit-monitor] Poll cycle error: {e}");
        }
        tokio::time::sleep(std::time::Duration::from_secs(cli.interval)).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_state_file_has_expected_suffix() {
        let path = default_state_file();
        let text = path.to_string_lossy();
        assert!(text.contains(".clawdstrike"));
        assert!(text.contains("audit-monitor"));
        assert!(text.ends_with("state.json"));
    }

    #[test]
    fn load_state_missing_returns_none() -> Result<(), Box<dyn std::error::Error>> {
        let tmp = tempfile::tempdir()?;
        let path = tmp.path().join("missing.json");
        assert!(load_state(&path).is_none());
        Ok(())
    }

    #[test]
    fn save_and_load_state_roundtrip() -> Result<(), Box<dyn std::error::Error>> {
        let tmp = tempfile::tempdir()?;
        let path = tmp.path().join("state.json");
        let original = MonitorState {
            tree_size: 42,
            root: "abcd".to_string(),
            last_checked: "2026-02-28T00:00:00Z".to_string(),
        };
        save_state(&path, &original)?;
        let loaded = load_state(&path).ok_or_else(|| {
            std::io::Error::new(std::io::ErrorKind::NotFound, "state was not persisted")
        })?;
        assert_eq!(loaded.tree_size, 42);
        assert_eq!(loaded.root, "abcd");
        assert_eq!(loaded.last_checked, "2026-02-28T00:00:00Z");
        Ok(())
    }

    #[test]
    fn verify_checkpoint_signature_accepts_valid_checkpoint() {
        let kp = hush_core::Keypair::from_seed(&[11u8; 32]);
        let root_hash = hush_core::sha256(b"checkpoint-root").to_hex();
        let timestamp = "2026-03-01T00:00:00Z".to_string();
        let message = checkpoint_signature_message(&root_hash, 7, &timestamp);
        let sig = kp.sign(message.as_bytes()).to_hex();
        let key = kp.public_key().to_hex();
        let checkpoint = CheckpointResponse {
            root: root_hash,
            tree_size: 7,
            timestamp,
            registry_sig: sig,
            registry_key: key.clone(),
        };
        assert!(verify_checkpoint_signature(&checkpoint, &key).is_ok());
    }

    #[test]
    fn verify_checkpoint_signature_rejects_mismatched_trust_anchor() {
        let kp = hush_core::Keypair::from_seed(&[12u8; 32]);
        let other = hush_core::Keypair::from_seed(&[13u8; 32]);
        let root_hash = hush_core::sha256(b"checkpoint-root").to_hex();
        let timestamp = "2026-03-01T00:00:00Z".to_string();
        let message = checkpoint_signature_message(&root_hash, 9, &timestamp);
        let sig = kp.sign(message.as_bytes()).to_hex();
        let checkpoint = CheckpointResponse {
            root: root_hash,
            tree_size: 9,
            timestamp,
            registry_sig: sig,
            registry_key: kp.public_key().to_hex(),
        };
        let err = match verify_checkpoint_signature(&checkpoint, &other.public_key().to_hex()) {
            Ok(()) => panic!("mismatched trust anchor should fail signature verification"),
            Err(err) => err,
        };
        assert!(err.to_string().contains("mismatch"));
    }
}
