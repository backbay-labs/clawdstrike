use anyhow::{Context, Result};
use colored::Colorize;
use futures::StreamExt;

/// List recent checkpoints from the spine-checkpoints JetStream stream.
pub async fn list(nats_url: &str, limit: u64, is_json: bool, verbose: bool) -> Result<()> {
    let client = spine::nats_transport::connect(nats_url).await?;
    let js = spine::nats_transport::jetstream(client);

    let mut stream = js
        .get_stream("spine-checkpoints")
        .await
        .context("failed to get spine-checkpoints stream")?;

    let info = stream.info().await.context("failed to get stream info")?;

    let last_seq = info.state.last_sequence;
    let first_seq = info.state.first_sequence;

    let start_seq = if last_seq >= limit {
        std::cmp::max(first_seq, last_seq - limit + 1)
    } else {
        first_seq
    };

    let consumer = stream
        .create_consumer(async_nats::jetstream::consumer::pull::Config {
            deliver_policy: async_nats::jetstream::consumer::DeliverPolicy::ByStartSequence {
                start_sequence: start_seq,
            },
            ..Default::default()
        })
        .await
        .context("failed to create consumer")?;

    let mut messages = consumer
        .fetch()
        .max_messages(limit as usize)
        .messages()
        .await
        .context("failed to fetch messages")?;

    let mut checkpoints = Vec::new();
    while let Some(Ok(msg)) = messages.next().await {
        if let Ok(v) = serde_json::from_slice::<serde_json::Value>(&msg.payload) {
            checkpoints.push(v);
        }
    }

    if is_json {
        println!("{}", serde_json::to_string_pretty(&checkpoints)?);
        return Ok(());
    }

    println!(
        "{} ({} checkpoints)",
        "Recent Checkpoints".bold().green(),
        checkpoints.len()
    );
    println!();

    for cp in &checkpoints {
        let log_id = cp
            .get("log_id")
            .and_then(|v| v.as_str())
            .unwrap_or("unknown");
        let seq = cp
            .get("checkpoint_seq")
            .and_then(|v| v.as_u64())
            .unwrap_or(0);
        let merkle_root = cp
            .get("merkle_root")
            .and_then(|v| v.as_str())
            .unwrap_or("unknown");
        let tree_size = cp
            .get("tree_size")
            .and_then(|v| v.as_u64())
            .unwrap_or(0);
        let issued_at = cp
            .get("issued_at")
            .and_then(|v| v.as_str())
            .unwrap_or("unknown");

        println!("  {} {} #{}", "Log:".bold(), log_id, seq);
        println!("    Merkle root: {}", merkle_root);
        println!("    Tree size: {}  Issued: {}", tree_size, issued_at);

        if verbose {
            if let Some(prev) = cp.get("prev_checkpoint_hash").and_then(|v| v.as_str()) {
                println!("    Prev hash: {}", prev);
            }
        }

        println!();
    }

    Ok(())
}

/// Verify a checkpoint's Merkle root by retrieving it from KV and recomputing.
pub async fn verify(nats_url: &str, hash: &str, is_json: bool) -> Result<()> {
    let normalized = spine::normalize_hash_hex(hash)
        .context("invalid hash format — expected 0x-prefixed 64-char hex")?;

    let client = spine::nats_transport::connect(nats_url).await?;
    let js = spine::nats_transport::jetstream(client);

    let kv = js
        .get_key_value("spine-checkpoints-kv")
        .await
        .context("failed to get spine-checkpoints-kv bucket")?;

    let entry = kv
        .get(&normalized)
        .await
        .context("failed to get checkpoint from KV")?;

    match entry {
        Some(bytes) => {
            let checkpoint: serde_json::Value = serde_json::from_slice(&bytes)?;

            // Recompute checkpoint hash from statement fields
            let statement = spine::checkpoint_statement(
                checkpoint
                    .get("log_id")
                    .and_then(|v| v.as_str())
                    .context("missing log_id")?,
                checkpoint
                    .get("checkpoint_seq")
                    .and_then(|v| v.as_u64())
                    .context("missing checkpoint_seq")?,
                checkpoint
                    .get("prev_checkpoint_hash")
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string()),
                checkpoint
                    .get("merkle_root")
                    .and_then(|v| v.as_str())
                    .context("missing merkle_root")?
                    .to_string(),
                checkpoint
                    .get("tree_size")
                    .and_then(|v| v.as_u64())
                    .context("missing tree_size")?,
                checkpoint
                    .get("issued_at")
                    .and_then(|v| v.as_str())
                    .context("missing issued_at")?
                    .to_string(),
            );

            let computed_hash = spine::checkpoint_hash(&statement)?;
            let computed_hex = computed_hash.to_hex_prefixed();
            let matches = computed_hex == normalized;

            if is_json {
                let result = serde_json::json!({
                    "checkpoint": checkpoint,
                    "computed_hash": computed_hex,
                    "expected_hash": normalized,
                    "valid": matches,
                });
                println!("{}", serde_json::to_string_pretty(&result)?);
            } else {
                println!("{}", "Checkpoint Verification".bold().green());
                println!("  {} {}", "Expected:".bold(), normalized);
                println!("  {} {}", "Computed:".bold(), computed_hex);
                if matches {
                    println!("  {} {}", "Result:".bold(), "VALID".green());
                } else {
                    println!("  {} {}", "Result:".bold(), "MISMATCH".red());
                }
            }
        }
        None => {
            if is_json {
                println!(
                    "{}",
                    serde_json::json!({"error": "not found", "hash": normalized})
                );
            } else {
                println!(
                    "{} checkpoint {} not found",
                    "Error:".bold().red(),
                    normalized
                );
            }
        }
    }

    Ok(())
}
