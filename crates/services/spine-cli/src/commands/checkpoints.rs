use anyhow::{Context, Result};
use colored::Colorize;
use futures::TryStreamExt;
use serde_json::Value;

fn checkpoint_fact_view(value: &Value) -> Option<&Value> {
    let candidate = value.get("fact").unwrap_or(value);
    let has_required = [
        "log_id",
        "checkpoint_seq",
        "merkle_root",
        "tree_size",
        "issued_at",
    ]
    .iter()
    .all(|k| candidate.get(*k).is_some());
    if has_required {
        Some(candidate)
    } else {
        None
    }
}

fn checkpoint_statement_from_value(value: &Value) -> Result<Value> {
    let fact = checkpoint_fact_view(value).context("value does not contain a checkpoint fact")?;
    Ok(spine::checkpoint_statement(
        fact.get("log_id")
            .and_then(|v| v.as_str())
            .context("missing log_id")?,
        fact.get("checkpoint_seq")
            .and_then(|v| v.as_u64())
            .context("missing checkpoint_seq")?,
        fact.get("prev_checkpoint_hash")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string()),
        fact.get("merkle_root")
            .and_then(|v| v.as_str())
            .context("missing merkle_root")?
            .to_string(),
        fact.get("tree_size")
            .and_then(|v| v.as_u64())
            .context("missing tree_size")?,
        fact.get("issued_at")
            .and_then(|v| v.as_str())
            .context("missing issued_at")?
            .to_string(),
    ))
}

fn checkpoint_hash_from_value(value: &Value) -> Result<String> {
    let statement = checkpoint_statement_from_value(value)?;
    Ok(spine::checkpoint_hash(&statement)?.to_hex_prefixed())
}

fn checkpoint_seq_from_kv_key(key: &str) -> Option<u64> {
    key.strip_prefix("checkpoint/")?.parse::<u64>().ok()
}

fn recent_checkpoint_keys(mut keys: Vec<String>, limit: u64) -> Vec<String> {
    let limit = usize::try_from(limit).unwrap_or(usize::MAX);
    keys.retain(|k| checkpoint_seq_from_kv_key(k).is_some());
    keys.sort_unstable_by_key(|k| checkpoint_seq_from_kv_key(k).unwrap_or(0));
    if keys.len() > limit {
        keys.drain(0..(keys.len() - limit));
    }
    keys
}

/// List recent checkpoints from the CLAWDSTRIKE_CHECKPOINTS KV bucket.
pub async fn list(nats_url: &str, limit: u64, is_json: bool, verbose: bool) -> Result<()> {
    if limit == 0 {
        anyhow::bail!("limit must be >= 1");
    }

    let client = spine::nats_transport::connect(nats_url).await?;
    let js = spine::nats_transport::jetstream(client);

    let kv = js
        .get_key_value("CLAWDSTRIKE_CHECKPOINTS")
        .await
        .context("failed to get CLAWDSTRIKE_CHECKPOINTS bucket")?;

    let keys = kv
        .keys()
        .await
        .context("failed to list checkpoint keys")?
        .try_collect::<Vec<String>>()
        .await
        .context("failed to collect checkpoint keys")?;

    let mut key_candidates = recent_checkpoint_keys(keys, limit);
    if key_candidates.is_empty() {
        key_candidates.push("latest".to_string());
    }

    let mut checkpoints: Vec<Value> = Vec::new();
    for key in key_candidates {
        let Some(bytes) = kv
            .get(&key)
            .await
            .with_context(|| format!("failed to get checkpoint key {key}"))?
        else {
            continue;
        };
        if let Ok(v) = serde_json::from_slice::<Value>(&bytes) {
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
        let fact = checkpoint_fact_view(cp).unwrap_or(cp);
        let log_id = fact
            .get("log_id")
            .and_then(|v| v.as_str())
            .unwrap_or("unknown");
        let seq = fact
            .get("checkpoint_seq")
            .and_then(|v| v.as_u64())
            .unwrap_or(0);
        let merkle_root = fact
            .get("merkle_root")
            .and_then(|v| v.as_str())
            .unwrap_or("unknown");
        let tree_size = fact.get("tree_size").and_then(|v| v.as_u64()).unwrap_or(0);
        let issued_at = fact
            .get("issued_at")
            .and_then(|v| v.as_str())
            .unwrap_or("unknown");

        println!("  {} {} #{}", "Log:".bold(), log_id, seq);
        println!("    Merkle root: {}", merkle_root);
        println!("    Tree size: {}  Issued: {}", tree_size, issued_at);

        if verbose {
            if let Some(prev) = fact.get("prev_checkpoint_hash").and_then(|v| v.as_str()) {
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
        .get_key_value("CLAWDSTRIKE_CHECKPOINTS")
        .await
        .context("failed to get CLAWDSTRIKE_CHECKPOINTS bucket")?;

    let mut found: Option<(String, Value, String)> = None;
    let direct_key = format!("checkpoint_hash/{normalized}");
    if let Some(bytes) = kv
        .get(&direct_key)
        .await
        .with_context(|| format!("failed to get checkpoint key {direct_key}"))?
    {
        let checkpoint: Value = serde_json::from_slice(&bytes)
            .with_context(|| format!("invalid JSON at checkpoint key {direct_key}"))?;
        let computed_hash = checkpoint_hash_from_value(&checkpoint)?;
        if computed_hash == normalized {
            found = Some((direct_key, checkpoint, computed_hash));
        }
    }

    if found.is_none() {
        let mut keys = kv
            .keys()
            .await
            .context("failed to list checkpoint keys")?
            .try_collect::<Vec<String>>()
            .await
            .context("failed to collect checkpoint keys")?;
        keys.sort_unstable();

        for key in keys {
            if key != "latest" && !key.starts_with("checkpoint/") {
                continue;
            }
            let Some(bytes) = kv
                .get(&key)
                .await
                .with_context(|| format!("failed to get checkpoint key {key}"))?
            else {
                continue;
            };

            let checkpoint: Value = match serde_json::from_slice(&bytes) {
                Ok(v) => v,
                Err(_) => continue,
            };
            let computed_hash = match checkpoint_hash_from_value(&checkpoint) {
                Ok(h) => h,
                Err(_) => continue,
            };
            if computed_hash == normalized {
                let hash_index_key = format!("checkpoint_hash/{computed_hash}");
                let _ = kv.put(&hash_index_key, bytes.clone()).await;
                found = Some((key, checkpoint, computed_hash));
                break;
            }
        }
    }

    match found {
        Some((key, checkpoint, computed_hash)) => {
            if is_json {
                let result = serde_json::json!({
                    "checkpoint_key": key,
                    "checkpoint": checkpoint,
                    "computed_hash": computed_hash,
                    "expected_hash": normalized,
                    "valid": true,
                });
                println!("{}", serde_json::to_string_pretty(&result)?);
            } else {
                println!("{}", "Checkpoint Verification".bold().green());
                println!("  {} {}", "Checkpoint Key:".bold(), key);
                println!("  {} {}", "Expected:".bold(), normalized);
                println!("  {} {}", "Computed:".bold(), computed_hash);
                println!("  {} {}", "Result:".bold(), "VALID".green());
            }
        }
        None => {
            if is_json {
                println!(
                    "{}",
                    serde_json::json!({"error": "not found", "checkpoint_hash": normalized})
                );
            } else {
                println!(
                    "{} checkpoint hash {} not found in {}",
                    "Error:".bold().red(),
                    normalized,
                    "CLAWDSTRIKE_CHECKPOINTS".bold()
                );
            }
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn checkpoint_fact_view_accepts_envelope_and_fact() {
        let fact = serde_json::json!({
            "schema": "clawdstrike.spine.fact.log_checkpoint.v1",
            "log_id": "log_a",
            "checkpoint_seq": 7,
            "prev_checkpoint_hash": null,
            "merkle_root": "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "tree_size": 42,
            "issued_at": "2026-01-01T00:00:00Z"
        });
        let envelope = serde_json::json!({
            "schema": "clawdstrike.envelope.v1",
            "fact": fact.clone()
        });

        assert_eq!(
            checkpoint_fact_view(&fact).and_then(|f| f.get("checkpoint_seq")),
            Some(&serde_json::json!(7))
        );
        assert_eq!(
            checkpoint_fact_view(&envelope).and_then(|f| f.get("checkpoint_seq")),
            Some(&serde_json::json!(7))
        );
    }

    #[test]
    fn checkpoint_hash_from_value_matches_statement_hash() {
        let fact = serde_json::json!({
            "schema": "clawdstrike.spine.fact.log_checkpoint.v1",
            "log_id": "log_a",
            "checkpoint_seq": 7,
            "prev_checkpoint_hash": "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
            "merkle_root": "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "tree_size": 42,
            "issued_at": "2026-01-01T00:00:00Z"
        });
        let envelope = serde_json::json!({
            "schema": "clawdstrike.envelope.v1",
            "fact": fact.clone()
        });

        let expected = spine::checkpoint_hash(&spine::checkpoint_statement(
            "log_a",
            7,
            Some("0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb".to_string()),
            "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_string(),
            42,
            "2026-01-01T00:00:00Z".to_string(),
        ))
        .unwrap()
        .to_hex_prefixed();

        let actual = checkpoint_hash_from_value(&envelope).unwrap();
        assert_eq!(actual, expected);
    }

    #[test]
    fn checkpoint_seq_from_kv_key_parses_only_checkpoint_entries() {
        assert_eq!(checkpoint_seq_from_kv_key("checkpoint/42"), Some(42));
        assert_eq!(checkpoint_seq_from_kv_key("latest"), None);
        assert_eq!(checkpoint_seq_from_kv_key("checkpoint_hash/0xabc"), None);
    }

    #[test]
    fn recent_checkpoint_keys_selects_latest_by_sequence() {
        let keys = vec![
            "checkpoint/1".to_string(),
            "checkpoint/3".to_string(),
            "checkpoint/2".to_string(),
            "checkpoint_hash/ignored".to_string(),
            "latest".to_string(),
        ];
        assert_eq!(
            recent_checkpoint_keys(keys, 2),
            vec!["checkpoint/2".to_string(), "checkpoint/3".to_string()]
        );
    }
}
