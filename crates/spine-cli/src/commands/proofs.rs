use anyhow::{Context, Result};
use colored::Colorize;

/// Get/verify an inclusion proof for an envelope by calling the proofs API.
pub async fn inclusion(hash: &str, api_url: &str, is_json: bool) -> Result<()> {
    let normalized = spine::normalize_hash_hex(hash)
        .context("invalid hash format — expected 0x-prefixed 64-char hex")?;

    let url = format!(
        "{}/v1/proofs/inclusion?envelope_hash={}",
        api_url.trim_end_matches('/'),
        normalized
    );

    let client = reqwest::Client::new();
    let resp = client
        .get(&url)
        .send()
        .await
        .context("failed to reach proofs API")?;

    let status = resp.status();
    let body: serde_json::Value = resp
        .json()
        .await
        .context("failed to parse proofs API response")?;

    if is_json {
        let result = serde_json::json!({
            "status": status.as_u16(),
            "response": body,
        });
        println!("{}", serde_json::to_string_pretty(&result)?);
        return Ok(());
    }

    if !status.is_success() {
        let err_msg = body
            .get("error")
            .and_then(|v| v.as_str())
            .unwrap_or("unknown error");
        println!(
            "{} proofs API returned {} — {}",
            "Error:".bold().red(),
            status.as_u16(),
            err_msg
        );
        return Ok(());
    }

    println!("{}", "Inclusion Proof".bold().green());
    println!("  {} {}", "Envelope:".bold(), normalized);

    if let Some(root) = body.get("merkle_root").and_then(|v| v.as_str()) {
        println!("  {} {}", "Merkle Root:".bold(), root);
    }
    if let Some(index) = body.get("leaf_index").and_then(|v| v.as_u64()) {
        println!("  {} {}", "Leaf Index:".bold(), index);
    }
    if let Some(size) = body.get("tree_size").and_then(|v| v.as_u64()) {
        println!("  {} {}", "Tree Size:".bold(), size);
    }
    if let Some(proof) = body.get("proof").and_then(|v| v.as_array()) {
        println!("  {} ({} nodes)", "Proof Path:".bold(), proof.len());
        for (i, node) in proof.iter().enumerate() {
            if let Some(s) = node.as_str() {
                println!("    [{}] {}", i, s);
            }
        }
    }

    if let Some(verified) = body.get("verified").and_then(|v| v.as_bool()) {
        if verified {
            println!("  {} {}", "Verified:".bold(), "YES".green());
        } else {
            println!("  {} {}", "Verified:".bold(), "NO".red());
        }
    }

    Ok(())
}
