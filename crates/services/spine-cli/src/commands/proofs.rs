use anyhow::{Context, Result};
use colored::Colorize;
use hush_core::{Hash, MerkleProof};

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

    // Client-side proof verification: reconstruct MerkleProof and verify locally
    let locally_verified = (|| -> Option<bool> {
        if !status.is_success() {
            return None;
        }
        let audit_path_json = body.get("audit_path")?.as_array()?;
        let tree_size = body.get("tree_size")?.as_u64()? as usize;
        let log_index = body.get("log_index")?.as_u64()? as usize;
        let merkle_root_hex = body.get("merkle_root").and_then(|v| v.as_str())?;
        let envelope_hash_hex = body.get("envelope_hash").and_then(|v| v.as_str())?;

        let audit_path: Vec<Hash> = audit_path_json
            .iter()
            .filter_map(|v| v.as_str())
            .filter_map(|s| Hash::from_hex(s).ok())
            .collect();
        if audit_path.len() != audit_path_json.len() {
            return Some(false);
        }

        let expected_root = Hash::from_hex(merkle_root_hex).ok()?;
        let envelope_hash = Hash::from_hex(envelope_hash_hex).ok()?;

        let proof = MerkleProof {
            tree_size,
            leaf_index: log_index,
            audit_path,
        };
        Some(proof.verify(envelope_hash.as_bytes(), &expected_root))
    })();

    if is_json {
        let mut result = serde_json::json!({
            "status": status.as_u16(),
            "response": body,
        });
        if let Some(v) = locally_verified {
            result["locally_verified"] = serde_json::json!(v);
        }
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
    if let Some(index) = body.get("log_index").and_then(|v| v.as_u64()) {
        println!("  {} {}", "Log Index:".bold(), index);
    }
    if let Some(size) = body.get("tree_size").and_then(|v| v.as_u64()) {
        println!("  {} {}", "Tree Size:".bold(), size);
    }
    if let Some(path) = body.get("audit_path").and_then(|v| v.as_array()) {
        println!("  {} ({} nodes)", "Audit Path:".bold(), path.len());
        for (i, node) in path.iter().enumerate() {
            if let Some(s) = node.as_str() {
                println!("    [{}] {}", i, s);
            }
        }
    }

    if let Some(verified) = body.get("verified").and_then(|v| v.as_bool()) {
        if verified {
            println!("  {} {}", "Server Verified:".bold(), "YES".green());
        } else {
            println!("  {} {}", "Server Verified:".bold(), "NO".red());
        }
    }

    match locally_verified {
        Some(true) => println!("  {} {}", "Locally Verified:".bold(), "YES".green()),
        Some(false) => println!("  {} {}", "Locally Verified:".bold(), "NO".red()),
        None => {}
    }

    Ok(())
}
