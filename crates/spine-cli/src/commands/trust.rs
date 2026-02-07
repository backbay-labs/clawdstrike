use anyhow::{Context, Result};
use colored::Colorize;
use spine::TrustBundle;

/// Show a loaded trust bundle.
pub fn show(path: &str, is_json: bool) -> Result<()> {
    let bundle = TrustBundle::load(path).context("failed to load trust bundle")?;

    if is_json {
        println!("{}", serde_json::to_string_pretty(&bundle)?);
        return Ok(());
    }

    println!("{}", "Trust Bundle".bold().green());
    println!("  {} {}", "File:".bold(), path);

    if let Some(ref schema) = bundle.schema {
        println!("  {} {}", "Schema:".bold(), schema);
    }

    println!("  {} {}", "Witness Quorum:".bold(), bundle.witness_quorum);
    println!(
        "  {} {}",
        "Require Kernel Loader Sigs:".bold(),
        bundle.require_kernel_loader_signatures
    );

    print_list("Allowed Log IDs", &bundle.allowed_log_ids);
    print_list("Allowed Witness Node IDs", &bundle.allowed_witness_node_ids);
    print_list(
        "Allowed Receipt Signer Node IDs",
        &bundle.allowed_receipt_signer_node_ids,
    );
    print_list(
        "Allowed Kernel Loader Signer Node IDs",
        &bundle.allowed_kernel_loader_signer_node_ids,
    );
    print_list(
        "Required Receipt Enforcement Tiers",
        &bundle.required_receipt_enforcement_tiers,
    );

    Ok(())
}

fn print_list(label: &str, items: &[String]) {
    if items.is_empty() {
        println!("  {} (any)", label.bold());
    } else {
        println!("  {} ({}):", label.bold(), items.len());
        for item in items {
            println!("    - {}", item);
        }
    }
}

/// Verify an envelope against a trust bundle.
pub async fn verify(nats_url: &str, hash: &str, trust_path: &str, is_json: bool) -> Result<()> {
    let normalized = spine::normalize_hash_hex(hash)
        .context("invalid hash format — expected 0x-prefixed 64-char hex")?;

    let bundle = TrustBundle::load(trust_path).context("failed to load trust bundle")?;

    let client = spine::nats_transport::connect(nats_url).await?;
    let js = spine::nats_transport::jetstream(client);

    let kv = js
        .get_key_value("spine-envelopes-kv")
        .await
        .context("failed to get spine-envelopes-kv bucket")?;

    let entry = kv
        .get(&normalized)
        .await
        .context("failed to get envelope from KV")?;

    match entry {
        Some(bytes) => {
            let envelope: serde_json::Value = serde_json::from_slice(&bytes)?;

            let issuer = envelope
                .get("issuer")
                .and_then(|v| v.as_str())
                .context("envelope missing issuer")?;

            // Check signature validity
            let sig_valid = spine::verify_envelope(&envelope).unwrap_or(false);

            // Check if issuer is an allowed receipt signer
            let signer_allowed = bundle.receipt_signer_allowed(issuer);

            let overall = sig_valid && signer_allowed;

            if is_json {
                let result = serde_json::json!({
                    "envelope_hash": normalized,
                    "issuer": issuer,
                    "signature_valid": sig_valid,
                    "signer_allowed": signer_allowed,
                    "trust_verified": overall,
                });
                println!("{}", serde_json::to_string_pretty(&result)?);
            } else {
                println!("{}", "Trust Verification".bold().green());
                println!("  {} {}", "Envelope:".bold(), normalized);
                println!("  {} {}", "Issuer:".bold(), issuer);

                if sig_valid {
                    println!("  {} {}", "Signature:".bold(), "VALID".green());
                } else {
                    println!("  {} {}", "Signature:".bold(), "INVALID".red());
                }

                if signer_allowed {
                    println!("  {} {}", "Signer Allowed:".bold(), "YES".green());
                } else {
                    println!("  {} {}", "Signer Allowed:".bold(), "NO".red());
                }

                if overall {
                    println!("  {} {}", "Trust:".bold(), "VERIFIED".green());
                } else {
                    println!("  {} {}", "Trust:".bold(), "FAILED".red());
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
                    "{} envelope {} not found",
                    "Error:".bold().red(),
                    normalized
                );
            }
        }
    }

    Ok(())
}
