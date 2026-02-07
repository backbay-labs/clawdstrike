use anyhow::{Context, Result};
use colored::Colorize;
use futures::StreamExt;
use std::io::Read;

/// List recent envelopes from the CLAWDSTRIKE_ENVELOPES JetStream stream.
pub async fn list(nats_url: &str, limit: u64, is_json: bool, verbose: bool) -> Result<()> {
    let client = spine::nats_transport::connect(nats_url).await?;
    let js = spine::nats_transport::jetstream(client);

    let mut stream = js
        .get_stream("CLAWDSTRIKE_ENVELOPES")
        .await
        .context("failed to get CLAWDSTRIKE_ENVELOPES stream")?;

    let info = stream.info().await.context("failed to get stream info")?;

    let last_seq = info.state.last_sequence;
    let first_seq = info.state.first_sequence;

    // Start from max(first_seq, last_seq - limit + 1)
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

    let mut envelopes = Vec::new();
    while let Some(Ok(msg)) = messages.next().await {
        if let Ok(v) = serde_json::from_slice::<serde_json::Value>(&msg.payload) {
            envelopes.push(v);
        }
    }

    if is_json {
        println!("{}", serde_json::to_string_pretty(&envelopes)?);
        return Ok(());
    }

    println!(
        "{} ({} envelopes)",
        "Recent Envelopes".bold().green(),
        envelopes.len()
    );
    println!();

    for env in &envelopes {
        let hash = env
            .get("envelope_hash")
            .and_then(|v| v.as_str())
            .unwrap_or("unknown");
        let issuer = env
            .get("issuer")
            .and_then(|v| v.as_str())
            .unwrap_or("unknown");
        let seq = env.get("seq").and_then(|v| v.as_u64()).unwrap_or(0);
        let issued_at = env
            .get("issued_at")
            .and_then(|v| v.as_str())
            .unwrap_or("unknown");
        let fact_type = env
            .get("fact")
            .and_then(|f| f.get("type"))
            .and_then(|v| v.as_str())
            .unwrap_or("unknown");

        println!("  {} {}", "Hash:".bold(), hash);
        println!(
            "    Seq: {}  Issued: {}  Type: {}",
            seq, issued_at, fact_type
        );

        if verbose {
            // Truncate issuer for readability
            let short_issuer = if issuer.len() > 30 {
                format!("{}...", &issuer[..30])
            } else {
                issuer.to_string()
            };
            println!("    Issuer: {}", short_issuer);
        }

        println!();
    }

    Ok(())
}

/// Get a single envelope by hash from the KV store.
pub async fn get(nats_url: &str, hash: &str, is_json: bool) -> Result<()> {
    let normalized = spine::normalize_hash_hex(hash)
        .context("invalid hash format — expected 0x-prefixed 64-char hex")?;

    let client = spine::nats_transport::connect(nats_url).await?;
    let js = spine::nats_transport::jetstream(client);

    let kv = js
        .get_key_value("CLAWDSTRIKE_ENVELOPES")
        .await
        .context("failed to get CLAWDSTRIKE_ENVELOPES bucket")?;

    let entry = kv
        .get(&normalized)
        .await
        .context("failed to get envelope from KV")?;

    match entry {
        Some(bytes) => {
            let envelope: serde_json::Value = serde_json::from_slice(&bytes)?;

            if is_json {
                println!("{}", serde_json::to_string_pretty(&envelope)?);
            } else {
                println!("{}", "Envelope".bold().green());
                println!("{}", serde_json::to_string_pretty(&envelope)?);

                // Verify signature
                match spine::verify_envelope(&envelope) {
                    Ok(true) => println!("\n  {} {}", "Signature:".bold(), "VALID".green()),
                    Ok(false) => println!("\n  {} {}", "Signature:".bold(), "INVALID".red()),
                    Err(e) => println!("\n  {} {} ({})", "Signature:".bold(), "ERROR".red(), e),
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

/// Sign a JSON fact from stdin and publish to NATS.
pub async fn sign(nats_url: &str, is_json: bool) -> Result<()> {
    let mut input = String::new();
    std::io::stdin()
        .read_to_string(&mut input)
        .context("failed to read from stdin")?;

    let fact: serde_json::Value =
        serde_json::from_str(&input).context("stdin is not valid JSON")?;

    let keypair = hush_core::Keypair::generate();
    let envelope = spine::build_signed_envelope(&keypair, 1, None, fact, spine::now_rfc3339())?;

    let client = spine::nats_transport::connect(nats_url).await?;
    let payload = serde_json::to_vec(&envelope)?;
    client
        .publish("clawdstrike.spine.envelope.cli.v1", payload.into())
        .await
        .context("failed to publish envelope")?;

    if is_json {
        println!("{}", serde_json::to_string_pretty(&envelope)?);
    } else {
        let hash = envelope
            .get("envelope_hash")
            .and_then(|v| v.as_str())
            .unwrap_or("unknown");
        println!("{} Published envelope {}", "OK".bold().green(), hash);
        println!(
            "  Issuer: {}",
            envelope
                .get("issuer")
                .and_then(|v| v.as_str())
                .unwrap_or("unknown")
        );
    }

    Ok(())
}
