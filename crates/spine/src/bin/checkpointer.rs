//! ClawdStrike Spine checkpointer.
//!
//! Subscribes to `clawdstrike.spine.envelope.>` on NATS, verifies envelope
//! signatures, appends to a JetStream log, builds RFC 6962 Merkle trees,
//! and emits checkpoint envelopes on a timer with witness co-signatures.

use std::collections::HashSet;
use std::path::PathBuf;
use std::time::Duration;

use anyhow::{Context, Result};
use clap::Parser;
use futures::StreamExt;
use futures::TryStreamExt;
use serde_json::{json, Value};
use tokio::time::{interval, timeout, Instant};
use tracing::{debug, info, warn};
use tracing_subscriber::{fmt, EnvFilter};

use async_nats::jetstream::context::Publish;
use hush_core::{sha256_hex, Hash, Keypair, MerkleTree, PublicKey, Signature};
use spine::{checkpoint, nats_transport as nats, TrustBundle};

#[derive(Parser, Debug)]
#[command(name = "spine-checkpointer")]
#[command(about = "ClawdStrike Spine log checkpointer (RFC6962 Merkle roots + witness co-sign)")]
struct Args {
    /// NATS server URL
    #[arg(long, env = "NATS_URL", default_value = "nats://localhost:4222")]
    nats_url: String,

    /// Subscribe subject for SignedEnvelopes
    #[arg(long, default_value = "clawdstrike.spine.envelope.>")]
    subscribe_subject: String,

    /// JetStream stream used to order log leaves
    #[arg(long, default_value = "CLAWDSTRIKE_SPINE_LOG")]
    log_stream: String,

    /// Subject for log leaf appends (payload = 32 raw bytes of envelope_hash)
    #[arg(long, default_value = "clawdstrike.spine.log.leaf.v1")]
    log_subject: String,

    /// KV bucket mapping envelope_hash -> log sequence number
    #[arg(long, default_value = "CLAWDSTRIKE_LOG_INDEX")]
    index_bucket: String,

    /// KV bucket storing checkpoints (keys: `latest`, `checkpoint/<seq>`)
    #[arg(long, default_value = "CLAWDSTRIKE_CHECKPOINTS")]
    checkpoint_bucket: String,

    /// KV bucket storing SignedEnvelope payloads (keyed by envelope_hash)
    #[arg(long, default_value = "CLAWDSTRIKE_ENVELOPES")]
    envelope_bucket: String,

    /// KV bucket indexing facts (policy hashes, versions, run_ids) to envelope hashes
    #[arg(long, default_value = "CLAWDSTRIKE_FACT_INDEX")]
    fact_index_bucket: String,

    /// Subject to publish log checkpoint envelopes
    #[arg(long, default_value = "clawdstrike.spine.envelope.log_checkpoint.v1")]
    checkpoint_publish_subject: String,

    /// NATS request subject for witness signatures
    #[arg(long, default_value = "clawdstrike.spine.witness.sign.v1")]
    witness_request_subject: String,

    /// Trust bundle JSON (optional; enforces witness allowlist + quorum)
    #[arg(long, env = "SPINE_TRUST_BUNDLE")]
    trust_bundle: Option<PathBuf>,

    /// Hex-encoded 32-byte Ed25519 seed for the log operator key
    #[arg(long, env = "SPINE_LOG_SEED_HEX")]
    log_seed_hex: String,

    /// Minimum number of new leaves required to emit a new checkpoint
    #[arg(long, default_value = "10")]
    checkpoint_every: u64,

    /// Check for checkpoint opportunities every N seconds
    #[arg(long, default_value = "10")]
    checkpoint_interval_sec: u64,

    /// NATS request timeout for witness signing
    #[arg(long, default_value = "5")]
    witness_timeout_sec: u64,

    /// JetStream replication factor for log/index/checkpoints (dev default: 3)
    #[arg(long, default_value = "3")]
    replicas: usize,
}

fn normalize_seed_hex(seed: &str) -> String {
    seed.trim()
        .strip_prefix("0x")
        .unwrap_or(seed.trim())
        .to_string()
}

fn verify_signed_envelope(envelope: &Value) -> Result<(String, Vec<u8>)> {
    let envelope_hash = envelope
        .get("envelope_hash")
        .and_then(|v| v.as_str())
        .context("envelope missing envelope_hash")?
        .to_string();

    let issuer = envelope
        .get("issuer")
        .and_then(|v| v.as_str())
        .context("envelope missing issuer")?;

    let signature_hex = envelope
        .get("signature")
        .and_then(|v| v.as_str())
        .context("envelope missing signature")?;

    let mut unsigned = envelope.clone();
    let Some(obj) = unsigned.as_object_mut() else {
        return Err(anyhow::anyhow!("envelope must be a JSON object"));
    };
    obj.remove("envelope_hash");
    obj.remove("signature");

    let canonical = spine::envelope_signing_bytes(&unsigned)?;
    let computed_hash = sha256_hex(&canonical);
    if computed_hash != envelope_hash {
        return Err(anyhow::anyhow!(
            "envelope_hash mismatch (computed {}, got {})",
            computed_hash,
            envelope_hash
        ));
    }

    let pubkey_hex = spine::parse_issuer_pubkey_hex(issuer)?;
    let pubkey = PublicKey::from_hex(&pubkey_hex)?;
    let sig = Signature::from_hex(signature_hex)?;
    if !pubkey.verify(&canonical, &sig) {
        return Err(anyhow::anyhow!(
            "envelope signature invalid for issuer={issuer}"
        ));
    }

    Ok((envelope_hash, canonical))
}

fn is_safe_index_key_token(s: &str, max_len: usize) -> bool {
    if s.is_empty() || s.len() > max_len {
        return false;
    }
    s.chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-' || c == '.')
}

async fn load_latest_checkpoint(kv: &async_nats::jetstream::kv::Store) -> Result<Option<Value>> {
    match kv.get("latest").await? {
        Some(bytes) => Ok(Some(serde_json::from_slice(&bytes)?)),
        None => Ok(None),
    }
}

fn build_checkpoint_statement_from_fact(fact: &Value) -> Result<Value> {
    let log_id = fact
        .get("log_id")
        .and_then(|v| v.as_str())
        .context("checkpoint fact missing log_id")?;
    let checkpoint_seq = fact
        .get("checkpoint_seq")
        .and_then(|v| v.as_u64())
        .context("checkpoint fact missing checkpoint_seq")?;
    let prev_checkpoint_hash = fact
        .get("prev_checkpoint_hash")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());
    let merkle_root = fact
        .get("merkle_root")
        .and_then(|v| v.as_str())
        .context("checkpoint fact missing merkle_root")?;
    let tree_size = fact
        .get("tree_size")
        .and_then(|v| v.as_u64())
        .context("checkpoint fact missing tree_size")?;
    let issued_at = fact
        .get("issued_at")
        .and_then(|v| v.as_str())
        .context("checkpoint fact missing issued_at")?;

    Ok(checkpoint::checkpoint_statement(
        log_id,
        checkpoint_seq,
        prev_checkpoint_hash,
        merkle_root.to_string(),
        tree_size,
        issued_at.to_string(),
    ))
}

async fn load_leaves_from_index(kv: &async_nats::jetstream::kv::Store) -> Result<Vec<Vec<u8>>> {
    let mut pairs: Vec<(u64, Vec<u8>)> = Vec::new();
    let keys = kv.keys().await?.try_collect::<Vec<String>>().await?;

    for key in keys {
        let Some(value) = kv.get(&key).await? else {
            continue;
        };
        let seq_str = std::str::from_utf8(&value).unwrap_or("").trim();
        let seq: u64 = match seq_str.parse() {
            Ok(s) => s,
            Err(_) => continue,
        };
        let h = Hash::from_hex(&key)?;
        pairs.push((seq, h.as_bytes().to_vec()));
    }

    pairs.sort_by_key(|(seq, _)| *seq);

    // Validate contiguous sequences (no gaps).
    for i in 1..pairs.len() {
        let prev_seq = pairs[i - 1].0;
        let curr_seq = pairs[i].0;
        if curr_seq != prev_seq + 1 {
            anyhow::bail!(
                "log index has gap: expected seq {} after {}, got {}",
                prev_seq + 1,
                prev_seq,
                curr_seq
            );
        }
    }

    Ok(pairs.into_iter().map(|(_, b)| b).collect())
}

async fn ensure_log_append(
    js: &async_nats::jetstream::Context,
    index_kv: &async_nats::jetstream::kv::Store,
    log_subject: &str,
    envelope_hash_hex: &str,
    envelope_hash_bytes: &[u8],
) -> Result<u64> {
    if index_kv.get(envelope_hash_hex).await?.is_some() {
        return Ok(0);
    }

    // Use Nats-Msg-Id = envelope_hash to make the publish idempotent.
    // If publish succeeds but the KV create below fails, a retry will be
    // de-duplicated by the JetStream server within its dedup window.
    // The index write uses create() (CAS) instead of put() so that if two
    // checkpointers race, only the first create succeeds and the second
    // gets AlreadyExists (which we log and skip).
    let ack_future = js
        .send_publish(
            log_subject.to_string(),
            Publish::build()
                .payload(envelope_hash_bytes.to_vec().into())
                .message_id(envelope_hash_hex),
        )
        .await
        .context("failed to append leaf to log stream")?;
    let ack = ack_future.await.context("failed to ack log append")?;

    let seq = ack.sequence;
    match index_kv
        .create(envelope_hash_hex, seq.to_string().into_bytes().into())
        .await
    {
        Ok(_) => {}
        Err(err) if err.kind() == async_nats::jetstream::kv::CreateErrorKind::AlreadyExists => {
            debug!(
                envelope_hash = %envelope_hash_hex,
                "log index entry already exists (concurrent checkpointer), skipping"
            );
        }
        Err(err) => return Err(err).context("failed to create log index KV entry"),
    }

    Ok(seq)
}

async fn collect_witness_signatures(
    client: &async_nats::Client,
    witness_request_subject: &str,
    statement: &Value,
    witness_timeout: Duration,
    trust_bundle: Option<&TrustBundle>,
) -> Result<Vec<(String, String)>> {
    let quorum = trust_bundle.map_or(1, |tb| tb.witness_quorum);
    if quorum == 0 {
        anyhow::bail!("witness quorum must be >= 1");
    }

    let inbox = client.new_inbox();
    let mut sub = client.subscribe(inbox.clone()).await?;
    client
        .publish_with_reply(
            witness_request_subject.to_string(),
            inbox,
            serde_json::to_vec(statement)?.into(),
        )
        .await?;

    // When no trust bundle is configured (quorum defaults to 1), check if
    // there are actually any witness subscribers. If no reply arrives within
    // 1 second, return an empty Vec instead of waiting the full timeout.
    let effective_timeout = if trust_bundle.is_none() {
        Duration::from_secs(1).min(witness_timeout)
    } else {
        witness_timeout
    };
    let deadline = Instant::now() + effective_timeout;
    let mut out: Vec<(String, String)> = Vec::new();
    let mut seen: HashSet<String> = HashSet::new();

    while out.len() < quorum {
        let now = Instant::now();
        if now >= deadline {
            break;
        }
        let remaining = deadline - now;
        let msg = match timeout(remaining, sub.next()).await {
            Ok(Some(m)) => m,
            Ok(None) => break,
            Err(_) => break,
        };

        let witness_sig: Value = match serde_json::from_slice(&msg.payload) {
            Ok(v) => v,
            Err(_) => continue,
        };

        let witness_node_id = match witness_sig.get("witness_node_id").and_then(|v| v.as_str()) {
            Some(v) => v.to_string(),
            None => continue,
        };
        let signature = match witness_sig.get("signature").and_then(|v| v.as_str()) {
            Some(v) => v.to_string(),
            None => continue,
        };

        if let Some(tb) = trust_bundle {
            if !tb.witness_allowed(&witness_node_id) {
                continue;
            }
        }

        if seen.contains(&witness_node_id) {
            continue;
        }

        let ok = match checkpoint::verify_witness_signature(statement, &witness_node_id, &signature)
        {
            Ok(valid) => valid,
            Err(err) => {
                warn!(witness = %witness_node_id, "witness signature verification error: {err:#}");
                continue;
            }
        };
        if !ok {
            warn!(witness = %witness_node_id, "witness signature invalid, skipping");
            continue;
        }

        seen.insert(witness_node_id.clone());
        out.push((witness_node_id, signature));
    }

    if out.len() < quorum {
        if trust_bundle.is_none() && out.is_empty() {
            return Ok(Vec::new());
        }
        anyhow::bail!("witness quorum not met (got {} need {})", out.len(), quorum);
    }

    Ok(out)
}

#[allow(clippy::too_many_arguments)]
async fn maybe_checkpoint(
    client: &async_nats::Client,
    index_kv: &async_nats::jetstream::kv::Store,
    checkpoint_kv: &async_nats::jetstream::kv::Store,
    log_id: &str,
    log_keypair: &Keypair,
    checkpoint_publish_subject: &str,
    witness_request_subject: &str,
    witness_timeout: Duration,
    trust_bundle: Option<&TrustBundle>,
    last_checkpoint_tree_size: &mut u64,
    last_envelope_seq: &mut u64,
    last_envelope_hash: &mut Option<String>,
    last_checkpoint_hash: &mut Option<String>,
    checkpoint_every: u64,
) -> Result<()> {
    let leaves = load_leaves_from_index(index_kv).await?;
    let tree_size = leaves.len() as u64;

    if tree_size == 0 {
        return Ok(());
    }
    if tree_size <= *last_checkpoint_tree_size {
        return Ok(());
    }
    if (tree_size - *last_checkpoint_tree_size) < checkpoint_every {
        return Ok(());
    }

    let tree = MerkleTree::from_leaves(&leaves)?;
    let merkle_root = tree.root().to_hex_prefixed();
    let issued_at = spine::now_rfc3339();
    let checkpoint_seq = last_envelope_seq
        .checked_add(1)
        .context("checkpoint sequence overflow")?;

    let prev_checkpoint_hash = (*last_checkpoint_hash).clone();
    let statement = checkpoint::checkpoint_statement(
        log_id,
        checkpoint_seq,
        prev_checkpoint_hash.clone(),
        merkle_root.clone(),
        tree_size,
        issued_at.clone(),
    );

    let witness_sigs = collect_witness_signatures(
        client,
        witness_request_subject,
        &statement,
        witness_timeout,
        trust_bundle,
    )
    .await
    .context("failed to collect witness signatures")?;
    let witnesses: Vec<Value> = witness_sigs
        .into_iter()
        .map(|(witness_node_id, signature)| {
            json!({"witness_node_id": witness_node_id, "signature": signature})
        })
        .collect();

    let fact_id = format!("cp_{}", uuid::Uuid::new_v4());
    let checkpoint_fact = json!({
        "schema": "clawdstrike.spine.fact.log_checkpoint.v1",
        "fact_id": fact_id,
        "log_id": log_id,
        "checkpoint_seq": checkpoint_seq,
        "prev_checkpoint_hash": prev_checkpoint_hash,
        "merkle_root": merkle_root,
        "tree_size": tree_size,
        "included_heads": [],
        "witnesses": witnesses,
        "anchors": {"rekor": Value::Null, "eas": Value::Null, "solana": Value::Null},
        "issued_at": issued_at,
    });

    let prev_envelope_hash = (*last_envelope_hash).clone();
    let envelope = spine::build_signed_envelope(
        log_keypair,
        checkpoint_seq,
        prev_envelope_hash,
        checkpoint_fact,
        spine::now_rfc3339(),
    )?;

    let envelope_bytes = serde_json::to_vec(&envelope)?;
    client
        .publish(
            checkpoint_publish_subject.to_string(),
            envelope_bytes.clone().into(),
        )
        .await
        .context("failed to publish checkpoint envelope")?;

    checkpoint_kv
        .put(
            format!("checkpoint/{}", checkpoint_seq),
            envelope_bytes.clone().into(),
        )
        .await
        .context("failed to store checkpoint in KV")?;
    checkpoint_kv
        .put("latest".to_string(), envelope_bytes.clone().into())
        .await
        .context("failed to store latest checkpoint in KV")?;

    *last_checkpoint_tree_size = tree_size;
    *last_envelope_seq = checkpoint_seq;
    *last_envelope_hash = envelope
        .get("envelope_hash")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());

    let cp_hash = checkpoint::checkpoint_hash(&statement)?.to_hex_prefixed();
    *last_checkpoint_hash = Some(cp_hash);

    info!(
        "published checkpoint seq={} tree_size={} merkle_root={}",
        checkpoint_seq, tree_size, envelope["fact"]["merkle_root"]
    );

    Ok(())
}

async fn maybe_index_fact(
    fact_index_kv: &async_nats::jetstream::kv::Store,
    envelope: &Value,
    envelope_hash: &str,
) -> Result<()> {
    let Some(fact) = envelope.get("fact") else {
        return Ok(());
    };
    let schema = fact.get("schema").and_then(|v| v.as_str()).unwrap_or("");
    if schema.is_empty() {
        debug!("envelope has no fact schema, skipping index");
        return Ok(());
    }

    match schema {
        "clawdstrike.spine.fact.policy.v1" => {
            let Some(policy_hash) = fact.get("policy_hash").and_then(|v| v.as_str()) else {
                return Ok(());
            };
            if !is_safe_index_key_token(policy_hash, 128) {
                return Ok(());
            }

            if let Err(e) = fact_index_kv
                .put(
                    &format!("policy.{policy_hash}"),
                    envelope_hash.as_bytes().to_vec().into(),
                )
                .await
            {
                warn!(key = %format!("policy.{policy_hash}"), "failed to index fact: {e}");
            }

            if let Some(version) = fact.get("policy_version").and_then(|v| v.as_str()) {
                if is_safe_index_key_token(version, 200) {
                    if let Err(e) = fact_index_kv
                        .put(
                            &format!("policy_version.{version}"),
                            policy_hash.as_bytes().to_vec().into(),
                        )
                        .await
                    {
                        warn!(key = %format!("policy_version.{version}"), "failed to index fact: {e}");
                    }
                }
            }
        }
        "clawdstrike.run_receipt.v1" => {
            let Some(run_id) = fact.get("run_id").and_then(|v| v.as_str()) else {
                return Ok(());
            };
            if !is_safe_index_key_token(run_id, 256) {
                return Ok(());
            }
            if let Err(e) = fact_index_kv
                .put(
                    &format!("run_receipt.{run_id}"),
                    envelope_hash.as_bytes().to_vec().into(),
                )
                .await
            {
                warn!(key = %format!("run_receipt.{run_id}"), "failed to index fact: {e}");
            }
        }
        "clawdstrike.spine.fact.receipt_verification.v1" => {
            let Some(target) = fact.get("target_envelope_hash").and_then(|v| v.as_str()) else {
                return Ok(());
            };
            if !is_safe_index_key_token(target, 128) {
                return Ok(());
            }
            let Some(verifier_node_id) = fact.get("verifier_node_id").and_then(|v| v.as_str())
            else {
                return Ok(());
            };
            let verifier_pk = match spine::parse_issuer_pubkey_hex(verifier_node_id) {
                Ok(p) => p,
                Err(_) => return Ok(()),
            };
            if !is_safe_index_key_token(&verifier_pk, 128) {
                return Ok(());
            }

            if let Err(e) = fact_index_kv
                .put(
                    &format!("receipt_verification.{target}.{verifier_pk}"),
                    envelope_hash.as_bytes().to_vec().into(),
                )
                .await
            {
                warn!(key = %format!("receipt_verification.{target}.{verifier_pk}"), "failed to index fact: {e}");
            }
        }
        _ => {}
    }

    Ok(())
}

#[tokio::main]
async fn main() -> Result<()> {
    fmt()
        .with_env_filter(EnvFilter::from_default_env().add_directive("info".parse()?))
        .with_target(false)
        .init();

    let args = Args::parse();
    let log_keypair = Keypair::from_hex(&normalize_seed_hex(&args.log_seed_hex))
        .context("invalid SPINE_LOG_SEED_HEX")?;
    let log_id = spine::issuer_from_keypair(&log_keypair);

    let trust_bundle = match &args.trust_bundle {
        Some(path) => Some(TrustBundle::load(path)?),
        None => None,
    };
    if let Some(tb) = trust_bundle.as_ref() {
        if !tb.log_id_allowed(&log_id) {
            anyhow::bail!("log_id not allowed by trust bundle: {log_id}");
        }
    }

    info!(
        "starting checkpointer log_id={} nats={}",
        log_id, args.nats_url
    );

    let client = nats::connect(&args.nats_url).await?;
    let js = nats::jetstream(client.clone());

    let _stream = nats::ensure_stream(
        &js,
        &args.log_stream,
        vec![args.log_subject.clone()],
        args.replicas,
    )
    .await?;

    let index_kv = nats::ensure_kv(&js, &args.index_bucket, args.replicas).await?;
    let checkpoint_kv = nats::ensure_kv(&js, &args.checkpoint_bucket, args.replicas).await?;
    let envelope_kv = nats::ensure_kv(&js, &args.envelope_bucket, args.replicas).await?;
    let fact_index_kv = nats::ensure_kv(&js, &args.fact_index_bucket, args.replicas).await?;

    // Initialize checkpoint state from KV (if present).
    let mut last_checkpoint_tree_size: u64 = 0;
    let mut last_envelope_seq: u64 = 0;
    let mut last_envelope_hash: Option<String> = None;
    let mut last_checkpoint_hash: Option<String> = None;

    if let Some(latest) = load_latest_checkpoint(&checkpoint_kv).await? {
        if let Some(seq) = latest.get("seq").and_then(|v| v.as_u64()) {
            last_envelope_seq = seq;
        }
        if let Some(h) = latest.get("envelope_hash").and_then(|v| v.as_str()) {
            last_envelope_hash = Some(h.to_string());
        }
        if let Some(fact) = latest.get("fact") {
            if let Some(ts) = fact.get("tree_size").and_then(|v| v.as_u64()) {
                last_checkpoint_tree_size = ts;
            }
            let statement = build_checkpoint_statement_from_fact(fact)?;
            last_checkpoint_hash = Some(checkpoint::checkpoint_hash(&statement)?.to_hex_prefixed());
        }
        info!(
            "loaded latest checkpoint seq={} tree_size={}",
            last_envelope_seq, last_checkpoint_tree_size
        );
    }

    let mut sub = client
        .subscribe(args.subscribe_subject.clone())
        .await
        .context("failed to subscribe to envelopes")?;

    let mut ticker = interval(Duration::from_secs(args.checkpoint_interval_sec));
    let witness_timeout = Duration::from_secs(args.witness_timeout_sec);

    loop {
        tokio::select! {
            _ = ticker.tick() => {
                if let Err(err) = maybe_checkpoint(
                    &client,
                    &index_kv,
                    &checkpoint_kv,
                    &log_id,
                    &log_keypair,
                    &args.checkpoint_publish_subject,
                    &args.witness_request_subject,
                    witness_timeout,
                    trust_bundle.as_ref(),
                    &mut last_checkpoint_tree_size,
                    &mut last_envelope_seq,
                    &mut last_envelope_hash,
                    &mut last_checkpoint_hash,
                    args.checkpoint_every,
                ).await {
                    warn!("checkpoint loop error: {err:#}");
                }
            }
            msg = sub.next() => {
                let Some(msg) = msg else { break; };
                let envelope: Value = match serde_json::from_slice(&msg.payload) {
                    Ok(v) => v,
                    Err(_) => continue,
                };
                let (envelope_hash_hex, _canonical_bytes) = match verify_signed_envelope(&envelope) {
                    Ok(v) => v,
                    Err(err) => {
                        warn!("rejected invalid envelope: {err:#}");
                        continue;
                    }
                };

                if envelope_kv.get(&envelope_hash_hex).await?.is_none() {
                    let _ = envelope_kv.put(&envelope_hash_hex, msg.payload.clone()).await;
                }

                let _ = maybe_index_fact(&fact_index_kv, &envelope, &envelope_hash_hex).await;

                let h = match Hash::from_hex(&envelope_hash_hex) {
                    Ok(v) => v,
                    Err(_) => continue,
                };

                let seq = ensure_log_append(
                    &js,
                    &index_kv,
                    &args.log_subject,
                    &envelope_hash_hex,
                    h.as_bytes(),
                ).await?;

                if seq > 0 {
                    info!("appended leaf seq={} envelope_hash={}", seq, envelope_hash_hex);
                }
            }
        }
    }

    Ok(())
}
