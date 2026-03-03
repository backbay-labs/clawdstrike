//! ClawdStrike Spine checkpointer.
//!
//! Subscribes to `clawdstrike.spine.envelope.>` on NATS, verifies envelope
//! signatures, appends to a JetStream log, builds RFC 6962 Merkle trees,
//! and emits checkpoint envelopes on a timer with witness co-signatures.

use std::collections::{HashMap, HashSet};
use std::path::PathBuf;
use std::time::Duration;

use anyhow::{Context, Result};
use clap::{Parser, ValueEnum};
use futures::StreamExt;
use futures::TryStreamExt;
use serde_json::{json, Value};
use tokio::time::{interval, sleep, timeout, Instant};
use tracing::{debug, info, warn};
use tracing_subscriber::{fmt, EnvFilter};

use async_nats::jetstream::context::Publish;
use hush_core::{sha256_hex, Hash, Keypair, MerkleTree, PublicKey, Signature};
use spine::{
    chain_head_from_envelope, checkpoint, nats_transport as nats, next_leaf_batch_size,
    verify_chain_link, ChainLinkVerdict, IssuerChainHead, TrustBundle,
};

const INGEST_RETRY_ATTEMPTS: usize = 4;
const INGEST_RETRY_BASE_BACKOFF_MS: u64 = 100;
const CHAIN_VIOLATION_SCHEMA: &str = "clawdstrike.spine.event.chain_violation.v1";

#[derive(Clone, Copy, Debug, Eq, PartialEq, ValueEnum)]
enum Mode {
    Run,
    Repair,
}

#[derive(Parser, Debug)]
#[command(name = "spine-checkpointer")]
#[command(about = "ClawdStrike Spine log checkpointer (RFC6962 Merkle roots + witness co-sign)")]
struct Args {
    /// Checkpointer mode: `run` (normal ingest/checkpoint loop) or `repair` (rebuild state from log/index)
    #[arg(long, default_value = "run", value_enum)]
    mode: Mode,

    /// Apply destructive repair mutations (purge + rebuild). Without this flag, repair runs as dry-run.
    #[arg(long, default_value_t = false)]
    repair_apply: bool,

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

    /// KV bucket storing checkpoints (keys: `latest`, `checkpoint/<seq>`, `checkpoint_hash/<hash>`)
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

    /// Hex-encoded 32-byte Ed25519 seed for the log operator key (required in `run` mode)
    #[arg(env = "SPINE_LOG_SEED_HEX")]
    log_seed_hex: Option<String>,

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

    /// KV bucket for per-issuer chain head state (restart recovery)
    #[arg(long, default_value = "CLAWDSTRIKE_ISSUER_HEADS")]
    issuer_heads_bucket: String,

    /// Chain enforcement mode: `warn` (log violations, accept anyway) or `strict` (reject violations)
    #[arg(long, default_value = "warn", value_parser = ["warn", "strict"])]
    chain_enforcement: String,

    /// JetStream stream for strict-mode chain violations
    #[arg(long, default_value = "CLAWDSTRIKE_CHAIN_VIOLATIONS")]
    chain_violation_stream: String,

    /// Subject for strict-mode chain violation events
    #[arg(long, default_value = "clawdstrike.spine.chain_violation.v1")]
    chain_violation_subject: String,
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

fn normalize_issuer_id(issuer: &str) -> String {
    issuer.to_ascii_lowercase()
}

fn issuer_heads_kv_key(issuer: &str) -> String {
    spine::parse_issuer_pubkey_hex(issuer).unwrap_or_else(|_| issuer.replace(':', "_"))
}

fn chain_verdict_reason(verdict: &ChainLinkVerdict) -> String {
    match verdict {
        ChainLinkVerdict::NewChain | ChainLinkVerdict::ValidContinuation => "valid".to_string(),
        ChainLinkVerdict::HashMismatch {
            expected_prev_hash,
            actual_prev_hash,
        } => format!(
            "prev_envelope_hash mismatch: expected {expected_prev_hash}, got {actual_prev_hash}"
        ),
        ChainLinkVerdict::SequenceMismatch {
            expected_seq,
            actual_seq,
        } => format!("sequence mismatch: expected {expected_seq}, got {actual_seq}"),
        ChainLinkVerdict::InvalidChainHead { reason } => reason.clone(),
    }
}

fn should_replace_loaded_head(existing: &IssuerChainHead, candidate: &IssuerChainHead) -> bool {
    if candidate.seq != existing.seq {
        return candidate.seq > existing.seq;
    }
    candidate.envelope_hash > existing.envelope_hash
}

#[derive(Debug, Clone)]
struct RetryPolicy {
    max_attempts: usize,
    base_backoff: Duration,
}

impl Default for RetryPolicy {
    fn default() -> Self {
        Self {
            max_attempts: INGEST_RETRY_ATTEMPTS,
            base_backoff: Duration::from_millis(INGEST_RETRY_BASE_BACKOFF_MS),
        }
    }
}

fn retry_delay(policy: &RetryPolicy, attempt: usize) -> Duration {
    let mut millis = policy.base_backoff.as_millis() as u64;
    for _ in 1..attempt {
        millis = millis.saturating_mul(3);
    }
    Duration::from_millis(millis)
}

async fn run_with_retries<T, F, Fut>(
    policy: &RetryPolicy,
    stage: &str,
    envelope_hash: &str,
    mut op: F,
) -> Result<T>
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = Result<T>>,
{
    for attempt in 1..=policy.max_attempts {
        match op().await {
            Ok(value) => return Ok(value),
            Err(err) if attempt < policy.max_attempts => {
                warn!(
                    stage = %stage,
                    envelope_hash = %envelope_hash,
                    attempt = attempt,
                    max_attempts = policy.max_attempts,
                    "stage failed, retrying: {err:#}"
                );
                sleep(retry_delay(policy, attempt)).await;
            }
            Err(err) => {
                return Err(err).context(format!(
                    "{stage} failed after {} attempts for envelope_hash={envelope_hash}",
                    policy.max_attempts
                ));
            }
        }
    }

    anyhow::bail!("unreachable retry loop termination")
}

async fn persist_envelope_if_missing(
    envelope_kv: &async_nats::jetstream::kv::Store,
    envelope_hash_hex: &str,
    payload: Vec<u8>,
) -> Result<()> {
    match envelope_kv.get(envelope_hash_hex).await {
        Ok(None) => {
            envelope_kv
                .put(envelope_hash_hex, payload.into())
                .await
                .context("failed to persist envelope payload")?;
        }
        Ok(Some(_)) => {}
        Err(err) => {
            return Err(err).context("failed to read envelope KV during persist");
        }
    }
    Ok(())
}

async fn persist_issuer_head(
    issuer_heads_kv: &async_nats::jetstream::kv::Store,
    issuer: &str,
    head: &IssuerChainHead,
) -> Result<()> {
    let head_bytes = serde_json::to_vec(head).context("failed to encode issuer head")?;
    issuer_heads_kv
        .put(issuer_heads_kv_key(issuer), head_bytes.into())
        .await
        .context("failed to persist issuer head")?;
    Ok(())
}

async fn publish_chain_violation_event(
    js: &async_nats::jetstream::Context,
    chain_violation_subject: &str,
    envelope: &Value,
    envelope_hash_hex: &str,
    issuer: &str,
    verdict: &ChainLinkVerdict,
    enforcement: &str,
) -> Result<()> {
    let seq = envelope.get("seq").and_then(|v| v.as_u64());
    let event = json!({
        "schema": CHAIN_VIOLATION_SCHEMA,
        "issuer": issuer,
        "issuer_pubkey_hex": spine::parse_issuer_pubkey_hex(issuer).ok(),
        "envelope_hash": envelope_hash_hex,
        "seq": seq,
        "enforcement": enforcement,
        "verdict": format!("{verdict:?}"),
        "reason": chain_verdict_reason(verdict),
        "detected_at": spine::now_rfc3339(),
        "envelope": envelope,
    });

    let payload = serde_json::to_vec(&event).context("failed to encode chain violation event")?;
    let ack = js
        .send_publish(
            chain_violation_subject.to_string(),
            Publish::build()
                .payload(payload.into())
                .message_id(format!("chain-violation:{envelope_hash_hex}")),
        )
        .await
        .context("failed to publish chain violation event")?;
    let _ = ack.await.context("failed to ack chain violation event")?;
    Ok(())
}

async fn load_latest_checkpoint(kv: &async_nats::jetstream::kv::Store) -> Result<Option<Value>> {
    match kv.get("latest").await? {
        Some(bytes) => Ok(Some(serde_json::from_slice(&bytes)?)),
        None => Ok(None),
    }
}

/// Load all persisted issuer chain heads from KV.
async fn load_issuer_heads(
    kv: &async_nats::jetstream::kv::Store,
) -> Result<HashMap<String, IssuerChainHead>> {
    let mut heads = HashMap::new();
    let keys = kv.keys().await?.try_collect::<Vec<String>>().await?;
    for key in keys {
        let Some(bytes) = kv.get(&key).await? else {
            continue;
        };
        let head: IssuerChainHead = match serde_json::from_slice(&bytes) {
            Ok(h) => h,
            Err(err) => {
                warn!(key = %key, "invalid issuer head JSON in KV: {err}");
                continue;
            }
        };
        let normalized_issuer = normalize_issuer_id(&head.issuer);
        if let Some(existing) = heads.get(&normalized_issuer) {
            if should_replace_loaded_head(existing, &head) {
                warn!(
                    issuer = %normalized_issuer,
                    existing_seq = existing.seq,
                    candidate_seq = head.seq,
                    "issuer head collision during load; replacing with higher-order head"
                );
                heads.insert(normalized_issuer, head);
            } else {
                warn!(
                    issuer = %normalized_issuer,
                    existing_seq = existing.seq,
                    candidate_seq = head.seq,
                    "issuer head collision during load; keeping existing head"
                );
            }
        } else {
            heads.insert(normalized_issuer, head);
        }
    }
    Ok(heads)
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

async fn backfill_checkpoint_hash_index(
    checkpoint_kv: &async_nats::jetstream::kv::Store,
) -> Result<(usize, usize)> {
    let keys = checkpoint_kv
        .keys()
        .await?
        .try_collect::<Vec<String>>()
        .await?;
    let mut scanned: usize = 0;
    let mut added: usize = 0;

    for key in keys {
        if !key.starts_with("checkpoint/") {
            continue;
        }
        scanned += 1;

        let Some(bytes) = checkpoint_kv.get(&key).await? else {
            continue;
        };

        let envelope: Value = match serde_json::from_slice(&bytes) {
            Ok(v) => v,
            Err(err) => {
                warn!(checkpoint_key = %key, "invalid checkpoint JSON in KV: {err}");
                continue;
            }
        };
        let Some(fact) = envelope.get("fact") else {
            warn!(checkpoint_key = %key, "checkpoint envelope missing fact");
            continue;
        };
        let statement = match build_checkpoint_statement_from_fact(fact) {
            Ok(v) => v,
            Err(err) => {
                warn!(checkpoint_key = %key, "invalid checkpoint fact: {err:#}");
                continue;
            }
        };
        let checkpoint_hash = match checkpoint::checkpoint_hash(&statement) {
            Ok(v) => v.to_hex_prefixed(),
            Err(err) => {
                warn!(checkpoint_key = %key, "failed to compute checkpoint hash: {err:#}");
                continue;
            }
        };

        let hash_index_key = format!("checkpoint_hash/{checkpoint_hash}");
        if checkpoint_kv.get(&hash_index_key).await?.is_some() {
            continue;
        }

        if let Err(err) = checkpoint_kv.put(&hash_index_key, bytes.clone()).await {
            warn!(checkpoint_key = %key, hash_index_key = %hash_index_key, "failed to backfill checkpoint hash index: {err}");
            continue;
        }
        added += 1;
    }

    Ok((scanned, added))
}

/// Load all leaves from the index KV bucket.
async fn load_leaves_from_index(kv: &async_nats::jetstream::kv::Store) -> Result<Vec<Vec<u8>>> {
    load_leaves_from_index_after(kv, 0).await
}

/// Load leaves from the index KV bucket with seq > `min_seq`.
/// Returns pairs sorted by seq, validated for contiguity starting from `min_seq + 1`.
async fn load_leaves_from_index_after(
    kv: &async_nats::jetstream::kv::Store,
    min_seq: u64,
) -> Result<Vec<Vec<u8>>> {
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
        if seq <= min_seq {
            continue;
        }
        let h = Hash::from_hex(&key)?;
        pairs.push((seq, h.as_bytes().to_vec()));
    }

    pairs.sort_by_key(|(seq, _)| *seq);

    // Validate contiguous sequences (no gaps).
    if let Some(first) = pairs.first() {
        if min_seq > 0 && first.0 != min_seq + 1 {
            anyhow::bail!(
                "log index has gap: expected seq {} after {}, got {}",
                min_seq + 1,
                min_seq,
                first.0
            );
        }
    }
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
            tracing::warn!("no trust bundle configured — checkpoint created with zero witness co-signatures (dev mode)");
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
    checkpoint_counter: &mut u64,
    cached_leaves: &mut Vec<Vec<u8>>,
    checkpoint_every: u64,
) -> Result<()> {
    // Incremental load: only fetch leaves with seq > current cached count.
    let new_leaves = load_leaves_from_index_after(index_kv, cached_leaves.len() as u64).await?;
    cached_leaves.extend(new_leaves);
    let tree_size = cached_leaves.len() as u64;

    if tree_size == 0 {
        return Ok(());
    }
    if tree_size <= *last_checkpoint_tree_size {
        return Ok(());
    }
    if (tree_size - *last_checkpoint_tree_size) < checkpoint_every {
        return Ok(());
    }

    *checkpoint_counter = checkpoint_counter
        .checked_add(1)
        .context("checkpoint counter overflow")?;
    let checkpoint_seq = *checkpoint_counter;

    let tree = MerkleTree::from_leaves(cached_leaves)?;
    let merkle_root = tree.root().to_hex_prefixed();
    let issued_at = spine::now_rfc3339();

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

    let envelope_seq = last_envelope_seq
        .checked_add(1)
        .context("envelope sequence overflow")?;
    let prev_envelope_hash = (*last_envelope_hash).clone();
    let envelope = spine::build_signed_envelope(
        log_keypair,
        envelope_seq,
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
    *last_envelope_seq = envelope_seq;
    *last_envelope_hash = envelope
        .get("envelope_hash")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());

    let cp_hash = checkpoint::checkpoint_hash(&statement)?.to_hex_prefixed();
    if let Err(e) = checkpoint_kv
        .put(
            format!("checkpoint_hash/{cp_hash}"),
            envelope_bytes.clone().into(),
        )
        .await
    {
        warn!(
            checkpoint_hash = %cp_hash,
            "failed to store checkpoint hash index: {e}"
        );
    }
    *last_checkpoint_hash = Some(cp_hash);

    info!(
        "published checkpoint seq={} tree_size={} merkle_root={}",
        checkpoint_seq, tree_size, envelope["fact"]["merkle_root"]
    );

    Ok(())
}

async fn index_fact_key(
    fact_index_kv: &async_nats::jetstream::kv::Store,
    key: &str,
    value: &[u8],
) -> Result<()> {
    fact_index_kv
        .put(key, value.to_vec().into())
        .await
        .with_context(|| format!("failed to index fact key={key}"))?;
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
            let Some((policy_key, normalized_policy_hash)) =
                normalized_policy_index_entry(policy_hash)
            else {
                return Ok(());
            };
            index_fact_key(fact_index_kv, &policy_key, envelope_hash.as_bytes()).await?;

            if let Some(version) = fact.get("policy_version").and_then(|v| v.as_str()) {
                if is_safe_index_key_token(version, 200) {
                    index_fact_key(
                        fact_index_kv,
                        &format!("policy_version.{version}"),
                        normalized_policy_hash.as_bytes(),
                    )
                    .await?;
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
            index_fact_key(
                fact_index_kv,
                &format!("run_receipt.{run_id}"),
                envelope_hash.as_bytes(),
            )
            .await?;
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

            index_fact_key(
                fact_index_kv,
                &format!("receipt_verification.{target}.{verifier_pk}"),
                envelope_hash.as_bytes(),
            )
            .await?;
        }
        spine::NODE_ATTESTATION_SCHEMA => {
            let Some(node_id) = fact.get("node_id").and_then(|v| v.as_str()) else {
                return Ok(());
            };
            let issuer_pk = match spine::parse_issuer_pubkey_hex(node_id) {
                Ok(p) => p,
                Err(_) => return Ok(()),
            };
            if !is_safe_index_key_token(&issuer_pk, 128) {
                return Ok(());
            }

            index_fact_key(
                fact_index_kv,
                &format!("node_attestation.{issuer_pk}"),
                envelope_hash.as_bytes(),
            )
            .await?;
        }
        spine::POLICY_ATTESTATION_SCHEMA => {
            let Some(bundle_hash) = fact.get("bundle_hash").and_then(|v| v.as_str()) else {
                return Ok(());
            };
            if !is_safe_index_key_token(bundle_hash, 256) {
                return Ok(());
            }

            index_fact_key(
                fact_index_kv,
                &format!("policy_attestation.{bundle_hash}"),
                envelope_hash.as_bytes(),
            )
            .await?;
        }
        spine::REVOCATION_SCHEMA => {
            let Some(bundle_hash) = fact.get("bundle_hash").and_then(|v| v.as_str()) else {
                return Ok(());
            };
            if !is_safe_index_key_token(bundle_hash, 256) {
                return Ok(());
            }

            index_fact_key(
                fact_index_kv,
                &format!("policy_revocation.{bundle_hash}"),
                envelope_hash.as_bytes(),
            )
            .await?;
        }
        spine::FEED_ENTRY_FACT_SCHEMA => {
            let issuer = envelope
                .get("issuer")
                .and_then(|v| v.as_str())
                .unwrap_or("");
            let issuer_pk = match spine::parse_issuer_pubkey_hex(issuer) {
                Ok(p) => p,
                Err(_) => return Ok(()),
            };
            let Some(feed_seq) = fact.get("feed_seq").and_then(|v| v.as_u64()) else {
                return Ok(());
            };
            if !is_safe_index_key_token(&issuer_pk, 128) {
                return Ok(());
            }

            index_fact_key(
                fact_index_kv,
                &format!("marketplace_entry.{issuer_pk}.{feed_seq}"),
                envelope_hash.as_bytes(),
            )
            .await?;
        }
        spine::HEAD_ANNOUNCEMENT_SCHEMA => {
            let issuer = envelope
                .get("issuer")
                .and_then(|v| v.as_str())
                .unwrap_or("");
            let issuer_pk = match spine::parse_issuer_pubkey_hex(issuer) {
                Ok(p) => p,
                Err(_) => return Ok(()),
            };
            if !is_safe_index_key_token(&issuer_pk, 128) {
                return Ok(());
            }

            index_fact_key(
                fact_index_kv,
                &format!("marketplace_head.{issuer_pk}"),
                envelope_hash.as_bytes(),
            )
            .await?;
        }
        spine::RUNTIME_PROOF_SCHEMA => {
            let exec_id = fact
                .get("execution")
                .and_then(|e| e.get("exec_id"))
                .and_then(|v| v.as_str());
            let Some(exec_id) = exec_id else {
                return Ok(());
            };
            let exec_id_hash = sha256_hex(exec_id.as_bytes());
            let hash_token = exec_id_hash.strip_prefix("0x").unwrap_or(&exec_id_hash);
            if !is_safe_index_key_token(hash_token, 128) {
                return Ok(());
            }

            index_fact_key(
                fact_index_kv,
                &format!("runtime_proof.{hash_token}"),
                envelope_hash.as_bytes(),
            )
            .await?;
        }
        _ => {}
    }

    Ok(())
}

fn normalized_policy_index_entry(policy_hash: &str) -> Option<(String, String)> {
    let policy_key = spine::policy_index_key(policy_hash)?;
    let normalized = policy_key.strip_prefix("policy.")?.to_string();
    Some((policy_key, normalized))
}

#[derive(Debug, Clone)]
struct IndexEntry {
    seq: u64,
    hash_hex: String,
}

async fn load_index_entries(
    index_kv: &async_nats::jetstream::kv::Store,
) -> Result<Vec<IndexEntry>> {
    let keys = index_kv.keys().await?.try_collect::<Vec<String>>().await?;
    let mut entries: Vec<IndexEntry> = Vec::with_capacity(keys.len());

    for key in keys {
        let hash =
            Hash::from_hex(&key).with_context(|| format!("invalid index key hash: {key}"))?;
        let Some(value) = index_kv.get(&key).await? else {
            continue;
        };
        let seq_str = std::str::from_utf8(&value)
            .context("index value is not valid UTF-8")?
            .trim();
        let seq: u64 = seq_str
            .parse()
            .with_context(|| format!("invalid index sequence for key={key}: {seq_str}"))?;
        entries.push(IndexEntry {
            seq,
            hash_hex: hash.to_hex_prefixed(),
        });
    }

    entries.sort_by_key(|e| e.seq);
    for (idx, entry) in entries.iter().enumerate() {
        let expected = (idx + 1) as u64;
        if entry.seq != expected {
            anyhow::bail!(
                "log index has gap or duplicate: expected seq={expected}, got seq={} hash={}",
                entry.seq,
                entry.hash_hex
            );
        }
    }

    Ok(entries)
}

async fn load_log_hashes(
    js: &async_nats::jetstream::Context,
    log_stream: &str,
    expected_messages: usize,
) -> Result<Vec<String>> {
    let mut stream = js
        .get_stream(log_stream)
        .await
        .with_context(|| format!("failed to get stream {log_stream}"))?;
    let stream_info = stream.info().await?;
    let stream_messages = usize::try_from(stream_info.state.messages)
        .context("stream message count exceeds usize")?;
    if stream_messages != expected_messages {
        anyhow::bail!(
            "stream/index mismatch: stream has {stream_messages} messages, index has {expected_messages} entries"
        );
    }
    if expected_messages == 0 {
        return Ok(Vec::new());
    }

    let consumer = stream
        .create_consumer(async_nats::jetstream::consumer::pull::Config {
            deliver_policy: async_nats::jetstream::consumer::DeliverPolicy::ByStartSequence {
                start_sequence: 1,
            },
            ack_policy: async_nats::jetstream::consumer::AckPolicy::None,
            ..Default::default()
        })
        .await
        .context("failed to create stream consumer for repair")?;

    let mut hashes = Vec::with_capacity(expected_messages);
    while hashes.len() < expected_messages {
        let remaining = expected_messages - hashes.len();
        let mut messages = consumer
            .fetch()
            .max_messages(next_leaf_batch_size(remaining))
            .messages()
            .await
            .context("failed to fetch stream leaves for repair")?;

        let mut pulled = 0usize;
        while let Some(msg) = messages.next().await {
            let msg = msg.map_err(|err| {
                anyhow::anyhow!("failed to read stream leaf during repair: {err}")
            })?;
            if msg.payload.len() != 32 {
                anyhow::bail!("invalid stream leaf payload length: {}", msg.payload.len());
            }
            let arr: [u8; 32] = msg
                .payload
                .as_ref()
                .try_into()
                .context("failed to convert stream leaf payload to hash bytes")?;
            hashes.push(Hash::from_bytes(arr).to_hex_prefixed());
            pulled += 1;
        }

        if pulled == 0 {
            break;
        }
    }

    if hashes.len() != expected_messages {
        anyhow::bail!(
            "incomplete stream read during repair: got {} expected {}",
            hashes.len(),
            expected_messages
        );
    }

    Ok(hashes)
}

async fn load_envelopes_by_index(
    envelope_kv: &async_nats::jetstream::kv::Store,
    index_entries: &[IndexEntry],
) -> Result<Vec<Value>> {
    let mut envelopes = Vec::with_capacity(index_entries.len());
    for entry in index_entries {
        let Some(bytes) = envelope_kv.get(&entry.hash_hex).await? else {
            anyhow::bail!(
                "missing envelope payload for hash={} seq={}",
                entry.hash_hex,
                entry.seq
            );
        };
        let envelope: Value = serde_json::from_slice(&bytes)
            .with_context(|| format!("invalid envelope JSON for hash={}", entry.hash_hex))?;
        let (verified_hash, _) = verify_signed_envelope(&envelope)
            .with_context(|| format!("invalid signed envelope for hash={}", entry.hash_hex))?;
        if verified_hash != entry.hash_hex {
            anyhow::bail!(
                "envelope hash mismatch during repair: index={} payload={}",
                entry.hash_hex,
                verified_hash
            );
        }
        envelopes.push(envelope);
    }
    Ok(envelopes)
}

async fn purge_kv_bucket(
    kv: &async_nats::jetstream::kv::Store,
    bucket_name: &str,
) -> Result<usize> {
    let keys = kv.keys().await?.try_collect::<Vec<String>>().await?;
    let mut deleted = 0usize;
    for key in keys {
        kv.delete(&key)
            .await
            .with_context(|| format!("failed to delete key={key} from bucket={bucket_name}"))?;
        deleted += 1;
    }
    Ok(deleted)
}

async fn run_repair_mode(
    args: &Args,
    js: &async_nats::jetstream::Context,
    index_kv: &async_nats::jetstream::kv::Store,
    envelope_kv: &async_nats::jetstream::kv::Store,
    fact_index_kv: &async_nats::jetstream::kv::Store,
    issuer_heads_kv: &async_nats::jetstream::kv::Store,
) -> Result<()> {
    let index_entries = load_index_entries(index_kv).await?;
    info!("repair: loaded {} log index entries", index_entries.len());

    let log_hashes = load_log_hashes(js, &args.log_stream, index_entries.len()).await?;
    for (idx, (entry, stream_hash)) in index_entries.iter().zip(log_hashes.iter()).enumerate() {
        if entry.hash_hex != *stream_hash {
            anyhow::bail!(
                "stream/index mismatch at seq {}: index={} stream={}",
                idx + 1,
                entry.hash_hex,
                stream_hash
            );
        }
    }

    let envelopes = load_envelopes_by_index(envelope_kv, &index_entries).await?;
    info!(
        "repair: loaded and validated {} envelopes from envelope KV",
        envelopes.len()
    );

    let mut rebuilt_heads: HashMap<String, IssuerChainHead> = HashMap::new();
    for envelope in &envelopes {
        let issuer = envelope
            .get("issuer")
            .and_then(|v| v.as_str())
            .map_or_else(String::new, normalize_issuer_id);
        let known_head = rebuilt_heads.get(&issuer);
        let verdict = verify_chain_link(envelope, known_head)
            .with_context(|| format!("repair: chain verification failed for issuer={issuer}"))?;
        let new_head = chain_head_from_envelope(envelope)
            .with_context(|| format!("repair: failed to build chain head for issuer={issuer}"))?;
        let dominated = rebuilt_heads
            .get(&issuer)
            .is_some_and(|cur| cur.seq >= new_head.seq);
        if verdict.is_valid() || !dominated {
            rebuilt_heads.insert(issuer, new_head);
        }
    }

    let fact_candidates = envelopes
        .iter()
        .filter(|e| {
            e.get("fact")
                .and_then(|f| f.get("schema"))
                .and_then(|v| v.as_str())
                .is_some_and(|s| !s.is_empty())
        })
        .count();

    if !args.repair_apply {
        info!(
            "repair dry-run complete: index_entries={} envelopes={} fact_candidates={} rebuilt_heads={} (no writes applied; pass --repair-apply to execute)",
            index_entries.len(),
            envelopes.len(),
            fact_candidates,
            rebuilt_heads.len()
        );
        return Ok(());
    }

    let deleted_fact_keys = purge_kv_bucket(fact_index_kv, &args.fact_index_bucket).await?;
    let deleted_head_keys = purge_kv_bucket(issuer_heads_kv, &args.issuer_heads_bucket).await?;
    info!(
        "repair apply: purged fact_index_keys={} issuer_head_keys={}",
        deleted_fact_keys, deleted_head_keys
    );

    for (entry, envelope) in index_entries.iter().zip(envelopes.iter()) {
        maybe_index_fact(fact_index_kv, envelope, &entry.hash_hex)
            .await
            .with_context(|| {
                format!("repair: failed indexing facts for hash={}", entry.hash_hex)
            })?;
    }

    for (issuer, head) in &rebuilt_heads {
        persist_issuer_head(issuer_heads_kv, issuer, head).await?;
    }

    info!(
        "repair apply complete: rebuilt_fact_candidates={} rebuilt_heads={}",
        fact_candidates,
        rebuilt_heads.len()
    );
    Ok(())
}

#[tokio::main]
async fn main() -> Result<()> {
    fmt()
        .with_env_filter(EnvFilter::from_default_env().add_directive("info".parse()?))
        .with_target(false)
        .init();

    let args = Args::parse();
    let (run_log_keypair, run_log_id, trust_bundle) = match args.mode {
        Mode::Run => {
            let seed = args
                .log_seed_hex
                .as_deref()
                .context("SPINE_LOG_SEED_HEX is required in run mode")?;
            let log_keypair = Keypair::from_hex(&spine::normalize_seed_hex(seed))
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
            (Some(log_keypair), Some(log_id), trust_bundle)
        }
        Mode::Repair => (None, None, None),
    };

    info!(
        "starting checkpointer mode={:?} nats={}",
        args.mode, args.nats_url
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
    let _chain_violation_stream = nats::ensure_stream(
        &js,
        &args.chain_violation_stream,
        vec![args.chain_violation_subject.clone()],
        args.replicas,
    )
    .await?;

    let index_kv = nats::ensure_kv(&js, &args.index_bucket, args.replicas).await?;
    let checkpoint_kv = nats::ensure_kv(&js, &args.checkpoint_bucket, args.replicas).await?;
    let envelope_kv = nats::ensure_kv(&js, &args.envelope_bucket, args.replicas).await?;
    let fact_index_kv = nats::ensure_kv(&js, &args.fact_index_bucket, args.replicas).await?;
    let issuer_heads_kv = nats::ensure_kv(&js, &args.issuer_heads_bucket, args.replicas).await?;

    if args.mode == Mode::Repair {
        return run_repair_mode(
            &args,
            &js,
            &index_kv,
            &envelope_kv,
            &fact_index_kv,
            &issuer_heads_kv,
        )
        .await;
    }

    let log_keypair = run_log_keypair.context("missing run-mode log keypair")?;
    let log_id = run_log_id.context("missing run-mode log_id")?;

    info!(
        "starting checkpointer ingest log_id={} nats={}",
        log_id, args.nats_url
    );

    let chain_strict = args.chain_enforcement == "strict";
    let retry_policy = RetryPolicy::default();
    let mut issuer_heads: HashMap<String, IssuerChainHead> = match run_with_retries(
        &retry_policy,
        "load_issuer_heads",
        "startup",
        || async { load_issuer_heads(&issuer_heads_kv).await },
    )
    .await
    {
        Ok(heads) => {
            info!("loaded {} issuer chain heads from KV", heads.len());
            heads
        }
        Err(err) => {
            if chain_strict {
                return Err(err).context(
                        "failed to load issuer heads in strict mode; refusing to start with empty chain state",
                    );
            }
            warn!("failed to load issuer heads: {err:#}, starting fresh");
            HashMap::new()
        }
    };

    match backfill_checkpoint_hash_index(&checkpoint_kv).await {
        Ok((scanned, added)) => {
            info!(
                "checkpoint hash index backfill complete scanned={} added={}",
                scanned, added
            );
        }
        Err(err) => {
            warn!("checkpoint hash index backfill failed: {err:#}");
        }
    }

    // Initialize checkpoint state from KV (if present).
    let mut last_checkpoint_tree_size: u64 = 0;
    let mut last_envelope_seq: u64 = 0;
    let mut last_envelope_hash: Option<String> = None;
    let mut last_checkpoint_hash: Option<String> = None;
    let mut checkpoint_counter: u64 = 0;

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
            if let Some(cs) = fact.get("checkpoint_seq").and_then(|v| v.as_u64()) {
                checkpoint_counter = cs;
            }
            let statement = build_checkpoint_statement_from_fact(fact)?;
            last_checkpoint_hash = Some(checkpoint::checkpoint_hash(&statement)?.to_hex_prefixed());
        }
        info!(
            "loaded latest checkpoint counter={} envelope_seq={} tree_size={}",
            checkpoint_counter, last_envelope_seq, last_checkpoint_tree_size
        );
    }

    // Pre-load existing leaves so incremental loading starts from the right offset.
    let mut cached_leaves: Vec<Vec<u8>> = if last_checkpoint_tree_size > 0 {
        load_leaves_from_index(&index_kv).await?
    } else {
        Vec::new()
    };

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
                    &mut checkpoint_counter,
                    &mut cached_leaves,
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

                let envelope_issuer = envelope
                    .get("issuer")
                    .and_then(|v| v.as_str())
                    .map_or_else(String::new, normalize_issuer_id);

                if let Some(tb) = trust_bundle.as_ref() {
                    if !tb.envelope_issuer_allowed(&envelope_issuer) {
                        warn!(
                            issuer = %envelope_issuer,
                            envelope_hash = %envelope_hash_hex,
                            "rejected envelope from disallowed issuer"
                        );
                        continue;
                    }
                }

                let known_head = issuer_heads.get(&envelope_issuer);
                let chain_verdict = match verify_chain_link(&envelope, known_head) {
                    Ok(v) => v,
                    Err(err) => {
                        warn!(
                            issuer = %envelope_issuer,
                            envelope_hash = %envelope_hash_hex,
                            "chain verification error: {err:#}"
                        );
                        continue;
                    }
                };

                if !chain_verdict.is_valid() {
                    warn!(
                        issuer = %envelope_issuer,
                        envelope_hash = %envelope_hash_hex,
                        verdict = ?chain_verdict,
                        enforcement = %args.chain_enforcement,
                        "chain integrity violation detected"
                    );
                    let publish_result = run_with_retries(
                        &retry_policy,
                        "publish_chain_violation",
                        &envelope_hash_hex,
                        || async {
                            publish_chain_violation_event(
                                &js,
                                &args.chain_violation_subject,
                                &envelope,
                                &envelope_hash_hex,
                                &envelope_issuer,
                                &chain_verdict,
                                &args.chain_enforcement,
                            )
                            .await
                        },
                    )
                    .await;
                    if let Err(err) = publish_result {
                        warn!(
                            issuer = %envelope_issuer,
                            envelope_hash = %envelope_hash_hex,
                            "failed to publish chain violation event: {err:#}"
                        );
                    }
                    if chain_strict {
                        continue;
                    }
                    // warn mode: update head anyway (self-heal on first deploy)
                }

                let persist_result = run_with_retries(
                    &retry_policy,
                    "persist_envelope",
                    &envelope_hash_hex,
                    || {
                        let payload = msg.payload.to_vec();
                        async {
                            persist_envelope_if_missing(&envelope_kv, &envelope_hash_hex, payload).await
                        }
                    },
                )
                .await;
                if let Err(err) = persist_result {
                    warn!(
                        issuer = %envelope_issuer,
                        envelope_hash = %envelope_hash_hex,
                        "dropping envelope after persistent envelope write failure: {err:#}"
                    );
                    continue;
                }

                let h = match Hash::from_hex(&envelope_hash_hex) {
                    Ok(v) => v,
                    Err(_) => continue,
                };

                let seq = match run_with_retries(
                    &retry_policy,
                    "append_log",
                    &envelope_hash_hex,
                    || async {
                        ensure_log_append(
                            &js,
                            &index_kv,
                            &args.log_subject,
                            &envelope_hash_hex,
                            h.as_bytes(),
                        )
                        .await
                    },
                )
                .await {
                    Ok(s) => s,
                    Err(err) => {
                        warn!(
                            issuer = %envelope_issuer,
                            envelope_hash = %envelope_hash_hex,
                            "dropping envelope after log append failure: {err:#}"
                        );
                        continue;
                    }
                };

                if seq > 0 {
                    info!("appended leaf seq={} envelope_hash={}", seq, envelope_hash_hex);
                }

                if let Err(err) = run_with_retries(
                    &retry_policy,
                    "index_fact",
                    &envelope_hash_hex,
                    || async { maybe_index_fact(&fact_index_kv, &envelope, &envelope_hash_hex).await },
                )
                .await
                {
                    warn!(
                        issuer = %envelope_issuer,
                        envelope_hash = %envelope_hash_hex,
                        "fact indexing failed after retries (continuing ingest): {err:#}"
                    );
                }

                if let Ok(new_head) = chain_head_from_envelope(&envelope) {
                    let dominated = issuer_heads
                        .get(&envelope_issuer)
                        .is_some_and(|cur| cur.seq >= new_head.seq);
                    if chain_verdict.is_valid() || !dominated {
                        issuer_heads.insert(envelope_issuer.clone(), new_head);
                        let head_to_persist = issuer_heads.get(&envelope_issuer).cloned();
                        if let Some(head_to_persist) = head_to_persist {
                            if let Err(err) = run_with_retries(
                                &retry_policy,
                                "persist_issuer_head",
                                &envelope_hash_hex,
                                || {
                                    let issuer_heads_kv = issuer_heads_kv.clone();
                                    let envelope_issuer = envelope_issuer.clone();
                                    let head_to_persist = head_to_persist.clone();
                                    async move {
                                        persist_issuer_head(
                                            &issuer_heads_kv,
                                            &envelope_issuer,
                                            &head_to_persist,
                                        )
                                        .await
                                    }
                                },
                            )
                            .await
                            {
                                warn!(
                                    issuer = %envelope_issuer,
                                    envelope_hash = %envelope_hash_hex,
                                    "failed to persist issuer head after retries: {err:#}"
                                );
                            }
                        }
                    }
                }
            }
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;
    use std::rc::Rc;

    #[test]
    fn normalized_policy_index_entry_normalizes_hash_and_key() {
        let Some((key, hash)) = normalized_policy_index_entry(
            "AABBcc00aabbcc00aabbcc00aabbcc00aabbcc00aabbcc00aabbcc00aabbcc00",
        ) else {
            panic!("expected valid policy hash to normalize");
        };
        assert_eq!(
            key,
            "policy.0xaabbcc00aabbcc00aabbcc00aabbcc00aabbcc00aabbcc00aabbcc00aabbcc00"
        );
        assert_eq!(
            hash,
            "0xaabbcc00aabbcc00aabbcc00aabbcc00aabbcc00aabbcc00aabbcc00aabbcc00"
        );
    }

    #[test]
    fn normalized_policy_index_entry_rejects_invalid_hash() {
        assert!(normalized_policy_index_entry("abc").is_none());
        assert!(normalized_policy_index_entry("0xzz").is_none());
    }

    #[test]
    fn normalize_issuer_id_lowercases() {
        let issuer =
            "aegis:ed25519:AABBCCDDEEFF00112233445566778899AABBCCDDEEFF00112233445566778899";
        assert_eq!(
            normalize_issuer_id(issuer),
            "aegis:ed25519:aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899"
        );
    }

    #[test]
    fn should_replace_loaded_head_prefers_higher_seq() {
        let existing = IssuerChainHead {
            issuer: "aegis:ed25519:aa".into(),
            seq: 10,
            envelope_hash: "0x10".into(),
        };
        let candidate = IssuerChainHead {
            issuer: "aegis:ed25519:aa".into(),
            seq: 11,
            envelope_hash: "0x01".into(),
        };
        assert!(should_replace_loaded_head(&existing, &candidate));
    }

    #[test]
    fn should_replace_loaded_head_tie_breaks_by_hash() {
        let existing = IssuerChainHead {
            issuer: "aegis:ed25519:aa".into(),
            seq: 10,
            envelope_hash: "0xaaaaaaaa".into(),
        };
        let candidate = IssuerChainHead {
            issuer: "aegis:ed25519:aa".into(),
            seq: 10,
            envelope_hash: "0xbbbbbbbb".into(),
        };
        assert!(should_replace_loaded_head(&existing, &candidate));
    }

    #[tokio::test]
    async fn retry_helper_retries_then_succeeds() {
        let attempts = Rc::new(RefCell::new(0usize));
        let policy = RetryPolicy {
            max_attempts: 4,
            base_backoff: Duration::from_millis(0),
        };
        let result = run_with_retries(&policy, "test_stage", "0xabc", || {
            let attempts = attempts.clone();
            async move {
                let mut n = attempts.borrow_mut();
                *n += 1;
                if *n < 3 {
                    anyhow::bail!("transient");
                }
                Ok(*n)
            }
        })
        .await;
        let result = match result {
            Ok(value) => value,
            Err(err) => panic!("retry should eventually succeed: {err:#}"),
        };
        assert_eq!(result, 3);
    }

    #[derive(Default, Debug)]
    struct MockIngestState {
        envelope_persisted: bool,
        log_appended: bool,
        fact_indexed: bool,
        head_persisted: bool,
    }

    #[derive(Default, Debug)]
    struct MockFailures {
        persist: usize,
        append: usize,
        index: usize,
        head: usize,
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    enum MockIngestResult {
        DroppedPersist,
        DroppedAppend,
        Completed,
    }

    async fn run_mock_ingest_with_failures(
        failures: MockFailures,
    ) -> (MockIngestResult, MockIngestState) {
        let policy = RetryPolicy {
            max_attempts: 2,
            base_backoff: Duration::from_millis(0),
        };
        let state = Rc::new(RefCell::new(MockIngestState::default()));
        let failures = Rc::new(RefCell::new(failures));

        let persist = run_with_retries(&policy, "persist_envelope", "0xdead", || {
            let state = state.clone();
            let failures = failures.clone();
            async move {
                let mut f = failures.borrow_mut();
                if f.persist > 0 {
                    f.persist -= 1;
                    anyhow::bail!("persist failed");
                }
                state.borrow_mut().envelope_persisted = true;
                Ok(())
            }
        })
        .await;
        if persist.is_err() {
            return (MockIngestResult::DroppedPersist, state.take());
        }

        let append = run_with_retries(&policy, "append_log", "0xdead", || {
            let state = state.clone();
            let failures = failures.clone();
            async move {
                let mut f = failures.borrow_mut();
                if f.append > 0 {
                    f.append -= 1;
                    anyhow::bail!("append failed");
                }
                state.borrow_mut().log_appended = true;
                Ok(7u64)
            }
        })
        .await;
        if append.is_err() {
            return (MockIngestResult::DroppedAppend, state.take());
        }

        let _ = run_with_retries(&policy, "index_fact", "0xdead", || {
            let state = state.clone();
            let failures = failures.clone();
            async move {
                let mut f = failures.borrow_mut();
                if f.index > 0 {
                    f.index -= 1;
                    anyhow::bail!("index failed");
                }
                state.borrow_mut().fact_indexed = true;
                Ok(())
            }
        })
        .await;

        let _ = run_with_retries(&policy, "persist_issuer_head", "0xdead", || {
            let state = state.clone();
            let failures = failures.clone();
            async move {
                let mut f = failures.borrow_mut();
                if f.head > 0 {
                    f.head -= 1;
                    anyhow::bail!("head failed");
                }
                state.borrow_mut().head_persisted = true;
                Ok(())
            }
        })
        .await;

        (MockIngestResult::Completed, state.take())
    }

    #[tokio::test]
    async fn ingest_contract_drop_on_persist_failure_prevents_partial_writes() {
        let (result, state) = run_mock_ingest_with_failures(MockFailures {
            persist: 2,
            ..MockFailures::default()
        })
        .await;
        assert_eq!(result, MockIngestResult::DroppedPersist);
        assert!(!state.envelope_persisted);
        assert!(!state.log_appended);
        assert!(!state.fact_indexed);
        assert!(!state.head_persisted);
    }

    #[tokio::test]
    async fn ingest_contract_drop_on_append_failure_prevents_fact_and_head_writes() {
        let (result, state) = run_mock_ingest_with_failures(MockFailures {
            append: 2,
            ..MockFailures::default()
        })
        .await;
        assert_eq!(result, MockIngestResult::DroppedAppend);
        assert!(state.envelope_persisted);
        assert!(!state.log_appended);
        assert!(!state.fact_indexed);
        assert!(!state.head_persisted);
    }

    #[tokio::test]
    async fn ingest_contract_continues_to_head_when_fact_index_fails() {
        let (result, state) = run_mock_ingest_with_failures(MockFailures {
            index: 2,
            ..MockFailures::default()
        })
        .await;
        assert_eq!(result, MockIngestResult::Completed);
        assert!(state.envelope_persisted);
        assert!(state.log_appended);
        assert!(!state.fact_indexed);
        assert!(state.head_persisted);
    }
}
