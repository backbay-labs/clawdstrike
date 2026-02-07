//! ClawdStrike Spine proofs API.
//!
//! Axum HTTP server exposing checkpoint and inclusion-proof endpoints.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use anyhow::{Context, Result};
use axum::{
    extract::{Path, Query, Request, State},
    http::StatusCode,
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::get,
    Json, Router,
};
use clap::Parser;
use futures::TryStreamExt;
use serde::Deserialize;
use serde_json::{json, Value};
use tower_http::trace::TraceLayer;
use tracing::{info, warn};
use tracing_subscriber::{fmt, EnvFilter};

use hush_core::{Hash, MerkleTree};
use spine::{hash, nats_transport as nats};

#[derive(Parser, Debug)]
#[command(name = "spine-proofs-api")]
#[command(about = "ClawdStrike Spine proofs API (inclusion proofs for log checkpoints)")]
struct Args {
    /// NATS server URL
    #[arg(long, env = "NATS_URL", default_value = "nats://localhost:4222")]
    nats_url: String,

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

    /// Bind address (host:port)
    #[arg(long, default_value = "0.0.0.0:8080")]
    listen: String,

    /// API bearer token (optional; when set, all /v1/* routes require Authorization header)
    #[arg(long, env = "SPINE_API_TOKEN")]
    api_token: Option<String>,

    /// Maximum requests per second (simple rate limiter)
    #[arg(long, env = "SPINE_RATE_LIMIT", default_value = "100")]
    rate_limit: u64,

    /// Maximum number of keys to scan in receipt-verifications-by-target
    #[arg(long, env = "SPINE_MAX_KEYS_SCAN", default_value = "10000")]
    max_keys_scan: usize,

    /// JetStream replication factor for KV buckets (dev default: 1)
    #[arg(long, env = "SPINE_REPLICAS", default_value = "1")]
    replicas: usize,
}

#[derive(Clone)]
struct AppState {
    index_kv: async_nats::jetstream::kv::Store,
    checkpoint_kv: async_nats::jetstream::kv::Store,
    envelope_kv: async_nats::jetstream::kv::Store,
    fact_index_kv: async_nats::jetstream::kv::Store,
    max_keys_scan: usize,
    /// Cache: tree_size -> Vec<Vec<u8>> leaves (avoids re-scanning KV for repeated proofs).
    leaves_cache: Arc<Mutex<HashMap<u64, Vec<Vec<u8>>>>>,
}

#[derive(Debug)]
struct ApiError {
    status: StatusCode,
    message: String,
}

impl ApiError {
    fn bad_request(message: impl Into<String>) -> Self {
        Self {
            status: StatusCode::BAD_REQUEST,
            message: message.into(),
        }
    }

    fn not_found(message: impl Into<String>) -> Self {
        Self {
            status: StatusCode::NOT_FOUND,
            message: message.into(),
        }
    }

    fn internal(message: impl Into<String>) -> Self {
        Self {
            status: StatusCode::INTERNAL_SERVER_ERROR,
            message: message.into(),
        }
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let body = Json(json!({ "error": self.message }));
        (self.status, body).into_response()
    }
}

fn normalize_hash_param(param: &str, raw: &str) -> Result<String, ApiError> {
    hash::normalize_hash_hex(raw).ok_or_else(|| ApiError::bad_request(format!("invalid {param}")))
}

fn policy_index_key_param(policy_hash: &str) -> Result<String, ApiError> {
    hash::policy_index_key(policy_hash).ok_or_else(|| ApiError::bad_request("invalid policy_hash"))
}

fn receipt_verification_prefix_param(
    target_envelope_hash: &str,
) -> Result<(String, String), ApiError> {
    let target = normalize_hash_param("target_envelope_hash", target_envelope_hash)?;
    let prefix = format!("receipt_verification.{target}.");
    Ok((target, prefix))
}

async fn get_checkpoint_value(state: &AppState, key: &str) -> Result<Value, ApiError> {
    let bytes = state
        .checkpoint_kv
        .get(key)
        .await
        .map_err(|_| ApiError::not_found(format!("checkpoint not found: {key}")))?;
    let bytes = bytes.ok_or_else(|| ApiError::not_found(format!("checkpoint not found: {key}")))?;
    serde_json::from_slice(&bytes).map_err(|_| ApiError::internal("invalid checkpoint JSON"))
}

fn extract_checkpoint_fact(envelope: &Value) -> Result<&Value, ApiError> {
    let fact = envelope
        .get("fact")
        .ok_or_else(|| ApiError::internal("checkpoint envelope missing fact"))?;
    let schema = fact.get("schema").and_then(|v| v.as_str()).unwrap_or("");
    if schema != "clawdstrike.spine.fact.log_checkpoint.v1" {
        return Err(ApiError::bad_request(format!(
            "unexpected fact schema: {schema}"
        )));
    }
    Ok(fact)
}

async fn load_leaves_for_tree_size(
    index_kv: &async_nats::jetstream::kv::Store,
    tree_size: u64,
) -> Result<Vec<Vec<u8>>, ApiError> {
    let keys = index_kv
        .keys()
        .await
        .map_err(|_| ApiError::internal("failed to list log index keys"))?
        .try_collect::<Vec<String>>()
        .await
        .map_err(|_| ApiError::internal("failed to collect log index keys"))?;
    let mut pairs: Vec<(u64, Vec<u8>)> = Vec::new();

    for key in keys {
        let Some(value) = index_kv
            .get(&key)
            .await
            .map_err(|_| ApiError::internal("failed to read log index"))?
        else {
            continue;
        };

        let seq_str = std::str::from_utf8(&value)
            .map_err(|_| ApiError::internal("log index entry is not valid UTF-8"))?
            .trim();
        let seq: u64 = match seq_str.parse() {
            Ok(s) => s,
            Err(_) => continue,
        };
        if seq == 0 || seq > tree_size {
            continue;
        }
        let h = Hash::from_hex(&key)
            .map_err(|_| ApiError::internal("invalid envelope_hash in index"))?;
        pairs.push((seq, h.as_bytes().to_vec()));
    }

    pairs.sort_by_key(|(seq, _)| *seq);
    if pairs.len() as u64 != tree_size {
        return Err(ApiError::internal(
            "log index incomplete for requested tree_size",
        ));
    }
    for i in 1..pairs.len() {
        if pairs[i].0 != pairs[i - 1].0 + 1 {
            return Err(ApiError::internal(format!(
                "log index has gap: seq {} followed by {}",
                pairs[i - 1].0,
                pairs[i].0
            )));
        }
    }
    Ok(pairs.into_iter().map(|(_, b)| b).collect())
}

async fn healthz() -> &'static str {
    "ok"
}

async fn v1_checkpoint_latest(State(state): State<Arc<AppState>>) -> Result<Json<Value>, ApiError> {
    let value = get_checkpoint_value(&state, "latest").await?;
    Ok(Json(value))
}

async fn v1_checkpoint_by_seq(
    State(state): State<Arc<AppState>>,
    Path(seq): Path<u64>,
) -> Result<Json<Value>, ApiError> {
    let value = get_checkpoint_value(&state, &format!("checkpoint/{seq}")).await?;
    Ok(Json(value))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct InclusionQuery {
    envelope_hash: String,
    checkpoint_seq: Option<u64>,
}

async fn v1_inclusion_proof(
    State(state): State<Arc<AppState>>,
    Query(q): Query<InclusionQuery>,
) -> Result<Json<Value>, ApiError> {
    let checkpoint_envelope = if let Some(seq) = q.checkpoint_seq {
        get_checkpoint_value(&state, &format!("checkpoint/{seq}")).await?
    } else {
        get_checkpoint_value(&state, "latest").await?
    };

    let fact = extract_checkpoint_fact(&checkpoint_envelope)?;
    let log_id = fact
        .get("log_id")
        .and_then(|v| v.as_str())
        .ok_or_else(|| ApiError::internal("checkpoint fact missing log_id"))?;
    let checkpoint_seq = fact
        .get("checkpoint_seq")
        .and_then(|v| v.as_u64())
        .ok_or_else(|| ApiError::internal("checkpoint fact missing checkpoint_seq"))?;
    let tree_size = fact
        .get("tree_size")
        .and_then(|v| v.as_u64())
        .ok_or_else(|| ApiError::internal("checkpoint fact missing tree_size"))?;
    let merkle_root = fact
        .get("merkle_root")
        .and_then(|v| v.as_str())
        .ok_or_else(|| ApiError::internal("checkpoint fact missing merkle_root"))?;

    let envelope_hash_hex = normalize_hash_param("envelope_hash", &q.envelope_hash)?;
    let entry = state
        .index_kv
        .get(&envelope_hash_hex)
        .await
        .map_err(|_| ApiError::internal("failed to read log index"))?;
    let entry = entry.ok_or_else(|| ApiError::not_found("envelope_hash not in log index"))?;

    let seq_str = std::str::from_utf8(&entry)
        .map_err(|_| ApiError::internal("log index entry is not valid UTF-8"))?
        .trim();
    let log_seq: u64 = seq_str
        .parse()
        .map_err(|_| ApiError::internal("invalid log index entry"))?;

    if log_seq == 0 || log_seq > tree_size {
        return Err(ApiError::not_found(
            "envelope_hash not committed by this checkpoint",
        ));
    }
    let log_index = log_seq - 1;

    let leaves = {
        let cached = state
            .leaves_cache
            .lock()
            .ok()
            .and_then(|c| c.get(&tree_size).cloned());
        if let Some(l) = cached {
            l
        } else {
            let l = load_leaves_for_tree_size(&state.index_kv, tree_size).await?;
            if let Ok(mut c) = state.leaves_cache.lock() {
                c.insert(tree_size, l.clone());
            }
            l
        }
    };
    let tree = MerkleTree::from_leaves(&leaves)
        .map_err(|_| ApiError::internal("failed to build merkle tree"))?;
    let proof = tree
        .inclusion_proof(log_index as usize)
        .map_err(|_| ApiError::internal("failed to generate inclusion proof"))?;

    if tree.root().to_hex_prefixed() != merkle_root {
        warn!(
            "checkpoint merkle_root mismatch (log_id={}, checkpoint_seq={})",
            log_id, checkpoint_seq
        );
    }

    let audit_path: Vec<String> = proof
        .audit_path
        .iter()
        .map(|h| h.to_hex_prefixed())
        .collect();

    // Verify the proof against the checkpoint's merkle_root.
    // The tree was built from raw envelope-hash bytes via from_leaves(),
    // which applies leaf_hash(). So we verify with the raw bytes.
    let expected_root = Hash::from_hex(merkle_root).ok();
    let envelope_hash_obj = Hash::from_hex(&envelope_hash_hex).ok();
    let verified = match (expected_root, envelope_hash_obj) {
        (Some(root), Some(eh)) => proof.verify(eh.as_bytes(), &root),
        _ => false,
    };

    Ok(Json(json!({
        "schema": "clawdstrike.spine.proof.inclusion.v1",
        "included": true,
        "log_id": log_id,
        "checkpoint_seq": checkpoint_seq,
        "tree_size": tree_size,
        "log_index": log_index,
        "envelope_hash": envelope_hash_hex,
        "merkle_root": merkle_root,
        "audit_path": audit_path,
        "verified": verified,
    })))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SyncQuery {
    issuer: String,
    from_seq: u64,
    to_seq: u64,
}

async fn v1_marketplace_sync(
    State(state): State<Arc<AppState>>,
    Query(q): Query<SyncQuery>,
) -> Result<Json<Value>, ApiError> {
    // Validate range.
    if q.from_seq == 0 {
        return Err(ApiError::bad_request("from_seq must be >= 1"));
    }
    if q.to_seq < q.from_seq {
        return Err(ApiError::bad_request("to_seq must be >= from_seq"));
    }
    let range = q.to_seq - q.from_seq + 1;
    if range > spine::MAX_SYNC_RANGE {
        return Err(ApiError::bad_request(format!(
            "sync range too large ({range}), max is {}",
            spine::MAX_SYNC_RANGE
        )));
    }

    // Normalize issuer to hex for key lookup.
    let issuer_hex = spine::parse_issuer_pubkey_hex(&q.issuer)
        .map_err(|_| ApiError::bad_request("invalid issuer format"))?;

    let mut envelopes: Vec<Value> = Vec::new();
    for seq in q.from_seq..=q.to_seq {
        let key = format!("marketplace_entry.{issuer_hex}.{seq}");
        let Some(envelope_hash) = kv_get_utf8(&state.fact_index_kv, &key).await? else {
            continue;
        };
        let Some(bytes) = state
            .envelope_kv
            .get(&envelope_hash)
            .await
            .map_err(|_| ApiError::internal("failed to read envelope KV"))?
        else {
            continue;
        };
        let envelope: Value = serde_json::from_slice(&bytes)
            .map_err(|_| ApiError::internal("invalid envelope JSON"))?;
        envelopes.push(envelope);
    }

    Ok(Json(json!({
        "schema": "clawdstrike.marketplace.sync_response.v1",
        "curator_issuer": q.issuer,
        "from_seq": q.from_seq,
        "to_seq": q.to_seq,
        "envelopes": envelopes,
    })))
}

async fn v1_marketplace_attestation_by_bundle_hash(
    State(state): State<Arc<AppState>>,
    Path(bundle_hash): Path<String>,
) -> Result<Json<Value>, ApiError> {
    let key = format!("policy_attestation.{bundle_hash}");
    let Some(envelope_hash) = kv_get_utf8(&state.fact_index_kv, &key).await? else {
        return Err(ApiError::not_found("no attestation for bundle hash"));
    };
    v1_envelope_by_hash(State(state), Path(envelope_hash)).await
}

async fn v1_marketplace_revocation_by_bundle_hash(
    State(state): State<Arc<AppState>>,
    Path(bundle_hash): Path<String>,
) -> Result<Json<Value>, ApiError> {
    let key = format!("policy_revocation.{bundle_hash}");
    let Some(envelope_hash) = kv_get_utf8(&state.fact_index_kv, &key).await? else {
        return Err(ApiError::not_found("no revocation for bundle hash"));
    };
    v1_envelope_by_hash(State(state), Path(envelope_hash)).await
}

async fn v1_node_attestation_by_issuer(
    State(state): State<Arc<AppState>>,
    Path(issuer_hex): Path<String>,
) -> Result<Json<Value>, ApiError> {
    let normalized = normalize_hash_param("issuer_hex", &issuer_hex)?;
    let key = format!("node_attestation.{normalized}");
    let Some(envelope_hash) = kv_get_utf8(&state.fact_index_kv, &key).await? else {
        return Err(ApiError::not_found("no node attestation for issuer"));
    };
    v1_envelope_by_hash(State(state), Path(envelope_hash)).await
}

async fn v1_envelope_by_hash(
    State(state): State<Arc<AppState>>,
    Path(envelope_hash): Path<String>,
) -> Result<Json<Value>, ApiError> {
    let key = normalize_hash_param("envelope_hash", &envelope_hash)?;
    let bytes = state
        .envelope_kv
        .get(&key)
        .await
        .map_err(|_| ApiError::internal("failed to read envelope KV"))?;
    let bytes = bytes.ok_or_else(|| ApiError::not_found("envelope not found"))?;
    let envelope: Value =
        serde_json::from_slice(&bytes).map_err(|_| ApiError::internal("invalid envelope JSON"))?;
    Ok(Json(envelope))
}

async fn v1_policy_by_hash(
    State(state): State<Arc<AppState>>,
    Path(policy_hash): Path<String>,
) -> Result<Json<Value>, ApiError> {
    let key = policy_index_key_param(&policy_hash)?;
    let Some(envelope_hash) = kv_get_utf8(&state.fact_index_kv, &key).await? else {
        return Err(ApiError::not_found("policy hash not indexed"));
    };
    v1_envelope_by_hash(State(state), Path(envelope_hash)).await
}

async fn v1_policy_by_version(
    State(state): State<Arc<AppState>>,
    Path(version): Path<String>,
) -> Result<Json<Value>, ApiError> {
    let key = format!("policy_version.{}", version);
    let Some(policy_hash) = kv_get_utf8(&state.fact_index_kv, &key).await? else {
        return Err(ApiError::not_found("policy version not indexed"));
    };
    v1_policy_by_hash(State(state), Path(policy_hash)).await
}

async fn v1_run_receipt_by_run_id(
    State(state): State<Arc<AppState>>,
    Path(run_id): Path<String>,
) -> Result<Json<Value>, ApiError> {
    let key = format!("run_receipt.{}", run_id);
    let Some(envelope_hash) = kv_get_utf8(&state.fact_index_kv, &key).await? else {
        return Err(ApiError::not_found("run_id not indexed"));
    };
    v1_envelope_by_hash(State(state), Path(envelope_hash)).await
}

async fn v1_receipt_verifications_by_target(
    State(state): State<Arc<AppState>>,
    Path(target_envelope_hash): Path<String>,
) -> Result<Json<Value>, ApiError> {
    let (target, prefix) = receipt_verification_prefix_param(&target_envelope_hash)?;

    let keys = state
        .fact_index_kv
        .keys()
        .await
        .map_err(|_| ApiError::internal("failed to list fact index keys"))?
        .try_collect::<Vec<String>>()
        .await
        .map_err(|_| ApiError::internal("failed to collect fact index keys"))?;

    let max_keys = state.max_keys_scan;
    let mut out: Vec<Value> = Vec::new();
    let mut scanned: usize = 0;
    for key in keys {
        scanned += 1;
        if scanned > max_keys {
            warn!(
                "receipt verifications scan capped at {} keys for target={}",
                max_keys, target
            );
            break;
        }
        if !key.starts_with(&prefix) {
            continue;
        }
        let verifier_pubkey_hex = key.strip_prefix(&prefix).unwrap_or("").to_string();
        let Some(env_hash) = kv_get_utf8(&state.fact_index_kv, &key).await? else {
            continue;
        };
        let bytes = state
            .envelope_kv
            .get(&env_hash)
            .await
            .map_err(|_| ApiError::internal("failed to read envelope KV"))?;
        let Some(bytes) = bytes else { continue };
        let envelope: Value = serde_json::from_slice(&bytes)
            .map_err(|_| ApiError::internal("invalid envelope JSON"))?;
        out.push(json!({
            "verifier_pubkey_hex": verifier_pubkey_hex,
            "envelope_hash": env_hash,
            "envelope": envelope,
        }));
    }

    Ok(Json(json!({
        "schema": "clawdstrike.spine.query.receipt_verifications.v1",
        "target_envelope_hash": target,
        "verifications": out,
    })))
}

async fn kv_get_utf8(
    kv: &async_nats::jetstream::kv::Store,
    key: &str,
) -> Result<Option<String>, ApiError> {
    let entry = kv
        .get(key)
        .await
        .map_err(|_| ApiError::internal("failed to read KV"))?;
    let Some(bytes) = entry else {
        return Ok(None);
    };
    let s = std::str::from_utf8(&bytes)
        .map_err(|_| ApiError::internal("invalid UTF-8 in KV value"))?
        .trim()
        .to_string();
    if s.is_empty() {
        return Ok(None);
    }
    Ok(Some(s))
}

#[tokio::main]
async fn main() -> Result<()> {
    fmt()
        .with_env_filter(EnvFilter::from_default_env().add_directive("info".parse()?))
        .with_target(false)
        .init();

    let args = Args::parse();

    let client = nats::connect(&args.nats_url).await?;
    let js = nats::jetstream(client);

    let replicas = args.replicas;
    let index_kv = nats::ensure_kv(&js, &args.index_bucket, replicas).await?;
    let checkpoint_kv = nats::ensure_kv(&js, &args.checkpoint_bucket, replicas).await?;
    let envelope_kv = nats::ensure_kv(&js, &args.envelope_bucket, replicas).await?;
    let fact_index_kv = nats::ensure_kv(&js, &args.fact_index_bucket, replicas).await?;

    let state = Arc::new(AppState {
        index_kv,
        checkpoint_kv,
        envelope_kv,
        fact_index_kv,
        max_keys_scan: args.max_keys_scan,
        leaves_cache: Arc::new(Mutex::new(HashMap::new())),
    });

    // Build the /v1/* router with auth and rate limiting middleware.
    let v1_routes = Router::new()
        .route("/v1/checkpoints/latest", get(v1_checkpoint_latest))
        .route("/v1/checkpoints/{seq}", get(v1_checkpoint_by_seq))
        .route("/v1/envelopes/{envelope_hash}", get(v1_envelope_by_hash))
        .route("/v1/policies/by-hash/{policy_hash}", get(v1_policy_by_hash))
        .route(
            "/v1/policies/by-version/{version}",
            get(v1_policy_by_version),
        )
        .route(
            "/v1/run-receipts/by-run-id/{run_id}",
            get(v1_run_receipt_by_run_id),
        )
        .route(
            "/v1/receipt-verifications/by-target/{target_envelope_hash}",
            get(v1_receipt_verifications_by_target),
        )
        .route(
            "/v1/node-attestations/by-issuer/{issuer_hex}",
            get(v1_node_attestation_by_issuer),
        )
        .route(
            "/v1/marketplace/attestation/{bundle_hash}",
            get(v1_marketplace_attestation_by_bundle_hash),
        )
        .route(
            "/v1/marketplace/revocation/{bundle_hash}",
            get(v1_marketplace_revocation_by_bundle_hash),
        )
        .route("/v1/marketplace/sync", get(v1_marketplace_sync))
        .route("/v1/proofs/inclusion", get(v1_inclusion_proof))
        .with_state(state);

    // Rate limiter: counter reset every second by a background task.
    let rate_counter = Arc::new(AtomicU64::new(0));
    let rate_limit = args.rate_limit;
    {
        let counter = rate_counter.clone();
        tokio::spawn(async move {
            let mut ticker = tokio::time::interval(Duration::from_secs(1));
            loop {
                ticker.tick().await;
                counter.store(0, Ordering::Relaxed);
            }
        });
    }

    // Layer rate limiting onto v1 routes.
    let rate_counter_mw = rate_counter.clone();
    let v1_routes = v1_routes.layer(middleware::from_fn(move |req: Request, next: Next| {
        let counter = rate_counter_mw.clone();
        let limit = rate_limit;
        async move {
            let current = counter.fetch_add(1, Ordering::Relaxed);
            if current >= limit {
                let body = Json(json!({ "error": "rate limit exceeded" }));
                return (StatusCode::TOO_MANY_REQUESTS, body).into_response();
            }
            next.run(req).await
        }
    }));

    // Layer auth if configured.
    let v1_routes = if let Some(token) = args.api_token {
        let expected = Arc::new(token);
        v1_routes.layer(middleware::from_fn(move |req: Request, next: Next| {
            let expected = expected.clone();
            async move {
                let auth_header = req
                    .headers()
                    .get("authorization")
                    .and_then(|v| v.to_str().ok())
                    .map(|s| s.to_string());
                match auth_header {
                    Some(h)
                        if h.strip_prefix("Bearer ")
                            .is_some_and(|t| t == expected.as_str()) =>
                    {
                        next.run(req).await
                    }
                    _ => {
                        let body = Json(json!({ "error": "unauthorized" }));
                        (StatusCode::UNAUTHORIZED, body).into_response()
                    }
                }
            }
        }))
    } else {
        v1_routes
    };

    let app = Router::new()
        .route("/healthz", get(healthz))
        .merge(v1_routes)
        .layer(TraceLayer::new_for_http());

    let addr: SocketAddr = args.listen.parse().context("invalid listen address")?;
    info!("proofs API listening on http://{}", addr);
    axum::serve(tokio::net::TcpListener::bind(addr).await?, app).await?;
    Ok(())
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn normalize_hash_param_accepts_prefixed_or_unprefixed() {
        let raw = "0xAABBcc00aabbcc00aabbcc00aabbcc00aabbcc00aabbcc00aabbcc00aabbcc00";
        let normalized = normalize_hash_param("envelope_hash", raw).unwrap();
        assert_eq!(
            normalized,
            "0xaabbcc00aabbcc00aabbcc00aabbcc00aabbcc00aabbcc00aabbcc00aabbcc00"
        );

        let raw2 = "aabbcc00aabbcc00aabbcc00aabbcc00aabbcc00aabbcc00aabbcc00aabbcc00";
        let normalized2 = normalize_hash_param("envelope_hash", raw2).unwrap();
        assert_eq!(normalized2, normalized);
    }

    #[test]
    fn policy_index_key_param_normalizes() {
        let raw = "AABBcc00aabbcc00aabbcc00aabbcc00aabbcc00aabbcc00aabbcc00aabbcc00";
        let key = policy_index_key_param(raw).unwrap();
        assert_eq!(
            key,
            "policy.0xaabbcc00aabbcc00aabbcc00aabbcc00aabbcc00aabbcc00aabbcc00aabbcc00"
        );
    }

    #[test]
    fn receipt_verification_prefix_param_normalizes() {
        let raw = "0xAABBcc00aabbcc00aabbcc00aabbcc00aabbcc00aabbcc00aabbcc00aabbcc00";
        let (target, prefix) = receipt_verification_prefix_param(raw).unwrap();
        assert_eq!(
            target,
            "0xaabbcc00aabbcc00aabbcc00aabbcc00aabbcc00aabbcc00aabbcc00aabbcc00"
        );
        assert_eq!(prefix, format!("receipt_verification.{target}."));
    }
}
