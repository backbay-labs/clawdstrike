//! Policy cache for warm-start recovery.
//!
//! Maintains a last-known-good policy bundle fetched from hushd so the
//! daemon can re-warm quickly on agent restart. This cache is **not** used
//! for inline policy evaluation — when hushd is unreachable, agent-side
//! checks fail closed (`hushd_unreachable`).

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{broadcast, Mutex};

fn policy_cache_path() -> PathBuf {
    crate::settings::get_config_dir().join("policy-cache.yaml")
}

fn policy_cache_manifest_path() -> PathBuf {
    crate::settings::get_config_dir().join("policy-cache.manifest.json")
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct PolicyCacheManifest {
    schema_version: u32,
    source_url: String,
    fetched_at: String,
    content_hash: String,
    byte_len: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    policy_version: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    policy_epoch: Option<u64>,
}

/// Persistent policy cache that stores the last-known-good policy bundle
/// fetched from hushd. Used for quick warm-start on agent restart so that
/// hushd can re-load policies faster. This is NOT used for inline evaluation
/// fallback — when hushd is unreachable, policy checks return deny with
/// guard "hushd_unreachable" (fail-closed).
pub struct PolicyCache {
    cache_path: PathBuf,
    manifest_path: PathBuf,
    http_client: reqwest::Client,
    sync_lock: Mutex<()>,
    cached_policy: Mutex<Option<String>>,
    cached_manifest: Mutex<Option<PolicyCacheManifest>>,
}

impl PolicyCache {
    pub fn new() -> Self {
        Self::with_paths(policy_cache_path(), policy_cache_manifest_path())
    }

    fn with_paths(cache_path: PathBuf, manifest_path: PathBuf) -> Self {
        let cached = std::fs::read_to_string(&cache_path).ok();
        let manifest = read_policy_cache_manifest(&manifest_path);
        Self {
            cache_path,
            manifest_path,
            http_client: reqwest::Client::builder()
                .timeout(Duration::from_secs(10))
                .build()
                .unwrap_or_else(|_| reqwest::Client::new()),
            sync_lock: Mutex::new(()),
            cached_policy: Mutex::new(cached),
            cached_manifest: Mutex::new(manifest),
        }
    }

    /// Fetch the policy bundle from hushd and persist it to disk.
    pub async fn sync_from_daemon(&self, daemon_url: &str, api_key: Option<&str>) -> Result<()> {
        let url = format!("{}/api/v1/policy/bundle", daemon_url);
        let mut request = self.http_client.get(&url);
        if let Some(key) = api_key {
            request = request.header("Authorization", format!("Bearer {}", key));
        }

        let response = request
            .send()
            .await
            .with_context(|| format!("Failed to fetch policy bundle from {}", url))?;

        if !response.status().is_success() {
            anyhow::bail!("Policy bundle endpoint returned {}", response.status());
        }

        let body = response
            .text()
            .await
            .with_context(|| "Failed to read policy bundle response body")?;
        let content_hash = hush_core::sha256(body.as_bytes()).to_hex_prefixed();
        let policy_version = parse_cached_policy_version(&body);
        let policy_epoch = parse_cached_policy_epoch(&body);
        let _sync_guard = self.sync_lock.lock().await;
        let current_manifest = self.cached_manifest.lock().await.clone();
        let current_policy = self.cached_policy.lock().await.clone();
        enforce_policy_cache_distribution_rules(
            current_manifest.as_ref(),
            current_policy.as_deref(),
            policy_epoch,
            &content_hash,
        )?;
        let manifest = PolicyCacheManifest {
            schema_version: 1,
            source_url: url.clone(),
            fetched_at: chrono::Utc::now().to_rfc3339(),
            content_hash,
            byte_len: body.len() as u64,
            policy_version,
            policy_epoch,
        };
        let manifest_bytes = serde_json::to_vec_pretty(&manifest)
            .with_context(|| "Failed to serialize policy cache manifest")?;

        // Persist to disk via spawn_blocking to avoid blocking the tokio runtime.
        let path = self.cache_path.clone();
        let manifest_path = self.manifest_path.clone();
        let path_for_log = path.clone();
        let body_clone = body.clone();
        tokio::task::spawn_blocking(move || {
            write_policy_cache_generation(
                &path,
                body_clone.as_bytes(),
                &manifest_path,
                &manifest_bytes,
            )?;
            Ok::<_, anyhow::Error>(())
        })
        .await
        .with_context(|| "Policy cache write task panicked")??;

        *self.cached_policy.lock().await = Some(body);
        *self.cached_manifest.lock().await = Some(manifest);
        tracing::info!(path = ?path_for_log, "Policy cache updated");
        Ok(())
    }

    /// Return the last-known-good cached policy YAML, if any.
    #[allow(dead_code)]
    pub async fn cached_policy(&self) -> Option<String> {
        self.cached_policy.lock().await.clone()
    }

    /// Return the cached policy version (best effort) for telemetry/health payloads.
    pub async fn cached_policy_version(&self) -> Option<String> {
        let raw = self.cached_policy.lock().await.clone()?;
        parse_cached_policy_version(&raw)
    }

    #[cfg(test)]
    fn new_test_isolated() -> Self {
        let id = uuid::Uuid::new_v4();
        let dir = std::env::temp_dir();
        Self::with_paths(
            dir.join(format!("clawdstrike-policy-cache-{id}.yaml")),
            dir.join(format!("clawdstrike-policy-cache-{id}.manifest.json")),
        )
    }

    #[cfg(test)]
    async fn cached_policy_manifest(&self) -> Option<PolicyCacheManifest> {
        self.cached_manifest.lock().await.clone()
    }

    /// Start a periodic sync loop that refreshes the policy cache from hushd.
    pub fn start_periodic_sync(
        self: &Arc<Self>,
        daemon_url: String,
        api_key: Option<String>,
        mut shutdown_rx: broadcast::Receiver<()>,
    ) {
        let cache = Arc::clone(self);
        tokio::spawn(async move {
            let sync_interval = Duration::from_secs(300); // 5 minutes
            loop {
                tokio::select! {
                    _ = shutdown_rx.recv() => {
                        tracing::debug!("Policy cache sync loop shutting down");
                        break;
                    }
                    _ = tokio::time::sleep(sync_interval) => {
                        if let Err(err) = cache.sync_from_daemon(&daemon_url, api_key.as_deref()).await {
                            tracing::debug!(error = %err, "Periodic policy cache sync failed (daemon may be offline)");
                        }
                    }
                }
            }
        });
    }
}

fn read_policy_cache_manifest(path: &Path) -> Option<PolicyCacheManifest> {
    let raw = std::fs::read(path).ok()?;
    serde_json::from_slice(&raw).ok()
}

fn write_policy_cache_generation(
    policy_path: &Path,
    policy_bytes: &[u8],
    manifest_path: &Path,
    manifest_bytes: &[u8],
) -> Result<()> {
    let previous_policy = std::fs::read(policy_path).ok();
    crate::security::fs::write_private_atomic(policy_path, policy_bytes, "policy cache file")?;

    if let Err(err) = crate::security::fs::write_private_atomic(
        manifest_path,
        manifest_bytes,
        "policy cache manifest",
    ) {
        if let Err(rollback_err) =
            rollback_policy_cache_file(policy_path, previous_policy.as_deref())
        {
            anyhow::bail!(
                "policy cache manifest write failed after policy file write: {err}; rollback failed: {rollback_err}"
            );
        }
        return Err(err).with_context(|| {
            format!(
                "Policy cache manifest commit failed for {}; rolled back policy cache file {}",
                manifest_path.display(),
                policy_path.display()
            )
        });
    }

    Ok(())
}

fn rollback_policy_cache_file(policy_path: &Path, previous_policy: Option<&[u8]>) -> Result<()> {
    if let Some(previous_policy) = previous_policy {
        crate::security::fs::write_private_atomic(
            policy_path,
            previous_policy,
            "policy cache rollback file",
        )
    } else {
        match std::fs::remove_file(policy_path) {
            Ok(()) => Ok(()),
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(err) => Err(err).with_context(|| {
                format!("Failed to remove partial policy cache file {policy_path:?}")
            }),
        }
    }
}

fn parse_cached_policy_version(policy_yaml: &str) -> Option<String> {
    let root: serde_yaml::Value = serde_yaml::from_str(policy_yaml).ok()?;
    let version = root.get("version")?;
    match version {
        serde_yaml::Value::String(value) => Some(value.clone()),
        serde_yaml::Value::Number(value) => Some(value.to_string()),
        serde_yaml::Value::Bool(value) => Some(value.to_string()),
        _ => None,
    }
}

const POLICY_CACHE_EPOCH_YAML_PATHS: &[&[&str]] = &[
    &["policy_epoch"],
    &["policyEpoch"],
    &["epoch"],
    &["policy", "epoch"],
    &["policy", "policy_epoch"],
    &["policy", "policyEpoch"],
    &["metadata", "policy_epoch"],
    &["metadata", "policyEpoch"],
    &["bundle", "epoch"],
    &["bundle", "policy_epoch"],
    &["bundle", "policyEpoch"],
];

fn parse_cached_policy_epoch(policy_yaml: &str) -> Option<u64> {
    let root: serde_yaml::Value = serde_yaml::from_str(policy_yaml).ok()?;
    POLICY_CACHE_EPOCH_YAML_PATHS
        .iter()
        .filter_map(|path| yaml_u64_at_path(&root, path))
        .find(|epoch| *epoch > 0)
}

fn yaml_u64_at_path(value: &serde_yaml::Value, path: &[&str]) -> Option<u64> {
    let mut current = value;
    for segment in path {
        current = current.get(*segment)?;
    }
    yaml_u64_value(current)
}

fn yaml_u64_value(value: &serde_yaml::Value) -> Option<u64> {
    match value {
        serde_yaml::Value::Number(value) => value.as_u64(),
        serde_yaml::Value::String(value) => value.trim().parse::<u64>().ok(),
        _ => None,
    }
}

fn enforce_policy_cache_distribution_rules(
    current_manifest: Option<&PolicyCacheManifest>,
    current_policy: Option<&str>,
    candidate_epoch: Option<u64>,
    candidate_hash: &str,
) -> Result<()> {
    let current_epoch = current_policy
        .and_then(parse_cached_policy_epoch)
        .or_else(|| current_manifest.and_then(|manifest| manifest.policy_epoch));
    let computed_current_hash =
        current_policy.map(|policy| hush_core::sha256(policy.as_bytes()).to_hex_prefixed());
    let current_hash = computed_current_hash
        .as_deref()
        .or_else(|| current_manifest.map(|manifest| manifest.content_hash.as_str()));

    match (current_epoch, candidate_epoch) {
        (Some(existing), Some(candidate)) if candidate < existing => {
            anyhow::bail!(
                "policy cache distribution rejected epoch downgrade: current epoch {existing}, candidate epoch {candidate}"
            );
        }
        (Some(existing), None) => {
            anyhow::bail!(
                "policy cache distribution rejected bundle without explicit policy epoch while current epoch is {existing}"
            );
        }
        (Some(existing), Some(candidate))
            if candidate == existing && current_hash != Some(candidate_hash) =>
        {
            anyhow::bail!(
                "policy cache distribution rejected content hash change without policy epoch advance: epoch {candidate}"
            );
        }
        _ => {}
    }

    Ok(())
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn parse_cached_policy_version_accepts_string_or_number() {
        assert_eq!(
            parse_cached_policy_version("version: \"42\"\nrules: []\n"),
            Some("42".to_string())
        );
        assert_eq!(
            parse_cached_policy_version("version: 7\nrules: []\n"),
            Some("7".to_string())
        );
    }

    #[test]
    fn parse_cached_policy_version_returns_none_for_missing_or_complex_values() {
        assert_eq!(parse_cached_policy_version("rules: []\n"), None);
        assert_eq!(parse_cached_policy_version("version:\n  major: 1\n"), None);
        assert_eq!(parse_cached_policy_version("not: [valid"), None);
    }

    #[test]
    fn parse_cached_policy_epoch_accepts_distribution_paths() {
        assert_eq!(
            parse_cached_policy_epoch("version: v1\npolicy_epoch: 7\n"),
            Some(7)
        );
        assert_eq!(
            parse_cached_policy_epoch("version: v1\nbundle:\n  policyEpoch: \"42\"\n"),
            Some(42)
        );
        assert_eq!(
            parse_cached_policy_epoch(
                "version: v1\npolicy:\n  epoch: 0\nmetadata:\n  policyEpoch: 9\n"
            ),
            Some(9)
        );
        assert_eq!(
            parse_cached_policy_epoch("version: v1\npolicy_epoch: 0\n"),
            None
        );
    }

    #[tokio::test]
    async fn policy_cache_sync_persists_manifest_and_rejects_epoch_regressions() {
        use axum::{extract::State, response::IntoResponse, routing::get, Router};
        use tokio::net::TcpListener;

        async fn policy_bundle(State(policy): State<Arc<Mutex<String>>>) -> impl IntoResponse {
            policy.lock().await.clone()
        }

        let remote_policy = Arc::new(Mutex::new(
            "version: fleet-v2\npolicy_epoch: 20\nrules: []\n".to_string(),
        ));
        let app = Router::new()
            .route("/api/v1/policy/bundle", get(policy_bundle))
            .with_state(remote_policy.clone());
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let server = tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        let base_url = format!("http://127.0.0.1:{port}");
        let cache = PolicyCache::new_test_isolated();

        cache.sync_from_daemon(&base_url, None).await.unwrap();
        assert_eq!(
            cache.cached_policy().await.as_deref(),
            Some("version: fleet-v2\npolicy_epoch: 20\nrules: []\n")
        );
        let manifest = cache.cached_policy_manifest().await.unwrap();
        assert_eq!(manifest.schema_version, 1);
        assert_eq!(
            manifest.source_url,
            format!("{base_url}/api/v1/policy/bundle")
        );
        assert_eq!(manifest.policy_version.as_deref(), Some("fleet-v2"));
        assert_eq!(manifest.policy_epoch, Some(20));
        assert_eq!(
            manifest.content_hash,
            hush_core::sha256(b"version: fleet-v2\npolicy_epoch: 20\nrules: []\n")
                .to_hex_prefixed()
        );

        *remote_policy.lock().await = "version: fleet-v1\npolicy_epoch: 19\nrules: []\n".into();
        let err = cache.sync_from_daemon(&base_url, None).await.unwrap_err();
        assert!(
            err.to_string().contains("epoch downgrade"),
            "unexpected stale-epoch error: {err}"
        );
        assert_eq!(
            cache.cached_policy().await.as_deref(),
            Some("version: fleet-v2\npolicy_epoch: 20\nrules: []\n")
        );

        *remote_policy.lock().await =
            "version: fleet-v2b\npolicy_epoch: 20\nrules:\n  - id: changed\n".into();
        let err = cache.sync_from_daemon(&base_url, None).await.unwrap_err();
        assert!(
            err.to_string().contains("without policy epoch advance"),
            "unexpected same-epoch mutation error: {err}"
        );

        *remote_policy.lock().await = "version: fleet-v3\npolicy_epoch: 21\nrules: []\n".into();
        cache.sync_from_daemon(&base_url, None).await.unwrap();
        assert_eq!(
            cache.cached_policy_manifest().await.unwrap().policy_epoch,
            Some(21)
        );

        server.abort();
        let _ = std::fs::remove_file(cache.cache_path);
        let _ = std::fs::remove_file(cache.manifest_path);
    }

    #[test]
    fn policy_cache_generation_rolls_back_policy_file_when_manifest_commit_fails() {
        let dir = std::env::temp_dir().join(format!(
            "clawdstrike-policy-cache-rollback-{}",
            uuid::Uuid::new_v4()
        ));
        std::fs::create_dir_all(&dir)
            .unwrap_or_else(|err| panic!("create policy cache rollback dir: {err}"));
        let policy_path = dir.join("policy.yaml");
        let manifest_path = dir.join("manifest.json");
        let original_policy = b"version: fleet-v2\npolicy_epoch: 20\nrules: []\n";
        crate::security::fs::write_private_atomic(
            &policy_path,
            original_policy,
            "test policy cache file",
        )
        .unwrap_or_else(|err| panic!("write original policy cache: {err}"));
        crate::security::fs::write_private_atomic(
            &manifest_path,
            br#"{"schema_version":1,"policy_epoch":20}"#,
            "test policy cache manifest",
        )
        .unwrap_or_else(|err| panic!("write original policy cache manifest: {err}"));

        std::fs::remove_file(&manifest_path)
            .unwrap_or_else(|err| panic!("remove manifest before failure injection: {err}"));
        std::fs::create_dir(&manifest_path)
            .unwrap_or_else(|err| panic!("create manifest collision directory: {err}"));

        let err = match write_policy_cache_generation(
            &policy_path,
            b"version: fleet-v3\npolicy_epoch: 21\nrules: []\n",
            &manifest_path,
            br#"{"schema_version":1,"policy_epoch":21}"#,
        ) {
            Ok(()) => panic!("manifest collision sync unexpectedly succeeded"),
            Err(err) => err,
        };
        let error = err.to_string();
        assert!(
            error.contains("rolled back policy cache file"),
            "unexpected manifest failure error: {error}"
        );
        let disk_policy = std::fs::read(&policy_path)
            .unwrap_or_else(|err| panic!("read rolled back policy cache: {err}"));
        assert_eq!(disk_policy, original_policy);

        let _ = std::fs::remove_dir_all(dir);
    }

    #[tokio::test]
    async fn policy_cache_returns_none_initially() {
        let cache = PolicyCache::new();
        // May or may not have a cached file on disk; just verify the method works.
        let _ = cache.cached_policy().await;
    }
}
