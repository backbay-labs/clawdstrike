//! NATS KV-based policy synchronization.
//!
//! Watches a tenant/agent-scoped KV bucket for policy updates and writes
//! them to the local policy file. On delete events, the last known policy
//! is retained (fail-closed: never leave the agent without a policy).

use anyhow::{Context, Result};
use async_nats::jetstream::kv;
use serde::{Deserialize, Serialize};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tokio::sync::broadcast;

use crate::nats_client::NatsClient;
use crate::nats_subjects;

/// Manages policy synchronization from NATS KV to local disk.
pub struct PolicySync {
    nats: Arc<NatsClient>,
    policy_path: PathBuf,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct PolicySyncManifest {
    schema_version: u32,
    source: String,
    stored_at: String,
    content_hash: String,
    byte_len: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    policy_epoch: Option<u64>,
}

impl PolicySync {
    pub fn new(nats: Arc<NatsClient>, policy_path: PathBuf) -> Self {
        Self { nats, policy_path }
    }

    /// Build the KV bucket name for this agent's policies.
    pub fn bucket_name(subject_prefix: &str, agent_id: &str) -> String {
        nats_subjects::policy_sync_bucket(subject_prefix, agent_id)
    }

    /// Build the KV key for the agent policy.
    fn policy_key() -> &'static str {
        "policy.yaml"
    }

    /// Start watching the KV bucket for policy updates.
    /// Runs until shutdown signal or unrecoverable error.
    pub async fn start(
        &self,
        mut shutdown_rx: broadcast::Receiver<()>,
        policy_update_tx: Option<tokio::sync::mpsc::Sender<()>>,
    ) {
        let bucket_name = Self::bucket_name(self.nats.subject_prefix(), self.nats.agent_id());
        tracing::info!(bucket = %bucket_name, "Starting NATS policy sync");

        let store = match self.ensure_kv_bucket(&bucket_name).await {
            Ok(store) => store,
            Err(err) => {
                tracing::error!(error = %err, "Failed to access policy KV bucket; policy sync disabled");
                return;
            }
        };

        // Try to do an initial read of the current value.
        match store.get(Self::policy_key()).await {
            Ok(Some(bytes)) => {
                if let Err(err) = self.write_policy(&bytes) {
                    tracing::warn!(error = %err, "Failed to write initial policy from KV");
                } else {
                    tracing::info!("Initial policy loaded from NATS KV");
                    if let Some(ref tx) = policy_update_tx {
                        let _ = tx.send(()).await;
                    }
                }
            }
            Ok(None) => {
                tracing::debug!("No policy found in KV bucket; keeping local policy");
            }
            Err(err) => {
                tracing::warn!(error = %err, "Failed to read initial policy from KV; keeping local policy");
            }
        }

        // Watch for updates.
        let mut watcher = match store.watch(Self::policy_key()).await {
            Ok(w) => w,
            Err(err) => {
                tracing::error!(error = %err, "Failed to start KV watch; policy sync disabled");
                return;
            }
        };

        loop {
            tokio::select! {
                _ = shutdown_rx.recv() => {
                    tracing::info!("Policy sync shutting down");
                    break;
                }
                entry = watcher_next(&mut watcher) => {
                    match entry {
                        Some(Ok(entry)) => {
                            match entry.operation {
                                kv::Operation::Put => {
                                    match self.write_policy(&entry.value) {
                                        Ok(()) => {
                                            tracing::info!(
                                                revision = entry.revision,
                                                "Policy updated from NATS KV"
                                            );
                                            if let Some(ref tx) = policy_update_tx {
                                                let _ = tx.send(()).await;
                                            }
                                        }
                                        Err(err) => {
                                            tracing::warn!(
                                                error = %err,
                                                "Failed to write policy update from KV"
                                            );
                                        }
                                    }
                                }
                                kv::Operation::Delete | kv::Operation::Purge => {
                                    // Fail-closed: keep the last known policy.
                                    tracing::info!(
                                        "Policy deleted from KV; retaining last known local policy"
                                    );
                                }
                            }
                        }
                        Some(Err(err)) => {
                            tracing::warn!(error = %err, "KV watch error; will retry on next event");
                        }
                        None => {
                            tracing::warn!("KV watch stream ended unexpectedly");
                            break;
                        }
                    }
                }
            }
        }
    }

    /// Write policy YAML to disk.
    fn write_policy(&self, data: &[u8]) -> Result<()> {
        write_policy_with_manifest(&self.policy_path, data)
    }

    /// Ensure the KV bucket exists (or access the existing one).
    async fn ensure_kv_bucket(&self, bucket_name: &str) -> Result<kv::Store> {
        spine::nats_transport::ensure_kv(self.nats.jetstream(), bucket_name, 1)
            .await
            .map_err(|e| anyhow::anyhow!("KV bucket error: {}", e))
    }
}

/// Helper to poll the next entry from a KV watcher.
async fn watcher_next(watcher: &mut kv::Watch) -> Option<Result<kv::Entry, kv::WatcherError>> {
    use futures::StreamExt;
    watcher.next().await
}

fn policy_sync_manifest_path(policy_path: &Path) -> PathBuf {
    let file_name = policy_path
        .file_name()
        .and_then(|name| name.to_str())
        .filter(|name| !name.is_empty())
        .unwrap_or("policy.yaml");
    policy_path.with_file_name(format!("{file_name}.manifest.json"))
}

fn write_policy_with_manifest(policy_path: &Path, data: &[u8]) -> Result<()> {
    let manifest_path = policy_sync_manifest_path(policy_path);
    let candidate_epoch = parse_policy_epoch_from_yaml(data)
        .with_context(|| "Failed to parse candidate policy from NATS KV")?;
    let candidate_hash = hush_core::sha256(data).to_hex_prefixed();
    let current_policy = std::fs::read(policy_path).ok();
    let current_manifest = read_policy_sync_manifest(&manifest_path);

    enforce_policy_sync_distribution_rules(
        current_policy.as_deref(),
        current_manifest.as_ref(),
        candidate_epoch,
        &candidate_hash,
    )?;

    if let Some(parent) = policy_path.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("Failed to create policy directory {:?}", parent))?;
    }

    let manifest = PolicySyncManifest {
        schema_version: 1,
        source: "nats-kv-policy-sync".to_string(),
        stored_at: chrono::Utc::now().to_rfc3339(),
        content_hash: candidate_hash,
        byte_len: data.len() as u64,
        policy_epoch: candidate_epoch,
    };
    let manifest_bytes = serde_json::to_vec_pretty(&manifest)
        .with_context(|| "Failed to serialize policy sync manifest")?;

    write_policy_generation_with_manifest(policy_path, data, &manifest_path, &manifest_bytes)?;

    Ok(())
}

fn read_policy_sync_manifest(path: &Path) -> Option<PolicySyncManifest> {
    let raw = std::fs::read(path).ok()?;
    serde_json::from_slice(&raw).ok()
}

const POLICY_SYNC_EPOCH_YAML_PATHS: &[&[&str]] = &[
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

fn parse_policy_epoch_from_yaml(policy_yaml: &[u8]) -> Result<Option<u64>> {
    let root: serde_yaml::Value =
        serde_yaml::from_slice(policy_yaml).with_context(|| "invalid policy YAML")?;
    Ok(POLICY_SYNC_EPOCH_YAML_PATHS
        .iter()
        .filter_map(|path| yaml_u64_at_path(&root, path))
        .find(|epoch| *epoch > 0))
}

fn policy_epoch_from_yaml(policy_yaml: &[u8]) -> Option<u64> {
    let root: serde_yaml::Value = serde_yaml::from_slice(policy_yaml).ok()?;
    POLICY_SYNC_EPOCH_YAML_PATHS
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

fn enforce_policy_sync_distribution_rules(
    current_policy: Option<&[u8]>,
    current_manifest: Option<&PolicySyncManifest>,
    candidate_epoch: Option<u64>,
    candidate_hash: &str,
) -> Result<()> {
    let current_epoch = current_policy
        .and_then(policy_epoch_from_yaml)
        .or_else(|| current_manifest.and_then(|manifest| manifest.policy_epoch));
    let computed_current_hash =
        current_policy.map(|policy| hush_core::sha256(policy).to_hex_prefixed());
    let current_hash = computed_current_hash
        .as_deref()
        .or_else(|| current_manifest.map(|manifest| manifest.content_hash.as_str()));

    if candidate_epoch.is_none() {
        anyhow::bail!("policy sync rejected update without explicit policy epoch");
    }

    match (current_epoch, candidate_epoch) {
        (Some(existing), Some(candidate)) if candidate < existing => {
            anyhow::bail!(
                "policy sync rejected epoch downgrade: current epoch {existing}, candidate epoch {candidate}"
            );
        }
        (Some(existing), Some(candidate))
            if candidate == existing && current_hash != Some(candidate_hash) =>
        {
            anyhow::bail!(
                "policy sync rejected content hash change without policy epoch advance: epoch {candidate}"
            );
        }
        _ => {}
    }

    Ok(())
}

fn atomic_write_policy(path: &Path, data: &[u8]) -> Result<()> {
    let tmp_path = path.with_extension("tmp");
    let mut tmp_file = std::fs::File::create(&tmp_path)
        .with_context(|| format!("Failed to create temporary policy file {:?}", tmp_path))?;
    tmp_file
        .write_all(data)
        .with_context(|| format!("Failed to write temporary policy file {:?}", tmp_path))?;
    // Best effort: force file contents to disk before replacement.
    let _ = tmp_file.sync_all();
    drop(tmp_file);

    #[cfg(windows)]
    if path.exists() {
        // Windows rename cannot replace existing destination atomically.
        std::fs::remove_file(path)
            .with_context(|| format!("Failed to remove existing policy file {:?}", path))?;
    }

    std::fs::rename(&tmp_path, path).with_context(|| {
        format!(
            "Failed to atomically replace policy file {:?} from {:?}",
            path, tmp_path
        )
    })?;

    Ok(())
}

fn write_policy_generation_with_manifest(
    policy_path: &Path,
    policy_bytes: &[u8],
    manifest_path: &Path,
    manifest_bytes: &[u8],
) -> Result<()> {
    let previous_policy = std::fs::read(policy_path).ok();
    atomic_write_policy(policy_path, policy_bytes)?;

    if let Err(error) = atomic_write_policy(manifest_path, manifest_bytes) {
        if let Err(rollback_error) = rollback_policy_file(policy_path, previous_policy.as_deref()) {
            anyhow::bail!(
                "policy sync manifest write failed after policy file write: {error}; rollback failed: {rollback_error}"
            );
        }
        return Err(error).with_context(|| {
            format!(
                "Failed to commit policy sync manifest {:?}; rolled back policy file {:?}",
                manifest_path, policy_path
            )
        });
    }

    Ok(())
}

fn rollback_policy_file(policy_path: &Path, previous_policy: Option<&[u8]>) -> Result<()> {
    if let Some(previous_policy) = previous_policy {
        atomic_write_policy(policy_path, previous_policy)
            .with_context(|| format!("Failed to roll back policy file {:?}", policy_path))?;
    } else if policy_path.exists() {
        std::fs::remove_file(policy_path).with_context(|| {
            format!(
                "Failed to remove partially written policy file {:?}",
                policy_path
            )
        })?;
    }
    Ok(())
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn bucket_name_format() {
        assert_eq!(
            PolicySync::bucket_name("tenant-acme.clawdstrike", "agent-xyz"),
            "tenant-acme-clawdstrike-policy-sync-agent-xyz"
        );
    }

    #[test]
    fn policy_key_is_stable() {
        assert_eq!(PolicySync::policy_key(), "policy.yaml");
    }

    #[test]
    fn atomic_write_policy_creates_and_overwrites_file() {
        let base =
            std::env::temp_dir().join(format!("policy-sync-write-test-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&base).unwrap();
        let path = base.join("policy.yaml");

        atomic_write_policy(&path, b"version: 1\n").unwrap();
        assert_eq!(std::fs::read(&path).unwrap(), b"version: 1\n");

        atomic_write_policy(&path, b"version: 2\n").unwrap();
        assert_eq!(std::fs::read(&path).unwrap(), b"version: 2\n");

        let tmp_path = path.with_extension("tmp");
        assert!(!tmp_path.exists());

        let _ = std::fs::remove_file(path);
        let _ = std::fs::remove_dir_all(base);
    }

    #[test]
    fn policy_sync_manifest_path_is_policy_scoped() {
        let path = PathBuf::from("/tmp/clawdstrike/policy.yaml");
        assert_eq!(
            policy_sync_manifest_path(&path),
            PathBuf::from("/tmp/clawdstrike/policy.yaml.manifest.json")
        );
    }

    #[test]
    fn write_policy_with_manifest_rejects_downgrades_and_same_epoch_mutation() {
        let base = std::env::temp_dir().join(format!(
            "policy-sync-integrity-test-{}",
            uuid::Uuid::new_v4()
        ));
        std::fs::create_dir_all(&base).unwrap();
        let path = base.join("policy.yaml");
        let manifest_path = policy_sync_manifest_path(&path);

        let v20 = b"version: fleet-v20\npolicy_epoch: 20\nrules: []\n";
        write_policy_with_manifest(&path, v20).unwrap();
        assert_eq!(std::fs::read(&path).unwrap(), v20);
        let manifest = read_policy_sync_manifest(&manifest_path).unwrap();
        assert_eq!(manifest.policy_epoch, Some(20));
        assert_eq!(
            manifest.content_hash,
            hush_core::sha256(v20).to_hex_prefixed()
        );

        let downgrade = b"version: fleet-v19\npolicy_epoch: 19\nrules: []\n";
        let downgrade_err = write_policy_with_manifest(&path, downgrade)
            .expect_err("epoch downgrade should be rejected");
        assert!(downgrade_err.to_string().contains("epoch downgrade"));
        assert_eq!(std::fs::read(&path).unwrap(), v20);

        let same_epoch_changed =
            b"version: fleet-v20-mutated\npolicy_epoch: 20\nrules:\n  - id: changed\n";
        let mutation_err = write_policy_with_manifest(&path, same_epoch_changed)
            .expect_err("same-epoch mutation should be rejected");
        assert!(mutation_err
            .to_string()
            .contains("content hash change without policy epoch advance"));
        assert_eq!(std::fs::read(&path).unwrap(), v20);

        let missing_epoch = b"version: missing-epoch\nrules: []\n";
        let missing_epoch_err = write_policy_with_manifest(&path, missing_epoch)
            .expect_err("missing explicit epoch should be rejected");
        assert!(missing_epoch_err
            .to_string()
            .contains("without explicit policy epoch"));
        assert_eq!(std::fs::read(&path).unwrap(), v20);

        let v21 = b"version: fleet-v21\npolicy_epoch: 21\nrules: []\n";
        write_policy_with_manifest(&path, v21).unwrap();
        assert_eq!(std::fs::read(&path).unwrap(), v21);
        assert_eq!(
            read_policy_sync_manifest(&manifest_path)
                .unwrap()
                .policy_epoch,
            Some(21)
        );

        let _ = std::fs::remove_dir_all(base);
    }

    #[test]
    fn write_policy_with_manifest_rejects_initial_missing_epoch() {
        let base = std::env::temp_dir().join(format!(
            "policy-sync-missing-epoch-test-{}",
            uuid::Uuid::new_v4()
        ));
        std::fs::create_dir_all(&base).unwrap();
        let path = base.join("policy.yaml");

        let err = write_policy_with_manifest(&path, b"version: legacy\nrules: []\n")
            .expect_err("fleet policy sync must require explicit policy epoch");
        assert!(err.to_string().contains("without explicit policy epoch"));
        assert!(!path.exists());

        let _ = std::fs::remove_dir_all(base);
    }

    #[test]
    fn write_policy_generation_rolls_back_policy_file_when_manifest_commit_fails() {
        let base = std::env::temp_dir().join(format!(
            "policy-sync-rollback-test-{}",
            uuid::Uuid::new_v4()
        ));
        std::fs::create_dir_all(&base).unwrap();
        let path = base.join("policy.yaml");
        let manifest_path = base.join("policy.yaml.manifest.json");
        let original = b"version: fleet-v20\npolicy_epoch: 20\nrules: []\n";
        let candidate = b"version: fleet-v21\npolicy_epoch: 21\nrules: []\n";
        let original_manifest = br#"{"schemaVersion":1}"#;

        write_policy_generation_with_manifest(&path, original, &manifest_path, original_manifest)
            .unwrap();
        std::fs::remove_file(&manifest_path).unwrap();
        std::fs::create_dir(&manifest_path).unwrap();

        let error = write_policy_generation_with_manifest(
            &path,
            candidate,
            &manifest_path,
            br#"{"schemaVersion":1,"policyEpoch":21}"#,
        )
        .expect_err("manifest path collision should fail");

        assert!(error.to_string().contains("rolled back policy file"));
        assert_eq!(std::fs::read(&path).unwrap(), original);

        let _ = std::fs::remove_dir_all(base);
    }
}
