//! NATS KV-based policy synchronization.
//!
//! Watches a tenant/agent-scoped KV bucket for policy updates and writes
//! them to the local policy file. On delete events, the last known policy
//! is retained (fail-closed: never leave the agent without a policy).

use anyhow::{Context, Result};
use async_nats::jetstream::kv;
use std::io::Write;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::broadcast;

use crate::nats_client::NatsClient;
use crate::nats_subjects;

/// Manages policy synchronization from NATS KV to local disk.
pub struct PolicySync {
    nats: Arc<NatsClient>,
    policy_path: PathBuf,
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
        if let Some(parent) = self.policy_path.parent() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("Failed to create policy directory {:?}", parent))?;
        }

        atomic_write_policy(&self.policy_path, data)?;

        Ok(())
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

fn atomic_write_policy(path: &PathBuf, data: &[u8]) -> Result<()> {
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
}
