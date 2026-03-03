//! Agent enrollment for cloud-managed enterprise deployment.
//!
//! Handles the enrollment handshake with the Control API, generating a keypair,
//! exchanging the public key for NATS credentials, and persisting the enrollment state.

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::RwLock;

use crate::settings::{enforce_private_mode, get_config_dir, hostname_best_effort, EnrollmentState, Settings};

/// Result of a successful enrollment.
#[derive(Debug, Clone, Serialize)]
pub struct EnrollmentResult {
    pub agent_uuid: String,
    pub tenant_id: String,
}

/// Request body sent to the Control API enrollment endpoint.
#[derive(Debug, Serialize)]
struct EnrollRequest {
    enrollment_token: String,
    public_key: String,
    hostname: String,
    version: String,
}

/// Response from the Control API enrollment endpoint.
#[derive(Debug, Deserialize)]
struct EnrollResponse {
    agent_uuid: String,
    tenant_id: String,
    nats_url: String,
    nats_account: String,
    nats_subject_prefix: String,
    nats_token: String,
    #[serde(default)]
    approval_response_trusted_issuer: Option<String>,
    agent_id: String,
}

/// Manages the enrollment lifecycle.
pub struct EnrollmentManager {
    settings: Arc<RwLock<Settings>>,
    http_client: reqwest::Client,
}

impl EnrollmentManager {
    pub fn new(settings: Arc<RwLock<Settings>>) -> Self {
        Self {
            settings,
            http_client: reqwest::Client::builder()
                .timeout(std::time::Duration::from_secs(30))
                .build()
                .unwrap_or_else(|_| reqwest::Client::new()),
        }
    }

    /// Perform the enrollment handshake with the Control API.
    pub async fn enroll(
        &self,
        control_api_url: &str,
        enrollment_token: &str,
    ) -> Result<EnrollmentResult> {
        // Mark enrollment as in-progress for crash recovery.
        {
            let mut settings = self.settings.write().await;
            settings.enrollment.enrollment_in_progress = true;
            if let Err(err) = settings.save() {
                tracing::warn!(error = %err, "Failed to persist enrollment-in-progress flag");
            }
        }

        let result = self
            .do_enroll(control_api_url, enrollment_token)
            .await;

        // `do_enroll` persists `enrollment_in_progress = false` on success.
        // On failure we clear and persist it here so crash-recovery state is accurate.
        if result.is_err() {
            let mut settings = self.settings.write().await;
            settings.enrollment.enrollment_in_progress = false;
            if let Err(err) = settings.save() {
                tracing::warn!(error = %err, "Failed to clear enrollment-in-progress flag");
            }
        }

        result
    }

    async fn do_enroll(
        &self,
        control_api_url: &str,
        enrollment_token: &str,
    ) -> Result<EnrollmentResult> {
        // Generate a new Ed25519 keypair.
        let keypair = hush_core::Keypair::generate();
        let public_key_hex = keypair.public_key().to_hex();

        let hostname = hostname_best_effort();

        let enroll_url = format!("{}/api/v1/agents/enroll", control_api_url.trim_end_matches('/'));

        let body = EnrollRequest {
            enrollment_token: enrollment_token.to_string(),
            public_key: public_key_hex.clone(),
            hostname,
            version: env!("CARGO_PKG_VERSION").to_string(),
        };

        tracing::info!(url = %enroll_url, "Sending enrollment request to Control API");

        let response = self
            .http_client
            .post(&enroll_url)
            .json(&body)
            .send()
            .await
            .with_context(|| format!("Failed to reach Control API at {}", enroll_url))?;

        if !response.status().is_success() {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            anyhow::bail!("Enrollment failed with status {}: {}", status, body);
        }

        let resp: EnrollResponse = response
            .json()
            .await
            .with_context(|| "Failed to parse enrollment response")?;

        // Store the private key.
        let key_path = get_config_dir().join("agent.key");
        write_private_file(&key_path, keypair.to_hex().as_bytes())
            .with_context(|| format!("Failed to write agent key to {:?}", key_path))?;
        tracing::info!(path = ?key_path, "Agent private key stored");

        // Update settings with enrollment state and all NATS configuration.
        {
            let mut settings = self.settings.write().await;
            settings.enrollment = EnrollmentState {
                enrolled: true,
                agent_uuid: Some(resp.agent_uuid.clone()),
                tenant_id: Some(resp.tenant_id.clone()),
                enrollment_in_progress: false,
            };
            settings.nats.enabled = true;
            settings.nats.nats_url = Some(resp.nats_url);
            settings.nats.tenant_id = Some(resp.tenant_id.clone());
            settings.nats.agent_id = Some(resp.agent_id);
            // Clear legacy auth fields so token-based auth is used consistently.
            settings.nats.creds_file = None;
            settings.nats.nkey_seed = None;
            settings.nats.token = Some(resp.nats_token);
            settings.nats.nats_account = Some(resp.nats_account);
            settings.nats.subject_prefix = Some(resp.nats_subject_prefix);
            settings.nats.approval_response_trusted_issuer = resp.approval_response_trusted_issuer;
            settings
                .save()
                .with_context(|| "Failed to persist enrollment settings")?;
        }

        let result = EnrollmentResult {
            agent_uuid: resp.agent_uuid,
            tenant_id: resp.tenant_id,
        };

        tracing::info!(
            agent_uuid = %result.agent_uuid,
            tenant_id = %result.tenant_id,
            "Enrollment complete"
        );

        Ok(result)
    }
}

/// Write a file with restricted permissions (owner-only read/write).
///
/// On Unix, the file is created with mode 0o600 from the start to avoid
/// a TOCTOU window where the private key would be world-readable.
fn write_private_file(path: &PathBuf, data: &[u8]) -> Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("Failed to create directory {:?}", parent))?;
    }

    #[cfg(unix)]
    {
        use std::fs::OpenOptions;
        use std::io::Write;
        use std::os::unix::fs::OpenOptionsExt;

        let mut file = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(path)
            .with_context(|| format!("Failed to create private file {:?}", path))?;
        file.write_all(data)
            .with_context(|| format!("Failed to write file {:?}", path))?;
        enforce_private_mode(path, "private file")?;
    }

    #[cfg(not(unix))]
    {
        std::fs::write(path, data)
            .with_context(|| format!("Failed to write file {:?}", path))?;
    }

    Ok(())
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn enrollment_state_default_is_not_enrolled() {
        let state = EnrollmentState::default();
        assert!(!state.enrolled);
        assert!(!state.enrollment_in_progress);
        assert!(state.agent_uuid.is_none());
        assert!(state.tenant_id.is_none());
    }

    #[test]
    fn get_hostname_returns_something() {
        let hostname = hostname_best_effort();
        assert!(!hostname.is_empty());
    }

    #[cfg(unix)]
    #[test]
    fn write_private_file_hardens_existing_file_permissions() {
        use std::os::unix::fs::PermissionsExt;

        let unique = match std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH) {
            Ok(duration) => duration.as_nanos(),
            Err(_) => 0,
        };
        let dir = std::env::temp_dir().join(format!("clawdstrike-private-file-perms-{unique}"));
        if let Err(err) = std::fs::create_dir_all(&dir) {
            panic!("failed to create temp dir: {err}");
        }
        let path = dir.join("agent.key");
        if let Err(err) = std::fs::write(&path, "seed") {
            panic!("failed to seed private file: {err}");
        }
        if let Err(err) = std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)) {
            panic!("failed to set initial private file mode: {err}");
        }

        if let Err(err) = write_private_file(&path, b"deadbeef") {
            panic!("failed to write private file: {err}");
        }

        let metadata = match std::fs::metadata(&path) {
            Ok(metadata) => metadata,
            Err(err) => panic!("failed to read private file metadata: {err}"),
        };
        let mode = metadata.permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);

        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_dir(&dir);
    }
}
