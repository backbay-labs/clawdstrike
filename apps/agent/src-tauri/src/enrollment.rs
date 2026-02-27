//! Agent enrollment for cloud-managed enterprise deployment.
//!
//! Handles the enrollment handshake with the cloud API, generating a keypair,
//! exchanging the public key for NATS credentials, and persisting the enrollment state.

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::RwLock;

use crate::settings::{get_config_dir, EnrollmentState, Settings};

/// Result of a successful enrollment.
#[derive(Debug, Clone, Serialize)]
pub struct EnrollmentResult {
    pub agent_uuid: String,
    pub tenant_id: String,
    pub nats_creds_path: String,
}

/// Request body sent to the cloud API enrollment endpoint.
#[derive(Debug, Serialize)]
struct EnrollRequest {
    enrollment_token: String,
    public_key: String,
    hostname: String,
    version: String,
}

/// Response from the cloud API enrollment endpoint.
#[derive(Debug, Deserialize)]
struct EnrollResponse {
    agent_uuid: String,
    tenant_id: String,
    nats_url: String,
    nats_credentials: String,
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

    /// Check whether the agent is currently enrolled.
    pub async fn is_enrolled(&self) -> bool {
        let settings = self.settings.read().await;
        settings.enrollment.enrolled
    }

    /// Get the current enrollment state.
    pub async fn enrollment_state(&self) -> EnrollmentState {
        let settings = self.settings.read().await;
        settings.enrollment.clone()
    }

    /// Perform the enrollment handshake with the cloud API.
    pub async fn enroll(
        &self,
        cloud_api_url: &str,
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
            .do_enroll(cloud_api_url, enrollment_token)
            .await;

        // Clear in-progress flag regardless of outcome.
        {
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
        cloud_api_url: &str,
        enrollment_token: &str,
    ) -> Result<EnrollmentResult> {
        // Generate a new Ed25519 keypair.
        let keypair = hush_core::Keypair::generate();
        let public_key_hex = keypair.public_key().to_hex();

        let hostname = get_hostname();

        let enroll_url = format!("{}/api/v1/agents/enroll", cloud_api_url.trim_end_matches('/'));

        let body = EnrollRequest {
            enrollment_token: enrollment_token.to_string(),
            public_key: public_key_hex.clone(),
            hostname,
            version: env!("CARGO_PKG_VERSION").to_string(),
        };

        tracing::info!(url = %enroll_url, "Sending enrollment request to cloud API");

        let response = self
            .http_client
            .post(&enroll_url)
            .json(&body)
            .send()
            .await
            .with_context(|| format!("Failed to reach cloud API at {}", enroll_url))?;

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

        // Store NATS credentials.
        let creds_path = get_config_dir().join("nats.creds");
        write_private_file(&creds_path, resp.nats_credentials.as_bytes())
            .with_context(|| format!("Failed to write NATS credentials to {:?}", creds_path))?;
        tracing::info!(path = ?creds_path, "NATS credentials stored");

        let creds_path_str = creds_path
            .to_str()
            .unwrap_or_default()
            .to_string();

        // Update settings with enrollment state and NATS configuration.
        {
            let mut settings = self.settings.write().await;
            settings.enrollment = EnrollmentState {
                enrolled: true,
                agent_uuid: Some(resp.agent_uuid.clone()),
                tenant_id: Some(resp.tenant_id.clone()),
                nats_creds_path: Some(creds_path_str.clone()),
                enrollment_in_progress: false,
            };
            settings.nats.enabled = true;
            settings.nats.nats_url = Some(resp.nats_url);
            settings.nats.creds_file = Some(creds_path_str.clone());
            settings.nats.tenant_id = Some(resp.tenant_id.clone());
            settings.nats.agent_id = Some(resp.agent_id);
            settings
                .save()
                .with_context(|| "Failed to persist enrollment settings")?;
        }

        let result = EnrollmentResult {
            agent_uuid: resp.agent_uuid,
            tenant_id: resp.tenant_id,
            nats_creds_path: creds_path_str,
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
fn write_private_file(path: &PathBuf, data: &[u8]) -> Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("Failed to create directory {:?}", parent))?;
    }

    std::fs::write(path, data)
        .with_context(|| format!("Failed to write file {:?}", path))?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
            .with_context(|| format!("Failed to set permissions on {:?}", path))?;
    }

    Ok(())
}

/// Get the system hostname (best-effort).
fn get_hostname() -> String {
    #[cfg(unix)]
    {
        let mut buf = vec![0u8; 256];
        let ret = unsafe { libc::gethostname(buf.as_mut_ptr() as *mut _, buf.len()) };
        if ret == 0 {
            let end = buf.iter().position(|&b| b == 0).unwrap_or(buf.len());
            buf.truncate(end);
            return String::from_utf8_lossy(&buf).into_owned();
        }
    }
    "unknown".to_string()
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
        assert!(state.nats_creds_path.is_none());
    }

    #[test]
    fn get_hostname_returns_something() {
        let hostname = get_hostname();
        assert!(!hostname.is_empty());
    }
}
