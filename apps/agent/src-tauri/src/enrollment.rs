//! Agent enrollment for cloud-managed enterprise deployment.
//!
//! Handles the enrollment handshake with the Control API, generating a keypair,
//! exchanging the public key for NATS credentials, and persisting the enrollment state.

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::RwLock;

use crate::settings::{get_config_dir, hostname_best_effort, EnrollmentState, Settings};

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

#[derive(Debug, Clone, Copy)]
enum EnrollmentKeyPersistence {
    Keyring,
    LegacyFileFallback,
}

fn extract_trusted_issuer(issuer: Option<&str>) -> Result<String> {
    issuer
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToString::to_string)
        .ok_or_else(|| {
            anyhow::anyhow!(
                "Enrollment response missing approval_response_trusted_issuer; refusing to enable NATS"
            )
        })
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

        let result = self.do_enroll(control_api_url, enrollment_token).await;

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
        let key_hex = keypair.to_hex();
        let public_key_hex = keypair.public_key().to_hex();
        let previous_key_hex = match load_enrollment_key_hex() {
            Ok(previous) => previous,
            Err(err) => {
                tracing::warn!(
                    error = %err,
                    "Failed to read existing enrollment key before enrollment; continuing without rollback key snapshot"
                );
                None
            }
        };
        let previous_settings_snapshot = self.settings.read().await.clone();

        let hostname = hostname_best_effort();

        let enroll_url = format!(
            "{}/api/v1/agents/enroll",
            control_api_url.trim_end_matches('/')
        );

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
        let trusted_issuer =
            extract_trusted_issuer(resp.approval_response_trusted_issuer.as_deref())?;

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
            settings.nats.require_signed_approval_responses = true;
            settings.nats.approval_response_trusted_issuer = Some(trusted_issuer);
            settings
                .save()
                .with_context(|| "Failed to persist enrollment settings")?;
        }

        let persistence = match persist_enrollment_key(&key_hex)
            .with_context(|| "Failed to persist enrollment key after enrollment response")
        {
            Ok(persistence) => persistence,
            Err(store_err) => {
                if let Err(rollback_err) = restore_previous_enrollment_key(previous_key_hex.clone())
                {
                    tracing::warn!(
                        error = %rollback_err,
                        "Failed to restore previous enrollment key after key-store write error"
                    );
                }
                if let Err(rollback_err) =
                    restore_previous_settings_snapshot(&self.settings, &previous_settings_snapshot)
                        .await
                {
                    tracing::warn!(
                        error = %rollback_err,
                        "Failed to restore previous enrollment settings after key-store write error"
                    );
                }
                return Err(store_err);
            }
        };
        match persistence {
            EnrollmentKeyPersistence::Keyring => {
                tracing::info!("Agent private key stored in keyring-backed store");
            }
            EnrollmentKeyPersistence::LegacyFileFallback => {
                tracing::warn!(
                    "Agent private key persisted to legacy on-disk fallback because keyring write failed"
                );
            }
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

fn legacy_agent_key_path() -> PathBuf {
    get_config_dir().join("agent.key")
}

fn persist_legacy_enrollment_key(key_hex: &str) -> Result<()> {
    let trimmed = key_hex.trim();
    if trimmed.is_empty() {
        anyhow::bail!("Enrollment key cannot be empty");
    }
    let legacy_path = legacy_agent_key_path();
    crate::security::fs::write_private_atomic(
        &legacy_path,
        trimmed.as_bytes(),
        "legacy enrollment key",
    )
    .with_context(|| {
        format!(
            "Failed to persist legacy enrollment key at {:?}",
            legacy_path
        )
    })
}

fn persist_enrollment_key(key_hex: &str) -> Result<EnrollmentKeyPersistence> {
    let trimmed = key_hex.trim();
    if trimmed.is_empty() {
        anyhow::bail!("Enrollment key cannot be empty");
    }

    match crate::security::key_store::store_enrollment_key_hex(trimmed) {
        Ok(()) => {
            let legacy_path = legacy_agent_key_path();
            if legacy_path.exists() {
                if let Err(err) = std::fs::remove_file(&legacy_path) {
                    tracing::warn!(
                        error = %err,
                        path = ?legacy_path,
                        "Failed to remove legacy enrollment key file after keyring write"
                    );
                }
            }
            Ok(EnrollmentKeyPersistence::Keyring)
        }
        Err(err) => {
            tracing::warn!(
                error = %err,
                "Failed to persist enrollment key to keyring; writing legacy fallback file"
            );
            persist_legacy_enrollment_key(trimmed)?;
            Ok(EnrollmentKeyPersistence::LegacyFileFallback)
        }
    }
}

fn restore_previous_enrollment_key(previous_key_hex: Option<String>) -> Result<()> {
    if let Some(previous_key_hex) = previous_key_hex {
        let _ = persist_enrollment_key(previous_key_hex.trim())
            .with_context(|| "Failed to restore previous enrollment key")?;
    } else {
        if let Err(err) = crate::security::key_store::delete_enrollment_key_hex() {
            tracing::warn!(
                error = %err,
                "Failed to clear keyring enrollment key during rollback"
            );
        }
        let legacy_path = legacy_agent_key_path();
        if legacy_path.exists() {
            std::fs::remove_file(&legacy_path).with_context(|| {
                format!(
                    "Failed to clear legacy enrollment key file during rollback {:?}",
                    legacy_path
                )
            })?;
        }
    }
    Ok(())
}

async fn restore_previous_settings_snapshot(
    settings_handle: &Arc<RwLock<Settings>>,
    snapshot: &Settings,
) -> Result<()> {
    let mut settings = settings_handle.write().await;
    *settings = snapshot.clone();
    settings
        .save()
        .with_context(|| "Failed to restore previous enrollment settings")?;
    Ok(())
}

/// Load the enrollment private key hex from secure storage.
///
/// If a legacy on-disk `agent.key` exists, migrate it into keyring-backed storage.
pub fn load_enrollment_key_hex() -> Result<Option<String>> {
    match crate::security::key_store::load_enrollment_key_hex() {
        Ok(Some(stored)) => {
            let trimmed = stored.trim();
            if !trimmed.is_empty() {
                return Ok(Some(trimmed.to_string()));
            }
        }
        Ok(None) => {}
        Err(err) => {
            tracing::warn!(
                error = %err,
                "Failed to load enrollment key from keyring-backed store; trying legacy key file and continuing if none exists"
            );
        }
    }

    let legacy_path = legacy_agent_key_path();
    if !legacy_path.exists() {
        return Ok(None);
    }

    let legacy = std::fs::read_to_string(&legacy_path).with_context(|| {
        format!(
            "Failed to read legacy enrollment key from {:?}",
            legacy_path
        )
    })?;
    let legacy_trimmed = legacy.trim().to_string();
    if legacy_trimmed.is_empty() {
        return Ok(None);
    }

    if let Err(err) = crate::security::key_store::store_enrollment_key_hex(&legacy_trimmed) {
        tracing::warn!(
            error = %err,
            path = ?legacy_path,
            "Failed to migrate legacy enrollment key into keyring-backed store; using legacy file"
        );
        return Ok(Some(legacy_trimmed));
    }

    std::fs::remove_file(&legacy_path).with_context(|| {
        format!(
            "Failed to remove migrated legacy enrollment key file {:?}",
            legacy_path
        )
    })?;

    Ok(Some(legacy_trimmed))
}

pub fn migrate_legacy_enrollment_key_file() -> Result<()> {
    let _ = load_enrollment_key_hex()?;
    Ok(())
}

/// Write a file with restricted permissions (owner-only read/write).
///
/// On Unix, the file is created with mode 0o600 from the start to avoid
/// a TOCTOU window where the private key would be world-readable.
#[cfg(test)]
fn write_private_file(path: &PathBuf, data: &[u8]) -> Result<()> {
    crate::security::fs::write_private_atomic(path, data, "private file")
        .with_context(|| format!("Failed to write file {:?}", path))
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

    #[test]
    fn extract_trusted_issuer_requires_non_empty_value() {
        let issuer = extract_trusted_issuer(Some("  issuer-1  "))
            .unwrap_or_else(|err| panic!("expected issuer parse to succeed: {err}"));
        assert_eq!(issuer, "issuer-1");

        let missing = extract_trusted_issuer(None);
        assert!(missing.is_err());

        let blank = extract_trusted_issuer(Some("   "));
        assert!(blank.is_err());
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
