//! Signed OTA updater for managed hushd binaries.

use crate::daemon::{managed_hushd_path, DaemonManager};
use crate::settings::Settings;
use anyhow::{Context, Result};
use chrono::Utc;
use hush_core::canonical::canonicalize;
use hush_core::{sha256, Hash, PublicKey, Signature};
use semver::Version;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::HashSet;
use std::path::Path;
use std::process::Stdio;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{broadcast, Mutex, RwLock};

const OTA_SCHEMA_VERSION: &str = "clawdstrike-hushd-ota-v1";
const OTA_DEFAULT_MANIFEST_STABLE_URL: &str =
    "https://github.com/backbay-labs/clawdstrike/releases/latest/download/hushd-ota-manifest-stable.json";
const OTA_DEFAULT_MANIFEST_BETA_URL: &str =
    "https://github.com/backbay-labs/clawdstrike/releases/latest/download/hushd-ota-manifest-beta.json";
const OTA_TRUST_ENV_VAR: &str = "CLAWDSTRIKE_HUSHD_OTA_TRUSTED_KEYS";
const OTA_DEFAULT_TRUSTED_KEYS_HEX: &[&str] =
    &["25dac855f4df93b016fa3e03c7e8775f235dbcd8ecea0b0fecf5299511ce6bb4"];

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OtaStatus {
    pub state: String,
    pub source_url: Option<String>,
    pub current_version: Option<String>,
    pub latest_version: Option<String>,
    pub update_available: bool,
    pub last_check_at: Option<String>,
    pub last_apply_at: Option<String>,
    pub last_result: Option<String>,
    pub last_error: Option<String>,
}

impl Default for OtaStatus {
    fn default() -> Self {
        Self {
            state: "idle".to_string(),
            source_url: None,
            current_version: None,
            latest_version: None,
            update_available: false,
            last_check_at: None,
            last_apply_at: None,
            last_result: None,
            last_error: None,
        }
    }
}

#[derive(Clone, Debug, Deserialize)]
struct OtaManifest {
    schema_version: String,
    release_version: String,
    published_at: String,
    channel: String,
    min_agent_version: Option<String>,
    notes_url: Option<String>,
    artifacts: Vec<OtaArtifact>,
    signature: String,
    public_key: Option<String>,
}

#[derive(Clone, Debug, Deserialize)]
struct OtaArtifact {
    platform: String,
    url: String,
    sha256: String,
    size: Option<u64>,
}

#[derive(Clone, Debug)]
struct VerifiedManifest {
    manifest: OtaManifest,
    source_url: String,
}

pub struct HushdUpdater {
    settings: Arc<RwLock<Settings>>,
    daemon_manager: Arc<DaemonManager>,
    http_client: reqwest::Client,
    status: Arc<RwLock<OtaStatus>>,
    op_lock: Arc<Mutex<()>>,
    background_started: AtomicBool,
}

impl HushdUpdater {
    pub fn new(settings: Arc<RwLock<Settings>>, daemon_manager: Arc<DaemonManager>) -> Self {
        let initial_settings = settings
            .try_read()
            .map(|guard| guard.clone())
            .unwrap_or_default();
        let status = OtaStatus {
            last_check_at: initial_settings.ota_last_check_at.clone(),
            last_result: initial_settings.ota_last_result.clone(),
            current_version: initial_settings.ota_current_hushd_version.clone(),
            ..OtaStatus::default()
        };

        Self {
            settings,
            daemon_manager,
            http_client: reqwest::Client::builder()
                .timeout(Duration::from_secs(20))
                .build()
                .unwrap_or_else(|_| reqwest::Client::new()),
            status: Arc::new(RwLock::new(status)),
            op_lock: Arc::new(Mutex::new(())),
            background_started: AtomicBool::new(false),
        }
    }

    pub fn start_background(self: &Arc<Self>, mut shutdown_rx: broadcast::Receiver<()>) {
        if self.background_started.swap(true, Ordering::SeqCst) {
            return;
        }

        let updater = Arc::clone(self);
        tokio::spawn(async move {
            // Let startup settle first.
            if tokio::time::timeout(Duration::from_secs(45), shutdown_rx.recv())
                .await
                .is_ok()
            {
                return;
            }

            loop {
                let snapshot = updater.settings.read().await.clone();
                if snapshot.ota_enabled {
                    let auto_mode = normalize_mode(&snapshot.ota_mode) == "auto";
                    let _ = updater.check_once(auto_mode).await;
                }

                let interval_minutes = snapshot.ota_check_interval_minutes.max(5) as u64;
                let jitter_seconds = Utc::now().timestamp().unsigned_abs() % 301;
                let wait = Duration::from_secs(interval_minutes * 60 + jitter_seconds);

                tokio::select! {
                    _ = shutdown_rx.recv() => break,
                    _ = tokio::time::sleep(wait) => {}
                }
            }
        });
    }

    pub async fn status(&self) -> OtaStatus {
        self.status.read().await.clone()
    }

    pub async fn check_now(&self) -> Result<OtaStatus> {
        self.check_once(false).await
    }

    pub async fn apply_now(&self) -> Result<OtaStatus> {
        self.check_once(true).await
    }

    async fn check_once(&self, apply_if_available: bool) -> Result<OtaStatus> {
        let _guard = self.op_lock.lock().await;
        self.set_state("checking").await;

        let settings_snapshot = self.settings.read().await.clone();
        if !settings_snapshot.ota_enabled {
            let now = now_rfc3339();
            self.set_result(
                Some("OTA disabled in settings".to_string()),
                None,
                Some(now.clone()),
            )
            .await;
            self.persist_status_fields(&now, "OTA disabled", None)
                .await?;
            return Ok(self.status().await);
        }

        let verified_manifest = match self.fetch_verified_manifest(&settings_snapshot).await {
            Ok(manifest) => manifest,
            Err(err) => {
                let msg = format!("OTA check failed: {err}");
                self.record_check_failure(&msg, None).await;
                return Err(err);
            }
        };

        let artifact = match select_platform_artifact(&verified_manifest.manifest)
            .with_context(|| format!("No OTA artifact for platform {}", current_platform_id()))
        {
            Ok(artifact) => artifact,
            Err(err) => {
                let msg = format!("OTA check failed: {err}");
                self.record_check_failure(&msg, None).await;
                return Err(err);
            }
        };

        let current_version = self.resolve_current_version(&settings_snapshot).await;
        let latest_version = verified_manifest.manifest.release_version.clone();
        let update_available =
            match is_update_available(current_version.as_deref(), &latest_version) {
                Ok(update_available) => update_available,
                Err(err) => {
                    let msg = format!("OTA check failed: {err}");
                    self.record_check_failure(&msg, current_version.as_deref())
                        .await;
                    return Err(err);
                }
            };
        let now = now_rfc3339();
        let source_url = Some(verified_manifest.source_url.clone());

        {
            let mut status = self.status.write().await;
            status.state = "idle".to_string();
            status.source_url = source_url;
            status.current_version = current_version.clone();
            status.latest_version = Some(latest_version.clone());
            status.update_available = update_available;
            status.last_check_at = Some(now.clone());
            status.last_error = None;
        }

        let check_summary = if update_available {
            format!("Update available: {}", latest_version)
        } else {
            format!(
                "No update available (current: {}, latest: {})",
                current_version
                    .clone()
                    .unwrap_or_else(|| "unknown".to_string()),
                latest_version
            )
        };

        self.persist_status_fields(&now, &check_summary, current_version.as_deref())
            .await?;

        if !update_available {
            return Ok(self.status().await);
        }

        if !apply_if_available {
            return Ok(self.status().await);
        }

        self.set_state("applying").await;
        let release_version = verified_manifest.manifest.release_version.clone();
        let apply_result = self
            .apply_update_artifact(&settings_snapshot, artifact)
            .await;

        match apply_result {
            Ok(()) => {
                let now = now_rfc3339();
                {
                    let mut status = self.status.write().await;
                    status.state = "succeeded".to_string();
                    status.last_apply_at = Some(now.clone());
                    status.last_result = Some(format!("Applied hushd update {release_version}"));
                    status.last_error = None;
                    status.current_version = Some(release_version.clone());
                    status.update_available = false;
                }
                self.persist_status_fields(
                    &now,
                    &format!("Applied hushd update {release_version}"),
                    Some(&release_version),
                )
                .await?;
            }
            Err(err) => {
                let msg = format!("Failed to apply hushd update {release_version}: {err}");
                self.record_check_failure(&msg, current_version.as_deref())
                    .await;
                return Err(err);
            }
        }

        Ok(self.status().await)
    }

    async fn fetch_verified_manifest(&self, settings: &Settings) -> Result<VerifiedManifest> {
        let mut errors = Vec::new();
        for source_url in resolve_manifest_urls(settings) {
            match self.fetch_and_verify_manifest(&source_url, settings).await {
                Ok(verified) => return Ok(verified),
                Err(err) => {
                    errors.push(format!("{source_url}: {err}"));
                }
            }
        }

        anyhow::bail!("No valid OTA manifest found. {}", errors.join(" | "));
    }

    async fn fetch_and_verify_manifest(
        &self,
        source_url: &str,
        settings: &Settings,
    ) -> Result<VerifiedManifest> {
        let response = self
            .http_client
            .get(source_url)
            .send()
            .await
            .with_context(|| format!("Failed to fetch manifest from {source_url}"))?;

        if !response.status().is_success() {
            anyhow::bail!("Manifest request returned {}", response.status());
        }

        let body = response
            .bytes()
            .await
            .with_context(|| "Failed to read manifest response body")?;
        let value: Value =
            serde_json::from_slice(&body).with_context(|| "Manifest payload is not valid JSON")?;
        let manifest: OtaManifest = serde_json::from_value(value.clone())
            .with_context(|| "Manifest does not match expected schema")?;

        if manifest.schema_version != OTA_SCHEMA_VERSION {
            anyhow::bail!(
                "Unsupported OTA schema version: {} (expected {})",
                manifest.schema_version,
                OTA_SCHEMA_VERSION
            );
        }

        let expected_channel = normalize_channel(&settings.ota_channel);
        if normalize_channel(&manifest.channel) != expected_channel {
            anyhow::bail!(
                "Manifest channel mismatch: got {}, expected {}",
                manifest.channel,
                expected_channel
            );
        }

        if let Some(min_agent_version) = &manifest.min_agent_version {
            let required = parse_semver(min_agent_version)
                .with_context(|| format!("Invalid min_agent_version: {min_agent_version}"))?;
            let current = parse_semver(env!("CARGO_PKG_VERSION"))
                .with_context(|| "Invalid agent package version")?;
            if current < required {
                anyhow::bail!(
                    "Manifest requires agent >= {}, current {}",
                    required,
                    current
                );
            }
        }

        let trusted_keys = load_trusted_keys(settings)?;
        let signer = verify_manifest_signature(&value, &manifest, &trusted_keys)?;
        tracing::info!(
            source_url,
            signer = %signer.to_hex(),
            version = %manifest.release_version,
            published_at = %manifest.published_at,
            notes_url = ?manifest.notes_url,
            "Verified hushd OTA manifest"
        );

        Ok(VerifiedManifest {
            manifest,
            source_url: source_url.to_string(),
        })
    }

    async fn apply_update_artifact(
        &self,
        settings: &Settings,
        artifact: &OtaArtifact,
    ) -> Result<()> {
        if settings.hushd_binary_path.is_some() {
            anyhow::bail!("Refusing OTA apply because hushd_binary_path override is configured");
        }

        let expected_hash = Hash::from_hex(&artifact.sha256)
            .with_context(|| format!("Invalid artifact sha256 hash: {}", artifact.sha256))?;
        let active_path = self.daemon_manager.binary_path();
        let managed_path = managed_hushd_path();
        if active_path != managed_path {
            anyhow::bail!(
                "Refusing OTA apply for non-managed daemon path {}",
                active_path.display()
            );
        }

        let bytes = self
            .download_artifact_bytes(&artifact.url)
            .await
            .with_context(|| "Failed to download OTA artifact")?;

        if let Some(size) = artifact.size {
            if bytes.len() as u64 != size {
                anyhow::bail!(
                    "Artifact size mismatch: expected {}, got {}",
                    size,
                    bytes.len()
                );
            }
        }

        let actual_hash = sha256(&bytes);
        if actual_hash != expected_hash {
            anyhow::bail!(
                "Artifact hash mismatch: expected {}, got {}",
                expected_hash.to_hex(),
                actual_hash.to_hex()
            );
        }

        let staged_path =
            active_path.with_file_name(format!("{}.staged", file_name_string(&active_path)?));
        std::fs::create_dir_all(
            staged_path
                .parent()
                .ok_or_else(|| anyhow::anyhow!("Invalid staged binary path"))?,
        )
        .with_context(|| format!("Failed to create staged dir for {}", staged_path.display()))?;
        std::fs::write(&staged_path, &bytes).with_context(|| {
            format!("Failed to write staged binary to {}", staged_path.display())
        })?;
        set_executable_if_needed(&staged_path)?;
        self.validate_staged_binary(&staged_path).await?;
        self.swap_binary_with_rollback(&active_path, &staged_path)
            .await
    }

    async fn download_artifact_bytes(&self, url: &str) -> Result<Vec<u8>> {
        let response = self
            .http_client
            .get(url)
            .send()
            .await
            .with_context(|| format!("Failed to fetch artifact from {url}"))?;
        if !response.status().is_success() {
            anyhow::bail!("Artifact download returned {}", response.status());
        }
        let bytes = response
            .bytes()
            .await
            .with_context(|| "Failed to read artifact response body")?;
        Ok(bytes.to_vec())
    }

    async fn validate_staged_binary(&self, staged_path: &Path) -> Result<()> {
        let status = tokio::process::Command::new(staged_path)
            .arg("--version")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .await
            .with_context(|| {
                format!("Failed to execute staged binary {}", staged_path.display())
            })?;
        if !status.success() {
            anyhow::bail!(
                "Staged binary validation failed for {}",
                staged_path.display()
            );
        }
        Ok(())
    }

    async fn swap_binary_with_rollback(
        &self,
        active_path: &Path,
        staged_path: &Path,
    ) -> Result<()> {
        let active_name = file_name_string(active_path)?;
        let prev_path = active_path.with_file_name(format!("{active_name}.prev"));

        self.daemon_manager
            .stop()
            .await
            .with_context(|| "Failed to stop daemon before OTA swap")?;

        if prev_path.exists() {
            let _ = std::fs::remove_file(&prev_path);
        }

        if active_path.exists() {
            std::fs::rename(active_path, &prev_path).with_context(|| {
                format!(
                    "Failed to move active binary {} to backup {}",
                    active_path.display(),
                    prev_path.display()
                )
            })?;
        }

        if let Err(err) = std::fs::rename(staged_path, active_path) {
            if prev_path.exists() {
                let _ = std::fs::rename(&prev_path, active_path);
            }
            anyhow::bail!("Failed to promote staged binary: {err}");
        }

        if let Err(err) = set_executable_if_needed(active_path) {
            let _ = self.rollback_swap(active_path, &prev_path).await;
            return Err(err);
        }

        if let Err(err) = self
            .daemon_manager
            .start()
            .await
            .with_context(|| "Daemon failed to start after OTA swap")
        {
            let _ = self.rollback_swap(active_path, &prev_path).await;
            return Err(err);
        }

        if prev_path.exists() {
            let _ = std::fs::remove_file(&prev_path);
        }
        Ok(())
    }

    async fn rollback_swap(&self, active_path: &Path, prev_path: &Path) -> Result<()> {
        tracing::warn!(
            active = %active_path.display(),
            backup = %prev_path.display(),
            "Rolling back hushd binary swap"
        );

        let _ = self.daemon_manager.stop().await;

        if active_path.exists() {
            let _ = std::fs::remove_file(active_path);
        }

        if prev_path.exists() {
            std::fs::rename(prev_path, active_path).with_context(|| {
                format!(
                    "Failed to restore backup binary {} to {}",
                    prev_path.display(),
                    active_path.display()
                )
            })?;
            set_executable_if_needed(active_path)?;
        }

        self.daemon_manager
            .start()
            .await
            .with_context(|| "Failed to restart daemon after rollback")?;
        Ok(())
    }

    async fn resolve_current_version(&self, settings: &Settings) -> Option<String> {
        let daemon_status = self.daemon_manager.status().await;
        daemon_status
            .version
            .or_else(|| settings.ota_current_hushd_version.clone())
    }

    async fn persist_status_fields(
        &self,
        check_at: &str,
        result: &str,
        current_version: Option<&str>,
    ) -> Result<()> {
        let mut settings = self.settings.write().await;
        settings.ota_last_check_at = Some(check_at.to_string());
        settings.ota_last_result = Some(result.to_string());
        if let Some(version) = current_version {
            settings.ota_current_hushd_version = Some(version.to_string());
        }
        settings
            .save()
            .with_context(|| "Failed to persist OTA status to settings")
    }

    async fn set_state(&self, state: &str) {
        self.status.write().await.state = state.to_string();
    }

    async fn set_result(
        &self,
        last_result: Option<String>,
        last_error: Option<String>,
        last_check_at: Option<String>,
    ) {
        let mut status = self.status.write().await;
        status.state = "idle".to_string();
        status.last_result = last_result;
        status.last_error = last_error;
        status.last_check_at = last_check_at;
    }

    async fn set_failure(&self, message: &str) {
        let mut status = self.status.write().await;
        status.state = "failed".to_string();
        status.last_error = Some(message.to_string());
        status.last_result = Some(message.to_string());
    }

    async fn record_check_failure(&self, message: &str, current_version: Option<&str>) {
        self.set_failure(message).await;
        let now = now_rfc3339();
        if let Err(persist_err) = self
            .persist_status_fields(&now, message, current_version)
            .await
        {
            tracing::warn!(
                error = %persist_err,
                "Failed to persist OTA failure status"
            );
        }
    }
}

fn resolve_manifest_urls(settings: &Settings) -> Vec<String> {
    let default_url = match normalize_channel(&settings.ota_channel).as_str() {
        "beta" => OTA_DEFAULT_MANIFEST_BETA_URL,
        _ => OTA_DEFAULT_MANIFEST_STABLE_URL,
    };

    let mut urls = Vec::new();
    if let Some(override_url) = settings.ota_manifest_url.clone() {
        urls.push(override_url);
        if settings.ota_allow_fallback_to_default {
            urls.push(default_url.to_string());
        }
        return urls;
    }

    urls.push(default_url.to_string());
    urls
}

fn normalize_mode(raw: &str) -> String {
    let raw = raw.trim().to_ascii_lowercase();
    match raw.as_str() {
        "manual" => "manual".to_string(),
        _ => "auto".to_string(),
    }
}

fn normalize_channel(raw: &str) -> String {
    let raw = raw.trim().to_ascii_lowercase();
    match raw.as_str() {
        "beta" => "beta".to_string(),
        _ => "stable".to_string(),
    }
}

fn parse_semver(input: &str) -> Result<Version> {
    let trimmed = input.trim().trim_start_matches('v');
    Version::parse(trimmed).with_context(|| format!("Invalid semver: {input}"))
}

fn is_update_available(current: Option<&str>, latest: &str) -> Result<bool> {
    let latest = parse_semver(latest)?;
    let Some(current) = current else {
        return Ok(true);
    };
    let current = parse_semver(current)?;
    Ok(latest > current)
}

fn current_platform_id() -> String {
    match (std::env::consts::OS, std::env::consts::ARCH) {
        ("macos", "aarch64") => "darwin-aarch64".to_string(),
        ("macos", "x86_64") => "darwin-x86_64".to_string(),
        ("linux", "x86_64") => "linux-x86_64".to_string(),
        ("windows", "x86_64") => "windows-x86_64".to_string(),
        (os, arch) => format!("{os}-{arch}"),
    }
}

fn select_platform_artifact(manifest: &OtaManifest) -> Result<&OtaArtifact> {
    let platform = current_platform_id();
    manifest
        .artifacts
        .iter()
        .find(|artifact| artifact.platform == platform)
        .ok_or_else(|| anyhow::anyhow!("No artifact for platform {platform}"))
}

fn load_trusted_keys(settings: &Settings) -> Result<Vec<PublicKey>> {
    let mut raw_keys: Vec<String> = OTA_DEFAULT_TRUSTED_KEYS_HEX
        .iter()
        .map(|v| (*v).to_string())
        .collect();
    raw_keys.extend(settings.ota_pinned_public_keys.clone());

    if cfg!(debug_assertions) {
        if let Ok(env_keys) = std::env::var(OTA_TRUST_ENV_VAR) {
            raw_keys.extend(
                env_keys
                    .split(',')
                    .map(str::trim)
                    .filter(|v| !v.is_empty())
                    .map(|v| v.to_string()),
            );
        }
    } else if std::env::var_os(OTA_TRUST_ENV_VAR).is_some() {
        tracing::warn!("{} is ignored in release builds", OTA_TRUST_ENV_VAR);
    }

    let mut seen = HashSet::new();
    let mut keys = Vec::new();
    for raw in raw_keys {
        let pk = PublicKey::from_hex(&raw)
            .with_context(|| format!("Invalid OTA trusted public key: {raw}"))?;
        let hex = pk.to_hex();
        if seen.insert(hex) {
            keys.push(pk);
        }
    }

    if keys.is_empty() {
        anyhow::bail!("No OTA trusted keys configured");
    }
    Ok(keys)
}

fn verify_manifest_signature(
    manifest_value: &Value,
    manifest: &OtaManifest,
    trusted_keys: &[PublicKey],
) -> Result<PublicKey> {
    let mut payload_value = manifest_value.clone();
    let payload_obj = payload_value
        .as_object_mut()
        .ok_or_else(|| anyhow::anyhow!("Manifest root must be an object"))?;
    payload_obj.remove("signature");

    let canonical =
        canonicalize(&payload_value).with_context(|| "Failed to canonicalize manifest")?;
    let signature = Signature::from_hex(&manifest.signature)
        .with_context(|| "Manifest signature is not valid hex Ed25519 bytes")?;

    if let Some(public_key_hex) = &manifest.public_key {
        let signer_key = PublicKey::from_hex(public_key_hex)
            .with_context(|| "Manifest embedded public_key is invalid")?;
        if !trusted_keys.iter().any(|trusted| trusted == &signer_key) {
            anyhow::bail!("Manifest embedded signer key is not trusted");
        }
        if !signer_key.verify(canonical.as_bytes(), &signature) {
            anyhow::bail!("Manifest signature verification failed");
        }
        return Ok(signer_key);
    }

    for key in trusted_keys {
        if key.verify(canonical.as_bytes(), &signature) {
            return Ok(key.clone());
        }
    }

    anyhow::bail!("Manifest signature did not match any trusted key")
}

fn file_name_string(path: &Path) -> Result<String> {
    let Some(name) = path.file_name().and_then(|v| v.to_str()) else {
        anyhow::bail!("Path {} has no file name", path.display());
    };
    Ok(name.to_string())
}

fn now_rfc3339() -> String {
    Utc::now().to_rfc3339()
}

fn set_executable_if_needed(path: &Path) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = std::fs::metadata(path)
            .with_context(|| format!("Failed to stat {}", path.display()))?
            .permissions();
        perms.set_mode(0o755);
        std::fs::set_permissions(path, perms)
            .with_context(|| format!("Failed to chmod {}", path.display()))?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use hush_core::Keypair;

    #[test]
    fn update_availability_uses_semver() {
        assert!(matches!(
            is_update_available(Some("0.1.0"), "0.1.1"),
            Ok(true)
        ));
        assert!(matches!(
            is_update_available(Some("0.1.1"), "0.1.1"),
            Ok(false)
        ));
        assert!(matches!(
            is_update_available(Some("0.2.0"), "0.1.9"),
            Ok(false)
        ));
    }

    #[test]
    fn verify_manifest_signature_accepts_trusted_embedded_key() {
        let keypair = Keypair::generate();
        let mut manifest = serde_json::json!({
            "schema_version": OTA_SCHEMA_VERSION,
            "release_version": "1.2.3",
            "published_at": "2026-01-01T00:00:00Z",
            "channel": "stable",
            "artifacts": [{
                "platform": "darwin-aarch64",
                "url": "https://example.com/hushd",
                "sha256": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                "size": 123
            }],
            "public_key": keypair.public_key().to_hex()
        });
        let canonical = match canonicalize(&manifest) {
            Ok(value) => value,
            Err(err) => panic!("manifest canonicalization should succeed: {err}"),
        };
        let signature = keypair.sign(canonical.as_bytes()).to_hex();
        manifest["signature"] = serde_json::Value::String(signature);

        let parsed: OtaManifest = match serde_json::from_value(manifest.clone()) {
            Ok(value) => value,
            Err(err) => panic!("manifest parse should succeed: {err}"),
        };
        let signer = match verify_manifest_signature(&manifest, &parsed, &[keypair.public_key()]) {
            Ok(value) => value,
            Err(err) => panic!("signature verification should succeed: {err}"),
        };
        assert_eq!(signer.to_hex(), keypair.public_key().to_hex());
    }
}
