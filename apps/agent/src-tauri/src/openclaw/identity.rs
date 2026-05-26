//! Filesystem identity discovery, parsing, and storage for OpenClaw devices.

use anyhow::{Context, Result};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use ed25519_dalek::{pkcs8::DecodePublicKey, VerifyingKey};
use serde::Deserialize;
use std::collections::HashSet;
use std::path::{Path, PathBuf};
use zeroize::Zeroizing;

pub(super) const OPENCLAW_STATE_DIR: &str = ".openclaw";
pub(super) const OPENCLAW_IDENTITY_PATH: &str = "identity/device.json";
pub(super) const OPENCLAW_LEGACY_STATE_DIRS: [&str; 3] = [".clawdbot", ".moldbot", ".moltbot"];

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct OpenClawDeviceIdentityFile {
    #[serde(default)]
    pub(super) version: Option<u32>,
    #[serde(alias = "device_id")]
    pub(super) device_id: String,
    #[serde(alias = "public_key_pem")]
    pub(super) public_key_pem: String,
    #[serde(default, alias = "private_key_pem")]
    pub(super) private_key_pem: Option<String>,
}

pub(super) struct OpenClawDeviceIdentity {
    pub(super) device_id: String,
    pub(super) public_key_raw_base64url: String,
    pub(super) private_key_pem: Zeroizing<String>,
}

impl std::fmt::Debug for OpenClawDeviceIdentity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OpenClawDeviceIdentity")
            .field("device_id", &self.device_id)
            .field("public_key_raw_base64url", &self.public_key_raw_base64url)
            .field("private_key_pem", &"[REDACTED]")
            .finish()
    }
}

pub(super) fn load_openclaw_device_identity() -> Result<Option<OpenClawDeviceIdentity>> {
    load_openclaw_device_identity_from_candidates(&openclaw_identity_candidate_paths())
}

pub(super) fn load_openclaw_device_identity_from_path(
    path: &Path,
) -> Result<OpenClawDeviceIdentity> {
    let raw = std::fs::read_to_string(path)
        .with_context(|| format!("failed to read OpenClaw identity file: {:?}", path))?;
    let parsed: OpenClawDeviceIdentityFile = serde_json::from_str(&raw)
        .with_context(|| format!("invalid OpenClaw identity JSON: {:?}", path))?;

    if parsed.version != Some(1) {
        return Err(anyhow::anyhow!(
            "unsupported OpenClaw identity version {:?} in {:?}",
            parsed.version,
            path
        ));
    }

    let verifying_key = VerifyingKey::from_public_key_pem(parsed.public_key_pem.trim())
        .map_err(|err| anyhow::anyhow!("invalid OpenClaw identity public key PEM: {err}"))?;
    let derived_device_id = hush_core::sha256(verifying_key.as_bytes()).to_hex();
    if !parsed.device_id.trim().is_empty() && parsed.device_id != derived_device_id {
        tracing::warn!(
            configured_device_id = %parsed.device_id,
            derived_device_id = %derived_device_id,
            "OpenClaw identity device id mismatch; using derived fingerprint"
        );
    }

    let private_key_pem = if let Some(raw_private_key) = parsed.private_key_pem.as_deref() {
        let trimmed = raw_private_key.trim();
        if trimmed.is_empty() {
            anyhow::bail!("OpenClaw identity private key is empty in {:?}", path);
        }
        match crate::security::key_store::store_openclaw_private_key(&derived_device_id, trimmed) {
            Ok(()) => {
                if let Err(err) = persist_openclaw_identity_metadata(
                    path,
                    &derived_device_id,
                    parsed.public_key_pem.trim(),
                ) {
                    tracing::warn!(
                        error = %err,
                        device_id = %derived_device_id,
                        "Failed to persist OpenClaw identity metadata after key migration; keeping current identity file"
                    );
                }
            }
            Err(err) => {
                tracing::warn!(
                    error = %err,
                    device_id = %derived_device_id,
                    "Failed to migrate OpenClaw private key to keyring-backed storage; keeping in-file key material"
                );
            }
        }
        trimmed.to_string()
    } else {
        crate::security::key_store::load_openclaw_private_key(&derived_device_id)
            .with_context(|| {
                format!(
                    "failed to load OpenClaw private key from keyring-backed storage for {}",
                    derived_device_id
                )
            })?
            .map(|value| value.trim().to_string())
            .filter(|value| !value.is_empty())
            .ok_or_else(|| {
                anyhow::anyhow!(
                    "OpenClaw identity private key is missing from keyring-backed storage for {}",
                    derived_device_id
                )
            })?
    };

    Ok(OpenClawDeviceIdentity {
        device_id: derived_device_id,
        public_key_raw_base64url: URL_SAFE_NO_PAD.encode(verifying_key.as_bytes()),
        private_key_pem: Zeroizing::new(private_key_pem),
    })
}

fn persist_openclaw_identity_metadata(
    path: &Path,
    device_id: &str,
    public_key_pem: &str,
) -> Result<()> {
    let metadata = serde_json::json!({
        "version": 1,
        "deviceId": device_id,
        "publicKeyPem": public_key_pem,
        "privateKeyStorage": "keyring"
    });
    let serialized = serde_json::to_string_pretty(&metadata)
        .with_context(|| "failed to serialize OpenClaw identity metadata")?;
    crate::security::fs::write_private_atomic(
        path,
        serialized.as_bytes(),
        "OpenClaw identity metadata",
    )
}

fn configured_openclaw_state_dir_override() -> Option<PathBuf> {
    normalized_env_var("OPENCLAW_STATE_DIR")
        .or_else(|| normalized_env_var("CLAWDBOT_STATE_DIR"))
        .map(|override_path| resolve_user_path(&override_path, &resolve_openclaw_home_dir()))
}

pub(super) fn openclaw_identity_candidate_paths() -> Vec<PathBuf> {
    openclaw_identity_candidate_paths_for(
        &resolve_openclaw_home_dir(),
        configured_openclaw_state_dir_override().as_deref(),
    )
}

pub(super) fn openclaw_identity_candidate_paths_for(
    home_dir: &Path,
    override_state_dir: Option<&Path>,
) -> Vec<PathBuf> {
    let mut candidates = Vec::new();
    if let Some(override_dir) = override_state_dir {
        candidates.push(override_dir.join(OPENCLAW_IDENTITY_PATH));
    } else {
        candidates.push(
            home_dir
                .join(OPENCLAW_STATE_DIR)
                .join(OPENCLAW_IDENTITY_PATH),
        );
        for legacy in OPENCLAW_LEGACY_STATE_DIRS {
            candidates.push(home_dir.join(legacy).join(OPENCLAW_IDENTITY_PATH));
        }
    }

    let mut seen = HashSet::new();
    candidates.retain(|path| seen.insert(path.clone()));
    candidates
}

pub(super) fn load_openclaw_device_identity_from_candidates(
    candidates: &[PathBuf],
) -> Result<Option<OpenClawDeviceIdentity>> {
    for identity_path in candidates {
        if !identity_path.exists() {
            continue;
        }

        return load_openclaw_device_identity_from_path(identity_path)
            .with_context(|| format!("failed to load OpenClaw identity from {:?}", identity_path))
            .map(Some);
    }

    Ok(None)
}

fn resolve_openclaw_home_dir() -> PathBuf {
    let fallback = dirs::home_dir().unwrap_or_else(|| PathBuf::from("."));
    if let Some(value) = normalized_env_var("OPENCLAW_HOME") {
        return resolve_user_path(&value, &fallback);
    }
    if let Some(value) = normalized_env_var("HOME") {
        return resolve_user_path(&value, &fallback);
    }
    if let Some(value) = normalized_env_var("USERPROFILE") {
        return resolve_user_path(&value, &fallback);
    }
    fallback
}

fn normalized_env_var(key: &str) -> Option<String> {
    std::env::var(key)
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
}

fn resolve_user_path(input: &str, home_dir: &Path) -> PathBuf {
    let trimmed = input.trim();
    let resolved = if trimmed == "~" {
        home_dir.to_path_buf()
    } else if let Some(remainder) = trimmed
        .strip_prefix("~/")
        .or_else(|| trimmed.strip_prefix("~\\"))
    {
        home_dir.join(remainder)
    } else {
        PathBuf::from(trimmed)
    };

    if resolved.is_absolute() {
        resolved
    } else if let Ok(current_dir) = std::env::current_dir() {
        current_dir.join(resolved)
    } else {
        resolved
    }
}
