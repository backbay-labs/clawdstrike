//! Manifest URL resolution, channel/version helpers, trust-key loading, and signature verification.

use anyhow::{Context, Result};
use chrono::Utc;
use hush_core::canonical::canonicalize;
use hush_core::{PublicKey, Signature};
use semver::Version;
use serde_json::Value;
use std::collections::HashSet;
use std::path::Path;

use crate::settings::Settings;

use super::types::{
    OtaArtifact, OtaManifest, OTA_DEFAULT_MANIFEST_BETA_URL, OTA_DEFAULT_MANIFEST_STABLE_URL,
    OTA_DEFAULT_TRUSTED_KEYS_HEX, OTA_TRUST_ENV_VAR,
};

pub(super) fn resolve_manifest_urls(settings: &Settings) -> Vec<String> {
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

pub(super) fn normalize_mode(raw: &str) -> String {
    let raw = raw.trim().to_ascii_lowercase();
    match raw.as_str() {
        "manual" => "manual".to_string(),
        _ => "auto".to_string(),
    }
}

pub(super) fn normalize_channel(raw: &str) -> String {
    let raw = raw.trim().to_ascii_lowercase();
    match raw.as_str() {
        "beta" => "beta".to_string(),
        _ => "stable".to_string(),
    }
}

pub(super) fn parse_semver(input: &str) -> Result<Version> {
    let trimmed = input.trim().trim_start_matches('v');
    Version::parse(trimmed).with_context(|| format!("Invalid semver: {input}"))
}

pub(super) fn is_update_available(current: Option<&str>, latest: &str) -> Result<bool> {
    let latest = parse_semver(latest)?;
    let Some(current) = current else {
        return Ok(true);
    };
    let current = parse_semver(current)?;
    Ok(latest > current)
}

pub(super) fn current_platform_id() -> String {
    match (std::env::consts::OS, std::env::consts::ARCH) {
        ("macos", "aarch64") => "darwin-aarch64".to_string(),
        ("macos", "x86_64") => "darwin-x86_64".to_string(),
        ("linux", "x86_64") => "linux-x86_64".to_string(),
        ("windows", "x86_64") => "windows-x86_64".to_string(),
        (os, arch) => format!("{os}-{arch}"),
    }
}

pub(super) fn select_platform_artifact(manifest: &OtaManifest) -> Result<&OtaArtifact> {
    let platform = current_platform_id();
    manifest
        .artifacts
        .iter()
        .find(|artifact| artifact.platform == platform)
        .ok_or_else(|| anyhow::anyhow!("No artifact for platform {platform}"))
}

pub(super) fn load_trusted_keys(settings: &Settings) -> Result<Vec<PublicKey>> {
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

pub(super) fn verify_manifest_signature(
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

pub(super) fn file_name_string(path: &Path) -> Result<String> {
    let Some(name) = path.file_name().and_then(|v| v.to_str()) else {
        anyhow::bail!("Path {} has no file name", path.display());
    };
    Ok(name.to_string())
}

pub(super) fn now_rfc3339() -> String {
    Utc::now().to_rfc3339()
}

pub(super) fn set_executable_if_needed(path: &Path) -> Result<()> {
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
