//! Multi-curator trust configuration.
//!
//! Trusted curator public keys can come from three sources (merged in order):
//! 1. Embedded defaults (compiled into the binary)
//! 2. A TOML config file (`trusted_curators.toml`)
//! 3. The `CLAWDSTRIKE_TRUSTED_CURATORS` environment variable (comma-separated hex keys)

use hush_core::PublicKey;
use serde::{Deserialize, Serialize};
use std::path::Path;

use crate::error::{Error, Result};

/// Embedded default curator keys (the official ClawdStrike feed signer).
const DEFAULT_CURATOR_KEYS_HEX: &[&str] = &[
    // clawdstrike-official
    "b51f6b9b8b2fcf77fb365f8a191579483c92af88ed914d6f79f08784699411ed",
];

/// Environment variable for additional trusted curator keys (comma-separated hex).
const ENV_VAR: &str = "CLAWDSTRIKE_TRUSTED_CURATORS";

/// On-disk representation of `trusted_curators.toml`.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct CuratorConfigFile {
    /// Hex-encoded Ed25519 public keys of trusted curators.
    #[serde(default)]
    pub trusted_keys: Vec<String>,
}

impl CuratorConfigFile {
    /// Load from a TOML file. Returns `None` if the file does not exist.
    pub fn load(path: impl AsRef<Path>) -> Result<Option<Self>> {
        let path = path.as_ref();
        if !path.exists() {
            return Ok(None);
        }
        let contents = std::fs::read_to_string(path).map_err(|e| {
            Error::ConfigError(format!(
                "Failed to read curator config {}: {}",
                path.display(),
                e
            ))
        })?;
        let config: Self = toml::from_str(&contents).map_err(|e| {
            Error::ConfigError(format!(
                "Failed to parse curator config {}: {}",
                path.display(),
                e
            ))
        })?;
        Ok(Some(config))
    }

    /// Save to a TOML file.
    pub fn save(&self, path: impl AsRef<Path>) -> Result<()> {
        let path = path.as_ref();
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).map_err(|e| {
                Error::ConfigError(format!(
                    "Failed to create config directory {}: {}",
                    parent.display(),
                    e
                ))
            })?;
        }
        let contents = toml::to_string_pretty(self).map_err(|e| {
            Error::ConfigError(format!("Failed to serialize curator config: {e}"))
        })?;
        std::fs::write(path, contents).map_err(|e| {
            Error::ConfigError(format!(
                "Failed to write curator config {}: {}",
                path.display(),
                e
            ))
        })?;
        Ok(())
    }
}

/// Resolved set of trusted curator public keys.
#[derive(Clone, Debug)]
pub struct CuratorTrustSet {
    keys: Vec<PublicKey>,
}

impl CuratorTrustSet {
    /// Build a trust set from embedded defaults only.
    pub fn defaults() -> Result<Self> {
        let keys = parse_hex_keys(DEFAULT_CURATOR_KEYS_HEX.iter().copied())?;
        Ok(Self { keys })
    }

    /// Build a trust set from all sources:
    /// 1. Embedded defaults
    /// 2. Config file at `config_path` (if it exists)
    /// 3. `CLAWDSTRIKE_TRUSTED_CURATORS` env var
    pub fn load(config_path: Option<&Path>) -> Result<Self> {
        let mut hex_keys: Vec<String> = DEFAULT_CURATOR_KEYS_HEX
            .iter()
            .map(|s| (*s).to_string())
            .collect();

        // Config file
        if let Some(path) = config_path {
            if let Some(file_config) = CuratorConfigFile::load(path)? {
                hex_keys.extend(file_config.trusted_keys);
            }
        }

        // Environment variable
        if let Ok(env_val) = std::env::var(ENV_VAR) {
            for chunk in env_val.split(',') {
                let trimmed = chunk.trim();
                if !trimmed.is_empty() {
                    hex_keys.push(trimmed.to_string());
                }
            }
        }

        // Deduplicate by hex string
        hex_keys.sort();
        hex_keys.dedup();

        let keys = parse_hex_keys(hex_keys.iter().map(|s| s.as_str()))?;
        Ok(Self { keys })
    }

    /// Returns a slice of the trusted public keys.
    pub fn keys(&self) -> &[PublicKey] {
        &self.keys
    }

    /// Returns true if the set contains the given public key.
    pub fn contains(&self, key: &PublicKey) -> bool {
        self.keys.iter().any(|k| k == key)
    }

    /// Number of trusted keys.
    pub fn len(&self) -> usize {
        self.keys.len()
    }

    /// Whether the trust set is empty.
    pub fn is_empty(&self) -> bool {
        self.keys.is_empty()
    }
}

fn parse_hex_keys<'a>(hex_iter: impl Iterator<Item = &'a str>) -> Result<Vec<PublicKey>> {
    let mut keys = Vec::new();
    for hex in hex_iter {
        let hex = hex.strip_prefix("0x").unwrap_or(hex);
        let pk = PublicKey::from_hex(hex).map_err(|e| {
            Error::ConfigError(format!("Invalid curator public key '{hex}': {e}"))
        })?;
        keys.push(pk);
    }
    Ok(keys)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_loads_embedded_key() {
        let trust = CuratorTrustSet::defaults().expect("should load defaults");
        assert_eq!(trust.len(), 1);
        assert_eq!(
            trust.keys()[0].to_hex(),
            "b51f6b9b8b2fcf77fb365f8a191579483c92af88ed914d6f79f08784699411ed"
        );
    }

    #[test]
    fn config_file_roundtrip() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("curators.toml");

        let keypair = hush_core::Keypair::generate();
        let hex = keypair.public_key().to_hex();

        let config = CuratorConfigFile {
            trusted_keys: vec![hex.clone()],
        };
        config.save(&path).expect("save");

        let loaded = CuratorConfigFile::load(&path)
            .expect("load")
            .expect("should exist");
        assert_eq!(loaded.trusted_keys, vec![hex]);
    }

    #[test]
    fn load_merges_defaults_and_config_file() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("curators.toml");

        let keypair = hush_core::Keypair::generate();
        let hex = keypair.public_key().to_hex();

        let config = CuratorConfigFile {
            trusted_keys: vec![hex.clone()],
        };
        config.save(&path).expect("save");

        let trust = CuratorTrustSet::load(Some(&path)).expect("load");
        // Should contain both the default key and the config file key
        assert!(trust.len() >= 2);
        assert!(trust.contains(&keypair.public_key()));
    }

    #[test]
    fn missing_config_file_uses_defaults() {
        let path = Path::new("/nonexistent/curators.toml");
        let trust = CuratorTrustSet::load(Some(path)).expect("should use defaults");
        assert_eq!(trust.len(), 1);
    }

    #[test]
    fn deduplicates_keys() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("curators.toml");

        // Put the same default key in the config file
        let config = CuratorConfigFile {
            trusted_keys: vec![
                "b51f6b9b8b2fcf77fb365f8a191579483c92af88ed914d6f79f08784699411ed".to_string(),
            ],
        };
        config.save(&path).expect("save");

        let trust = CuratorTrustSet::load(Some(&path)).expect("load");
        assert_eq!(trust.len(), 1);
    }
}
