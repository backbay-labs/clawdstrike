//! Multi-curator trust configuration.
//!
//! Trusted curator public keys can come from three sources (merged in order):
//! 1. Embedded defaults (compiled into the binary)
//! 2. A TOML config file (`trusted_curators.toml`)
//! 3. The `CLAWDSTRIKE_TRUSTED_CURATORS` environment variable (comma-separated hex keys)
//!
//! The richer [`CuratorConfig`] type adds per-curator trust levels and feed-scoping
//! on top of the original [`CuratorTrustSet`] flat key list.

use hush_core::PublicKey;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

use crate::error::{Error, Result};

/// Embedded default curator keys (the official ClawdStrike feed signer).
const DEFAULT_CURATOR_KEYS_HEX: &[&str] = &[
    // clawdstrike-official
    "b51f6b9b8b2fcf77fb365f8a191579483c92af88ed914d6f79f08784699411ed",
];

/// Environment variable for additional trusted curator keys (comma-separated hex).
const ENV_VAR: &str = "CLAWDSTRIKE_TRUSTED_CURATORS";

// ---------------------------------------------------------------------------
// Original flat config types (preserved for backward compatibility)
// ---------------------------------------------------------------------------

/// On-disk representation of `trusted_curators.toml` (legacy flat key list).
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
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
        let contents = toml::to_string_pretty(self)
            .map_err(|e| Error::ConfigError(format!("Failed to serialize curator config: {e}")))?;
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
            let mut env_keys = Vec::new();
            for chunk in env_val.split(',') {
                let trimmed = chunk.trim();
                if !trimmed.is_empty() {
                    env_keys.push(trimmed.to_string());
                }
            }
            if !env_keys.is_empty() {
                tracing::warn!(
                    count = env_keys.len(),
                    "loaded curator trust keys from CLAWDSTRIKE_TRUSTED_CURATORS env var"
                );
                hex_keys.extend(env_keys);
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
        let pk = PublicKey::from_hex(hex)
            .map_err(|e| Error::ConfigError(format!("Invalid curator public key '{hex}': {e}")))?;
        keys.push(pk);
    }
    Ok(keys)
}

// ---------------------------------------------------------------------------
// Rich multi-curator config types
// ---------------------------------------------------------------------------

/// Default config file location: `~/.clawdstrike/trusted_curators.toml`.
pub fn default_config_path() -> Option<PathBuf> {
    dirs::home_dir().map(|h| h.join(".clawdstrike").join("trusted_curators.toml"))
}

/// Trust level for a curator.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum TrustLevel {
    /// Policies from this curator can be auto-installed.
    Full,
    /// Policies shown in UI but require explicit user approval before installation.
    AuditOnly,
}

fn default_trust_level() -> TrustLevel {
    TrustLevel::AuditOnly
}

/// A single trusted curator entry as it appears in the TOML config.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CuratorEntry {
    /// Human-readable curator name.
    pub name: String,
    /// Ed25519 public key (hex-encoded, 0x-prefix optional).
    pub public_key: String,
    /// Trust level (defaults to `audit-only`).
    #[serde(default = "default_trust_level")]
    pub trust_level: TrustLevel,
    /// Optional: restrict this curator to specific feed IDs.
    /// Empty means trust for any feed.
    #[serde(default)]
    pub feed_ids: Vec<String>,
}

/// TOML file representation for the rich curator config format.
///
/// Example:
/// ```toml
/// [[curator]]
/// name = "clawdstrike-official"
/// public_key = "b51f6b9b..."
/// trust_level = "full"
/// feed_ids = ["clawdstrike-official"]
/// ```
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RichCuratorConfigFile {
    #[serde(default)]
    pub curator: Vec<CuratorEntry>,
}

/// A curator entry with its public key parsed and validated.
#[derive(Clone, Debug)]
pub struct ValidatedCurator {
    pub name: String,
    pub public_key: PublicKey,
    pub trust_level: TrustLevel,
    pub feed_ids: Vec<String>,
}

/// Loaded and validated multi-curator configuration.
///
/// Provides feed-scoped key lookups and trust-level awareness on top of
/// the flat [`CuratorTrustSet`].
#[derive(Clone, Debug)]
pub struct CuratorConfig {
    entries: Vec<ValidatedCurator>,
}

impl CuratorConfig {
    /// Load from a TOML file path.
    pub fn load(path: &Path) -> Result<Self> {
        let content = std::fs::read_to_string(path).map_err(|e| {
            Error::ConfigError(format!(
                "Failed to read curator config at {}: {}",
                path.display(),
                e
            ))
        })?;
        Self::parse(&content)
    }

    /// Load from the default path (`~/.clawdstrike/trusted_curators.toml`),
    /// falling back to an empty config if the file does not exist.
    pub fn load_default() -> Result<Self> {
        if let Some(path) = default_config_path() {
            if path.exists() {
                return Self::load(&path);
            }
        }
        // Fallback: empty config (no curators trusted)
        Ok(Self {
            entries: Vec::new(),
        })
    }

    /// Parse from a TOML string.
    pub fn parse(toml_str: &str) -> Result<Self> {
        let file: RichCuratorConfigFile = toml::from_str(toml_str).map_err(|e| {
            Error::ConfigError(format!("Invalid curator config TOML: {e}"))
        })?;

        let mut entries = Vec::with_capacity(file.curator.len());
        for entry in file.curator {
            let hex = entry.public_key.strip_prefix("0x").unwrap_or(&entry.public_key);
            let pk = PublicKey::from_hex(hex).map_err(|e| {
                Error::ConfigError(format!(
                    "Invalid public key for curator '{}': {}",
                    entry.name, e
                ))
            })?;
            entries.push(ValidatedCurator {
                name: entry.name,
                public_key: pk,
                trust_level: entry.trust_level,
                feed_ids: entry.feed_ids,
            });
        }

        Ok(Self { entries })
    }

    /// Get all trusted public keys (for use with `verify_trusted`).
    pub fn public_keys(&self) -> Vec<PublicKey> {
        self.entries.iter().map(|e| e.public_key.clone()).collect()
    }

    /// Get public keys restricted to a specific feed ID.
    ///
    /// A curator matches if its `feed_ids` list is empty (wildcard) or contains
    /// the given `feed_id`.
    pub fn public_keys_for_feed(&self, feed_id: &str) -> Vec<PublicKey> {
        self.entries
            .iter()
            .filter(|e| e.feed_ids.is_empty() || e.feed_ids.iter().any(|f| f == feed_id))
            .map(|e| e.public_key.clone())
            .collect()
    }

    /// Look up the curator entry for a given public key.
    pub fn find_curator(&self, public_key: &PublicKey) -> Option<&ValidatedCurator> {
        self.entries.iter().find(|e| &e.public_key == public_key)
    }

    /// Returns all curator entries.
    pub fn curators(&self) -> &[ValidatedCurator] {
        &self.entries
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // -----------------------------------------------------------------------
    // Legacy CuratorTrustSet tests (preserved)
    // -----------------------------------------------------------------------

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

    // -----------------------------------------------------------------------
    // Rich CuratorConfig tests
    // -----------------------------------------------------------------------

    #[test]
    fn parse_valid_config() {
        let kp = hush_core::Keypair::generate();
        let toml_str = format!(
            r#"
[[curator]]
name = "test-curator"
public_key = "{}"
trust_level = "full"
feed_ids = ["test-feed"]
"#,
            kp.public_key().to_hex()
        );
        let config = CuratorConfig::parse(&toml_str).unwrap();
        assert_eq!(config.curators().len(), 1);
        assert_eq!(config.curators()[0].name, "test-curator");
        assert_eq!(config.curators()[0].trust_level, TrustLevel::Full);
        assert_eq!(config.curators()[0].feed_ids, vec!["test-feed"]);
    }

    #[test]
    fn parse_config_with_0x_prefix() {
        let kp = hush_core::Keypair::generate();
        let toml_str = format!(
            r#"
[[curator]]
name = "prefixed"
public_key = "0x{}"
trust_level = "full"
"#,
            kp.public_key().to_hex()
        );
        let config = CuratorConfig::parse(&toml_str).unwrap();
        assert_eq!(config.curators()[0].public_key, kp.public_key());
    }

    #[test]
    fn empty_config_returns_no_curators() {
        let config = CuratorConfig::parse("").unwrap();
        assert!(config.curators().is_empty());
        assert!(config.public_keys().is_empty());
    }

    #[test]
    fn feed_id_filtering() {
        let kp1 = hush_core::Keypair::generate();
        let kp2 = hush_core::Keypair::generate();
        let toml_str = format!(
            r#"
[[curator]]
name = "specific"
public_key = "{}"
trust_level = "full"
feed_ids = ["feed-a"]

[[curator]]
name = "wildcard"
public_key = "{}"
trust_level = "full"
feed_ids = []
"#,
            kp1.public_key().to_hex(),
            kp2.public_key().to_hex()
        );
        let config = CuratorConfig::parse(&toml_str).unwrap();
        // "feed-a" should match both (specific + wildcard)
        assert_eq!(config.public_keys_for_feed("feed-a").len(), 2);
        // "feed-b" should match only wildcard
        assert_eq!(config.public_keys_for_feed("feed-b").len(), 1);
    }

    #[test]
    fn invalid_public_key_errors() {
        let toml_str = r#"
[[curator]]
name = "bad"
public_key = "not-a-valid-key"
trust_level = "full"
"#;
        let err = CuratorConfig::parse(toml_str).unwrap_err();
        assert!(err.to_string().contains("Invalid public key"));
    }

    #[test]
    fn default_trust_level_is_audit_only() {
        let kp = hush_core::Keypair::generate();
        let toml_str = format!(
            r#"
[[curator]]
name = "no-level"
public_key = "{}"
"#,
            kp.public_key().to_hex()
        );
        let config = CuratorConfig::parse(&toml_str).unwrap();
        assert_eq!(config.curators()[0].trust_level, TrustLevel::AuditOnly);
    }

    #[test]
    fn find_curator_by_public_key() {
        let kp1 = hush_core::Keypair::generate();
        let kp2 = hush_core::Keypair::generate();
        let toml_str = format!(
            r#"
[[curator]]
name = "alice"
public_key = "{}"
trust_level = "full"

[[curator]]
name = "bob"
public_key = "{}"
trust_level = "audit-only"
"#,
            kp1.public_key().to_hex(),
            kp2.public_key().to_hex()
        );
        let config = CuratorConfig::parse(&toml_str).unwrap();

        let alice = config.find_curator(&kp1.public_key()).unwrap();
        assert_eq!(alice.name, "alice");
        assert_eq!(alice.trust_level, TrustLevel::Full);

        let bob = config.find_curator(&kp2.public_key()).unwrap();
        assert_eq!(bob.name, "bob");
        assert_eq!(bob.trust_level, TrustLevel::AuditOnly);

        let unknown = hush_core::Keypair::generate();
        assert!(config.find_curator(&unknown.public_key()).is_none());
    }

    #[test]
    fn unknown_fields_rejected() {
        let kp = hush_core::Keypair::generate();
        let toml_str = format!(
            r#"
[[curator]]
name = "test"
public_key = "{}"
trust_level = "full"
bogus_field = true
"#,
            kp.public_key().to_hex()
        );
        let err = CuratorConfig::parse(&toml_str).unwrap_err();
        assert!(err.to_string().contains("unknown field"));
    }

    #[test]
    fn load_from_file() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("curators.toml");
        let kp = hush_core::Keypair::generate();
        let content = format!(
            r#"
[[curator]]
name = "file-curator"
public_key = "{}"
trust_level = "full"
"#,
            kp.public_key().to_hex()
        );
        std::fs::write(&path, content).expect("write");

        let config = CuratorConfig::load(&path).unwrap();
        assert_eq!(config.curators().len(), 1);
        assert_eq!(config.curators()[0].name, "file-curator");
    }

    #[test]
    fn load_default_returns_empty_when_no_file() {
        // load_default should not fail even if ~/.clawdstrike/ doesn't exist
        let config = CuratorConfig::load_default().unwrap();
        // May or may not have entries depending on machine state, but should not error
        let _ = config.curators();
    }
}
