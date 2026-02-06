use std::collections::HashSet;

use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PluginManifest {
    pub plugin: PluginMetadata,
    #[serde(default)]
    pub clawdstrike: Option<PluginClawdstrikeCompatibility>,
    #[serde(default)]
    pub guards: Vec<PluginGuardManifestEntry>,
    #[serde(default)]
    pub capabilities: PluginCapabilities,
    #[serde(default)]
    pub resources: PluginResourceLimits,
    #[serde(default)]
    pub trust: PluginTrust,
}

impl PluginManifest {
    pub fn validate(&self) -> Result<()> {
        if self.plugin.version.trim().is_empty() {
            return Err(Error::ConfigError(
                "plugin manifest.plugin.version must be a non-empty string".to_string(),
            ));
        }
        if self.plugin.name.trim().is_empty() {
            return Err(Error::ConfigError(
                "plugin manifest.plugin.name must be a non-empty string".to_string(),
            ));
        }
        if self.guards.is_empty() {
            return Err(Error::ConfigError(
                "plugin manifest.guards must be a non-empty array".to_string(),
            ));
        }
        if self.resources.max_memory_mb < 1
            || self.resources.max_cpu_ms < 1
            || self.resources.max_timeout_ms < 1
        {
            return Err(Error::ConfigError(
                "plugin manifest.resources values must be positive integers".to_string(),
            ));
        }

        if let Some(compat) = &self.clawdstrike {
            if let Some(min) = &compat.min_version {
                if !is_strict_semver(min) {
                    return Err(Error::ConfigError(
                        "plugin manifest.clawdstrike.min_version must be strict semver (x.y.z)"
                            .to_string(),
                    ));
                }
            }

            if let Some(max) = &compat.max_version {
                if !is_semver_range(max) {
                    return Err(Error::ConfigError(
                        "plugin manifest.clawdstrike.max_version must be semver or wildcard range (e.g. 1.x)"
                            .to_string(),
                    ));
                }
            }
        }

        let mut names = HashSet::new();
        for (idx, guard) in self.guards.iter().enumerate() {
            if guard.name.trim().is_empty() {
                return Err(Error::ConfigError(format!(
                    "plugin manifest.guards[{idx}].name must be a non-empty string"
                )));
            }
            if !names.insert(guard.name.clone()) {
                return Err(Error::ConfigError(format!(
                    "plugin manifest.guards[{idx}].name duplicates guard: {}",
                    guard.name
                )));
            }
            if let Some(entrypoint) = &guard.entrypoint {
                if entrypoint.trim().is_empty() {
                    return Err(Error::ConfigError(format!(
                        "plugin manifest.guards[{idx}].entrypoint must be a non-empty string when provided"
                    )));
                }
            }
        }

        if self.trust.level == PluginTrustLevel::Untrusted {
            if self.capabilities.subprocess {
                return Err(Error::ConfigError(format!(
                    "untrusted plugin {} cannot request subprocess capability",
                    self.plugin.name
                )));
            }
            if self.capabilities.filesystem.write {
                return Err(Error::ConfigError(format!(
                    "untrusted plugin {} cannot request filesystem write capability",
                    self.plugin.name
                )));
            }
            if self.capabilities.secrets.access {
                return Err(Error::ConfigError(format!(
                    "untrusted plugin {} cannot request secrets access capability",
                    self.plugin.name
                )));
            }
        }

        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PluginMetadata {
    pub version: String,
    pub name: String,
    #[serde(default)]
    pub display_name: Option<String>,
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default)]
    pub author: Option<String>,
    #[serde(default)]
    pub license: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PluginClawdstrikeCompatibility {
    #[serde(default)]
    pub min_version: Option<String>,
    #[serde(default)]
    pub max_version: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PluginGuardManifestEntry {
    pub name: String,
    #[serde(default)]
    pub display_name: Option<String>,
    #[serde(default)]
    pub entrypoint: Option<String>,
    #[serde(default)]
    pub handles: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PluginCapabilities {
    #[serde(default)]
    pub network: bool,
    #[serde(default)]
    pub subprocess: bool,
    #[serde(default)]
    pub filesystem: PluginFilesystemCapabilities,
    #[serde(default)]
    pub secrets: PluginSecretsCapabilities,
}

impl Default for PluginCapabilities {
    fn default() -> Self {
        Self {
            network: false,
            subprocess: false,
            filesystem: PluginFilesystemCapabilities::default(),
            secrets: PluginSecretsCapabilities::default(),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PluginFilesystemCapabilities {
    #[serde(default)]
    pub read: Vec<String>,
    #[serde(default)]
    pub write: bool,
}

impl Default for PluginFilesystemCapabilities {
    fn default() -> Self {
        Self {
            read: Vec::new(),
            write: false,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct PluginSecretsCapabilities {
    #[serde(default)]
    pub access: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum PluginTrustLevel {
    Trusted,
    Untrusted,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum PluginSandbox {
    Native,
    Wasm,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PluginTrust {
    pub level: PluginTrustLevel,
    pub sandbox: PluginSandbox,
}

impl Default for PluginTrust {
    fn default() -> Self {
        Self {
            level: PluginTrustLevel::Untrusted,
            sandbox: PluginSandbox::Wasm,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PluginResourceLimits {
    #[serde(default = "default_max_memory_mb")]
    pub max_memory_mb: u32,
    #[serde(default = "default_max_cpu_ms")]
    pub max_cpu_ms: u32,
    #[serde(default = "default_max_timeout_ms")]
    pub max_timeout_ms: u32,
}

impl Default for PluginResourceLimits {
    fn default() -> Self {
        Self {
            max_memory_mb: default_max_memory_mb(),
            max_cpu_ms: default_max_cpu_ms(),
            max_timeout_ms: default_max_timeout_ms(),
        }
    }
}

const fn default_max_memory_mb() -> u32 {
    64
}

const fn default_max_cpu_ms() -> u32 {
    100
}

const fn default_max_timeout_ms() -> u32 {
    5000
}

pub fn parse_plugin_manifest_toml(content: &str) -> Result<PluginManifest> {
    let manifest: PluginManifest = toml::from_str(content)
        .map_err(|e| Error::ConfigError(format!("failed to parse plugin manifest TOML: {e}")))?;
    manifest.validate()?;
    Ok(manifest)
}

fn is_strict_semver(value: &str) -> bool {
    parse_semver(value).is_some()
}

fn is_semver_range(value: &str) -> bool {
    parse_semver(value).is_some()
        || parse_major_wildcard(value).is_some()
        || parse_minor_wildcard(value).is_some()
}

fn parse_semver(value: &str) -> Option<[u32; 3]> {
    let mut parts = value.split('.');
    let major = parts.next()?.parse::<u32>().ok()?;
    let minor = parts.next()?.parse::<u32>().ok()?;
    let patch = parts.next()?.parse::<u32>().ok()?;
    if parts.next().is_some() {
        return None;
    }
    Some([major, minor, patch])
}

fn parse_major_wildcard(value: &str) -> Option<u32> {
    let mut parts = value.split('.');
    let major = parts.next()?.parse::<u32>().ok()?;
    let mid = parts.next()?;
    if mid != "x" || parts.next().is_some() {
        return None;
    }
    Some(major)
}

fn parse_minor_wildcard(value: &str) -> Option<(u32, u32)> {
    let mut parts = value.split('.');
    let major = parts.next()?.parse::<u32>().ok()?;
    let minor = parts.next()?.parse::<u32>().ok()?;
    let patch = parts.next()?;
    if patch != "x" || parts.next().is_some() {
        return None;
    }
    Some((major, minor))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_minimal_manifest_and_defaults() {
        let raw = r#"
[plugin]
version = "1.0.0"
name = "acme-guard"

[[guards]]
name = "acme.deny"

[trust]
level = "trusted"
sandbox = "native"
"#;

        let manifest = parse_plugin_manifest_toml(raw).expect("manifest parsed");
        assert_eq!(manifest.plugin.name, "acme-guard");
        assert_eq!(manifest.resources.max_memory_mb, 64);
        assert!(!manifest.capabilities.network);
        assert!(!manifest.capabilities.filesystem.write);
    }

    #[test]
    fn rejects_duplicate_guard_names() {
        let raw = r#"
[plugin]
version = "1.0.0"
name = "acme-guard"

[[guards]]
name = "acme.deny"

[[guards]]
name = "acme.deny"

[trust]
level = "trusted"
sandbox = "native"
"#;

        let err = parse_plugin_manifest_toml(raw).expect_err("duplicate should fail");
        assert!(err.to_string().contains("duplicates guard"));
    }

    #[test]
    fn rejects_untrusted_high_risk_caps() {
        let raw = r#"
[plugin]
version = "1.0.0"
name = "acme-untrusted"

[[guards]]
name = "acme.guard"

[capabilities]
subprocess = true

[trust]
level = "untrusted"
sandbox = "wasm"
"#;

        let err = parse_plugin_manifest_toml(raw).expect_err("should reject subprocess");
        assert!(err
            .to_string()
            .contains("cannot request subprocess capability"));
    }
}
