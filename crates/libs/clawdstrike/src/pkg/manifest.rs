//! Package manifest (`clawdstrike-pkg.toml`) parsing and validation.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use super::version::VersionReq;
use crate::error::{Error, Result};
use crate::plugins::{
    PluginCapabilities, PluginClawdstrikeCompatibility, PluginResourceLimits, PluginTrust,
};
use crate::semver_utils::is_strict_semver;

/// Package type discriminator.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum PkgType {
    Guard,
    PolicyPack,
    Adapter,
    Engine,
    Template,
    Bundle,
}

impl std::fmt::Display for PkgType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PkgType::Guard => write!(f, "guard"),
            PkgType::PolicyPack => write!(f, "policy-pack"),
            PkgType::Adapter => write!(f, "adapter"),
            PkgType::Engine => write!(f, "engine"),
            PkgType::Template => write!(f, "template"),
            PkgType::Bundle => write!(f, "bundle"),
        }
    }
}

/// Top-level package manifest (`clawdstrike-pkg.toml`).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PkgManifest {
    pub package: PackageSection,
    #[serde(default)]
    pub clawdstrike: Option<PluginClawdstrikeCompatibility>,
    #[serde(default)]
    pub capabilities: PluginCapabilities,
    #[serde(default)]
    pub resources: PluginResourceLimits,
    #[serde(default)]
    pub trust: PluginTrust,
    #[serde(default)]
    pub dependencies: BTreeMap<String, String>,
    #[serde(default)]
    pub build: Option<BuildConfig>,
}

/// The `[package]` section of a manifest.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PackageSection {
    pub name: String,
    pub version: String,
    pub pkg_type: PkgType,
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default)]
    pub authors: Vec<String>,
    #[serde(default)]
    pub license: Option<String>,
    #[serde(default)]
    pub repository: Option<String>,
    #[serde(default)]
    pub keywords: Vec<String>,
    #[serde(default)]
    pub readme: Option<String>,
}

/// Optional `[build]` section.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BuildConfig {
    #[serde(default)]
    pub target: Option<String>,
    #[serde(default)]
    pub profile: Option<String>,
}

// ---------------------------------------------------------------------------
// Validation
// ---------------------------------------------------------------------------

/// Regex for unscoped package names: `^[a-z0-9]([a-z0-9._-]*[a-z0-9])?$`
fn is_valid_unscoped_name(name: &str) -> bool {
    if name.is_empty() {
        return false;
    }
    let bytes = name.as_bytes();
    if !bytes[0].is_ascii_lowercase() && !bytes[0].is_ascii_digit() {
        return false;
    }
    if bytes.len() > 1 {
        let last = bytes[bytes.len() - 1];
        if !last.is_ascii_lowercase() && !last.is_ascii_digit() {
            return false;
        }
    }
    bytes.iter().all(|&b| {
        b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'.' || b == b'_' || b == b'-'
    })
}

/// Regex for scope names: `^[a-z0-9]([a-z0-9-]*[a-z0-9])?$`
fn is_valid_scope_name(scope: &str) -> bool {
    if scope.is_empty() {
        return false;
    }
    let bytes = scope.as_bytes();
    if !bytes[0].is_ascii_lowercase() && !bytes[0].is_ascii_digit() {
        return false;
    }
    if bytes.len() > 1 {
        let last = bytes[bytes.len() - 1];
        if !last.is_ascii_lowercase() && !last.is_ascii_digit() {
            return false;
        }
    }
    bytes
        .iter()
        .all(|&b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
}

/// Validate package name: unscoped or `@scope/name`.
pub(crate) fn is_valid_pkg_name(name: &str) -> bool {
    if let Some(rest) = name.strip_prefix('@') {
        // scoped: @scope/name
        let mut parts = rest.splitn(2, '/');
        let scope = match parts.next() {
            Some(s) if !s.is_empty() => s,
            _ => return false,
        };
        let pkg = match parts.next() {
            Some(s) if !s.is_empty() => s,
            _ => return false,
        };
        // scope must match [a-z0-9]([a-z0-9-]*[a-z0-9])?
        let scope_valid = is_valid_scope_name(scope);
        scope_valid && is_valid_unscoped_name(pkg)
    } else {
        is_valid_unscoped_name(name)
    }
}

impl PkgManifest {
    /// Validate the manifest, returning an error on the first problem found.
    pub fn validate(&self) -> Result<()> {
        // Name format
        if !is_valid_pkg_name(&self.package.name) {
            return Err(Error::PkgError(format!(
                "invalid package name '{}': must match [a-z0-9][a-z0-9._-]*[a-z0-9] or @scope/name",
                self.package.name
            )));
        }

        // Semver
        if !is_strict_semver(&self.package.version) {
            return Err(Error::PkgError(format!(
                "invalid package version '{}': must be strict semver (x.y.z)",
                self.package.version
            )));
        }

        // clawdstrike compatibility min_version must be semver if present
        if let Some(compat) = &self.clawdstrike {
            if let Some(min) = &compat.min_version {
                if !is_strict_semver(min) {
                    return Err(Error::PkgError(format!(
                        "clawdstrike.min_version '{}' must be strict semver (x.y.z)",
                        min
                    )));
                }
            }

            if let Some(max) = &compat.max_version {
                if !is_strict_semver(max) {
                    return Err(Error::PkgError(format!(
                        "clawdstrike.max_version '{}' must be strict semver (x.y.z)",
                        max
                    )));
                }
            }
        }

        if self.resources.max_memory_mb < 1
            || self.resources.max_cpu_ms < 1
            || self.resources.max_timeout_ms < 1
        {
            return Err(Error::PkgError(
                "package manifest.resources values must be positive integers".to_string(),
            ));
        }

        // Dependency version constraints must be non-empty and parseable semver requirements.
        for (dep_name, constraint) in &self.dependencies {
            let trimmed = constraint.trim();
            if trimmed.is_empty() {
                return Err(Error::PkgError(format!(
                    "dependency '{}' has empty version constraint",
                    dep_name
                )));
            }
            VersionReq::parse(trimmed).map_err(|e| {
                Error::PkgError(format!(
                    "dependency '{}' has invalid version constraint '{}': {}",
                    dep_name, constraint, e
                ))
            })?;
        }

        Ok(())
    }
}

/// Parse and validate a `clawdstrike-pkg.toml` string.
pub fn parse_pkg_manifest_toml(content: &str) -> Result<PkgManifest> {
    let manifest: PkgManifest = toml::from_str(content)?;
    manifest.validate()?;
    Ok(manifest)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn minimal_toml(name: &str, version: &str, pkg_type: &str) -> String {
        format!(
            r#"
[package]
name = "{name}"
version = "{version}"
pkg_type = "{pkg_type}"

[trust]
level = "trusted"
sandbox = "native"
"#
        )
    }

    #[test]
    fn parses_minimal_manifest() {
        let raw = minimal_toml("my-guard", "1.0.0", "guard");
        let m = parse_pkg_manifest_toml(&raw).unwrap();
        assert_eq!(m.package.name, "my-guard");
        assert_eq!(m.package.version, "1.0.0");
        assert_eq!(m.package.pkg_type, PkgType::Guard);
        assert!(m.dependencies.is_empty());
    }

    #[test]
    fn parses_scoped_name() {
        let raw = minimal_toml("@acme/firewall", "0.2.1", "policy-pack");
        let m = parse_pkg_manifest_toml(&raw).unwrap();
        assert_eq!(m.package.name, "@acme/firewall");
        assert_eq!(m.package.pkg_type, PkgType::PolicyPack);
    }

    #[test]
    fn parses_all_pkg_types() {
        for ty in &[
            "guard",
            "policy-pack",
            "adapter",
            "engine",
            "template",
            "bundle",
        ] {
            let raw = minimal_toml("test-pkg", "1.0.0", ty);
            let m = parse_pkg_manifest_toml(&raw).unwrap();
            assert_eq!(m.package.pkg_type.to_string(), *ty);
        }
    }

    #[test]
    fn parses_full_manifest() {
        let raw = r#"
[package]
name = "@acme/my-guard"
version = "2.3.4"
pkg_type = "guard"
description = "A cool guard"
authors = ["Alice <alice@example.com>"]
license = "MIT"
repository = "https://github.com/acme/my-guard"
keywords = ["security", "guard"]
readme = "README.md"

[clawdstrike]
min_version = "0.1.0"

[capabilities]
network = true

[resources]
max_memory_mb = 128
max_cpu_ms = 200
max_timeout_ms = 10000

[trust]
level = "trusted"
sandbox = "native"

[dependencies]
"@acme/base" = "^1.0"
"other-pkg" = ">=2.0.0"

[build]
target = "wasm32-unknown-unknown"
profile = "release"
"#;
        let m = parse_pkg_manifest_toml(raw).unwrap();
        assert_eq!(m.package.description.as_deref(), Some("A cool guard"));
        assert_eq!(m.package.authors.len(), 1);
        assert_eq!(m.dependencies.len(), 2);
        assert!(m.capabilities.network);
        assert_eq!(m.resources.max_memory_mb, 128);
        assert!(m.build.is_some());
    }

    #[test]
    fn rejects_invalid_name_uppercase() {
        let raw = minimal_toml("MyGuard", "1.0.0", "guard");
        let err = parse_pkg_manifest_toml(&raw).unwrap_err();
        assert!(err.to_string().contains("invalid package name"));
    }

    #[test]
    fn rejects_invalid_name_trailing_dash() {
        let raw = minimal_toml("my-guard-", "1.0.0", "guard");
        let err = parse_pkg_manifest_toml(&raw).unwrap_err();
        assert!(err.to_string().contains("invalid package name"));
    }

    #[test]
    fn rejects_empty_name() {
        let raw = minimal_toml("", "1.0.0", "guard");
        let err = parse_pkg_manifest_toml(&raw).unwrap_err();
        assert!(err.to_string().contains("invalid package name"));
    }

    #[test]
    fn rejects_invalid_semver() {
        let raw = minimal_toml("ok-name", "1.0", "guard");
        let err = parse_pkg_manifest_toml(&raw).unwrap_err();
        assert!(err.to_string().contains("invalid package version"));
    }

    #[test]
    fn rejects_semver_with_leading_zeros() {
        let raw = minimal_toml("ok-name", "01.0.0", "guard");
        let err = parse_pkg_manifest_toml(&raw).unwrap_err();
        assert!(err.to_string().contains("invalid package version"));
    }

    #[test]
    fn rejects_empty_dep_constraint() {
        let raw = r#"
[package]
name = "my-pkg"
version = "1.0.0"
pkg_type = "guard"

[trust]
level = "trusted"
sandbox = "native"

[dependencies]
"bad-dep" = ""
"#;
        let err = parse_pkg_manifest_toml(raw).unwrap_err();
        assert!(err.to_string().contains("empty version constraint"));
    }

    #[test]
    fn rejects_invalid_dep_constraint() {
        let raw = r#"
[package]
name = "my-pkg"
version = "1.0.0"
pkg_type = "guard"

[trust]
level = "trusted"
sandbox = "native"

[dependencies]
"bad-dep" = "not-a-version"
"#;
        let err = parse_pkg_manifest_toml(raw).unwrap_err();
        assert!(err
            .to_string()
            .contains("dependency 'bad-dep' has invalid version constraint"));
    }

    #[test]
    fn rejects_invalid_clawdstrike_min_version() {
        let raw = r#"
[package]
name = "my-pkg"
version = "1.0.0"
pkg_type = "guard"

[clawdstrike]
min_version = "abc"

[trust]
level = "trusted"
sandbox = "native"
"#;
        let err = parse_pkg_manifest_toml(raw).unwrap_err();
        assert!(err.to_string().contains("min_version"));
    }

    #[test]
    fn rejects_invalid_clawdstrike_max_version() {
        let raw = r#"
[package]
name = "my-pkg"
version = "1.0.0"
pkg_type = "guard"

[clawdstrike]
max_version = "abc"

[trust]
level = "trusted"
sandbox = "native"
"#;
        let err = parse_pkg_manifest_toml(raw).unwrap_err();
        assert!(err.to_string().contains("max_version"));
    }

    #[test]
    fn rejects_non_positive_resource_limits() {
        let raw = r#"
[package]
name = "my-pkg"
version = "1.0.0"
pkg_type = "guard"

[resources]
max_memory_mb = 0
max_cpu_ms = 200
max_timeout_ms = 10000

[trust]
level = "trusted"
sandbox = "native"
"#;
        let err = parse_pkg_manifest_toml(raw).unwrap_err();
        assert!(err.to_string().contains("resources"));
    }

    #[test]
    fn name_validation_edge_cases() {
        // single char
        assert!(is_valid_pkg_name("a"));
        // two chars
        assert!(is_valid_pkg_name("ab"));
        // digits
        assert!(is_valid_pkg_name("1pkg2"));
        // dots and underscores
        assert!(is_valid_pkg_name("my.pkg_name"));
        // scoped single char name
        assert!(is_valid_pkg_name("@s/a"));
        // bad scope with slash only
        assert!(!is_valid_pkg_name("@/name"));
        // no name after scope
        assert!(!is_valid_pkg_name("@scope/"));
        // no @ prefix but has slash
        assert!(!is_valid_pkg_name("scope/name"));
        // scoped: scope cannot start/end with '-'
        assert!(!is_valid_pkg_name("@-scope/name"));
        assert!(!is_valid_pkg_name("@scope-/name"));
        assert!(!is_valid_pkg_name("@--/name"));
        // scoped valid boundaries
        assert!(is_valid_pkg_name("@scope-1/name"));
    }
}
