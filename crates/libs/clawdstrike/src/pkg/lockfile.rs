//! Package lockfile (`clawdstrike-pkg.lock`) for reproducible installs.

use serde::{Deserialize, Serialize};

use super::manifest::PkgType;
use crate::error::Result;

/// The lockfile schema.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Lockfile {
    /// Schema version (always 1).
    pub version: u32,
    /// Locked packages, sorted by name for determinism.
    #[serde(default)]
    pub packages: Vec<LockedPackage>,
}

/// A locked package entry.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LockedPackage {
    pub name: String,
    pub version: String,
    pub pkg_type: PkgType,
    /// Content hash in the form `sha256:<hex>`.
    pub checksum: String,
    /// Source descriptor, e.g. `"local"` or `"registry+https://..."`.
    pub source: String,
    #[serde(default)]
    pub dependencies: Vec<LockedDependency>,
}

/// A locked dependency reference.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LockedDependency {
    pub name: String,
    pub version: String,
}

impl Lockfile {
    /// Create an empty lockfile.
    pub fn new() -> Self {
        Self {
            version: 1,
            packages: Vec::new(),
        }
    }

    /// Add a locked package entry. The package list is kept sorted by name.
    pub fn add(&mut self, pkg: LockedPackage) {
        // Remove any existing entry with the same name.
        self.packages.retain(|p| p.name != pkg.name);
        self.packages.push(pkg);
        self.packages.sort_by(|a, b| a.name.cmp(&b.name));
    }

    /// Serialize to deterministic TOML.
    pub fn to_toml(&self) -> Result<String> {
        let s = toml::to_string_pretty(self)?;
        Ok(s)
    }

    /// Deserialize from TOML.
    pub fn from_toml(content: &str) -> Result<Self> {
        let lf: Lockfile = toml::from_str(content)?;
        Ok(lf)
    }
}

impl Default for Lockfile {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_pkg(name: &str) -> LockedPackage {
        LockedPackage {
            name: name.to_string(),
            version: "1.0.0".to_string(),
            pkg_type: PkgType::Guard,
            checksum: "sha256:abcdef1234567890".to_string(),
            source: "local".to_string(),
            dependencies: vec![],
        }
    }

    #[test]
    fn empty_lockfile_roundtrip() {
        let lf = Lockfile::new();
        let toml = lf.to_toml().unwrap();
        let parsed = Lockfile::from_toml(&toml).unwrap();
        assert_eq!(parsed.version, 1);
        assert!(parsed.packages.is_empty());
    }

    #[test]
    fn add_keeps_sorted() {
        let mut lf = Lockfile::new();
        lf.add(sample_pkg("zeta"));
        lf.add(sample_pkg("alpha"));
        lf.add(sample_pkg("mu"));

        assert_eq!(lf.packages[0].name, "alpha");
        assert_eq!(lf.packages[1].name, "mu");
        assert_eq!(lf.packages[2].name, "zeta");
    }

    #[test]
    fn add_replaces_existing() {
        let mut lf = Lockfile::new();
        lf.add(sample_pkg("my-pkg"));
        let mut updated = sample_pkg("my-pkg");
        updated.version = "2.0.0".to_string();
        lf.add(updated);

        assert_eq!(lf.packages.len(), 1);
        assert_eq!(lf.packages[0].version, "2.0.0");
    }

    #[test]
    fn roundtrip_with_dependencies() {
        let mut lf = Lockfile::new();
        lf.add(LockedPackage {
            name: "my-guard".to_string(),
            version: "1.0.0".to_string(),
            pkg_type: PkgType::Guard,
            checksum: "sha256:aabbccdd".to_string(),
            source: "registry+https://pkg.clawdstrike.dev".to_string(),
            dependencies: vec![LockedDependency {
                name: "base-guard".to_string(),
                version: "0.5.0".to_string(),
            }],
        });

        let toml = lf.to_toml().unwrap();
        let parsed = Lockfile::from_toml(&toml).unwrap();

        assert_eq!(parsed.packages.len(), 1);
        let pkg = &parsed.packages[0];
        assert_eq!(pkg.name, "my-guard");
        assert_eq!(pkg.dependencies.len(), 1);
        assert_eq!(pkg.dependencies[0].name, "base-guard");
    }

    #[test]
    fn toml_is_deterministic() {
        let mut lf = Lockfile::new();
        lf.add(sample_pkg("beta"));
        lf.add(sample_pkg("alpha"));

        let toml1 = lf.to_toml().unwrap();
        let toml2 = lf.to_toml().unwrap();
        assert_eq!(toml1, toml2);
    }
}
