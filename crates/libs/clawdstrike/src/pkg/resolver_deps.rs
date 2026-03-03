//! PubGrub-based dependency resolver for `.cpkg` packages.
//!
//! Implements the `DependencyProvider` trait to integrate with the pubgrub
//! SAT-based version solver, providing clear conflict error messages.

use std::collections::BTreeMap;
use std::fmt;

use pubgrub::{
    DefaultStringReporter, Dependencies, DependencyProvider, Map, PackageResolutionStatistics,
    PubGrubError, Ranges, Reporter,
};

use super::encode_url_path_segment;
use super::index::{IndexVersion, PackageIndexEntry};
use super::lockfile::{LockedDependency, LockedPackage, Lockfile};
use super::manifest::PkgType;
use super::version::VersionReq;
use crate::error::{Error, Result};

// ---------------------------------------------------------------------------
// Package / Version wrappers
// ---------------------------------------------------------------------------

/// Package identifier used by the resolver.
///
/// We distinguish the synthetic "root" package (the project being resolved)
/// from real registry/local packages.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub enum PkgId {
    /// The synthetic root package representing the project itself.
    Root,
    /// A named package from the registry or local source.
    Named(String),
}

impl fmt::Display for PkgId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PkgId::Root => write!(f, "<root>"),
            PkgId::Named(n) => write!(f, "{}", n),
        }
    }
}

/// A resolved package in the final resolution plan.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ResolvedPackage {
    pub name: String,
    pub version: semver::Version,
    pub checksum: String,
    pub pkg_type: PkgType,
    pub dependencies: BTreeMap<String, String>,
    pub download_url: Option<String>,
}

// ---------------------------------------------------------------------------
// DependencyProvider implementation
// ---------------------------------------------------------------------------

/// Resolver error type for pubgrub's `Err` associated type.
#[derive(Debug, Clone, thiserror::Error)]
pub enum ResolverError {
    #[error("{0}")]
    PackageNotFound(String),
    #[error("{0}")]
    VersionParse(String),
    #[error("{0}")]
    ConstraintParse(String),
}

/// Unavailable reason marker (pubgrub's M type).
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct Unavailable(String);

impl fmt::Display for Unavailable {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// The dependency provider that bridges the package index to pubgrub.
pub struct DependencyResolver {
    /// Index data — all package versions we know about.
    index: BTreeMap<String, PackageIndexEntry>,
    /// Versions to exclude because they are yanked (unless locked).
    locked_versions: BTreeMap<String, semver::Version>,
    /// Registry base URL for generating download URLs.
    registry_url: String,
}

impl DependencyResolver {
    /// Create a new resolver with pre-loaded index data.
    pub fn new(entries: Vec<PackageIndexEntry>, locked: &Lockfile, registry_url: &str) -> Self {
        let index: BTreeMap<String, PackageIndexEntry> =
            entries.into_iter().map(|e| (e.name.clone(), e)).collect();

        let locked_versions: BTreeMap<String, semver::Version> = locked
            .packages
            .iter()
            .filter_map(|lp| {
                semver::Version::parse(&lp.version)
                    .ok()
                    .map(|v| (lp.name.clone(), v))
            })
            .collect();

        Self {
            index,
            locked_versions,
            registry_url: registry_url.to_string(),
        }
    }

    /// Add a package index entry (for incremental construction / testing).
    pub fn add_entry(&mut self, entry: PackageIndexEntry) {
        self.index.insert(entry.name.clone(), entry);
    }

    /// Pin a locked version (yanked versions matching this pin are still allowed).
    pub fn pin_locked(&mut self, name: &str, version: semver::Version) {
        self.locked_versions.insert(name.to_string(), version);
    }

    /// Get available (non-yanked, unless locked) versions for a package, sorted ascending.
    fn available_versions(&self, name: &str) -> Vec<(&IndexVersion, semver::Version)> {
        let entry = match self.index.get(name) {
            Some(e) => e,
            None => return Vec::new(),
        };

        let locked = self.locked_versions.get(name);

        let mut versions: Vec<(&IndexVersion, semver::Version)> = entry
            .versions
            .iter()
            .filter_map(|iv| {
                let sv = semver::Version::parse(&iv.version).ok()?;
                // Exclude yanked versions unless they are the locked version.
                if iv.yanked && locked != Some(&sv) {
                    return None;
                }
                Some((iv, sv))
            })
            .collect();

        versions.sort_by(|a, b| a.1.cmp(&b.1));
        versions
    }

    /// Resolve dependencies starting from a set of root requirements.
    ///
    /// Returns the resolved packages (excluding the synthetic root) on success,
    /// or a human-readable error on failure.
    pub fn resolve(
        &self,
        root_deps: &BTreeMap<String, VersionReq>,
    ) -> Result<Vec<ResolvedPackage>> {
        // Feed root deps into pubgrub by resolving from the Root package
        // at version 0.0.0.
        let root_version = semver::Version::new(0, 0, 0);

        let provider = PubGrubProvider {
            resolver: self,
            root_deps,
        };

        let solution =
            pubgrub::resolve(&provider, PkgId::Root, root_version).map_err(|err| match err {
                PubGrubError::NoSolution(derivation_tree) => {
                    let report = DefaultStringReporter::report(&derivation_tree);
                    Error::PkgError(format!("dependency resolution failed:\n{}", report))
                }
                PubGrubError::ErrorRetrievingDependencies {
                    package,
                    version,
                    source,
                } => Error::PkgError(format!(
                    "error retrieving dependencies for {}@{}: {}",
                    package, version, source
                )),
                PubGrubError::ErrorChoosingVersion { package, source } => Error::PkgError(format!(
                    "error choosing version for {}: {}",
                    package, source
                )),
                PubGrubError::ErrorInShouldCancel(e) => {
                    Error::PkgError(format!("resolution cancelled: {}", e))
                }
            })?;

        // Convert solution to resolved packages (skip Root).
        let mut resolved: Vec<ResolvedPackage> = Vec::new();
        for (pkg_id, version) in &solution {
            let name = match pkg_id {
                PkgId::Root => continue,
                PkgId::Named(n) => n,
            };

            // Find the matching IndexVersion to get checksum and deps.
            let (iv, download_url) = self.find_index_version(name, version).ok_or_else(|| {
                Error::PkgError(format!(
                    "resolved {}@{} not found in index (internal error)",
                    name, version
                ))
            })?;

            resolved.push(ResolvedPackage {
                name: name.clone(),
                version: version.clone(),
                checksum: iv.checksum.clone(),
                pkg_type: iv.pkg_type,
                dependencies: iv.dependencies.clone(),
                download_url: Some(download_url),
            });
        }

        // Sort by name for determinism.
        resolved.sort_by(|a, b| a.name.cmp(&b.name));
        Ok(resolved)
    }

    fn find_index_version(
        &self,
        name: &str,
        version: &semver::Version,
    ) -> Option<(&IndexVersion, String)> {
        let entry = self.index.get(name)?;
        for iv in &entry.versions {
            if let Ok(sv) = semver::Version::parse(&iv.version) {
                if &sv == version {
                    // URL-encode the package name so scoped names like
                    // `@acme/firewall` don't produce broken URL segments.
                    let encoded_name = encode_url_path_segment(name);
                    let url = format!(
                        "{}/api/v1/packages/{}/{}/download",
                        self.registry_url, encoded_name, iv.version
                    );
                    return Some((iv, url));
                }
            }
        }
        None
    }
}

// ---------------------------------------------------------------------------
// PubGrub DependencyProvider
// ---------------------------------------------------------------------------

struct PubGrubProvider<'a> {
    resolver: &'a DependencyResolver,
    root_deps: &'a BTreeMap<String, VersionReq>,
}

type VS = Ranges<semver::Version>;

impl<'a> DependencyProvider for PubGrubProvider<'a> {
    type P = PkgId;
    type V = semver::Version;
    type VS = VS;
    type Priority = u32;
    type M = Unavailable;
    type Err = ResolverError;

    fn prioritize(
        &self,
        package: &PkgId,
        _range: &VS,
        _stats: &PackageResolutionStatistics,
    ) -> u32 {
        // Higher priority = resolved first. Root always first.
        match package {
            PkgId::Root => u32::MAX,
            PkgId::Named(name) => {
                // Prioritize packages with fewer available versions (more constrained).
                let count = self.resolver.available_versions(name).len();
                // Invert: fewer versions = higher priority.
                u32::MAX.saturating_sub(count as u32).saturating_sub(1)
            }
        }
    }

    fn choose_version(
        &self,
        package: &PkgId,
        range: &VS,
    ) -> std::result::Result<Option<semver::Version>, ResolverError> {
        match package {
            PkgId::Root => Ok(Some(semver::Version::new(0, 0, 0))),
            PkgId::Named(name) => {
                let versions = self.resolver.available_versions(name);
                // Choose the highest compatible version (reverse iterate).
                let chosen = versions
                    .iter()
                    .rev()
                    .find(|(_, sv)| range.contains(sv))
                    .map(|(_, sv)| sv.clone());
                Ok(chosen)
            }
        }
    }

    fn get_dependencies(
        &self,
        package: &PkgId,
        version: &semver::Version,
    ) -> std::result::Result<Dependencies<PkgId, VS, Unavailable>, ResolverError> {
        match package {
            PkgId::Root => {
                let mut deps: Map<PkgId, VS> = Map::default();
                for (name, req) in self.root_deps {
                    let range = version_req_to_range(req)?;
                    deps.insert(PkgId::Named(name.clone()), range);
                }
                Ok(Dependencies::Available(deps))
            }
            PkgId::Named(name) => {
                let entry = self.resolver.index.get(name.as_str());
                let entry = match entry {
                    Some(e) => e,
                    None => {
                        return Ok(Dependencies::Unavailable(Unavailable(format!(
                            "package '{}' not found in registry",
                            name
                        ))));
                    }
                };

                // Find the exact version.
                let iv = entry.versions.iter().find(|iv| {
                    semver::Version::parse(&iv.version)
                        .map(|sv| &sv == version)
                        .unwrap_or(false)
                });

                let iv = match iv {
                    Some(v) => v,
                    None => {
                        return Ok(Dependencies::Unavailable(Unavailable(format!(
                            "version {} of '{}' not found",
                            version, name
                        ))));
                    }
                };

                let mut deps: Map<PkgId, VS> = Map::default();
                for (dep_name, constraint_str) in &iv.dependencies {
                    let req = VersionReq::parse(constraint_str).map_err(|e| {
                        ResolverError::ConstraintParse(format!(
                            "invalid constraint '{}' for dependency '{}' of '{}@{}': {}",
                            constraint_str, dep_name, name, version, e
                        ))
                    })?;
                    let range = version_req_to_range(&req)?;
                    deps.insert(PkgId::Named(dep_name.clone()), range);
                }

                Ok(Dependencies::Available(deps))
            }
        }
    }
}

/// Convert a `VersionReq` to a pubgrub `Ranges<semver::Version>`.
///
/// We use the semver crate's comparators to build precise ranges.
fn version_req_to_range(req: &VersionReq) -> std::result::Result<VS, ResolverError> {
    // Defensively preserve the semantics of bare `*` even if upstream parser
    // behavior changes in future semver releases.
    if req.to_string() == "*" {
        return Ok(Ranges::full());
    }

    let semver_req = req.inner();

    // If there are no comparators, it matches everything.
    if semver_req.comparators.is_empty() {
        return Ok(Ranges::full());
    }

    // Each comparator represents one constraint; they are ANDed together.
    let mut combined = Ranges::full();
    for comp in &semver_req.comparators {
        let range = comparator_to_range(comp)?;
        combined = combined.intersection(&range);
    }

    Ok(combined)
}

fn comparator_to_range(comp: &semver::Comparator) -> std::result::Result<VS, ResolverError> {
    let major = comp.major;
    let minor = comp.minor;
    let patch = comp.patch;
    let pre = &comp.pre;

    match comp.op {
        semver::Op::Exact => {
            // =I.J.K → singleton [I.J.K, I.J.K]
            // =I.J   → [I.J.0, I.(J+1).0)
            // =I     → [I.0.0, (I+1).0.0)
            match (minor, patch) {
                (Some(_), Some(_)) => {
                    let v = make_version(major, minor, patch, pre);
                    Ok(Ranges::singleton(v))
                }
                (Some(min_val), None) => {
                    if !pre.is_empty() {
                        return Err(ResolverError::ConstraintParse(format!(
                            "invalid prerelease comparator '{}': prerelease requires explicit patch",
                            comp
                        )));
                    }
                    let lo = semver::Version::new(major, min_val, 0);
                    let hi =
                        semver::Version::new(major, checked_increment(min_val, "minor", comp)?, 0);
                    Ok(Ranges::between(lo, hi))
                }
                _ => {
                    if !pre.is_empty() {
                        return Err(ResolverError::ConstraintParse(format!(
                            "invalid prerelease comparator '{}': prerelease requires explicit minor/patch",
                            comp
                        )));
                    }
                    let lo = semver::Version::new(major, 0, 0);
                    let hi = semver::Version::new(checked_increment(major, "major", comp)?, 0, 0);
                    Ok(Ranges::between(lo, hi))
                }
            }
        }
        semver::Op::Greater => {
            // >I.J.K → strictly_higher_than(I.J.K)
            // >I.J   → higher_than(I.(J+1).0)  (greater than all I.J.*)
            // >I     → higher_than((I+1).0.0)   (greater than all I.*.*)
            match (minor, patch) {
                (Some(_), Some(_)) => Ok(Ranges::strictly_higher_than(make_version(
                    major, minor, patch, pre,
                ))),
                (Some(min_val), None) => Ok(Ranges::higher_than(semver::Version::new(
                    major,
                    checked_increment(min_val, "minor", comp)?,
                    0,
                ))),
                _ => Ok(Ranges::higher_than(semver::Version::new(
                    checked_increment(major, "major", comp)?,
                    0,
                    0,
                ))),
            }
        }
        semver::Op::GreaterEq => {
            let v = make_version(major, minor, patch, pre);
            Ok(Ranges::higher_than(v))
        }
        semver::Op::Less => {
            let v = make_version(major, minor, patch, pre);
            Ok(Ranges::strictly_lower_than(v))
        }
        semver::Op::LessEq => {
            // <=I.J.K → (<I.J.K) OR (=I.J.K)
            // <=I.J   → strictly_lower_than(I.(J+1).0)
            // <=I     → strictly_lower_than((I+1).0.0)
            match (minor, patch) {
                (Some(_), Some(_)) => {
                    let v = make_version(major, minor, patch, pre);
                    Ok(Ranges::strictly_lower_than(v.clone()).union(&Ranges::singleton(v)))
                }
                (Some(min_val), None) => Ok(Ranges::strictly_lower_than(semver::Version::new(
                    major,
                    checked_increment(min_val, "minor", comp)?,
                    0,
                ))),
                _ => Ok(Ranges::strictly_lower_than(semver::Version::new(
                    checked_increment(major, "major", comp)?,
                    0,
                    0,
                ))),
            }
        }
        semver::Op::Tilde => {
            // ~I.J.K → [I.J.K, I.(J+1).0)
            // ~I.J   → [I.J.0, I.(J+1).0)
            // ~I     → [I.0.0, (I+1).0.0)
            let lo = make_version(major, minor, patch, pre);
            let hi = match minor {
                Some(min_val) => {
                    semver::Version::new(major, checked_increment(min_val, "minor", comp)?, 0)
                }
                None => semver::Version::new(checked_increment(major, "major", comp)?, 0, 0),
            };
            Ok(Ranges::between(lo, hi))
        }
        semver::Op::Caret => {
            // ^I.J.K → [I.J.K, next-breaking)
            // ^I.J   → [I.J.0, next-breaking)  (None patch ≠ Some(0))
            // ^I     → [I.0.0, (I+1).0.0)      (None minor ≠ Some(0))
            //
            // "next breaking" depends on the leftmost non-zero specified component:
            //   major > 0              → (major+1).0.0
            //   major == 0, minor specified:
            //     minor > 0            → 0.(minor+1).0
            //     minor == 0, patch specified:
            //       patch value        → 0.0.(patch+1)
            //     minor == 0, patch unspecified (^0.0) → 0.1.0
            //   major == 0, minor unspecified (^0) → 1.0.0
            let lo = make_version(major, minor, patch, pre);
            let hi = if major > 0 {
                semver::Version::new(checked_increment(major, "major", comp)?, 0, 0)
            } else {
                match minor {
                    None => {
                        // ^0 → [0.0.0, 1.0.0)
                        semver::Version::new(1, 0, 0)
                    }
                    Some(min_val) if min_val > 0 => {
                        semver::Version::new(0, checked_increment(min_val, "minor", comp)?, 0)
                    }
                    Some(_) => {
                        // minor == 0
                        match patch {
                            Some(pat_val) => semver::Version::new(
                                0,
                                0,
                                checked_increment(pat_val, "patch", comp)?,
                            ),
                            None => {
                                // ^0.0 → [0.0.0, 0.1.0)
                                semver::Version::new(0, 1, 0)
                            }
                        }
                    }
                }
            };
            Ok(Ranges::between(lo, hi))
        }
        semver::Op::Wildcard => {
            // X.Y.* or X.* (bare `*` handled above).
            if let Some(min_val) = minor {
                // X.Y.*: >=X.Y.0, <X.(Y+1).0
                let lo = semver::Version::new(major, min_val, 0);
                let hi = semver::Version::new(major, checked_increment(min_val, "minor", comp)?, 0);
                Ok(Ranges::between(lo, hi))
            } else {
                // X.* or *: >=X.0.0, <(X+1).0.0
                let lo = semver::Version::new(major, 0, 0);
                let hi = semver::Version::new(checked_increment(major, "major", comp)?, 0, 0);
                Ok(Ranges::between(lo, hi))
            }
        }
        _ => Err(ResolverError::ConstraintParse(format!(
            "unsupported semver operator: {:?}",
            comp.op
        ))),
    }
}

fn checked_increment(
    value: u64,
    component: &str,
    comp: &semver::Comparator,
) -> std::result::Result<u64, ResolverError> {
    value.checked_add(1).ok_or_else(|| {
        ResolverError::ConstraintParse(format!(
            "invalid constraint '{}': {} component overflow",
            comp, component
        ))
    })
}

/// Build a `semver::Version` from major/optional-minor/optional-patch.
fn make_version(
    major: u64,
    minor: Option<u64>,
    patch: Option<u64>,
    pre: &semver::Prerelease,
) -> semver::Version {
    let mut v = semver::Version::new(major, minor.unwrap_or(0), patch.unwrap_or(0));
    if !pre.is_empty() {
        v.pre = pre.clone();
    }
    v
}

// ---------------------------------------------------------------------------
// Lockfile generation from resolution
// ---------------------------------------------------------------------------

/// Generate a lockfile from a resolution plan.
pub fn lockfile_from_resolution(resolved: &[ResolvedPackage], registry_url: &str) -> Lockfile {
    let mut lockfile = Lockfile::new();
    for rp in resolved {
        let deps: Vec<LockedDependency> = rp
            .dependencies
            .iter()
            .filter_map(|(dep_name, _constraint)| {
                // Find the resolved version for this dependency.
                resolved
                    .iter()
                    .find(|r| r.name == *dep_name)
                    .map(|r| LockedDependency {
                        name: dep_name.clone(),
                        version: r.version.to_string(),
                    })
            })
            .collect();

        lockfile.add(LockedPackage {
            name: rp.name.clone(),
            version: rp.version.to_string(),
            pkg_type: rp.pkg_type,
            checksum: rp.checksum.clone(),
            source: format!("registry+{}", registry_url),
            dependencies: deps,
        });
    }
    lockfile
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    /// Helper: create a simple index entry with one version and no deps.
    fn simple_entry(name: &str, versions: &[&str]) -> PackageIndexEntry {
        PackageIndexEntry {
            name: name.to_string(),
            versions: versions
                .iter()
                .map(|v| IndexVersion {
                    version: v.to_string(),
                    checksum: format!("sha256:{}", v.replace('.', "")),
                    dependencies: BTreeMap::new(),
                    yanked: false,
                    pkg_type: PkgType::Guard,
                })
                .collect(),
        }
    }

    fn entry_with_deps(name: &str, version: &str, deps: &[(&str, &str)]) -> PackageIndexEntry {
        let dep_map: BTreeMap<String, String> = deps
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect();

        PackageIndexEntry {
            name: name.to_string(),
            versions: vec![IndexVersion {
                version: version.to_string(),
                checksum: format!("sha256:{}", version.replace('.', "")),
                dependencies: dep_map,
                yanked: false,
                pkg_type: PkgType::Guard,
            }],
        }
    }

    #[test]
    fn resolve_simple_single_package() {
        let resolver = DependencyResolver::new(
            vec![simple_entry("my-guard", &["1.0.0", "1.1.0", "2.0.0"])],
            &Lockfile::new(),
            "https://registry.test",
        );

        let mut root_deps = BTreeMap::new();
        root_deps.insert("my-guard".to_string(), VersionReq::parse("^1.0.0").unwrap());

        let resolved = resolver.resolve(&root_deps).unwrap();
        assert_eq!(resolved.len(), 1);
        assert_eq!(resolved[0].name, "my-guard");
        // Should choose highest compatible: 1.1.0
        assert_eq!(resolved[0].version, semver::Version::new(1, 1, 0));
    }

    #[test]
    fn resolve_multiple_packages() {
        let resolver = DependencyResolver::new(
            vec![
                simple_entry("alpha", &["1.0.0", "1.1.0"]),
                simple_entry("beta", &["2.0.0", "2.1.0", "3.0.0"]),
            ],
            &Lockfile::new(),
            "https://registry.test",
        );

        let mut root_deps = BTreeMap::new();
        root_deps.insert("alpha".to_string(), VersionReq::parse("^1.0").unwrap());
        root_deps.insert("beta".to_string(), VersionReq::parse("^2.0").unwrap());

        let resolved = resolver.resolve(&root_deps).unwrap();
        assert_eq!(resolved.len(), 2);

        let alpha = resolved.iter().find(|r| r.name == "alpha").unwrap();
        let beta = resolved.iter().find(|r| r.name == "beta").unwrap();
        assert_eq!(alpha.version, semver::Version::new(1, 1, 0));
        assert_eq!(beta.version, semver::Version::new(2, 1, 0));
    }

    #[test]
    fn resolve_with_transitive_dependencies() {
        // app -> my-guard@^1.0 -> base-guard@^2.0
        let resolver = DependencyResolver::new(
            vec![
                entry_with_deps("my-guard", "1.0.0", &[("base-guard", "^2.0.0")]),
                simple_entry("base-guard", &["2.0.0", "2.1.0", "3.0.0"]),
            ],
            &Lockfile::new(),
            "https://registry.test",
        );

        let mut root_deps = BTreeMap::new();
        root_deps.insert("my-guard".to_string(), VersionReq::parse("^1.0.0").unwrap());

        let resolved = resolver.resolve(&root_deps).unwrap();
        assert_eq!(resolved.len(), 2);

        let guard = resolved.iter().find(|r| r.name == "my-guard").unwrap();
        let base = resolved.iter().find(|r| r.name == "base-guard").unwrap();
        assert_eq!(guard.version, semver::Version::new(1, 0, 0));
        assert_eq!(base.version, semver::Version::new(2, 1, 0));
    }

    #[test]
    fn resolve_diamond_dependency() {
        // root -> A@^1.0, B@^1.0
        // A@1.0.0 -> C@^1.0
        // B@1.0.0 -> C@^1.2
        // C has versions 1.0.0, 1.2.0, 1.3.0
        // Should resolve C to >=1.2 (intersection of ^1.0 and ^1.2)
        let resolver = DependencyResolver::new(
            vec![
                entry_with_deps("pkg-a", "1.0.0", &[("pkg-c", "^1.0.0")]),
                entry_with_deps("pkg-b", "1.0.0", &[("pkg-c", "^1.2.0")]),
                simple_entry("pkg-c", &["1.0.0", "1.2.0", "1.3.0"]),
            ],
            &Lockfile::new(),
            "https://registry.test",
        );

        let mut root_deps = BTreeMap::new();
        root_deps.insert("pkg-a".to_string(), VersionReq::parse("^1.0").unwrap());
        root_deps.insert("pkg-b".to_string(), VersionReq::parse("^1.0").unwrap());

        let resolved = resolver.resolve(&root_deps).unwrap();
        assert_eq!(resolved.len(), 3);

        let c = resolved.iter().find(|r| r.name == "pkg-c").unwrap();
        // Should pick 1.3.0 (highest satisfying both ^1.0 and ^1.2)
        assert_eq!(c.version, semver::Version::new(1, 3, 0));
    }

    #[test]
    fn resolve_conflict_produces_error() {
        // root -> A@^1.0, B@^1.0
        // A@1.0.0 -> C@^1.0
        // B@1.0.0 -> C@^2.0
        // C has 1.0.0 and 2.0.0 — conflict!
        let resolver = DependencyResolver::new(
            vec![
                entry_with_deps("pkg-a", "1.0.0", &[("pkg-c", "^1.0.0")]),
                entry_with_deps("pkg-b", "1.0.0", &[("pkg-c", "^2.0.0")]),
                simple_entry("pkg-c", &["1.0.0", "2.0.0"]),
            ],
            &Lockfile::new(),
            "https://registry.test",
        );

        let mut root_deps = BTreeMap::new();
        root_deps.insert("pkg-a".to_string(), VersionReq::parse("^1.0").unwrap());
        root_deps.insert("pkg-b".to_string(), VersionReq::parse("^1.0").unwrap());

        let err = resolver.resolve(&root_deps).unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("dependency resolution failed"),
            "expected conflict error, got: {}",
            msg
        );
    }

    #[test]
    fn resolve_package_not_found() {
        let resolver = DependencyResolver::new(vec![], &Lockfile::new(), "https://registry.test");

        let mut root_deps = BTreeMap::new();
        root_deps.insert(
            "nonexistent".to_string(),
            VersionReq::parse("^1.0").unwrap(),
        );

        let err = resolver.resolve(&root_deps).unwrap_err();
        assert!(err.to_string().contains("resolution failed"));
    }

    #[test]
    fn resolve_yanked_excluded() {
        let mut entry = simple_entry("my-guard", &["1.0.0", "1.1.0"]);
        // Yank 1.1.0
        entry.versions[1].yanked = true;

        let resolver =
            DependencyResolver::new(vec![entry], &Lockfile::new(), "https://registry.test");

        let mut root_deps = BTreeMap::new();
        root_deps.insert("my-guard".to_string(), VersionReq::parse("^1.0.0").unwrap());

        let resolved = resolver.resolve(&root_deps).unwrap();
        assert_eq!(resolved.len(), 1);
        // Should pick 1.0.0 since 1.1.0 is yanked
        assert_eq!(resolved[0].version, semver::Version::new(1, 0, 0));
    }

    #[test]
    fn resolve_yanked_allowed_if_locked() {
        let mut entry = simple_entry("my-guard", &["1.0.0", "1.1.0"]);
        entry.versions[1].yanked = true;

        let mut lockfile = Lockfile::new();
        lockfile.add(LockedPackage {
            name: "my-guard".to_string(),
            version: "1.1.0".to_string(),
            pkg_type: PkgType::Guard,
            checksum: "sha256:110".to_string(),
            source: "registry+https://registry.test".to_string(),
            dependencies: vec![],
        });

        let resolver = DependencyResolver::new(vec![entry], &lockfile, "https://registry.test");

        let mut root_deps = BTreeMap::new();
        root_deps.insert("my-guard".to_string(), VersionReq::parse("^1.0.0").unwrap());

        let resolved = resolver.resolve(&root_deps).unwrap();
        assert_eq!(resolved.len(), 1);
        // 1.1.0 is yanked but locked, so it should still be available
        // (resolver should pick 1.1.0 as highest compatible)
        assert_eq!(resolved[0].version, semver::Version::new(1, 1, 0));
    }

    #[test]
    fn resolve_exact_version() {
        let resolver = DependencyResolver::new(
            vec![simple_entry("my-guard", &["1.0.0", "1.1.0", "2.0.0"])],
            &Lockfile::new(),
            "https://registry.test",
        );

        let mut root_deps = BTreeMap::new();
        root_deps.insert("my-guard".to_string(), VersionReq::parse("=1.0.0").unwrap());

        let resolved = resolver.resolve(&root_deps).unwrap();
        assert_eq!(resolved.len(), 1);
        assert_eq!(resolved[0].version, semver::Version::new(1, 0, 0));
    }

    #[test]
    fn lockfile_from_resolution_creates_valid_lockfile() {
        let resolved = vec![
            ResolvedPackage {
                name: "alpha".to_string(),
                version: semver::Version::new(1, 0, 0),
                checksum: "sha256:aaa".to_string(),
                pkg_type: PkgType::Guard,
                dependencies: {
                    let mut d = BTreeMap::new();
                    d.insert("beta".to_string(), "^2.0".to_string());
                    d
                },
                download_url: Some("https://reg.test/alpha/1.0.0".to_string()),
            },
            ResolvedPackage {
                name: "beta".to_string(),
                version: semver::Version::new(2, 1, 0),
                checksum: "sha256:bbb".to_string(),
                pkg_type: PkgType::PolicyPack,
                dependencies: BTreeMap::new(),
                download_url: Some("https://reg.test/beta/2.1.0".to_string()),
            },
        ];

        let lockfile = lockfile_from_resolution(&resolved, "https://registry.test");
        assert_eq!(lockfile.version, 1);
        assert_eq!(lockfile.packages.len(), 2);

        let alpha = lockfile
            .packages
            .iter()
            .find(|p| p.name == "alpha")
            .unwrap();
        assert_eq!(alpha.version, "1.0.0");
        assert_eq!(alpha.source, "registry+https://registry.test");
        assert_eq!(alpha.dependencies.len(), 1);
        assert_eq!(alpha.dependencies[0].name, "beta");
        assert_eq!(alpha.dependencies[0].version, "2.1.0");

        // Lockfile should be deterministic (sorted by name).
        assert_eq!(lockfile.packages[0].name, "alpha");
        assert_eq!(lockfile.packages[1].name, "beta");
    }

    #[test]
    fn lockfile_roundtrip() {
        let resolved = vec![ResolvedPackage {
            name: "test-pkg".to_string(),
            version: semver::Version::new(1, 2, 3),
            checksum: "sha256:abc123".to_string(),
            pkg_type: PkgType::Guard,
            dependencies: BTreeMap::new(),
            download_url: None,
        }];

        let lockfile = lockfile_from_resolution(&resolved, "https://registry.test");
        let toml = lockfile.to_toml().unwrap();
        let parsed = Lockfile::from_toml(&toml).unwrap();
        assert_eq!(parsed, lockfile);
    }

    #[test]
    fn resolve_download_urls_are_correct() {
        let resolver = DependencyResolver::new(
            vec![simple_entry("my-guard", &["1.0.0"])],
            &Lockfile::new(),
            "https://registry.clawdstrike.dev",
        );

        let mut root_deps = BTreeMap::new();
        root_deps.insert("my-guard".to_string(), VersionReq::parse("^1.0").unwrap());

        let resolved = resolver.resolve(&root_deps).unwrap();
        assert_eq!(
            resolved[0].download_url.as_deref(),
            Some("https://registry.clawdstrike.dev/api/v1/packages/my-guard/1.0.0/download")
        );
    }

    #[test]
    fn version_req_to_range_caret() {
        let req = VersionReq::parse("^1.2.3").unwrap();
        let range = version_req_to_range(&req).unwrap();
        assert!(range.contains(&semver::Version::new(1, 2, 3)));
        assert!(range.contains(&semver::Version::new(1, 9, 0)));
        assert!(!range.contains(&semver::Version::new(2, 0, 0)));
        assert!(!range.contains(&semver::Version::new(1, 2, 2)));
    }

    #[test]
    fn version_req_to_range_tilde() {
        let req = VersionReq::parse("~1.2.0").unwrap();
        let range = version_req_to_range(&req).unwrap();
        assert!(range.contains(&semver::Version::new(1, 2, 0)));
        assert!(range.contains(&semver::Version::new(1, 2, 9)));
        assert!(!range.contains(&semver::Version::new(1, 3, 0)));
    }

    #[test]
    fn version_req_to_range_exact() {
        let req = VersionReq::parse("=1.0.0").unwrap();
        let range = version_req_to_range(&req).unwrap();
        assert!(range.contains(&semver::Version::new(1, 0, 0)));
        assert!(!range.contains(&semver::Version::new(1, 0, 1)));
    }

    #[test]
    fn version_req_to_range_exact_prerelease() {
        let req = VersionReq::parse("=1.2.3-alpha.1").unwrap();
        let range = version_req_to_range(&req).unwrap();
        assert!(range.contains(&semver::Version::parse("1.2.3-alpha.1").unwrap()));
        assert!(!range.contains(&semver::Version::new(1, 2, 3)));
        assert!(!range.contains(&semver::Version::parse("1.2.3-alpha.2").unwrap()));
    }

    #[test]
    fn version_req_to_range_wildcard() {
        let req = VersionReq::parse("*").unwrap();
        let range = version_req_to_range(&req).unwrap();
        assert!(range.contains(&semver::Version::new(0, 0, 1)));
        assert!(range.contains(&semver::Version::new(99, 0, 0)));
    }

    #[test]
    fn version_req_to_range_wildcard_major_only() {
        let req = VersionReq::parse("1.*").unwrap();
        let range = version_req_to_range(&req).unwrap();
        assert!(range.contains(&semver::Version::new(1, 0, 0)));
        assert!(range.contains(&semver::Version::new(1, 99, 99)));
        assert!(!range.contains(&semver::Version::new(2, 0, 0)));
    }

    #[test]
    fn version_req_to_range_wildcard_zero_major() {
        let req = VersionReq::parse("0.*").unwrap();
        let range = version_req_to_range(&req).unwrap();
        assert!(range.contains(&semver::Version::new(0, 0, 0)));
        assert!(range.contains(&semver::Version::new(0, 50, 0)));
        assert!(!range.contains(&semver::Version::new(1, 0, 0)));
    }

    #[test]
    fn version_req_to_range_compound() {
        let req = VersionReq::parse(">=1.0.0, <2.0.0").unwrap();
        let range = version_req_to_range(&req).unwrap();
        assert!(range.contains(&semver::Version::new(1, 0, 0)));
        assert!(range.contains(&semver::Version::new(1, 5, 0)));
        assert!(!range.contains(&semver::Version::new(2, 0, 0)));
        assert!(!range.contains(&semver::Version::new(0, 9, 9)));
    }

    #[test]
    fn version_req_to_range_rejects_major_overflow() {
        let req = VersionReq::parse("^18446744073709551615").unwrap();
        let err = version_req_to_range(&req).unwrap_err();
        assert!(err.to_string().contains("major component overflow"));
    }

    #[test]
    fn version_req_to_range_rejects_minor_overflow() {
        let req = VersionReq::parse("~1.18446744073709551615").unwrap();
        let err = version_req_to_range(&req).unwrap_err();
        assert!(err.to_string().contains("minor component overflow"));
    }

    #[test]
    fn version_req_to_range_rejects_patch_overflow() {
        let req = VersionReq::parse("^0.0.18446744073709551615").unwrap();
        let err = version_req_to_range(&req).unwrap_err();
        assert!(err.to_string().contains("patch component overflow"));
    }

    #[test]
    fn resolve_deep_transitive_chain() {
        // A -> B -> C -> D
        let resolver = DependencyResolver::new(
            vec![
                entry_with_deps("pkg-a", "1.0.0", &[("pkg-b", "^1.0.0")]),
                entry_with_deps("pkg-b", "1.0.0", &[("pkg-c", "^1.0.0")]),
                entry_with_deps("pkg-c", "1.0.0", &[("pkg-d", "^1.0.0")]),
                simple_entry("pkg-d", &["1.0.0"]),
            ],
            &Lockfile::new(),
            "https://registry.test",
        );

        let mut root_deps = BTreeMap::new();
        root_deps.insert("pkg-a".to_string(), VersionReq::parse("^1.0").unwrap());

        let resolved = resolver.resolve(&root_deps).unwrap();
        assert_eq!(resolved.len(), 4);

        let names: Vec<&str> = resolved.iter().map(|r| r.name.as_str()).collect();
        assert!(names.contains(&"pkg-a"));
        assert!(names.contains(&"pkg-b"));
        assert!(names.contains(&"pkg-c"));
        assert!(names.contains(&"pkg-d"));
    }

    #[test]
    fn resolve_no_compatible_version() {
        let resolver = DependencyResolver::new(
            vec![simple_entry("my-guard", &["1.0.0"])],
            &Lockfile::new(),
            "https://registry.test",
        );

        let mut root_deps = BTreeMap::new();
        root_deps.insert("my-guard".to_string(), VersionReq::parse("^2.0.0").unwrap());

        let err = resolver.resolve(&root_deps).unwrap_err();
        assert!(err.to_string().contains("resolution failed"));
    }

    #[test]
    fn resolve_empty_deps() {
        let resolver = DependencyResolver::new(vec![], &Lockfile::new(), "https://registry.test");

        let root_deps = BTreeMap::new();
        let resolved = resolver.resolve(&root_deps).unwrap();
        assert!(resolved.is_empty());
    }

    #[test]
    fn resolved_packages_sorted_by_name() {
        let resolver = DependencyResolver::new(
            vec![
                simple_entry("zeta", &["1.0.0"]),
                simple_entry("alpha", &["1.0.0"]),
                simple_entry("mu", &["1.0.0"]),
            ],
            &Lockfile::new(),
            "https://registry.test",
        );

        let mut root_deps = BTreeMap::new();
        root_deps.insert("zeta".to_string(), VersionReq::parse("^1.0").unwrap());
        root_deps.insert("alpha".to_string(), VersionReq::parse("^1.0").unwrap());
        root_deps.insert("mu".to_string(), VersionReq::parse("^1.0").unwrap());

        let resolved = resolver.resolve(&root_deps).unwrap();
        assert_eq!(resolved[0].name, "alpha");
        assert_eq!(resolved[1].name, "mu");
        assert_eq!(resolved[2].name, "zeta");
    }
}
