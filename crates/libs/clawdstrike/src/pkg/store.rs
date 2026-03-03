//! Local package store — manages installed `.cpkg` packages on disk.

use std::fs;
use std::path::{Path, PathBuf};

use hush_core::Hash;
use semver::Version;
use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};

use super::archive;
use super::manifest::parse_pkg_manifest_toml;
use super::normalize_package_name;
use super::normalize_relative_path_for_key;

/// An installed package record.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InstalledPackage {
    pub name: String,
    pub version: String,
    pub path: PathBuf,
    pub content_hash: Hash,
}

/// Metadata persisted alongside an installed package (`.pkg-meta.json`).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct StoreMetadata {
    pub content_hash: Hash,
    pub installed_at: String,
    /// Original package name (including scope if any). Used to avoid
    /// ambiguity when denormalizing directory names that contain `--`.
    #[serde(default)]
    pub name: Option<String>,
    /// Deterministic fingerprint of installed package contents (excluding
    /// `.pkg-meta.json`), used for local tamper detection.
    #[serde(default)]
    pub content_fingerprint: Option<Hash>,
}

/// Local package store rooted at `~/.clawdstrike/packages/` by default.
pub struct PackageStore {
    root: PathBuf,
}

/// Derive a display name from a package directory name when metadata is absent.
///
/// New installs always persist the original name in [`StoreMetadata`],
/// so [`PackageStore::list`] prefers that authoritative value and only
/// calls this function for old metadata that lacks the `name` field.
///
/// Normalized directory keys are not guaranteed to be a lossless display
/// representation for historical installs that may lack `StoreMetadata::name`,
/// so this function simply returns the directory name unchanged. Callers that
/// need the original package name should use `StoreMetadata::name` instead.
fn denormalize_name(dir_name: &str) -> String {
    dir_name.to_string()
}

fn cmp_package_versions(lhs: &str, rhs: &str) -> std::cmp::Ordering {
    match (Version::parse(lhs), Version::parse(rhs)) {
        (Ok(a), Ok(b)) => a.cmp(&b),
        _ => lhs.cmp(rhs),
    }
}

const INVALID_VERSION_SEGMENT: &str = "__invalid_version__";

fn is_safe_version_segment(version: &str) -> bool {
    if version.is_empty() || version == "." || version == ".." {
        return false;
    }
    if version.contains('/') || version.contains('\\') {
        return false;
    }
    let mut components = Path::new(version).components();
    matches!(components.next(), Some(std::path::Component::Normal(_)))
        && components.next().is_none()
}

fn append_fingerprint_material(base: &Path, dir: &Path, out: &mut Vec<u8>) -> Result<()> {
    let mut entries = Vec::new();
    for entry in fs::read_dir(dir)? {
        entries.push(entry?);
    }
    entries.sort_by_key(|entry| entry.file_name());

    for entry in entries {
        let path = entry.path();
        let rel = path
            .strip_prefix(base)
            .map_err(|e| Error::PkgError(format!("failed to fingerprint package path: {e}")))?;
        if rel == Path::new(".pkg-meta.json") {
            continue;
        }

        let rel_norm = normalize_relative_path_for_key(rel);
        let file_type = entry.file_type()?;
        if file_type.is_dir() {
            out.extend_from_slice(b"D\0");
            out.extend_from_slice(rel_norm.as_bytes());
            out.push(0);
            append_fingerprint_material(base, &path, out)?;
        } else if file_type.is_file() {
            out.extend_from_slice(b"F\0");
            out.extend_from_slice(rel_norm.as_bytes());
            out.push(0);
            let bytes = fs::read(&path)?;
            out.extend_from_slice(&(bytes.len() as u64).to_le_bytes());
            out.extend_from_slice(&bytes);
        } else {
            return Err(Error::PkgError(format!(
                "unsupported entry type in installed package: {rel_norm}"
            )));
        }
    }

    Ok(())
}

/// Compute a deterministic fingerprint of installed package contents.
///
/// The fingerprint includes file paths, directory paths, and file bytes while
/// excluding store metadata (`.pkg-meta.json`).
pub fn compute_content_fingerprint(package_dir: &Path) -> Result<Hash> {
    let mut material = Vec::new();
    append_fingerprint_material(package_dir, package_dir, &mut material)?;
    Ok(hush_core::sha256(&material))
}

impl PackageStore {
    /// Create a store at the default location (`~/.clawdstrike/packages/`).
    pub fn new() -> Result<Self> {
        let home = dirs::home_dir()
            .ok_or_else(|| Error::PkgError("cannot determine home directory".to_string()))?;
        let root = home.join(".clawdstrike").join("packages");
        Self::with_root(root)
    }

    /// Create a store at a custom root (useful for testing).
    pub fn with_root(root: PathBuf) -> Result<Self> {
        fs::create_dir_all(&root)?;
        Ok(Self { root })
    }

    /// Return the directory path for a given package name and version.
    pub fn package_dir(&self, name: &str, version: &str) -> PathBuf {
        let safe_version = if is_safe_version_segment(version) {
            version
        } else {
            INVALID_VERSION_SEGMENT
        };
        self.root
            .join(normalize_package_name(name))
            .join(safe_version)
    }

    /// Install a package from a `.cpkg` archive file.
    ///
    /// Atomically unpacks to a temp dir, validates the manifest, then moves
    /// to `<root>/<normalized_name>/<version>/`.
    pub fn install_from_file(&self, archive_path: &Path) -> Result<InstalledPackage> {
        // Unpack to a temp directory first (atomic install).
        // Use a guard so the temp dir is cleaned up on any error path.
        let tmp_name = format!(".tmp-{}", uuid::Uuid::new_v4());
        let tmp_dir = self.root.join(&tmp_name);
        fs::create_dir_all(&tmp_dir)?;

        // Guard that removes the temp directory when dropped, unless
        // explicitly disarmed after a successful rename.
        struct TmpGuard {
            path: PathBuf,
            disarmed: bool,
        }
        impl Drop for TmpGuard {
            fn drop(&mut self) {
                if !self.disarmed {
                    let _ = fs::remove_dir_all(&self.path);
                }
            }
        }
        let mut guard = TmpGuard {
            path: tmp_dir.clone(),
            disarmed: false,
        };

        let content_hash = archive::unpack(archive_path, &tmp_dir)?;

        // Read and validate manifest.
        let manifest_path = tmp_dir.join("clawdstrike-pkg.toml");
        let manifest_content = fs::read_to_string(&manifest_path)
            .map_err(|e| Error::PkgError(format!("package missing clawdstrike-pkg.toml: {e}")))?;
        let manifest = parse_pkg_manifest_toml(&manifest_content)?;

        let name = &manifest.package.name;
        let version = &manifest.package.version;
        let target = self.package_dir(name, version);

        if let Some(parent) = target.parent() {
            fs::create_dir_all(parent)?;
        }

        // Preserve existing install until the replacement is safely in place.
        let mut backup: Option<PathBuf> = None;
        if target.exists() {
            let nonce = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0);
            let backup_path = target.with_extension(format!("bak.{nonce:x}"));
            fs::rename(&target, &backup_path)?;
            backup = Some(backup_path);
        }

        // Atomic rename (same filesystem). If this fails, restore backup.
        if let Err(e) = fs::rename(&tmp_dir, &target) {
            if let Some(ref backup_path) = backup {
                let _ = fs::rename(backup_path, &target);
            }
            return Err(e.into());
        }

        // Disarm the guard — the temp dir no longer exists (it was renamed).
        guard.disarmed = true;

        let content_fingerprint = match compute_content_fingerprint(&target) {
            Ok(f) => f,
            Err(e) => {
                if let Some(ref backup_path) = backup {
                    let _ = fs::remove_dir_all(&target);
                    let _ = fs::rename(backup_path, &target);
                } else {
                    let _ = fs::remove_dir_all(&target);
                }
                return Err(e);
            }
        };

        // Write metadata file.
        let meta = StoreMetadata {
            content_hash,
            installed_at: chrono::Utc::now().to_rfc3339(),
            name: Some(name.clone()),
            content_fingerprint: Some(content_fingerprint),
        };
        let meta_path = target.join(".pkg-meta.json");
        let meta_json = match serde_json::to_string_pretty(&meta) {
            Ok(v) => v,
            Err(e) => {
                // Roll back to previous install if metadata serialization fails.
                if let Some(ref backup_path) = backup {
                    let _ = fs::remove_dir_all(&target);
                    let _ = fs::rename(backup_path, &target);
                } else {
                    let _ = fs::remove_dir_all(&target);
                }
                return Err(e.into());
            }
        };
        if let Err(e) = fs::write(&meta_path, meta_json) {
            // Roll back to previous install if metadata persistence fails.
            if let Some(ref backup_path) = backup {
                let _ = fs::remove_dir_all(&target);
                let _ = fs::rename(backup_path, &target);
            } else {
                let _ = fs::remove_dir_all(&target);
            }
            return Err(e.into());
        }

        // Remove old backup only after metadata write succeeds.
        if let Some(backup_path) = backup {
            let _ = fs::remove_dir_all(backup_path);
        }

        Ok(InstalledPackage {
            name: name.clone(),
            version: version.clone(),
            path: target,
            content_hash,
        })
    }

    /// Look up an installed package by name and version.
    pub fn get(&self, name: &str, version: &str) -> Result<Option<InstalledPackage>> {
        let pkg_dir = self.package_dir(name, version);
        if !pkg_dir.exists() {
            return Ok(None);
        }

        let meta_path = pkg_dir.join(".pkg-meta.json");
        let meta_content = fs::read_to_string(&meta_path)
            .map_err(|e| Error::PkgError(format!("missing metadata for {name}@{version}: {e}")))?;
        let meta: StoreMetadata = serde_json::from_str(&meta_content)?;

        Ok(Some(InstalledPackage {
            name: name.to_string(),
            version: version.to_string(),
            path: pkg_dir,
            content_hash: meta.content_hash,
        }))
    }

    /// List all installed packages.
    pub fn list(&self) -> Result<Vec<InstalledPackage>> {
        let mut packages = Vec::new();
        let entries = match fs::read_dir(&self.root) {
            Ok(e) => e,
            Err(_) => return Ok(packages),
        };

        for entry in entries {
            let entry = entry?;
            let pkg_dir = entry.path();
            if !pkg_dir.is_dir() {
                continue;
            }

            let dir_name = entry.file_name().to_string_lossy().to_string();

            // Each package dir contains version subdirs.
            let version_entries = match fs::read_dir(&pkg_dir) {
                Ok(e) => e,
                Err(_) => continue,
            };

            for ver_entry in version_entries {
                let ver_entry = ver_entry?;
                let ver_dir = ver_entry.path();
                if !ver_dir.is_dir() {
                    continue;
                }

                let meta_path = ver_dir.join(".pkg-meta.json");
                if !meta_path.exists() {
                    continue;
                }

                let meta_content = match fs::read_to_string(&meta_path) {
                    Ok(c) => c,
                    Err(_) => continue,
                };
                let meta: StoreMetadata = match serde_json::from_str(&meta_content) {
                    Ok(m) => m,
                    Err(_) => continue,
                };

                // Prefer the original name stored in metadata (avoids
                // double-dash ambiguity); fall back to heuristic
                // denormalization for older metadata without the field.
                let name = meta
                    .name
                    .clone()
                    .unwrap_or_else(|| denormalize_name(&dir_name));
                let version = ver_entry.file_name().to_string_lossy().to_string();

                packages.push(InstalledPackage {
                    name,
                    version,
                    path: ver_dir,
                    content_hash: meta.content_hash,
                });
            }
        }

        packages.sort_by(|a, b| {
            a.name
                .cmp(&b.name)
                .then_with(|| cmp_package_versions(&a.version, &b.version))
        });
        Ok(packages)
    }

    /// Remove an installed package.
    pub fn remove(&self, name: &str, version: &str) -> Result<()> {
        let pkg_dir = self.package_dir(name, version);
        if !pkg_dir.exists() {
            return Err(Error::PkgError(format!(
                "package {name}@{version} is not installed"
            )));
        }
        fs::remove_dir_all(&pkg_dir)?;

        // Clean up parent dir if empty.
        let parent = pkg_dir.parent().map(Path::to_path_buf).ok_or_else(|| {
            Error::PkgError(format!(
                "failed to determine parent directory for package {name}@{version}"
            ))
        })?;
        if parent.exists() {
            let is_empty = fs::read_dir(&parent)?.next().is_none();
            if is_empty {
                fs::remove_dir(&parent)?;
            }
        }

        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    /// Create a minimal package directory with a manifest and pack it.
    fn create_test_package(
        tmp: &Path,
        name: &str,
        version: &str,
        pkg_type: &str,
        suffix: &str,
    ) -> PathBuf {
        let src = tmp.join(format!("pkg-src-{suffix}"));
        fs::create_dir_all(&src).unwrap();

        let manifest = format!(
            r#"[package]
name = "{name}"
version = "{version}"
pkg_type = "{pkg_type}"

[trust]
level = "trusted"
sandbox = "native"
"#
        );
        fs::write(src.join("clawdstrike-pkg.toml"), &manifest).unwrap();
        fs::write(src.join("guard.wasm"), b"fake wasm").unwrap();

        let archive_path = tmp.join(format!("{suffix}.cpkg"));
        archive::pack(&src, &archive_path).unwrap();
        archive_path
    }

    fn create_test_package_with_meta_path_directory(
        tmp: &Path,
        name: &str,
        version: &str,
        pkg_type: &str,
        suffix: &str,
        payload: &[u8],
    ) -> PathBuf {
        let src = tmp.join(format!("pkg-src-{suffix}"));
        fs::create_dir_all(&src).unwrap();

        let manifest = format!(
            r#"[package]
name = "{name}"
version = "{version}"
pkg_type = "{pkg_type}"

[trust]
level = "trusted"
sandbox = "native"
"#
        );
        fs::write(src.join("clawdstrike-pkg.toml"), &manifest).unwrap();
        fs::create_dir_all(src.join(".pkg-meta.json")).unwrap();
        fs::write(src.join("guard.wasm"), payload).unwrap();

        let archive_path = tmp.join(format!("{suffix}.cpkg"));
        archive::pack(&src, &archive_path).unwrap();
        archive_path
    }

    #[test]
    fn install_and_get() {
        let tmp = tempfile::tempdir().unwrap();
        let store = PackageStore::with_root(tmp.path().join("store")).unwrap();

        let archive = create_test_package(tmp.path(), "my-guard", "1.0.0", "guard", "a");
        let installed = store.install_from_file(&archive).unwrap();

        assert_eq!(installed.name, "my-guard");
        assert_eq!(installed.version, "1.0.0");
        assert!(installed.path.exists());

        let got = store.get("my-guard", "1.0.0").unwrap().unwrap();
        assert_eq!(got.name, "my-guard");
        assert_eq!(got.content_hash, installed.content_hash);

        let meta_path = got.path.join(".pkg-meta.json");
        let meta_raw = fs::read_to_string(meta_path).unwrap();
        let meta: StoreMetadata = serde_json::from_str(&meta_raw).unwrap();
        assert!(meta.content_fingerprint.is_some());
    }

    #[test]
    fn install_scoped_package() {
        let tmp = tempfile::tempdir().unwrap();
        let store = PackageStore::with_root(tmp.path().join("store")).unwrap();

        let archive =
            create_test_package(tmp.path(), "@acme/firewall", "0.1.0", "policy-pack", "b");
        let installed = store.install_from_file(&archive).unwrap();

        assert_eq!(installed.name, "@acme/firewall");
        assert!(installed
            .path
            .to_string_lossy()
            .contains("s--acme%2Ffirewall"));

        let got = store.get("@acme/firewall", "0.1.0").unwrap().unwrap();
        assert_eq!(got.name, "@acme/firewall");
    }

    #[test]
    fn scoped_and_unscoped_names_do_not_collide() {
        let tmp = tempfile::tempdir().unwrap();
        let store = PackageStore::with_root(tmp.path().join("store")).unwrap();

        let scoped = create_test_package(tmp.path(), "@acme/foo", "1.0.0", "guard", "coll-a");
        let unscoped = create_test_package(tmp.path(), "acme--foo", "1.0.0", "guard", "coll-b");

        let scoped_installed = store.install_from_file(&scoped).unwrap();
        let unscoped_installed = store.install_from_file(&unscoped).unwrap();

        assert_ne!(scoped_installed.path, unscoped_installed.path);

        let scoped_got = store.get("@acme/foo", "1.0.0").unwrap().unwrap();
        let unscoped_got = store.get("acme--foo", "1.0.0").unwrap().unwrap();
        assert_eq!(scoped_got.name, "@acme/foo");
        assert_eq!(unscoped_got.name, "acme--foo");
        assert_ne!(scoped_got.content_hash, unscoped_got.content_hash);
    }

    #[test]
    fn scoped_names_with_dashes_do_not_collide() {
        let tmp = tempfile::tempdir().unwrap();
        let store = PackageStore::with_root(tmp.path().join("store")).unwrap();

        let a = create_test_package(tmp.path(), "@a--b/c", "1.0.0", "guard", "scope-coll-a");
        let b = create_test_package(tmp.path(), "@a/b--c", "1.0.0", "guard", "scope-coll-b");

        let installed_a = store.install_from_file(&a).unwrap();
        let installed_b = store.install_from_file(&b).unwrap();

        assert_ne!(installed_a.path, installed_b.path);
        assert!(installed_a.path.to_string_lossy().contains("s--a--b%2Fc"));
        assert!(installed_b.path.to_string_lossy().contains("s--a%2Fb--c"));
    }

    #[test]
    fn scoped_lookup_does_not_match_unscoped_s_prefix() {
        let tmp = tempfile::tempdir().unwrap();
        let store = PackageStore::with_root(tmp.path().join("store")).unwrap();

        let scoped = create_test_package(tmp.path(), "@scope/name", "1.0.0", "guard", "scoped");
        store.install_from_file(&scoped).unwrap();

        let got = store.get("s--scope--name", "1.0.0").unwrap();
        assert!(got.is_none());
    }

    #[test]
    fn list_packages() {
        let tmp = tempfile::tempdir().unwrap();
        let store = PackageStore::with_root(tmp.path().join("store")).unwrap();

        let a1 = create_test_package(tmp.path(), "alpha", "1.0.0", "guard", "c");
        let a2 = create_test_package(tmp.path(), "beta", "2.0.0", "adapter", "d");

        store.install_from_file(&a1).unwrap();
        store.install_from_file(&a2).unwrap();

        let list = store.list().unwrap();
        assert_eq!(list.len(), 2);
        assert_eq!(list[0].name, "alpha");
        assert_eq!(list[1].name, "beta");
    }

    #[test]
    fn list_sorts_versions_by_semver_not_lexicographic() {
        let tmp = tempfile::tempdir().unwrap();
        let store = PackageStore::with_root(tmp.path().join("store")).unwrap();

        let v1 = create_test_package(tmp.path(), "alpha", "1.2.0", "guard", "semver-a");
        let v2 = create_test_package(tmp.path(), "alpha", "1.10.0", "guard", "semver-b");

        store.install_from_file(&v2).unwrap();
        store.install_from_file(&v1).unwrap();

        let list = store.list().unwrap();
        let alpha_versions: Vec<_> = list
            .iter()
            .filter(|pkg| pkg.name == "alpha")
            .map(|pkg| pkg.version.as_str())
            .collect();
        assert_eq!(alpha_versions, vec!["1.2.0", "1.10.0"]);
    }

    #[test]
    fn remove_package() {
        let tmp = tempfile::tempdir().unwrap();
        let store = PackageStore::with_root(tmp.path().join("store")).unwrap();

        let archive = create_test_package(tmp.path(), "removable", "1.0.0", "guard", "e");
        store.install_from_file(&archive).unwrap();
        assert!(store.get("removable", "1.0.0").unwrap().is_some());

        store.remove("removable", "1.0.0").unwrap();
        assert!(store.get("removable", "1.0.0").unwrap().is_none());
    }

    #[test]
    fn remove_nonexistent_fails() {
        let tmp = tempfile::tempdir().unwrap();
        let store = PackageStore::with_root(tmp.path().join("store")).unwrap();

        let err = store.remove("nope", "1.0.0").unwrap_err();
        assert!(err.to_string().contains("not installed"));
    }

    #[test]
    fn get_nonexistent_returns_none() {
        let tmp = tempfile::tempdir().unwrap();
        let store = PackageStore::with_root(tmp.path().join("store")).unwrap();

        assert!(store.get("nope", "1.0.0").unwrap().is_none());
    }

    #[test]
    fn reinstall_overwrites() {
        let tmp = tempfile::tempdir().unwrap();
        let store = PackageStore::with_root(tmp.path().join("store")).unwrap();

        let archive = create_test_package(tmp.path(), "my-guard", "1.0.0", "guard", "f");
        let first = store.install_from_file(&archive).unwrap();
        let second = store.install_from_file(&archive).unwrap();

        assert_eq!(first.content_hash, second.content_hash);
        assert_eq!(store.list().unwrap().len(), 1);
    }

    #[test]
    fn metadata_write_failure_restores_previous_install() {
        let tmp = tempfile::tempdir().unwrap();
        let store = PackageStore::with_root(tmp.path().join("store")).unwrap();

        let good = create_test_package(tmp.path(), "demo", "1.0.0", "guard", "h");
        let first = store.install_from_file(&good).unwrap();

        let bad = create_test_package_with_meta_path_directory(
            tmp.path(),
            "demo",
            "1.0.0",
            "guard",
            "i",
            b"new payload",
        );
        let _err = store.install_from_file(&bad).unwrap_err();

        let current = store.get("demo", "1.0.0").unwrap().unwrap();
        assert_eq!(current.content_hash, first.content_hash);
        assert!(current.path.join(".pkg-meta.json").is_file());
    }

    #[test]
    fn denormalize_returns_dir_name_unchanged() {
        // `denormalize_name` intentionally does not interpret `--` as scope
        // separators because that mapping is ambiguous.
        assert_eq!(denormalize_name("acme--firewall"), "acme--firewall");
        assert_eq!(denormalize_name("my--pkg"), "my--pkg");
        assert_eq!(denormalize_name("a--b--c"), "a--b--c");
        assert_eq!(denormalize_name("simple-guard"), "simple-guard");
        assert_eq!(denormalize_name("--name"), "--name");
    }

    #[test]
    fn list_uses_metadata_name_for_scoped_packages() {
        let tmp = tempfile::tempdir().unwrap();
        let store = PackageStore::with_root(tmp.path().join("store")).unwrap();

        let archive =
            create_test_package(tmp.path(), "@acme/firewall", "0.1.0", "policy-pack", "g");
        store.install_from_file(&archive).unwrap();

        let list = store.list().unwrap();
        assert_eq!(list.len(), 1);
        // The original scoped name is preserved via StoreMetadata.name,
        // NOT via denormalize_name heuristics.
        assert_eq!(list[0].name, "@acme/firewall");
    }

    #[test]
    fn package_dir_sanitizes_traversal_like_versions() {
        let tmp = tempfile::tempdir().unwrap();
        let store = PackageStore::with_root(tmp.path().join("store")).unwrap();
        let pkg_root = store.root.join(normalize_package_name("demo"));

        assert_eq!(
            store.package_dir("demo", ".."),
            pkg_root.join(INVALID_VERSION_SEGMENT)
        );
        assert_eq!(
            store.package_dir("demo", "1.0.0/../../evil"),
            pkg_root.join(INVALID_VERSION_SEGMENT)
        );
        assert_eq!(
            store.package_dir("demo", "1.0.0\\..\\evil"),
            pkg_root.join(INVALID_VERSION_SEGMENT)
        );
        assert_eq!(store.package_dir("demo", "1.0.0"), pkg_root.join("1.0.0"));
    }

    #[test]
    fn get_with_traversal_like_version_cannot_escape_package_root() {
        let tmp = tempfile::tempdir().unwrap();
        let store = PackageStore::with_root(tmp.path().join("store")).unwrap();

        let package_root = store.root.join(normalize_package_name("demo"));
        fs::create_dir_all(&package_root).unwrap();
        // Even if a metadata file exists at package root, version traversal
        // strings must not resolve to it.
        fs::write(package_root.join(".pkg-meta.json"), "{}").unwrap();

        assert!(store.get("demo", "..").unwrap().is_none());
    }

    #[test]
    fn content_fingerprint_ignores_metadata_file() {
        let tmp = tempfile::tempdir().unwrap();
        let store = PackageStore::with_root(tmp.path().join("store")).unwrap();

        let archive = create_test_package(tmp.path(), "demo", "1.0.0", "guard", "fp-meta");
        let installed = store.install_from_file(&archive).unwrap();

        let meta_path = installed.path.join(".pkg-meta.json");
        let initial_meta: StoreMetadata =
            serde_json::from_str(&fs::read_to_string(&meta_path).unwrap()).unwrap();
        let expected = initial_meta.content_fingerprint.unwrap();

        let mut modified_meta = initial_meta.clone();
        modified_meta.installed_at = "2099-01-01T00:00:00Z".to_string();
        fs::write(
            &meta_path,
            serde_json::to_string_pretty(&modified_meta).unwrap(),
        )
        .unwrap();

        let recomputed = compute_content_fingerprint(&installed.path).unwrap();
        assert_eq!(recomputed, expected);
    }
}
