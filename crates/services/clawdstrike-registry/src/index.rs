//! Sparse index generation — one JSON file per package.

use std::fs;
use std::path::{Path, PathBuf};

use serde::Serialize;

use crate::db::{RegistryDb, VersionRow};
use crate::error::RegistryError;

/// An entry in the sparse index for a single package.
#[derive(Clone, Debug, Serialize)]
pub struct IndexEntry {
    pub name: String,
    pub versions: Vec<IndexVersionEntry>,
}

/// A single version within a sparse index entry.
#[derive(Clone, Debug, Serialize)]
pub struct IndexVersionEntry {
    pub version: String,
    pub pkg_type: String,
    pub checksum: String,
    pub dependencies: serde_json::Value,
    pub yanked: bool,
    pub published_at: String,
}

impl From<&VersionRow> for IndexVersionEntry {
    fn from(v: &VersionRow) -> Self {
        let dependencies = serde_json::from_str(&v.dependencies_json)
            .unwrap_or(serde_json::Value::Object(serde_json::Map::new()));
        Self {
            version: v.version.clone(),
            pkg_type: v.pkg_type.clone(),
            checksum: v.checksum.clone(),
            dependencies,
            yanked: v.yanked,
            published_at: v.published_at.clone(),
        }
    }
}

/// Build an `IndexEntry` from the database for a given package name.
pub fn build_index_entry(db: &RegistryDb, name: &str) -> Result<Option<IndexEntry>, RegistryError> {
    let versions = db.list_versions(name)?;
    if versions.is_empty() {
        return Ok(None);
    }

    let entries: Vec<IndexVersionEntry> = versions.iter().map(IndexVersionEntry::from).collect();
    Ok(Some(IndexEntry {
        name: name.to_string(),
        versions: entries,
    }))
}

/// Write the sparse index file for a package to the index directory.
///
/// For scoped packages (`@scope/name`), creates `index_dir/@scope/name.json`.
/// For unscoped packages, creates `index_dir/name.json`.
pub fn write_index_file(index_dir: &Path, entry: &IndexEntry) -> Result<PathBuf, RegistryError> {
    let file_path = index_file_path(index_dir, &entry.name);

    if let Some(parent) = file_path.parent() {
        fs::create_dir_all(parent)?;
    }

    let json = serde_json::to_string_pretty(entry)
        .map_err(|e| RegistryError::Internal(format!("failed to serialize index entry: {e}")))?;
    fs::write(&file_path, json)?;

    Ok(file_path)
}

/// Compute the filesystem path for an index entry.
pub fn index_file_path(index_dir: &Path, name: &str) -> PathBuf {
    if let Some(rest) = name.strip_prefix('@') {
        // Scoped: @scope/name -> index_dir/@scope/name.json
        let mut parts = rest.splitn(2, '/');
        let scope = parts.next().unwrap_or("");
        let pkg = parts.next().unwrap_or("");
        index_dir
            .join(format!("@{scope}"))
            .join(format!("{pkg}.json"))
    } else {
        index_dir.join(format!("{name}.json"))
    }
}

/// Update the sparse index for a package after a publish or yank.
pub fn update_index(db: &RegistryDb, index_dir: &Path, name: &str) -> Result<(), RegistryError> {
    match build_index_entry(db, name)? {
        Some(entry) => {
            write_index_file(index_dir, &entry)?;
        }
        None => {
            // No versions: remove the index file if it exists.
            let path = index_file_path(index_dir, name);
            if path.exists() {
                fs::remove_file(&path)?;
            }
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::{RegistryDb, VersionRow};

    #[test]
    fn build_index_entry_empty() {
        let db = RegistryDb::open_in_memory().unwrap();
        let entry = build_index_entry(&db, "nonexistent").unwrap();
        assert!(entry.is_none());
    }

    #[test]
    fn build_and_write_index_entry() {
        let db = RegistryDb::open_in_memory().unwrap();
        db.upsert_package("my-guard", Some("A guard"), "2025-01-01T00:00:00Z")
            .unwrap();
        db.insert_version(&VersionRow {
            name: "my-guard".into(),
            version: "1.0.0".into(),
            pkg_type: "guard".into(),
            checksum: "abc123".into(),
            manifest_toml: "".into(),
            publisher_key: "pk".into(),
            publisher_sig: "sig".into(),
            registry_sig: None,
            dependencies_json: r#"{"dep-a": "^1.0"}"#.into(),
            yanked: false,
            published_at: "2025-01-01T00:00:00Z".into(),
            attestation_hash: None,
            key_id: None,
            leaf_index: None,
            download_count: 0,
        })
        .unwrap();

        let entry = build_index_entry(&db, "my-guard").unwrap().unwrap();
        assert_eq!(entry.versions.len(), 1);
        assert_eq!(entry.versions[0].version, "1.0.0");

        let tmp = tempfile::tempdir().unwrap();
        let path = write_index_file(tmp.path(), &entry).unwrap();
        assert!(path.exists());

        let content = std::fs::read_to_string(&path).unwrap();
        assert!(content.contains("my-guard"));
    }

    #[test]
    fn scoped_index_path() {
        let base = Path::new("/registry/index");
        let path = index_file_path(base, "@acme/firewall");
        assert_eq!(path, PathBuf::from("/registry/index/@acme/firewall.json"));
    }

    #[test]
    fn unscoped_index_path() {
        let base = Path::new("/registry/index");
        let path = index_file_path(base, "my-guard");
        assert_eq!(path, PathBuf::from("/registry/index/my-guard.json"));
    }
}
