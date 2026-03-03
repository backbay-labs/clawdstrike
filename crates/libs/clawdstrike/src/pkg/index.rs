//! Sparse registry index client for fetching package metadata.
//!
//! Follows a pattern similar to `remote_extends.rs` for content-addressed HTTP
//! caching with ETag-based revalidation.

use std::collections::BTreeMap;
use std::fs;
use std::io::Read;
use std::path::PathBuf;
use std::time::Duration;

use serde::{Deserialize, Serialize};

use super::manifest::PkgType;
use super::{encode_url_path_segment, normalize_package_name};
use crate::error::{Error, Result};

/// Default registry base URL.
pub const DEFAULT_REGISTRY_URL: &str = "https://registry.clawdstrike.dev";
/// Maximum accepted sparse-index response body size (8 MiB).
const MAX_INDEX_RESPONSE_BYTES: u64 = 8 * 1024 * 1024;

/// A sparse-index client that fetches and caches package metadata from a remote
/// registry.
#[derive(Clone, Debug)]
pub struct RegistryIndex {
    /// Registry base URL (e.g. `https://registry.clawdstrike.dev`).
    base_url: String,
    /// Local cache directory for index entries.
    cache_dir: PathBuf,
    /// Shared blocking client for connection/TLS reuse across fetches.
    http_client: reqwest::blocking::Client,
}

/// All known versions for a single package.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PackageIndexEntry {
    /// Package name.
    pub name: String,
    /// Available versions in chronological order.
    pub versions: Vec<IndexVersion>,
}

/// A single version record within a package index entry.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct IndexVersion {
    /// Semver version string.
    pub version: String,
    /// Content-address checksum (`sha256:<hex>`).
    pub checksum: String,
    /// Dependencies: name -> version constraint string.
    #[serde(default)]
    pub dependencies: BTreeMap<String, String>,
    /// Whether this version has been yanked.
    #[serde(default)]
    pub yanked: bool,
    /// Package type.
    pub pkg_type: PkgType,
}

/// Cached ETag metadata for a given index entry.
#[derive(Clone, Debug, Serialize, Deserialize)]
struct CacheMetadata {
    etag: Option<String>,
}

impl RegistryIndex {
    /// Create a new index client with default cache directory
    /// (`~/.clawdstrike/registry-cache/index/`).
    pub fn new(base_url: &str) -> Result<Self> {
        let home = dirs::home_dir()
            .ok_or_else(|| Error::PkgError("cannot determine home directory".to_string()))?;
        let cache_dir = home
            .join(".clawdstrike")
            .join("registry-cache")
            .join("index");
        Self::with_cache_dir(base_url, cache_dir)
    }

    /// Create an index client with a custom cache directory.
    pub fn with_cache_dir(base_url: &str, cache_dir: PathBuf) -> Result<Self> {
        fs::create_dir_all(&cache_dir)?;
        // Construct the blocking client outside any active Tokio runtime to
        // avoid reqwest's blocking-runtime panic.
        let http_client = run_blocking_http(build_blocking_client)?;
        Ok(Self {
            base_url: base_url.trim_end_matches('/').to_string(),
            cache_dir,
            http_client,
        })
    }

    /// Return the base URL of the registry.
    pub fn base_url(&self) -> &str {
        &self.base_url
    }

    /// Fetch (or return cached) version information for a package.
    ///
    /// The index follows a sparse layout where package metadata lives at:
    /// `{base_url}/api/v1/index/{normalized_name}`
    ///
    /// HTTP ETag headers are used for cache revalidation.
    pub fn fetch_package_versions(&self, name: &str) -> Result<PackageIndexEntry> {
        let normalized = normalize_package_name(name);
        let cache_path = self.cache_dir.join(format!("{normalized}.json"));
        let meta_path = self.cache_dir.join(format!("{normalized}.meta.json"));

        // Read cached ETag if available.
        let cached_etag = fs::read_to_string(&meta_path)
            .ok()
            .and_then(|s| serde_json::from_str::<CacheMetadata>(&s).ok())
            .and_then(|m| m.etag);

        let url = format!(
            "{}/api/v1/index/{}",
            self.base_url,
            encode_url_path_segment(name)
        );
        let package_name = name.to_string();
        let client = self.http_client.clone();

        let (status, etag, body) = run_blocking_http(move || {
            let mut request = client.get(&url);
            if let Some(etag) = cached_etag.as_deref() {
                request = request.header("If-None-Match", etag);
            }

            let mut response = request.send().map_err(|e| {
                Error::PkgError(format!(
                    "failed to fetch index for '{}': {}",
                    package_name, e
                ))
            })?;

            let status = response.status();
            let etag = response
                .headers()
                .get("etag")
                .and_then(|v: &reqwest::header::HeaderValue| v.to_str().ok())
                .map(String::from);

            let body = if status == reqwest::StatusCode::NOT_MODIFIED {
                None
            } else {
                if response
                    .content_length()
                    .is_some_and(|len| len > MAX_INDEX_RESPONSE_BYTES)
                {
                    return Err(Error::PkgError(format!(
                        "index body for '{}' exceeds limit ({} bytes)",
                        package_name, MAX_INDEX_RESPONSE_BYTES
                    )));
                }
                Some(read_utf8_body_limited(
                    &mut response,
                    MAX_INDEX_RESPONSE_BYTES,
                    &package_name,
                )?)
            };

            Ok((status, etag, body))
        })?;

        // 304 Not Modified — use cached version.
        if status == reqwest::StatusCode::NOT_MODIFIED {
            let cached = fs::read_to_string(&cache_path).map_err(|e| {
                Error::PkgError(format!(
                    "cache hit (304) but failed to read cached index for '{}': {}",
                    name, e
                ))
            })?;
            let entry: PackageIndexEntry = serde_json::from_str(&cached)?;
            return Ok(entry);
        }

        if status == reqwest::StatusCode::NOT_FOUND {
            return Err(Error::PkgError(format!(
                "package '{}' not found in registry",
                name
            )));
        }

        if !status.is_success() {
            return Err(Error::PkgError(format!(
                "registry returned HTTP {} for package '{}'",
                status, name
            )));
        }

        let body = body.ok_or_else(|| {
            Error::PkgError(format!(
                "registry returned success without body for package '{}'",
                name
            ))
        })?;

        // Validate JSON before caching.
        let entry: PackageIndexEntry = serde_json::from_str(&body)
            .map_err(|e| Error::PkgError(format!("invalid index JSON for '{}': {}", name, e)))?;

        // Write cache.
        fs::write(&cache_path, &body)?;
        let meta = CacheMetadata { etag };
        let meta_json = serde_json::to_string(&meta)
            .map_err(|e| Error::PkgError(format!("failed to serialize cache metadata: {}", e)))?;
        fs::write(&meta_path, meta_json)?;

        Ok(entry)
    }

    /// Invalidate the cached index entry for a package.
    pub fn invalidate_cache(&self, name: &str) -> Result<()> {
        let normalized = normalize_package_name(name);
        let cache_path = self.cache_dir.join(format!("{normalized}.json"));
        let meta_path = self.cache_dir.join(format!("{normalized}.meta.json"));
        let _ = fs::remove_file(&cache_path);
        let _ = fs::remove_file(&meta_path);
        Ok(())
    }
}

/// Build a blocking HTTP client suitable for registry communication.
fn build_blocking_client() -> Result<reqwest::blocking::Client> {
    reqwest::blocking::Client::builder()
        .timeout(Duration::from_secs(30))
        .user_agent(format!("clawdstrike-pkg/{}", env!("CARGO_PKG_VERSION")))
        .build()
        .map_err(|e| Error::PkgError(format!("failed to build HTTP client: {}", e)))
}

fn read_utf8_body_limited<R: Read>(
    mut reader: R,
    max_bytes: u64,
    package_name: &str,
) -> Result<String> {
    let mut bytes = Vec::new();
    let mut limited = reader.by_ref().take(max_bytes + 1);
    limited.read_to_end(&mut bytes).map_err(|e| {
        Error::PkgError(format!(
            "failed to read index body for '{}': {}",
            package_name, e
        ))
    })?;

    if bytes.len() as u64 > max_bytes {
        return Err(Error::PkgError(format!(
            "index body for '{}' exceeds limit ({} bytes)",
            package_name, max_bytes
        )));
    }

    String::from_utf8(bytes).map_err(|e| {
        Error::PkgError(format!(
            "index body for '{}' is not valid UTF-8: {}",
            package_name, e
        ))
    })
}

fn run_blocking_http<T, F>(f: F) -> Result<T>
where
    T: Send + 'static,
    F: FnOnce() -> Result<T> + Send + 'static,
{
    if tokio::runtime::Handle::try_current().is_ok() {
        std::thread::spawn(f)
            .join()
            .map_err(|_| Error::PkgError("blocking HTTP worker panicked".to_string()))?
    } else {
        f()
    }
}

// ---------------------------------------------------------------------------
// In-memory mock for testing
// ---------------------------------------------------------------------------

/// An in-memory index for testing that doesn't require network access.
#[derive(Clone, Debug, Default)]
pub struct MockRegistryIndex {
    entries: BTreeMap<String, PackageIndexEntry>,
}

impl MockRegistryIndex {
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a package with its versions.
    pub fn add_entry(&mut self, entry: PackageIndexEntry) {
        self.entries.insert(entry.name.clone(), entry);
    }

    /// Add a single version to a package (creates the entry if needed).
    pub fn add_version(
        &mut self,
        name: &str,
        version: &str,
        checksum: &str,
        pkg_type: PkgType,
        dependencies: BTreeMap<String, String>,
        yanked: bool,
    ) {
        let entry = self
            .entries
            .entry(name.to_string())
            .or_insert_with(|| PackageIndexEntry {
                name: name.to_string(),
                versions: Vec::new(),
            });
        entry.versions.push(IndexVersion {
            version: version.to_string(),
            checksum: checksum.to_string(),
            dependencies,
            yanked,
            pkg_type,
        });
    }

    /// Look up a package's index entry.
    pub fn fetch_package_versions(&self, name: &str) -> Result<PackageIndexEntry> {
        self.entries
            .get(name)
            .cloned()
            .ok_or_else(|| Error::PkgError(format!("package '{}' not found in index", name)))
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mock_index_add_and_fetch() {
        let mut index = MockRegistryIndex::new();
        index.add_version(
            "my-guard",
            "1.0.0",
            "sha256:aabb",
            PkgType::Guard,
            BTreeMap::new(),
            false,
        );
        index.add_version(
            "my-guard",
            "1.1.0",
            "sha256:ccdd",
            PkgType::Guard,
            BTreeMap::new(),
            false,
        );

        let entry = index.fetch_package_versions("my-guard").unwrap();
        assert_eq!(entry.name, "my-guard");
        assert_eq!(entry.versions.len(), 2);
        assert_eq!(entry.versions[0].version, "1.0.0");
        assert_eq!(entry.versions[1].version, "1.1.0");
    }

    #[test]
    fn mock_index_not_found() {
        let index = MockRegistryIndex::new();
        let err = index.fetch_package_versions("missing").unwrap_err();
        assert!(err.to_string().contains("not found"));
    }

    #[test]
    fn mock_index_with_dependencies() {
        let mut index = MockRegistryIndex::new();
        let mut deps = BTreeMap::new();
        deps.insert("base-guard".to_string(), "^1.0.0".to_string());

        index.add_version(
            "my-guard",
            "2.0.0",
            "sha256:eeff",
            PkgType::Guard,
            deps,
            false,
        );

        let entry = index.fetch_package_versions("my-guard").unwrap();
        let v = &entry.versions[0];
        assert_eq!(v.dependencies.len(), 1);
        assert_eq!(v.dependencies["base-guard"], "^1.0.0");
    }

    #[test]
    fn mock_index_yanked() {
        let mut index = MockRegistryIndex::new();
        index.add_version(
            "old-pkg",
            "1.0.0",
            "sha256:1111",
            PkgType::Guard,
            BTreeMap::new(),
            true,
        );

        let entry = index.fetch_package_versions("old-pkg").unwrap();
        assert!(entry.versions[0].yanked);
    }

    #[test]
    fn normalize_scoped_name() {
        assert_eq!(
            normalize_package_name("@acme/firewall"),
            "s--acme%2Ffirewall"
        );
        assert_eq!(normalize_package_name("simple-name"), "u--simple-name");
        assert_eq!(normalize_package_name("pkg%v1"), "u--pkg%25v1");
        assert_ne!(
            normalize_package_name("@acme/foo"),
            normalize_package_name("acme--foo")
        );
        assert_ne!(
            normalize_package_name("@a--b/c"),
            normalize_package_name("@a/b--c")
        );
    }

    #[test]
    fn index_version_serde_roundtrip() {
        let mut deps = BTreeMap::new();
        deps.insert("dep-a".to_string(), "^1.0".to_string());

        let iv = IndexVersion {
            version: "1.2.3".to_string(),
            checksum: "sha256:abcdef".to_string(),
            dependencies: deps,
            yanked: false,
            pkg_type: PkgType::Guard,
        };

        let json = serde_json::to_string(&iv).unwrap();
        let parsed: IndexVersion = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, iv);
    }

    #[test]
    fn package_index_entry_serde_roundtrip() {
        let entry = PackageIndexEntry {
            name: "test-pkg".to_string(),
            versions: vec![IndexVersion {
                version: "0.1.0".to_string(),
                checksum: "sha256:000".to_string(),
                dependencies: BTreeMap::new(),
                yanked: false,
                pkg_type: PkgType::PolicyPack,
            }],
        };

        let json = serde_json::to_string_pretty(&entry).unwrap();
        let parsed: PackageIndexEntry = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, entry);
    }

    #[test]
    fn registry_index_construction_is_runtime_safe() {
        let tmp = tempfile::tempdir().unwrap();
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();

        let result = runtime.block_on(async {
            RegistryIndex::with_cache_dir(DEFAULT_REGISTRY_URL, tmp.path().to_path_buf())
        });

        assert!(result.is_ok());
    }

    #[test]
    fn read_utf8_body_limited_rejects_oversized_payload() {
        let bytes = vec![b'a'; 11];
        let err = read_utf8_body_limited(bytes.as_slice(), 10, "demo").unwrap_err();
        assert!(err.to_string().contains("exceeds limit"));
    }

    #[test]
    fn read_utf8_body_limited_accepts_valid_utf8() {
        let body = read_utf8_body_limited(br#"{"name":"demo"}"#.as_slice(), 64, "demo").unwrap();
        assert_eq!(body, r#"{"name":"demo"}"#);
    }
}
