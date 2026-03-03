//! Shared application state for the registry service.

use std::sync::{Arc, Mutex};

use clawdstrike::pkg::merkle::{LeafData, MerkleTree};
use hush_core::Keypair;

use crate::config::Config;
use crate::db::RegistryDb;
use crate::error::RegistryError;
use crate::keys::RegistryKeyManager;
use crate::oidc::JwksCache;
use crate::storage::BlobStorage;

/// Shared application state, cheaply cloneable via `Arc`.
#[derive(Clone)]
pub struct AppState {
    pub config: Arc<Config>,
    pub db: Arc<Mutex<RegistryDb>>,
    pub blobs: Arc<BlobStorage>,
    pub registry_keypair: Arc<Keypair>,
    pub key_manager: Arc<Mutex<RegistryKeyManager>>,
    pub merkle_tree: Arc<Mutex<MerkleTree>>,
    pub jwks_cache: Arc<Mutex<JwksCache>>,
}

impl AppState {
    /// Initialize application state from config.
    ///
    /// Creates directories, opens the database, and loads or generates the
    /// registry Ed25519 keypair. Rebuilds the Merkle tree from existing
    /// version rows.
    pub fn new(config: Config) -> anyhow::Result<Self> {
        // Ensure directories exist.
        std::fs::create_dir_all(config.data_dir.clone())?;
        std::fs::create_dir_all(config.index_dir())?;
        std::fs::create_dir_all(config.keys_dir())?;

        // Open database.
        let db = RegistryDb::open(&config.db_path())?;

        // Open blob storage.
        let blobs = BlobStorage::new(config.blob_dir())?;

        // Load or generate registry keypair.
        let keypair = load_or_generate_keypair(&config)?;
        tracing::info!(
            public_key = %keypair.public_key().to_hex(),
            "Registry keypair loaded"
        );

        // Initialize key manager with the loaded keypair.
        let key_manager = RegistryKeyManager::new(keypair.clone());

        // Ensure the initial key is recorded in the database.
        let key_info = key_manager.current_key();
        db.upsert_registry_key(key_info)?;

        // Rebuild the Merkle tree from existing version rows.
        let mut tree = MerkleTree::new();
        let versions = db.list_all_versions_ordered()?;
        for v in &versions {
            let Some(idx) = v.leaf_index else {
                // Legacy versions may not be included in the transparency log.
                continue;
            };
            let expected_index = tree.tree_size();
            if idx != expected_index {
                return Err(anyhow::anyhow!(
                    "transparency log leaf_index sequence mismatch while rebuilding tree: expected {}, found {} for {}@{}",
                    expected_index,
                    idx,
                    v.name,
                    v.version
                ));
            }
            let leaf_data = LeafData {
                package_name: v.name.clone(),
                version: v.version.clone(),
                content_hash: v.checksum.clone(),
                publisher_key: v.publisher_key.clone(),
                timestamp: v.published_at.clone(),
            };
            let leaf_hash = leaf_data.leaf_hash().map_err(|e| {
                RegistryError::Internal(format!("failed to compute leaf hash on rebuild: {e}"))
            })?;
            tree.append_hash(leaf_hash);
        }
        tracing::info!(
            tree_size = tree.tree_size(),
            "Merkle tree rebuilt from existing versions"
        );

        Ok(Self {
            config: Arc::new(config),
            db: Arc::new(Mutex::new(db)),
            blobs: Arc::new(blobs),
            registry_keypair: Arc::new(keypair),
            key_manager: Arc::new(Mutex::new(key_manager)),
            merkle_tree: Arc::new(Mutex::new(tree)),
            jwks_cache: Arc::new(Mutex::new(JwksCache::new())),
        })
    }
}

/// Load the registry keypair from disk, or generate a new one.
fn load_or_generate_keypair(config: &Config) -> anyhow::Result<Keypair> {
    let key_path = config.keys_dir().join("registry.key");
    let pub_path = config.keys_dir().join("registry.pub");

    if key_path.exists() {
        tighten_private_key_permissions(&key_path)?;
        let hex = std::fs::read_to_string(&key_path)?.trim().to_string();
        let keypair = Keypair::from_hex(&hex)
            .map_err(|e| RegistryError::Internal(format!("failed to load registry key: {e}")))?;
        Ok(keypair)
    } else {
        let keypair = Keypair::generate();
        write_private_key_file(&key_path, &keypair.to_hex())?;
        tighten_private_key_permissions(&key_path)?;
        std::fs::write(&pub_path, keypair.public_key().to_hex())?;
        tracing::info!("Generated new registry keypair");
        Ok(keypair)
    }
}

#[cfg(unix)]
fn write_private_key_file(path: &std::path::Path, contents: &str) -> std::io::Result<()> {
    use std::fs::OpenOptions;
    use std::io::Write as _;
    use std::os::unix::fs::OpenOptionsExt;

    let mut file = OpenOptions::new()
        .create(true)
        .truncate(true)
        .write(true)
        .mode(0o600)
        .open(path)?;
    file.write_all(contents.as_bytes())?;
    file.sync_all()?;
    Ok(())
}

#[cfg(not(unix))]
fn write_private_key_file(path: &std::path::Path, contents: &str) -> std::io::Result<()> {
    std::fs::write(path, contents)
}

#[cfg(unix)]
fn tighten_private_key_permissions(path: &std::path::Path) -> std::io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
}

#[cfg(not(unix))]
fn tighten_private_key_permissions(_path: &std::path::Path) -> std::io::Result<()> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_config(dir: &std::path::Path) -> Config {
        Config {
            host: "127.0.0.1".to_string(),
            port: 0,
            data_dir: dir.to_path_buf(),
            api_key: String::new(),
            allow_insecure_no_auth: false,
            max_upload_bytes: 1024 * 1024,
        }
    }

    #[test]
    fn app_state_new_creates_dirs_and_keypair() {
        let tmp = tempfile::tempdir().unwrap();
        let cfg = test_config(tmp.path());
        let state = AppState::new(cfg).unwrap();
        assert!(state.config.db_path().exists());
        assert!(state.config.blob_dir().exists());
        assert!(state.config.index_dir().exists());
        assert!(state.config.keys_dir().join("registry.key").exists());
        assert!(state.config.keys_dir().join("registry.pub").exists());
        assert_eq!(state.merkle_tree.lock().unwrap().tree_size(), 0);
    }

    #[test]
    fn load_or_generate_keypair_is_stable_across_reloads() {
        let tmp = tempfile::tempdir().unwrap();
        let cfg = test_config(tmp.path());
        std::fs::create_dir_all(cfg.keys_dir()).unwrap();
        let first = load_or_generate_keypair(&cfg).unwrap();
        let second = load_or_generate_keypair(&cfg).unwrap();
        assert_eq!(first.public_key().to_hex(), second.public_key().to_hex());
    }

    #[test]
    fn app_state_new_rejects_non_sequential_leaf_indices() {
        let tmp = tempfile::tempdir().unwrap();
        let cfg = test_config(tmp.path());
        std::fs::create_dir_all(cfg.data_dir.clone()).unwrap();
        std::fs::create_dir_all(cfg.index_dir()).unwrap();
        std::fs::create_dir_all(cfg.keys_dir()).unwrap();

        let db = RegistryDb::open(&cfg.db_path()).unwrap();
        db.upsert_package("pkg", None, "2026-02-28T00:00:00Z")
            .unwrap();
        db.insert_version(&crate::db::VersionRow {
            name: "pkg".into(),
            version: "1.0.0".into(),
            pkg_type: "guard".into(),
            checksum: "abc".into(),
            manifest_toml: "".into(),
            publisher_key: "pk".into(),
            publisher_sig: "sig".into(),
            registry_sig: None,
            dependencies_json: "{}".into(),
            yanked: false,
            published_at: "2026-02-28T00:00:00Z".into(),
            attestation_hash: None,
            key_id: None,
            leaf_index: Some(7),
            download_count: 0,
        })
        .unwrap();
        drop(db);

        let err = AppState::new(cfg)
            .err()
            .expect("non-sequential leaf indices should fail");
        assert!(
            err.to_string().contains("leaf_index sequence mismatch"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn app_state_new_allows_legacy_unindexed_versions_before_indexed_rows() {
        let tmp = tempfile::tempdir().unwrap();
        let cfg = test_config(tmp.path());
        std::fs::create_dir_all(cfg.data_dir.clone()).unwrap();
        std::fs::create_dir_all(cfg.index_dir()).unwrap();
        std::fs::create_dir_all(cfg.keys_dir()).unwrap();

        let db = RegistryDb::open(&cfg.db_path()).unwrap();
        db.upsert_package("legacy", None, "2025-01-01T00:00:00Z")
            .unwrap();
        db.upsert_package("indexed", None, "2025-01-02T00:00:00Z")
            .unwrap();
        db.insert_version(&crate::db::VersionRow {
            name: "legacy".into(),
            version: "0.1.0".into(),
            pkg_type: "guard".into(),
            checksum: "legacy_hash".into(),
            manifest_toml: "".into(),
            publisher_key: "legacy_pk".into(),
            publisher_sig: "sig".into(),
            registry_sig: None,
            dependencies_json: "{}".into(),
            yanked: false,
            published_at: "2025-01-01T00:00:00Z".into(),
            attestation_hash: None,
            key_id: None,
            leaf_index: None,
            download_count: 0,
        })
        .unwrap();
        db.insert_version(&crate::db::VersionRow {
            name: "indexed".into(),
            version: "1.0.0".into(),
            pkg_type: "guard".into(),
            checksum: "indexed_hash".into(),
            manifest_toml: "".into(),
            publisher_key: "indexed_pk".into(),
            publisher_sig: "sig".into(),
            registry_sig: None,
            dependencies_json: "{}".into(),
            yanked: false,
            published_at: "2025-01-02T00:00:00Z".into(),
            attestation_hash: None,
            key_id: None,
            leaf_index: Some(0),
            download_count: 0,
        })
        .unwrap();
        drop(db);

        let state = AppState::new(cfg).expect("legacy unindexed versions should be ignored");
        assert_eq!(state.merkle_tree.lock().unwrap().tree_size(), 1);
    }

    #[cfg(unix)]
    #[test]
    fn load_or_generate_keypair_sets_private_key_mode_600() {
        use std::os::unix::fs::PermissionsExt;

        let tmp = tempfile::tempdir().unwrap();
        let cfg = test_config(tmp.path());
        std::fs::create_dir_all(cfg.keys_dir()).unwrap();
        let _ = load_or_generate_keypair(&cfg).unwrap();
        let mode = std::fs::metadata(cfg.keys_dir().join("registry.key"))
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o600);
    }
}
