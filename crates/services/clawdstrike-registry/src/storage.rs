//! Content-addressed blob storage for .cpkg archives.

use std::fs;
use std::path::Path;
use std::path::PathBuf;

use crate::error::RegistryError;

/// Filesystem-based content-addressed blob storage.
pub struct BlobStorage {
    root: PathBuf,
}

impl BlobStorage {
    /// Create a new blob storage rooted at the given directory.
    pub fn new(root: PathBuf) -> Result<Self, RegistryError> {
        fs::create_dir_all(&root)?;
        Ok(Self { root })
    }

    /// Store raw bytes and return the SHA-256 hex digest used as the key.
    #[allow(dead_code)]
    pub fn store(&self, data: &[u8]) -> Result<String, RegistryError> {
        let hash = Self::canonical_hash(&hush_core::sha256_hex(data))?;
        self.ensure_parent(&hash)?;
        let blob_path = self.blob_path(&hash);

        if !blob_path.exists() {
            self.write_blob_if_missing(&blob_path, data)?;
        }

        Ok(hash)
    }

    /// Load raw bytes by SHA-256 hex digest.
    pub fn load(&self, hash: &str) -> Result<Vec<u8>, RegistryError> {
        let canonical = Self::canonical_hash(hash)?;
        let blob_path = self.blob_path(&canonical);
        if !blob_path.exists() {
            return Err(RegistryError::NotFound(format!(
                "blob not found: {canonical}"
            )));
        }
        Ok(fs::read(&blob_path)?)
    }

    /// Check if a blob exists.
    #[allow(dead_code)]
    pub fn exists(&self, hash: &str) -> bool {
        Self::canonical_hash(hash)
            .ok()
            .is_some_and(|canonical| self.blob_path(&canonical).exists())
    }

    /// Get the filesystem path for a blob.
    fn blob_path(&self, hash: &str) -> PathBuf {
        // Use a two-level directory structure (first 2 chars / rest) to avoid
        // too many files in a single directory.
        // Hashes are canonicalized as `0x` + 64 hex chars; fan out by the
        // first two digest hex chars (skip the `0x` prefix).
        let digest = hash
            .strip_prefix("0x")
            .or_else(|| hash.strip_prefix("0X"))
            .unwrap_or(hash);
        let (prefix, _rest) = if digest.len() >= 2 {
            digest.split_at(2)
        } else {
            (digest, "")
        };
        self.root.join(prefix).join(hash)
    }

    fn canonical_hash(hash: &str) -> Result<String, RegistryError> {
        let raw = hash
            .strip_prefix("0x")
            .or_else(|| hash.strip_prefix("0X"))
            .unwrap_or(hash);
        if raw.len() != 64 || !raw.as_bytes().iter().all(u8::is_ascii_hexdigit) {
            return Err(RegistryError::BadRequest(
                "invalid blob hash format; expected 0x-prefixed SHA-256 hex".into(),
            ));
        }
        Ok(format!("0x{}", raw.to_ascii_lowercase()))
    }

    /// Ensure the parent directory of a blob exists.
    fn ensure_parent(&self, hash: &str) -> Result<(), RegistryError> {
        let path = self.blob_path(hash);
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        Ok(())
    }

    /// Store with a pre-computed hash (for verified content).
    pub fn store_with_hash(&self, data: &[u8], hash: &str) -> Result<(), RegistryError> {
        let canonical = Self::canonical_hash(hash)?;
        let computed = Self::canonical_hash(&hush_core::sha256_hex(data))?;
        if computed != canonical {
            return Err(RegistryError::Integrity(
                "provided hash does not match payload digest".into(),
            ));
        }

        self.ensure_parent(&canonical)?;
        let blob_path = self.blob_path(&canonical);

        if !blob_path.exists() {
            self.write_blob_if_missing(&blob_path, data)?;
        }

        Ok(())
    }

    fn write_blob_if_missing(&self, blob_path: &Path, data: &[u8]) -> Result<(), RegistryError> {
        let tmp_path = self.root.join(format!(".tmp-{}", uuid::Uuid::new_v4()));
        fs::write(&tmp_path, data)?;
        match fs::rename(&tmp_path, blob_path) {
            Ok(()) => Ok(()),
            Err(err) => {
                let _ = fs::remove_file(&tmp_path);

                // Another writer may have committed the same hash between our
                // pre-check and rename; hash-addressed paths make this safe.
                if blob_path.exists() {
                    Ok(())
                } else {
                    Err(RegistryError::Io(err))
                }
            }
        }
    }

    /// Delete a blob by hash if it exists.
    pub fn delete(&self, hash: &str) -> Result<(), RegistryError> {
        let canonical = Self::canonical_hash(hash)?;
        let blob_path = self.blob_path(&canonical);
        match fs::remove_file(&blob_path) {
            Ok(()) => {
                if let Some(parent) = blob_path.parent() {
                    let _ = fs::remove_dir(parent);
                }
                Ok(())
            }
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(err) => Err(RegistryError::Io(err)),
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Barrier};
    use std::thread;

    #[test]
    fn store_and_load() {
        let tmp = tempfile::tempdir().unwrap();
        let storage = BlobStorage::new(tmp.path().join("blobs")).unwrap();

        let data = b"hello world";
        let hash = storage.store(data).unwrap();
        assert!(!hash.is_empty());
        assert!(storage.exists(&hash));

        let loaded = storage.load(&hash).unwrap();
        assert_eq!(loaded, data);
    }

    #[test]
    fn store_with_hash_and_load() {
        let tmp = tempfile::tempdir().unwrap();
        let storage = BlobStorage::new(tmp.path().join("blobs")).unwrap();

        let data = b"test content";
        let hash = hush_core::sha256_hex(data);
        storage.store_with_hash(data, &hash).unwrap();

        let loaded = storage.load(&hash).unwrap();
        assert_eq!(loaded, data);
    }

    #[test]
    fn load_missing_blob() {
        let tmp = tempfile::tempdir().unwrap();
        let storage = BlobStorage::new(tmp.path().join("blobs")).unwrap();

        let err = storage.load(&"00".repeat(32)).unwrap_err();
        assert!(err.to_string().contains("not found"));
    }

    #[test]
    fn idempotent_store() {
        let tmp = tempfile::tempdir().unwrap();
        let storage = BlobStorage::new(tmp.path().join("blobs")).unwrap();

        let data = b"duplicate";
        let h1 = storage.store(data).unwrap();
        let h2 = storage.store(data).unwrap();
        assert_eq!(h1, h2);
        assert!(h1.starts_with("0x"));
    }

    #[test]
    fn store_with_hash_accepts_uppercase_and_unprefixed_digest() {
        let tmp = tempfile::tempdir().unwrap();
        let storage = BlobStorage::new(tmp.path().join("blobs")).unwrap();

        let data = b"canonical digest";
        let upper_unprefixed = hush_core::sha256_hex(data)
            .trim_start_matches("0x")
            .to_ascii_uppercase();
        storage.store_with_hash(data, &upper_unprefixed).unwrap();
        let loaded = storage.load(&upper_unprefixed).unwrap();
        assert_eq!(loaded, data);
    }

    #[test]
    fn rejects_invalid_hash_format_for_store_and_load() {
        let tmp = tempfile::tempdir().unwrap();
        let storage = BlobStorage::new(tmp.path().join("blobs")).unwrap();

        let err = storage
            .store_with_hash(b"abc", "../../../etc/passwd")
            .unwrap_err();
        assert!(err.to_string().contains("invalid blob hash format"));

        let err = storage.load("../../../etc/passwd").unwrap_err();
        assert!(err.to_string().contains("invalid blob hash format"));
    }

    #[test]
    fn store_with_hash_rejects_digest_mismatch() {
        let tmp = tempfile::tempdir().unwrap();
        let storage = BlobStorage::new(tmp.path().join("blobs")).unwrap();

        let data = b"trusted payload";
        let wrong_hash = hush_core::sha256_hex(b"different payload");
        let err = storage.store_with_hash(data, &wrong_hash).unwrap_err();
        assert!(err.to_string().contains("does not match payload digest"));
        assert!(!storage.exists(&wrong_hash));
    }

    #[test]
    fn delete_removes_blob_and_is_idempotent() {
        let tmp = tempfile::tempdir().unwrap();
        let storage = BlobStorage::new(tmp.path().join("blobs")).unwrap();

        let data = b"delete me";
        let hash = storage.store(data).unwrap();
        assert!(storage.exists(&hash));

        storage.delete(&hash).unwrap();
        assert!(!storage.exists(&hash));

        storage.delete(&hash).unwrap();
    }

    #[test]
    fn blob_path_fanout_uses_digest_prefix_not_0x() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().join("blobs");
        let storage = BlobStorage::new(root.clone()).unwrap();

        let hash = storage.store(b"fanout-check").unwrap();
        let digest = hash.trim_start_matches("0x");
        let expected_prefix = &digest[..2];
        let expected_path = root.join(expected_prefix).join(&hash);

        assert!(expected_path.exists());
        assert!(!root.join("0x").join(&hash).exists());
    }

    #[test]
    fn concurrent_store_with_hash_is_idempotent() {
        let tmp = tempfile::tempdir().unwrap();
        let storage = Arc::new(BlobStorage::new(tmp.path().join("blobs")).unwrap());
        let payload = b"parallel-content".to_vec();
        let hash = hush_core::sha256_hex(&payload);
        let workers = 8usize;
        let barrier = Arc::new(Barrier::new(workers));

        let mut handles = Vec::with_capacity(workers);
        for _ in 0..workers {
            let storage = Arc::clone(&storage);
            let barrier = Arc::clone(&barrier);
            let payload = payload.clone();
            let hash = hash.clone();
            handles.push(thread::spawn(move || {
                barrier.wait();
                storage.store_with_hash(&payload, &hash)
            }));
        }

        for handle in handles {
            handle.join().unwrap().unwrap();
        }

        assert!(storage.exists(&hash));
        assert_eq!(storage.load(&hash).unwrap(), payload);
    }
}
