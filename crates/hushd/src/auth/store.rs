//! API key storage and validation

use std::collections::HashMap;

use sha2::{Digest, Sha256};
use tokio::sync::RwLock;

use super::types::ApiKey;

/// Error types for authentication operations
#[derive(Debug, thiserror::Error)]
pub enum AuthError {
    #[error("Invalid API key")]
    InvalidKey,
    #[error("API key has expired")]
    KeyExpired,
    #[error("Insufficient scope for this operation")]
    InsufficientScope,
}

/// Storage for API keys
pub struct AuthStore {
    /// Map from key hash to ApiKey
    keys: RwLock<HashMap<String, ApiKey>>,
}

impl AuthStore {
    /// Create a new empty auth store
    pub fn new() -> Self {
        Self {
            keys: RwLock::new(HashMap::new()),
        }
    }

    /// Compute a stable hash of an API key token.
    ///
    /// If `HUSHD_AUTH_PEPPER` is set (recommended), uses HMAC-SHA256 to make offline guessing
    /// attacks significantly harder if key hashes ever leak.
    ///
    /// If unset, falls back to raw SHA-256 for backward compatibility.
    pub fn hash_key(key: &str) -> String {
        let pepper = std::env::var("HUSHD_AUTH_PEPPER").ok();
        let pepper = pepper.as_deref().filter(|s| !s.is_empty());
        hash_key_with_pepper(key, pepper.map(|p| p.as_bytes()))
    }

    /// Add a key to the store
    pub async fn add_key(&self, key: ApiKey) {
        let mut keys = self.keys.write().await;
        keys.insert(key.key_hash.clone(), key);
    }

    /// Validate a raw API key token and return the ApiKey if valid
    pub async fn validate_key(&self, token: &str) -> Result<ApiKey, AuthError> {
        let hash = Self::hash_key(token);
        let keys = self.keys.read().await;

        let key = keys.get(&hash).cloned().ok_or(AuthError::InvalidKey)?;

        if key.is_expired() {
            return Err(AuthError::KeyExpired);
        }

        Ok(key)
    }

    /// Remove a key by its hash
    pub async fn remove_key(&self, key_hash: &str) {
        let mut keys = self.keys.write().await;
        keys.remove(key_hash);
    }

    /// List all keys (for admin purposes)
    pub async fn list_keys(&self) -> Vec<ApiKey> {
        let keys = self.keys.read().await;
        keys.values().cloned().collect()
    }

    /// Get number of keys in the store
    pub async fn key_count(&self) -> usize {
        let keys = self.keys.read().await;
        keys.len()
    }
}

fn hash_key_with_pepper(key: &str, pepper: Option<&[u8]>) -> String {
    let digest: [u8; 32] = match pepper {
        Some(pepper) => hmac_sha256(pepper, key.as_bytes()),
        None => Sha256::digest(key.as_bytes()).into(),
    };
    hex::encode(digest)
}

fn hmac_sha256(key: &[u8], message: &[u8]) -> [u8; 32] {
    // HMAC-SHA256 as defined in RFC 2104.
    const BLOCK_SIZE: usize = 64;

    let mut key_block = [0u8; BLOCK_SIZE];
    if key.len() > BLOCK_SIZE {
        let hashed = Sha256::digest(key);
        key_block[..hashed.len()].copy_from_slice(&hashed);
    } else {
        key_block[..key.len()].copy_from_slice(key);
    }

    let mut ipad = [0u8; BLOCK_SIZE];
    let mut opad = [0u8; BLOCK_SIZE];
    for i in 0..BLOCK_SIZE {
        ipad[i] = key_block[i] ^ 0x36;
        opad[i] = key_block[i] ^ 0x5c;
    }

    let mut inner = Sha256::new();
    inner.update(ipad);
    inner.update(message);
    let inner = inner.finalize();

    let mut outer = Sha256::new();
    outer.update(opad);
    outer.update(inner);
    outer.finalize().into()
}

impl Default for AuthStore {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;

    use super::*;
    use crate::auth::Scope;

    #[test]
    fn test_hash_key_deterministic() {
        let key = "my-secret-key-12345";
        let hash1 = AuthStore::hash_key(key);
        let hash2 = AuthStore::hash_key(key);
        assert_eq!(hash1, hash2);
        assert_eq!(hash1.len(), 64); // 32-byte digest = 64 hex chars
    }

    #[test]
    fn test_hash_key_different_inputs() {
        let hash1 = AuthStore::hash_key("key1");
        let hash2 = AuthStore::hash_key("key2");
        assert_ne!(hash1, hash2);
    }

    #[test]
    fn test_hash_key_pepper_changes_digest() {
        let a = hash_key_with_pepper("token", Some(b"pepper-a"));
        let b = hash_key_with_pepper("token", Some(b"pepper-b"));
        assert_ne!(a, b);
    }

    #[tokio::test]
    async fn test_auth_store_add_and_validate() {
        let store = AuthStore::new();
        let raw_key = "test-api-key-12345";

        let mut scopes = HashSet::new();
        scopes.insert(Scope::Check);

        let key = ApiKey {
            id: "1".to_string(),
            key_hash: AuthStore::hash_key(raw_key),
            name: "test".to_string(),
            tier: None,
            scopes,
            created_at: chrono::Utc::now(),
            expires_at: None,
        };

        store.add_key(key.clone()).await;

        let result = store.validate_key(raw_key).await;
        assert!(result.is_ok());
        assert_eq!(result.unwrap().name, "test");
    }

    #[tokio::test]
    async fn test_auth_store_invalid_key() {
        let store = AuthStore::new();
        let result = store.validate_key("nonexistent").await;
        assert!(matches!(result, Err(AuthError::InvalidKey)));
    }

    #[tokio::test]
    async fn test_auth_store_expired_key() {
        let store = AuthStore::new();
        let raw_key = "expired-key";

        let key = ApiKey {
            id: "1".to_string(),
            key_hash: AuthStore::hash_key(raw_key),
            name: "expired".to_string(),
            tier: None,
            scopes: HashSet::new(),
            created_at: chrono::Utc::now() - chrono::Duration::hours(2),
            expires_at: Some(chrono::Utc::now() - chrono::Duration::hours(1)),
        };

        store.add_key(key).await;

        let result = store.validate_key(raw_key).await;
        assert!(matches!(result, Err(AuthError::KeyExpired)));
    }

    #[tokio::test]
    async fn test_auth_store_remove_key() {
        let store = AuthStore::new();
        let raw_key = "removable-key";
        let hash = AuthStore::hash_key(raw_key);

        let key = ApiKey {
            id: "1".to_string(),
            key_hash: hash.clone(),
            name: "removable".to_string(),
            tier: None,
            scopes: HashSet::new(),
            created_at: chrono::Utc::now(),
            expires_at: None,
        };

        store.add_key(key).await;
        assert_eq!(store.key_count().await, 1);

        store.remove_key(&hash).await;
        assert_eq!(store.key_count().await, 0);
    }

    #[tokio::test]
    async fn test_auth_store_list_keys() {
        let store = AuthStore::new();

        let key1 = ApiKey {
            id: "1".to_string(),
            key_hash: AuthStore::hash_key("key1"),
            name: "first".to_string(),
            tier: None,
            scopes: HashSet::new(),
            created_at: chrono::Utc::now(),
            expires_at: None,
        };

        let key2 = ApiKey {
            id: "2".to_string(),
            key_hash: AuthStore::hash_key("key2"),
            name: "second".to_string(),
            tier: None,
            scopes: HashSet::new(),
            created_at: chrono::Utc::now(),
            expires_at: None,
        };

        store.add_key(key1).await;
        store.add_key(key2).await;

        let keys = store.list_keys().await;
        assert_eq!(keys.len(), 2);
    }
}
