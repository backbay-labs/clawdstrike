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

    /// Compute SHA-256 hash of a key
    pub fn hash_key(key: &str) -> String {
        let hash = Sha256::digest(key.as_bytes());
        hex::encode(hash)
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
        assert_eq!(hash1.len(), 64); // SHA-256 = 32 bytes = 64 hex chars
    }

    #[test]
    fn test_hash_key_different_inputs() {
        let hash1 = AuthStore::hash_key("key1");
        let hash2 = AuthStore::hash_key("key2");
        assert_ne!(hash1, hash2);
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
            scopes: HashSet::new(),
            created_at: chrono::Utc::now(),
            expires_at: None,
        };

        let key2 = ApiKey {
            id: "2".to_string(),
            key_hash: AuthStore::hash_key("key2"),
            name: "second".to_string(),
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
