//! API key storage and validation

use std::collections::HashMap;
use std::path::Path;
use std::sync::Mutex;

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
    #[error("Database error: {0}")]
    Database(String),
}

/// Storage for API keys (in-memory only).
pub struct AuthStore {
    /// Map from key hash to ApiKey
    keys: RwLock<HashMap<String, ApiKey>>,
    /// Optional pepper resolved at store construction time.
    pepper: Option<Vec<u8>>,
}

impl AuthStore {
    /// Create a new empty auth store
    pub fn new() -> Self {
        Self::with_pepper(current_pepper_from_env())
    }

    /// Create a store with an explicit pepper.
    pub fn with_pepper(pepper: Option<Vec<u8>>) -> Self {
        Self {
            keys: RwLock::new(HashMap::new()),
            pepper,
        }
    }

    /// Compute a stable hash of an API key token.
    ///
    /// If `CLAWDSTRIKE_AUTH_PEPPER` is set (recommended), uses HMAC-SHA256 to make
    /// offline guessing attacks significantly harder if key hashes ever leak.
    ///
    /// If unset, falls back to raw SHA-256.
    pub fn hash_key(key: &str) -> String {
        let pepper = current_pepper_from_env();
        hash_key_with_pepper(key, pepper.as_deref())
    }

    /// Compute a key hash using this store's configured pepper.
    pub fn hash_key_for_token(&self, key: &str) -> String {
        hash_key_with_pepper(key, self.pepper.as_deref())
    }

    /// Add a key to the store
    pub async fn add_key(&self, key: ApiKey) {
        let mut keys = self.keys.write().await;
        keys.insert(key.key_hash.clone(), key);
    }

    /// Validate a raw API key token and return the ApiKey if valid
    pub async fn validate_key(&self, token: &str) -> Result<ApiKey, AuthError> {
        let hash = self.hash_key_for_token(token);
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

fn current_pepper_from_env() -> Option<Vec<u8>> {
    std::env::var("CLAWDSTRIKE_AUTH_PEPPER")
        .ok()
        .filter(|v| !v.is_empty())
        .map(|v| v.into_bytes())
}

// ---------------------------------------------------------------------------
// SQLite-backed durable AuthStore
// ---------------------------------------------------------------------------

const CREATE_API_KEYS_TABLE: &str = r#"
CREATE TABLE IF NOT EXISTS api_keys (
    key_hash    TEXT PRIMARY KEY,
    id          TEXT NOT NULL,
    name        TEXT NOT NULL,
    tier        TEXT,
    scopes      TEXT NOT NULL,
    created_at  TEXT NOT NULL,
    expires_at  TEXT
);
"#;

/// Durable API key store backed by SQLite with an in-memory read cache.
///
/// Writes go to both the in-memory cache and SQLite. Reads are served from the
/// in-memory cache for speed. On construction the cache is populated from SQLite.
pub struct SqliteAuthStore {
    cache: RwLock<HashMap<String, ApiKey>>,
    conn: Mutex<rusqlite::Connection>,
    pepper: Option<Vec<u8>>,
}

impl SqliteAuthStore {
    /// Open (or create) the store at `path`.
    pub fn new(path: impl AsRef<Path>) -> Result<Self, AuthError> {
        Self::new_with_pepper(path, current_pepper_from_env())
    }

    /// Open (or create) the store at `path` with an explicit pepper.
    pub fn new_with_pepper(
        path: impl AsRef<Path>,
        pepper: Option<Vec<u8>>,
    ) -> Result<Self, AuthError> {
        if let Some(parent) = path.as_ref().parent() {
            std::fs::create_dir_all(parent).map_err(|e| AuthError::Database(e.to_string()))?;
        }
        let conn =
            rusqlite::Connection::open(path).map_err(|e| AuthError::Database(e.to_string()))?;
        Self::init(conn, pepper)
    }

    /// Create an in-memory store (useful for tests).
    #[cfg(test)]
    pub fn in_memory() -> Result<Self, AuthError> {
        Self::in_memory_with_pepper(current_pepper_from_env())
    }

    /// Create an in-memory store (useful for tests) with an explicit pepper.
    #[cfg(test)]
    pub fn in_memory_with_pepper(pepper: Option<Vec<u8>>) -> Result<Self, AuthError> {
        let conn = rusqlite::Connection::open_in_memory()
            .map_err(|e| AuthError::Database(e.to_string()))?;
        Self::init(conn, pepper)
    }

    fn init(conn: rusqlite::Connection, pepper: Option<Vec<u8>>) -> Result<Self, AuthError> {
        conn.execute_batch("PRAGMA journal_mode=WAL; PRAGMA synchronous=NORMAL;")
            .map_err(|e| AuthError::Database(e.to_string()))?;
        conn.execute_batch(CREATE_API_KEYS_TABLE)
            .map_err(|e| AuthError::Database(e.to_string()))?;

        // Load all existing keys into the cache.
        let cache = Self::load_all_from_db(&conn)?;

        Ok(Self {
            cache: RwLock::new(cache),
            conn: Mutex::new(conn),
            pepper,
        })
    }

    fn load_all_from_db(conn: &rusqlite::Connection) -> Result<HashMap<String, ApiKey>, AuthError> {
        let mut stmt = conn
            .prepare(
                "SELECT key_hash, id, name, tier, scopes, created_at, expires_at FROM api_keys",
            )
            .map_err(|e| AuthError::Database(e.to_string()))?;

        let mut map = HashMap::new();
        let mut rows = stmt
            .query([])
            .map_err(|e| AuthError::Database(e.to_string()))?;

        while let Some(row) = rows
            .next()
            .map_err(|e| AuthError::Database(e.to_string()))?
        {
            let key = row_to_api_key(row)?;
            map.insert(key.key_hash.clone(), key);
        }

        Ok(map)
    }

    fn load_key_from_db(
        conn: &rusqlite::Connection,
        key_hash: &str,
    ) -> Result<Option<ApiKey>, AuthError> {
        let mut stmt = conn
            .prepare(
                "SELECT key_hash, id, name, tier, scopes, created_at, expires_at FROM api_keys WHERE key_hash = ?1",
            )
            .map_err(|e| AuthError::Database(e.to_string()))?;

        let mut rows = stmt
            .query(rusqlite::params![key_hash])
            .map_err(|e| AuthError::Database(e.to_string()))?;

        if let Some(row) = rows
            .next()
            .map_err(|e| AuthError::Database(e.to_string()))?
        {
            return row_to_api_key(row).map(Some);
        }
        Ok(None)
    }

    fn lock_conn(&self) -> std::sync::MutexGuard<'_, rusqlite::Connection> {
        self.conn.lock().unwrap_or_else(|e| e.into_inner())
    }

    fn persist_key(conn: &rusqlite::Connection, key: &ApiKey) -> Result<(), AuthError> {
        let scopes_json =
            serde_json::to_string(&key.scopes).map_err(|e| AuthError::Database(e.to_string()))?;
        let tier_str = key
            .tier
            .map(|t| serde_json::to_string(&t).unwrap_or_default());
        let created_str = key.created_at.to_rfc3339();
        let expires_str = key.expires_at.map(|e| e.to_rfc3339());

        conn.execute(
            r#"INSERT OR REPLACE INTO api_keys
                (key_hash, id, name, tier, scopes, created_at, expires_at)
            VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)"#,
            rusqlite::params![
                key.key_hash,
                key.id,
                key.name,
                tier_str,
                scopes_json,
                created_str,
                expires_str,
            ],
        )
        .map_err(|e| AuthError::Database(e.to_string()))?;

        Ok(())
    }

    /// Compute a stable hash of an API key token (delegates to `AuthStore::hash_key`).
    pub fn hash_key(key: &str) -> String {
        AuthStore::hash_key(key)
    }

    fn hash_key_for_token(&self, key: &str) -> String {
        hash_key_with_pepper(key, self.pepper.as_deref())
    }

    /// Add a key to the store (persists to SQLite).
    pub async fn add_key(&self, key: ApiKey) -> Result<(), AuthError> {
        {
            let conn = self.lock_conn();
            Self::persist_key(&conn, &key)?;
        }
        let mut cache = self.cache.write().await;
        cache.insert(key.key_hash.clone(), key);
        Ok(())
    }

    /// Validate a raw API key token and return the ApiKey if valid.
    pub async fn validate_key(&self, token: &str) -> Result<ApiKey, AuthError> {
        let hash = self.hash_key_for_token(token);
        let cached = {
            let cache = self.cache.read().await;
            cache.get(&hash).cloned()
        };

        // Always reconcile with SQLite so external key add/remove operations are observed.
        let db_key = {
            let conn = self.lock_conn();
            Self::load_key_from_db(&conn, &hash)?
        };

        let key = match (cached, db_key) {
            (Some(_), Some(db_key)) => {
                let mut cache = self.cache.write().await;
                cache.insert(hash.clone(), db_key.clone());
                db_key
            }
            (Some(_), None) => {
                let mut cache = self.cache.write().await;
                cache.remove(&hash);
                return Err(AuthError::InvalidKey);
            }
            (None, Some(db_key)) => {
                let mut cache = self.cache.write().await;
                cache.insert(hash.clone(), db_key.clone());
                db_key
            }
            (None, None) => return Err(AuthError::InvalidKey),
        };

        if key.is_expired() {
            return Err(AuthError::KeyExpired);
        }

        Ok(key)
    }

    /// Remove a key by its hash (removes from both cache and SQLite).
    pub async fn remove_key(&self, key_hash: &str) -> Result<(), AuthError> {
        {
            let conn = self.lock_conn();
            conn.execute(
                "DELETE FROM api_keys WHERE key_hash = ?1",
                rusqlite::params![key_hash],
            )
            .map_err(|e| AuthError::Database(e.to_string()))?;
        }
        let mut cache = self.cache.write().await;
        cache.remove(key_hash);
        Ok(())
    }

    /// List all keys (for admin purposes).
    pub async fn list_keys(&self) -> Vec<ApiKey> {
        let cache = self.cache.read().await;
        cache.values().cloned().collect()
    }

    /// Get number of keys in the store.
    pub async fn key_count(&self) -> usize {
        let cache = self.cache.read().await;
        cache.len()
    }
}

fn row_to_api_key(row: &rusqlite::Row<'_>) -> Result<ApiKey, AuthError> {
    let key_hash: String = row.get(0).map_err(|e| AuthError::Database(e.to_string()))?;
    let id: String = row.get(1).map_err(|e| AuthError::Database(e.to_string()))?;
    let name: String = row.get(2).map_err(|e| AuthError::Database(e.to_string()))?;
    let tier_str: Option<String> = row.get(3).map_err(|e| AuthError::Database(e.to_string()))?;
    let scopes_json: String = row.get(4).map_err(|e| AuthError::Database(e.to_string()))?;
    let created_str: String = row.get(5).map_err(|e| AuthError::Database(e.to_string()))?;
    let expires_str: Option<String> = row.get(6).map_err(|e| AuthError::Database(e.to_string()))?;

    let tier = tier_str.and_then(|s| serde_json::from_str(&s).ok());
    let scopes = serde_json::from_str(&scopes_json)
        .map_err(|e| AuthError::Database(format!("invalid scopes JSON: {e}")))?;
    let created_at = chrono::DateTime::parse_from_rfc3339(&created_str)
        .map(|dt| dt.with_timezone(&chrono::Utc))
        .map_err(|e| AuthError::Database(format!("invalid created_at: {e}")))?;
    let expires_at = expires_str
        .map(|s| {
            chrono::DateTime::parse_from_rfc3339(&s)
                .map(|dt| dt.with_timezone(&chrono::Utc))
                .map_err(|e| AuthError::Database(format!("invalid expires_at: {e}")))
        })
        .transpose()?;

    Ok(ApiKey {
        id,
        key_hash,
        name,
        tier,
        scopes,
        created_at,
        expires_at,
    })
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
        let store = AuthStore::with_pepper(None);
        let raw_key = "test-api-key-12345";

        let mut scopes = HashSet::new();
        scopes.insert(Scope::Check);

        let key = ApiKey {
            id: "1".to_string(),
            key_hash: store.hash_key_for_token(raw_key),
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
        let store = AuthStore::with_pepper(None);
        let result = store.validate_key("nonexistent").await;
        assert!(matches!(result, Err(AuthError::InvalidKey)));
    }

    #[tokio::test]
    async fn test_auth_store_expired_key() {
        let store = AuthStore::with_pepper(None);
        let raw_key = "expired-key";

        let key = ApiKey {
            id: "1".to_string(),
            key_hash: store.hash_key_for_token(raw_key),
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
        let store = AuthStore::with_pepper(None);
        let raw_key = "removable-key";
        let hash = store.hash_key_for_token(raw_key);

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
        let store = AuthStore::with_pepper(None);

        let key1 = ApiKey {
            id: "1".to_string(),
            key_hash: store.hash_key_for_token("key1"),
            name: "first".to_string(),
            tier: None,
            scopes: HashSet::new(),
            created_at: chrono::Utc::now(),
            expires_at: None,
        };

        let key2 = ApiKey {
            id: "2".to_string(),
            key_hash: store.hash_key_for_token("key2"),
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

    // -----------------------------------------------------------------------
    // SqliteAuthStore tests
    // -----------------------------------------------------------------------

    fn make_test_key(raw_key: &str, name: &str, scopes: HashSet<Scope>) -> ApiKey {
        ApiKey {
            id: uuid::Uuid::new_v4().to_string(),
            key_hash: hash_key_with_pepper(raw_key, None),
            name: name.to_string(),
            tier: None,
            scopes,
            created_at: chrono::Utc::now(),
            expires_at: None,
        }
    }

    #[tokio::test]
    async fn sqlite_auth_store_add_and_validate() {
        let store = SqliteAuthStore::in_memory_with_pepper(None).expect("init");
        let raw = "test-sqlite-key";
        let mut scopes = HashSet::new();
        scopes.insert(Scope::Check);

        let key = make_test_key(raw, "sqlite-test", scopes);
        store.add_key(key).await.expect("add");

        let validated = store.validate_key(raw).await.expect("validate");
        assert_eq!(validated.name, "sqlite-test");
    }

    #[tokio::test]
    async fn sqlite_auth_store_invalid_key() {
        let store = SqliteAuthStore::in_memory_with_pepper(None).expect("init");
        let result = store.validate_key("nonexistent").await;
        assert!(matches!(result, Err(AuthError::InvalidKey)));
    }

    #[tokio::test]
    async fn sqlite_auth_store_expired_key() {
        let store = SqliteAuthStore::in_memory_with_pepper(None).expect("init");
        let raw = "expired-sqlite-key";

        let key = ApiKey {
            id: "1".to_string(),
            key_hash: hash_key_with_pepper(raw, None),
            name: "expired".to_string(),
            tier: None,
            scopes: HashSet::new(),
            created_at: chrono::Utc::now() - chrono::Duration::hours(2),
            expires_at: Some(chrono::Utc::now() - chrono::Duration::hours(1)),
        };

        store.add_key(key).await.expect("add");
        let result = store.validate_key(raw).await;
        assert!(matches!(result, Err(AuthError::KeyExpired)));
    }

    #[tokio::test]
    async fn sqlite_auth_store_remove_key() {
        let store = SqliteAuthStore::in_memory_with_pepper(None).expect("init");
        let raw = "removable-sqlite-key";
        let hash = hash_key_with_pepper(raw, None);

        let key = make_test_key(raw, "removable", HashSet::new());
        store.add_key(key).await.expect("add");
        assert_eq!(store.key_count().await, 1);

        store.remove_key(&hash).await.expect("remove");
        assert_eq!(store.key_count().await, 0);
    }

    #[tokio::test]
    async fn sqlite_auth_store_list_keys() {
        let store = SqliteAuthStore::in_memory_with_pepper(None).expect("init");

        store
            .add_key(make_test_key("k1", "first", HashSet::new()))
            .await
            .expect("add1");
        store
            .add_key(make_test_key("k2", "second", HashSet::new()))
            .await
            .expect("add2");

        let keys = store.list_keys().await;
        assert_eq!(keys.len(), 2);
    }

    #[tokio::test]
    async fn sqlite_auth_store_persistence_across_connections() {
        let dir = tempfile::tempdir().expect("tmpdir");
        let path = dir.path().join("auth.db");

        // Pre-compute hash once so it stays consistent regardless of env var races.
        let stable_hash = hash_key_with_pepper("persist-key", None);
        let mut scopes = HashSet::new();
        scopes.insert(Scope::Admin);

        {
            let store = SqliteAuthStore::new_with_pepper(&path, None).expect("init");
            let key = ApiKey {
                id: "p1".to_string(),
                key_hash: stable_hash.clone(),
                name: "persistent".to_string(),
                tier: None,
                scopes: scopes.clone(),
                created_at: chrono::Utc::now(),
                expires_at: None,
            };
            store.add_key(key).await.expect("add");
            assert_eq!(store.key_count().await, 1);
        }

        // Reopen from the same path: key should still be there.
        {
            let store = SqliteAuthStore::new_with_pepper(&path, None).expect("reopen");
            assert_eq!(store.key_count().await, 1);

            // Look up directly by the pre-computed hash in the cache.
            let keys = store.list_keys().await;
            let key = keys
                .iter()
                .find(|k| k.key_hash == stable_hash)
                .expect("find key");
            assert_eq!(key.name, "persistent");
            assert!(key.has_scope(Scope::Admin));
        }
    }

    #[tokio::test]
    async fn sqlite_auth_store_remove_persists() {
        let dir = tempfile::tempdir().expect("tmpdir");
        let path = dir.path().join("auth.db");

        let stable_hash = hash_key_with_pepper("remove-persist-key", None);

        {
            let store = SqliteAuthStore::new_with_pepper(&path, None).expect("init");
            let key = ApiKey {
                id: "r1".to_string(),
                key_hash: stable_hash.clone(),
                name: "removable".to_string(),
                tier: None,
                scopes: HashSet::new(),
                created_at: chrono::Utc::now(),
                expires_at: None,
            };
            store.add_key(key).await.expect("add");
            store.remove_key(&stable_hash).await.expect("remove");
            assert_eq!(store.key_count().await, 0);
        }

        // Reopen: removed key should still be gone.
        {
            let store = SqliteAuthStore::new_with_pepper(&path, None).expect("reopen");
            assert_eq!(store.key_count().await, 0);
        }
    }

    #[tokio::test]
    async fn sqlite_auth_store_tier_round_trips() {
        let store = SqliteAuthStore::in_memory_with_pepper(None).expect("init");
        let raw = "tier-key";

        let mut scopes = HashSet::new();
        scopes.insert(Scope::Check);

        let key = ApiKey {
            id: "t1".to_string(),
            key_hash: hash_key_with_pepper(raw, None),
            name: "tiered".to_string(),
            tier: Some(crate::auth::ApiKeyTier::Gold),
            scopes,
            created_at: chrono::Utc::now(),
            expires_at: None,
        };

        store.add_key(key).await.expect("add");

        let validated = store.validate_key(raw).await.expect("validate");
        assert_eq!(validated.tier, Some(crate::auth::ApiKeyTier::Gold));
    }

    #[tokio::test]
    async fn sqlite_auth_store_validate_key_refreshes_on_external_insert() {
        let dir = tempfile::tempdir().expect("tmpdir");
        let path = dir.path().join("auth.db");

        let store = SqliteAuthStore::new_with_pepper(&path, None).expect("init");
        let raw = "externally-added";
        let hash = hash_key_with_pepper(raw, None);

        // Simulate another process adding a key directly in SQLite.
        let conn = rusqlite::Connection::open(&path).expect("open sqlite");
        let key = make_test_key(raw, "external", HashSet::new());
        SqliteAuthStore::persist_key(&conn, &key).expect("persist external key");

        // Cache starts stale/missing; validate_key should refresh from DB on miss.
        let validated = store.validate_key(raw).await.expect("validate");
        assert_eq!(validated.key_hash, hash);
        assert_eq!(validated.name, "external");
    }

    #[tokio::test]
    async fn sqlite_auth_store_validate_key_detects_external_delete() {
        let dir = tempfile::tempdir().expect("tmpdir");
        let path = dir.path().join("auth.db");

        let store = SqliteAuthStore::new_with_pepper(&path, None).expect("init");
        let raw = "externally-removed";
        let hash = hash_key_with_pepper(raw, None);
        let key = make_test_key(raw, "victim", HashSet::new());
        store.add_key(key).await.expect("add");
        assert!(store.validate_key(raw).await.is_ok());

        // Simulate another process removing the key directly in SQLite.
        let conn = rusqlite::Connection::open(&path).expect("open sqlite");
        conn.execute(
            "DELETE FROM api_keys WHERE key_hash = ?1",
            rusqlite::params![hash],
        )
        .expect("delete external key");

        // Cached value should be invalidated when DB says key is gone.
        let result = store.validate_key(raw).await;
        assert!(matches!(result, Err(AuthError::InvalidKey)));
    }
}
