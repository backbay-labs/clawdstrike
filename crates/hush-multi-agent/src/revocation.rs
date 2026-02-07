use std::collections::HashMap;
use std::sync::Mutex;

use crate::error::{Error, Result};

pub trait RevocationStore: Send + Sync {
    fn is_revoked(&self, token_id: &str, now_unix: i64) -> bool;
    fn revoke(&self, token_id: String, until_unix: Option<i64>);

    /// Replay protection helper: returns `Ok(())` if the nonce is new, else `Err(Replay)`.
    fn check_and_mark_nonce(
        &self,
        scope: &str,
        nonce: &str,
        now_unix: i64,
        ttl_secs: i64,
    ) -> Result<()>;
}

/// Simple in-memory implementation (best-effort; not durable).
pub struct InMemoryRevocationStore {
    revoked: Mutex<HashMap<String, Option<i64>>>,
    nonces: Mutex<HashMap<String, i64>>,
}

impl Default for InMemoryRevocationStore {
    fn default() -> Self {
        Self {
            revoked: Mutex::new(HashMap::new()),
            nonces: Mutex::new(HashMap::new()),
        }
    }
}

impl InMemoryRevocationStore {
    fn lock_revoked(&self) -> std::sync::MutexGuard<'_, HashMap<String, Option<i64>>> {
        self.revoked.lock().unwrap_or_else(|e| e.into_inner())
    }

    fn lock_nonces(&self) -> std::sync::MutexGuard<'_, HashMap<String, i64>> {
        self.nonces.lock().unwrap_or_else(|e| e.into_inner())
    }

    fn prune_nonces_locked(nonces: &mut HashMap<String, i64>, now_unix: i64) {
        nonces.retain(|_, exp| *exp > now_unix);
    }
}

impl RevocationStore for InMemoryRevocationStore {
    fn is_revoked(&self, token_id: &str, now_unix: i64) -> bool {
        let mut revoked = self.lock_revoked();
        match revoked.get(token_id).copied() {
            Some(None) => true,
            Some(Some(until)) => {
                if now_unix < until {
                    true
                } else {
                    // Expired revocation.
                    revoked.remove(token_id);
                    false
                }
            }
            None => false,
        }
    }

    fn revoke(&self, token_id: String, until_unix: Option<i64>) {
        let mut revoked = self.lock_revoked();
        revoked.insert(token_id, until_unix);
    }

    fn check_and_mark_nonce(
        &self,
        scope: &str,
        nonce: &str,
        now_unix: i64,
        ttl_secs: i64,
    ) -> Result<()> {
        if ttl_secs <= 0 {
            return Err(Error::InvalidClaims("ttl_secs must be > 0".to_string()));
        }

        let key = format!("{scope}:{nonce}");
        let mut nonces = self.lock_nonces();
        Self::prune_nonces_locked(&mut nonces, now_unix);

        if nonces.contains_key(&key) {
            return Err(Error::Replay);
        }

        nonces.insert(key, now_unix + ttl_secs);
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// SQLite-backed durable RevocationStore
// ---------------------------------------------------------------------------

#[cfg(feature = "sqlite")]
mod sqlite_store {
    use std::path::Path;
    use std::sync::Mutex;

    use rusqlite::Connection;

    use super::RevocationStore;
    use crate::error::{Error, Result};

    const DEFAULT_MAX_REVOCATIONS: usize = 100_000;
    const DEFAULT_MAX_NONCES: usize = 100_000;

    const CREATE_TABLES: &str = r#"
CREATE TABLE IF NOT EXISTS revocations (
    token_id   TEXT PRIMARY KEY,
    until_unix INTEGER
);

CREATE TABLE IF NOT EXISTS nonces (
    nonce_key  TEXT PRIMARY KEY,
    expires_at INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_nonces_expires ON nonces (expires_at);
CREATE INDEX IF NOT EXISTS idx_revocations_until ON revocations (until_unix);
"#;

    /// Durable SQLite-backed revocation + nonce store.
    pub struct SqliteRevocationStore {
        conn: Mutex<Connection>,
        max_revocations: usize,
        max_nonces: usize,
    }

    impl SqliteRevocationStore {
        /// Open (or create) the store at `path`.
        pub fn new(path: impl AsRef<Path>) -> Result<Self> {
            if let Some(parent) = path.as_ref().parent() {
                std::fs::create_dir_all(parent).map_err(|e| Error::Database(e.to_string()))?;
            }
            let conn = Connection::open(path).map_err(|e| Error::Database(e.to_string()))?;
            Self::init(conn)
        }

        /// Create an in-memory store (useful for tests).
        #[cfg(test)]
        pub fn in_memory() -> Result<Self> {
            let conn = Connection::open_in_memory().map_err(|e| Error::Database(e.to_string()))?;
            Self::init(conn)
        }

        fn init(conn: Connection) -> Result<Self> {
            conn.execute_batch("PRAGMA journal_mode=WAL; PRAGMA synchronous=NORMAL;")
                .map_err(|e| Error::Database(e.to_string()))?;
            conn.execute_batch(CREATE_TABLES)
                .map_err(|e| Error::Database(e.to_string()))?;
            Ok(Self {
                conn: Mutex::new(conn),
                max_revocations: DEFAULT_MAX_REVOCATIONS,
                max_nonces: DEFAULT_MAX_NONCES,
            })
        }

        /// Override the maximum number of revocation entries (default 100 000).
        pub fn with_max_revocations(mut self, max: usize) -> Self {
            self.max_revocations = max;
            self
        }

        /// Override the maximum number of nonce entries (default 100 000).
        pub fn with_max_nonces(mut self, max: usize) -> Self {
            self.max_nonces = max;
            self
        }

        fn lock_conn(&self) -> std::sync::MutexGuard<'_, Connection> {
            self.conn.lock().unwrap_or_else(|e| e.into_inner())
        }

        /// Return the number of revocation entries (for testing / monitoring).
        pub fn revocation_count(&self) -> Result<usize> {
            let conn = self.lock_conn();
            let count: i64 = conn
                .query_row("SELECT COUNT(*) FROM revocations", [], |row| row.get(0))
                .map_err(|e| Error::Database(e.to_string()))?;
            Ok(count as usize)
        }

        /// Return the number of nonce entries (for testing / monitoring).
        pub fn nonce_count(&self) -> Result<usize> {
            let conn = self.lock_conn();
            let count: i64 = conn
                .query_row("SELECT COUNT(*) FROM nonces", [], |row| row.get(0))
                .map_err(|e| Error::Database(e.to_string()))?;
            Ok(count as usize)
        }

        /// Remove expired nonces from the table.
        fn prune_nonces(
            conn: &Connection,
            now_unix: i64,
        ) -> std::result::Result<(), rusqlite::Error> {
            conn.execute(
                "DELETE FROM nonces WHERE expires_at <= ?1",
                rusqlite::params![now_unix],
            )?;
            Ok(())
        }

        /// Remove expired time-limited revocations.
        fn prune_revocations(
            conn: &Connection,
            now_unix: i64,
        ) -> std::result::Result<(), rusqlite::Error> {
            conn.execute(
                "DELETE FROM revocations WHERE until_unix IS NOT NULL AND until_unix <= ?1",
                rusqlite::params![now_unix],
            )?;
            Ok(())
        }

        /// Enforce capacity limit by dropping the oldest entries when the table exceeds `max`.
        fn enforce_limit(
            conn: &Connection,
            table: &str,
            key_col: &str,
            order_by: &str,
            max: usize,
        ) -> std::result::Result<(), rusqlite::Error> {
            let count: i64 =
                conn.query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |row| {
                    row.get(0)
                })?;
            if (count as usize) > max {
                let excess = count as usize - max;
                conn.execute(
                    &format!(
                        "DELETE FROM {table} WHERE {key_col} IN (SELECT {key_col} FROM {table} ORDER BY {order_by} LIMIT ?1)"
                    ),
                    rusqlite::params![excess as i64],
                )?;
            }
            Ok(())
        }
    }

    impl RevocationStore for SqliteRevocationStore {
        fn is_revoked(&self, token_id: &str, now_unix: i64) -> bool {
            let conn = self.lock_conn();

            // Prune expired revocations opportunistically.
            let _ = Self::prune_revocations(&conn, now_unix);

            let result: std::result::Result<Option<Option<i64>>, _> = conn
                .query_row(
                    "SELECT until_unix FROM revocations WHERE token_id = ?1",
                    rusqlite::params![token_id],
                    |row| row.get::<_, Option<i64>>(0),
                )
                .optional();

            match result {
                Ok(Some(Some(until))) => now_unix < until,
                Ok(Some(None)) => true, // permanent revocation (until_unix IS NULL)
                Ok(None) => false,      // row not found
                Err(_) => {
                    // Fail closed: treat DB errors as revoked.
                    true
                }
            }
        }

        fn revoke(&self, token_id: String, until_unix: Option<i64>) {
            let conn = self.lock_conn();
            let _ = conn.execute(
                "INSERT OR REPLACE INTO revocations (token_id, until_unix) VALUES (?1, ?2)",
                rusqlite::params![token_id, until_unix],
            );
            let _ = Self::enforce_limit(
                &conn,
                "revocations",
                "token_id",
                "(until_unix IS NULL) ASC, until_unix ASC, rowid ASC",
                self.max_revocations,
            );
        }

        fn check_and_mark_nonce(
            &self,
            scope: &str,
            nonce: &str,
            now_unix: i64,
            ttl_secs: i64,
        ) -> Result<()> {
            if ttl_secs <= 0 {
                return Err(Error::InvalidClaims("ttl_secs must be > 0".to_string()));
            }

            let key = format!("{scope}:{nonce}");
            let conn = self.lock_conn();

            Self::prune_nonces(&conn, now_unix).map_err(|e| Error::Database(e.to_string()))?;

            // Check if nonce already exists (and is still live).
            let exists: bool = conn
                .query_row(
                    "SELECT 1 FROM nonces WHERE nonce_key = ?1 AND expires_at > ?2",
                    rusqlite::params![key, now_unix],
                    |_| Ok(true),
                )
                .optional()
                .map_err(|e| Error::Database(e.to_string()))?
                .unwrap_or(false);

            if exists {
                return Err(Error::Replay);
            }

            conn.execute(
                "INSERT OR REPLACE INTO nonces (nonce_key, expires_at) VALUES (?1, ?2)",
                rusqlite::params![key, now_unix + ttl_secs],
            )
            .map_err(|e| Error::Database(e.to_string()))?;

            Self::enforce_limit(
                &conn,
                "nonces",
                "nonce_key",
                "expires_at ASC, rowid ASC",
                self.max_nonces,
            )
            .map_err(|e| Error::Database(e.to_string()))?;

            Ok(())
        }
    }

    /// Extension trait to convert rusqlite optional results.
    trait OptionalExt<T> {
        fn optional(self) -> std::result::Result<Option<T>, rusqlite::Error>;
    }

    impl<T> OptionalExt<T> for std::result::Result<T, rusqlite::Error> {
        fn optional(self) -> std::result::Result<Option<T>, rusqlite::Error> {
            match self {
                Ok(v) => Ok(Some(v)),
                Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
                Err(e) => Err(e),
            }
        }
    }
}

#[cfg(feature = "sqlite")]
pub use sqlite_store::SqliteRevocationStore;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn in_memory_basic_revoke_and_check() {
        let store = InMemoryRevocationStore::default();
        assert!(!store.is_revoked("tok-1", 1000));

        store.revoke("tok-1".to_string(), None);
        assert!(store.is_revoked("tok-1", 1000));
        assert!(store.is_revoked("tok-1", 9999));
    }

    #[test]
    fn in_memory_timed_revocation_expires() {
        let store = InMemoryRevocationStore::default();
        store.revoke("tok-2".to_string(), Some(2000));
        assert!(store.is_revoked("tok-2", 1000));
        assert!(!store.is_revoked("tok-2", 2001));
    }

    #[test]
    fn in_memory_nonce_replay() {
        let store = InMemoryRevocationStore::default();
        store
            .check_and_mark_nonce("scope", "n1", 1000, 60)
            .expect("first use ok");

        let err = store
            .check_and_mark_nonce("scope", "n1", 1010, 60)
            .expect_err("replay");
        assert!(matches!(err, Error::Replay));
    }

    #[test]
    fn in_memory_nonce_reuse_after_ttl() {
        let store = InMemoryRevocationStore::default();
        store
            .check_and_mark_nonce("scope", "n1", 1000, 60)
            .expect("first use ok");

        // After TTL expires, the nonce can be reused.
        store
            .check_and_mark_nonce("scope", "n1", 1061, 60)
            .expect("reuse after expiry ok");
    }
}

#[cfg(all(test, feature = "sqlite"))]
mod sqlite_tests {
    use super::*;

    #[test]
    fn sqlite_basic_revoke_and_check() {
        let store = SqliteRevocationStore::in_memory().expect("init");
        assert!(!store.is_revoked("tok-1", 1000));

        store.revoke("tok-1".to_string(), None);
        assert!(store.is_revoked("tok-1", 1000));
        assert!(store.is_revoked("tok-1", 9999));
    }

    #[test]
    fn sqlite_timed_revocation_expires() {
        let store = SqliteRevocationStore::in_memory().expect("init");
        store.revoke("tok-2".to_string(), Some(2000));
        assert!(store.is_revoked("tok-2", 1000));
        assert!(!store.is_revoked("tok-2", 2001));
    }

    #[test]
    fn sqlite_nonce_replay() {
        let store = SqliteRevocationStore::in_memory().expect("init");
        store
            .check_and_mark_nonce("scope", "n1", 1000, 60)
            .expect("first use ok");

        let err = store
            .check_and_mark_nonce("scope", "n1", 1010, 60)
            .expect_err("replay");
        assert!(matches!(err, Error::Replay));
    }

    #[test]
    fn sqlite_nonce_reuse_after_ttl() {
        let store = SqliteRevocationStore::in_memory().expect("init");
        store
            .check_and_mark_nonce("scope", "n1", 1000, 60)
            .expect("first use ok");

        store
            .check_and_mark_nonce("scope", "n1", 1061, 60)
            .expect("reuse after expiry ok");
    }

    #[test]
    fn sqlite_capacity_limit_revocations() {
        let store = SqliteRevocationStore::in_memory()
            .expect("init")
            .with_max_revocations(5);

        for i in 0..10 {
            store.revoke(format!("tok-{i}"), None);
        }

        let count = store.revocation_count().expect("count");
        assert!(count <= 5, "expected <= 5, got {count}");
    }

    #[test]
    fn sqlite_capacity_limit_nonces() {
        let store = SqliteRevocationStore::in_memory()
            .expect("init")
            .with_max_nonces(5);

        for i in 0..10 {
            store
                .check_and_mark_nonce("scope", &format!("n-{i}"), 1000, 600)
                .expect("mark nonce");
        }

        let count = store.nonce_count().expect("count");
        assert!(count <= 5, "expected <= 5, got {count}");
    }

    #[test]
    fn sqlite_capacity_limit_nonces_evicts_earliest_expiry() {
        let store = SqliteRevocationStore::in_memory()
            .expect("init")
            .with_max_nonces(1);

        store
            .check_and_mark_nonce("scope", "z-old", 1000, 30)
            .expect("insert first");
        store
            .check_and_mark_nonce("scope", "a-new", 1000, 120)
            .expect("insert second");

        store
            .check_and_mark_nonce("scope", "z-old", 1001, 30)
            .expect("earliest-expiry nonce should have been evicted");
        let err = store
            .check_and_mark_nonce("scope", "a-new", 1001, 30)
            .expect_err("newer nonce should still be present");
        assert!(matches!(err, Error::Replay));
    }

    #[test]
    fn sqlite_capacity_limit_revocations_evicts_smallest_until_first() {
        let store = SqliteRevocationStore::in_memory()
            .expect("init")
            .with_max_revocations(1);

        store.revoke("z-old".to_string(), Some(2000));
        store.revoke("a-new".to_string(), Some(3000));

        assert!(
            !store.is_revoked("z-old", 1000),
            "older/smaller-until revocation should be evicted first"
        );
        assert!(store.is_revoked("a-new", 1000));
    }

    #[test]
    fn sqlite_invalid_ttl_rejected() {
        let store = SqliteRevocationStore::in_memory().expect("init");
        let err = store
            .check_and_mark_nonce("scope", "n1", 1000, 0)
            .expect_err("invalid ttl");
        assert!(matches!(err, Error::InvalidClaims(_)));
    }

    #[test]
    fn sqlite_persistence_across_connections() {
        let dir = tempfile::tempdir().expect("tmpdir");
        let path = dir.path().join("revocation.db");

        {
            let store = SqliteRevocationStore::new(&path).expect("init");
            store.revoke("tok-persist".to_string(), None);
            store
                .check_and_mark_nonce("scope", "n-persist", 1000, 600)
                .expect("mark nonce");
        }

        // Reopen from the same path.
        {
            let store = SqliteRevocationStore::new(&path).expect("reopen");
            assert!(store.is_revoked("tok-persist", 1000));

            let err = store
                .check_and_mark_nonce("scope", "n-persist", 1010, 600)
                .expect_err("replay after reopen");
            assert!(matches!(err, Error::Replay));
        }
    }
}
