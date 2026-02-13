//! SQLite-backed control-plane state (sessions, RBAC, scoped policies, ...).

mod schema;

use std::path::Path;
use std::sync::Mutex;

use rusqlite::Connection;

/// Error type for control DB operations.
#[derive(Debug, thiserror::Error)]
pub enum ControlDbError {
    #[error("database error: {0}")]
    Database(#[from] rusqlite::Error),
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
}

pub type Result<T> = std::result::Result<T, ControlDbError>;

pub struct ControlDb {
    conn: Mutex<Connection>,
}

impl ControlDb {
    pub fn new(path: impl AsRef<Path>) -> Result<Self> {
        if let Some(parent) = path.as_ref().parent() {
            std::fs::create_dir_all(parent)?;
        }

        let conn = Connection::open(path)?;
        conn.execute_batch("PRAGMA journal_mode=WAL; PRAGMA synchronous=NORMAL;")?;
        conn.execute_batch(schema::CREATE_TABLES)?;

        Ok(Self {
            conn: Mutex::new(conn),
        })
    }

    #[cfg(test)]
    pub fn in_memory() -> Result<Self> {
        let conn = Connection::open_in_memory()?;
        conn.execute_batch(schema::CREATE_TABLES)?;
        Ok(Self {
            conn: Mutex::new(conn),
        })
    }

    pub fn lock_conn(&self) -> std::sync::MutexGuard<'_, Connection> {
        self.conn.lock().unwrap_or_else(|err| err.into_inner())
    }

    /// Spawn a blocking DB operation on the tokio blocking pool.
    ///
    /// Requires an `Arc<ControlDb>` so the DB handle can be moved to the blocking thread.
    pub async fn spawn_blocking<F, T>(
        self: &std::sync::Arc<Self>,
        f: F,
    ) -> std::result::Result<T, ControlDbError>
    where
        F: FnOnce(&Connection) -> std::result::Result<T, ControlDbError> + Send + 'static,
        T: Send + 'static,
    {
        let db = self.clone();
        tokio::task::spawn_blocking(move || {
            let conn = db.lock_conn();
            f(&conn)
        })
        .await
        .map_err(|e| ControlDbError::Io(std::io::Error::other(e)))?
    }
}
