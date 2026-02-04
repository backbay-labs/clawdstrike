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
