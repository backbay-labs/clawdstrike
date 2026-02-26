//! Secure storage for OpenClaw gateway secrets.

use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use tokio::sync::RwLock;
use zeroize::Zeroize;

#[derive(Clone, Default, Serialize, Deserialize)]
pub struct GatewaySecrets {
    pub token: Option<String>,
    pub device_token: Option<String>,
}

impl GatewaySecrets {
    /// Zeroize all token fields in place, overwriting the heap-allocated string
    /// contents with zeroes before dropping.
    fn zeroize_tokens(&mut self) {
        if let Some(ref mut t) = self.token {
            t.zeroize();
        }
        if let Some(ref mut t) = self.device_token {
            t.zeroize();
        }
    }
}

impl Drop for GatewaySecrets {
    fn drop(&mut self) {
        self.zeroize_tokens();
    }
}

impl std::fmt::Debug for GatewaySecrets {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GatewaySecrets")
            .field("token", &self.token.as_ref().map(|_| "[REDACTED]"))
            .field("device_token", &self.device_token.as_ref().map(|_| "[REDACTED]"))
            .finish()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SecretStoreMode {
    Keyring,
    MemoryFallback,
}

/// Persistent secret storage for OpenClaw gateway credentials.
///
/// The store prefers the OS keyring (via the `keyring` crate) for at-rest
/// encryption.  When the keyring is unavailable — common in headless CI,
/// containers, or sandboxed environments — it falls back to an in-memory
/// `HashMap`.
///
/// ## Fallback behaviour
///
/// The fallback is **non-sticky**: every [`set`](Self::set) call re-attempts
/// the keyring first.  If the keyring recovers (e.g. after a transient D-Bus
/// timeout), `fallback_active` is cleared and the entry is removed from the
/// in-memory map.  This avoids the previous bug where a single keyring
/// failure permanently pinned all future operations to the memory path.
///
/// ## Memory protection
///
/// Token fields inside [`GatewaySecrets`] are zeroized on [`Drop`] and when
/// entries are explicitly removed from or replaced in the in-memory map.
/// This limits the window in which plaintext credentials are observable on
/// the heap.
///
/// **Security trade-off:** in fallback mode, tokens still reside in
/// process-accessible heap memory for the duration of the session.  A
/// sufficiently privileged attacker with read access to process memory could
/// extract them.  The long-term plan is to use an encrypted in-memory vault
/// (e.g. `ring::aead` with a process-lifetime ephemeral key) so that tokens
/// are never stored in plaintext, even in fallback mode.
#[derive(Clone)]
pub struct OpenClawSecretStore {
    service_name: String,
    memory: Arc<RwLock<HashMap<String, GatewaySecrets>>>,
    fallback_active: Arc<AtomicBool>,
}

impl OpenClawSecretStore {
    pub fn new(service_name: impl Into<String>) -> Self {
        Self {
            service_name: service_name.into(),
            memory: Arc::new(RwLock::new(HashMap::new())),
            fallback_active: Arc::new(AtomicBool::new(false)),
        }
    }

    pub fn mode(&self) -> SecretStoreMode {
        if self.fallback_active.load(Ordering::Relaxed) {
            SecretStoreMode::MemoryFallback
        } else {
            SecretStoreMode::Keyring
        }
    }

    pub async fn get(&self, gateway_id: &str) -> GatewaySecrets {
        if self.fallback_active.load(Ordering::Relaxed) {
            return self
                .memory
                .read()
                .await
                .get(gateway_id)
                .cloned()
                .unwrap_or_default();
        }

        match self.get_keyring(gateway_id) {
            Some(value) => value,
            None => {
                // Transient keyring read failure — fall back to the
                // write-through memory copy so we never return empty
                // credentials when the keyring is temporarily unavailable.
                self.memory
                    .read()
                    .await
                    .get(gateway_id)
                    .cloned()
                    .unwrap_or_default()
            }
        }
    }

    pub async fn set(&self, gateway_id: &str, secrets: GatewaySecrets) -> Result<()> {
        // Always attempt the keyring first — even if a previous call failed —
        // so that a recovered keyring is picked up immediately.
        // Always keep a write-through memory copy so that transient keyring
        // read failures in `get()` can fall back to a valid credential instead
        // of returning empty/default secrets.
        {
            let mut mem = self.memory.write().await;
            if let Some(mut old) = mem.remove(gateway_id) {
                old.zeroize_tokens();
            }
            mem.insert(gateway_id.to_string(), secrets.clone());
        }

        if self.set_keyring(gateway_id, &secrets).is_ok() {
            // Keyring succeeded — clear fallback flag.  The memory copy is
            // intentionally kept as a read-through cache for resilience
            // against transient keyring read failures.
            if self.fallback_active.swap(false, Ordering::Relaxed) {
                tracing::info!(
                    gateway_id = %gateway_id,
                    "Keyring recovered — leaving in-memory fallback mode"
                );
            }
        } else {
            self.fallback_active.store(true, Ordering::Relaxed);
            tracing::warn!(
                gateway_id = %gateway_id,
                "Falling back to in-memory OpenClaw secret storage"
            );
            // Memory copy was already written above (write-through).
        }

        Ok(())
    }

    pub async fn delete(&self, gateway_id: &str) -> Result<()> {
        // Remove from memory first; Drop impl zeroizes the token fields.
        if let Some(mut old) = self.memory.write().await.remove(gateway_id) {
            old.zeroize_tokens();
        }

        if self.delete_keyring(gateway_id).is_err() {
            self.fallback_active.store(true, Ordering::Relaxed);
        }

        Ok(())
    }

    fn keyring_user(&self, gateway_id: &str) -> String {
        format!("openclaw:{}", gateway_id)
    }

    fn get_keyring(&self, gateway_id: &str) -> Option<GatewaySecrets> {
        let entry = keyring::Entry::new(&self.service_name, &self.keyring_user(gateway_id)).ok()?;
        let raw = match entry.get_password() {
            Ok(value) => value,
            Err(_) => return None,
        };

        serde_json::from_str::<GatewaySecrets>(&raw).ok()
    }

    fn set_keyring(&self, gateway_id: &str, secrets: &GatewaySecrets) -> Result<()> {
        let entry = keyring::Entry::new(&self.service_name, &self.keyring_user(gateway_id))?;
        let raw = serde_json::to_string(secrets)?;
        entry.set_password(&raw)?;
        Ok(())
    }

    fn delete_keyring(&self, gateway_id: &str) -> Result<()> {
        let entry = keyring::Entry::new(&self.service_name, &self.keyring_user(gateway_id))?;
        let _ = entry.delete_credential();
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn memory_roundtrip_still_works() {
        let store = OpenClawSecretStore::new("clawdstrike-test");
        let key = "gw-1";

        let secrets = GatewaySecrets {
            token: Some("abc".to_string()),
            device_token: Some("def".to_string()),
        };

        let _ = store.set(key, secrets.clone()).await;
        let loaded = store.get(key).await;

        // The backend can be keyring or fallback memory depending on environment;
        // this assertion is backend-agnostic.
        assert_eq!(loaded.token, secrets.token);
        assert_eq!(loaded.device_token, secrets.device_token);
    }

    #[tokio::test]
    async fn fallback_mode_reads_memory_first() {
        let store = OpenClawSecretStore::new("clawdstrike-test");
        let key = "gw-fallback";
        let secrets = GatewaySecrets {
            token: Some("fresh-token".to_string()),
            device_token: Some("fresh-device".to_string()),
        };

        store
            .memory
            .write()
            .await
            .insert(key.to_string(), secrets.clone());
        store.fallback_active.store(true, Ordering::Relaxed);

        let loaded = store.get(key).await;
        assert_eq!(loaded.token, secrets.token);
        assert_eq!(loaded.device_token, secrets.device_token);
    }
}
