//! Secure storage for OpenClaw gateway secrets.

use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use tokio::sync::RwLock;

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct GatewaySecrets {
    pub token: Option<String>,
    pub device_token: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SecretStoreMode {
    Keyring,
    MemoryFallback,
}

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

        if let Some(value) = self.get_keyring(gateway_id) {
            return value;
        }

        self.memory
            .read()
            .await
            .get(gateway_id)
            .cloned()
            .unwrap_or_default()
    }

    pub async fn set(&self, gateway_id: &str, secrets: GatewaySecrets) -> Result<()> {
        if self.set_keyring(gateway_id, &secrets).is_err() {
            self.fallback_active.store(true, Ordering::Relaxed);
            tracing::warn!(
                gateway_id = %gateway_id,
                "Falling back to in-memory OpenClaw secret storage"
            );
        }

        // Keep an in-memory mirror so transient keyring read failures do not drop active sessions.
        self.memory
            .write()
            .await
            .insert(gateway_id.to_string(), secrets);

        Ok(())
    }

    pub async fn delete(&self, gateway_id: &str) -> Result<()> {
        self.memory.write().await.remove(gateway_id);

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
