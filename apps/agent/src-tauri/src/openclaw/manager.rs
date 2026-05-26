//! Agent-owned OpenClaw gateway session management.
//!
//! Re-exports DTOs from sibling submodules to preserve the legacy
//! `crate::openclaw::manager::*` import paths used by `api_server.rs`.

use super::command::run_openclaw_json;
use super::dto::{
    GatewayConnectionStatus, GatewayListResponse, GatewayRuntimeSnapshot, GatewayUpsertRequest,
    ImportGatewayRequest, ImportGatewayResponse, OpenClawAgentEvent,
};

// Re-exported so external callers using `crate::openclaw::manager::GatewayView`
// (notably `api_server.rs`) keep compiling after the file split.
pub use super::dto::GatewayView;

use super::secret_store::OpenClawSecretStore;
use super::session::{GatewayHandle, SessionCommand};
use super::url_validation::validate_gateway_url;
use super::util::normalize_secret_field;
use crate::settings::{OpenClawGatewayMetadata, Settings};
use anyhow::Result;
use serde_json::Value;
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{broadcast, mpsc, oneshot, RwLock};

#[derive(Clone)]
pub struct OpenClawManager {
    pub(super) settings: Arc<RwLock<Settings>>,
    pub(super) secrets: OpenClawSecretStore,
    pub(super) sessions: Arc<RwLock<HashMap<String, GatewayHandle>>>,
    pub(super) runtime_by_id: Arc<RwLock<HashMap<String, GatewayRuntimeSnapshot>>>,
    pub(super) events_tx: broadcast::Sender<OpenClawAgentEvent>,
}

static NEXT_SESSION_ID: AtomicU64 = AtomicU64::new(1);

impl OpenClawManager {
    pub fn new(settings: Arc<RwLock<Settings>>) -> Self {
        let (events_tx, _) = broadcast::channel(512);
        Self {
            settings,
            secrets: OpenClawSecretStore::new("clawdstrike-agent-openclaw"),
            sessions: Arc::new(RwLock::new(HashMap::new())),
            runtime_by_id: Arc::new(RwLock::new(HashMap::new())),
            events_tx,
        }
    }

    pub fn subscribe(&self) -> broadcast::Receiver<OpenClawAgentEvent> {
        self.events_tx.subscribe()
    }

    pub async fn list_gateways(&self) -> GatewayListResponse {
        let settings = self.settings.read().await;
        let runtimes = self.runtime_by_id.read().await;

        let mut gateways = Vec::with_capacity(settings.openclaw.gateways.len());
        for gw in &settings.openclaw.gateways {
            let secrets = self.secrets.get(&gw.id).await;
            gateways.push(GatewayView {
                id: gw.id.clone(),
                label: gw.label.clone(),
                gateway_url: gw.gateway_url.clone(),
                has_token: secrets
                    .token
                    .as_deref()
                    .is_some_and(|v| !v.trim().is_empty()),
                has_device_token: secrets
                    .device_token
                    .as_deref()
                    .is_some_and(|v| !v.trim().is_empty()),
                runtime: runtimes.get(&gw.id).cloned().unwrap_or_default(),
            });
        }

        GatewayListResponse {
            active_gateway_id: settings.openclaw.active_gateway_id.clone(),
            gateways,
            secret_store_mode: self.secrets.mode(),
        }
    }

    pub async fn upsert_gateway(&self, input: GatewayUpsertRequest) -> Result<GatewayView> {
        let validation = validate_gateway_url(&input.gateway_url).await?;
        let gateway_id = input
            .id
            .clone()
            .unwrap_or_else(|| format!("gw:{}", uuid::Uuid::new_v4()));

        {
            let mut settings = self.settings.write().await;
            let mut found = false;
            for gw in &mut settings.openclaw.gateways {
                if gw.id == gateway_id {
                    gw.label = input.label.clone();
                    gw.gateway_url = validation.normalized_url.clone();
                    gw.pinned_ips = validation
                        .pinned_ips
                        .iter()
                        .map(ToString::to_string)
                        .collect();
                    found = true;
                    break;
                }
            }

            if !found {
                settings.openclaw.gateways.push(OpenClawGatewayMetadata {
                    id: gateway_id.clone(),
                    label: input.label.clone(),
                    gateway_url: validation.normalized_url.clone(),
                    pinned_ips: validation
                        .pinned_ips
                        .iter()
                        .map(ToString::to_string)
                        .collect(),
                });
            }

            if settings.openclaw.active_gateway_id.is_none() {
                settings.openclaw.active_gateway_id = Some(gateway_id.clone());
            }

            settings.save()?;
        }

        let mut existing = self.secrets.get(&gateway_id).await;
        if let Some(token) = input.token {
            existing.token = normalize_secret_field(token);
        }
        if let Some(device_token) = input.device_token {
            existing.device_token = normalize_secret_field(device_token);
        }
        self.secrets.set(&gateway_id, existing).await?;

        let list = self.list_gateways().await;
        list.gateways
            .into_iter()
            .find(|g| g.id == gateway_id)
            .ok_or_else(|| anyhow::anyhow!("gateway not found after upsert"))
    }

    pub async fn delete_gateway(&self, gateway_id: &str) -> Result<()> {
        self.disconnect_gateway(gateway_id).await?;

        {
            let mut settings = self.settings.write().await;
            settings.openclaw.gateways.retain(|g| g.id != gateway_id);
            if settings.openclaw.active_gateway_id.as_deref() == Some(gateway_id) {
                settings.openclaw.active_gateway_id =
                    settings.openclaw.gateways.first().map(|g| g.id.clone());
            }
            settings.save()?;
        }

        self.runtime_by_id.write().await.remove(gateway_id);
        self.secrets.delete(gateway_id).await?;
        Ok(())
    }

    pub async fn set_active_gateway(&self, gateway_id: Option<String>) -> Result<()> {
        let mut settings = self.settings.write().await;
        settings.openclaw.active_gateway_id = gateway_id;
        settings.save()?;
        Ok(())
    }

    pub async fn connect_gateway(&self, gateway_id: &str) -> Result<()> {
        self.disconnect_gateway(gateway_id).await?;

        let metadata = {
            let settings = self.settings.read().await;
            settings
                .openclaw
                .gateways
                .iter()
                .find(|g| g.id == gateway_id)
                .cloned()
        }
        .ok_or_else(|| anyhow::anyhow!("unknown gateway id: {}", gateway_id))?;

        let secrets = self.secrets.get(gateway_id).await;

        self.set_runtime_status(gateway_id, GatewayConnectionStatus::Connecting, None)
            .await;

        let session_id = NEXT_SESSION_ID.fetch_add(1, Ordering::Relaxed);
        let (tx, rx) = mpsc::channel(128);
        self.sessions
            .write()
            .await
            .insert(gateway_id.to_string(), GatewayHandle { tx, session_id });

        let manager = self.clone();
        let gateway_id = gateway_id.to_string();

        tokio::spawn(async move {
            manager
                .run_gateway_session(gateway_id, session_id, metadata, secrets, rx)
                .await;
        });

        Ok(())
    }

    pub async fn disconnect_gateway(&self, gateway_id: &str) -> Result<()> {
        let handle = self.sessions.write().await.remove(gateway_id);
        if let Some(handle) = handle {
            let _ = handle.tx.send(SessionCommand::Disconnect).await;
        }

        self.set_runtime_status(gateway_id, GatewayConnectionStatus::Disconnected, None)
            .await;
        Ok(())
    }

    pub async fn request_gateway(
        &self,
        gateway_id: &str,
        method: String,
        params: Option<Value>,
        timeout_ms: u64,
    ) -> Result<Value> {
        let handle = self
            .sessions
            .read()
            .await
            .get(gateway_id)
            .cloned()
            .ok_or_else(|| anyhow::anyhow!("gateway {} is not connected", gateway_id))?;

        let (tx, rx) = oneshot::channel();
        handle
            .tx
            .send(SessionCommand::Request {
                method,
                params,
                timeout_ms,
                response_tx: tx,
            })
            .await
            .map_err(|_| anyhow::anyhow!("gateway {} command channel closed", gateway_id))?;

        match tokio::time::timeout(Duration::from_millis(timeout_ms), rx).await {
            Ok(Ok(Ok(payload))) => Ok(payload),
            Ok(Ok(Err(err))) => Err(anyhow::anyhow!(err)),
            Ok(Err(_)) => Err(anyhow::anyhow!("gateway response channel closed")),
            Err(_) => Err(anyhow::anyhow!("timeout after {}ms", timeout_ms)),
        }
    }

    pub async fn import_desktop_gateways(
        &self,
        payload: ImportGatewayRequest,
    ) -> Result<ImportGatewayResponse> {
        let mut imported = 0usize;
        let mut skipped = 0usize;

        for entry in payload.gateways {
            if entry.label.trim().is_empty() || entry.gateway_url.trim().is_empty() {
                skipped += 1;
                continue;
            }

            self.upsert_gateway(entry).await?;
            imported += 1;
        }

        if payload.active_gateway_id.is_some() {
            self.set_active_gateway(payload.active_gateway_id).await?;
        }

        Ok(ImportGatewayResponse { imported, skipped })
    }

    pub async fn shutdown(&self) {
        let ids: Vec<String> = self.sessions.read().await.keys().cloned().collect();
        for id in ids {
            let _ = self.disconnect_gateway(&id).await;
        }
    }

    pub async fn gateway_discover(&self, timeout_ms: Option<u64>) -> Result<Value> {
        let mut args = vec![
            "gateway".to_string(),
            "discover".to_string(),
            "--json".to_string(),
        ];

        if let Some(timeout_ms) = timeout_ms {
            args.push("--timeout".to_string());
            args.push(timeout_ms.to_string());
        }

        run_openclaw_json(args).await
    }

    pub async fn gateway_probe(&self, timeout_ms: Option<u64>) -> Result<Value> {
        let mut args = vec![
            "gateway".to_string(),
            "probe".to_string(),
            "--json".to_string(),
        ];

        if let Some(timeout_ms) = timeout_ms {
            args.push("--timeout".to_string());
            args.push(timeout_ms.to_string());
        }

        run_openclaw_json(args).await
    }
}
