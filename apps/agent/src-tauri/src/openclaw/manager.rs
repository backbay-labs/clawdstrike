//! Agent-owned OpenClaw gateway session management.

use super::protocol::{
    create_request_id, parse_gateway_frame, GatewayAuth, GatewayClientIdentity,
    GatewayConnectParams, GatewayEventFrame, GatewayFrame, GatewayRequestFrame,
    GatewayResponseError, GatewayResponseFrame,
};
use super::secret_store::{GatewaySecrets, OpenClawSecretStore, SecretStoreMode};
use crate::settings::{OpenClawGatewayMetadata, Settings};
use anyhow::{Context, Result};
use futures::{SinkExt, StreamExt};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tokio::sync::{broadcast, mpsc, oneshot, RwLock};
use tokio_tungstenite::connect_async;
use tokio_tungstenite::tungstenite::Message;

#[cfg(test)]
const CONNECT_HANDSHAKE_TIMEOUT: Duration = Duration::from_millis(400);
#[cfg(not(test))]
const CONNECT_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(5);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum GatewayConnectionStatus {
    Disconnected,
    Connecting,
    Connected,
    Error,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GatewayRuntimeSnapshot {
    pub status: GatewayConnectionStatus,
    pub last_error: Option<String>,
    pub connected_at_ms: Option<u64>,
    pub last_message_at_ms: Option<u64>,
    #[serde(default)]
    pub presence: Vec<Value>,
    #[serde(default)]
    pub nodes: Vec<Value>,
    #[serde(default)]
    pub devices: Option<Value>,
    #[serde(default)]
    pub exec_approval_queue: Vec<Value>,
}

impl Default for GatewayRuntimeSnapshot {
    fn default() -> Self {
        Self {
            status: GatewayConnectionStatus::Disconnected,
            last_error: None,
            connected_at_ms: None,
            last_message_at_ms: None,
            presence: Vec::new(),
            nodes: Vec::new(),
            devices: None,
            exec_approval_queue: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GatewayView {
    pub id: String,
    pub label: String,
    pub gateway_url: String,
    pub has_token: bool,
    pub has_device_token: bool,
    pub runtime: GatewayRuntimeSnapshot,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GatewayListResponse {
    pub active_gateway_id: Option<String>,
    pub gateways: Vec<GatewayView>,
    pub secret_store_mode: SecretStoreMode,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GatewayUpsertRequest {
    pub id: Option<String>,
    pub label: String,
    pub gateway_url: String,
    pub token: Option<String>,
    pub device_token: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ImportGatewayRequest {
    pub gateways: Vec<GatewayUpsertRequest>,
    pub active_gateway_id: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ImportGatewayResponse {
    pub imported: usize,
    pub skipped: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GatewayRequestInput {
    pub gateway_id: String,
    pub method: String,
    pub params: Option<Value>,
    pub timeout_ms: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GatewayDiscoverInput {
    pub timeout_ms: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum OpenClawAgentEvent {
    Status {
        gateway_id: String,
        runtime: GatewayRuntimeSnapshot,
    },
    GatewayEvent {
        gateway_id: String,
        frame: GatewayEventFrame,
    },
}

enum SessionCommand {
    Request {
        method: String,
        params: Option<Value>,
        timeout_ms: u64,
        response_tx: oneshot::Sender<Result<Value, String>>,
    },
    Disconnect,
}

#[derive(Clone)]
struct GatewayHandle {
    tx: mpsc::Sender<SessionCommand>,
    session_id: u64,
}

struct PendingResponse {
    tx: oneshot::Sender<Result<Value, String>>,
    expires_at: Instant,
}

#[derive(Clone)]
pub struct OpenClawManager {
    settings: Arc<RwLock<Settings>>,
    secrets: OpenClawSecretStore,
    sessions: Arc<RwLock<HashMap<String, GatewayHandle>>>,
    runtime_by_id: Arc<RwLock<HashMap<String, GatewayRuntimeSnapshot>>>,
    events_tx: broadcast::Sender<OpenClawAgentEvent>,
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
                    gw.gateway_url = input.gateway_url.clone();
                    found = true;
                    break;
                }
            }

            if !found {
                settings.openclaw.gateways.push(OpenClawGatewayMetadata {
                    id: gateway_id.clone(),
                    label: input.label.clone(),
                    gateway_url: input.gateway_url.clone(),
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

    async fn run_gateway_session(
        &self,
        gateway_id: String,
        session_id: u64,
        metadata: OpenClawGatewayMetadata,
        secrets: GatewaySecrets,
        mut rx: mpsc::Receiver<SessionCommand>,
    ) {
        let mut reconnect_attempt = 0u32;
        let max_attempts = 20u32;
        let stable_reset = Duration::from_secs(90);

        loop {
            if reconnect_attempt >= max_attempts {
                self.set_runtime_status(
                    &gateway_id,
                    GatewayConnectionStatus::Error,
                    Some("reconnect attempts exhausted".to_string()),
                )
                .await;
                break;
            }

            self.set_runtime_status(&gateway_id, GatewayConnectionStatus::Connecting, None)
                .await;

            let connect_result = self
                .run_gateway_connection_once(&gateway_id, &metadata, &secrets, &mut rx)
                .await;
            let was_stable = self.connection_was_stable(&gateway_id, stable_reset).await;

            match connect_result {
                Ok(ConnectionExit::ManualDisconnect) => {
                    self.set_runtime_status(
                        &gateway_id,
                        GatewayConnectionStatus::Disconnected,
                        None,
                    )
                    .await;
                    break;
                }
                Ok(ConnectionExit::RemoteClosed(reason)) => {
                    reconnect_attempt = next_reconnect_attempt(reconnect_attempt, was_stable);
                    self.set_runtime_status(
                        &gateway_id,
                        GatewayConnectionStatus::Disconnected,
                        Some(reason),
                    )
                    .await;
                }
                Err(err) => {
                    reconnect_attempt = next_reconnect_attempt(reconnect_attempt, was_stable);
                    self.set_runtime_status(
                        &gateway_id,
                        GatewayConnectionStatus::Error,
                        Some(err.to_string()),
                    )
                    .await;
                }
            }

            let backoff_ms = (400.0_f64 * 1.6_f64.powi(reconnect_attempt as i32)).round() as u64;
            let backoff_ms = backoff_ms.clamp(250, 12_000);
            tokio::time::sleep(Duration::from_millis(backoff_ms)).await;

            // If the channel is closed, stop reconnecting.
            if rx.is_closed() {
                break;
            }
        }

        self.remove_session_if_current(&gateway_id, session_id)
            .await;
    }

    async fn run_gateway_connection_once(
        &self,
        gateway_id: &str,
        metadata: &OpenClawGatewayMetadata,
        secrets: &GatewaySecrets,
        rx: &mut mpsc::Receiver<SessionCommand>,
    ) -> Result<ConnectionExit> {
        let (ws_stream, _) = connect_async(&metadata.gateway_url)
            .await
            .with_context(|| format!("failed to connect websocket to {}", metadata.gateway_url))?;

        let (mut sink, mut stream) = ws_stream.split();

        let connect_id = create_request_id("connect");
        let params = GatewayConnectParams {
            min_protocol: 3,
            max_protocol: 3,
            client: GatewayClientIdentity {
                id: "cli".to_string(),
                display_name: Some("Clawdstrike Agent".to_string()),
                version: Some(env!("CARGO_PKG_VERSION").to_string()),
                platform: Some("tauri".to_string()),
                mode: Some("cli".to_string()),
                instance_id: Some(format!("agent:{}", gateway_id)),
            },
            role: Some("operator".to_string()),
            scopes: Some(vec![
                "operator.read".to_string(),
                "operator.write".to_string(),
                "operator.approvals".to_string(),
                "operator.pairing".to_string(),
            ]),
            auth: if secrets.token.is_some() || secrets.device_token.is_some() {
                Some(GatewayAuth {
                    token: secrets.token.clone(),
                    device_token: secrets.device_token.clone(),
                })
            } else {
                None
            },
            locale: Some("en-US".to_string()),
            user_agent: Some("clawdstrike-agent".to_string()),
        };

        let connect_frame = GatewayFrame::Req(GatewayRequestFrame {
            id: connect_id.clone(),
            method: "connect".to_string(),
            params: Some(serde_json::to_value(params)?),
        });

        sink.send(Message::Text(serde_json::to_string(&connect_frame)?))
            .await
            .with_context(|| "failed to send connect frame")?;

        let mut connected = false;
        let connect_deadline = Instant::now() + CONNECT_HANDSHAKE_TIMEOUT;
        let mut pending: HashMap<String, PendingResponse> = HashMap::new();

        loop {
            let timeout_tick = tokio::time::sleep(Duration::from_millis(200));
            tokio::pin!(timeout_tick);

            tokio::select! {
                _ = &mut timeout_tick => {
                    let now = Instant::now();
                    if !connected && now > connect_deadline {
                        reject_all_pending(&mut pending, "connect timeout");
                        return Err(anyhow::anyhow!(
                            "timeout waiting for connect response ({:?})",
                            CONNECT_HANDSHAKE_TIMEOUT
                        ));
                    }

                    let expired: Vec<String> = pending
                        .iter()
                        .filter_map(|(id, p)| if now > p.expires_at { Some(id.clone()) } else { None })
                        .collect();

                    for id in expired {
                        if let Some(pending_item) = pending.remove(&id) {
                            let _ = pending_item.tx.send(Err(format!("timeout waiting for gateway response ({id})")));
                        }
                    }
                }
                maybe_command = rx.recv() => {
                    match maybe_command {
                        None => return Ok(ConnectionExit::ManualDisconnect),
                        Some(SessionCommand::Disconnect) => {
                            let _ = sink.send(Message::Close(None)).await;
                            reject_all_pending(&mut pending, "disconnected");
                            return Ok(ConnectionExit::ManualDisconnect);
                        }
                        Some(SessionCommand::Request { method, params, timeout_ms, response_tx }) => {
                            if !connected {
                                let _ = response_tx.send(Err("not connected".to_string()));
                                continue;
                            }

                            let req_id = create_request_id(&method);
                            let frame = GatewayFrame::Req(GatewayRequestFrame {
                                id: req_id.clone(),
                                method,
                                params,
                            });

                            match serde_json::to_string(&frame) {
                                Ok(text) => {
                                    if let Err(err) = sink.send(Message::Text(text)).await {
                                        let _ = response_tx.send(Err(format!("send failed: {}", err)));
                                    } else {
                                        pending.insert(
                                            req_id,
                                            PendingResponse {
                                                tx: response_tx,
                                                expires_at: Instant::now() + Duration::from_millis(timeout_ms),
                                            },
                                        );
                                    }
                                }
                                Err(err) => {
                                    let _ = response_tx.send(Err(format!("serialization failed: {}", err)));
                                }
                            }
                        }
                    }
                }
                inbound = stream.next() => {
                    match inbound {
                        None => {
                            reject_all_pending(&mut pending, "disconnected");
                            return Ok(ConnectionExit::RemoteClosed("websocket closed".to_string()));
                        }
                        Some(Err(err)) => {
                            reject_all_pending(&mut pending, "disconnected");
                            return Err(anyhow::anyhow!("websocket read error: {}", err));
                        }
                        Some(Ok(Message::Close(frame))) => {
                            reject_all_pending(&mut pending, "disconnected");
                            let reason = frame
                                .map(|f| format!("websocket closed ({}) {}", f.code, f.reason))
                                .unwrap_or_else(|| "websocket closed".to_string());
                            return Ok(ConnectionExit::RemoteClosed(reason));
                        }
                        Some(Ok(Message::Text(text))) => {
                            self.touch_runtime_message(gateway_id).await;

                            let Some(frame) = parse_gateway_frame(&text) else {
                                continue;
                            };

                            match frame {
                                GatewayFrame::Event(evt) => {
                                    self.apply_gateway_event(gateway_id, evt).await;
                                }
                                GatewayFrame::Res(GatewayResponseFrame { id, ok, payload, error }) => {
                                    if id == connect_id {
                                        if ok {
                                            connected = true;
                                            self.set_runtime_connected(gateway_id).await;
                                        } else {
                                            let msg = error
                                                .as_ref()
                                                .map(|e| e.message.clone())
                                                .unwrap_or_else(|| "connect failed".to_string());
                                            return Err(anyhow::anyhow!(msg));
                                        }
                                        continue;
                                    }

                                    if let Some(waiter) = pending.remove(&id) {
                                        if ok {
                                            let _ = waiter.tx.send(Ok(payload.unwrap_or(Value::Null)));
                                        } else {
                                            let err_msg = normalize_gateway_error(error, "request failed");
                                            let _ = waiter.tx.send(Err(err_msg));
                                        }
                                    }
                                }
                                GatewayFrame::Req(_) => {
                                    // Gateway-to-client requests are currently ignored.
                                }
                            }
                        }
                        Some(Ok(_)) => {
                            // Ignore binary/ping/pong frames.
                        }
                    }
                }
            }
        }
    }

    async fn set_runtime_connected(&self, gateway_id: &str) {
        let mut runtimes = self.runtime_by_id.write().await;
        let rt = runtimes
            .entry(gateway_id.to_string())
            .or_insert_with(GatewayRuntimeSnapshot::default);

        rt.status = GatewayConnectionStatus::Connected;
        rt.last_error = None;
        rt.connected_at_ms = Some(now_ms());

        let snapshot = rt.clone();
        drop(runtimes);

        let _ = self.events_tx.send(OpenClawAgentEvent::Status {
            gateway_id: gateway_id.to_string(),
            runtime: snapshot,
        });
    }

    async fn touch_runtime_message(&self, gateway_id: &str) {
        let mut runtimes = self.runtime_by_id.write().await;
        let rt = runtimes
            .entry(gateway_id.to_string())
            .or_insert_with(GatewayRuntimeSnapshot::default);
        rt.last_message_at_ms = Some(now_ms());
    }

    async fn set_runtime_status(
        &self,
        gateway_id: &str,
        status: GatewayConnectionStatus,
        last_error: Option<String>,
    ) {
        let mut runtimes = self.runtime_by_id.write().await;
        let rt = runtimes
            .entry(gateway_id.to_string())
            .or_insert_with(GatewayRuntimeSnapshot::default);

        rt.status = status;
        rt.last_error = last_error;

        if status != GatewayConnectionStatus::Connected {
            rt.connected_at_ms = None;
        }

        let snapshot = rt.clone();
        drop(runtimes);

        let _ = self.events_tx.send(OpenClawAgentEvent::Status {
            gateway_id: gateway_id.to_string(),
            runtime: snapshot,
        });
    }

    async fn connection_was_stable(&self, gateway_id: &str, stable_reset: Duration) -> bool {
        let connected_at = self
            .runtime_by_id
            .read()
            .await
            .get(gateway_id)
            .and_then(|rt| rt.connected_at_ms);
        was_connected_long_enough(connected_at, stable_reset, now_ms())
    }

    async fn remove_session_if_current(&self, gateway_id: &str, session_id: u64) {
        let mut sessions = self.sessions.write().await;
        let should_remove = sessions
            .get(gateway_id)
            .is_some_and(|handle| handle.session_id == session_id);

        if should_remove {
            sessions.remove(gateway_id);
        }
    }

    async fn apply_gateway_event(&self, gateway_id: &str, frame: GatewayEventFrame) {
        {
            let mut runtimes = self.runtime_by_id.write().await;
            let rt = runtimes
                .entry(gateway_id.to_string())
                .or_insert_with(GatewayRuntimeSnapshot::default);

            match frame.event.as_str() {
                "presence" => {
                    rt.presence = frame
                        .payload
                        .as_ref()
                        .and_then(|v| v.as_array().cloned())
                        .unwrap_or_default();
                }
                "exec.approval.requested" => {
                    if let Some(payload) = frame.payload.clone() {
                        let id = payload
                            .get("id")
                            .and_then(|v| v.as_str())
                            .map(|s| s.to_string());
                        if let Some(id) = id {
                            rt.exec_approval_queue.retain(|item| {
                                item.get("id").and_then(|v| v.as_str()) != Some(id.as_str())
                            });
                            rt.exec_approval_queue.insert(0, payload);
                            if rt.exec_approval_queue.len() > 100 {
                                rt.exec_approval_queue.truncate(100);
                            }
                        }
                    }
                }
                _ => {}
            }
        }

        let _ = self.events_tx.send(OpenClawAgentEvent::GatewayEvent {
            gateway_id: gateway_id.to_string(),
            frame,
        });
    }
}

#[derive(Debug)]
enum ConnectionExit {
    ManualDisconnect,
    RemoteClosed(String),
}

fn reject_all_pending(pending: &mut HashMap<String, PendingResponse>, reason: &str) {
    let entries: Vec<PendingResponse> = pending.drain().map(|(_, v)| v).collect();
    for entry in entries {
        let _ = entry.tx.send(Err(reason.to_string()));
    }
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_else(|_| Duration::from_millis(0))
        .as_millis() as u64
}

fn normalize_gateway_error(error: Option<GatewayResponseError>, fallback: &str) -> String {
    error
        .and_then(|e| {
            if e.message.trim().is_empty() {
                None
            } else {
                Some(e.message)
            }
        })
        .unwrap_or_else(|| fallback.to_string())
}

fn was_connected_long_enough(
    connected_at_ms: Option<u64>,
    stable_reset: Duration,
    now_ms_value: u64,
) -> bool {
    connected_at_ms.is_some_and(|connected_at| {
        now_ms_value.saturating_sub(connected_at) >= stable_reset.as_millis() as u64
    })
}

fn next_reconnect_attempt(current_attempt: u32, was_stable: bool) -> u32 {
    if was_stable {
        1
    } else {
        current_attempt.saturating_add(1)
    }
}

fn normalize_secret_field(value: String) -> Option<String> {
    if value.trim().is_empty() {
        None
    } else {
        Some(value)
    }
}

fn extract_json_payload(output: &str) -> Result<Value> {
    let mut saw_candidate = false;
    let mut best: Option<(Value, usize)> = None;
    let mut last_error: Option<String> = None;

    for (idx, ch) in output.char_indices() {
        if ch != '{' && ch != '[' {
            continue;
        }
        saw_candidate = true;
        let json = &output[idx..];
        let deser = serde_json::Deserializer::from_str(json);
        let mut stream = deser.into_iter::<Value>();
        match stream.next() {
            Some(Ok(value)) => {
                let remainder = &json[stream.byte_offset()..];
                let remainder_len = remainder.trim().len();
                if remainder_len == 0 {
                    return Ok(value);
                }

                match &best {
                    Some((_, best_len)) if remainder_len >= *best_len => {}
                    _ => best = Some((value, remainder_len)),
                }
            }
            Some(Err(err)) => {
                last_error = Some(format!("Failed to parse OpenClaw JSON: {}", err));
            }
            None => {}
        }
    }

    if let Some((value, _)) = best {
        return Ok(value);
    }

    Err(anyhow::anyhow!(last_error.unwrap_or_else(|| {
        if saw_candidate {
            "Failed to parse OpenClaw JSON".to_string()
        } else {
            "OpenClaw returned no JSON payload".to_string()
        }
    })))
}

async fn run_openclaw_json(args: Vec<String>) -> Result<Value> {
    let output = tokio::task::spawn_blocking(move || {
        let mut full_args = vec!["--no-color".to_string()];
        full_args.extend(args);

        std::process::Command::new("openclaw")
            .args(full_args)
            .output()
            .map_err(|e| anyhow::anyhow!("Failed to execute openclaw: {}", e))
    })
    .await
    .map_err(|e| anyhow::anyhow!("Failed to join openclaw task: {}", e))??;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        let stdout = String::from_utf8_lossy(&output.stdout);
        return Err(anyhow::anyhow!(
            "OpenClaw exited with {}: {}{}",
            output.status,
            stderr.trim(),
            if stderr.trim().is_empty() && !stdout.trim().is_empty() {
                format!(" (stdout: {})", stdout.trim())
            } else {
                "".to_string()
            }
        ));
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    extract_json_payload(&stdout)
}

#[cfg(test)]
mod tests {
    use super::*;
    use futures::{SinkExt, StreamExt};
    use tokio::net::TcpListener;
    use tokio::time::{sleep, Duration};
    use tokio_tungstenite::{accept_async, tungstenite::Message};

    #[test]
    fn extract_json_payload_prefers_clean_payload() {
        let raw = "noise\n{\"ok\":true}\n";
        let value = match extract_json_payload(raw) {
            Ok(v) => v,
            Err(err) => panic!("expected json payload, got error: {err}"),
        };
        assert_eq!(value["ok"], Value::Bool(true));
    }

    #[test]
    fn normalize_gateway_error_uses_fallback() {
        assert_eq!(normalize_gateway_error(None, "fallback"), "fallback");
    }

    #[test]
    fn stable_connection_window_detection_works() {
        let stable_reset = Duration::from_secs(90);
        assert!(was_connected_long_enough(
            Some(1000),
            stable_reset,
            1000 + 90_000
        ));
        assert!(!was_connected_long_enough(
            Some(1000),
            stable_reset,
            1000 + 10_000
        ));
        assert!(!was_connected_long_enough(
            None,
            stable_reset,
            1000 + 90_000
        ));
    }

    #[test]
    fn reconnect_attempt_resets_after_stable_session() {
        assert_eq!(next_reconnect_attempt(7, true), 1);
        assert_eq!(next_reconnect_attempt(7, false), 8);
    }

    #[test]
    fn empty_secret_fields_are_cleared() {
        assert_eq!(normalize_secret_field(String::new()), None);
        assert_eq!(normalize_secret_field("   ".to_string()), None);
        assert_eq!(
            normalize_secret_field("token-value".to_string()),
            Some("token-value".to_string())
        );
    }

    #[tokio::test]
    async fn stale_session_exit_does_not_remove_replacement_handle() {
        let settings = Arc::new(RwLock::new(Settings::default()));
        let manager = OpenClawManager::new(settings);

        let (old_tx, _old_rx) = mpsc::channel(1);
        let (new_tx, _new_rx) = mpsc::channel(1);

        manager.sessions.write().await.insert(
            "gw-1".to_string(),
            GatewayHandle {
                tx: old_tx,
                session_id: 1,
            },
        );
        manager.sessions.write().await.insert(
            "gw-1".to_string(),
            GatewayHandle {
                tx: new_tx,
                session_id: 2,
            },
        );

        manager.remove_session_if_current("gw-1", 1).await;

        let sessions = manager.sessions.read().await;
        let handle = match sessions.get("gw-1") {
            Some(value) => value,
            None => panic!("replacement session should remain present"),
        };
        assert_eq!(handle.session_id, 2);
    }

    #[tokio::test]
    async fn connects_and_relays_request_against_mock_gateway() {
        let listener = match TcpListener::bind("127.0.0.1:0").await {
            Ok(value) => value,
            Err(err) => panic!("failed to bind mock gateway listener: {}", err),
        };
        let addr = match listener.local_addr() {
            Ok(value) => value,
            Err(err) => panic!("failed to read listener address: {}", err),
        };

        let server = tokio::spawn(async move {
            let (stream, _) = match listener.accept().await {
                Ok(value) => value,
                Err(err) => return Err(format!("accept failed: {}", err)),
            };
            let mut ws = match accept_async(stream).await {
                Ok(value) => value,
                Err(err) => return Err(format!("ws accept failed: {}", err)),
            };

            let connect_text = match ws.next().await {
                Some(Ok(Message::Text(text))) => text,
                Some(Ok(_)) => return Err("expected text connect frame".to_string()),
                Some(Err(err)) => return Err(format!("read connect frame failed: {}", err)),
                None => return Err("stream closed before connect frame".to_string()),
            };

            let connect_id = match parse_gateway_frame(&connect_text) {
                Some(GatewayFrame::Req(req)) if req.method == "connect" => req.id,
                Some(_) => return Err("unexpected first frame shape".to_string()),
                None => return Err("failed to parse connect frame".to_string()),
            };

            let connect_response = GatewayFrame::Res(GatewayResponseFrame {
                id: connect_id,
                ok: true,
                payload: Some(serde_json::json!({"session":"mock"})),
                error: None,
            });

            let connect_response_text = match serde_json::to_string(&connect_response) {
                Ok(value) => value,
                Err(err) => return Err(format!("serialize connect response failed: {}", err)),
            };

            if let Err(err) = ws.send(Message::Text(connect_response_text)).await {
                return Err(format!("send connect response failed: {}", err));
            }

            let presence_event = GatewayFrame::Event(GatewayEventFrame {
                event: "presence".to_string(),
                payload: Some(serde_json::json!([{"client":"mock"}])),
                seq: Some(1),
                state_version: None,
            });
            let presence_text = match serde_json::to_string(&presence_event) {
                Ok(value) => value,
                Err(err) => return Err(format!("serialize presence event failed: {}", err)),
            };
            if let Err(err) = ws.send(Message::Text(presence_text)).await {
                return Err(format!("send presence event failed: {}", err));
            }

            let request_text = match ws.next().await {
                Some(Ok(Message::Text(text))) => text,
                Some(Ok(_)) => return Err("expected text relay frame".to_string()),
                Some(Err(err)) => return Err(format!("read relay frame failed: {}", err)),
                None => return Err("stream closed before relay frame".to_string()),
            };

            let request_id = match parse_gateway_frame(&request_text) {
                Some(GatewayFrame::Req(req)) if req.method == "node.list" => req.id,
                Some(_) => return Err("unexpected relay frame method".to_string()),
                None => return Err("failed to parse relay frame".to_string()),
            };

            let relay_response = GatewayFrame::Res(GatewayResponseFrame {
                id: request_id,
                ok: true,
                payload: Some(serde_json::json!({
                    "nodes": [{"nodeId":"node-1"}]
                })),
                error: None,
            });
            let relay_text = match serde_json::to_string(&relay_response) {
                Ok(value) => value,
                Err(err) => return Err(format!("serialize relay response failed: {}", err)),
            };
            if let Err(err) = ws.send(Message::Text(relay_text)).await {
                return Err(format!("send relay response failed: {}", err));
            }

            let _ = ws.next().await;
            Ok::<(), String>(())
        });

        let mut settings = Settings::default();
        settings.openclaw.gateways.push(OpenClawGatewayMetadata {
            id: "gw-test".to_string(),
            label: "Gateway Test".to_string(),
            gateway_url: format!("ws://{}", addr),
        });
        settings.openclaw.active_gateway_id = Some("gw-test".to_string());

        let manager = OpenClawManager::new(Arc::new(RwLock::new(settings)));
        let mut events_rx = manager.subscribe();

        if let Err(err) = manager.connect_gateway("gw-test").await {
            panic!("connect_gateway failed: {}", err);
        }

        let mut connected = false;
        for _ in 0..40 {
            let list = manager.list_gateways().await;
            let status = list
                .gateways
                .iter()
                .find(|g| g.id == "gw-test")
                .map(|g| g.runtime.status);
            if status == Some(GatewayConnectionStatus::Connected) {
                connected = true;
                break;
            }
            sleep(Duration::from_millis(50)).await;
        }
        assert!(connected, "gateway did not reach connected state");

        let payload = match manager
            .request_gateway("gw-test", "node.list".to_string(), None, 4_000)
            .await
        {
            Ok(value) => value,
            Err(err) => panic!("request_gateway failed: {}", err),
        };
        assert_eq!(
            payload["nodes"][0]["nodeId"].as_str(),
            Some("node-1"),
            "node.list relay payload mismatch"
        );

        let mut saw_presence = false;
        for _ in 0..20 {
            let event = tokio::time::timeout(Duration::from_millis(150), events_rx.recv()).await;
            if let Ok(Ok(OpenClawAgentEvent::GatewayEvent { frame, .. })) = event {
                if frame.event == "presence" {
                    saw_presence = true;
                    break;
                }
            }
        }
        assert!(saw_presence, "did not observe presence event fan-out");

        if let Err(err) = manager.disconnect_gateway("gw-test").await {
            panic!("disconnect_gateway failed: {}", err);
        }

        let server_result = match server.await {
            Ok(value) => value,
            Err(err) => panic!("mock gateway task join failed: {}", err),
        };
        if let Err(err) = server_result {
            panic!("mock gateway task failed: {}", err);
        }
    }

    #[tokio::test]
    async fn connect_handshake_times_out_when_gateway_never_replies() {
        let listener = match TcpListener::bind("127.0.0.1:0").await {
            Ok(value) => value,
            Err(err) => panic!("failed to bind timeout test listener: {}", err),
        };
        let addr = match listener.local_addr() {
            Ok(value) => value,
            Err(err) => panic!("failed to read timeout test listener address: {}", err),
        };

        let server = tokio::spawn(async move {
            let (stream, _) = match listener.accept().await {
                Ok(value) => value,
                Err(err) => return Err(format!("accept failed: {}", err)),
            };
            let mut ws = match accept_async(stream).await {
                Ok(value) => value,
                Err(err) => return Err(format!("ws accept failed: {}", err)),
            };

            // Accept the connect request but never send the response.
            let _ = ws.next().await;
            tokio::time::sleep(Duration::from_millis(1_000)).await;
            Ok::<(), String>(())
        });

        let manager = OpenClawManager::new(Arc::new(RwLock::new(Settings::default())));
        let metadata = OpenClawGatewayMetadata {
            id: "gw-timeout".to_string(),
            label: "Timeout Gateway".to_string(),
            gateway_url: format!("ws://{}", addr),
        };
        let secrets = GatewaySecrets::default();
        let (_tx, mut rx) = mpsc::channel(4);

        let started_at = Instant::now();
        let result = manager
            .run_gateway_connection_once("gw-timeout", &metadata, &secrets, &mut rx)
            .await;

        assert!(result.is_err(), "expected handshake timeout error");
        let err_text = format!(
            "{}",
            result
                .err()
                .unwrap_or_else(|| anyhow::anyhow!("missing error"))
        );
        assert!(
            err_text.contains("timeout waiting for connect response"),
            "unexpected error text: {err_text}"
        );
        assert!(
            started_at.elapsed() >= CONNECT_HANDSHAKE_TIMEOUT,
            "handshake timeout elapsed too quickly"
        );

        server.abort();
    }
}
