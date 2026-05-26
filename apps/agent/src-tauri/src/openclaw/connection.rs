//! WebSocket connection loop driving each gateway session.
//!
//! `run_gateway_session` owns the reconnect lifecycle; `run_gateway_connection_once`
//! drives a single WS connection: handshake, request multiplexing, heartbeats,
//! server-initiated request handling, and event fan-out.

use super::backoff::{compute_reconnect_sleep_ms, next_reconnect_attempt};
use super::device_proof::{build_gateway_device_proof, default_gateway_scopes};
use super::dto::GatewayConnectionStatus;
use super::manager::OpenClawManager;
use super::protocol::{
    create_request_id, parse_gateway_frame, GatewayAuth, GatewayClientIdentity,
    GatewayConnectParams, GatewayFrame, GatewayRequestFrame, GatewayResponseFrame,
};
use super::secret_store::GatewaySecrets;
use super::session::{PendingResponse, SessionCommand};
use super::url_validation::validate_gateway_runtime_target;
use super::util::normalize_gateway_error;
use crate::settings::OpenClawGatewayMetadata;
use anyhow::{Context, Result};
use futures::{SinkExt, StreamExt};
use serde_json::Value;
use std::collections::HashMap;
use std::time::{Duration, Instant};
use tokio::sync::mpsc;
use tokio_tungstenite::connect_async;
use tokio_tungstenite::tungstenite::Message;

#[cfg(test)]
pub(super) const CONNECT_HANDSHAKE_TIMEOUT: Duration = Duration::from_millis(400);
#[cfg(not(test))]
pub(super) const CONNECT_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(5);

#[derive(Debug)]
pub(super) enum ConnectionExit {
    ManualDisconnect,
    RemoteClosed(String),
}

impl OpenClawManager {
    pub(super) async fn run_gateway_session(
        &self,
        gateway_id: String,
        session_id: u64,
        metadata: OpenClawGatewayMetadata,
        initial_secrets: GatewaySecrets,
        mut rx: mpsc::Receiver<SessionCommand>,
    ) {
        let mut reconnect_attempt = 0u32;
        let max_attempts = 20u32;
        let stable_reset = Duration::from_secs(90);
        let mut secrets = initial_secrets;

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

            let backoff_ms = compute_reconnect_sleep_ms(reconnect_attempt);
            tokio::time::sleep(Duration::from_millis(backoff_ms)).await;

            // If the channel is closed, stop reconnecting.
            if rx.is_closed() {
                break;
            }

            // Re-read secrets from store in case tokens were rotated while disconnected.
            secrets = self.secrets.get(&gateway_id).await;
        }

        self.remove_session_if_current(&gateway_id, session_id)
            .await;
    }

    pub(super) async fn run_gateway_connection_once(
        &self,
        gateway_id: &str,
        metadata: &OpenClawGatewayMetadata,
        secrets: &GatewaySecrets,
        rx: &mut mpsc::Receiver<SessionCommand>,
    ) -> Result<ConnectionExit> {
        validate_gateway_runtime_target(&metadata.gateway_url, &metadata.pinned_ips)
            .await
            .with_context(|| "runtime gateway target validation failed")?;

        let (ws_stream, _) = connect_async(&metadata.gateway_url)
            .await
            .with_context(|| format!("failed to connect websocket to {}", metadata.gateway_url))?;

        let (mut sink, mut stream) = ws_stream.split();

        let connect_challenge_nonce = match tokio::time::timeout(
            Duration::from_millis(150),
            stream.next(),
        )
        .await
        {
            Ok(Some(Ok(Message::Text(text)))) => match parse_gateway_frame(&text) {
                Some(GatewayFrame::Event(event)) if event.event == "connect.challenge" => {
                    let nonce = event
                        .payload
                        .as_ref()
                        .and_then(|payload| payload.get("nonce"))
                        .and_then(|value| value.as_str())
                        .map(|value| value.to_string());
                    if nonce.is_none() {
                        tracing::warn!(
                            gateway_id = %gateway_id,
                            "gateway emitted connect.challenge without nonce; using fallback device nonce"
                        );
                    }
                    nonce
                }
                _ => None,
            },
            Ok(Some(Ok(Message::Close(frame)))) => {
                return Ok(ConnectionExit::RemoteClosed(format!(
                    "closed before connect: {:?}",
                    frame
                )))
            }
            Ok(Some(Err(err))) => {
                return Err(anyhow::anyhow!(
                    "failed while waiting for pre-connect challenge: {err}"
                ))
            }
            Ok(None) => {
                return Ok(ConnectionExit::RemoteClosed(
                    "stream ended before connect".to_string(),
                ))
            }
            Err(_) | Ok(Some(Ok(_))) => None,
        };

        let connect_id = create_request_id("connect");
        let role = "operator".to_string();
        let scopes = default_gateway_scopes();
        let auth_token = secrets
            .token
            .clone()
            .or_else(|| secrets.device_token.clone());
        let client = GatewayClientIdentity {
            id: "cli".to_string(),
            display_name: Some("Clawdstrike Agent".to_string()),
            version: Some(env!("CARGO_PKG_VERSION").to_string()),
            platform: Some("tauri".to_string()),
            mode: Some("cli".to_string()),
            instance_id: Some(format!("agent:{}", gateway_id)),
        };
        let device = match build_gateway_device_proof(
            &client,
            &role,
            &scopes,
            auth_token.as_deref(),
            connect_challenge_nonce.as_deref(),
        ) {
            Ok(value) => value,
            Err(err) => {
                tracing::warn!(
                    gateway_id = %gateway_id,
                    "OpenClaw device proof unavailable: {err}"
                );
                None
            }
        };
        let params = GatewayConnectParams {
            min_protocol: 3,
            max_protocol: 3,
            client,
            role: Some(role),
            scopes: Some(scopes),
            auth: if secrets.token.is_some() || secrets.device_token.is_some() {
                Some(GatewayAuth {
                    token: auth_token.clone(),
                    password: secrets.device_token.clone(),
                    device_token: secrets.device_token.clone(),
                })
            } else {
                None
            },
            device,
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
        let mut heartbeat_interval = tokio::time::interval(Duration::from_secs(30));
        heartbeat_interval.reset(); // skip the immediate first tick
        let mut last_received_at = Instant::now();
        const HEARTBEAT_DEAD_TIMEOUT: Duration = Duration::from_secs(90);

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

                    // Check for dead connection (no data received within heartbeat window)
                    if connected && now.duration_since(last_received_at) > HEARTBEAT_DEAD_TIMEOUT {
                        tracing::warn!(
                            gateway_id = %gateway_id,
                            elapsed_secs = now.duration_since(last_received_at).as_secs(),
                            "no data received within heartbeat window, treating connection as dead"
                        );
                        reject_all_pending(&mut pending, "heartbeat timeout");
                        return Ok(ConnectionExit::RemoteClosed("heartbeat timeout".to_string()));
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
                _ = heartbeat_interval.tick() => {
                    if connected {
                        if let Err(err) = sink.send(Message::Ping(Vec::new())).await {
                            tracing::warn!(
                                gateway_id = %gateway_id,
                                "failed to send WebSocket ping: {err}"
                            );
                            reject_all_pending(&mut pending, "ping send failed");
                            return Err(anyhow::anyhow!("failed to send heartbeat ping: {err}"));
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
                            last_received_at = Instant::now();
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
                                GatewayFrame::Req(server_req) => {
                                    let response_frame = match server_req.method.as_str() {
                                        "ping" => Some(GatewayFrame::Res(GatewayResponseFrame {
                                            id: server_req.id.clone(),
                                            ok: true,
                                            payload: Some(serde_json::json!({ "pong": true })),
                                            error: None,
                                        })),
                                        "capabilities" => Some(GatewayFrame::Res(GatewayResponseFrame {
                                            id: server_req.id.clone(),
                                            ok: true,
                                            payload: Some(serde_json::json!({
                                                "capabilities": [
                                                    "operator.read",
                                                    "operator.write",
                                                    "operator.approvals",
                                                    "operator.pairing"
                                                ]
                                            })),
                                            error: None,
                                        })),
                                        _ => None,
                                    };

                                    if let Some(resp) = response_frame {
                                        tracing::debug!(
                                            method = %server_req.method,
                                            "received server-initiated request (handled)"
                                        );
                                        if let Ok(text) = serde_json::to_string(&resp) {
                                            if let Err(err) = sink.send(Message::Text(text)).await {
                                                tracing::warn!(
                                                    method = %server_req.method,
                                                    "failed to send response to server request: {err}"
                                                );
                                            }
                                        }
                                    } else {
                                        tracing::debug!(
                                            method = %server_req.method,
                                            "received server-initiated request (not handled)"
                                        );
                                    }
                                }
                            }
                        }
                        Some(Ok(_)) => {
                            // Binary/ping/pong frames still count as activity.
                            last_received_at = Instant::now();
                        }
                    }
                }
            }
        }
    }
}

pub(super) fn reject_all_pending(pending: &mut HashMap<String, PendingResponse>, reason: &str) {
    let entries: Vec<PendingResponse> = pending.drain().map(|(_, v)| v).collect();
    for entry in entries {
        let _ = entry.tx.send(Err(reason.to_string()));
    }
}
