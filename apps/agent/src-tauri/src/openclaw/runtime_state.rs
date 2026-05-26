//! Runtime-state mutators on `OpenClawManager`.
//!
//! These helpers are used by the connection loop in `connection.rs` to update
//! per-gateway runtime snapshots (status, last-error, last-message-at,
//! connected-at) and to fan out updates to the broadcast bus.

use super::dto::{GatewayConnectionStatus, GatewayRuntimeSnapshot, OpenClawAgentEvent};
use super::manager::OpenClawManager;
use super::protocol::GatewayEventFrame;
use super::util::now_ms;
use std::time::Duration;

impl OpenClawManager {
    pub(super) async fn set_runtime_connected(&self, gateway_id: &str) {
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

    pub(super) async fn touch_runtime_message(&self, gateway_id: &str) {
        let mut runtimes = self.runtime_by_id.write().await;
        let rt = runtimes
            .entry(gateway_id.to_string())
            .or_insert_with(GatewayRuntimeSnapshot::default);
        rt.last_message_at_ms = Some(now_ms());
    }

    pub(super) async fn set_runtime_status(
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

    pub(super) async fn connection_was_stable(
        &self,
        gateway_id: &str,
        stable_reset: Duration,
    ) -> bool {
        let connected_at = self
            .runtime_by_id
            .read()
            .await
            .get(gateway_id)
            .and_then(|rt| rt.connected_at_ms);
        super::backoff::was_connected_long_enough(connected_at, stable_reset, now_ms())
    }

    pub(super) async fn remove_session_if_current(&self, gateway_id: &str, session_id: u64) {
        let mut sessions = self.sessions.write().await;
        let should_remove = sessions
            .get(gateway_id)
            .is_some_and(|handle| handle.session_id == session_id);

        if should_remove {
            sessions.remove(gateway_id);
        }
    }

    pub(super) async fn apply_gateway_event(&self, gateway_id: &str, frame: GatewayEventFrame) {
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
                "exec.approval.resolved" | "exec.approval.rejected" => {
                    if let Some(payload) = &frame.payload {
                        let approval_id = payload
                            .get("approvalId")
                            .or_else(|| payload.get("id"))
                            .and_then(|v| v.as_str());
                        if let Some(id) = approval_id {
                            rt.exec_approval_queue
                                .retain(|a| a.get("id").and_then(|v| v.as_str()) != Some(id));
                        }
                    }
                }
                "node.connected" | "node.updated" => {
                    if let Some(payload) = &frame.payload {
                        let node_id = payload
                            .get("nodeId")
                            .and_then(|v| v.as_str())
                            .or_else(|| payload.get("id").and_then(|v| v.as_str()));
                        if let Some(node_id) = node_id {
                            // Normalize: ensure nodeId is always present on the
                            // stored entry, matching the TS client behaviour.
                            let mut normalized = payload.clone();
                            if let serde_json::Value::Object(ref mut m) = normalized {
                                m.insert(
                                    "nodeId".into(),
                                    serde_json::Value::String(node_id.to_owned()),
                                );
                            }
                            if let Some(existing) = rt.nodes.iter_mut().find(|n| {
                                n.get("nodeId").and_then(|v| v.as_str()) == Some(node_id)
                                    || n.get("id").and_then(|v| v.as_str()) == Some(node_id)
                            }) {
                                *existing = normalized;
                            } else {
                                rt.nodes.push(normalized);
                            }
                        }
                    }
                }
                "node.disconnected" => {
                    if let Some(payload) = &frame.payload {
                        let node_id = payload
                            .get("nodeId")
                            .and_then(|v| v.as_str())
                            .or_else(|| payload.get("id").and_then(|v| v.as_str()));
                        if let Some(node_id) = node_id {
                            rt.nodes.retain(|n| {
                                n.get("nodeId").and_then(|v| v.as_str()) != Some(node_id)
                                    && n.get("id").and_then(|v| v.as_str()) != Some(node_id)
                            });
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
