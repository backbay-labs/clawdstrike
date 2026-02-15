//! Event streaming from hushd daemon.
//!
//! Uses SSE as the primary transport and falls back to audit polling when SSE is unavailable.

use crate::decision::NormalizedDecision;
use anyhow::{Context, Result};
use futures::StreamExt;
use reqwest_eventsource::{Event, EventSource};
use serde::{Deserialize, Serialize};
use std::collections::{HashSet, VecDeque};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{broadcast, Mutex};

/// A policy check event from hushd.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyEvent {
    /// Event ID.
    pub id: String,
    /// Timestamp.
    pub timestamp: String,
    /// Action type (e.g., "file_access", "file_write", "egress", "shell", "mcp_tool", "patch").
    pub action_type: String,
    /// Target (file path, URL, command).
    pub target: Option<String>,
    /// Decision (allow/allowed, block/blocked, warn).
    pub decision: String,
    /// Guard that made the decision.
    pub guard: Option<String>,
    /// Severity level.
    pub severity: Option<String>,
    /// Human-readable message.
    pub message: Option<String>,
    /// Additional details.
    #[serde(default)]
    pub details: serde_json::Value,
}

impl PolicyEvent {
    pub fn normalized_decision(&self) -> NormalizedDecision {
        NormalizedDecision::from_str(&self.decision)
    }
}

/// Daemon-level SSE event types beyond audit events.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum DaemonEvent {
    /// Policy was updated on hushd; local cache should refresh.
    PolicyUpdated {
        #[serde(default)]
        version: Option<String>,
    },
    /// A security violation was detected.
    Violation {
        #[serde(default)]
        guard: Option<String>,
        #[serde(default)]
        message: Option<String>,
        #[serde(default)]
        severity: Option<String>,
        #[serde(default)]
        target: Option<String>,
    },
    /// Session posture transitioned (e.g., standard -> restricted).
    SessionPostureTransition {
        #[serde(default)]
        session_id: Option<String>,
        #[serde(default)]
        from: Option<String>,
        #[serde(default)]
        to: Option<String>,
    },
}

#[derive(Debug, Clone)]
struct EventDeduper {
    order: VecDeque<String>,
    set: HashSet<String>,
    max: usize,
}

impl EventDeduper {
    fn new(max: usize) -> Self {
        Self {
            order: VecDeque::new(),
            set: HashSet::new(),
            max,
        }
    }

    fn insert_if_new(&mut self, id: &str) -> bool {
        if self.set.contains(id) {
            return false;
        }

        self.order.push_back(id.to_string());
        self.set.insert(id.to_string());

        while self.order.len() > self.max {
            if let Some(old) = self.order.pop_front() {
                self.set.remove(&old);
            }
        }

        true
    }
}

/// Unified event manager that prefers SSE and falls back to polling.
pub struct EventManager {
    daemon_url: String,
    api_key: Option<String>,
    http_client: reqwest::Client,
    events_tx: broadcast::Sender<PolicyEvent>,
    daemon_events_tx: broadcast::Sender<DaemonEvent>,
    deduper: Arc<Mutex<EventDeduper>>,
    /// Cursor for the polling fallback so we resume from where we left off.
    poll_cursor: Arc<Mutex<Option<String>>>,
}

impl EventManager {
    pub fn new(daemon_url: String, api_key: Option<String>) -> Self {
        let (events_tx, _) = broadcast::channel(200);
        let (daemon_events_tx, _) = broadcast::channel(64);

        Self {
            daemon_url,
            api_key,
            http_client: reqwest::Client::builder()
                .timeout(Duration::from_secs(10))
                .build()
                .unwrap_or_else(|_| reqwest::Client::new()),
            events_tx,
            daemon_events_tx,
            deduper: Arc::new(Mutex::new(EventDeduper::new(2_000))),
            poll_cursor: Arc::new(Mutex::new(None)),
        }
    }

    /// Subscribe to policy check events.
    pub fn subscribe(&self) -> broadcast::Receiver<PolicyEvent> {
        self.events_tx.subscribe()
    }

    /// Subscribe to daemon-level events (policy updates, violations, posture transitions).
    pub fn subscribe_daemon_events(&self) -> broadcast::Receiver<DaemonEvent> {
        self.daemon_events_tx.subscribe()
    }

    /// Start event collection.
    pub async fn start(&self, mut shutdown_rx: broadcast::Receiver<()>) {
        loop {
            match self.stream_sse_until_error(&mut shutdown_rx).await {
                Ok(()) => {
                    tracing::info!("Event manager shutdown (SSE loop)");
                    break;
                }
                Err(err) => {
                    tracing::warn!(error = %err, "SSE unavailable; entering polling fallback");
                    if self.poll_fallback_window(&mut shutdown_rx).await {
                        break;
                    }
                }
            }
        }
    }

    async fn stream_sse_until_error(
        &self,
        shutdown_rx: &mut broadcast::Receiver<()>,
    ) -> Result<()> {
        let url = format!("{}/api/v1/events", self.daemon_url);
        tracing::info!(%url, "Connecting to hushd SSE endpoint");

        let mut builder = reqwest::Client::new().get(&url);
        if let Some(ref key) = self.api_key {
            builder = builder.header("Authorization", format!("Bearer {}", key));
        }

        let mut es = EventSource::new(builder)
            .with_context(|| format!("Failed to create EventSource for {}", url))?;

        loop {
            tokio::select! {
                _ = shutdown_rx.recv() => {
                    es.close();
                    return Ok(());
                }
                evt = es.next() => {
                    match evt {
                        Some(Ok(Event::Open)) => {
                            tracing::info!("hushd SSE connection opened");
                        }
                        Some(Ok(Event::Message(msg))) => {
                            if let Err(err) = self.handle_sse_message(&msg.event, &msg.data).await {
                                tracing::warn!(error = %err, "Failed to parse SSE event payload");
                            }
                        }
                        Some(Err(err)) => {
                            es.close();
                            return Err(anyhow::anyhow!("SSE stream error: {}", err));
                        }
                        None => {
                            es.close();
                            return Err(anyhow::anyhow!("SSE stream ended unexpectedly"));
                        }
                    }
                }
            }
        }
    }

    /// Poll fallback is bounded, then we retry SSE.
    async fn poll_fallback_window(&self, shutdown_rx: &mut broadcast::Receiver<()>) -> bool {
        let poll_interval = Duration::from_secs(2);
        let attempts = 15;

        for _ in 0..attempts {
            tokio::select! {
                _ = shutdown_rx.recv() => return true,
                _ = tokio::time::sleep(poll_interval) => {
                    tokio::select! {
                        _ = shutdown_rx.recv() => return true,
                        result = self.poll_once() => {
                            if let Err(err) = result {
                                tracing::debug!(error = %err, "Audit poll fallback failed");
                            }
                        }
                    }
                }
            }
        }

        false
    }

    async fn poll_once(&self) -> Result<()> {
        #[derive(Deserialize)]
        struct AuditResponse {
            events: Vec<PolicyEvent>,
        }

        let base_url = format!("{}/api/v1/audit", self.daemon_url);
        let limit = 50u32;
        let max_pages = 40u32;
        let cursor = self.poll_cursor.lock().await.clone();

        let mut all_events: Vec<PolicyEvent> = Vec::new();

        for page in 0..max_pages {
            let offset = page * limit;
            let mut request = self
                .http_client
                .get(&base_url)
                .query(&[
                    ("limit", &limit.to_string()),
                    ("offset", &offset.to_string()),
                ]);

            if let Some(ref key) = self.api_key {
                request = request.header("Authorization", format!("Bearer {}", key));
            }

            let response = request
                .send()
                .await
                .with_context(|| "Failed to poll audit events")?;

            if !response.status().is_success() {
                anyhow::bail!("Audit API returned status: {}", response.status());
            }

            let audit: AuditResponse = response
                .json()
                .await
                .with_context(|| "Failed to parse audit response")?;

            let fetched = audit.events.len();

            // Audit endpoint returns newest-first. Collect until we hit the cursor
            // (last seen event id) or exhaust the page.
            let mut hit_cursor = false;
            for event in audit.events {
                if let Some(ref cursor_id) = cursor {
                    if event.id == *cursor_id {
                        hit_cursor = true;
                        break;
                    }
                }
                all_events.push(event);
            }

            if hit_cursor || fetched < limit as usize {
                break;
            }
        }

        // Emit oldest-first for stable UI ordering.
        all_events.reverse();

        // Advance cursor to the newest event we've seen.
        if let Some(newest) = all_events.last() {
            *self.poll_cursor.lock().await = Some(newest.id.clone());
        }

        for event in all_events {
            self.publish_event_if_new(event).await;
        }

        Ok(())
    }

    /// Handle an SSE message using both the SSE event-type field and the JSON data payload.
    ///
    /// hushd puts the event type in the SSE `event:` protocol field, not in the JSON
    /// `data:` payload. We use the SSE event field to identify daemon-level events and
    /// inject the `"type"` key so serde can deserialize the tagged enum.
    async fn handle_sse_message(&self, event_type: &str, data: &str) -> Result<()> {
        if data.is_empty() || data == "ping" {
            return Ok(());
        }

        // Daemon-level events: hushd sends type via SSE `event:` field.
        match event_type {
            "policy_updated" | "violation" | "session_posture_transition" => {
                let mut json: serde_json::Value =
                    serde_json::from_str(data).with_context(|| {
                        format!("Malformed JSON in SSE daemon event ({event_type}): {data}")
                    })?;
                if let Some(obj) = json.as_object_mut() {
                    obj.insert(
                        "type".to_string(),
                        serde_json::Value::String(event_type.to_string()),
                    );
                }
                let daemon_event: DaemonEvent =
                    serde_json::from_value(json).with_context(|| {
                        format!("Failed to parse daemon event ({event_type}): {data}")
                    })?;
                let _ = self.daemon_events_tx.send(daemon_event);
                return Ok(());
            }
            _ => {}
        }

        // Prefer policy audit events when the payload is ambiguous (policy events may also
        // contain a "type" key).
        match serde_json::from_str::<PolicyEvent>(data) {
            Ok(event) => {
                self.publish_event_if_new(event).await;
                Ok(())
            }
            Err(policy_err) => {
                // Fallback: try direct daemon-event deserialization in case the data payload
                // contains "type".
                if let Ok(daemon_event) = serde_json::from_str::<DaemonEvent>(data) {
                    let _ = self.daemon_events_tx.send(daemon_event);
                    return Ok(());
                }

                Err::<(), _>(policy_err)
                    .with_context(|| format!("Failed to parse SSE event payload: {}", data))
            }
        }
    }

    async fn publish_event_if_new(&self, event: PolicyEvent) {
        {
            let mut deduper = self.deduper.lock().await;
            if !deduper.insert_if_new(&event.id) {
                return;
            }
        }

        let _ = self.events_tx.send(event);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_policy_event_deserialize() {
        let json = r#"{
            "id": "123",
            "timestamp": "2024-01-01T00:00:00Z",
            "action_type": "file_access",
            "target": "/etc/passwd",
            "decision": "blocked",
            "guard": "fs_blocklist",
            "severity": "high"
        }"#;

        let event: PolicyEvent = match serde_json::from_str(json) {
            Ok(value) => value,
            Err(err) => panic!("failed to parse event fixture: {err}"),
        };
        assert_eq!(event.id, "123");
        assert!(event.normalized_decision().is_blocked());
    }

    #[test]
    fn daemon_event_policy_updated_deserializes() {
        let json = r#"{"type":"policy_updated","version":"1.2.0"}"#;
        let event: DaemonEvent = match serde_json::from_str(json) {
            Ok(v) => v,
            Err(err) => panic!("failed to parse policy_updated event: {err}"),
        };
        assert!(matches!(event, DaemonEvent::PolicyUpdated { .. }));
    }

    #[test]
    fn daemon_event_violation_deserializes() {
        let json = r#"{"type":"violation","guard":"fs_blocklist","severity":"high","target":"/etc/shadow"}"#;
        let event: DaemonEvent = match serde_json::from_str(json) {
            Ok(v) => v,
            Err(err) => panic!("failed to parse violation event: {err}"),
        };
        assert!(matches!(event, DaemonEvent::Violation { .. }));
    }

    #[test]
    fn daemon_event_posture_transition_deserializes() {
        let json = r#"{"type":"session_posture_transition","session_id":"s-1","from":"standard","to":"restricted"}"#;
        let event: DaemonEvent = match serde_json::from_str(json) {
            Ok(v) => v,
            Err(err) => panic!("failed to parse posture transition event: {err}"),
        };
        assert!(matches!(
            event,
            DaemonEvent::SessionPostureTransition { .. }
        ));
    }

    /// Verify that handle_sse_message dispatches daemon events using the SSE event-type
    /// field (how hushd actually sends them) rather than requiring "type" in the JSON data.
    #[tokio::test]
    async fn sse_event_field_dispatches_daemon_events() {
        let mgr = EventManager::new("http://localhost:0".to_string(), None);
        let mut daemon_rx = mgr.subscribe_daemon_events();

        // hushd sends: event: policy_updated\ndata: {"version":"2.0.0"}
        // Note: no "type" key in the JSON payload.
        mgr.handle_sse_message("policy_updated", r#"{"version":"2.0.0"}"#)
            .await
            .expect("should dispatch policy_updated");

        let evt = daemon_rx
            .try_recv()
            .expect("should have received daemon event");
        assert!(matches!(evt, DaemonEvent::PolicyUpdated { version: Some(v) } if v == "2.0.0"));

        // violation with SSE event field
        mgr.handle_sse_message("violation", r#"{"guard":"fs_blocklist","severity":"high"}"#)
            .await
            .expect("should dispatch violation");

        let evt = daemon_rx
            .try_recv()
            .expect("should have received violation event");
        assert!(
            matches!(evt, DaemonEvent::Violation { guard: Some(g), .. } if g == "fs_blocklist")
        );
    }

    /// Verify that audit events (no special SSE event field) still parse correctly.
    #[tokio::test]
    async fn sse_default_event_dispatches_audit() {
        let mgr = EventManager::new("http://localhost:0".to_string(), None);
        let mut events_rx = mgr.subscribe();

        let data = r#"{"id":"ev-1","timestamp":"2024-01-01T00:00:00Z","action_type":"file_access","decision":"blocked"}"#;
        mgr.handle_sse_message("message", data)
            .await
            .expect("should dispatch audit event");

        let evt = events_rx
            .try_recv()
            .expect("should have received policy event");
        assert_eq!(evt.id, "ev-1");
    }

    /// Malformed JSON in a known daemon event type must return an error,
    /// not silently create a phantom event with all-None fields.
    #[tokio::test]
    async fn sse_malformed_json_returns_error() {
        let mgr = EventManager::new("http://localhost:0".to_string(), None);
        let mut daemon_rx = mgr.subscribe_daemon_events();

        let result = mgr
            .handle_sse_message("violation", "not valid json{{{")
            .await;
        assert!(result.is_err(), "malformed JSON should be an error");

        // No phantom event should have been emitted.
        assert!(daemon_rx.try_recv().is_err());
    }

    #[test]
    fn deduper_drops_replays() {
        let mut deduper = EventDeduper::new(3);
        assert!(deduper.insert_if_new("a"));
        assert!(!deduper.insert_if_new("a"));
        assert!(deduper.insert_if_new("b"));
        assert!(deduper.insert_if_new("c"));
        assert!(deduper.insert_if_new("d"));
        // "a" falls out of the dedupe window and can re-appear if needed.
        assert!(deduper.insert_if_new("a"));
    }
}
