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
    /// Session that triggered this event.
    #[serde(default)]
    pub session_id: Option<String>,
    /// Agent that triggered this event.
    #[serde(default)]
    pub agent_id: Option<String>,
}

impl PolicyEvent {
    pub fn normalized_decision(&self) -> NormalizedDecision {
        NormalizedDecision::from_str(&self.decision)
    }
}

fn should_publish_polled_event(event: &PolicyEvent) -> bool {
    !matches!(event.normalized_decision(), NormalizedDecision::Allowed)
}

fn decision_from_allowed_and_severity(allowed: bool, severity: Option<&str>) -> &'static str {
    if !allowed {
        return "blocked";
    }

    let is_warning = severity
        .map(|value| value.trim().to_ascii_lowercase())
        .map(|value| matches!(value.as_str(), "warn" | "warning" | "medium"))
        .unwrap_or(false);

    if is_warning {
        "warn"
    } else {
        "allowed"
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
        #[serde(default)]
        session_id: Option<String>,
        #[serde(default)]
        agent_id: Option<String>,
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
    /// Endpoint/runtime heartbeat update from hushd.
    AgentHeartbeat {
        #[serde(default)]
        endpoint_agent_id: Option<String>,
        #[serde(default)]
        runtime_agent_id: Option<String>,
        #[serde(default)]
        runtime_agent_kind: Option<String>,
        #[serde(default)]
        session_id: Option<String>,
        #[serde(default)]
        posture: Option<String>,
        #[serde(default)]
        policy_version: Option<String>,
        #[serde(default)]
        daemon_version: Option<String>,
        #[serde(default)]
        timestamp: Option<String>,
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
            let mut request = self.http_client.get(&base_url).query(&[
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
            if should_publish_polled_event(&event) {
                self.publish_event_if_new(event).await;
            }
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
            "policy_updated"
            | "violation"
            | "check"
            | "session_posture_transition"
            | "agent_heartbeat" => {
                let mut json: serde_json::Value =
                    serde_json::from_str(data).with_context(|| {
                        format!("Malformed JSON in SSE daemon event ({event_type}): {data}")
                    })?;

                // Synthesize a PolicyEvent for the tray display from check and violation events.
                // To avoid flooding the in-process broadcast channel with high-volume allowed
                // checks, we only surface blocked checks and all violations.
                if event_type == "check" || event_type == "violation" {
                    let Some(obj) = json.as_object() else {
                        anyhow::bail!("Expected JSON object for {event_type} event, got: {data}");
                    };
                    let allowed = obj
                        .get("allowed")
                        .and_then(|v| v.as_bool())
                        .unwrap_or(false);
                    let severity = obj.get("severity").and_then(|v| v.as_str());
                    let decision = if event_type == "violation" {
                        "blocked"
                    } else {
                        decision_from_allowed_and_severity(allowed, severity)
                    };
                    let should_publish = !matches!(
                        NormalizedDecision::from_str(decision),
                        NormalizedDecision::Allowed
                    );
                    if should_publish {
                        let policy_event = PolicyEvent {
                            id: obj
                                .get("event_id")
                                .and_then(|v| v.as_str())
                                .map(String::from)
                                .unwrap_or_else(|| uuid::Uuid::new_v4().to_string()),
                            timestamp: obj
                                .get("timestamp")
                                .and_then(|v| v.as_str())
                                .map(String::from)
                                .unwrap_or_else(|| chrono::Utc::now().to_rfc3339()),
                            action_type: obj
                                .get("action_type")
                                .and_then(|v| v.as_str())
                                .unwrap_or("unknown")
                                .to_string(),
                            target: obj.get("target").and_then(|v| v.as_str()).map(String::from),
                            decision: decision.to_string(),
                            guard: obj.get("guard").and_then(|v| v.as_str()).map(String::from),
                            severity: severity.map(String::from).or_else(|| {
                                if allowed {
                                    None
                                } else {
                                    Some("high".to_string())
                                }
                            }),
                            message: obj
                                .get("message")
                                .and_then(|v| v.as_str())
                                .map(String::from),
                            details: obj
                                .get("details")
                                .cloned()
                                .unwrap_or(serde_json::Value::Null),
                            session_id: obj
                                .get("session_id")
                                .and_then(|v| v.as_str())
                                .map(String::from),
                            agent_id: obj
                                .get("agent_id")
                                .and_then(|v| v.as_str())
                                .map(String::from),
                        };
                        self.publish_event_if_new(policy_event).await;
                    }
                }

                // "check" events are only for tray display; skip daemon event dispatch.
                if event_type == "check" {
                    return Ok(());
                }

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
#[allow(clippy::unwrap_used, clippy::expect_used)]
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
        let json = r#"{"type":"violation","guard":"fs_blocklist","severity":"high","target":"/etc/shadow","session_id":"s-1","agent_id":"a-1"}"#;
        let event: DaemonEvent = match serde_json::from_str(json) {
            Ok(v) => v,
            Err(err) => panic!("failed to parse violation event: {err}"),
        };
        match event {
            DaemonEvent::Violation {
                guard,
                session_id,
                agent_id,
                ..
            } => {
                assert_eq!(guard.as_deref(), Some("fs_blocklist"));
                assert_eq!(session_id.as_deref(), Some("s-1"));
                assert_eq!(agent_id.as_deref(), Some("a-1"));
            }
            other => panic!("expected Violation, got {:?}", other),
        }
    }

    #[test]
    fn daemon_event_violation_deserializes_without_attribution() {
        let json = r#"{"type":"violation","guard":"fs_blocklist","severity":"high"}"#;
        let event: DaemonEvent = match serde_json::from_str(json) {
            Ok(v) => v,
            Err(err) => panic!("failed to parse violation event: {err}"),
        };
        match event {
            DaemonEvent::Violation {
                session_id,
                agent_id,
                ..
            } => {
                assert!(session_id.is_none());
                assert!(agent_id.is_none());
            }
            other => panic!("expected Violation, got {:?}", other),
        }
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

    #[test]
    fn daemon_event_agent_heartbeat_deserializes() {
        let json = r#"{"type":"agent_heartbeat","endpoint_agent_id":"agent-1","runtime_agent_id":"runtime-1","runtime_agent_kind":"desktop","session_id":"s-1","posture":"standard","policy_version":"1.0.0","daemon_version":"0.2.5","timestamp":"2026-03-06T03:49:39Z"}"#;
        let event: DaemonEvent = match serde_json::from_str(json) {
            Ok(v) => v,
            Err(err) => panic!("failed to parse agent heartbeat event: {err}"),
        };
        assert!(matches!(
            event,
            DaemonEvent::AgentHeartbeat {
                endpoint_agent_id: Some(ref agent_id),
                runtime_agent_id: Some(ref runtime_id),
                ..
            } if agent_id == "agent-1" && runtime_id == "runtime-1"
        ));
    }

    /// Verify that handle_sse_message dispatches daemon events using the SSE event-type
    /// field (how hushd actually sends them) rather than requiring "type" in the JSON data.
    #[tokio::test]
    async fn sse_event_field_dispatches_daemon_events() {
        let mgr = EventManager::new("http://localhost:0".to_string(), None);
        let mut daemon_rx = mgr.subscribe_daemon_events();
        let mut events_rx = mgr.subscribe();

        // hushd sends: event: policy_updated\ndata: {"version":"2.0.0"}
        // Note: no "type" key in the JSON payload.
        mgr.handle_sse_message("policy_updated", r#"{"version":"2.0.0"}"#)
            .await
            .expect("should dispatch policy_updated");

        let evt = daemon_rx
            .try_recv()
            .expect("should have received daemon event");
        assert!(matches!(evt, DaemonEvent::PolicyUpdated { version: Some(v) } if v == "2.0.0"));

        // violation with SSE event field — should produce both a PolicyEvent and a DaemonEvent
        mgr.handle_sse_message(
            "violation",
            r#"{"event_id":"ev-v7","guard":"fs_blocklist","severity":"high","allowed":false,"action_type":"file_access","target":"/etc/shadow","session_id":"s-1","agent_id":"a-1"}"#,
        )
        .await
        .expect("should dispatch violation");

        // Violation should produce a PolicyEvent via the unified path.
        let policy_evt = events_rx
            .try_recv()
            .expect("violation should produce a PolicyEvent");
        assert_eq!(policy_evt.id, "ev-v7");
        assert_eq!(policy_evt.session_id.as_deref(), Some("s-1"));
        assert_eq!(policy_evt.agent_id.as_deref(), Some("a-1"));
        assert!(policy_evt.normalized_decision().is_blocked());

        // Violation should also produce a DaemonEvent for logging.
        let evt = daemon_rx
            .try_recv()
            .expect("should have received violation event");
        assert!(
            matches!(evt, DaemonEvent::Violation { guard: Some(g), session_id: Some(s), .. } if g == "fs_blocklist" && s == "s-1")
        );

        mgr.handle_sse_message(
            "agent_heartbeat",
            r#"{"endpoint_agent_id":"agent-1","runtime_agent_id":"runtime-1","runtime_agent_kind":"desktop","session_id":"s-1","posture":"standard","policy_version":"1.0.0","daemon_version":"0.2.5","timestamp":"2026-03-06T03:49:39Z"}"#,
        )
        .await
        .expect("should dispatch agent heartbeat");

        let evt = daemon_rx
            .try_recv()
            .expect("should have received agent heartbeat event");
        assert!(matches!(
            evt,
            DaemonEvent::AgentHeartbeat {
                endpoint_agent_id: Some(ref agent_id),
                posture: Some(ref posture),
                ..
            } if agent_id == "agent-1" && posture == "standard"
        ));
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

    /// Non-object JSON payloads (arrays, strings) for check/violation must be rejected
    /// rather than producing a phantom PolicyEvent with action_type="unknown".
    #[tokio::test]
    async fn sse_non_object_json_rejects_for_check_and_violation() {
        let mgr = EventManager::new("http://localhost:0".to_string(), None);
        let mut events_rx = mgr.subscribe();

        for event_type in &["check", "violation"] {
            let result = mgr.handle_sse_message(event_type, r#"[1, 2, 3]"#).await;
            assert!(
                result.is_err(),
                "non-object JSON should be rejected for {event_type}"
            );

            let result = mgr
                .handle_sse_message(event_type, r#""just a string""#)
                .await;
            assert!(
                result.is_err(),
                "string JSON should be rejected for {event_type}"
            );
        }

        // No phantom events should have been emitted.
        assert!(events_rx.try_recv().is_err());
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

    #[test]
    fn policy_event_with_session_and_agent_ids() {
        let json = r#"{
            "id": "ev-100",
            "timestamp": "2024-01-01T00:00:00Z",
            "action_type": "file_access",
            "target": "/etc/passwd",
            "decision": "blocked",
            "guard": "fs_blocklist",
            "severity": "high",
            "session_id": "sess-abc",
            "agent_id": "agent-xyz"
        }"#;

        let event: PolicyEvent = serde_json::from_str(json).expect("should parse with ids");
        assert_eq!(event.session_id.as_deref(), Some("sess-abc"));
        assert_eq!(event.agent_id.as_deref(), Some("agent-xyz"));
    }

    #[test]
    fn policy_event_without_session_and_agent_ids() {
        let json = r#"{
            "id": "ev-101",
            "timestamp": "2024-01-01T00:00:00Z",
            "action_type": "egress",
            "decision": "allowed"
        }"#;

        let event: PolicyEvent = serde_json::from_str(json).expect("should parse without ids");
        assert!(event.session_id.is_none());
        assert!(event.agent_id.is_none());
    }

    #[tokio::test]
    async fn sse_check_event_propagates_session_agent_ids() {
        let mgr = EventManager::new("http://localhost:0".to_string(), None);
        let mut events_rx = mgr.subscribe();

        let data = r#"{"action_type":"file_access","target":"/etc/shadow","allowed":false,"guard":"fs_blocklist","policy_hash":"abc123","session_id":"s-42","agent_id":"a-7"}"#;
        mgr.handle_sse_message("check", data)
            .await
            .expect("should handle check with ids");

        let evt = events_rx.try_recv().expect("should have received event");
        assert_eq!(evt.session_id.as_deref(), Some("s-42"));
        assert_eq!(evt.agent_id.as_deref(), Some("a-7"));
        assert_eq!(evt.decision, "blocked");
    }

    #[tokio::test]
    async fn sse_allowed_check_event_is_not_published() {
        let mgr = EventManager::new("http://localhost:0".to_string(), None);
        let mut events_rx = mgr.subscribe();

        let data =
            r#"{"action_type":"file_access","target":"/tmp/x","allowed":true,"guard":"fs_allow"}"#;
        mgr.handle_sse_message("check", data)
            .await
            .expect("should handle allowed check event");

        assert!(
            events_rx.try_recv().is_err(),
            "allowed check should not be published to policy channel"
        );
    }

    #[tokio::test]
    async fn sse_allowed_warning_check_event_is_published_as_warn() {
        let mgr = EventManager::new("http://localhost:0".to_string(), None);
        let mut events_rx = mgr.subscribe();

        let data = r#"{"action_type":"file_access","target":"/tmp/x","allowed":true,"guard":"fs_allow","severity":"warning"}"#;
        mgr.handle_sse_message("check", data)
            .await
            .expect("should handle warning check event");

        let evt = events_rx
            .try_recv()
            .expect("warning check should be published");
        assert_eq!(evt.decision, "warn");
    }

    /// Verify that SSE events with a stable event_id from hushd are deduped against the same
    /// events arriving via poll_once().
    #[tokio::test]
    async fn sse_and_poll_dedup_with_stable_event_id() {
        let mgr = EventManager::new("http://localhost:0".to_string(), None);
        let mut events_rx = mgr.subscribe();

        // Simulate SSE check event with stable event_id (as hushd now sends).
        let data = r#"{"event_id":"019abc-v7","action_type":"file_access","target":"/etc/shadow","allowed":false,"guard":"fs_blocklist","session_id":"s-1","agent_id":"a-1"}"#;
        mgr.handle_sse_message("check", data)
            .await
            .expect("should handle check event");

        let evt = events_rx
            .try_recv()
            .expect("should have received policy event");
        assert_eq!(evt.id, "019abc-v7", "should use stable ID from hushd");

        // Simulate the same event arriving via poll_once (audit API returns same ID).
        let poll_event = PolicyEvent {
            id: "019abc-v7".to_string(),
            timestamp: "2024-01-01T00:00:00Z".to_string(),
            action_type: "file_access".to_string(),
            target: Some("/etc/shadow".to_string()),
            decision: "blocked".to_string(),
            guard: Some("fs_blocklist".to_string()),
            severity: Some("high".to_string()),
            message: None,
            details: serde_json::Value::Null,
            session_id: Some("s-1".to_string()),
            agent_id: Some("a-1".to_string()),
        };
        mgr.publish_event_if_new(poll_event).await;

        // Should be deduped — no new event on the channel.
        assert!(
            events_rx.try_recv().is_err(),
            "duplicate event should be deduped"
        );
    }

    #[tokio::test]
    async fn poll_filter_suppresses_allowed_events_and_keeps_blocks() {
        let mgr = EventManager::new("http://localhost:0".to_string(), None);
        let mut events_rx = mgr.subscribe();

        for i in 0..500usize {
            let allowed = PolicyEvent {
                id: format!("allow-{i}"),
                timestamp: "2024-01-01T00:00:00Z".to_string(),
                action_type: "file_access".to_string(),
                target: Some(format!("/tmp/allowed-{i}")),
                decision: "allowed".to_string(),
                guard: Some("fs_allow".to_string()),
                severity: None,
                message: None,
                details: serde_json::Value::Null,
                session_id: None,
                agent_id: None,
            };
            if should_publish_polled_event(&allowed) {
                mgr.publish_event_if_new(allowed).await;
            }
        }

        let blocked = PolicyEvent {
            id: "blocked-1".to_string(),
            timestamp: "2024-01-01T00:00:00Z".to_string(),
            action_type: "file_access".to_string(),
            target: Some("/etc/shadow".to_string()),
            decision: "blocked".to_string(),
            guard: Some("fs_blocklist".to_string()),
            severity: Some("high".to_string()),
            message: None,
            details: serde_json::Value::Null,
            session_id: None,
            agent_id: None,
        };
        if should_publish_polled_event(&blocked) {
            mgr.publish_event_if_new(blocked).await;
        }

        let evt = events_rx
            .try_recv()
            .expect("blocked event should still be published");
        assert_eq!(evt.id, "blocked-1");
        assert!(
            events_rx.try_recv().is_err(),
            "allowed poll events should be suppressed"
        );
    }
}
