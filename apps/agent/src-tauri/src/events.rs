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

const AUDIT_PAGE_SIZE: usize = 50;
const AUDIT_MAX_PAGES: usize = 40;

/// A policy check event from hushd.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyEvent {
    /// Event ID.
    pub id: String,
    /// Timestamp.
    pub timestamp: String,
    /// Action type (e.g., "file_access", "network", "exec").
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
    poll_cursor_id: Arc<Mutex<Option<String>>>,
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
            poll_cursor_id: Arc::new(Mutex::new(None)),
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
                            if let Err(err) = self.handle_raw_event(&msg.data).await {
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

        let url = format!("{}/api/v1/audit", self.daemon_url);
        let cursor_id = self.poll_cursor_id.lock().await.clone();
        let mut offset = 0usize;
        let mut pages = 0usize;
        let mut found_cursor = false;
        let mut unseen_desc: Vec<PolicyEvent> = Vec::new();

        while pages < AUDIT_MAX_PAGES {
            let mut request = self.http_client.get(&url).query(&[
                ("limit", AUDIT_PAGE_SIZE.to_string()),
                ("offset", offset.to_string()),
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
            if audit.events.is_empty() {
                break;
            }

            let page_len = audit.events.len();
            for event in audit.events {
                if cursor_id.as_ref().is_some_and(|id| &event.id == id) {
                    found_cursor = true;
                    break;
                }
                unseen_desc.push(event);
            }

            pages += 1;
            if found_cursor || page_len < AUDIT_PAGE_SIZE {
                break;
            }
            offset += AUDIT_PAGE_SIZE;
        }

        if pages == AUDIT_MAX_PAGES && !found_cursor {
            tracing::warn!(
                page_limit = AUDIT_MAX_PAGES,
                "Audit poll fallback reached pagination cap; some older events may be skipped"
            );
        }

        if let Some(newest_unseen) = unseen_desc.first() {
            *self.poll_cursor_id.lock().await = Some(newest_unseen.id.clone());
        }

        // Audit endpoint is newest-first; emit oldest-first for stable UI ordering.
        for event in unseen_desc.into_iter().rev() {
            self.publish_event_if_new(event).await;
        }

        Ok(())
    }

    async fn handle_raw_event(&self, data: &str) -> Result<()> {
        // Skip heartbeats.
        if data.is_empty() || data == "ping" {
            return Ok(());
        }

        // Try to parse as a daemon-level event first (has a "type" field).
        if let Ok(daemon_event) = serde_json::from_str::<DaemonEvent>(data) {
            let _ = self.daemon_events_tx.send(daemon_event);
            return Ok(());
        }

        // Otherwise treat as a policy audit event.
        let event: PolicyEvent = serde_json::from_str(data)
            .with_context(|| format!("Failed to parse SSE event payload: {}", data))?;

        self.publish_event_if_new(event).await;
        Ok(())
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
