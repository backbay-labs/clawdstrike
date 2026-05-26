//! SSE-first event collection with audit polling fallback.

use super::dedupe::EventDeduper;
use super::types::{decision_from_allowed_and_severity, should_publish_polled_event};
use super::{DaemonEvent, PolicyEvent};
use crate::decision::NormalizedDecision;
use anyhow::{Context, Result};
use futures::StreamExt;
use reqwest_eventsource::{Event, EventSource};
use serde::Deserialize;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{broadcast, Mutex};

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

    /// Test-only accessor for the SSE dispatch path.
    #[cfg(test)]
    pub(super) async fn handle_sse_message_for_test(
        &self,
        event_type: &str,
        data: &str,
    ) -> Result<()> {
        self.handle_sse_message(event_type, data).await
    }

    /// Test-only accessor for the dedupe/publish path.
    #[cfg(test)]
    pub(super) async fn publish_event_if_new_for_test(&self, event: PolicyEvent) {
        self.publish_event_if_new(event).await
    }
}
