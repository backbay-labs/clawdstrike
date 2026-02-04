//! Event streaming from hushd daemon
//!
//! Subscribes to SSE events from the daemon and dispatches them.

use anyhow::{Context, Result};
use futures::StreamExt;
use reqwest_eventsource::{Event, EventSource};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{broadcast, RwLock};

/// A policy check event from hushd
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyEvent {
    /// Event ID
    pub id: String,
    /// Timestamp
    pub timestamp: String,
    /// Action type (e.g., "file_access", "network", "exec")
    pub action_type: String,
    /// Target (file path, URL, command)
    pub target: Option<String>,
    /// Decision (allow, block, warn)
    pub decision: String,
    /// Guard that made the decision
    pub guard: Option<String>,
    /// Severity level
    pub severity: Option<String>,
    /// Human-readable message
    pub message: Option<String>,
    /// Additional details
    #[serde(default)]
    pub details: serde_json::Value,
}

/// Event subscriber that connects to hushd SSE endpoint
pub struct EventSubscriber {
    daemon_url: String,
    api_key: Option<String>,
    events_tx: broadcast::Sender<PolicyEvent>,
    recent_events: Arc<RwLock<Vec<PolicyEvent>>>,
    max_recent: usize,
}

impl EventSubscriber {
    /// Create a new event subscriber
    pub fn new(daemon_url: String, api_key: Option<String>) -> Self {
        let (events_tx, _) = broadcast::channel(100);

        Self {
            daemon_url,
            api_key,
            events_tx,
            recent_events: Arc::new(RwLock::new(Vec::new())),
            max_recent: 100,
        }
    }

    /// Subscribe to events
    pub fn subscribe(&self) -> broadcast::Receiver<PolicyEvent> {
        self.events_tx.subscribe()
    }

    /// Get recent events
    pub async fn recent_events(&self) -> Vec<PolicyEvent> {
        self.recent_events.read().await.clone()
    }

    /// Start the event subscription loop
    pub async fn start(&self, mut shutdown_rx: broadcast::Receiver<()>) {
        loop {
            tokio::select! {
                _ = shutdown_rx.recv() => {
                    tracing::info!("Event subscriber received shutdown signal");
                    break;
                }
                result = self.connect_and_stream() => {
                    match result {
                        Ok(_) => {
                            tracing::info!("SSE stream ended normally");
                        }
                        Err(e) => {
                            tracing::warn!("SSE connection error: {}", e);
                        }
                    }
                    // Reconnect after a delay
                    tokio::time::sleep(Duration::from_secs(5)).await;
                }
            }
        }
    }

    async fn connect_and_stream(&self) -> Result<()> {
        let url = format!("{}/api/v1/events", self.daemon_url);
        tracing::info!("Connecting to SSE endpoint: {}", url);

        let mut builder = reqwest::Client::new().get(&url);

        if let Some(ref key) = self.api_key {
            builder = builder.header("Authorization", format!("Bearer {}", key));
        }

        let mut es = EventSource::new(builder)
            .with_context(|| format!("Failed to create EventSource for {}", url))?;

        while let Some(event) = es.next().await {
            match event {
                Ok(Event::Open) => {
                    tracing::info!("SSE connection opened");
                }
                Ok(Event::Message(msg)) => {
                    if let Err(e) = self.handle_message(&msg.data).await {
                        tracing::warn!("Failed to handle SSE message: {}", e);
                    }
                }
                Err(e) => {
                    tracing::warn!("SSE error: {}", e);
                    es.close();
                    return Err(anyhow::anyhow!("SSE error: {}", e));
                }
            }
        }

        Ok(())
    }

    async fn handle_message(&self, data: &str) -> Result<()> {
        // Skip empty messages or heartbeats
        if data.is_empty() || data == "ping" {
            return Ok(());
        }

        // Parse the event
        let event: PolicyEvent = serde_json::from_str(data)
            .with_context(|| format!("Failed to parse event: {}", data))?;

        tracing::debug!("Received event: {:?}", event);

        // Store in recent events
        {
            let mut recent = self.recent_events.write().await;
            recent.insert(0, event.clone());
            if recent.len() > self.max_recent {
                recent.truncate(self.max_recent);
            }
        }

        // Broadcast to subscribers
        let _ = self.events_tx.send(event);

        Ok(())
    }
}

/// Poll-based event fetcher for when SSE is not available
pub struct EventPoller {
    daemon_url: String,
    api_key: Option<String>,
    http_client: reqwest::Client,
    events_tx: broadcast::Sender<PolicyEvent>,
    recent_events: Arc<RwLock<Vec<PolicyEvent>>>,
    last_event_id: Arc<RwLock<Option<String>>>,
    max_recent: usize,
}

impl EventPoller {
    /// Create a new event poller
    pub fn new(daemon_url: String, api_key: Option<String>) -> Self {
        let (events_tx, _) = broadcast::channel(100);

        Self {
            daemon_url,
            api_key,
            http_client: reqwest::Client::builder()
                .timeout(Duration::from_secs(10))
                .build()
                .unwrap_or_default(),
            events_tx,
            recent_events: Arc::new(RwLock::new(Vec::new())),
            last_event_id: Arc::new(RwLock::new(None)),
            max_recent: 100,
        }
    }

    /// Subscribe to events
    pub fn subscribe(&self) -> broadcast::Receiver<PolicyEvent> {
        self.events_tx.subscribe()
    }

    /// Get recent events
    pub async fn recent_events(&self) -> Vec<PolicyEvent> {
        self.recent_events.read().await.clone()
    }

    /// Start the polling loop
    pub async fn start(&self, mut shutdown_rx: broadcast::Receiver<()>) {
        let poll_interval = Duration::from_secs(2);

        loop {
            tokio::select! {
                _ = shutdown_rx.recv() => {
                    tracing::info!("Event poller received shutdown signal");
                    break;
                }
                _ = tokio::time::sleep(poll_interval) => {
                    if let Err(e) = self.poll_events().await {
                        tracing::debug!("Event poll failed: {}", e);
                    }
                }
            }
        }
    }

    async fn poll_events(&self) -> Result<()> {
        let url = format!("{}/api/v1/audit", self.daemon_url);

        let mut request = self.http_client.get(&url);

        if let Some(ref key) = self.api_key {
            request = request.header("Authorization", format!("Bearer {}", key));
        }

        // Add pagination params
        let last_id = self.last_event_id.read().await.clone();
        if let Some(ref id) = last_id {
            request = request.query(&[("after", id)]);
        }
        request = request.query(&[("limit", "50")]);

        let response = request
            .send()
            .await
            .with_context(|| "Failed to poll audit events")?;

        if !response.status().is_success() {
            anyhow::bail!("Audit API returned status: {}", response.status());
        }

        #[derive(Deserialize)]
        struct AuditResponse {
            events: Vec<PolicyEvent>,
        }

        let audit: AuditResponse = response
            .json()
            .await
            .with_context(|| "Failed to parse audit response")?;

        // Process new events
        for event in audit.events {
            // Update last event ID
            *self.last_event_id.write().await = Some(event.id.clone());

            // Store in recent events
            {
                let mut recent = self.recent_events.write().await;
                recent.insert(0, event.clone());
                if recent.len() > self.max_recent {
                    recent.truncate(self.max_recent);
                }
            }

            // Broadcast to subscribers
            let _ = self.events_tx.send(event);
        }

        Ok(())
    }
}

/// Unified event manager that tries SSE first, falls back to polling
pub struct EventManager {
    daemon_url: String,
    api_key: Option<String>,
    events_tx: broadcast::Sender<PolicyEvent>,
    recent_events: Arc<RwLock<Vec<PolicyEvent>>>,
}

impl EventManager {
    pub fn new(daemon_url: String, api_key: Option<String>) -> Self {
        let (events_tx, _) = broadcast::channel(100);

        Self {
            daemon_url,
            api_key,
            events_tx,
            recent_events: Arc::new(RwLock::new(Vec::new())),
        }
    }

    /// Subscribe to events
    pub fn subscribe(&self) -> broadcast::Receiver<PolicyEvent> {
        self.events_tx.subscribe()
    }

    /// Get recent events
    pub async fn recent_events(&self) -> Vec<PolicyEvent> {
        self.recent_events.read().await.clone()
    }

    /// Start event collection
    pub async fn start(&self, shutdown_rx: broadcast::Receiver<()>) {
        // Use polling since hushd may not have SSE endpoint
        let poller = EventPoller::new(self.daemon_url.clone(), self.api_key.clone());

        // Forward events from poller to our channel
        let events_tx = self.events_tx.clone();
        let recent_events = Arc::clone(&self.recent_events);
        let mut rx = poller.subscribe();

        tokio::spawn(async move {
            while let Ok(event) = rx.recv().await {
                // Store in our recent events
                {
                    let mut recent = recent_events.write().await;
                    recent.insert(0, event.clone());
                    if recent.len() > 100 {
                        recent.truncate(100);
                    }
                }
                // Forward
                let _ = events_tx.send(event);
            }
        });

        poller.start(shutdown_rx).await;
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
            "decision": "block",
            "guard": "fs_blocklist",
            "severity": "high"
        }"#;

        let event: PolicyEvent = serde_json::from_str(json).unwrap();
        assert_eq!(event.id, "123");
        assert_eq!(event.decision, "block");
    }
}
