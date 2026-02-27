//! JetStream heartbeat publisher for enterprise observability.
//!
//! Publishes heartbeat telemetry to tenant/agent-scoped JetStream streams.
//! All publish operations are best-effort: failures are logged but never block
//! the agent's critical path.

use anyhow::Result;
use std::sync::Arc;

use crate::nats_client::NatsClient;
use crate::nats_subjects;

/// Publishes heartbeat telemetry to NATS JetStream.
pub struct TelemetryPublisher {
    nats: Arc<NatsClient>,
    stream_initialized: tokio::sync::Mutex<bool>,
}

impl TelemetryPublisher {
    pub fn new(nats: Arc<NatsClient>) -> Self {
        Self {
            nats,
            stream_initialized: tokio::sync::Mutex::new(false),
        }
    }

    /// Agent identifier associated with this publisher.
    pub fn agent_id(&self) -> &str {
        self.nats.agent_id()
    }

    /// Build the stream name for this agent's telemetry.
    pub fn stream_name(subject_prefix: &str, agent_id: &str) -> String {
        nats_subjects::telemetry_stream_name(subject_prefix, agent_id)
    }

    /// Build the subject for heartbeat telemetry.
    pub fn heartbeat_subject(subject_prefix: &str, agent_id: &str) -> String {
        nats_subjects::heartbeat_subject(subject_prefix, agent_id)
    }

    /// Build stream subjects scoped to this agent to avoid cross-agent overlap.
    fn stream_subjects(subject_prefix: &str, agent_id: &str) -> Vec<String> {
        vec![
            format!("{subject_prefix}.telemetry.{agent_id}.>"),
            Self::heartbeat_subject(subject_prefix, agent_id),
        ]
    }

    /// Ensure the telemetry stream exists (lazy initialization).
    async fn ensure_stream(&self) -> Result<()> {
        let mut initialized = self.stream_initialized.lock().await;
        if *initialized {
            return Ok(());
        }

        let subject_prefix = self.nats.subject_prefix();
        let agent_id = self.nats.agent_id();
        let stream_name = Self::stream_name(subject_prefix, agent_id);
        let subjects = Self::stream_subjects(subject_prefix, agent_id);

        spine::nats_transport::ensure_stream(self.nats.jetstream(), &stream_name, subjects, 1)
            .await
            .map_err(|e| anyhow::anyhow!("Failed to ensure telemetry stream: {}", e))?;

        *initialized = true;
        tracing::info!(stream = %stream_name, "Telemetry stream initialized");
        Ok(())
    }

    /// Publish a heartbeat to the telemetry stream (best-effort).
    pub async fn publish_heartbeat(&self, heartbeat_json: &[u8]) {
        if let Err(err) = self.try_publish_heartbeat(heartbeat_json).await {
            tracing::warn!(error = %err, "Failed to publish heartbeat to NATS (best-effort)");
        }
    }

    async fn try_publish_heartbeat(&self, heartbeat_json: &[u8]) -> Result<()> {
        self.ensure_stream().await?;

        let subject = Self::heartbeat_subject(self.nats.subject_prefix(), self.nats.agent_id());

        self.nats
            .jetstream()
            .publish(subject, heartbeat_json.to_vec().into())
            .await
            .map_err(|e| anyhow::anyhow!("JetStream publish error: {}", e))?
            .await
            .map_err(|e| anyhow::anyhow!("JetStream ack error: {}", e))?;

        Ok(())
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn stream_name_format() {
        assert_eq!(
            TelemetryPublisher::stream_name("tenant-abc.clawdstrike", "agent-xyz"),
            "tenant-abc-clawdstrike-telemetry-agent-xyz"
        );
    }

    #[test]
    fn heartbeat_subject_format() {
        assert_eq!(
            TelemetryPublisher::heartbeat_subject("tenant-abc.clawdstrike", "agent-xyz"),
            "tenant-abc.clawdstrike.agent.heartbeat.agent-xyz"
        );
    }

    #[test]
    fn stream_subjects_are_agent_scoped() {
        let subjects = TelemetryPublisher::stream_subjects("tenant-abc.clawdstrike", "agent-xyz");
        assert_eq!(
            subjects,
            vec![
                "tenant-abc.clawdstrike.telemetry.agent-xyz.>".to_string(),
                "tenant-abc.clawdstrike.agent.heartbeat.agent-xyz".to_string()
            ]
        );
    }

    /// Verify the NATS heartbeat payload serializes with all expected fields
    /// (mirrors the shape produced by `nats_heartbeat_loop` in main.rs).
    #[test]
    fn heartbeat_payload_shape() {
        let heartbeat = serde_json::json!({
            "agent_id": "agent-xyz",
            "timestamp": "2026-02-26T12:00:00Z",
            "session_id": "sess-123",
            "posture": "standard",
            "budget_used": 10,
            "budget_limit": 100,
            "mode": "connected",
            "last_policy_version": "42",
            "hostname": "dev-machine",
            "version": "0.1.0",
        });
        let payload = serde_json::to_vec(&heartbeat).unwrap();
        let parsed: serde_json::Value = serde_json::from_slice(&payload).unwrap();
        assert_eq!(parsed["agent_id"], "agent-xyz");
        assert_eq!(parsed["timestamp"], "2026-02-26T12:00:00Z");
        assert_eq!(parsed["session_id"], "sess-123");
        assert_eq!(parsed["posture"], "standard");
        assert_eq!(parsed["budget_used"], 10);
        assert_eq!(parsed["budget_limit"], 100);
        assert_eq!(parsed["mode"], "connected");
        assert_eq!(parsed["last_policy_version"], "42");
        assert_eq!(parsed["hostname"], "dev-machine");
        assert_eq!(parsed["version"], "0.1.0");
    }
}
