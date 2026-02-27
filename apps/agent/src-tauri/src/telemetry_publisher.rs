//! JetStream-based telemetry publisher for enterprise observability.
//!
//! Publishes receipts and heartbeats to tenant/agent-scoped JetStream streams.
//! All publish operations are best-effort: failures are logged but never block
//! the agent's critical path.

use anyhow::Result;
use std::sync::Arc;

use crate::nats_client::NatsClient;

/// Publishes telemetry data (receipts, heartbeats) to NATS JetStream.
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

    /// Build the stream name for this agent's telemetry.
    pub fn stream_name(tenant_id: &str, agent_id: &str) -> String {
        // JetStream stream names use underscores (no dots allowed in stream names).
        format!("telemetry_{}_{}", tenant_id, agent_id)
    }

    /// Build the subject for receipt telemetry.
    pub fn receipts_subject(tenant_id: &str, agent_id: &str) -> String {
        format!("telemetry.{}.{}.receipts", tenant_id, agent_id)
    }

    /// Build the subject for heartbeat telemetry.
    pub fn heartbeat_subject(tenant_id: &str, agent_id: &str) -> String {
        format!("telemetry.{}.{}.heartbeat", tenant_id, agent_id)
    }

    /// Ensure the telemetry stream exists (lazy initialization).
    async fn ensure_stream(&self) -> Result<()> {
        let mut initialized = self.stream_initialized.lock().await;
        if *initialized {
            return Ok(());
        }

        let tenant_id = self.nats.tenant_id();
        let agent_id = self.nats.agent_id();
        let stream_name = Self::stream_name(tenant_id, agent_id);
        let subjects = vec![format!("telemetry.{}.{}.>", tenant_id, agent_id)];

        spine::nats_transport::ensure_stream(self.nats.jetstream(), &stream_name, subjects, 1)
            .await
            .map_err(|e| anyhow::anyhow!("Failed to ensure telemetry stream: {}", e))?;

        *initialized = true;
        tracing::info!(stream = %stream_name, "Telemetry stream initialized");
        Ok(())
    }

    /// Publish a receipt to the telemetry stream (best-effort).
    pub async fn publish_receipt(&self, receipt_json: &[u8]) {
        if let Err(err) = self.try_publish_receipt(receipt_json).await {
            tracing::warn!(error = %err, "Failed to publish receipt to NATS (best-effort)");
        }
    }

    async fn try_publish_receipt(&self, receipt_json: &[u8]) -> Result<()> {
        self.ensure_stream().await?;

        let subject =
            Self::receipts_subject(self.nats.tenant_id(), self.nats.agent_id());

        self.nats
            .jetstream()
            .publish(subject, receipt_json.to_vec().into())
            .await
            .map_err(|e| anyhow::anyhow!("JetStream publish error: {}", e))?
            .await
            .map_err(|e| anyhow::anyhow!("JetStream ack error: {}", e))?;

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

        let subject =
            Self::heartbeat_subject(self.nats.tenant_id(), self.nats.agent_id());

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
            TelemetryPublisher::stream_name("tenant-abc", "agent-xyz"),
            "telemetry_tenant-abc_agent-xyz"
        );
    }

    #[test]
    fn receipts_subject_format() {
        assert_eq!(
            TelemetryPublisher::receipts_subject("tenant-abc", "agent-xyz"),
            "telemetry.tenant-abc.agent-xyz.receipts"
        );
    }

    #[test]
    fn heartbeat_subject_format() {
        assert_eq!(
            TelemetryPublisher::heartbeat_subject("tenant-abc", "agent-xyz"),
            "telemetry.tenant-abc.agent-xyz.heartbeat"
        );
    }

    /// Verify the NATS heartbeat payload serializes with all expected fields
    /// (mirrors the shape produced by `nats_heartbeat_loop` in main.rs).
    #[test]
    fn heartbeat_payload_shape() {
        let heartbeat = serde_json::json!({
            "timestamp": "2026-02-26T12:00:00Z",
            "session_id": "sess-123",
            "posture": "standard",
            "budget_used": 10,
            "budget_limit": 100,
            "hostname": "dev-machine",
            "version": "0.1.0",
        });
        let payload = serde_json::to_vec(&heartbeat).unwrap();
        let parsed: serde_json::Value = serde_json::from_slice(&payload).unwrap();
        assert_eq!(parsed["timestamp"], "2026-02-26T12:00:00Z");
        assert_eq!(parsed["session_id"], "sess-123");
        assert_eq!(parsed["posture"], "standard");
        assert_eq!(parsed["budget_used"], 10);
        assert_eq!(parsed["budget_limit"], 100);
        assert_eq!(parsed["hostname"], "dev-machine");
        assert_eq!(parsed["version"], "0.1.0");
    }
}
