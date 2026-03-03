//! NATS connection manager for enterprise connectivity.
//!
//! Wraps the spine NATS transport layer with agent-specific connection logic.

use anyhow::Result;
use spine::nats_transport::{connect_with_auth, jetstream, NatsAuthConfig};

use crate::settings::NatsSettings;

/// Manages a NATS client connection and JetStream context.
#[derive(Debug)]
pub struct NatsClient {
    client: async_nats::Client,
    js: async_nats::jetstream::Context,
    agent_id: String,
    subject_prefix: String,
}

impl NatsClient {
    /// Connect to the NATS server using the provided settings.
    pub async fn connect(settings: &NatsSettings) -> Result<Self> {
        let nats_url = settings
            .nats_url
            .as_deref()
            .ok_or_else(|| anyhow::anyhow!("nats_url is required when NATS is enabled"))?;

        let tenant_id = settings
            .tenant_id
            .as_deref()
            .ok_or_else(|| anyhow::anyhow!("tenant_id is required when NATS is enabled"))?;

        let agent_id = settings
            .agent_id
            .as_deref()
            .ok_or_else(|| anyhow::anyhow!("agent_id is required when NATS is enabled"))?;

        let auth = NatsAuthConfig {
            creds_file: settings.creds_file.clone(),
            token: settings.token.clone(),
            nkey_seed: settings.nkey_seed.clone(),
        };
        let subject_prefix = settings
            .subject_prefix
            .as_deref()
            .ok_or_else(|| anyhow::anyhow!("subject_prefix is required when NATS is enabled"))?;

        let client = connect_with_auth(nats_url, Some(&auth)).await?;
        let js = jetstream(client.clone());

        tracing::info!(
            nats_url = %nats_url,
            tenant_id = %tenant_id,
            agent_id = %agent_id,
            "NATS client connected"
        );

        Ok(Self {
            client,
            js,
            agent_id: agent_id.to_string(),
            subject_prefix: subject_prefix.to_string(),
        })
    }

    /// Get a reference to the underlying NATS client.
    pub fn client(&self) -> &async_nats::Client {
        &self.client
    }

    /// Get a reference to the JetStream context.
    pub fn jetstream(&self) -> &async_nats::jetstream::Context {
        &self.js
    }

    /// Get the agent ID.
    pub fn agent_id(&self) -> &str {
        &self.agent_id
    }

    /// Get the tenant-scoped NATS subject prefix provisioned by cloud enrollment.
    pub fn subject_prefix(&self) -> &str {
        &self.subject_prefix
    }
}

/// Helper to poll the next message from an async-nats subscriber.
pub async fn subscriber_next(
    subscriber: &mut async_nats::Subscriber,
) -> Option<async_nats::Message> {
    use futures::StreamExt;
    subscriber.next().await
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn connect_requires_nats_url() {
        let settings = NatsSettings {
            enabled: true,
            nats_url: None,
            tenant_id: Some("t-1".to_string()),
            agent_id: Some("a-1".to_string()),
            ..Default::default()
        };
        let rt = tokio::runtime::Runtime::new().unwrap();
        let result = rt.block_on(NatsClient::connect(&settings));
        assert!(result.is_err());
        assert!(
            result.unwrap_err().to_string().contains("nats_url"),
            "should mention nats_url"
        );
    }

    #[test]
    fn connect_requires_tenant_id() {
        let settings = NatsSettings {
            enabled: true,
            nats_url: Some("nats://localhost:4222".to_string()),
            tenant_id: None,
            agent_id: Some("a-1".to_string()),
            ..Default::default()
        };
        let rt = tokio::runtime::Runtime::new().unwrap();
        let result = rt.block_on(NatsClient::connect(&settings));
        assert!(result.is_err());
        assert!(
            result.unwrap_err().to_string().contains("tenant_id"),
            "should mention tenant_id"
        );
    }

    #[test]
    fn connect_requires_agent_id() {
        let settings = NatsSettings {
            enabled: true,
            nats_url: Some("nats://localhost:4222".to_string()),
            tenant_id: Some("t-1".to_string()),
            agent_id: None,
            subject_prefix: Some("tenant-acme.clawdstrike".to_string()),
            ..Default::default()
        };
        let rt = tokio::runtime::Runtime::new().unwrap();
        let result = rt.block_on(NatsClient::connect(&settings));
        assert!(result.is_err());
        assert!(
            result.unwrap_err().to_string().contains("agent_id"),
            "should mention agent_id"
        );
    }

    #[test]
    fn connect_requires_subject_prefix() {
        let settings = NatsSettings {
            enabled: true,
            nats_url: Some("nats://localhost:4222".to_string()),
            tenant_id: Some("t-1".to_string()),
            agent_id: Some("a-1".to_string()),
            subject_prefix: None,
            ..Default::default()
        };
        let rt = tokio::runtime::Runtime::new().unwrap();
        let result = rt.block_on(NatsClient::connect(&settings));
        assert!(result.is_err());
        assert!(
            result.unwrap_err().to_string().contains("subject_prefix"),
            "should mention subject_prefix"
        );
    }
}
