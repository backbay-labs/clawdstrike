//! NATS connection and JetStream helpers for spine transport.
//!
//! Adapted from `aegisnet::nats`.

use crate::error::{Error, Result};

/// Connect to a NATS server.
pub async fn connect(servers: &str) -> Result<async_nats::Client> {
    async_nats::connect(servers)
        .await
        .map_err(|e| Error::Nats(format!("failed to connect to NATS at {servers}: {e}")))
}

/// Create a JetStream context from a NATS client.
pub fn jetstream(client: async_nats::Client) -> async_nats::jetstream::Context {
    async_nats::jetstream::new(client)
}

/// Ensure a JetStream KV bucket exists (create if missing).
pub async fn ensure_kv(
    js: &async_nats::jetstream::Context,
    bucket: &str,
    replicas: usize,
) -> Result<async_nats::jetstream::kv::Store> {
    match js.get_key_value(bucket).await {
        Ok(store) => Ok(store),
        Err(_) => {
            let config = async_nats::jetstream::kv::Config {
                bucket: bucket.to_string(),
                history: 1,
                num_replicas: replicas,
                ..Default::default()
            };
            js.create_key_value(config)
                .await
                .map_err(|e| Error::Nats(format!("failed to create KV bucket {bucket}: {e}")))
        }
    }
}

/// Ensure a JetStream stream exists (create if missing).
pub async fn ensure_stream(
    js: &async_nats::jetstream::Context,
    name: &str,
    subjects: Vec<String>,
    replicas: usize,
) -> Result<async_nats::jetstream::stream::Stream> {
    match js.get_stream(name).await {
        Ok(stream) => Ok(stream),
        Err(_) => {
            let config = async_nats::jetstream::stream::Config {
                name: name.to_string(),
                subjects,
                num_replicas: replicas,
                storage: async_nats::jetstream::stream::StorageType::File,
                retention: async_nats::jetstream::stream::RetentionPolicy::Limits,
                ..Default::default()
            };
            js.create_stream(config)
                .await
                .map_err(|e| Error::Nats(format!("failed to create stream {name}: {e}")))
        }
    }
}
