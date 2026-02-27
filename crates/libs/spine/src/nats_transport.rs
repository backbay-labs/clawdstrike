//! NATS connection and JetStream helpers for spine transport.
//!
//! Adapted from `aegisnet::nats`.

use crate::error::{Error, Result};

/// Optional authentication configuration for NATS connections.
#[derive(Debug, Default, Clone)]
pub struct NatsAuthConfig {
    /// Path to a `.creds` file for NATS authentication.
    pub creds_file: Option<String>,
    /// Bearer token for NATS authentication.
    pub token: Option<String>,
    /// NKey seed for NATS authentication.
    pub nkey_seed: Option<String>,
}

/// Connect to a NATS server (no authentication).
pub async fn connect(servers: &str) -> Result<async_nats::Client> {
    connect_with_auth(servers, None).await
}

/// Connect to a NATS server with optional authentication.
pub async fn connect_with_auth(
    servers: &str,
    auth: Option<&NatsAuthConfig>,
) -> Result<async_nats::Client> {
    let map_err = |e| Error::Nats(format!("failed to connect to NATS at {servers}: {e}"));

    let client = match auth {
        Some(NatsAuthConfig {
            creds_file: Some(path),
            ..
        }) => async_nats::ConnectOptions::with_credentials_file(path)
            .await
            .map_err(|e| Error::Nats(format!("failed to load NATS credentials from {path}: {e}")))?
            .connect(servers)
            .await
            .map_err(map_err)?,
        Some(NatsAuthConfig {
            token: Some(token), ..
        }) => async_nats::ConnectOptions::with_token(token.clone())
            .connect(servers)
            .await
            .map_err(map_err)?,
        Some(NatsAuthConfig {
            nkey_seed: Some(seed),
            ..
        }) => async_nats::ConnectOptions::with_nkey(seed.clone())
            .connect(servers)
            .await
            .map_err(map_err)?,
        _ => async_nats::connect(servers).await.map_err(map_err)?,
    };
    Ok(client)
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
    ensure_stream_with_limits(js, name, subjects, replicas, None, None).await
}

/// Ensure a JetStream stream exists and reconcile key retention/replication limits.
pub async fn ensure_stream_with_limits(
    js: &async_nats::jetstream::Context,
    name: &str,
    subjects: Vec<String>,
    replicas: usize,
    max_bytes: Option<i64>,
    max_age: Option<std::time::Duration>,
) -> Result<async_nats::jetstream::stream::Stream> {
    match js.get_stream(name).await {
        Ok(stream) => {
            let mut desired = stream.cached_info().config.clone();
            let mut changed = false;

            if desired.subjects != subjects {
                desired.subjects = subjects;
                changed = true;
            }
            if desired.num_replicas != replicas {
                desired.num_replicas = replicas;
                changed = true;
            }
            if desired.storage != async_nats::jetstream::stream::StorageType::File {
                desired.storage = async_nats::jetstream::stream::StorageType::File;
                changed = true;
            }
            if desired.retention != async_nats::jetstream::stream::RetentionPolicy::Limits {
                desired.retention = async_nats::jetstream::stream::RetentionPolicy::Limits;
                changed = true;
            }
            if desired.discard != async_nats::jetstream::stream::DiscardPolicy::Old {
                desired.discard = async_nats::jetstream::stream::DiscardPolicy::Old;
                changed = true;
            }

            if let Some(limit) = max_bytes {
                if desired.max_bytes != limit {
                    desired.max_bytes = limit;
                    changed = true;
                }
            }
            if let Some(limit) = max_age {
                if desired.max_age != limit {
                    desired.max_age = limit;
                    changed = true;
                }
            }

            if changed {
                js.update_stream(&desired).await.map_err(|e| {
                    Error::Nats(format!("failed to update stream {name} configuration: {e}"))
                })?;
                js.get_stream(name).await.map_err(|e| {
                    Error::Nats(format!("failed to reload stream {name} after update: {e}"))
                })
            } else {
                Ok(stream)
            }
        }
        Err(_) => {
            let mut config = async_nats::jetstream::stream::Config {
                name: name.to_string(),
                subjects,
                num_replicas: replicas,
                storage: async_nats::jetstream::stream::StorageType::File,
                retention: async_nats::jetstream::stream::RetentionPolicy::Limits,
                discard: async_nats::jetstream::stream::DiscardPolicy::Old,
                ..Default::default()
            };
            if let Some(limit) = max_bytes {
                config.max_bytes = limit;
            }
            if let Some(limit) = max_age {
                config.max_age = limit;
            }
            js.create_stream(config)
                .await
                .map_err(|e| Error::Nats(format!("failed to create stream {name}: {e}")))
        }
    }
}
