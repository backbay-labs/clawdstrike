use std::time::Duration;

use async_trait::async_trait;
use serde::{Deserialize, Serialize};

use crate::siem::types::SecurityEvent;

#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SchemaFormat {
    Ecs,
    Cef,
    Ocsf,
    Native,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ExporterConfig {
    /// Maximum batch size before flush.
    #[serde(default = "default_batch_size")]
    pub batch_size: usize,
    /// Maximum time to wait before flush (ms).
    #[serde(default = "default_flush_interval_ms")]
    pub flush_interval_ms: u64,
    /// Retry configuration.
    #[serde(default)]
    pub retry: RetryConfig,
    /// Optional rate limiting.
    #[serde(default)]
    pub rate_limit: Option<RateLimitConfig>,
}

fn default_batch_size() -> usize {
    100
}

fn default_flush_interval_ms() -> u64 {
    5_000
}

impl Default for ExporterConfig {
    fn default() -> Self {
        Self {
            batch_size: default_batch_size(),
            flush_interval_ms: default_flush_interval_ms(),
            retry: RetryConfig::default(),
            rate_limit: None,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RetryConfig {
    #[serde(default = "default_max_retries")]
    pub max_retries: u32,
    #[serde(default = "default_initial_backoff_ms")]
    pub initial_backoff_ms: u64,
    #[serde(default = "default_max_backoff_ms")]
    pub max_backoff_ms: u64,
    #[serde(default = "default_backoff_multiplier")]
    pub backoff_multiplier: f64,
}

fn default_max_retries() -> u32 {
    3
}

fn default_initial_backoff_ms() -> u64 {
    1_000
}

fn default_max_backoff_ms() -> u64 {
    30_000
}

fn default_backoff_multiplier() -> f64 {
    2.0
}

impl Default for RetryConfig {
    fn default() -> Self {
        Self {
            max_retries: default_max_retries(),
            initial_backoff_ms: default_initial_backoff_ms(),
            max_backoff_ms: default_max_backoff_ms(),
            backoff_multiplier: default_backoff_multiplier(),
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RateLimitConfig {
    pub requests_per_second: u32,
    pub burst_size: u32,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct ExportResult {
    pub exported: usize,
    pub failed: usize,
    #[serde(default)]
    pub errors: Vec<ExportEventError>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ExportEventError {
    pub event_id: String,
    pub error: String,
    pub retryable: bool,
}

#[derive(Debug, thiserror::Error)]
pub enum ExporterError {
    #[error("HTTP error: status {status}, body: {body}")]
    Http { status: u16, body: String },
    #[error("configuration error: {0}")]
    Config(String),
    #[error("authentication error: {0}")]
    Auth(String),
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    #[error("serialization error: {0}")]
    Serialization(#[from] serde_json::Error),
    #[error("unexpected error: {0}")]
    Other(String),
}

#[async_trait]
pub trait Exporter: Send + Sync {
    fn name(&self) -> &str;
    fn schema(&self) -> SchemaFormat;

    /// Export a batch of events.
    ///
    /// Return `ExportResult` on success (including partial failures in `errors`).
    /// Return `ExporterError` only for complete failures (auth, connection, etc.).
    async fn export(&self, events: Vec<SecurityEvent>) -> Result<ExportResult, ExporterError>;

    async fn health_check(&self) -> Result<(), String>;

    async fn shutdown(&self) -> Result<(), String>;
}

pub fn backoff_duration_ms(config: &RetryConfig, attempt: u32) -> u64 {
    if attempt == 0 {
        return 0;
    }

    let mut backoff = config.initial_backoff_ms as f64;
    for _ in 1..attempt {
        backoff *= config.backoff_multiplier;
    }
    backoff = backoff.min(config.max_backoff_ms as f64);
    backoff.round().max(0.0) as u64
}

pub async fn sleep_backoff(config: &RetryConfig, attempt: u32) {
    let ms = backoff_duration_ms(config, attempt);
    if ms == 0 {
        return;
    }
    tokio::time::sleep(Duration::from_millis(ms)).await;
}
