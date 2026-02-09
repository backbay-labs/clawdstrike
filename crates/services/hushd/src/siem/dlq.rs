use std::path::{Path, PathBuf};
use std::sync::Arc;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use tokio::sync::Mutex;

use crate::siem::types::SecurityEvent;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DeadLetterQueueConfig {
    pub path: PathBuf,
    #[serde(default = "default_max_bytes")]
    pub max_bytes: u64,
}

fn default_max_bytes() -> u64 {
    50 * 1024 * 1024
}

#[derive(Clone)]
pub struct DeadLetterQueue {
    config: DeadLetterQueueConfig,
    lock: Arc<Mutex<()>>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DeadLetterEntry {
    pub exporter: String,
    pub failed_at: DateTime<Utc>,
    pub attempts: u32,
    pub error: String,
    pub retryable: bool,
    pub event: SecurityEvent,
}

impl DeadLetterQueue {
    pub fn new(config: DeadLetterQueueConfig) -> Self {
        Self {
            config,
            lock: Arc::new(Mutex::new(())),
        }
    }

    pub async fn enqueue(&self, entry: DeadLetterEntry) -> std::io::Result<()> {
        let _guard = self.lock.lock().await;

        self.rotate_if_needed().await?;

        let mut file = tokio::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.config.path)
            .await?;

        let line = serde_json::to_string(&entry).map_err(std::io::Error::other)?;
        use tokio::io::AsyncWriteExt;
        file.write_all(line.as_bytes()).await?;
        file.write_all(b"\n").await?;
        file.flush().await?;
        Ok(())
    }

    async fn rotate_if_needed(&self) -> std::io::Result<()> {
        let path = &self.config.path;
        let meta = match tokio::fs::metadata(path).await {
            Ok(m) => m,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
            Err(e) => return Err(e),
        };

        if meta.len() <= self.config.max_bytes {
            return Ok(());
        }

        let rotated = rotated_path(path);
        tokio::fs::rename(path, rotated).await?;
        Ok(())
    }
}

fn rotated_path(path: &Path) -> PathBuf {
    let ts = Utc::now().format("%Y%m%d%H%M%S").to_string();
    let file_name = path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("dlq.jsonl");
    let rotated_name = format!("{file_name}.{ts}");
    path.with_file_name(rotated_name)
}
