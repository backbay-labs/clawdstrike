use std::io::Write;
use std::time::Duration;

use async_trait::async_trait;
use flate2::{write::GzEncoder, Compression};
use reqwest::header;
use serde::{Deserialize, Serialize};

use crate::siem::exporter::{
    ExportEventError, ExportResult, Exporter, ExporterError, SchemaFormat,
};
use crate::siem::types::SecurityEvent;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SumoLogicConfig {
    pub http_source_url: String,
    #[serde(default = "default_source_category")]
    pub source_category: String,
    #[serde(default = "default_source_name")]
    pub source_name: String,
    #[serde(default)]
    pub source_host: Option<String>,
    #[serde(default = "default_format")]
    pub format: SumoFormat,
    #[serde(default = "default_compression")]
    pub compression: bool,
    #[serde(default = "default_timeout_ms")]
    pub timeout_ms: u64,
}

fn default_source_category() -> String {
    "security/clawdstrike".to_string()
}

fn default_source_name() -> String {
    "clawdstrike".to_string()
}

fn default_format() -> SumoFormat {
    SumoFormat::Json
}

fn default_compression() -> bool {
    true
}

fn default_timeout_ms() -> u64 {
    30_000
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SumoFormat {
    Json,
    Text,
    KeyValue,
}

#[derive(Clone)]
pub struct SumoLogicExporter {
    config: SumoLogicConfig,
    client: reqwest::Client,
}

impl SumoLogicExporter {
    pub fn new(mut config: SumoLogicConfig) -> Result<Self, ExporterError> {
        config.http_source_url = config.http_source_url.trim().to_string();

        let client = reqwest::Client::builder()
            .timeout(Duration::from_millis(config.timeout_ms.max(1)))
            .build()
            .map_err(|e| ExporterError::Other(e.to_string()))?;

        Ok(Self { config, client })
    }

    fn hostname(&self) -> String {
        self.config
            .source_host
            .clone()
            .unwrap_or_else(|| std::env::var("HOSTNAME").unwrap_or_else(|_| "unknown".to_string()))
    }

    fn format_event(&self, event: &SecurityEvent) -> String {
        match self.config.format {
            SumoFormat::Json => serde_json::to_string(event).unwrap_or_else(|_| "{}".to_string()),
            SumoFormat::Text => format!(
                "{} {} {} {}",
                event.timestamp_rfc3339_nanos(),
                event.event_id,
                event.decision.guard,
                event.decision.reason
            ),
            SumoFormat::KeyValue => {
                let allowed = event.decision.allowed;
                format!(
                    "event_id={} event_type={:?} guard={} severity={:?} allowed={} session_id={} resource={} reason={}",
                    event.event_id,
                    event.event_type,
                    event.decision.guard,
                    event.decision.severity,
                    allowed,
                    event.session.id,
                    event.resource.name,
                    event.decision.reason.replace('\"', "'"),
                )
            }
        }
    }

    async fn send_batch(&self, events: &[SecurityEvent]) -> Result<(), ExporterError> {
        let body = events
            .iter()
            .map(|e| self.format_event(e))
            .collect::<Vec<_>>()
            .join("\n");

        let mut req = self
            .client
            .post(self.config.http_source_url.clone())
            .header(header::CONTENT_TYPE, "application/json")
            .header("X-Sumo-Category", &self.config.source_category)
            .header("X-Sumo-Name", &self.config.source_name)
            .header("X-Sumo-Host", self.hostname());

        let body = if self.config.compression {
            req = req.header(header::CONTENT_ENCODING, "gzip");
            compress_gzip(body.as_bytes())?
        } else {
            body.into_bytes()
        };

        let resp =
            req.body(body).send().await.map_err(|e| {
                ExporterError::Other(format!("Sumo HTTP source request failed: {e}"))
            })?;

        if resp.status().is_success() {
            Ok(())
        } else {
            Err(ExporterError::Http {
                status: resp.status().as_u16(),
                body: resp.text().await.unwrap_or_default(),
            })
        }
    }
}

#[async_trait]
impl Exporter for SumoLogicExporter {
    fn name(&self) -> &str {
        "sumo-logic"
    }

    fn schema(&self) -> SchemaFormat {
        SchemaFormat::Native
    }

    async fn export(&self, events: Vec<SecurityEvent>) -> Result<ExportResult, ExporterError> {
        if events.is_empty() {
            return Ok(ExportResult::default());
        }

        match self.send_batch(&events).await {
            Ok(()) => Ok(ExportResult {
                exported: events.len(),
                failed: 0,
                errors: vec![],
            }),
            Err(err) => {
                let retryable = matches!(err, ExporterError::Http { status, .. } if status == 429 || (500..=599).contains(&status));
                Ok(ExportResult {
                    exported: 0,
                    failed: events.len(),
                    errors: events
                        .iter()
                        .map(|e| ExportEventError {
                            event_id: e.event_id.to_string(),
                            error: err.to_string(),
                            retryable,
                        })
                        .collect(),
                })
            }
        }
    }

    async fn health_check(&self) -> Result<(), String> {
        // Sumo HTTP source doesn't have a standard health endpoint; do a lightweight POST with empty body.
        let resp = self
            .client
            .post(self.config.http_source_url.clone())
            .header("X-Sumo-Category", &self.config.source_category)
            .header("X-Sumo-Name", &self.config.source_name)
            .header("X-Sumo-Host", self.hostname())
            .body("")
            .send()
            .await
            .map_err(|e| e.to_string())?;
        if resp.status().is_success() || resp.status().as_u16() == 202 {
            Ok(())
        } else {
            Err(format!("Sumo health probe failed: {}", resp.status()))
        }
    }

    async fn shutdown(&self) -> Result<(), String> {
        Ok(())
    }
}

fn compress_gzip(data: &[u8]) -> Result<Vec<u8>, ExporterError> {
    let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
    encoder.write_all(data)?;
    encoder.finish().map_err(ExporterError::from)
}
