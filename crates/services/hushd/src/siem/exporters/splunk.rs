use std::collections::HashMap;
use std::io::Write;
use std::time::{Duration, Instant};

use async_trait::async_trait;
use flate2::{write::GzEncoder, Compression};
use reqwest::header;
use serde::{Deserialize, Serialize};

use crate::siem::exporter::{ExportResult, Exporter, ExporterError, SchemaFormat};
use crate::siem::types::SecurityEvent;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SplunkConfig {
    pub hec_url: String,
    pub hec_token: String,
    #[serde(default = "default_index")]
    pub index: String,
    #[serde(default = "default_sourcetype")]
    pub sourcetype: String,
    #[serde(default = "default_source")]
    pub source: String,
    #[serde(default)]
    pub host: Option<String>,
    #[serde(default = "default_use_ack")]
    pub use_ack: bool,
    #[serde(default)]
    pub ack_channel: Option<String>,
    #[serde(default = "default_ack_timeout_secs")]
    pub ack_timeout_secs: u64,
    #[serde(default = "default_compression")]
    pub compression: bool,
    #[serde(default)]
    pub tls: SplunkTlsConfig,
    #[serde(default)]
    pub connection: SplunkConnectionConfig,
}

fn default_index() -> String {
    "main".to_string()
}

fn default_sourcetype() -> String {
    "clawdstrike:security".to_string()
}

fn default_source() -> String {
    "clawdstrike".to_string()
}

fn default_use_ack() -> bool {
    true
}

fn default_ack_timeout_secs() -> u64 {
    30
}

fn default_compression() -> bool {
    true
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct SplunkTlsConfig {
    #[serde(default)]
    pub insecure_skip_verify: bool,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct SplunkConnectionConfig {
    #[serde(default = "default_timeout_ms")]
    pub timeout_ms: u64,
}

fn default_timeout_ms() -> u64 {
    30_000
}

#[derive(Clone)]
pub struct SplunkExporter {
    config: SplunkConfig,
    client: reqwest::Client,
    channel: String,
}

#[derive(Clone, Debug, Serialize)]
struct SplunkEvent {
    time: f64,
    #[serde(skip_serializing_if = "Option::is_none")]
    index: Option<String>,
    sourcetype: String,
    source: String,
    host: String,
    event: serde_json::Value,
    #[serde(skip_serializing_if = "Option::is_none")]
    fields: Option<HashMap<String, String>>,
}

#[derive(Clone, Debug, Deserialize)]
struct HecResponse {
    text: String,
    code: i32,
    #[serde(rename = "ackId")]
    ack_id: Option<u64>,
}

impl SplunkExporter {
    pub fn new(mut config: SplunkConfig) -> Result<Self, ExporterError> {
        config.hec_url = config.hec_url.trim_end_matches('/').to_string();

        let mut builder = reqwest::Client::builder()
            .timeout(Duration::from_millis(config.connection.timeout_ms.max(1)));

        if config.tls.insecure_skip_verify {
            builder = builder.danger_accept_invalid_certs(true);
        }

        let client = builder
            .build()
            .map_err(|e| ExporterError::Other(e.to_string()))?;

        let channel = config
            .ack_channel
            .clone()
            .unwrap_or_else(|| uuid::Uuid::now_v7().to_string());

        Ok(Self {
            config,
            client,
            channel,
        })
    }

    fn hostname(&self) -> String {
        if let Some(h) = &self.config.host {
            return h.clone();
        }
        std::env::var("HOSTNAME").unwrap_or_else(|_| "unknown".to_string())
    }

    fn to_splunk_event(&self, event: &SecurityEvent) -> SplunkEvent {
        let time = event.timestamp.timestamp_millis() as f64 / 1000.0;
        let host = self.hostname();

        let event_type = serde_json::to_value(&event.event_type)
            .ok()
            .and_then(|v| v.as_str().map(|s| s.to_string()))
            .unwrap_or_else(|| format!("{:?}", event.event_type));

        let severity = serde_json::to_value(&event.decision.severity)
            .ok()
            .and_then(|v| v.as_str().map(|s| s.to_string()))
            .unwrap_or_else(|| format!("{:?}", event.decision.severity));

        let fields = Some(HashMap::from([
            ("event_id".to_string(), event.event_id.to_string()),
            ("event_type".to_string(), event_type),
            ("guard".to_string(), event.decision.guard.clone()),
            ("severity".to_string(), severity),
            ("session_id".to_string(), event.session.id.clone()),
            (
                "environment".to_string(),
                event
                    .session
                    .environment
                    .clone()
                    .unwrap_or_else(|| "unknown".to_string()),
            ),
            (
                "tenant_id".to_string(),
                event
                    .session
                    .tenant_id
                    .clone()
                    .unwrap_or_else(|| "default".to_string()),
            ),
        ]));

        SplunkEvent {
            time,
            index: Some(self.config.index.clone()),
            sourcetype: self.config.sourcetype.clone(),
            source: self.config.source.clone(),
            host,
            event: serde_json::to_value(event).unwrap_or_else(|_| serde_json::json!({})),
            fields,
        }
    }

    async fn send_batch(&self, events: &[SecurityEvent]) -> Result<HecResponse, ExporterError> {
        let splunk_events: Vec<SplunkEvent> =
            events.iter().map(|e| self.to_splunk_event(e)).collect();
        let body: String = splunk_events
            .iter()
            .map(|e| serde_json::to_string(e).unwrap_or_else(|_| "{}".to_string()))
            .collect::<Vec<_>>()
            .join("\n");

        let mut request = self
            .client
            .post(format!("{}/services/collector/event", self.config.hec_url))
            .header(
                header::AUTHORIZATION,
                format!("Splunk {}", self.config.hec_token),
            )
            .header(header::CONTENT_TYPE, "application/json");

        if self.config.use_ack {
            request = request.header("X-Splunk-Request-Channel", &self.channel);
        }

        let body = if self.config.compression {
            request = request.header(header::CONTENT_ENCODING, "gzip");
            compress_gzip(body.as_bytes())?
        } else {
            body.into_bytes()
        };

        let response = request
            .body(body)
            .send()
            .await
            .map_err(|e| ExporterError::Other(format!("Splunk HEC request failed: {e}")))?;
        let status = response.status();
        let text = response.text().await.unwrap_or_default();

        if !status.is_success() {
            return Err(ExporterError::Http {
                status: status.as_u16(),
                body: text,
            });
        }

        let hec_response: HecResponse =
            serde_json::from_str(&text).map_err(|e| ExporterError::Other(e.to_string()))?;

        if hec_response.code != 0 {
            return Err(ExporterError::Other(format!(
                "Splunk HEC error code {}: {}",
                hec_response.code, hec_response.text
            )));
        }

        Ok(hec_response)
    }

    async fn wait_for_ack(&self, ack_id: u64) -> Result<(), ExporterError> {
        let started = Instant::now();
        let timeout = Duration::from_secs(self.config.ack_timeout_secs.max(1));

        loop {
            if started.elapsed() > timeout {
                return Err(ExporterError::Other(format!(
                    "Splunk HEC ack timeout after {}s (ack_id={})",
                    self.config.ack_timeout_secs, ack_id
                )));
            }

            let response = self
                .client
                .post(format!("{}/services/collector/ack", self.config.hec_url))
                .header(
                    header::AUTHORIZATION,
                    format!("Splunk {}", self.config.hec_token),
                )
                .header("X-Splunk-Request-Channel", &self.channel)
                .json(&serde_json::json!({ "acks": [ack_id] }))
                .send()
                .await
                .map_err(|e| ExporterError::Other(format!("Splunk ack poll failed: {e}")))?;

            let status = response.status();
            if !status.is_success() {
                let body = response.text().await.unwrap_or_default();
                return Err(ExporterError::Http {
                    status: status.as_u16(),
                    body,
                });
            }

            #[derive(Deserialize)]
            struct AckResponse {
                acks: HashMap<String, bool>,
            }

            let ack: AckResponse = response
                .json()
                .await
                .map_err(|e| ExporterError::Other(format!("Splunk ack decode failed: {e}")))?;

            if ack.acks.get(&ack_id.to_string()).copied().unwrap_or(false) {
                return Ok(());
            }

            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    }
}

#[async_trait]
impl Exporter for SplunkExporter {
    fn name(&self) -> &str {
        "splunk"
    }

    fn schema(&self) -> SchemaFormat {
        SchemaFormat::Native
    }

    async fn export(&self, events: Vec<SecurityEvent>) -> Result<ExportResult, ExporterError> {
        if events.is_empty() {
            return Ok(ExportResult::default());
        }

        match self.send_batch(&events).await {
            Ok(resp) => {
                if self.config.use_ack {
                    if let Some(ack_id) = resp.ack_id {
                        if let Err(err) = self.wait_for_ack(ack_id).await {
                            return Ok(ExportResult {
                                exported: 0,
                                failed: events.len(),
                                errors: events
                                    .iter()
                                    .map(|e| crate::siem::exporter::ExportEventError {
                                        event_id: e.event_id.to_string(),
                                        error: err.to_string(),
                                        retryable: true,
                                    })
                                    .collect(),
                            });
                        }
                    }
                }

                Ok(ExportResult {
                    exported: events.len(),
                    failed: 0,
                    errors: vec![],
                })
            }
            Err(err) => Ok(ExportResult {
                exported: 0,
                failed: events.len(),
                errors: events
                    .iter()
                    .map(|e| crate::siem::exporter::ExportEventError {
                        event_id: e.event_id.to_string(),
                        error: err.to_string(),
                        retryable: matches!(err, ExporterError::Http { status, .. } if status == 429 || (500..=599).contains(&status)),
                    })
                    .collect(),
            }),
        }
    }

    async fn health_check(&self) -> Result<(), String> {
        let response = self
            .client
            .get(format!("{}/services/collector/health", self.config.hec_url))
            .header(
                header::AUTHORIZATION,
                format!("Splunk {}", self.config.hec_token),
            )
            .send()
            .await
            .map_err(|e| e.to_string())?;

        if response.status().is_success() {
            Ok(())
        } else {
            Err(format!("Splunk health check failed: {}", response.status()))
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
