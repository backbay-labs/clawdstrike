//! Audit forwarding to external sinks

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use tokio::sync::{mpsc, Mutex};
use tokio::time::timeout;

use crate::audit::AuditEvent;
use crate::config::{AuditForwardConfig, AuditSinkConfig};

#[async_trait]
pub trait AuditSink: Send + Sync {
    fn name(&self) -> &'static str;
    async fn send(&self, event: &AuditEvent) -> anyhow::Result<()>;
}

#[derive(Clone)]
pub struct AuditForwarder {
    tx: mpsc::Sender<AuditEvent>,
    dropped_total: Arc<AtomicU64>,
}

impl AuditForwarder {
    pub fn from_config(config: &AuditForwardConfig) -> anyhow::Result<Option<Self>> {
        if !config.enabled || config.sinks.is_empty() {
            return Ok(None);
        }

        let timeout_ms = config.timeout_ms;
        let (tx, mut rx) = mpsc::channel::<AuditEvent>(config.queue_size);
        let dropped_total = Arc::new(AtomicU64::new(0));

        let sinks = build_sinks(&config.sinks, Duration::from_millis(timeout_ms))?;
        let send_timeout = Duration::from_millis(timeout_ms);

        tokio::spawn(async move {
            while let Some(event) = rx.recv().await {
                // Fan out to sinks; failures are logged but do not stop the pipeline.
                for sink in &sinks {
                    let sink_name = sink.name();
                    match timeout(send_timeout, sink.send(&event)).await {
                        Ok(Ok(())) => {}
                        Ok(Err(err)) => {
                            tracing::warn!(sink = sink_name, error = %err, "Audit sink send failed");
                        }
                        Err(_) => {
                            tracing::warn!(
                                sink = sink_name,
                                timeout_ms,
                                "Audit sink send timed out"
                            );
                        }
                    }
                }
            }
        });

        Ok(Some(Self { tx, dropped_total }))
    }

    pub fn try_enqueue(&self, event: AuditEvent) {
        if let Err(err) = self.tx.try_send(event) {
            self.dropped_total.fetch_add(1, Ordering::Relaxed);
            tracing::warn!(error = %err, "Audit forward queue full; dropping event");
        }
    }

    pub fn dropped_total(&self) -> u64 {
        self.dropped_total.load(Ordering::Relaxed)
    }
}

fn build_sinks(
    configs: &[AuditSinkConfig],
    timeout: Duration,
) -> anyhow::Result<Vec<Arc<dyn AuditSink>>> {
    let client = reqwest::Client::builder().timeout(timeout).build()?;
    let mut sinks: Vec<Arc<dyn AuditSink>> = Vec::new();

    for cfg in configs {
        match cfg {
            AuditSinkConfig::StdoutJsonl => sinks.push(Arc::new(StdoutJsonlSink::new())),
            AuditSinkConfig::FileJsonl { path } => {
                sinks.push(Arc::new(FileJsonlSink::new(path.clone())?))
            }
            AuditSinkConfig::Webhook { url, headers } => sinks.push(Arc::new(WebhookSink::new(
                client.clone(),
                url.clone(),
                headers.clone(),
            )?)),
            AuditSinkConfig::OtlpHttp {
                endpoint,
                headers,
                service_name,
                service_version,
                resource_attributes,
            } => sinks.push(Arc::new(OtlpHttpSink::new(
                client.clone(),
                endpoint.clone(),
                headers.clone(),
                service_name.clone(),
                service_version.clone(),
                resource_attributes.clone(),
            )?)),
            AuditSinkConfig::SplunkHec {
                url,
                token,
                index,
                sourcetype,
                source,
            } => sinks.push(Arc::new(SplunkHecSink::new(
                client.clone(),
                url.clone(),
                token.clone(),
                index.clone(),
                sourcetype.clone(),
                source.clone(),
            )?)),
            AuditSinkConfig::Elastic {
                url,
                api_key,
                index,
            } => sinks.push(Arc::new(ElasticSink::new(
                client.clone(),
                url.clone(),
                api_key.clone(),
                index.clone(),
            )?)),
        }
    }

    Ok(sinks)
}

struct StdoutJsonlSink {
    lock: Mutex<()>,
}

impl StdoutJsonlSink {
    fn new() -> Self {
        Self {
            lock: Mutex::new(()),
        }
    }
}

#[async_trait]
impl AuditSink for StdoutJsonlSink {
    fn name(&self) -> &'static str {
        "stdout_jsonl"
    }

    async fn send(&self, event: &AuditEvent) -> anyhow::Result<()> {
        let _guard = self.lock.lock().await;
        let line = serde_json::to_vec(event)?;
        let mut out = tokio::io::stdout();
        use tokio::io::AsyncWriteExt;
        out.write_all(&line).await?;
        out.write_all(b"\n").await?;
        out.flush().await?;
        Ok(())
    }
}

struct FileJsonlSink {
    file: Mutex<tokio::fs::File>,
}

impl FileJsonlSink {
    fn new(path: PathBuf) -> anyhow::Result<Self> {
        let parent = path
            .parent()
            .map(std::path::Path::to_path_buf)
            .unwrap_or_else(|| PathBuf::from("."));
        std::fs::create_dir_all(parent)?;

        let file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&path)?;
        let file = tokio::fs::File::from_std(file);
        Ok(Self {
            file: Mutex::new(file),
        })
    }
}

#[async_trait]
impl AuditSink for FileJsonlSink {
    fn name(&self) -> &'static str {
        "file_jsonl"
    }

    async fn send(&self, event: &AuditEvent) -> anyhow::Result<()> {
        let line = serde_json::to_vec(event)?;
        let mut file = self.file.lock().await;
        use tokio::io::AsyncWriteExt;
        file.write_all(&line).await?;
        file.write_all(b"\n").await?;
        file.flush().await?;
        Ok(())
    }
}

struct WebhookSink {
    client: reqwest::Client,
    url: reqwest::Url,
    headers: HashMap<String, String>,
}

impl WebhookSink {
    fn new(
        client: reqwest::Client,
        url: String,
        headers: Option<HashMap<String, String>>,
    ) -> anyhow::Result<Self> {
        Ok(Self {
            client,
            url: url.parse()?,
            headers: headers.unwrap_or_default(),
        })
    }
}

#[async_trait]
impl AuditSink for WebhookSink {
    fn name(&self) -> &'static str {
        "webhook"
    }

    async fn send(&self, event: &AuditEvent) -> anyhow::Result<()> {
        let mut req = self.client.post(self.url.clone()).json(event);
        for (k, v) in &self.headers {
            req = req.header(k, v);
        }
        let resp = req.send().await?;
        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            return Err(anyhow::anyhow!("non-2xx from webhook: {} {}", status, body));
        }
        Ok(())
    }
}

struct OtlpHttpSink {
    client: reqwest::Client,
    endpoint: reqwest::Url,
    headers: HashMap<String, String>,
    service_name: String,
    service_version: String,
    resource_attributes: HashMap<String, String>,
}

impl OtlpHttpSink {
    fn new(
        client: reqwest::Client,
        endpoint: String,
        headers: Option<HashMap<String, String>>,
        service_name: Option<String>,
        service_version: Option<String>,
        resource_attributes: Option<HashMap<String, String>>,
    ) -> anyhow::Result<Self> {
        let mut endpoint: reqwest::Url = endpoint.parse()?;
        let path = endpoint.path().trim_end_matches('/');
        if path.is_empty() || path == "/" {
            endpoint.set_path("/v1/logs");
        } else if !path.ends_with("/v1/logs") {
            endpoint.set_path(&format!("{}/v1/logs", path));
        }

        Ok(Self {
            client,
            endpoint,
            headers: headers.unwrap_or_default(),
            service_name: service_name.unwrap_or_else(|| "hushd".to_string()),
            service_version: service_version
                .unwrap_or_else(|| env!("CARGO_PKG_VERSION").to_string()),
            resource_attributes: resource_attributes.unwrap_or_default(),
        })
    }

    fn build_payload(&self, event: &AuditEvent) -> anyhow::Result<serde_json::Value> {
        let time_unix_nano = format!(
            "{}{:09}",
            event.timestamp.timestamp(),
            event.timestamp.timestamp_subsec_nanos()
        );

        let mut resource_attributes = vec![
            attr("service.name", self.service_name.clone()),
            attr("service.version", self.service_version.clone()),
            attr("service.namespace", "clawdstrike".to_string()),
        ];
        for (k, v) in &self.resource_attributes {
            resource_attributes.push(attr(k.as_str(), v.clone()));
        }

        let mut log_attributes = vec![
            attr("hush.audit.id", event.id.clone()),
            attr("hush.audit.event_type", event.event_type.clone()),
            attr("hush.audit.action_type", event.action_type.clone()),
            attr("hush.audit.decision", event.decision.clone()),
        ];
        if let Some(target) = &event.target {
            log_attributes.push(attr("hush.audit.target", target.clone()));
        }
        if let Some(guard) = &event.guard {
            log_attributes.push(attr("hush.audit.guard", guard.clone()));
        }
        if let Some(session_id) = &event.session_id {
            log_attributes.push(attr("hush.audit.session_id", session_id.clone()));
        }
        if let Some(agent_id) = &event.agent_id {
            log_attributes.push(attr("hush.audit.agent_id", agent_id.clone()));
        }

        let body_text = event
            .message
            .clone()
            .unwrap_or_else(|| format!("{} {}", event.event_type, event.decision));
        let serialized_event = serde_json::to_string(event)?;
        log_attributes.push(attr("hush.audit.raw_json", serialized_event));

        Ok(serde_json::json!({
            "resourceLogs": [{
                "resource": {
                    "attributes": resource_attributes
                },
                "scopeLogs": [{
                    "scope": {
                        "name": "hushd.audit_forward",
                        "version": self.service_version.clone(),
                    },
                    "logRecords": [{
                        "timeUnixNano": time_unix_nano,
                        "severityText": event
                            .severity
                            .clone()
                            .unwrap_or_else(|| "INFO".to_string()),
                        "body": {
                            "stringValue": body_text
                        },
                        "attributes": log_attributes
                    }]
                }]
            }]
        }))
    }
}

#[async_trait]
impl AuditSink for OtlpHttpSink {
    fn name(&self) -> &'static str {
        "otlp_http"
    }

    async fn send(&self, event: &AuditEvent) -> anyhow::Result<()> {
        let payload = self.build_payload(event)?;
        let mut req = self.client.post(self.endpoint.clone()).json(&payload);
        for (k, v) in &self.headers {
            req = req.header(k, v);
        }
        let resp = req.send().await?;
        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            return Err(anyhow::anyhow!(
                "non-2xx from otlp http: {} {}",
                status,
                body
            ));
        }
        Ok(())
    }
}

fn attr(key: &str, value: String) -> serde_json::Value {
    serde_json::json!({
        "key": key,
        "value": { "stringValue": value }
    })
}

struct SplunkHecSink {
    client: reqwest::Client,
    url: reqwest::Url,
    token: String,
    index: Option<String>,
    sourcetype: Option<String>,
    source: Option<String>,
}

impl SplunkHecSink {
    fn new(
        client: reqwest::Client,
        url: String,
        token: String,
        index: Option<String>,
        sourcetype: Option<String>,
        source: Option<String>,
    ) -> anyhow::Result<Self> {
        let mut url: reqwest::Url = url.parse()?;
        // If the URL doesn't look like a HEC endpoint, append the default event path.
        if !url.path().contains("/services/collector") {
            url.set_path("/services/collector/event");
        }

        Ok(Self {
            client,
            url,
            token,
            index,
            sourcetype,
            source,
        })
    }
}

#[async_trait]
impl AuditSink for SplunkHecSink {
    fn name(&self) -> &'static str {
        "splunk_hec"
    }

    async fn send(&self, event: &AuditEvent) -> anyhow::Result<()> {
        // Splunk HEC envelope.
        let mut payload = serde_json::Map::new();
        payload.insert(
            "time".to_string(),
            serde_json::Value::Number(
                serde_json::Number::from_f64(event.timestamp.timestamp_millis() as f64 / 1000.0)
                    .unwrap_or_else(|| serde_json::Number::from(0)),
            ),
        );
        payload.insert("event".to_string(), serde_json::to_value(event)?);
        if let Some(index) = &self.index {
            payload.insert(
                "index".to_string(),
                serde_json::Value::String(index.clone()),
            );
        }
        if let Some(sourcetype) = &self.sourcetype {
            payload.insert(
                "sourcetype".to_string(),
                serde_json::Value::String(sourcetype.clone()),
            );
        }
        if let Some(source) = &self.source {
            payload.insert(
                "source".to_string(),
                serde_json::Value::String(source.clone()),
            );
        }

        let resp = self
            .client
            .post(self.url.clone())
            .header("Authorization", format!("Splunk {}", self.token))
            .json(&payload)
            .send()
            .await?;
        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            return Err(anyhow::anyhow!(
                "non-2xx from splunk hec: {} {}",
                status,
                body
            ));
        }
        Ok(())
    }
}

struct ElasticSink {
    client: reqwest::Client,
    base: reqwest::Url,
    api_key: Option<String>,
    index: String,
}

impl ElasticSink {
    fn new(
        client: reqwest::Client,
        url: String,
        api_key: Option<String>,
        index: Option<String>,
    ) -> anyhow::Result<Self> {
        Ok(Self {
            client,
            base: url.parse()?,
            api_key,
            index: index.unwrap_or_else(|| "clawdstrike-audit".to_string()),
        })
    }
}

#[async_trait]
impl AuditSink for ElasticSink {
    fn name(&self) -> &'static str {
        "elastic"
    }

    async fn send(&self, event: &AuditEvent) -> anyhow::Result<()> {
        let mut url = self.base.clone();
        url.set_path(&format!("/{}/_doc", self.index));

        let mut req = self.client.post(url).json(event);
        if let Some(api_key) = &self.api_key {
            req = req.header("Authorization", format!("ApiKey {}", api_key));
        }

        let resp = req.send().await?;
        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            return Err(anyhow::anyhow!("non-2xx from elastic: {} {}", status, body));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn splunk_hec_appends_default_path_when_missing() {
        let sink = SplunkHecSink::new(
            reqwest::Client::new(),
            "https://splunk.example:8088".to_string(),
            "token".to_string(),
            None,
            None,
            None,
        )
        .expect("sink");
        assert_eq!(sink.url.path(), "/services/collector/event");
    }

    #[test]
    fn otlp_http_appends_default_logs_path() {
        let sink = OtlpHttpSink::new(
            reqwest::Client::new(),
            "https://collector.example:4318".to_string(),
            None,
            None,
            None,
            None,
        )
        .expect("sink");
        assert_eq!(sink.endpoint.path(), "/v1/logs");

        let sink = OtlpHttpSink::new(
            reqwest::Client::new(),
            "https://collector.example:4318/custom".to_string(),
            None,
            None,
            None,
            None,
        )
        .expect("sink");
        assert_eq!(sink.endpoint.path(), "/custom/v1/logs");
    }
}
