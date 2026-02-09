use std::time::Duration;

use async_trait::async_trait;
use chrono::Utc;
use reqwest::header;
use serde::{Deserialize, Serialize};

use crate::siem::exporter::{
    ExportEventError, ExportResult, Exporter, ExporterError, SchemaFormat,
};
use crate::siem::types::{SecurityEvent, SecuritySeverity};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DatadogConfig {
    pub api_key: String,
    #[serde(default)]
    pub app_key: Option<String>,
    #[serde(default = "default_site")]
    pub site: String,
    #[serde(default)]
    pub logs: DatadogLogsConfig,
    #[serde(default)]
    pub metrics: DatadogMetricsConfig,
    #[serde(default)]
    pub tls: DatadogTlsConfig,
    #[serde(default = "default_timeout_ms")]
    pub timeout_ms: u64,
}

fn default_site() -> String {
    "datadoghq.com".to_string()
}

fn default_timeout_ms() -> u64 {
    30_000
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct DatadogTlsConfig {
    #[serde(default)]
    pub insecure_skip_verify: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DatadogLogsConfig {
    #[serde(default = "default_service")]
    pub service: String,
    #[serde(default = "default_source")]
    pub source: String,
    #[serde(default)]
    pub tags: Vec<String>,
    #[serde(default)]
    pub hostname: Option<String>,
}

fn default_service() -> String {
    "clawdstrike".to_string()
}

fn default_source() -> String {
    "clawdstrike".to_string()
}

impl Default for DatadogLogsConfig {
    fn default() -> Self {
        Self {
            service: default_service(),
            source: default_source(),
            tags: Vec::new(),
            hostname: None,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DatadogMetricsConfig {
    #[serde(default = "default_metrics_enabled")]
    pub enabled: bool,
    #[serde(default = "default_metric_prefix")]
    pub prefix: String,
    #[serde(default)]
    pub tags: Vec<String>,
}

fn default_metrics_enabled() -> bool {
    true
}

fn default_metric_prefix() -> String {
    "clawdstrike".to_string()
}

impl Default for DatadogMetricsConfig {
    fn default() -> Self {
        Self {
            enabled: default_metrics_enabled(),
            prefix: default_metric_prefix(),
            tags: Vec::new(),
        }
    }
}

#[derive(Clone)]
pub struct DatadogExporter {
    config: DatadogConfig,
    client: reqwest::Client,
}

impl DatadogExporter {
    pub fn new(mut config: DatadogConfig) -> Result<Self, ExporterError> {
        config.site = config.site.trim().trim_start_matches('.').to_string();

        let mut builder =
            reqwest::Client::builder().timeout(Duration::from_millis(config.timeout_ms.max(1)));
        if config.tls.insecure_skip_verify {
            builder = builder.danger_accept_invalid_certs(true);
        }
        let client = builder
            .build()
            .map_err(|e| ExporterError::Other(e.to_string()))?;

        Ok(Self { config, client })
    }

    fn hostname(&self) -> String {
        if let Some(h) = &self.config.logs.hostname {
            return h.clone();
        }
        std::env::var("HOSTNAME").unwrap_or_else(|_| "unknown".to_string())
    }

    fn logs_intake_url(&self) -> String {
        format!("https://http-intake.logs.{}/api/v2/logs", self.config.site)
    }

    fn metrics_intake_url(&self) -> String {
        format!("https://api.{}/api/v1/series", self.config.site)
    }

    fn validate_url(&self) -> String {
        format!("https://api.{}/api/v1/validate", self.config.site)
    }

    fn datadog_status(sev: &SecuritySeverity, allowed: bool) -> &'static str {
        if !allowed {
            return match sev {
                SecuritySeverity::Critical => "critical",
                SecuritySeverity::High => "error",
                _ => "error",
            };
        }

        match sev {
            SecuritySeverity::Critical => "critical",
            SecuritySeverity::High => "error",
            SecuritySeverity::Medium => "warn",
            SecuritySeverity::Low => "warn",
            SecuritySeverity::Info => "info",
        }
    }

    async fn send_logs(&self, events: &[SecurityEvent]) -> Result<(), ExporterError> {
        let hostname = self.hostname();

        let mut logs: Vec<serde_json::Value> = Vec::with_capacity(events.len());
        for e in events {
            let mut tags = self.config.logs.tags.clone();
            tags.push(format!("guard:{}", e.decision.guard));
            tags.push(format!("event_type:{:?}", e.event_type));
            tags.push(format!("severity:{:?}", e.decision.severity));
            tags.push(format!("outcome:{:?}", e.outcome));
            if let Some(env) = &e.session.environment {
                tags.push(format!("env:{env}"));
            }
            if let Some(tenant) = &e.session.tenant_id {
                tags.push(format!("tenant:{tenant}"));
            }

            logs.push(serde_json::json!({
                "message": e.decision.reason,
                "ddsource": self.config.logs.source,
                "service": self.config.logs.service,
                "hostname": hostname,
                "status": Self::datadog_status(&e.decision.severity, e.decision.allowed),
                "ddtags": tags.join(","),
                "event": e,
            }));
        }

        let resp = self
            .client
            .post(self.logs_intake_url())
            .header("DD-API-KEY", &self.config.api_key)
            .header(header::CONTENT_TYPE, "application/json")
            .json(&logs)
            .send()
            .await
            .map_err(|e| ExporterError::Other(format!("Datadog logs request failed: {e}")))?;

        if resp.status().is_success() || resp.status().as_u16() == 202 {
            Ok(())
        } else {
            Err(ExporterError::Http {
                status: resp.status().as_u16(),
                body: resp.text().await.unwrap_or_default(),
            })
        }
    }

    async fn send_metrics(&self, events: &[SecurityEvent]) -> Result<(), ExporterError> {
        if !self.config.metrics.enabled {
            return Ok(());
        }

        let now = Utc::now().timestamp();
        let total = events.len() as f64;
        let denied = events.iter().filter(|e| !e.decision.allowed).count() as f64;
        let allowed = total - denied;

        let mut base_tags = self.config.metrics.tags.clone();
        base_tags.push("source:clawdstrike".to_string());

        let mut series = vec![
            serde_json::json!({
                "metric": format!("{}.security.events.total", self.config.metrics.prefix),
                "type": "count",
                "points": [[now, total]],
                "tags": base_tags,
            }),
            serde_json::json!({
                "metric": format!("{}.security.events.allowed", self.config.metrics.prefix),
                "type": "count",
                "points": [[now, allowed]],
                "tags": base_tags,
            }),
            serde_json::json!({
                "metric": format!("{}.security.events.denied", self.config.metrics.prefix),
                "type": "count",
                "points": [[now, denied]],
                "tags": base_tags,
            }),
        ];

        // Breakdowns for dashboards: by severity and by guard.
        let mut by_severity: std::collections::HashMap<String, u64> =
            std::collections::HashMap::new();
        let mut by_guard: std::collections::HashMap<String, u64> = std::collections::HashMap::new();

        for e in events {
            let sev = serde_json::to_value(&e.decision.severity)
                .ok()
                .and_then(|v| v.as_str().map(|s| s.to_string()))
                .unwrap_or_else(|| format!("{:?}", e.decision.severity));
            *by_severity.entry(sev).or_insert(0) += 1;
            *by_guard.entry(e.decision.guard.clone()).or_insert(0) += 1;
        }

        for (sev, count) in by_severity {
            let mut tags = base_tags.clone();
            tags.push(format!("severity:{}", sanitize_tag_value(&sev)));
            series.push(serde_json::json!({
                "metric": format!("{}.security.events.by_severity", self.config.metrics.prefix),
                "type": "count",
                "points": [[now, count as f64]],
                "tags": tags,
            }));
        }

        for (guard, count) in by_guard {
            let mut tags = base_tags.clone();
            tags.push(format!("guard:{}", sanitize_tag_value(&guard)));
            series.push(serde_json::json!({
                "metric": format!("{}.security.events.by_guard", self.config.metrics.prefix),
                "type": "count",
                "points": [[now, count as f64]],
                "tags": tags,
            }));
        }

        let resp = self
            .client
            .post(self.metrics_intake_url())
            .header("DD-API-KEY", &self.config.api_key)
            .header(header::CONTENT_TYPE, "application/json")
            .json(&serde_json::json!({ "series": series }))
            .send()
            .await
            .map_err(|e| ExporterError::Other(format!("Datadog metrics request failed: {e}")))?;

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
impl Exporter for DatadogExporter {
    fn name(&self) -> &str {
        "datadog"
    }

    fn schema(&self) -> SchemaFormat {
        SchemaFormat::Native
    }

    async fn export(&self, events: Vec<SecurityEvent>) -> Result<ExportResult, ExporterError> {
        if events.is_empty() {
            return Ok(ExportResult::default());
        }

        let mut errors: Vec<ExportEventError> = Vec::new();

        let logs_res = self.send_logs(&events).await;
        let metrics_res = self.send_metrics(&events).await;

        if let Err(err) = logs_res {
            let retryable = matches!(err, ExporterError::Http { status, .. } if status == 429 || (500..=599).contains(&status));
            errors.extend(events.iter().map(|e| ExportEventError {
                event_id: e.event_id.to_string(),
                error: err.to_string(),
                retryable,
            }));
        } else if let Err(err) = metrics_res {
            // Metrics failures shouldn't fail the whole batch; treat as retryable but allow logs through.
            tracing::warn!(error = %err, "Datadog metrics export failed");
        }

        if errors.is_empty() {
            Ok(ExportResult {
                exported: events.len(),
                failed: 0,
                errors,
            })
        } else {
            Ok(ExportResult {
                exported: 0,
                failed: events.len(),
                errors,
            })
        }
    }

    async fn health_check(&self) -> Result<(), String> {
        let resp = self
            .client
            .get(self.validate_url())
            .header("DD-API-KEY", &self.config.api_key)
            .send()
            .await
            .map_err(|e| e.to_string())?;
        if resp.status().is_success() {
            Ok(())
        } else {
            Err(format!("Datadog validate failed: {}", resp.status()))
        }
    }

    async fn shutdown(&self) -> Result<(), String> {
        Ok(())
    }
}

fn sanitize_tag_value(value: &str) -> String {
    value
        .chars()
        .map(|c| match c {
            ' ' | ',' | '\n' | '\r' | '\t' => '_',
            _ => c,
        })
        .collect()
}
