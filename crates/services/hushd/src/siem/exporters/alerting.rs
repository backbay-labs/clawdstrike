use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use reqwest::header;
use serde::{Deserialize, Serialize};
use tokio::sync::{watch, Mutex, RwLock};

use crate::siem::exporter::{
    ExportEventError, ExportResult, Exporter, ExporterError, SchemaFormat,
};
use crate::siem::types::{SecurityEvent, SecuritySeverity};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AlertingConfig {
    #[serde(default)]
    pub pagerduty: Option<PagerDutyConfig>,
    #[serde(default)]
    pub opsgenie: Option<OpsGenieConfig>,
    #[serde(default)]
    pub min_severity: Option<SecuritySeverity>,
    #[serde(default)]
    pub include_guards: Vec<String>,
    #[serde(default)]
    pub exclude_guards: Vec<String>,
    #[serde(default = "default_timeout_ms")]
    pub timeout_ms: u64,
}

fn default_timeout_ms() -> u64 {
    30_000
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PagerDutyConfig {
    /// Events API v2 routing key.
    pub routing_key: String,
    #[serde(default = "default_pagerduty_endpoint")]
    pub api_endpoint: String,
    #[serde(default)]
    pub severity_mapping: PagerDutySeverityMapping,
    #[serde(default)]
    pub dedup_key_template: Option<String>,
    #[serde(default)]
    pub custom_details: bool,
    #[serde(default)]
    pub auto_resolve: AutoResolveConfig,
}

fn default_pagerduty_endpoint() -> String {
    "https://events.pagerduty.com".to_string()
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct PagerDutySeverityMapping {
    #[serde(default)]
    pub critical: Option<String>,
    #[serde(default)]
    pub high: Option<String>,
    #[serde(default)]
    pub medium: Option<String>,
    #[serde(default)]
    pub low: Option<String>,
    #[serde(default)]
    pub info: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct OpsGenieConfig {
    pub api_key: String,
    #[serde(default = "default_opsgenie_endpoint")]
    pub api_endpoint: String,
    #[serde(default)]
    pub priority_mapping: OpsGeniePriorityMapping,
    #[serde(default)]
    pub tags: Vec<String>,
    #[serde(default)]
    pub responders: Vec<OpsGenieResponder>,
    #[serde(default)]
    pub dedup_key_template: Option<String>,
    #[serde(default)]
    pub heartbeat: HeartbeatConfig,
}

fn default_opsgenie_endpoint() -> String {
    "https://api.opsgenie.com".to_string()
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct OpsGeniePriorityMapping {
    #[serde(default)]
    pub critical: Option<String>,
    #[serde(default)]
    pub high: Option<String>,
    #[serde(default)]
    pub medium: Option<String>,
    #[serde(default)]
    pub low: Option<String>,
    #[serde(default)]
    pub info: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct OpsGenieResponder {
    #[serde(rename = "type")]
    pub responder_type: String,
    #[serde(default)]
    pub id: Option<String>,
    #[serde(default)]
    pub name: Option<String>,
}

#[derive(Clone)]
pub struct AlertingExporter {
    config: AlertingConfig,
    client: reqwest::Client,
    shutdown_tx: watch::Sender<bool>,
    tasks: Arc<Mutex<Vec<tokio::task::JoinHandle<()>>>>,
    open_pagerduty: Arc<RwLock<HashMap<String, chrono::DateTime<chrono::Utc>>>>,
}

impl AlertingExporter {
    pub fn new(config: AlertingConfig) -> Result<Self, ExporterError> {
        let client = reqwest::Client::builder()
            .timeout(Duration::from_millis(config.timeout_ms.max(1)))
            .build()
            .map_err(|e| ExporterError::Other(e.to_string()))?;

        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        let tasks: Arc<Mutex<Vec<tokio::task::JoinHandle<()>>>> = Arc::new(Mutex::new(Vec::new()));
        let open_pagerduty: Arc<RwLock<HashMap<String, chrono::DateTime<chrono::Utc>>>> =
            Arc::new(RwLock::new(HashMap::new()));

        // PagerDuty auto-resolve background loop.
        if let Some(pd) = &config.pagerduty {
            if pd.auto_resolve.enabled {
                let client = client.clone();
                let pd = pd.clone();
                let open = open_pagerduty.clone();
                let mut shutdown_rx = shutdown_rx.clone();
                let handle = tokio::spawn(async move {
                    let mut ticker = tokio::time::interval(Duration::from_secs(60));
                    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

                    loop {
                        tokio::select! {
                            _ = shutdown_rx.changed() => {
                                if *shutdown_rx.borrow() { break; }
                            }
                            _ = ticker.tick() => {}
                        }

                        if !pd.auto_resolve.enabled {
                            continue;
                        }

                        let threshold =
                            chrono::Duration::minutes(pd.auto_resolve.after_minutes as i64);
                        let now = chrono::Utc::now();

                        let keys_to_resolve: Vec<String> = {
                            let open = open.read().await;
                            open.iter()
                                .filter_map(|(k, last)| {
                                    if now.signed_duration_since(*last) >= threshold {
                                        Some(k.clone())
                                    } else {
                                        None
                                    }
                                })
                                .collect()
                        };

                        for key in keys_to_resolve {
                            if let Err(err) = pagerduty_resolve(&client, &pd, &key).await {
                                tracing::warn!(error = %err, dedup_key = %key, "PagerDuty auto-resolve failed");
                            } else {
                                let mut open = open.write().await;
                                open.remove(&key);
                            }
                        }
                    }
                });
                tasks.blocking_lock().push(handle);
            }
        }

        // OpsGenie heartbeat loop.
        if let Some(og) = &config.opsgenie {
            if og.heartbeat.enabled {
                let client = client.clone();
                let og = og.clone();
                let mut shutdown_rx = shutdown_rx.clone();
                let handle = tokio::spawn(async move {
                    let mut ticker = tokio::time::interval(Duration::from_secs(
                        60 * og.heartbeat.interval_minutes.max(1),
                    ));
                    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

                    // Initial ping
                    let _ = opsgenie_ping_heartbeat(&client, &og).await;

                    loop {
                        tokio::select! {
                            _ = shutdown_rx.changed() => {
                                if *shutdown_rx.borrow() { break; }
                            }
                            _ = ticker.tick() => {}
                        }

                        if let Err(err) = opsgenie_ping_heartbeat(&client, &og).await {
                            tracing::warn!(error = %err, "OpsGenie heartbeat ping failed");
                        }
                    }
                });
                tasks.blocking_lock().push(handle);
            }
        }

        Ok(Self {
            config,
            client,
            shutdown_tx,
            tasks,
            open_pagerduty,
        })
    }

    fn should_alert(&self, event: &SecurityEvent) -> bool {
        if event.decision.allowed {
            return false;
        }

        if let Some(min) = &self.config.min_severity {
            if severity_ord(&event.decision.severity) < severity_ord(min) {
                return false;
            }
        }

        if !self.config.include_guards.is_empty()
            && !self.config.include_guards.contains(&event.decision.guard)
        {
            return false;
        }

        if self.config.exclude_guards.contains(&event.decision.guard) {
            return false;
        }

        true
    }

    fn render_dedup_key(template: Option<&str>, event: &SecurityEvent) -> String {
        let default = format!(
            "{}:{}:{}",
            event.decision.guard, event.session.id, event.resource.name
        );
        let Some(template) = template else {
            return default;
        };

        let event_type = serde_json::to_value(&event.event_type)
            .ok()
            .and_then(|v| v.as_str().map(|s| s.to_string()))
            .unwrap_or_else(|| format!("{:?}", event.event_type));

        template
            .replace("{guard}", &event.decision.guard)
            .replace("{session_id}", &event.session.id)
            .replace("{resource}", &event.resource.name)
            .replace("{tenant}", event.session.tenant_id.as_deref().unwrap_or(""))
            .replace("{event_type}", &event_type)
    }

    async fn send_pagerduty(
        &self,
        cfg: &PagerDutyConfig,
        event: &SecurityEvent,
    ) -> Result<String, ExporterError> {
        let dedup_key = Self::render_dedup_key(cfg.dedup_key_template.as_deref(), event);
        let severity = pagerduty_severity(&event.decision.severity, &cfg.severity_mapping);

        let event_type = serde_json::to_value(&event.event_type)
            .ok()
            .and_then(|v| v.as_str().map(|s| s.to_string()))
            .unwrap_or_else(|| format!("{:?}", event.event_type));

        let mut payload = serde_json::json!({
            "routing_key": cfg.routing_key,
            "event_action": "trigger",
            "dedup_key": dedup_key,
            "payload": {
                "summary": format!("Clawdstrike security violation: {}", event.decision.guard),
                "source": "clawdstrike",
                "severity": severity,
                "timestamp": event.timestamp_rfc3339_nanos(),
                "component": event.resource.name,
                "group": event.session.id,
                "class": event_type,
            }
        });

        if cfg.custom_details {
            payload["payload"]["custom_details"] = serde_json::to_value(event).unwrap_or_default();
        }

        let resp = self
            .client
            .post(format!(
                "{}/v2/enqueue",
                cfg.api_endpoint.trim_end_matches('/')
            ))
            .header(header::CONTENT_TYPE, "application/json")
            .json(&payload)
            .send()
            .await
            .map_err(|e| ExporterError::Other(format!("PagerDuty request failed: {e}")))?;

        if resp.status().is_success() {
            Ok(dedup_key)
        } else {
            Err(ExporterError::Http {
                status: resp.status().as_u16(),
                body: resp.text().await.unwrap_or_default(),
            })
        }
    }

    async fn send_opsgenie(
        &self,
        cfg: &OpsGenieConfig,
        event: &SecurityEvent,
    ) -> Result<(), ExporterError> {
        let alias = Self::render_dedup_key(cfg.dedup_key_template.as_deref(), event);
        let priority = opsgenie_priority(&event.decision.severity, &cfg.priority_mapping);

        let mut tags = cfg.tags.clone();
        tags.push(format!("guard:{}", event.decision.guard));
        tags.push(format!("severity:{:?}", event.decision.severity));

        let mut body = serde_json::json!({
            "message": format!("Clawdstrike violation: {}", event.decision.guard),
            "alias": alias,
            "description": event.decision.reason,
            "priority": priority,
            "tags": tags,
            "details": serde_json::to_value(event).unwrap_or_default(),
        });

        if !cfg.responders.is_empty() {
            body["responders"] = serde_json::to_value(&cfg.responders).unwrap_or_default();
        }

        let resp = self
            .client
            .post(format!(
                "{}/v2/alerts",
                cfg.api_endpoint.trim_end_matches('/')
            ))
            .header(header::CONTENT_TYPE, "application/json")
            .header(header::AUTHORIZATION, format!("GenieKey {}", cfg.api_key))
            .json(&body)
            .send()
            .await
            .map_err(|e| ExporterError::Other(format!("OpsGenie request failed: {e}")))?;

        if resp.status().is_success() || resp.status().as_u16() == 202 {
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
impl Exporter for AlertingExporter {
    fn name(&self) -> &str {
        "alerting"
    }

    fn schema(&self) -> SchemaFormat {
        SchemaFormat::Native
    }

    async fn export(&self, events: Vec<SecurityEvent>) -> Result<ExportResult, ExporterError> {
        if events.is_empty() {
            return Ok(ExportResult::default());
        }

        let mut exported = 0usize;
        let mut errors: Vec<ExportEventError> = Vec::new();

        for event in events {
            if !self.should_alert(&event) {
                exported += 1;
                continue;
            }

            let mut per_event_errors: Vec<String> = Vec::new();
            let mut retryable = false;

            if let Some(cfg) = &self.config.pagerduty {
                match self.send_pagerduty(cfg, &event).await {
                    Ok(dedup_key) => {
                        let mut open = self.open_pagerduty.write().await;
                        open.insert(dedup_key, chrono::Utc::now());
                    }
                    Err(err) => {
                        retryable |= matches!(err, ExporterError::Http { status, .. } if status == 429 || (500..=599).contains(&status));
                        per_event_errors.push(format!("pagerduty: {err}"));
                    }
                }
            }

            if let Some(cfg) = &self.config.opsgenie {
                if let Err(err) = self.send_opsgenie(cfg, &event).await {
                    retryable |= matches!(err, ExporterError::Http { status, .. } if status == 429 || (500..=599).contains(&status));
                    per_event_errors.push(format!("opsgenie: {err}"));
                }
            }

            if per_event_errors.is_empty() {
                exported += 1;
            } else {
                errors.push(ExportEventError {
                    event_id: event.event_id.to_string(),
                    error: per_event_errors.join("; "),
                    retryable,
                });
            }
        }

        let failed = errors.len();
        Ok(ExportResult {
            exported,
            failed,
            errors,
        })
    }

    async fn health_check(&self) -> Result<(), String> {
        // Best-effort: validate that endpoints are reachable.
        if let Some(pd) = &self.config.pagerduty {
            let resp = self
                .client
                .get(format!("{}/", pd.api_endpoint.trim_end_matches('/')))
                .send()
                .await
                .map_err(|e| e.to_string())?;
            if !resp.status().is_success() && resp.status().as_u16() != 404 {
                return Err(format!(
                    "PagerDuty endpoint not reachable: {}",
                    resp.status()
                ));
            }
        }
        if let Some(og) = &self.config.opsgenie {
            let resp = self
                .client
                .get(format!("{}/", og.api_endpoint.trim_end_matches('/')))
                .send()
                .await
                .map_err(|e| e.to_string())?;
            if !resp.status().is_success() && resp.status().as_u16() != 404 {
                return Err(format!(
                    "OpsGenie endpoint not reachable: {}",
                    resp.status()
                ));
            }
        }
        Ok(())
    }

    async fn shutdown(&self) -> Result<(), String> {
        let _ = self.shutdown_tx.send(true);
        let mut tasks = self.tasks.lock().await;
        for task in tasks.drain(..) {
            let _ = task.await;
        }
        Ok(())
    }
}

fn severity_ord(sev: &SecuritySeverity) -> u8 {
    match sev {
        SecuritySeverity::Info => 0,
        SecuritySeverity::Low => 1,
        SecuritySeverity::Medium => 2,
        SecuritySeverity::High => 3,
        SecuritySeverity::Critical => 4,
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AutoResolveConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default = "default_resolve_minutes")]
    pub after_minutes: u64,
}

fn default_resolve_minutes() -> u64 {
    30
}

impl Default for AutoResolveConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            after_minutes: default_resolve_minutes(),
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct HeartbeatConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default = "default_heartbeat_name")]
    pub name: String,
    #[serde(default = "default_heartbeat_interval")]
    pub interval_minutes: u64,
}

fn default_heartbeat_name() -> String {
    "clawdstrike".to_string()
}

fn default_heartbeat_interval() -> u64 {
    5
}

impl Default for HeartbeatConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            name: default_heartbeat_name(),
            interval_minutes: default_heartbeat_interval(),
        }
    }
}

async fn pagerduty_resolve(
    client: &reqwest::Client,
    cfg: &PagerDutyConfig,
    dedup_key: &str,
) -> Result<(), ExporterError> {
    let payload = serde_json::json!({
        "routing_key": cfg.routing_key,
        "event_action": "resolve",
        "dedup_key": dedup_key,
        "payload": {
            "summary": "Clawdstrike security violation resolved",
            "source": "clawdstrike",
            "severity": "info",
        }
    });

    let resp = client
        .post(format!(
            "{}/v2/enqueue",
            cfg.api_endpoint.trim_end_matches('/')
        ))
        .header(header::CONTENT_TYPE, "application/json")
        .json(&payload)
        .send()
        .await
        .map_err(|e| ExporterError::Other(format!("PagerDuty resolve failed: {e}")))?;

    if resp.status().is_success() {
        Ok(())
    } else {
        Err(ExporterError::Http {
            status: resp.status().as_u16(),
            body: resp.text().await.unwrap_or_default(),
        })
    }
}

async fn opsgenie_ping_heartbeat(
    client: &reqwest::Client,
    cfg: &OpsGenieConfig,
) -> Result<(), ExporterError> {
    if !cfg.heartbeat.enabled {
        return Ok(());
    }

    let url = format!(
        "{}/v2/heartbeats/{}/ping",
        cfg.api_endpoint.trim_end_matches('/'),
        cfg.heartbeat.name
    );

    let resp = client
        .post(url)
        .header(header::AUTHORIZATION, format!("GenieKey {}", cfg.api_key))
        .header(header::CONTENT_TYPE, "application/json")
        .json(&serde_json::json!({}))
        .send()
        .await
        .map_err(|e| ExporterError::Other(format!("OpsGenie heartbeat failed: {e}")))?;

    if resp.status().is_success() || resp.status().as_u16() == 202 {
        Ok(())
    } else {
        Err(ExporterError::Http {
            status: resp.status().as_u16(),
            body: resp.text().await.unwrap_or_default(),
        })
    }
}

fn pagerduty_severity(sev: &SecuritySeverity, mapping: &PagerDutySeverityMapping) -> String {
    match sev {
        SecuritySeverity::Critical => mapping
            .critical
            .clone()
            .unwrap_or_else(|| "critical".to_string()),
        SecuritySeverity::High => mapping.high.clone().unwrap_or_else(|| "error".to_string()),
        SecuritySeverity::Medium => mapping
            .medium
            .clone()
            .unwrap_or_else(|| "warning".to_string()),
        SecuritySeverity::Low => mapping.low.clone().unwrap_or_else(|| "warning".to_string()),
        SecuritySeverity::Info => mapping.info.clone().unwrap_or_else(|| "info".to_string()),
    }
}

fn opsgenie_priority(sev: &SecuritySeverity, mapping: &OpsGeniePriorityMapping) -> String {
    match sev {
        SecuritySeverity::Critical => mapping.critical.clone().unwrap_or_else(|| "P1".to_string()),
        SecuritySeverity::High => mapping.high.clone().unwrap_or_else(|| "P2".to_string()),
        SecuritySeverity::Medium => mapping.medium.clone().unwrap_or_else(|| "P3".to_string()),
        SecuritySeverity::Low => mapping.low.clone().unwrap_or_else(|| "P4".to_string()),
        SecuritySeverity::Info => mapping.info.clone().unwrap_or_else(|| "P5".to_string()),
    }
}
