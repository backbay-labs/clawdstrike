use serde::{Deserialize, Serialize};
use sqlx::row::Row;
use uuid::Uuid;

use crate::db::{PgPool, PgRow};

#[derive(Debug, thiserror::Error)]
pub enum AlertError {
    #[error("database error: {0}")]
    Database(#[from] sqlx::error::Error),
    #[error("http error: {0}")]
    Http(#[from] reqwest::Error),
    #[error("missing config field: {0}")]
    MissingConfig(&'static str),
}

/// A security event that may trigger alerts.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityEvent {
    pub guard_name: String,
    pub verdict: String,
    pub agent_id: String,
    pub target: String,
    pub timestamp: String,
    pub severity: String,
}

#[derive(Debug, Clone)]
pub struct AlertConfig {
    pub id: Uuid,
    pub tenant_id: Uuid,
    pub name: String,
    pub channel: String,
    pub config: serde_json::Value,
    pub guard_filter: Option<Vec<String>>,
    pub severity_threshold: String,
    pub enabled: bool,
}

impl AlertConfig {
    pub fn from_row(row: PgRow) -> Result<Self, sqlx::error::Error> {
        Ok(Self {
            id: row.try_get("id")?,
            tenant_id: row.try_get("tenant_id")?,
            name: row.try_get("name")?,
            channel: row.try_get("channel")?,
            config: row.try_get("config")?,
            guard_filter: row.try_get("guard_filter")?,
            severity_threshold: row.try_get("severity_threshold")?,
            enabled: row.try_get("enabled")?,
        })
    }
}

impl Serialize for AlertConfig {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        use serde::ser::SerializeStruct;
        let mut s = serializer.serialize_struct("AlertConfig", 8)?;
        s.serialize_field("id", &self.id)?;
        s.serialize_field("tenant_id", &self.tenant_id)?;
        s.serialize_field("name", &self.name)?;
        s.serialize_field("channel", &self.channel)?;
        s.serialize_field("config", &self.config)?;
        s.serialize_field("guard_filter", &self.guard_filter)?;
        s.serialize_field("severity_threshold", &self.severity_threshold)?;
        s.serialize_field("enabled", &self.enabled)?;
        s.end()
    }
}

/// Service for dispatching alerts to PagerDuty, Slack, and webhooks.
#[derive(Clone)]
pub struct AlerterService {
    db: PgPool,
    http_client: reqwest::Client,
}

impl AlerterService {
    pub fn new(db: PgPool) -> Self {
        Self {
            db,
            http_client: reqwest::Client::new(),
        }
    }

    /// Process a security event and dispatch alerts to matching configs.
    pub async fn process_violation(
        &self,
        tenant_id: Uuid,
        event: &SecurityEvent,
    ) -> Result<(), AlertError> {
        let rows = sqlx::query::query(
            "SELECT * FROM alert_configs WHERE tenant_id = $1 AND enabled = true",
        )
        .bind(tenant_id)
        .fetch_all(&self.db)
        .await?;

        let configs: Vec<AlertConfig> = rows
            .into_iter()
            .filter_map(|r| AlertConfig::from_row(r).ok())
            .collect();

        for config in configs {
            if !matches_filter(&config, event) {
                continue;
            }

            let result = match config.channel.as_str() {
                "pagerduty" => self.send_pagerduty(&config, event).await,
                "slack" => self.send_slack(&config, event).await,
                "webhook" => self.send_webhook(&config, event).await,
                _ => Ok(()),
            };

            if let Err(e) = result {
                tracing::error!(
                    alert_id = %config.id,
                    channel = %config.channel,
                    error = %e,
                    "Failed to dispatch alert"
                );
            }
        }

        Ok(())
    }

    async fn send_slack(&self, config: &AlertConfig, event: &SecurityEvent) -> Result<(), AlertError> {
        let webhook_url = config.config["webhook_url"]
            .as_str()
            .ok_or(AlertError::MissingConfig("webhook_url"))?;

        let payload = serde_json::json!({
            "text": format!(
                "*ClawdStrike Alert*\nGuard: {}\nVerdict: {}\nAgent: {}\nTarget: {}\nTime: {}",
                event.guard_name, event.verdict, event.agent_id, event.target, event.timestamp
            )
        });

        self.http_client
            .post(webhook_url)
            .json(&payload)
            .send()
            .await?;

        Ok(())
    }

    async fn send_pagerduty(
        &self,
        config: &AlertConfig,
        event: &SecurityEvent,
    ) -> Result<(), AlertError> {
        let routing_key = config.config["routing_key"]
            .as_str()
            .ok_or(AlertError::MissingConfig("routing_key"))?;

        let payload = serde_json::json!({
            "routing_key": routing_key,
            "event_action": "trigger",
            "payload": {
                "summary": format!("ClawdStrike: {} - {}", event.guard_name, event.verdict),
                "source": event.agent_id,
                "severity": event.severity,
                "custom_details": event,
            }
        });

        self.http_client
            .post("https://events.pagerduty.com/v2/enqueue")
            .json(&payload)
            .send()
            .await?;

        Ok(())
    }

    async fn send_webhook(
        &self,
        config: &AlertConfig,
        event: &SecurityEvent,
    ) -> Result<(), AlertError> {
        let url = config.config["url"]
            .as_str()
            .ok_or(AlertError::MissingConfig("url"))?;

        self.http_client.post(url).json(event).send().await?;

        Ok(())
    }
}

fn matches_filter(config: &AlertConfig, event: &SecurityEvent) -> bool {
    if let Some(ref filters) = config.guard_filter {
        if !filters.is_empty() && !filters.iter().any(|f| f == &event.guard_name) {
            return false;
        }
    }
    let severity_rank = |s: &str| -> u8 {
        match s {
            "info" => 0,
            "warn" => 1,
            "error" => 2,
            "critical" => 3,
            _ => 0,
        }
    };
    severity_rank(&event.severity) >= severity_rank(&config.severity_threshold)
}
