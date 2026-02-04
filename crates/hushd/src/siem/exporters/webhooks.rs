use std::collections::HashMap;
use std::time::Duration;

use async_trait::async_trait;
use reqwest::header;
use serde::{Deserialize, Serialize};

use crate::siem::exporter::{
    ExportEventError, ExportResult, Exporter, ExporterError, SchemaFormat,
};
use crate::siem::types::{SecurityEvent, SecuritySeverity};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct WebhookExporterConfig {
    #[serde(default)]
    pub slack: Option<SlackConfig>,
    #[serde(default)]
    pub teams: Option<TeamsConfig>,
    #[serde(default)]
    pub webhooks: Vec<GenericWebhookConfig>,
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
pub struct SlackConfig {
    pub webhook_url: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TeamsConfig {
    pub webhook_url: String,
    #[serde(default = "default_theme_color")]
    pub theme_color: String,
}

fn default_theme_color() -> String {
    "D32F2F".to_string()
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GenericWebhookConfig {
    pub url: String,
    #[serde(default)]
    pub method: Option<String>,
    #[serde(default)]
    pub headers: HashMap<String, String>,
    #[serde(default)]
    pub auth: Option<WebhookAuthConfig>,
    #[serde(default)]
    pub content_type: Option<String>,
    #[serde(default)]
    pub body_template: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct WebhookAuthConfig {
    #[serde(rename = "type")]
    pub auth_type: String, // bearer|basic|header
    #[serde(default)]
    pub token: Option<String>,
    #[serde(default)]
    pub username: Option<String>,
    #[serde(default)]
    pub password: Option<String>,
    #[serde(default)]
    pub header_name: Option<String>,
    #[serde(default)]
    pub header_value: Option<String>,
}

#[derive(Clone)]
pub struct WebhookExporter {
    config: WebhookExporterConfig,
    client: reqwest::Client,
}

impl WebhookExporter {
    pub fn new(config: WebhookExporterConfig) -> Result<Self, ExporterError> {
        let client = reqwest::Client::builder()
            .timeout(Duration::from_millis(config.timeout_ms.max(1)))
            .build()
            .map_err(|e| ExporterError::Other(e.to_string()))?;
        Ok(Self { config, client })
    }

    fn should_notify(&self, event: &SecurityEvent) -> bool {
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

    async fn post_slack(
        &self,
        cfg: &SlackConfig,
        event: &SecurityEvent,
    ) -> Result<(), ExporterError> {
        let title = if event.decision.allowed {
            "Clawdstrike security event (allowed)"
        } else {
            "Clawdstrike security event (blocked)"
        };

        let payload = serde_json::json!({
            "text": format!("{title}: {} ({:?})", event.decision.guard, event.decision.severity),
            "blocks": [
                {
                    "type": "section",
                    "text": { "type": "mrkdwn", "text": format!("*{title}*\n*Guard:* `{}`\n*Severity:* `{:?}`\n*Reason:* {}", event.decision.guard, event.decision.severity, event.decision.reason) }
                },
                {
                    "type": "context",
                    "elements": [
                        { "type": "mrkdwn", "text": format!("Session: `{}`  Event: `{}`", event.session.id, event.event_id) }
                    ]
                }
            ]
        });

        let resp = self
            .client
            .post(cfg.webhook_url.clone())
            .header(header::CONTENT_TYPE, "application/json")
            .json(&payload)
            .send()
            .await
            .map_err(|e| ExporterError::Other(format!("Slack webhook failed: {e}")))?;

        if resp.status().is_success() || resp.status().as_u16() == 202 {
            Ok(())
        } else {
            Err(ExporterError::Http {
                status: resp.status().as_u16(),
                body: resp.text().await.unwrap_or_default(),
            })
        }
    }

    async fn post_teams(
        &self,
        cfg: &TeamsConfig,
        event: &SecurityEvent,
    ) -> Result<(), ExporterError> {
        let title = if event.decision.allowed {
            "Clawdstrike security event (allowed)"
        } else {
            "Clawdstrike security event (blocked)"
        };

        let payload = serde_json::json!({
            "@type": "MessageCard",
            "@context": "http://schema.org/extensions",
            "summary": title,
            "themeColor": cfg.theme_color,
            "title": title,
            "sections": [
                {
                    "facts": [
                        { "name": "Guard", "value": event.decision.guard },
                        { "name": "Severity", "value": format!("{:?}", event.decision.severity) },
                        { "name": "Session", "value": event.session.id },
                        { "name": "Event ID", "value": event.event_id.to_string() }
                    ],
                    "text": event.decision.reason
                }
            ]
        });

        let resp = self
            .client
            .post(cfg.webhook_url.clone())
            .header(header::CONTENT_TYPE, "application/json")
            .json(&payload)
            .send()
            .await
            .map_err(|e| ExporterError::Other(format!("Teams webhook failed: {e}")))?;

        if resp.status().is_success() || resp.status().as_u16() == 202 {
            Ok(())
        } else {
            Err(ExporterError::Http {
                status: resp.status().as_u16(),
                body: resp.text().await.unwrap_or_default(),
            })
        }
    }

    async fn post_generic(
        &self,
        cfg: &GenericWebhookConfig,
        event: &SecurityEvent,
    ) -> Result<(), ExporterError> {
        let method = cfg.method.clone().unwrap_or_else(|| "POST".to_string());
        let mut req = match method.to_uppercase().as_str() {
            "PUT" => self.client.put(cfg.url.clone()),
            _ => self.client.post(cfg.url.clone()),
        };

        for (k, v) in &cfg.headers {
            req = req.header(k, v);
        }

        if let Some(auth) = &cfg.auth {
            match auth.auth_type.as_str() {
                "bearer" => {
                    if let Some(token) = &auth.token {
                        req = req.bearer_auth(token);
                    }
                }
                "basic" => {
                    if let Some(user) = &auth.username {
                        req = req.basic_auth(user, auth.password.as_deref());
                    }
                }
                "header" => {
                    if let (Some(name), Some(value)) = (&auth.header_name, &auth.header_value) {
                        req = req.header(name, value);
                    }
                }
                _ => {}
            }
        }

        let content_type = cfg
            .content_type
            .clone()
            .unwrap_or_else(|| "application/json".to_string());

        req = req.header(header::CONTENT_TYPE, content_type.clone());

        if let Some(tpl) = &cfg.body_template {
            let rendered = render_template(tpl, &serde_json::to_value(event).unwrap_or_default());
            if content_type.contains("application/json") {
                match serde_json::from_str::<serde_json::Value>(&rendered) {
                    Ok(v) => {
                        req = req.json(&v);
                    }
                    Err(_) => {
                        req = req.json(&serde_json::json!({ "message": rendered, "event": event }));
                    }
                }
            } else {
                req = req.body(rendered);
            }
        } else if content_type.contains("application/json") {
            req = req.json(event);
        } else {
            req = req.body(serde_json::to_string(event).unwrap_or_else(|_| "{}".to_string()));
        }

        let resp = req
            .send()
            .await
            .map_err(|e| ExporterError::Other(format!("Webhook request failed: {e}")))?;

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

fn render_template(template: &str, data: &serde_json::Value) -> String {
    // Minimal handlebars-ish replacement: {{a.b.c}}
    let mut out = String::with_capacity(template.len());
    let chars: Vec<char> = template.chars().collect();
    let mut i = 0usize;
    while i < chars.len() {
        if chars[i] == '{' && i + 1 < chars.len() && chars[i + 1] == '{' {
            let mut j = i + 2;
            while j + 1 < chars.len() && !(chars[j] == '}' && chars[j + 1] == '}') {
                j += 1;
            }
            if j + 1 >= chars.len() {
                // Unclosed, append remainder.
                out.extend(chars[i..].iter());
                break;
            }

            let key: String = chars[i + 2..j]
                .iter()
                .collect::<String>()
                .trim()
                .to_string();
            if let Some(val) = get_by_path(data, &key) {
                out.push_str(&val);
            }
            i = j + 2;
            continue;
        }

        out.push(chars[i]);
        i += 1;
    }
    out
}

fn get_by_path(root: &serde_json::Value, path: &str) -> Option<String> {
    let mut cur = root;
    for part in path.split('.').filter(|p| !p.is_empty()) {
        cur = cur.get(part)?;
    }

    match cur {
        serde_json::Value::String(s) => Some(s.clone()),
        serde_json::Value::Number(n) => Some(n.to_string()),
        serde_json::Value::Bool(b) => Some(b.to_string()),
        serde_json::Value::Null => Some(String::new()),
        other => serde_json::to_string(other).ok(),
    }
}

#[async_trait]
impl Exporter for WebhookExporter {
    fn name(&self) -> &str {
        "webhooks"
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
            if !self.should_notify(&event) {
                exported += 1;
                continue;
            }

            let mut per_event_errors: Vec<String> = Vec::new();
            let mut retryable = false;

            if let Some(cfg) = &self.config.slack {
                if let Err(err) = self.post_slack(cfg, &event).await {
                    retryable |= matches!(err, ExporterError::Http { status, .. } if status == 429 || (500..=599).contains(&status));
                    per_event_errors.push(format!("slack: {err}"));
                }
            }

            if let Some(cfg) = &self.config.teams {
                if let Err(err) = self.post_teams(cfg, &event).await {
                    retryable |= matches!(err, ExporterError::Http { status, .. } if status == 429 || (500..=599).contains(&status));
                    per_event_errors.push(format!("teams: {err}"));
                }
            }

            for cfg in &self.config.webhooks {
                if let Err(err) = self.post_generic(cfg, &event).await {
                    retryable |= matches!(err, ExporterError::Http { status, .. } if status == 429 || (500..=599).contains(&status));
                    per_event_errors.push(format!("webhook({}): {err}", cfg.url));
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

        Ok(ExportResult {
            exported,
            failed: errors.len(),
            errors,
        })
    }

    async fn health_check(&self) -> Result<(), String> {
        // Webhooks don't have a reliable health check without sending, so just validate config shape.
        if self.config.slack.is_none()
            && self.config.teams.is_none()
            && self.config.webhooks.is_empty()
        {
            return Err("No webhooks configured".to_string());
        }
        Ok(())
    }

    async fn shutdown(&self) -> Result<(), String> {
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
