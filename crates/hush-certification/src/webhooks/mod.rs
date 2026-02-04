use std::path::Path;
use std::sync::Mutex;

use chrono::{SecondsFormat, Utc};
use rusqlite::{params, Connection, OptionalExtension as _};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use uuid::Uuid;

use crate::{Result};

const CREATE_TABLES: &str = r#"
CREATE TABLE IF NOT EXISTS webhooks (
  webhook_id TEXT PRIMARY KEY,
  url TEXT NOT NULL,
  events TEXT NOT NULL,
  secret TEXT NOT NULL,
  enabled INTEGER NOT NULL,
  created_at TEXT NOT NULL,
  metadata TEXT NULL
);

CREATE INDEX IF NOT EXISTS idx_webhooks_enabled ON webhooks(enabled);
"#;

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct WebhookRecord {
    pub webhook_id: String,
    pub url: String,
    pub events: Vec<String>,
    pub enabled: bool,
    pub created_at: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub metadata: Option<Value>,
}

/// Internal record with secret for delivery.
#[derive(Clone, Debug)]
pub struct WebhookDeliveryTarget {
    pub webhook_id: String,
    pub url: String,
    pub events: Vec<String>,
    pub secret: String,
    pub enabled: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CreateWebhookInput {
    pub url: String,
    pub events: Vec<String>,
    pub secret: String,
    #[serde(default)]
    pub enabled: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub metadata: Option<Value>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UpdateWebhookInput {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub events: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub secret: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub enabled: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub metadata: Option<Value>,
}

pub struct SqliteWebhookStore {
    conn: Mutex<Connection>,
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used, clippy::unwrap_used)]

    use super::*;

    #[test]
    fn create_and_query_webhook() {
        let store = SqliteWebhookStore::new(":memory:").unwrap();
        let created = store
            .create(CreateWebhookInput {
                url: "https://example.com/hook".to_string(),
                events: vec!["certification.issued".to_string(), "violation.detected".to_string()],
                secret: "secret".to_string(),
                enabled: Some(true),
                metadata: None,
            })
            .unwrap();

        let loaded = store.get(&created.webhook_id).unwrap().unwrap();
        assert_eq!(loaded.url, "https://example.com/hook");
        assert!(loaded.events.iter().any(|e| e == "certification.issued"));

        let targets = store
            .list_enabled_for_event("certification.issued")
            .unwrap();
        assert_eq!(targets.len(), 1);
        assert_eq!(targets[0].webhook_id, created.webhook_id);

        let updated = store
            .update(
                &created.webhook_id,
                UpdateWebhookInput {
                    enabled: Some(false),
                    url: None,
                    events: None,
                    secret: None,
                    metadata: None,
                },
            )
            .unwrap()
            .unwrap();
        assert_eq!(updated.enabled, false);

        let targets = store
            .list_enabled_for_event("certification.issued")
            .unwrap();
        assert!(targets.is_empty());

        assert!(store.delete(&created.webhook_id).unwrap());
        assert!(store.get(&created.webhook_id).unwrap().is_none());
    }
}

impl SqliteWebhookStore {
    fn lock_conn(&self) -> std::sync::MutexGuard<'_, Connection> {
        self.conn.lock().unwrap_or_else(|err| err.into_inner())
    }

    pub fn new(path: impl AsRef<Path>) -> Result<Self> {
        if let Some(parent) = path.as_ref().parent() {
            std::fs::create_dir_all(parent)?;
        }
        let conn = Connection::open(path)?;
        conn.execute_batch("PRAGMA journal_mode=WAL; PRAGMA synchronous=NORMAL;")?;
        conn.execute_batch(CREATE_TABLES)?;
        Ok(Self {
            conn: Mutex::new(conn),
        })
    }

    pub fn create(&self, input: CreateWebhookInput) -> Result<WebhookRecord> {
        let conn = self.lock_conn();

        let webhook_id = format!("whk_{}", Uuid::now_v7());
        let created_at = Utc::now().to_rfc3339_opts(SecondsFormat::Nanos, true);
        let enabled = input.enabled.unwrap_or(true);

        conn.execute(
            "INSERT INTO webhooks (webhook_id, url, events, secret, enabled, created_at, metadata) VALUES (?,?,?,?,?,?,?)",
            params![
                webhook_id,
                input.url,
                serde_json::to_string(&input.events)?,
                input.secret,
                if enabled { 1 } else { 0 },
                created_at,
                input.metadata.as_ref().and_then(|v| serde_json::to_string(v).ok()),
            ],
        )?;

        Ok(WebhookRecord {
            webhook_id,
            url: input.url,
            events: input.events,
            enabled,
            created_at,
            metadata: input.metadata,
        })
    }

    pub fn get(&self, webhook_id: &str) -> Result<Option<WebhookRecord>> {
        let conn = self.lock_conn();
        let mut stmt = conn.prepare(
            "SELECT webhook_id, url, events, enabled, created_at, metadata FROM webhooks WHERE webhook_id = ?",
        )?;
        let row = stmt
            .query_row(params![webhook_id], |row| {
                let events_raw: String = row.get(2)?;
                let meta_raw: Option<String> = row.get(5)?;
                Ok(WebhookRecord {
                    webhook_id: row.get(0)?,
                    url: row.get(1)?,
                    events: serde_json::from_str(&events_raw).unwrap_or_default(),
                    enabled: row.get::<_, i64>(3)? != 0,
                    created_at: row.get(4)?,
                    metadata: meta_raw.and_then(|s| serde_json::from_str(&s).ok()),
                })
            })
            .optional()?;
        Ok(row)
    }

    pub fn list(&self, limit: Option<usize>, offset: Option<usize>) -> Result<Vec<WebhookRecord>> {
        let conn = self.lock_conn();
        let limit = limit.unwrap_or(50).min(100);
        let offset = offset.unwrap_or(0);
        let mut stmt = conn.prepare(
            "SELECT webhook_id, url, events, enabled, created_at, metadata FROM webhooks ORDER BY created_at DESC LIMIT ? OFFSET ?",
        )?;
        let rows = stmt.query_map(params![limit as i64, offset as i64], |row| {
            let events_raw: String = row.get(2)?;
            let meta_raw: Option<String> = row.get(5)?;
            Ok(WebhookRecord {
                webhook_id: row.get(0)?,
                url: row.get(1)?,
                events: serde_json::from_str(&events_raw).unwrap_or_default(),
                enabled: row.get::<_, i64>(3)? != 0,
                created_at: row.get(4)?,
                metadata: meta_raw.and_then(|s| serde_json::from_str(&s).ok()),
            })
        })?;
        Ok(rows.collect::<std::result::Result<Vec<_>, _>>()?)
    }

    pub fn update(&self, webhook_id: &str, input: UpdateWebhookInput) -> Result<Option<WebhookRecord>> {
        let existing = self.get(webhook_id)?;
        let Some(existing) = existing else {
            return Ok(None);
        };

        let conn = self.lock_conn();

        let url = input.url.unwrap_or(existing.url);
        let events = input.events.unwrap_or(existing.events);
        let enabled = input.enabled.unwrap_or(existing.enabled);
        let metadata = input.metadata.or(existing.metadata);

        if let Some(secret) = input.secret.as_ref() {
            conn.execute(
                "UPDATE webhooks SET url = ?, events = ?, secret = ?, enabled = ?, metadata = ? WHERE webhook_id = ?",
                params![
                    url,
                    serde_json::to_string(&events)?,
                    secret,
                    if enabled { 1 } else { 0 },
                    metadata.as_ref().and_then(|v| serde_json::to_string(v).ok()),
                    webhook_id,
                ],
            )?;
        } else {
            conn.execute(
                "UPDATE webhooks SET url = ?, events = ?, enabled = ?, metadata = ? WHERE webhook_id = ?",
                params![
                    url,
                    serde_json::to_string(&events)?,
                    if enabled { 1 } else { 0 },
                    metadata.as_ref().and_then(|v| serde_json::to_string(v).ok()),
                    webhook_id,
                ],
            )?;
        }

        Ok(Some(WebhookRecord {
            webhook_id: webhook_id.to_string(),
            url,
            events,
            enabled,
            created_at: existing.created_at,
            metadata,
        }))
    }

    pub fn delete(&self, webhook_id: &str) -> Result<bool> {
        let conn = self.lock_conn();
        let n = conn.execute("DELETE FROM webhooks WHERE webhook_id = ?", params![webhook_id])?;
        Ok(n > 0)
    }

    pub fn list_enabled_for_event(&self, event: &str) -> Result<Vec<WebhookDeliveryTarget>> {
        let conn = self.lock_conn();
        let mut stmt = conn.prepare(
            "SELECT webhook_id, url, events, secret, enabled FROM webhooks WHERE enabled = 1",
        )?;
        let rows = stmt.query_map([], |row| {
            let events_raw: String = row.get(2)?;
            Ok(WebhookDeliveryTarget {
                webhook_id: row.get(0)?,
                url: row.get(1)?,
                events: serde_json::from_str(&events_raw).unwrap_or_default(),
                secret: row.get(3)?,
                enabled: row.get::<_, i64>(4)? != 0,
            })
        })?;

        let mut out = Vec::new();
        for r in rows {
            let r = r?;
            if r.events.iter().any(|e| e == event) {
                out.push(r);
            }
        }
        Ok(out)
    }
}
