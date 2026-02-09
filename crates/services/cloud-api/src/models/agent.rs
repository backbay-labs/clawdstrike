use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::row::Row;
use uuid::Uuid;

use crate::db::PgRow;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Agent {
    pub id: Uuid,
    pub tenant_id: Uuid,
    pub agent_id: String,
    pub name: String,
    pub public_key: String,
    pub role: String,
    pub trust_level: String,
    pub status: String,
    pub last_heartbeat_at: Option<DateTime<Utc>>,
    pub metadata: Option<serde_json::Value>,
    pub created_at: DateTime<Utc>,
}

impl Agent {
    pub fn from_row(row: PgRow) -> Result<Self, sqlx::error::Error> {
        Ok(Self {
            id: row.try_get("id")?,
            tenant_id: row.try_get("tenant_id")?,
            agent_id: row.try_get("agent_id")?,
            name: row.try_get("name")?,
            public_key: row.try_get("public_key")?,
            role: row.try_get("role")?,
            trust_level: row.try_get("trust_level")?,
            status: row.try_get("status")?,
            last_heartbeat_at: row.try_get("last_heartbeat_at")?,
            metadata: row.try_get("metadata")?,
            created_at: row.try_get("created_at")?,
        })
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RegisterAgentRequest {
    pub agent_id: String,
    pub name: String,
    pub public_key: String,
    pub role: Option<String>,
    pub trust_level: Option<String>,
    pub metadata: Option<serde_json::Value>,
}

#[derive(Debug, Serialize)]
pub struct RegisterAgentResponse {
    pub id: Uuid,
    pub agent_id: String,
    pub nats_credentials: NatsCredentials,
}

#[derive(Debug, Serialize)]
pub struct NatsCredentials {
    pub nats_url: String,
    pub account: String,
    pub subject_prefix: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HeartbeatRequest {
    pub agent_id: String,
    pub status: Option<String>,
    pub metadata: Option<serde_json::Value>,
}
