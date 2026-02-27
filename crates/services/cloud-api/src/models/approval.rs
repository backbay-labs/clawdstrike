//! Approval model for cloud-managed approval escalation.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::row::Row;
use uuid::Uuid;

use crate::db::PgRow;

/// A pending or resolved approval request escalated from an agent.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Approval {
    pub id: Uuid,
    pub tenant_id: Uuid,
    pub agent_id: String,
    pub request_id: String,
    pub event_type: String,
    pub event_data: serde_json::Value,
    pub status: String,
    pub resolved_by: Option<String>,
    pub resolved_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
}

impl Approval {
    pub fn from_row(row: PgRow) -> Result<Self, sqlx::error::Error> {
        Ok(Self {
            id: row.try_get("id")?,
            tenant_id: row.try_get("tenant_id")?,
            agent_id: row.try_get("agent_id")?,
            request_id: row.try_get("request_id")?,
            event_type: row.try_get("event_type")?,
            event_data: row.try_get("event_data")?,
            status: row.try_get("status")?,
            resolved_by: row.try_get("resolved_by")?,
            resolved_at: row.try_get("resolved_at")?,
            created_at: row.try_get("created_at")?,
        })
    }
}

/// Input for resolving an approval request.
#[derive(Debug, Deserialize)]
pub struct ResolveApprovalInput {
    pub resolution: String,
    pub resolved_by: Option<String>,
}
