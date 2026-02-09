use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::row::Row;
use uuid::Uuid;

use crate::db::PgRow;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Tenant {
    pub id: Uuid,
    pub name: String,
    pub slug: String,
    pub plan: String,
    pub status: String,
    pub stripe_customer_id: Option<String>,
    pub stripe_subscription_id: Option<String>,
    pub agent_limit: i32,
    pub retention_days: i32,
    pub nats_account_id: Option<String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

impl Tenant {
    pub fn from_row(row: PgRow) -> Result<Self, sqlx::error::Error> {
        Ok(Self {
            id: row.try_get("id")?,
            name: row.try_get("name")?,
            slug: row.try_get("slug")?,
            plan: row.try_get("plan")?,
            status: row.try_get("status")?,
            stripe_customer_id: row.try_get("stripe_customer_id")?,
            stripe_subscription_id: row.try_get("stripe_subscription_id")?,
            agent_limit: row.try_get("agent_limit")?,
            retention_days: row.try_get("retention_days")?,
            nats_account_id: row.try_get("nats_account_id")?,
            created_at: row.try_get("created_at")?,
            updated_at: row.try_get("updated_at")?,
        })
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CreateTenantRequest {
    pub name: String,
    pub slug: String,
    pub plan: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UpdateTenantRequest {
    pub name: Option<String>,
    pub plan: Option<String>,
    pub agent_limit: Option<i32>,
    pub retention_days: Option<i32>,
}
