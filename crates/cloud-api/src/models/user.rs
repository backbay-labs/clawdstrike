use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::row::Row;
use uuid::Uuid;

use crate::db::PgRow;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct User {
    pub id: Uuid,
    pub tenant_id: Uuid,
    pub email: String,
    pub name: String,
    pub role: String,
    pub auth_provider: String,
    pub auth_provider_id: Option<String>,
    pub last_login_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
}

impl User {
    pub fn from_row(row: PgRow) -> Result<Self, sqlx::error::Error> {
        Ok(Self {
            id: row.try_get("id")?,
            tenant_id: row.try_get("tenant_id")?,
            email: row.try_get("email")?,
            name: row.try_get("name")?,
            role: row.try_get("role")?,
            auth_provider: row.try_get("auth_provider")?,
            auth_provider_id: row.try_get("auth_provider_id")?,
            last_login_at: row.try_get("last_login_at")?,
            created_at: row.try_get("created_at")?,
        })
    }
}
