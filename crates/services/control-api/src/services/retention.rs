use sqlx::row::Row;

use crate::db::PgPool;

#[derive(Debug, thiserror::Error)]
pub enum RetentionError {
    #[error("database error: {0}")]
    Database(#[from] sqlx::error::Error),
}

/// Service for enforcing per-tenant data retention policies.
#[derive(Clone)]
pub struct RetentionService {
    db: PgPool,
}

impl RetentionService {
    pub fn new(db: PgPool) -> Self {
        Self { db }
    }

    /// Delete usage events older than each tenant's retention period.
    pub async fn enforce_retention(&self) -> Result<u64, RetentionError> {
        let rows = sqlx::query::query(
            "SELECT id, slug, retention_days FROM tenants WHERE status = 'active'",
        )
        .fetch_all(&self.db)
        .await?;

        let mut total_deleted = 0u64;
        for row in rows {
            let tenant_id: uuid::Uuid = row.try_get("id")?;
            let slug: String = row.try_get("slug")?;
            let retention_days: i32 = row.try_get("retention_days")?;

            let deleted = sqlx::query::query(
                "DELETE FROM usage_events WHERE tenant_id = $1 AND recorded_at < now() - ($2 || ' days')::interval",
            )
            .bind(tenant_id)
            .bind(retention_days.to_string())
            .execute(&self.db)
            .await?;

            let rows_affected = deleted.rows_affected();
            if rows_affected > 0 {
                tracing::info!(
                    tenant = %slug,
                    retention_days = retention_days,
                    deleted = rows_affected,
                    "Retention enforcement completed"
                );
            }
            total_deleted += rows_affected;
        }

        Ok(total_deleted)
    }
}
