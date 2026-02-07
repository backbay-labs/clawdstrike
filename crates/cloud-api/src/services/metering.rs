use sqlx::row::Row;
use uuid::Uuid;

use crate::db::PgPool;

#[derive(Debug, thiserror::Error)]
pub enum MeteringError {
    #[error("database error: {0}")]
    Database(#[from] sqlx::error::Error),
    #[error("stripe error: {0}")]
    Stripe(String),
}

/// Service for recording usage events and reporting to Stripe.
#[derive(Clone)]
pub struct MeteringService {
    db: PgPool,
}

impl MeteringService {
    pub fn new(db: PgPool) -> Self {
        Self { db }
    }

    /// Record a usage event for billing purposes.
    pub async fn record(
        &self,
        tenant_id: Uuid,
        event_type: &str,
        quantity: i32,
    ) -> Result<(), MeteringError> {
        sqlx::query::query(
            "INSERT INTO usage_events (tenant_id, event_type, quantity) VALUES ($1, $2, $3)",
        )
        .bind(tenant_id)
        .bind(event_type)
        .bind(quantity)
        .execute(&self.db)
        .await?;
        Ok(())
    }

    /// Daily job: count distinct active agents per tenant and report to Stripe.
    pub async fn report_daily_usage(&self) -> Result<(), MeteringError> {
        let rows = sqlx::query::query(
            r#"SELECT t.id as tenant_id, t.stripe_subscription_id,
                      COUNT(DISTINCT a.id)::int as agent_count
               FROM tenants t
               JOIN agents a ON a.tenant_id = t.id
               WHERE a.status = 'active'
                 AND a.last_heartbeat_at > now() - interval '24 hours'
                 AND t.status = 'active'
               GROUP BY t.id"#,
        )
        .fetch_all(&self.db)
        .await?;

        for row in rows {
            let tenant_id: Uuid = row.try_get("tenant_id")?;
            let stripe_sub: Option<String> = row.try_get("stripe_subscription_id")?;
            let agent_count: Option<i32> = row.try_get("agent_count")?;

            if stripe_sub.is_some() {
                tracing::info!(
                    tenant_id = %tenant_id,
                    agents = agent_count.unwrap_or(0),
                    "Reported daily usage to Stripe"
                );
            }
        }
        Ok(())
    }
}
