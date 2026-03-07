//! Background task that detects stale and dead agents.
//!
//! Periodically scans the agents table and marks agents as `stale` (120s without
//! heartbeat) or `dead` (300s without heartbeat).

use std::collections::HashSet;
use std::time::Duration;

use crate::db::PgPool;
use sqlx::row::Row;
use sqlx::transaction::Transaction;
use uuid::Uuid;

const DEAD_UPDATE_SQL: &str = r#"UPDATE agents
           SET status = 'dead'
           WHERE status = 'stale'
             AND COALESCE(last_heartbeat_at, created_at) < now() - make_interval(secs => $1)
           RETURNING tenant_id, principal_id"#;

const STALE_UPDATE_SQL: &str = r#"UPDATE agents
           SET status = 'stale'
           WHERE status = 'active'
             AND COALESCE(last_heartbeat_at, created_at) < now() - make_interval(secs => $1)
           RETURNING tenant_id, principal_id"#;

const SYNC_PRINCIPAL_LIVENESS_SQL: &str = r#"UPDATE principals
               SET liveness_state = $3,
                   updated_at = now()
               WHERE tenant_id = $1
                 AND id = $2"#;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct PrincipalLivenessRef {
    tenant_id: Uuid,
    principal_id: Uuid,
}

/// Configuration for the stale agent detector.
#[derive(Debug, Clone)]
pub struct StaleAgentConfig {
    /// Interval between detection runs.
    pub check_interval: Duration,
    /// Seconds without heartbeat before marking as stale.
    pub stale_threshold_secs: i64,
    /// Seconds without heartbeat before marking as dead.
    pub dead_threshold_secs: i64,
}

impl Default for StaleAgentConfig {
    fn default() -> Self {
        Self {
            check_interval: Duration::from_secs(60),
            stale_threshold_secs: 120,
            dead_threshold_secs: 300,
        }
    }
}

/// Runs the stale agent detection loop until the shutdown receiver fires.
pub async fn run(
    db: PgPool,
    config: StaleAgentConfig,
    mut shutdown_rx: tokio::sync::broadcast::Receiver<()>,
) {
    tracing::info!(
        stale_secs = config.stale_threshold_secs,
        dead_secs = config.dead_threshold_secs,
        interval_secs = config.check_interval.as_secs(),
        "Starting stale agent detector"
    );

    loop {
        tokio::select! {
            _ = shutdown_rx.recv() => {
                tracing::info!("Stale agent detector shutting down");
                break;
            }
            _ = tokio::time::sleep(config.check_interval) => {
                if let Err(err) = detect_stale_agents(&db, &config).await {
                    tracing::warn!(error = %err, "Stale agent detection run failed");
                }
            }
        }
    }
}

pub(crate) async fn detect_stale_agents(
    db: &PgPool,
    config: &StaleAgentConfig,
) -> Result<(), sqlx::error::Error> {
    let mut tx = db.begin().await?;

    // Mark previously stale agents as dead.
    // Ordering matters: this runs before the stale transition so agents cannot
    // jump directly from active -> dead within a single detection cycle.
    let dead_rows = sqlx::query::query(DEAD_UPDATE_SQL)
        .bind(config.dead_threshold_secs as f64)
        .fetch_all(tx.as_mut())
        .await?;
    let dead_principal_ids = collect_principal_ids(dead_rows)?;
    sync_principal_liveness_state(&mut tx, &dead_principal_ids, "dead").await?;

    if !dead_principal_ids.is_empty() {
        tracing::info!(count = dead_principal_ids.len(), "Marked agents as dead");
    }

    // Mark active agents as stale. For newly enrolled agents that have not
    // heartbeated yet, created_at serves as a fallback staleness timestamp.
    let stale_rows = sqlx::query::query(STALE_UPDATE_SQL)
        .bind(config.stale_threshold_secs as f64)
        .fetch_all(tx.as_mut())
        .await?;
    let stale_principal_ids = collect_principal_ids(stale_rows)?;
    sync_principal_liveness_state(&mut tx, &stale_principal_ids, "stale").await?;

    tx.commit().await?;

    if !stale_principal_ids.is_empty() {
        tracing::info!(count = stale_principal_ids.len(), "Marked agents as stale");
    }

    Ok(())
}

fn collect_principal_ids(
    rows: Vec<sqlx_postgres::PgRow>,
) -> Result<Vec<PrincipalLivenessRef>, sqlx::error::Error> {
    let mut principal_ids = HashSet::new();
    for row in rows {
        if let Some(principal_id) = row.try_get::<Option<Uuid>, _>("principal_id")? {
            let tenant_id = row.try_get::<Uuid, _>("tenant_id")?;
            principal_ids.insert(PrincipalLivenessRef {
                tenant_id,
                principal_id,
            });
        }
    }

    Ok(principal_ids.into_iter().collect())
}

async fn sync_principal_liveness_state(
    tx: &mut Transaction<'_, sqlx_postgres::Postgres>,
    principal_ids: &[PrincipalLivenessRef],
    liveness_state: &str,
) -> Result<(), sqlx::error::Error> {
    for principal_id in principal_ids {
        sqlx::query::query(SYNC_PRINCIPAL_LIVENESS_SQL)
            .bind(principal_id.tenant_id)
            .bind(principal_id.principal_id)
            .bind(liveness_state)
            .execute(tx.as_mut())
            .await?;
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_config_values() {
        let config = StaleAgentConfig::default();
        assert_eq!(config.stale_threshold_secs, 120);
        assert_eq!(config.dead_threshold_secs, 300);
        assert_eq!(config.check_interval.as_secs(), 60);
    }

    #[test]
    fn queries_enforce_stale_then_dead_lifecycle() {
        assert!(DEAD_UPDATE_SQL.contains("WHERE status = 'stale'"));
        assert!(STALE_UPDATE_SQL.contains("WHERE status = 'active'"));
        assert!(STALE_UPDATE_SQL.contains("COALESCE(last_heartbeat_at, created_at)"));
        assert!(DEAD_UPDATE_SQL.contains("COALESCE(last_heartbeat_at, created_at)"));
        assert!(STALE_UPDATE_SQL.contains("RETURNING tenant_id, principal_id"));
        assert!(DEAD_UPDATE_SQL.contains("RETURNING tenant_id, principal_id"));
    }

    #[test]
    fn principal_liveness_sync_is_tenant_scoped() {
        assert!(SYNC_PRINCIPAL_LIVENESS_SQL.contains("WHERE tenant_id = $1"));
        assert!(SYNC_PRINCIPAL_LIVENESS_SQL.contains("AND id = $2"));
        assert!(SYNC_PRINCIPAL_LIVENESS_SQL.contains("SET liveness_state = $3"));
    }
}
