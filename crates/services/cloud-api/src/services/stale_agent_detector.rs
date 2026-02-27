//! Background task that detects stale and dead agents.
//!
//! Periodically scans the agents table and marks agents as `stale` (120s without
//! heartbeat) or `dead` (300s without heartbeat).

use std::time::Duration;

use crate::db::PgPool;

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

async fn detect_stale_agents(
    db: &PgPool,
    config: &StaleAgentConfig,
) -> Result<(), sqlx::error::Error> {
    // Mark agents as dead (superset of stale threshold).
    let dead_result = sqlx::query::query(
        r#"UPDATE agents SET status = 'dead'
           WHERE status IN ('active', 'stale')
             AND last_heartbeat_at IS NOT NULL
             AND last_heartbeat_at < now() - make_interval(secs => $1)"#,
    )
    .bind(config.dead_threshold_secs as f64)
    .execute(db)
    .await?;

    if dead_result.rows_affected() > 0 {
        tracing::info!(count = dead_result.rows_affected(), "Marked agents as dead");
    }

    // Mark agents as stale (not yet dead).
    let stale_result = sqlx::query::query(
        r#"UPDATE agents SET status = 'stale'
           WHERE status = 'active'
             AND last_heartbeat_at IS NOT NULL
             AND last_heartbeat_at < now() - make_interval(secs => $1)"#,
    )
    .bind(config.stale_threshold_secs as f64)
    .execute(db)
    .await?;

    if stale_result.rows_affected() > 0 {
        tracing::info!(
            count = stale_result.rows_affected(),
            "Marked agents as stale"
        );
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
}
