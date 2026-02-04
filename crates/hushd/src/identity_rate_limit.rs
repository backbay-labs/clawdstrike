//! Identity-based rate limiting (SQLite baseline).

use std::sync::Arc;

use chrono::Utc;
use rusqlite::params;

use crate::config::IdentityRateLimitConfig;
use crate::control_db::ControlDb;

#[derive(Debug, thiserror::Error)]
pub enum IdentityRateLimitError {
    #[error("database error: {0}")]
    Database(#[from] rusqlite::Error),
    #[error("rate limited (retry after {retry_after_secs}s)")]
    RateLimited { retry_after_secs: u64 },
}

pub type Result<T> = std::result::Result<T, IdentityRateLimitError>;

#[derive(Clone)]
pub struct IdentityRateLimiter {
    db: Arc<ControlDb>,
    config: IdentityRateLimitConfig,
}

impl IdentityRateLimiter {
    pub fn new(db: Arc<ControlDb>, config: IdentityRateLimitConfig) -> Self {
        Self { db, config }
    }

    pub fn config(&self) -> &IdentityRateLimitConfig {
        &self.config
    }

    pub fn check_and_increment(
        &self,
        principal: &clawdstrike::IdentityPrincipal,
        action_type: &str,
    ) -> Result<()> {
        if !self.config.enabled {
            return Ok(());
        }

        if !self.config.apply_to_actions.is_empty()
            && !self
                .config
                .apply_to_actions
                .iter()
                .any(|a| a == action_type)
        {
            return Ok(());
        }

        let user_max = self.config.max_requests_per_window_user;
        let org_max = self.config.max_requests_per_window_org;

        // 0 means unlimited.
        if user_max == 0 && org_max == 0 {
            return Ok(());
        }

        let now = Utc::now().timestamp();
        let window_secs = self.config.window_secs.max(1) as i64;
        let cutoff = now.saturating_sub(window_secs);

        let user_key = format!("user:{}:{}", principal.issuer, principal.id);
        let org_key = principal
            .organization_id
            .as_deref()
            .map(|org| format!("org:{org}"));

        let mut conn = self.db.lock_conn();
        let tx = conn.transaction()?;

        // Global cleanup for the sliding window.
        tx.execute(
            "DELETE FROM identity_rate_limit_events WHERE ts < ?1",
            params![cutoff],
        )?;

        let mut denied = false;
        let mut retry_after_secs = 0u64;

        let mut check_key = |identity_key: &str,
                             max: u32|
         -> std::result::Result<(), rusqlite::Error> {
            if max == 0 {
                return Ok(());
            }

            let count: i64 = tx.query_row(
                "SELECT COUNT(*) FROM identity_rate_limit_events WHERE identity_key = ?1 AND ts >= ?2",
                params![identity_key, cutoff],
                |row| row.get(0),
            )?;

            if count >= max as i64 {
                denied = true;
                let oldest: Option<i64> = tx.query_row(
                    "SELECT MIN(ts) FROM identity_rate_limit_events WHERE identity_key = ?1 AND ts >= ?2",
                    params![identity_key, cutoff],
                    |row| row.get(0),
                )?;
                let wait = oldest
                    .map(|oldest| (window_secs - (now - oldest)).max(1) as u64)
                    .unwrap_or(self.config.window_secs.max(1));
                retry_after_secs = retry_after_secs.max(wait);
            }

            Ok(())
        };

        check_key(&user_key, user_max)?;
        if let Some(ref org_key) = org_key {
            check_key(org_key, org_max)?;
        }

        if denied {
            return Err(IdentityRateLimitError::RateLimited { retry_after_secs });
        }

        // Record the event (one row per key).
        tx.execute(
            "INSERT INTO identity_rate_limit_events (identity_key, ts) VALUES (?1, ?2)",
            params![user_key, now],
        )?;
        if let Some(org_key) = org_key {
            tx.execute(
                "INSERT INTO identity_rate_limit_events (identity_key, ts) VALUES (?1, ?2)",
                params![org_key, now],
            )?;
        }

        tx.commit()?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_principal() -> clawdstrike::IdentityPrincipal {
        clawdstrike::IdentityPrincipal {
            id: "user-1".to_string(),
            provider: clawdstrike::IdentityProvider::Oidc,
            issuer: "https://issuer.example".to_string(),
            display_name: None,
            email: None,
            email_verified: None,
            organization_id: Some("org-1".to_string()),
            teams: Vec::new(),
            roles: Vec::new(),
            attributes: std::collections::HashMap::new(),
            authenticated_at: chrono::Utc::now().to_rfc3339(),
            auth_method: None,
            expires_at: None,
        }
    }

    #[test]
    fn disabled_is_noop() {
        let db = Arc::new(ControlDb::in_memory().expect("db"));
        let cfg = IdentityRateLimitConfig {
            enabled: false,
            ..Default::default()
        };
        let limiter = IdentityRateLimiter::new(db, cfg);

        limiter
            .check_and_increment(&test_principal(), "shell")
            .expect("ok");
    }

    #[test]
    fn enforces_user_limit() {
        let db = Arc::new(ControlDb::in_memory().expect("db"));
        let cfg = IdentityRateLimitConfig {
            enabled: true,
            window_secs: 3600,
            max_requests_per_window_user: 2,
            max_requests_per_window_org: 0,
            apply_to_actions: vec!["shell".to_string()],
        };
        let limiter = IdentityRateLimiter::new(db, cfg);

        let principal = test_principal();
        limiter
            .check_and_increment(&principal, "shell")
            .expect("ok");
        limiter
            .check_and_increment(&principal, "shell")
            .expect("ok");
        let err = limiter
            .check_and_increment(&principal, "shell")
            .expect_err("limited");
        match err {
            IdentityRateLimitError::RateLimited { retry_after_secs } => {
                assert!(retry_after_secs >= 1)
            }
            other => panic!("unexpected error: {other:?}"),
        }
    }
}
