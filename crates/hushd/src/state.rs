//! Shared application state for the daemon

use std::sync::Arc;
use tokio::sync::{broadcast, RwLock};

use hush_core::Keypair;
use hushclaw::{HushEngine, Policy, RuleSet};

use crate::audit::{AuditEvent, AuditLedger};
use crate::config::Config;

/// Event broadcast for SSE streaming
#[derive(Clone, Debug)]
pub struct DaemonEvent {
    pub event_type: String,
    pub data: serde_json::Value,
}

/// Shared application state
#[derive(Clone)]
pub struct AppState {
    /// Security engine
    pub engine: Arc<RwLock<HushEngine>>,
    /// Audit ledger
    pub ledger: Arc<AuditLedger>,
    /// Event broadcaster
    pub event_tx: broadcast::Sender<DaemonEvent>,
    /// Configuration
    pub config: Arc<Config>,
    /// Session ID
    pub session_id: String,
    /// Start time
    pub started_at: chrono::DateTime<chrono::Utc>,
}

impl AppState {
    /// Create new application state
    pub fn new(config: Config) -> anyhow::Result<Self> {
        // Load policy
        let policy = if let Some(ref path) = config.policy_path {
            Policy::from_yaml_file(path)?
        } else {
            RuleSet::by_name(&config.ruleset)
                .ok_or_else(|| anyhow::anyhow!("Unknown ruleset: {}", config.ruleset))?
                .policy
        };

        // Create engine
        let mut engine = HushEngine::with_policy(policy);

        // Load signing key
        if let Some(ref key_path) = config.signing_key {
            let key_hex = std::fs::read_to_string(key_path)?.trim().to_string();
            let keypair = Keypair::from_hex(&key_hex)?;
            engine = engine.with_keypair(keypair);
            tracing::info!(path = %key_path.display(), "Loaded signing key");
        } else {
            engine = engine.with_generated_keypair();
            tracing::warn!("Using ephemeral keypair (receipts won't be verifiable across restarts)");
        }

        // Create audit ledger
        let ledger = AuditLedger::new(&config.audit_db)?;
        let ledger = if config.max_audit_entries > 0 {
            ledger.with_max_entries(config.max_audit_entries)
        } else {
            ledger
        };

        // Create event channel
        let (event_tx, _) = broadcast::channel(1024);

        // Generate session ID
        let session_id = uuid::Uuid::new_v4().to_string();

        // Record session start
        let start_event = AuditEvent::session_start(&session_id, None);
        ledger.record(&start_event)?;

        Ok(Self {
            engine: Arc::new(RwLock::new(engine)),
            ledger: Arc::new(ledger),
            event_tx,
            config: Arc::new(config),
            session_id,
            started_at: chrono::Utc::now(),
        })
    }

    /// Broadcast an event
    pub fn broadcast(&self, event: DaemonEvent) {
        // Ignore send errors (no subscribers)
        let _ = self.event_tx.send(event);
    }

    /// Reload policy from config
    pub async fn reload_policy(&self) -> anyhow::Result<()> {
        let policy = if let Some(ref path) = self.config.policy_path {
            Policy::from_yaml_file(path)?
        } else {
            RuleSet::by_name(&self.config.ruleset)
                .ok_or_else(|| anyhow::anyhow!("Unknown ruleset: {}", self.config.ruleset))?
                .policy
        };

        // Get the keypair from current engine
        let mut engine = self.engine.write().await;
        let new_engine = HushEngine::with_policy(policy).with_generated_keypair();
        *engine = new_engine;

        tracing::info!("Policy reloaded");

        self.broadcast(DaemonEvent {
            event_type: "policy_reload".to_string(),
            data: serde_json::json!({"timestamp": chrono::Utc::now().to_rfc3339()}),
        });

        Ok(())
    }

    /// Get daemon uptime in seconds
    pub fn uptime_secs(&self) -> i64 {
        (chrono::Utc::now() - self.started_at).num_seconds()
    }
}
