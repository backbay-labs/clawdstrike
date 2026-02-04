//! Shared application state for the daemon

use std::sync::Arc;
use tokio::sync::{broadcast, Notify, RwLock};

use clawdstrike::{HushEngine, Policy, RuleSet};
use hush_core::Keypair;

use crate::audit::{AuditEvent, AuditLedger};
use crate::auth::AuthStore;
use crate::config::Config;
use crate::control_db::ControlDb;
use crate::identity::oidc::OidcValidator;
use crate::metrics::Metrics;
use crate::policy_engine_cache::PolicyEngineCache;
use crate::policy_scoping::{PolicyResolver, SqlitePolicyScopingStore};
use crate::remote_extends::{RemoteExtendsResolverConfig, RemotePolicyResolver};
use crate::rate_limit::RateLimitState;
use crate::rbac::{RbacManager, SqliteRbacStore};
use crate::session::{SessionManager, SqliteSessionStore};

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
    /// API key authentication store
    pub auth_store: Arc<AuthStore>,
    /// Optional OIDC validator (JWT authentication)
    pub oidc: Option<Arc<OidcValidator>>,
    /// Session manager (identity-aware sessions)
    pub sessions: Arc<SessionManager>,
    /// RBAC manager (authorization for user principals)
    pub rbac: Arc<RbacManager>,
    /// Policy resolver (identity-based policy scoping)
    pub policy_resolver: Arc<PolicyResolver>,
    /// Cache of compiled engines for resolved policies
    pub policy_engine_cache: Arc<PolicyEngineCache>,
    /// Session ID
    pub session_id: String,
    /// Start time
    pub started_at: chrono::DateTime<chrono::Utc>,
    /// Rate limiter state
    pub rate_limit: RateLimitState,
    /// Metrics
    pub metrics: Arc<Metrics>,
    /// Shutdown notifier (used for API-triggered shutdown)
    pub shutdown: Arc<Notify>,
}

impl AppState {
    fn load_policy_from_config(config: &Config) -> anyhow::Result<Policy> {
        if let Some(ref path) = config.policy_path {
            let content = std::fs::read_to_string(path)?;
            let resolver = RemotePolicyResolver::new(RemoteExtendsResolverConfig::from_config(
                &config.remote_extends,
            ))?;
            return Ok(Policy::from_yaml_with_extends_resolver(
                &content,
                Some(path.as_path()),
                &resolver,
            )?);
        }

        Ok(RuleSet::by_name(&config.ruleset)?
            .ok_or_else(|| anyhow::anyhow!("Unknown ruleset: {}", config.ruleset))?
            .policy)
    }

    /// Create new application state
    pub async fn new(config: Config) -> anyhow::Result<Self> {
        let metrics = Arc::new(Metrics::default());

        // Load policy
        let policy = Self::load_policy_from_config(&config)?;

        // Create engine (fail closed if custom guards are requested but unavailable)
        let mut engine = HushEngine::builder(policy).build()?;

        // Load signing key
        if let Some(ref key_path) = config.signing_key {
            let key_hex = std::fs::read_to_string(key_path)?.trim().to_string();
            let keypair = Keypair::from_hex(&key_hex)?;
            engine = engine.with_keypair(keypair);
            tracing::info!(path = %key_path.display(), "Loaded signing key");
        } else {
            engine = engine.with_generated_keypair();
            tracing::warn!(
                "Using ephemeral keypair (receipts won't be verifiable across restarts)"
            );
        }

        // Create audit ledger
        let ledger = AuditLedger::new(&config.audit_db)?;
        let ledger = if config.max_audit_entries > 0 {
            ledger.with_max_entries(config.max_audit_entries)
        } else {
            ledger
        };

        // Create control-plane DB (sessions/RBAC/scoped policies).
        let control_path = config.control_db.clone().unwrap_or_else(|| config.audit_db.clone());
        let control_db = Arc::new(ControlDb::new(control_path)?);

        // Create policy resolver (scoped policies).
        let policy_store = Arc::new(SqlitePolicyScopingStore::new(control_db.clone()));
        let policy_resolver = Arc::new(PolicyResolver::new(
            policy_store,
            Arc::new(config.policy_scoping.clone()),
            None,
        ));

        // Cache of compiled policy engines (resolved policy hash -> HushEngine).
        let policy_engine_cache = Arc::new(PolicyEngineCache::from_config(&config.policy_scoping.cache));

        // Create RBAC manager and seed builtin roles.
        let rbac_store = Arc::new(SqliteRbacStore::new(control_db.clone()));
        let rbac_config = Arc::new(config.rbac.clone());
        let rbac = Arc::new(RbacManager::new(rbac_store, rbac_config)?);
        rbac.seed_builtin_roles()?;

        // Create session manager (SQLite baseline; in-memory is used in unit tests).
        let session_store = Arc::new(SqliteSessionStore::new(control_db.clone()));
        let default_ttl_seconds = engine.policy().settings.effective_session_timeout_secs();
        let sessions = Arc::new(SessionManager::new(
            session_store,
            default_ttl_seconds,
            86_400,
            Some(rbac.clone()),
        ));

        // Create event channel
        let (event_tx, _) = broadcast::channel(1024);

        // Load auth store from config
        let auth_store = Arc::new(config.load_auth_store().await?);
        if config.auth.enabled {
            tracing::info!(key_count = auth_store.key_count().await, "Auth enabled");
        }

        // Build OIDC validator (optional).
        let oidc = match (&config.auth.enabled, config.identity.oidc.clone()) {
            (true, Some(oidc_cfg)) => {
                let validator = OidcValidator::from_config(oidc_cfg, Some(control_db.clone())).await?;
                tracing::info!(issuer = %validator.issuer(), "OIDC enabled");
                Some(Arc::new(validator))
            }
            _ => None,
        };

        // Create rate limiter state
        let rate_limit = RateLimitState::new(&config.rate_limit, metrics.clone());
        if config.rate_limit.enabled {
            tracing::info!(
                requests_per_second = config.rate_limit.requests_per_second,
                burst_size = config.rate_limit.burst_size,
                "Rate limiting enabled"
            );
        }

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
            auth_store,
            oidc,
            sessions,
            rbac,
            policy_resolver,
            policy_engine_cache,
            session_id,
            started_at: chrono::Utc::now(),
            rate_limit,
            metrics,
            shutdown: Arc::new(Notify::new()),
        })
    }

    /// Broadcast an event
    pub fn broadcast(&self, event: DaemonEvent) {
        // Ignore send errors (no subscribers)
        let _ = self.event_tx.send(event);
    }

    /// Request graceful shutdown of the daemon.
    pub fn request_shutdown(&self) {
        self.shutdown.notify_one();
    }

    /// Reload policy from config
    pub async fn reload_policy(&self) -> anyhow::Result<()> {
        let policy = Self::load_policy_from_config(&self.config)?;

        // Preserve the existing signing keypair to keep receipts verifiable across reloads.
        let mut engine = self.engine.write().await;
        let keypair = if let Some(ref key_path) = self.config.signing_key {
            let key_hex = std::fs::read_to_string(key_path)?.trim().to_string();
            Some(Keypair::from_hex(&key_hex)?)
        } else {
            engine.keypair().cloned()
        };

        let mut new_engine = HushEngine::builder(policy).build()?;
        new_engine = match keypair {
            Some(keypair) => new_engine.with_keypair(keypair),
            None => new_engine.with_generated_keypair(),
        };
        *engine = new_engine;
        self.policy_engine_cache.clear();

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

    /// Check if authentication is enabled
    pub fn auth_enabled(&self) -> bool {
        self.config.auth.enabled
    }
}
