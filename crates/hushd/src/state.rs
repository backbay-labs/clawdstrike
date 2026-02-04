//! Shared application state for the daemon

use std::sync::Arc;
use tokio::sync::{broadcast, Mutex, Notify, RwLock};

use clawdstrike::{HushEngine, Policy, RuleSet};
use hush_core::Keypair;
use hush_core::PublicKey;

use crate::audit::forward::AuditForwarder;
use crate::audit::{AuditEvent, AuditLedger};
use crate::auth::AuthStore;
use crate::config::{Config, SiemPrivacyConfig};
use crate::control_db::ControlDb;
use crate::identity::oidc::OidcValidator;
use crate::identity_rate_limit::IdentityRateLimiter;
use crate::metrics::Metrics;
use crate::policy_engine_cache::PolicyEngineCache;
use crate::policy_scoping::{PolicyResolver, SqlitePolicyScopingStore};
use crate::rate_limit::RateLimitState;
use crate::rbac::{RbacManager, SqliteRbacStore};
use crate::remote_extends::{RemoteExtendsResolverConfig, RemotePolicyResolver};
use crate::session::{SessionManager, SqliteSessionStore};
use crate::siem::dlq::DeadLetterQueue;
use crate::siem::exporters::alerting::AlertingExporter;
use crate::siem::exporters::datadog::DatadogExporter;
use crate::siem::exporters::elastic::ElasticExporter;
use crate::siem::exporters::splunk::SplunkExporter;
use crate::siem::exporters::sumo_logic::SumoLogicExporter;
use crate::siem::exporters::webhooks::WebhookExporter;
use crate::siem::manager::{
    spawn_exporter_worker, ExporterHandle, ExporterHealth, ExporterManager,
};
use crate::siem::threat_intel::guard::ThreatIntelGuard;
use crate::siem::threat_intel::service::{ThreatIntelService, ThreatIntelState};
use crate::siem::types::{SecurityEvent, SecurityEventContext};

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
    /// Optional audit forwarder (fan-out to external sinks)
    pub audit_forwarder: Option<AuditForwarder>,
    /// Prometheus-style metrics
    pub metrics: Arc<Metrics>,
    /// Event broadcaster
    pub event_tx: broadcast::Sender<DaemonEvent>,
    /// Canonical security event broadcaster (for SIEM/SOAR exporters)
    pub security_event_tx: broadcast::Sender<SecurityEvent>,
    /// Default context for canonical security events
    pub security_ctx: Arc<RwLock<SecurityEventContext>>,
    /// Configuration
    pub config: Arc<Config>,
    /// Control-plane DB (sessions/RBAC/scoped policies, rate limits, ...).
    pub control_db: Arc<ControlDb>,
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
    /// Trusted keys for verifying signed policy bundles
    pub policy_bundle_trusted_keys: Arc<Vec<PublicKey>>,
    /// Session ID
    pub session_id: String,
    /// Start time
    pub started_at: chrono::DateTime<chrono::Utc>,
    /// Rate limiter state
    pub rate_limit: RateLimitState,
    /// Identity-based rate limiter (sliding window, SQLite baseline)
    pub identity_rate_limiter: Arc<IdentityRateLimiter>,
    /// Threat intel state (if enabled)
    pub threat_intel_state: Option<Arc<RwLock<ThreatIntelState>>>,
    /// Threat intel background task (if enabled)
    pub threat_intel_task: Arc<Mutex<Option<tokio::task::JoinHandle<()>>>>,
    /// Exporter health handles (if SIEM is enabled)
    pub siem_exporters: Arc<RwLock<Vec<ExporterStatusHandle>>>,
    /// Exporter manager (fanout task) if SIEM is enabled
    pub siem_manager: Arc<Mutex<Option<ExporterManager>>>,
    /// Shutdown notifier (used for API-triggered shutdown)
    pub shutdown: Arc<Notify>,
}

#[derive(Clone)]
pub struct ExporterStatusHandle {
    pub name: String,
    pub health: Arc<RwLock<ExporterHealth>>,
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
        // Load policy
        let policy = Self::load_policy_from_config(&config)?;

        // Create engine (fail closed if custom guards are requested but unavailable)
        let mut engine = HushEngine::builder(policy).build()?;

        // Optional threat intelligence guard + polling.
        let (threat_intel_state, threat_intel_task) = if config.threat_intel.enabled {
            let state = Arc::new(RwLock::new(ThreatIntelState::default()));
            engine.add_extra_guard(ThreatIntelGuard::new(
                state.clone(),
                config.threat_intel.actions.clone(),
            ));
            let task = ThreatIntelService::new(config.threat_intel.clone(), state.clone()).start();
            (Some(state), Some(task))
        } else {
            (None, None)
        };

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
        let mut ledger = AuditLedger::new(&config.audit_db)?;
        if let Some(key) = config.audit_encryption_key()? {
            ledger = ledger.with_encryption_key(key)?;
            tracing::info!("Audit encryption enabled");
        }
        if config.max_audit_entries > 0 {
            ledger = ledger.with_max_entries(config.max_audit_entries);
        }
        let ledger = Arc::new(ledger);

        // Optional audit forwarding pipeline
        let audit_forward_config = config.audit_forward.resolve_env_refs()?;
        let audit_forwarder = AuditForwarder::from_config(&audit_forward_config)?;

        // Create control-plane DB (sessions/RBAC/scoped policies).
        let control_path = config
            .control_db
            .clone()
            .unwrap_or_else(|| config.audit_db.clone());
        let control_db = Arc::new(ControlDb::new(control_path)?);
        let identity_rate_limiter = Arc::new(IdentityRateLimiter::new(
            control_db.clone(),
            config.rate_limit.identity.clone(),
        ));

        // Create policy resolver (scoped policies).
        let policy_store = Arc::new(SqlitePolicyScopingStore::new(control_db.clone()));
        let policy_resolver = Arc::new(PolicyResolver::new(
            policy_store,
            Arc::new(config.policy_scoping.clone()),
            None,
        ));

        // Cache of compiled policy engines (resolved policy hash -> HushEngine).
        let policy_engine_cache =
            Arc::new(PolicyEngineCache::from_config(&config.policy_scoping.cache));

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
            config.session.clone(),
        ));

        // Create event channels
        let (event_tx, _) = broadcast::channel(1024);
        let (security_event_tx, _) = broadcast::channel(1024);

        let metrics = Arc::new(Metrics::default());

        // Load auth store from config
        let auth_store = Arc::new(config.load_auth_store().await?);
        if config.auth.enabled {
            tracing::info!(key_count = auth_store.key_count().await, "Auth enabled");
        }

        // Build OIDC validator (optional).
        let oidc = match (&config.auth.enabled, config.identity.oidc.clone()) {
            (true, Some(oidc_cfg)) => {
                let validator =
                    OidcValidator::from_config(oidc_cfg, Some(control_db.clone())).await?;
                tracing::info!(issuer = %validator.issuer(), "OIDC enabled");
                Some(Arc::new(validator))
            }
            _ => None,
        };

        // Load trusted policy bundle keys
        let policy_bundle_trusted_keys = Arc::new(config.load_trusted_policy_bundle_keys()?);
        if !policy_bundle_trusted_keys.is_empty() {
            tracing::info!(
                key_count = policy_bundle_trusted_keys.len(),
                "Loaded trusted policy bundle keys"
            );
        }

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

        // Initialize canonical SecurityEvent context.
        let mut base_security_ctx = SecurityEventContext::hushd(session_id.clone());
        base_security_ctx.policy_hash = engine.policy_hash().ok().map(|h| h.to_hex_prefixed());
        base_security_ctx.ruleset = Some(engine.policy().name.clone());
        if config.siem.enabled {
            base_security_ctx.environment = config.siem.environment.clone();
            base_security_ctx.tenant_id = config.siem.tenant_id.clone();
            base_security_ctx.labels.extend(config.siem.labels.clone());
        }
        let security_ctx = Arc::new(RwLock::new(base_security_ctx));

        // Optional SIEM exporters.
        let (siem_exporters, siem_manager): (Vec<ExporterStatusHandle>, Option<ExporterManager>) =
            if config.siem.enabled {
                let mut handles: Vec<ExporterHandle> = Vec::new();
                let mut statuses: Vec<ExporterStatusHandle> = Vec::new();

                let exporters = &config.siem.exporters;

                if let Some(settings) = &exporters.splunk {
                    if settings.enabled {
                        let exporter = SplunkExporter::new(settings.config.clone())
                            .map_err(|e| anyhow::anyhow!("splunk exporter: {e}"))?;
                        let dlq = settings.dlq.clone().map(DeadLetterQueue::new);
                        let handle = spawn_exporter_worker(
                            Box::new(exporter),
                            settings.runtime.clone(),
                            dlq,
                            settings.filter.clone(),
                            settings.queue_capacity,
                        );
                        statuses.push(ExporterStatusHandle {
                            name: handle.name.clone(),
                            health: handle.health.clone(),
                        });
                        handles.push(handle);
                    }
                }

                if let Some(settings) = &exporters.elastic {
                    if settings.enabled {
                        let exporter = ElasticExporter::new(settings.config.clone())
                            .map_err(|e| anyhow::anyhow!("elastic exporter: {e}"))?;
                        let dlq = settings.dlq.clone().map(DeadLetterQueue::new);
                        let handle = spawn_exporter_worker(
                            Box::new(exporter),
                            settings.runtime.clone(),
                            dlq,
                            settings.filter.clone(),
                            settings.queue_capacity,
                        );
                        statuses.push(ExporterStatusHandle {
                            name: handle.name.clone(),
                            health: handle.health.clone(),
                        });
                        handles.push(handle);
                    }
                }

                if let Some(settings) = &exporters.datadog {
                    if settings.enabled {
                        let exporter = DatadogExporter::new(settings.config.clone())
                            .map_err(|e| anyhow::anyhow!("datadog exporter: {e}"))?;
                        let dlq = settings.dlq.clone().map(DeadLetterQueue::new);
                        let handle = spawn_exporter_worker(
                            Box::new(exporter),
                            settings.runtime.clone(),
                            dlq,
                            settings.filter.clone(),
                            settings.queue_capacity,
                        );
                        statuses.push(ExporterStatusHandle {
                            name: handle.name.clone(),
                            health: handle.health.clone(),
                        });
                        handles.push(handle);
                    }
                }

                if let Some(settings) = &exporters.sumo_logic {
                    if settings.enabled {
                        let exporter = SumoLogicExporter::new(settings.config.clone())
                            .map_err(|e| anyhow::anyhow!("sumo exporter: {e}"))?;
                        let dlq = settings.dlq.clone().map(DeadLetterQueue::new);
                        let handle = spawn_exporter_worker(
                            Box::new(exporter),
                            settings.runtime.clone(),
                            dlq,
                            settings.filter.clone(),
                            settings.queue_capacity,
                        );
                        statuses.push(ExporterStatusHandle {
                            name: handle.name.clone(),
                            health: handle.health.clone(),
                        });
                        handles.push(handle);
                    }
                }

                if let Some(settings) = &exporters.alerting {
                    if settings.enabled {
                        let exporter = AlertingExporter::new(settings.config.clone())
                            .map_err(|e| anyhow::anyhow!("alerting exporter: {e}"))?;
                        let dlq = settings.dlq.clone().map(DeadLetterQueue::new);
                        let handle = spawn_exporter_worker(
                            Box::new(exporter),
                            settings.runtime.clone(),
                            dlq,
                            settings.filter.clone(),
                            settings.queue_capacity,
                        );
                        statuses.push(ExporterStatusHandle {
                            name: handle.name.clone(),
                            health: handle.health.clone(),
                        });
                        handles.push(handle);
                    }
                }

                if let Some(settings) = &exporters.webhooks {
                    if settings.enabled {
                        let exporter = WebhookExporter::new(settings.config.clone())
                            .map_err(|e| anyhow::anyhow!("webhooks exporter: {e}"))?;
                        let dlq = settings.dlq.clone().map(DeadLetterQueue::new);
                        let handle = spawn_exporter_worker(
                            Box::new(exporter),
                            settings.runtime.clone(),
                            dlq,
                            settings.filter.clone(),
                            settings.queue_capacity,
                        );
                        statuses.push(ExporterStatusHandle {
                            name: handle.name.clone(),
                            health: handle.health.clone(),
                        });
                        handles.push(handle);
                    }
                }

                let manager = if handles.is_empty() {
                    None
                } else {
                    Some(ExporterManager::start(
                        security_event_tx.subscribe(),
                        handles,
                    ))
                };

                (statuses, manager)
            } else {
                (Vec::new(), None)
            };

        let state = Self {
            engine: Arc::new(RwLock::new(engine)),
            ledger,
            audit_forwarder,
            metrics,
            event_tx,
            security_event_tx,
            security_ctx,
            config: Arc::new(config),
            control_db: control_db.clone(),
            auth_store,
            oidc,
            sessions,
            rbac,
            policy_resolver,
            policy_engine_cache,
            policy_bundle_trusted_keys,
            session_id,
            started_at: chrono::Utc::now(),
            rate_limit,
            identity_rate_limiter,
            threat_intel_state,
            threat_intel_task: Arc::new(Mutex::new(threat_intel_task)),
            siem_exporters: Arc::new(RwLock::new(siem_exporters)),
            siem_manager: Arc::new(Mutex::new(siem_manager)),
            shutdown: Arc::new(Notify::new()),
        };

        // Record session start (after forwarder is initialized).
        let start_event = AuditEvent::session_start(&state.session_id, None);
        {
            let ctx = state.security_ctx.read().await.clone();
            let event = SecurityEvent::from_audit_event(&start_event, &ctx);
            if let Err(err) = event.validate() {
                tracing::warn!(error = %err, "Generated invalid SecurityEvent");
            } else {
                state.emit_security_event(event);
            }
        }
        state.record_audit_event(start_event);

        Ok(state)
    }

    /// Broadcast an event
    pub fn broadcast(&self, event: DaemonEvent) {
        // Ignore send errors (no subscribers)
        let _ = self.event_tx.send(event);
    }

    pub fn emit_security_event(&self, event: SecurityEvent) {
        let mut event = event;
        if self.config.siem.enabled {
            apply_siem_privacy(&mut event, &self.config.siem.privacy);
        }
        let _ = self.security_event_tx.send(event);
    }

    /// Request graceful shutdown of the daemon.
    pub fn request_shutdown(&self) {
        self.shutdown.notify_one();
    }

    /// Record an audit event to the local ledger and optionally forward it to external sinks.
    pub fn record_audit_event(&self, event: AuditEvent) {
        self.metrics.inc_audit_event();
        if let Err(err) = self.ledger.record(&event) {
            self.metrics.inc_audit_write_failure();
            tracing::warn!(error = %err, "Failed to record audit event");
        }
        if let Some(forwarder) = &self.audit_forwarder {
            forwarder.try_enqueue(event);
        }
    }

    pub async fn shutdown_background_tasks(&self) {
        if let Some(manager) = self.siem_manager.lock().await.take() {
            manager.shutdown().await;
        }

        if let Some(task) = self.threat_intel_task.lock().await.take() {
            task.abort();
            let _ = task.await;
        }
    }

    /// Reload policy from config
    pub async fn reload_policy(&self) -> anyhow::Result<()> {
        let policy = Self::load_policy_from_config(self.config.as_ref())?;

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
        let new_policy_hash = new_engine.policy_hash().ok().map(|h| h.to_hex_prefixed());
        let new_ruleset = Some(new_engine.policy().name.clone());
        *engine = new_engine;
        self.policy_engine_cache.clear();

        tracing::info!("Policy reloaded");

        self.record_audit_event(AuditEvent {
            id: uuid::Uuid::new_v4().to_string(),
            timestamp: chrono::Utc::now(),
            event_type: "policy_reload".to_string(),
            action_type: "policy".to_string(),
            target: None,
            decision: "allowed".to_string(),
            guard: None,
            severity: None,
            message: Some("Policy reloaded".to_string()),
            session_id: Some(self.session_id.clone()),
            agent_id: None,
            metadata: Some(serde_json::json!({
                "policy_path": self.config.policy_path.as_ref().map(|p| p.display().to_string()),
                "ruleset": self.config.ruleset.clone(),
            })),
        });

        self.broadcast(DaemonEvent {
            event_type: "policy_reload".to_string(),
            data: serde_json::json!({"timestamp": chrono::Utc::now().to_rfc3339()}),
        });

        {
            let mut ctx = self.security_ctx.write().await;
            ctx.policy_hash = new_policy_hash;
            ctx.ruleset = new_ruleset;
        }

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

fn apply_siem_privacy(event: &mut SecurityEvent, privacy: &SiemPrivacyConfig) {
    if privacy.drop_metadata || privacy.deny_fields.iter().any(|f| f == "metadata") {
        event.metadata = serde_json::json!({});
    }
    if privacy.drop_labels || privacy.deny_fields.iter().any(|f| f == "labels") {
        event.labels.clear();
    }

    let replacement = privacy.redaction_replacement.clone();

    for field in &privacy.deny_fields {
        match field.as_str() {
            "session.user_id" => event.session.user_id = None,
            "session.tenant_id" => event.session.tenant_id = None,
            "session.environment" => event.session.environment = None,
            "decision.policy_hash" => event.decision.policy_hash = None,
            "decision.ruleset" => event.decision.ruleset = None,
            "resource.path" => event.resource.path = None,
            "resource.host" => event.resource.host = None,
            "resource.port" => event.resource.port = None,
            // Required strings: treat "deny" as redaction.
            "decision.reason" => event.decision.reason = replacement.clone(),
            "agent.id" => event.agent.id = replacement.clone(),
            _ => {}
        }
    }

    for field in &privacy.redact_fields {
        match field.as_str() {
            "decision.reason" => event.decision.reason = replacement.clone(),
            "agent.id" => event.agent.id = replacement.clone(),
            "session.id" => event.session.id = replacement.clone(),
            "session.user_id" => {
                event.session.user_id = event.session.user_id.as_ref().map(|_| replacement.clone())
            }
            "session.tenant_id" => {
                event.session.tenant_id = event
                    .session
                    .tenant_id
                    .as_ref()
                    .map(|_| replacement.clone())
            }
            "resource.name" => event.resource.name = replacement.clone(),
            "resource.path" => {
                event.resource.path = event.resource.path.as_ref().map(|_| replacement.clone())
            }
            "resource.host" => {
                event.resource.host = event.resource.host.as_ref().map(|_| replacement.clone())
            }
            "threat.indicator.value" => {
                if let Some(ind) = &mut event.threat.indicator {
                    ind.value = replacement.clone();
                }
            }
            _ => {}
        }
    }
}
