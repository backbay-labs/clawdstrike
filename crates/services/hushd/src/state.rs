//! Shared application state for the daemon

use std::sync::Arc;
use tokio::sync::{broadcast, Mutex, Notify, RwLock};

use clawdstrike::{HushEngine, Policy, RuleSet};
use hush_certification::audit::AuditLedgerV2;
use hush_certification::certification::{IssuerConfig, SqliteCertificationStore};
use hush_certification::evidence::SqliteEvidenceExportStore;
use hush_certification::webhooks::SqliteWebhookStore;
use hush_core::{Keypair, PublicKey};
use hush_multi_agent::InMemoryRevocationStore;

use crate::api::presence::{PresenceHub, PresenceTicketStore};
use crate::audit::forward::AuditForwarder;
use crate::audit::{AuditEvent, AuditLedger};
use crate::auth::AuthStore;
use crate::broker_state::BrokerStateStore;
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
use crate::spine_publisher::SpinePublisher;
use crate::v1_rate_limit::V1RateLimitState;

#[derive(Clone, Debug)]
pub struct DaemonEvent {
    pub event_type: String,
    pub data: serde_json::Value,
}

#[derive(Clone)]
pub struct AppState {
    pub engine: Arc<RwLock<HushEngine>>,
    pub ledger: Arc<AuditLedger>,
    pub audit_v2: Arc<AuditLedgerV2>,
    pub audit_forwarder: Option<AuditForwarder>,
    pub metrics: Arc<Metrics>,
    pub certification_store: Arc<SqliteCertificationStore>,
    pub evidence_exports: Arc<SqliteEvidenceExportStore>,
    pub webhook_store: Arc<SqliteWebhookStore>,
    pub evidence_dir: std::path::PathBuf,
    pub issuer: IssuerConfig,
    pub event_tx: broadcast::Sender<DaemonEvent>,
    pub security_event_tx: broadcast::Sender<SecurityEvent>,
    pub security_ctx: Arc<RwLock<SecurityEventContext>>,
    pub config: Arc<Config>,
    pub control_db: Arc<ControlDb>,
    pub auth_store: Arc<AuthStore>,
    pub oidc: Option<Arc<OidcValidator>>,
    pub sessions: Arc<SessionManager>,
    pub rbac: Arc<RbacManager>,
    pub policy_resolver: Arc<PolicyResolver>,
    pub policy_engine_cache: Arc<PolicyEngineCache>,
    pub policy_bundle_trusted_keys: Arc<Vec<PublicKey>>,
    pub session_id: String,
    pub started_at: chrono::DateTime<chrono::Utc>,
    pub rate_limit: RateLimitState,
    pub v1_rate_limit: V1RateLimitState,
    pub identity_rate_limiter: Arc<IdentityRateLimiter>,
    pub threat_intel_state: Option<Arc<RwLock<ThreatIntelState>>>,
    pub threat_intel_task: Arc<Mutex<Option<tokio::task::JoinHandle<()>>>>,
    pub siem_exporters: Arc<RwLock<Vec<ExporterStatusHandle>>>,
    pub siem_manager: Arc<Mutex<Option<ExporterManager>>>,
    pub spine_publisher: Option<Arc<SpinePublisher>>,
    pub presence_hub: Arc<PresenceHub>,
    pub presence_ticket_store: Arc<PresenceTicketStore>,
    pub shutdown: Arc<Notify>,
    pub broker_state: Arc<BrokerStateStore>,
    /// Without this, each call to `resolve_delegation_lineage` would create a
    /// fresh empty store, silently accepting revoked tokens.
    pub delegation_revocations: Arc<InMemoryRevocationStore>,
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

    pub async fn new(config: Config) -> anyhow::Result<Self> {
        let policy = Self::load_policy_from_config(&config)?;
        let mut engine = HushEngine::builder(policy).build()?;

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

        let mut ledger = AuditLedger::new(&config.audit_db)?;
        if let Some(key) = config.audit_encryption_key()? {
            ledger = ledger.with_encryption_key(key)?;
            tracing::info!("Audit encryption enabled");
        }
        if config.max_audit_entries > 0 {
            ledger = ledger.with_max_entries(config.max_audit_entries);
        }
        let ledger = Arc::new(ledger);

        let audit_v2 = Arc::new(AuditLedgerV2::new(&config.audit_db)?);
        let certification_store = Arc::new(SqliteCertificationStore::new(&config.audit_db)?);
        let evidence_exports = Arc::new(SqliteEvidenceExportStore::new(&config.audit_db)?);
        let webhook_store = Arc::new(SqliteWebhookStore::new(&config.audit_db)?);
        let evidence_dir = config
            .audit_db
            .parent()
            .unwrap_or_else(|| std::path::Path::new("."))
            .join("evidence_exports");
        let issuer = IssuerConfig::default();

        let audit_forward_config = config.audit_forward.resolve_env_refs()?;
        let audit_forwarder = AuditForwarder::from_config(&audit_forward_config)?;

        let control_path = config
            .control_db
            .clone()
            .unwrap_or_else(|| config.audit_db.clone());
        let control_db = Arc::new(ControlDb::new(control_path)?);
        let identity_rate_limiter = Arc::new(IdentityRateLimiter::new(
            control_db.clone(),
            config.rate_limit.identity.clone(),
        ));

        let policy_store = Arc::new(SqlitePolicyScopingStore::new(control_db.clone()));
        let policy_resolver = Arc::new(PolicyResolver::new(
            policy_store,
            Arc::new(config.policy_scoping.clone()),
            None,
        ));

        let policy_engine_cache =
            Arc::new(PolicyEngineCache::from_config(&config.policy_scoping.cache));

        let rbac_store = Arc::new(SqliteRbacStore::new(control_db.clone()));
        let rbac_config = Arc::new(config.rbac.clone());
        let rbac = Arc::new(RbacManager::new(rbac_store, rbac_config)?);
        rbac.seed_builtin_roles()?;

        let session_store = Arc::new(SqliteSessionStore::new(control_db.clone()));
        let default_ttl_seconds = engine.policy().settings.effective_session_timeout_secs();
        let sessions = Arc::new(SessionManager::new(
            session_store,
            default_ttl_seconds,
            86_400,
            Some(rbac.clone()),
            config.session.clone(),
        ));

        let (event_tx, _) = broadcast::channel(1024);
        let (security_event_tx, _) = broadcast::channel(1024);

        let metrics = Arc::new(Metrics::default());

        let auth_store = Arc::new(config.load_auth_store().await?);
        if config.auth.enabled {
            tracing::info!(key_count = auth_store.key_count().await, "Auth enabled");
        }

        let oidc = match (&config.auth.enabled, config.identity.oidc.clone()) {
            (true, Some(oidc_cfg)) => {
                let validator =
                    OidcValidator::from_config(oidc_cfg, Some(control_db.clone())).await?;
                tracing::info!(issuer = %validator.issuer(), "OIDC enabled");
                Some(Arc::new(validator))
            }
            _ => None,
        };

        let policy_bundle_trusted_keys = Arc::new(config.load_trusted_policy_bundle_keys()?);
        if !policy_bundle_trusted_keys.is_empty() {
            tracing::info!(
                key_count = policy_bundle_trusted_keys.len(),
                "Loaded trusted policy bundle keys"
            );
        }

        let spine_publisher = {
            let signing_kp = engine.keypair().cloned().unwrap_or_else(Keypair::generate);
            match crate::spine_publisher::init_spine_publisher(&config.spine, &signing_kp).await {
                Ok(publisher) => publisher,
                Err(e) => {
                    tracing::warn!(error = %e, "Failed to initialize Spine publisher, continuing without it");
                    None
                }
            }
        };

        let rate_limit = RateLimitState::new(&config.rate_limit, metrics.clone());
        if config.rate_limit.enabled {
            tracing::info!(
                requests_per_second = config.rate_limit.requests_per_second,
                burst_size = config.rate_limit.burst_size,
                "Rate limiting enabled"
            );
        }

        let v1_rate_limit = V1RateLimitState::default();

        let session_id = uuid::Uuid::new_v4().to_string();

        let mut base_security_ctx = SecurityEventContext::hushd(session_id.clone());
        base_security_ctx.policy_hash = engine.policy_hash().ok().map(|h| h.to_hex_prefixed());
        base_security_ctx.ruleset = Some(engine.policy().name.clone());
        if config.siem.enabled {
            base_security_ctx.environment = config.siem.environment.clone();
            base_security_ctx.tenant_id = config.siem.tenant_id.clone();
            base_security_ctx.labels.extend(config.siem.labels.clone());
        }
        let security_ctx = Arc::new(RwLock::new(base_security_ctx));

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

        let (presence_hub, _presence_rx) = PresenceHub::new();
        let presence_hub = Arc::new(presence_hub);
        let presence_ticket_store = Arc::new(PresenceTicketStore::new());

        let shutdown = Arc::new(Notify::new());

        // Spawn the heartbeat reaper for presence tracking
        {
            let hub_for_reaper = presence_hub.clone();
            let shutdown_for_reaper = shutdown.clone();
            tokio::spawn(async move {
                crate::api::presence::spawn_heartbeat_reaper(hub_for_reaper, shutdown_for_reaper)
                    .await;
            });
        }

        let state = Self {
            engine: Arc::new(RwLock::new(engine)),
            ledger,
            audit_v2,
            audit_forwarder,
            metrics,
            certification_store,
            evidence_exports,
            webhook_store,
            evidence_dir,
            issuer,
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
            v1_rate_limit,
            identity_rate_limiter,
            threat_intel_state,
            threat_intel_task: Arc::new(Mutex::new(threat_intel_task)),
            siem_exporters: Arc::new(RwLock::new(siem_exporters)),
            siem_manager: Arc::new(Mutex::new(siem_manager)),
            spine_publisher,
            presence_hub,
            presence_ticket_store,
            shutdown,
            broker_state: Arc::new(BrokerStateStore::new()),
            delegation_revocations: Arc::new(InMemoryRevocationStore::default()),
        };

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

    pub fn broadcast(&self, event: DaemonEvent) {
        let _ = self.event_tx.send(event);
    }

    pub fn emit_security_event(&self, event: SecurityEvent) {
        let mut event = event;
        if self.config.siem.enabled {
            apply_siem_privacy(&mut event, &self.config.siem.privacy);
        }
        let _ = self.security_event_tx.send(event);
    }

    pub fn request_shutdown(&self) {
        self.shutdown.notify_waiters();
    }

    /// Record an audit event to the local ledger and optionally forward it to external sinks.
    ///
    /// This synchronous variant is kept for fire-and-forget usage (e.g. session start/end).
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

    pub async fn record_audit_event_async(&self, event: AuditEvent) {
        self.metrics.inc_audit_event();
        if let Err(err) = self.ledger.record_async(event.clone()).await {
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

    pub fn uptime_secs(&self) -> i64 {
        (chrono::Utc::now() - self.started_at).num_seconds()
    }

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

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn request_shutdown_wakes_all_waiters() {
        let temp_dir = tempfile::tempdir().expect("tempdir");
        let config = crate::config::Config {
            cors_enabled: false,
            audit_db: temp_dir.path().join("audit.db"),
            control_db: Some(temp_dir.path().join("control.db")),
            ..Default::default()
        };
        let state = AppState::new(config).await.expect("state");

        let waiter_one = {
            let shutdown = state.shutdown.clone();
            tokio::spawn(async move { shutdown.notified().await })
        };
        let waiter_two = {
            let shutdown = state.shutdown.clone();
            tokio::spawn(async move { shutdown.notified().await })
        };

        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        state.request_shutdown();

        tokio::time::timeout(std::time::Duration::from_secs(1), waiter_one)
            .await
            .expect("waiter one timeout")
            .expect("waiter one join");
        tokio::time::timeout(std::time::Duration::from_secs(1), waiter_two)
            .await
            .expect("waiter two timeout")
            .expect("waiter two join");
    }
}
