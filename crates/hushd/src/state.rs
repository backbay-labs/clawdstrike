//! Shared application state for the daemon

use std::sync::Arc;
use tokio::sync::{broadcast, Mutex, Notify, RwLock};

use clawdstrike::{HushEngine, Policy, RuleSet};
use hush_core::Keypair;

use crate::audit::{AuditEvent, AuditLedger};
use crate::auth::AuthStore;
use crate::config::{Config, SiemPrivacyConfig};
use crate::rate_limit::RateLimitState;
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
    /// Event broadcaster
    pub event_tx: broadcast::Sender<DaemonEvent>,
    /// Canonical security event broadcaster (for SIEM/SOAR exporters)
    pub security_event_tx: broadcast::Sender<SecurityEvent>,
    /// Default context for canonical security events
    pub security_ctx: Arc<RwLock<SecurityEventContext>>,
    /// Configuration
    pub config: Arc<Config>,
    /// API key authentication store
    pub auth_store: Arc<AuthStore>,
    /// Session ID
    pub session_id: String,
    /// Start time
    pub started_at: chrono::DateTime<chrono::Utc>,
    /// Rate limiter state
    pub rate_limit: RateLimitState,
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
    /// Create new application state
    pub async fn new(config: Config) -> anyhow::Result<Self> {
        // Load policy
        let policy = if let Some(ref path) = config.policy_path {
            Policy::from_yaml_file_with_extends(path)?
        } else {
            RuleSet::by_name(&config.ruleset)?
                .ok_or_else(|| anyhow::anyhow!("Unknown ruleset: {}", config.ruleset))?
                .policy
        };

        // Create engine
        let mut engine = HushEngine::with_policy(policy);

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
        let ledger = AuditLedger::new(&config.audit_db)?;
        let ledger = if config.max_audit_entries > 0 {
            ledger.with_max_entries(config.max_audit_entries)
        } else {
            ledger
        };

        // Create event channels
        let (event_tx, _) = broadcast::channel(1024);
        let (security_event_tx, _) = broadcast::channel(1024);

        // Load auth store from config
        let auth_store = Arc::new(config.load_auth_store().await?);
        if config.auth.enabled {
            tracing::info!(key_count = auth_store.key_count().await, "Auth enabled");
        }

        // Create rate limiter state
        let rate_limit = RateLimitState::new(&config.rate_limit);
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
        let mut security_ctx = SecurityEventContext::hushd(session_id.clone());
        security_ctx.policy_hash = engine.policy_hash().ok().map(|h| h.to_hex_prefixed());
        security_ctx.ruleset = Some(engine.policy().name.clone());
        if config.siem.enabled {
            security_ctx.environment = config.siem.environment.clone();
            security_ctx.tenant_id = config.siem.tenant_id.clone();
            security_ctx.labels.extend(config.siem.labels.clone());
        }
        // Emit a session_start event to the audit ledger and the SecurityEvent bus.
        let start_event = AuditEvent::session_start(&session_id, None);
        ledger.record(&start_event)?;
        let start_security_event = SecurityEvent::from_audit_event(&start_event, &security_ctx);
        let _ = security_event_tx.send(start_security_event);

        let security_ctx = Arc::new(RwLock::new(security_ctx));

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

        Ok(Self {
            engine: Arc::new(RwLock::new(engine)),
            ledger: Arc::new(ledger),
            event_tx,
            security_event_tx,
            security_ctx,
            config: Arc::new(config),
            auth_store,
            session_id,
            started_at: chrono::Utc::now(),
            rate_limit,
            threat_intel_state,
            threat_intel_task: Arc::new(Mutex::new(threat_intel_task)),
            siem_exporters: Arc::new(RwLock::new(siem_exporters)),
            siem_manager: Arc::new(Mutex::new(siem_manager)),
            shutdown: Arc::new(Notify::new()),
        })
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
        let policy = if let Some(ref path) = self.config.policy_path {
            Policy::from_yaml_file_with_extends(path)?
        } else {
            RuleSet::by_name(&self.config.ruleset)?
                .ok_or_else(|| anyhow::anyhow!("Unknown ruleset: {}", self.config.ruleset))?
                .policy
        };

        // Preserve the existing signing keypair to keep receipts verifiable across reloads.
        let mut engine = self.engine.write().await;
        let keypair = if let Some(ref key_path) = self.config.signing_key {
            let key_hex = std::fs::read_to_string(key_path)?.trim().to_string();
            Some(Keypair::from_hex(&key_hex)?)
        } else {
            engine.keypair().cloned()
        };

        let mut new_engine = HushEngine::with_policy(policy);
        new_engine = match keypair {
            Some(keypair) => new_engine.with_keypair(keypair),
            None => new_engine.with_generated_keypair(),
        };
        let new_policy_hash = new_engine.policy_hash().ok().map(|h| h.to_hex_prefixed());
        let new_ruleset = Some(new_engine.policy().name.clone());
        *engine = new_engine;

        tracing::info!("Policy reloaded");

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
