//! Shared runtime state for the agent API server.
//!
//! `AgentApiServer` is the public entry constructed by `main.rs`. It owns
//! an `Arc<AgentApiState>` which threads through every handler via
//! `State<Arc<AgentApiState>>`. Submodules (`auth`, `daemon_proxy`,
//! `ui_bootstrap`, `rate_limit`) and `crate::edr::handlers::*` reach the
//! same state via re-export through `crate::api_server`.
//!
//! Background tasks (`token_rotation_loop`, control-ack/receipt retry drains,
//! fleet-secret-touch sync loop) clone the `Arc<AgentApiState>` at spawn
//! time; field visibility is `pub(crate)` so those tasks read/write
//! ledgers and limiters without going through accessor methods.

use std::collections::{BTreeSet, HashMap, VecDeque};
use std::future::Future;
use std::path::PathBuf;
use std::pin::Pin;
use std::sync::{Arc, Mutex as StdMutex, RwLock as StdRwLock};
use std::time::Instant;

use anyhow::Result;
use clawdstrike_policy_event::edr::{DetectionFinding, EndpointFlightRecorder};
use tokio::sync::{Mutex, RwLock};

use crate::approval::ApprovalQueue;
use crate::daemon::{AuditQueue, DaemonManager};
use crate::edr::ledger::{
    EndpointControlAckPostbackRetryLedger, EndpointControlArchiveUploadRetryLedger,
    EndpointControlReceiptUploadRetryLedger, EndpointEgressRestrictionLedger,
    EndpointEvidenceBundleStore, EndpointFleetHuntEventOutbox, EndpointHoneyRegistry,
    EndpointPolicyDeltaStore, EndpointReceiptLedger, EndpointResponseAcknowledgementLedger,
    EndpointResponseExecutionLedger, EndpointStagedDetectionLedger,
};
use crate::macos::MacosHostService;
use crate::openclaw::OpenClawManager;
use crate::session::SessionManager;
use crate::settings::Settings;
use crate::telemetry_publisher::TelemetryPublisher;
use crate::updater::HushdUpdater;

use super::constants::POLICY_VERSION_REFRESH_IN_FLIGHT_TIMEOUT;
use super::edr_paths::{
    default_edr_control_ack_postback_retry_ledger, default_edr_control_archive_upload_retry_ledger,
    default_edr_control_receipt_upload_retry_ledger, default_edr_egress_restriction_ledger,
    default_edr_evidence_bundle_store, default_edr_fleet_hunt_event_outbox,
    default_edr_flight_recorder, default_edr_honey_registry,
    default_edr_network_extension_egress_policy_path, default_edr_policy_delta_store,
    default_edr_quarantine_dir, default_edr_receipt_ledger,
    default_edr_response_acknowledgement_ledger, default_edr_response_execution_ledger,
    default_edr_staged_detection_ledger,
};
use super::rate_limit::{ApprovalSubmissionLimiter, RouteRateLimiter};
use super::ui_bootstrap::UiBootstrapSession;

pub type FleetHuntEventPublishFuture<'a> = Pin<Box<dyn Future<Output = Result<()>> + Send + 'a>>;

pub trait FleetHuntEventPublisher: Send + Sync {
    fn agent_id(&self) -> &str;

    fn publish_hunt_event<'a>(&'a self, event_json: &'a [u8]) -> FleetHuntEventPublishFuture<'a>;
}

impl FleetHuntEventPublisher for TelemetryPublisher {
    fn agent_id(&self) -> &str {
        self.agent_id()
    }

    fn publish_hunt_event<'a>(&'a self, event_json: &'a [u8]) -> FleetHuntEventPublishFuture<'a> {
        Box::pin(async move { TelemetryPublisher::publish_hunt_event(self, event_json).await })
    }
}

#[derive(Clone)]
pub struct AgentApiServer {
    pub(super) port: u16,
    pub(super) state: Arc<AgentApiState>,
}

#[derive(Clone)]
pub struct ControlAckPostbackRetrySink {
    pub(crate) state: Arc<AgentApiState>,
}

pub struct ControlAckPostbackRetryRequest {
    pub control_api_url: String,
    pub use_authenticated_route: bool,
    pub response_action_id: String,
    pub target_kind: String,
    pub target_id: String,
    pub ack_token: String,
    pub status: String,
    pub observed_at: chrono::DateTime<chrono::Utc>,
    pub message: Option<String>,
    pub resulting_state: Option<String>,
    pub raw_payload: serde_json::Value,
    pub failure_message: String,
}

#[derive(Clone)]
pub struct AgentApiServerDeps {
    pub settings: Arc<RwLock<Settings>>,
    pub daemon_manager: Arc<DaemonManager>,
    pub session_manager: Arc<SessionManager>,
    pub approval_queue: Arc<ApprovalQueue>,
    pub audit_queue: Arc<AuditQueue>,
    pub macos_host: Arc<MacosHostService>,
    pub openclaw: OpenClawManager,
    pub updater: Arc<HushdUpdater>,
    pub fleet_hunt_publisher: Option<Arc<dyn FleetHuntEventPublisher>>,
    pub auth_token: String,
}

#[derive(Clone)]
pub(crate) struct AgentApiState {
    pub(crate) settings: Arc<RwLock<Settings>>,
    pub(crate) daemon_manager: Arc<DaemonManager>,
    pub(crate) session_manager: Arc<SessionManager>,
    pub(crate) approval_queue: Arc<ApprovalQueue>,
    pub(crate) audit_queue: Arc<AuditQueue>,
    pub(crate) macos_host: Arc<MacosHostService>,
    pub(crate) openclaw: OpenClawManager,
    pub(crate) updater: Arc<HushdUpdater>,
    pub(crate) fleet_hunt_publisher: Option<Arc<dyn FleetHuntEventPublisher>>,
    pub(crate) auth_token: Arc<StdRwLock<String>>,
    pub(crate) previous_auth_token: Arc<StdMutex<Option<PreviousAuthToken>>>,
    pub(crate) token_grace_minutes: Arc<StdRwLock<u32>>,
    pub(crate) http_client: reqwest::Client,
    pub(crate) policy_version_cache: Arc<RwLock<PolicyVersionCache>>,
    pub(crate) approval_rate_limiter: Arc<Mutex<ApprovalSubmissionLimiter>>,
    pub(crate) ui_bootstrap_start_rate_limiter: Arc<Mutex<RouteRateLimiter>>,
    pub(crate) ui_bootstrap_verify_rate_limiter: Arc<Mutex<RouteRateLimiter>>,
    pub(crate) policy_check_rate_limiter: Arc<Mutex<RouteRateLimiter>>,
    pub(crate) integration_test_rate_limiter: Arc<Mutex<RouteRateLimiter>>,
    pub(crate) openclaw_request_rate_limiter: Arc<Mutex<RouteRateLimiter>>,
    pub(crate) ui_bootstrap_sessions: Arc<Mutex<HashMap<String, UiBootstrapSession>>>,
    pub(crate) edr_flight_recorder: Arc<Mutex<EndpointFlightRecorder>>,
    pub(crate) edr_receipt_ledger: Arc<Mutex<EndpointReceiptLedger>>,
    pub(crate) edr_honey_registry: Arc<Mutex<EndpointHoneyRegistry>>,
    pub(crate) edr_evidence_bundle_store: Arc<Mutex<EndpointEvidenceBundleStore>>,
    pub(crate) edr_response_execution_ledger: Arc<Mutex<EndpointResponseExecutionLedger>>,
    pub(crate) edr_response_acknowledgement_ledger: Arc<Mutex<EndpointResponseAcknowledgementLedger>>,
    pub(crate) edr_control_ack_postback_retry_ledger: Arc<Mutex<EndpointControlAckPostbackRetryLedger>>,
    pub(crate) edr_control_archive_upload_retry_ledger: Arc<Mutex<EndpointControlArchiveUploadRetryLedger>>,
    pub(crate) edr_control_receipt_upload_retry_ledger: Arc<Mutex<EndpointControlReceiptUploadRetryLedger>>,
    pub(crate) edr_fleet_hunt_event_outbox: Arc<Mutex<EndpointFleetHuntEventOutbox>>,
    pub(crate) edr_egress_restriction_ledger: Arc<Mutex<EndpointEgressRestrictionLedger>>,
    pub(crate) edr_staged_detection_ledger: Arc<Mutex<EndpointStagedDetectionLedger>>,
    pub(crate) edr_policy_delta_store: Arc<Mutex<EndpointPolicyDeltaStore>>,
    pub(crate) edr_network_extension_egress_policy_path: Arc<PathBuf>,
    pub(crate) edr_quarantine_root: Arc<PathBuf>,
    pub(crate) edr_recent_findings: Arc<Mutex<VecDeque<DetectionFinding>>>,
    pub(crate) edr_auto_published_agent_secret_touch_keys: Arc<Mutex<BTreeSet<String>>>,
}

#[derive(Debug, Default)]
pub(crate) struct PolicyVersionCache {
    pub(crate) value: Option<String>,
    pub(crate) last_refresh_at: Option<std::time::Instant>,
    pub(crate) refresh_in_flight: bool,
    pub(crate) refresh_started_at: Option<std::time::Instant>,
}

impl PolicyVersionCache {
    pub(crate) fn mark_refresh_started_if_due(&mut self, now: std::time::Instant) -> bool {
        if self.refresh_in_flight {
            let stuck = self
                .refresh_started_at
                .map(|started| {
                    now.duration_since(started) >= POLICY_VERSION_REFRESH_IN_FLIGHT_TIMEOUT
                })
                .unwrap_or(true);

            if stuck {
                self.refresh_in_flight = false;
                self.refresh_started_at = None;
            }
        }

        let stale = self
            .last_refresh_at
            .map(|last| now.duration_since(last) >= super::constants::POLICY_VERSION_CACHE_REFRESH_INTERVAL)
            .unwrap_or(true);

        if !stale || self.refresh_in_flight {
            return false;
        }

        self.refresh_in_flight = true;
        self.refresh_started_at = Some(now);
        // Marking last_refresh_at immediately keeps concurrent /health calls from
        // each spawning their own background refresh task.
        self.last_refresh_at = Some(now);
        true
    }

    pub(crate) fn finish_refresh(&mut self, fetched: Option<String>, now: std::time::Instant) {
        if let Some(version) = fetched {
            self.value = Some(version);
        }
        self.last_refresh_at = Some(now);
        self.refresh_in_flight = false;
        self.refresh_started_at = None;
    }
}

#[derive(Debug, Clone)]
pub(crate) struct PreviousAuthToken {
    pub(crate) token: String,
    pub(crate) expires_at: Instant,
}

impl AgentApiServer {
    pub fn new(port: u16, deps: AgentApiServerDeps) -> Self {
        let token_grace_minutes = deps
            .settings
            .try_read()
            .map(|settings| settings.local_api_security.token_grace_minutes.max(1))
            .unwrap_or(15);
        Self {
            port,
            state: Arc::new(AgentApiState {
                settings: deps.settings,
                daemon_manager: deps.daemon_manager,
                session_manager: deps.session_manager,
                approval_queue: deps.approval_queue,
                audit_queue: deps.audit_queue,
                macos_host: deps.macos_host,
                openclaw: deps.openclaw,
                updater: deps.updater,
                fleet_hunt_publisher: deps.fleet_hunt_publisher,
                auth_token: Arc::new(StdRwLock::new(deps.auth_token)),
                previous_auth_token: Arc::new(StdMutex::new(None)),
                token_grace_minutes: Arc::new(StdRwLock::new(token_grace_minutes)),
                http_client: reqwest::Client::new(),
                policy_version_cache: Arc::new(RwLock::new(PolicyVersionCache::default())),
                approval_rate_limiter: Arc::new(Mutex::new(ApprovalSubmissionLimiter::default())),
                ui_bootstrap_start_rate_limiter: Arc::new(Mutex::new(RouteRateLimiter::default())),
                ui_bootstrap_verify_rate_limiter: Arc::new(Mutex::new(RouteRateLimiter::default())),
                policy_check_rate_limiter: Arc::new(Mutex::new(RouteRateLimiter::default())),
                integration_test_rate_limiter: Arc::new(Mutex::new(RouteRateLimiter::default())),
                openclaw_request_rate_limiter: Arc::new(Mutex::new(RouteRateLimiter::default())),
                ui_bootstrap_sessions: Arc::new(Mutex::new(HashMap::new())),
                edr_flight_recorder: Arc::new(Mutex::new(default_edr_flight_recorder())),
                edr_receipt_ledger: Arc::new(Mutex::new(default_edr_receipt_ledger())),
                edr_honey_registry: Arc::new(Mutex::new(default_edr_honey_registry())),
                edr_evidence_bundle_store: Arc::new(
                    Mutex::new(default_edr_evidence_bundle_store()),
                ),
                edr_response_execution_ledger: Arc::new(Mutex::new(
                    default_edr_response_execution_ledger(),
                )),
                edr_response_acknowledgement_ledger: Arc::new(Mutex::new(
                    default_edr_response_acknowledgement_ledger(),
                )),
                edr_control_ack_postback_retry_ledger: Arc::new(Mutex::new(
                    default_edr_control_ack_postback_retry_ledger(),
                )),
                edr_control_archive_upload_retry_ledger: Arc::new(Mutex::new(
                    default_edr_control_archive_upload_retry_ledger(),
                )),
                edr_control_receipt_upload_retry_ledger: Arc::new(Mutex::new(
                    default_edr_control_receipt_upload_retry_ledger(),
                )),
                edr_fleet_hunt_event_outbox: Arc::new(Mutex::new(
                    default_edr_fleet_hunt_event_outbox(),
                )),
                edr_egress_restriction_ledger: Arc::new(Mutex::new(
                    default_edr_egress_restriction_ledger(),
                )),
                edr_staged_detection_ledger: Arc::new(Mutex::new(
                    default_edr_staged_detection_ledger(),
                )),
                edr_policy_delta_store: Arc::new(Mutex::new(default_edr_policy_delta_store())),
                edr_network_extension_egress_policy_path: Arc::new(
                    default_edr_network_extension_egress_policy_path(),
                ),
                edr_quarantine_root: Arc::new(default_edr_quarantine_dir()),
                edr_recent_findings: Arc::new(Mutex::new(VecDeque::new())),
                edr_auto_published_agent_secret_touch_keys: Arc::new(Mutex::new(BTreeSet::new())),
            }),
        }
    }

    pub fn control_ack_postback_retry_sink(&self) -> ControlAckPostbackRetrySink {
        ControlAckPostbackRetrySink {
            state: self.state.clone(),
        }
    }
}
