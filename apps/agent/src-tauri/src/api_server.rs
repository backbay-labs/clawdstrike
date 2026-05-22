//! Authenticated local API server for agent control and OpenClaw transport.

use crate::agent_auth::rotate_local_api_token;
use crate::approval::{
    ApprovalQueue, ApprovalRequestInput, ApprovalResolution, ApprovalResolveInput, ApprovalStatus,
    ApprovalStatusResponse,
};
use crate::daemon::{AuditQueue, DaemonManager, DaemonStatus};
use crate::macos::status::{
    CombinedSystemExtensionStatus, ProviderAvailability, ProviderRuntimeState, ProviderStatus,
    SystemExtensionApproval, SystemExtensionInstallState,
};
use crate::macos::MacosHostService;
use crate::openclaw::{
    GatewayDiscoverInput, GatewayRequestInput, GatewayUpsertRequest, ImportGatewayRequest,
    OpenClawManager,
};
use crate::policy::{evaluate_policy_check, PolicyCheckInput, PolicyCheckOutput};
use crate::runtime_registry::{
    register_runtime_agent, resolve_effective_endpoint_agent_id, RuntimeRegistrationInput,
};
use crate::security::auth::constant_time_eq_token;
use crate::session::{SessionManager, SessionState};
use crate::settings::{IntegrationSettings, RuntimeAgentRegistration, Settings};
use crate::telemetry_publisher::TelemetryPublisher;
use crate::updater::{HushdUpdater, OtaStatus};
use anyhow::{Context, Result};
use axum::body::Body;
use axum::extract::DefaultBodyLimit;
use axum::extract::{Form, Path, Request, State};
use axum::http::header::{
    ACCEPT, AUTHORIZATION, CACHE_CONTROL, CONNECTION, CONTENT_TYPE, COOKIE, LOCATION, SET_COOKIE,
};
use axum::http::{uri::Authority, HeaderMap, HeaderValue, StatusCode, Uri};
use axum::middleware::Next;
use axum::response::sse::{Event, KeepAlive, Sse};
use axum::response::Html;
use axum::response::{IntoResponse, Response};
use axum::routing::{get, patch, post, put};
use axum::{Json, Router};
// Receipt*Input types are used only in `mod tests { use super::* }` below.
#[allow(unused_imports)]
use clawdstrike_policy_event::edr::{
    endpoint_policy_delta_id, endpoint_policy_event_impact_id, endpoint_policy_event_replay_id,
    CausalEdgeKind, CausalGraph, CausalGraphRecorder, CausalNode, CausalNodeKind, CredentialKind,
    DeceptionCleanupReport, DeceptionMaterializationReport, DeceptionPlan, DeceptionRotationReport,
    DetectionFinding, DetectionSeverity, EndpointDeceptionCleanupReceiptInput,
    EndpointDeceptionMaterializationReceiptInput, EndpointDeceptionRotationReceiptInput,
    EndpointDecisionAction, EndpointDecisionActor, EndpointDecisionReceipt,
    EndpointDetectionReceiptInput, EndpointEvent, EndpointEvidenceBundleManifestReceiptInput,
    EndpointEvidenceBundleReference, EndpointEvidenceRedactionClass, EndpointFlightRecorder,
    EndpointFlightRecorderCompactionRecord, EndpointFlightRecorderGraphEdgeIndexEntry,
    EndpointFlightRecorderGraphNodeIndexEntry, EndpointFlightRecorderHistoryIndexEntry,
    EndpointGraphReference, EndpointGraphSliceReceiptInput, EndpointObservation,
    EndpointObservationReceiptInput, EndpointPolicyDecisionReceiptInput,
    EndpointPolicyDeltaIdInput, EndpointPolicyDeltaReceiptInput, EndpointPolicyEventImpactIdInput,
    EndpointPolicyEventImpactReceiptInput, EndpointPolicyEventReplayIdInput,
    EndpointPolicyEventReplayReceiptInput, EndpointPolicySimulationIdentityContext,
    EndpointPolicySimulationReport, EndpointPolicySimulationRule,
    EndpointPolicySimulationToolContext, EndpointPolicySnapshot, EndpointProcess,
    EndpointProviderDegradationReceiptInput, EndpointProviderKind, EndpointProviderState,
    EndpointReceiptEvidence, EndpointResponseAcknowledgementReceiptInput,
    EndpointResponseAcknowledgementReport, EndpointResponseControlCorrelation,
    EndpointResponseExecutionEffect, EndpointResponseExecutionReceiptInput,
    EndpointResponseExecutionReport, EndpointResponseExecutionStatus, EndpointResponsePlan,
    EndpointResponseProcessIdentityBinding, EndpointResponseReceiptInput,
    EndpointResponseRollbackReceiptInput, EndpointResponseRollbackReport, EndpointSensorState,
    EndpointSensorStateReceiptInput, EndpointSimulationImpactLevel, EndpointSimulationReceiptInput,
    EndpointTelemetryPrivacyMode, EndpointTelemetryPrivacyReceiptInput,
    EndpointTelemetryPrivacyReport, FileOperation, HoneyArtifact, PackageManager,
    SupplyChainRuntimeGuard,
};
use clawdstrike_policy_event::event::PolicyEvent;
use clawdstrike_policy_event::simulate::replay_events;
use futures::{Stream, StreamExt, TryStreamExt};
use hush_core::{canonicalize_json, sha256, Keypair, SignedReceipt};
use serde::{Deserialize, Deserializer, Serialize};
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet, HashMap, VecDeque};
use std::fs;
use std::future::Future;
use std::io::{Read as _, Seek as _, SeekFrom};
use std::net::{IpAddr, SocketAddr};
use std::path::{Component, Path as FsPath, PathBuf};
use std::pin::Pin;
use std::sync::{Arc, Mutex as StdMutex, RwLock as StdRwLock};
use std::time::{Duration, Instant};
use tokio::net::TcpListener;
use tokio::sync::{broadcast, Mutex, RwLock};
use tokio_stream::wrappers::BroadcastStream;
use tower_http::services::{ServeDir, ServeFile};

pub(crate) use crate::edr::conversion::*;
pub(crate) use crate::edr::dto::*;
pub(crate) use crate::edr::handlers::*;
pub(crate) use crate::edr::policy_events::*;
pub(crate) use crate::edr::queries::*;
pub(crate) use crate::edr::response::*;

mod policy_delta;
pub(crate) use policy_delta::*;

const HUSHD_AUTHORIZATION_HEADER: &str = "x-hushd-authorization";
const AGENT_AUTH_COOKIE_NAME: &str = "clawdstrike_agent_auth";
const POLICY_VERSION_CACHE_REFRESH_INTERVAL: Duration = Duration::from_secs(5);
const POLICY_VERSION_FETCH_TIMEOUT: Duration = Duration::from_millis(200);
const POLICY_VERSION_REFRESH_IN_FLIGHT_TIMEOUT: Duration = Duration::from_secs(20);
const AGENT_API_MAX_BODY_BYTES: usize = 256 * 1024;
const BROKER_MUTATION_MAX_BODY_BYTES: usize = 2 * 1024 * 1024;
pub(crate) const EDR_MAX_OBSERVATIONS_PER_REQUEST: usize = 10_000;
pub(crate) const EDR_MAX_HONEY_ARTIFACTS_PER_REQUEST: usize = 1_000;
pub(crate) const EDR_MAX_STORED_FINDINGS: usize = 10_000;
pub(crate) const EDR_MAX_CONTROL_ACK_POSTBACK_RETRIES: usize = 1_000;
pub(crate) const EDR_MAX_CONTROL_ARCHIVE_UPLOAD_RETRIES: usize = 1_000;
pub(crate) const EDR_MAX_CONTROL_RECEIPT_UPLOAD_RETRIES: usize = 1_000;
pub(crate) const EDR_MAX_FLEET_HUNT_EVENT_OUTBOX: usize = 1_000;
pub(crate) const EDR_CONTROL_ACK_RETRY_INITIAL_BACKOFF_SECONDS: i64 = 30;
pub(crate) const EDR_CONTROL_ACK_RETRY_MAX_BACKOFF_SECONDS: i64 = 300;
pub(crate) const EDR_CONTROL_ACK_RETRY_DRAIN_INTERVAL: Duration = Duration::from_secs(30);
pub(crate) const EDR_RESPONSE_EXPIRATION_SWEEP_INTERVAL: Duration = Duration::from_secs(30);
pub(crate) const EDR_CONTROL_ACK_RETRY_BACKGROUND_LIMIT: usize = 25;
pub(crate) const EDR_CONTROL_RECEIPT_UPLOAD_BACKGROUND_LIMIT: usize = 25;
pub(crate) const EDR_CONTROL_RECEIPT_UPLOAD_REQUEST_TIMEOUT: Duration = Duration::from_secs(2);
pub(crate) const EDR_CONTROL_ACK_STATUS_ALLOWLIST: &str =
    "acknowledged, rejected, failed, expired, rolled_back";
pub(crate) const EDR_CONTROL_ACK_TARGET_KIND_ALLOWLIST: &str =
    "endpoint, runtime, session, principal, grant, swarm, project";
pub(crate) const EDR_MAX_CAUSAL_SUBGRAPH_DEPTH: usize = 64;
pub(crate) const EDR_DEFAULT_RECEIPT_QUERY_LIMIT: usize = 100;
pub(crate) const EDR_MAX_RECEIPT_QUERY_LIMIT: usize = 1_000;
pub(crate) const EDR_DEFAULT_RESPONSE_TTL_SECONDS: u64 = 600;
pub(crate) const EDR_MAX_RESPONSE_TTL_SECONDS: u64 = 3_600;
pub(crate) const EDR_MAX_RESPONSE_REASON_BYTES: usize = 1024;
pub(crate) const EDR_MAX_RESPONSE_ACTOR_FIELD_BYTES: usize = 256;
pub(crate) const EDR_MAX_RAW_ARTIFACT_APPROVAL_ID_BYTES: usize = 128;
pub(crate) const EDR_MAX_RAW_ARTIFACT_APPROVAL_REASON_BYTES: usize = 1024;
pub(crate) const EDR_RAW_ARTIFACT_UPLOAD_GUARD: &str = "endpoint.telemetry.raw_artifact_upload";
pub(crate) const EDR_DEFAULT_RESPONSE_EXECUTION_QUERY_LIMIT: usize = 100;
pub(crate) const EDR_MAX_RESPONSE_EXECUTION_QUERY_LIMIT: usize = 1_000;
pub(crate) const EDR_NETWORK_EXTENSION_EGRESS_POLICY_SCHEMA_VERSION: u32 = 1;
pub(crate) const EDR_POLICY_DELTA_SCHEMA_VERSION: &str = "clawdstrike.endpoint_policy_delta.v1";
pub(crate) const EDR_DEFAULT_POLICY_EVENT_IMPACT_CAUSAL_DEPTH: usize = 3;
pub(crate) const EDR_MAX_POLICY_EVENT_IMPACT_CONTEXTS: usize = 16;
pub(crate) const EDR_MAX_POLICY_EVENT_IMPACT_CHAINS_PER_CONTEXT: usize = 8;
pub(crate) const EDR_MAX_POLICY_EVENT_IMPACT_CHAIN_DRIVER_SAMPLES: usize = 5;
pub(crate) const EDR_MAX_POLICY_EVENT_IMPACT_PROMOTION_SUGGESTIONS: usize = 16;
pub(crate) const EDR_MAX_POLICY_EVENT_IMPACT_BREAKAGE_DRIVERS: usize = 8;
pub(crate) const EDR_MAX_POLICY_EVENT_IMPACT_VALIDATION_WINDOW_SECONDS: u64 = 86_400;
pub(crate) const EDR_CROSS_WINDOW_PROMOTION_VALIDATION_CACHE_LIMIT: usize = 128;
pub(crate) const EDR_CROSS_WINDOW_PROMOTION_VALIDATION_MAX_AGE_SECONDS: i64 = 86_400;
pub(crate) const EDR_MAX_AUTO_FLEET_AGENT_SECRET_TOUCHES_PER_BATCH: usize = 100;
pub(crate) const EDR_MAX_AUTO_FLEET_HUNT_EVENT_OUTBOX_RETRIES_PER_BATCH: usize = 100;
pub(crate) const EDR_FLEET_AGENT_SECRET_TOUCH_SYNC_INTERVAL: Duration = Duration::from_secs(60);
pub(crate) const EDR_DEFAULT_PROVIDER_ACK_TIMEOUT_MS: u64 = 750;
pub(crate) const EDR_MAX_PROVIDER_ACK_TIMEOUT_MS: u64 = 5_000;
pub(crate) const EDR_PROVIDER_ACK_POLL_INTERVAL: Duration = Duration::from_millis(50);
const APPROVAL_RATE_LIMIT_WINDOW: Duration = Duration::from_secs(60);
const APPROVAL_RATE_LIMIT_BURST_WINDOW: Duration = Duration::from_secs(1);
const APPROVAL_RATE_LIMIT_PER_MINUTE: usize = 30;
const APPROVAL_RATE_LIMIT_BURST: usize = 10;
const ROUTE_RATE_LIMIT_WINDOW: Duration = Duration::from_secs(60);
const ROUTE_RATE_LIMIT_UI_BOOTSTRAP_START: usize = 20;
const ROUTE_RATE_LIMIT_UI_BOOTSTRAP_VERIFY: usize = 60;
const ROUTE_RATE_LIMIT_POLICY_CHECK: usize = 1200;
const ROUTE_RATE_LIMIT_INTEGRATION_TEST: usize = 30;
const ROUTE_RATE_LIMIT_OPENCLAW_REQUEST: usize = 120;
const UI_BOOTSTRAP_TTL: Duration = Duration::from_secs(60);
const UI_BOOTSTRAP_MAX_ATTEMPTS: u8 = 5;
const UI_BOOTSTRAP_MAX_SESSIONS: usize = 32;
const LOCAL_API_TOKEN_ROTATION_MIN_HOURS: u32 = 1;
const LOCAL_API_TOKEN_ROTATION_MAX_HOURS: u32 = 24 * 30;
const LOCAL_API_TOKEN_GRACE_MIN_MINUTES: u32 = 1;
const LOCAL_API_TOKEN_GRACE_MAX_MINUTES: u32 = 120;
const LOCAL_API_MTLS_MIN_PORT: u16 = 1024;
const OTA_CHECK_INTERVAL_MIN_MINUTES: u32 = 5;
const OTA_CHECK_INTERVAL_MAX_MINUTES: u32 = 60 * 24 * 7;

#[derive(Clone)]
pub struct AgentApiServer {
    port: u16,
    state: Arc<AgentApiState>,
}

#[derive(Clone)]
pub struct ControlAckPostbackRetrySink {
    state: Arc<AgentApiState>,
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
    pub(crate) edr_response_acknowledgement_ledger:
        Arc<Mutex<EndpointResponseAcknowledgementLedger>>,
    pub(crate) edr_control_ack_postback_retry_ledger:
        Arc<Mutex<EndpointControlAckPostbackRetryLedger>>,
    pub(crate) edr_control_archive_upload_retry_ledger:
        Arc<Mutex<EndpointControlArchiveUploadRetryLedger>>,
    pub(crate) edr_control_receipt_upload_retry_ledger:
        Arc<Mutex<EndpointControlReceiptUploadRetryLedger>>,
    pub(crate) edr_fleet_hunt_event_outbox: Arc<Mutex<EndpointFleetHuntEventOutbox>>,
    pub(crate) edr_egress_restriction_ledger: Arc<Mutex<EndpointEgressRestrictionLedger>>,
    pub(crate) edr_staged_detection_ledger: Arc<Mutex<EndpointStagedDetectionLedger>>,
    pub(crate) edr_policy_delta_store: Arc<Mutex<EndpointPolicyDeltaStore>>,
    pub(crate) edr_cross_window_promotion_validations:
        Arc<Mutex<VecDeque<EdrCrossWindowPromotionValidation>>>,
    pub(crate) edr_network_extension_egress_policy_path: Arc<PathBuf>,
    pub(crate) edr_quarantine_root: Arc<PathBuf>,
    pub(crate) edr_recent_findings: Arc<Mutex<VecDeque<DetectionFinding>>>,
    pub(crate) edr_auto_published_agent_secret_touch_keys: Arc<Mutex<BTreeSet<String>>>,
}

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

#[derive(Debug, Default)]
pub(crate) struct PolicyVersionCache {
    value: Option<String>,
    last_refresh_at: Option<std::time::Instant>,
    refresh_in_flight: bool,
    refresh_started_at: Option<std::time::Instant>,
}

#[derive(Clone, Debug)]
pub(crate) struct EdrCrossWindowPromotionValidation {
    pub(crate) recorded_at: chrono::DateTime<chrono::Utc>,
    pub(crate) impact_hash: String,
    pub(crate) recommendation_hash: String,
    pub(crate) current_policy_hash: String,
    pub(crate) current_policy_epoch: u64,
    pub(crate) proposed_policy_hash: String,
    pub(crate) proposed_policy_epoch: u64,
    pub(crate) event_stream_hash: String,
    pub(crate) current_result_hash: String,
    pub(crate) proposed_result_hash: String,
    pub(crate) history_selector_hash: String,
    pub(crate) newest_event_at: Option<chrono::DateTime<chrono::Utc>>,
    pub(crate) max_age_seconds: Option<u64>,
    pub(crate) recommended_stage: String,
    pub(crate) root_node_id: String,
    pub(crate) action: EndpointDecisionAction,
    pub(crate) promotion_ready: bool,
}

impl PolicyVersionCache {
    fn mark_refresh_started_if_due(&mut self, now: std::time::Instant) -> bool {
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
            .map(|last| now.duration_since(last) >= POLICY_VERSION_CACHE_REFRESH_INTERVAL)
            .unwrap_or(true);

        if !stale || self.refresh_in_flight {
            return false;
        }

        self.refresh_in_flight = true;
        self.refresh_started_at = Some(now);
        // Mark immediately to avoid concurrent /health calls all spawning refresh tasks.
        self.last_refresh_at = Some(now);
        true
    }

    fn finish_refresh(&mut self, fetched: Option<String>, now: std::time::Instant) {
        if let Some(version) = fetched {
            self.value = Some(version);
        }
        self.last_refresh_at = Some(now);
        self.refresh_in_flight = false;
        self.refresh_started_at = None;
    }
}

#[derive(Debug, Default)]
pub(crate) struct ApprovalSubmissionLimiter {
    minute_events: VecDeque<Instant>,
    burst_events: VecDeque<Instant>,
}

#[derive(Debug, Clone)]
pub(crate) struct UiBootstrapSession {
    code_normalized: String,
    next_path: String,
    created_at: Instant,
    expires_at: Instant,
    attempts: u8,
}

#[derive(Debug, Clone)]
pub(crate) struct PreviousAuthToken {
    token: String,
    expires_at: Instant,
}

#[derive(Debug, Default)]
pub(crate) struct RouteRateLimiter {
    events: VecDeque<Instant>,
}

#[derive(Debug, Deserialize)]
struct UiBootstrapStartInput {
    #[serde(default)]
    next_path: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
struct UiBootstrapStartResponse {
    session_id: String,
    user_code: String,
    expires_in_seconds: u64,
}

#[derive(Debug, Deserialize)]
struct UiBootstrapVerifyInput {
    session_id: String,
    user_code: String,
}

impl ApprovalSubmissionLimiter {
    fn allow_now(&mut self, now: Instant) -> std::result::Result<(), u64> {
        while self
            .minute_events
            .front()
            .is_some_and(|ts| now.duration_since(*ts) >= APPROVAL_RATE_LIMIT_WINDOW)
        {
            let _ = self.minute_events.pop_front();
        }
        while self
            .burst_events
            .front()
            .is_some_and(|ts| now.duration_since(*ts) >= APPROVAL_RATE_LIMIT_BURST_WINDOW)
        {
            let _ = self.burst_events.pop_front();
        }

        if self.minute_events.len() >= APPROVAL_RATE_LIMIT_PER_MINUTE {
            if let Some(oldest) = self.minute_events.front().copied() {
                let retry_after = APPROVAL_RATE_LIMIT_WINDOW
                    .saturating_sub(now.duration_since(oldest))
                    .as_secs()
                    .max(1);
                return Err(retry_after);
            }
            return Err(1);
        }

        if self.burst_events.len() >= APPROVAL_RATE_LIMIT_BURST {
            if let Some(oldest) = self.burst_events.front().copied() {
                let retry_after = APPROVAL_RATE_LIMIT_BURST_WINDOW
                    .saturating_sub(now.duration_since(oldest))
                    .as_secs()
                    .max(1);
                return Err(retry_after);
            }
            return Err(1);
        }

        self.minute_events.push_back(now);
        self.burst_events.push_back(now);
        Ok(())
    }
}

impl RouteRateLimiter {
    fn allow_now(
        &mut self,
        now: Instant,
        window: Duration,
        limit: usize,
    ) -> std::result::Result<(), u64> {
        while self
            .events
            .front()
            .is_some_and(|ts| now.duration_since(*ts) >= window)
        {
            let _ = self.events.pop_front();
        }

        if self.events.len() >= limit {
            if let Some(oldest) = self.events.front().copied() {
                let retry_after = window
                    .saturating_sub(now.duration_since(oldest))
                    .as_secs()
                    .max(1);
                return Err(retry_after);
            }
            return Err(1);
        }

        self.events.push_back(now);
        Ok(())
    }
}

impl AgentApiServer {
    pub fn try_new(port: u16, deps: AgentApiServerDeps) -> Result<Self> {
        let (token_grace_minutes, require_enrolled_receipt_signer) = deps
            .settings
            .try_read()
            .map(|settings| {
                (
                    settings.local_api_security.token_grace_minutes.max(1),
                    edr_receipt_signer_requires_enrollment(&settings),
                )
            })
            .unwrap_or((15, false));
        let edr_flight_recorder = Arc::new(Mutex::new(default_edr_flight_recorder()?));
        let edr_receipt_ledger = Arc::new(Mutex::new(default_edr_receipt_ledger(
            require_enrolled_receipt_signer,
        )?));
        let edr_honey_registry = Arc::new(Mutex::new(default_edr_honey_registry()?));
        let edr_evidence_bundle_store = Arc::new(Mutex::new(default_edr_evidence_bundle_store()?));
        let edr_response_execution_ledger =
            Arc::new(Mutex::new(default_edr_response_execution_ledger()?));
        let edr_response_acknowledgement_ledger =
            Arc::new(Mutex::new(default_edr_response_acknowledgement_ledger()?));
        let edr_control_ack_postback_retry_ledger =
            Arc::new(Mutex::new(default_edr_control_ack_postback_retry_ledger()?));
        let edr_control_archive_upload_retry_ledger = Arc::new(Mutex::new(
            default_edr_control_archive_upload_retry_ledger()?,
        ));
        let edr_control_receipt_upload_retry_ledger = Arc::new(Mutex::new(
            default_edr_control_receipt_upload_retry_ledger()?,
        ));
        let edr_fleet_hunt_event_outbox =
            Arc::new(Mutex::new(default_edr_fleet_hunt_event_outbox()?));
        let edr_egress_restriction_ledger =
            Arc::new(Mutex::new(default_edr_egress_restriction_ledger()?));
        let edr_staged_detection_ledger =
            Arc::new(Mutex::new(default_edr_staged_detection_ledger()?));
        let edr_policy_delta_store = Arc::new(Mutex::new(default_edr_policy_delta_store()?));

        Ok(Self {
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
                edr_flight_recorder,
                edr_receipt_ledger,
                edr_honey_registry,
                edr_evidence_bundle_store,
                edr_response_execution_ledger,
                edr_response_acknowledgement_ledger,
                edr_control_ack_postback_retry_ledger,
                edr_control_archive_upload_retry_ledger,
                edr_control_receipt_upload_retry_ledger,
                edr_fleet_hunt_event_outbox,
                edr_egress_restriction_ledger,
                edr_staged_detection_ledger,
                edr_policy_delta_store,
                edr_cross_window_promotion_validations: Arc::new(Mutex::new(VecDeque::new())),
                edr_network_extension_egress_policy_path: Arc::new(
                    default_edr_network_extension_egress_policy_path(),
                ),
                edr_quarantine_root: Arc::new(default_edr_quarantine_dir()),
                edr_recent_findings: Arc::new(Mutex::new(VecDeque::new())),
                edr_auto_published_agent_secret_touch_keys: Arc::new(Mutex::new(BTreeSet::new())),
            }),
        })
    }

    pub fn control_ack_postback_retry_sink(&self) -> ControlAckPostbackRetrySink {
        ControlAckPostbackRetrySink {
            state: self.state.clone(),
        }
    }

    pub async fn start(self, mut shutdown_rx: broadcast::Receiver<()>) -> Result<()> {
        let mut app = Router::new()
            .route("/health", get(proxy_daemon_get))
            .route("/api/v1/audit", get(proxy_daemon_get))
            .route("/api/v1/audit/stats", get(proxy_daemon_get))
            .route("/api/v1/policy", get(proxy_daemon_get))
            .route("/api/v1/agents/status", get(proxy_daemon_get))
            .route("/api/v1/events", get(proxy_daemon_events))
            .route("/api/v1/siem/exporters", get(proxy_daemon_get))
            .route("/api/v1/broker/public-key", get(proxy_daemon_get))
            .route(
                "/api/v1/broker/capabilities",
                get(proxy_daemon_get).post(proxy_daemon_mutation),
            )
            .route(
                "/api/v1/broker/previews",
                get(proxy_daemon_get).post(proxy_daemon_mutation),
            )
            .route(
                "/api/v1/broker/capabilities/revoke-all",
                post(proxy_daemon_mutation),
            )
            .route("/api/v1/broker/capabilities/{id}", get(proxy_daemon_get))
            .route(
                "/api/v1/broker/capabilities/{id}/status",
                get(proxy_daemon_get),
            )
            .route(
                "/api/v1/broker/capabilities/{id}/replay",
                post(proxy_daemon_mutation),
            )
            .route(
                "/api/v1/broker/capabilities/{id}/bundle",
                get(proxy_daemon_get),
            )
            .route(
                "/api/v1/broker/capabilities/{id}/revoke",
                post(proxy_daemon_mutation),
            )
            .route("/api/v1/broker/previews/{id}", get(proxy_daemon_get))
            .route(
                "/api/v1/broker/previews/{id}/approve",
                post(proxy_daemon_mutation),
            )
            .route("/api/v1/broker/providers/freeze", get(proxy_daemon_get))
            .route(
                "/api/v1/broker/providers/{provider}/freeze",
                post(proxy_daemon_mutation).delete(proxy_daemon_mutation),
            )
            .route("/api/v1/agent/health", get(agent_health))
            .route(
                "/api/v1/agent/settings",
                get(get_settings).put(update_settings),
            )
            .route("/api/v1/agent/runtimes", get(list_runtime_agents))
            .route(
                "/api/v1/agent/runtimes/register",
                post(register_runtime_agent_route),
            )
            .route(
                "/api/v1/agent/integrations",
                get(get_integrations_settings).put(update_integrations_settings),
            )
            .route(
                "/api/v1/agent/integrations/test",
                post(test_integration_delivery),
            )
            .route("/api/v1/agent/ota/status", get(get_ota_status))
            .route("/api/v1/agent/ota/check", post(trigger_ota_check))
            .route("/api/v1/agent/ota/apply", post(trigger_ota_apply))
            .route(
                "/api/v1/agent/diagnostics/bundle",
                post(create_diagnostics_bundle),
            )
            .route(
                "/api/v1/agent/security/token/rotate",
                post(rotate_local_api_token_route),
            )
            .route("/api/v1/agent/policy-check", post(agent_policy_check))
            .route("/api/v1/agent/edr/findings", post(agent_edr_findings))
            .route(
                "/api/v1/agent/edr/developer-activity",
                post(agent_edr_developer_activity),
            )
            .route(
                "/api/v1/agent/edr/package-manager/events",
                post(agent_edr_package_manager_events),
            )
            .route(
                "/api/v1/agent/edr/endpoint-security/events",
                post(agent_edr_endpoint_security_events),
            )
            .route(
                "/api/v1/agent/edr/network-extension/events",
                post(agent_edr_network_extension_events),
            )
            .route(
                "/api/v1/agent/edr/policy-events",
                post(agent_edr_policy_events),
            )
            .route(
                "/api/v1/agent/edr/policy-events/jsonl",
                post(agent_edr_policy_events_jsonl),
            )
            .route(
                "/api/v1/agent/edr/policy-events/replay",
                post(agent_edr_policy_events_replay),
            )
            .route(
                "/api/v1/agent/edr/policy-events/replay/jsonl",
                post(agent_edr_policy_events_replay_jsonl),
            )
            .route(
                "/api/v1/agent/edr/policy-events/replay/history",
                post(agent_edr_policy_events_replay_history),
            )
            .route(
                "/api/v1/agent/edr/policy-events/impact",
                post(agent_edr_policy_events_impact),
            )
            .route(
                "/api/v1/agent/edr/policy-events/impact/history",
                post(agent_edr_policy_events_impact_history),
            )
            .route(
                "/api/v1/agent/edr/finding-groups",
                get(agent_edr_finding_groups),
            )
            .route(
                "/api/v1/agent/edr/flight-recorder",
                get(agent_edr_flight_recorder),
            )
            .route(
                "/api/v1/agent/edr/flight-recorder/compact",
                post(agent_edr_flight_recorder_compact),
            )
            .route(
                "/api/v1/agent/edr/protection-state",
                get(agent_edr_protection_state),
            )
            .route(
                "/api/v1/agent/edr/privacy-report",
                post(agent_edr_privacy_report),
            )
            .route("/api/v1/agent/edr/receipts", get(agent_edr_receipts))
            .route(
                "/api/v1/agent/edr/receipts/upload",
                post(agent_edr_receipts_upload),
            )
            .route(
                "/api/v1/agent/edr/receipts/compact",
                post(agent_edr_receipts_compact),
            )
            .route(
                "/api/v1/agent/edr/evidence-bundles",
                get(agent_edr_evidence_bundles),
            )
            .route(
                "/api/v1/agent/edr/evidence-bundles/compact",
                post(agent_edr_evidence_bundles_compact),
            )
            .route(
                "/api/v1/agent/edr/evidence-bundles/archive/verify",
                post(agent_edr_evidence_bundle_archive_verify),
            )
            .route(
                "/api/v1/agent/edr/evidence-bundles/{bundle_id}/fleet-publish",
                post(agent_edr_evidence_bundle_fleet_publish),
            )
            .route(
                "/api/v1/agent/edr/fleet-hunt-events/retry",
                post(agent_edr_fleet_hunt_events_retry),
            )
            .route(
                "/api/v1/agent/edr/evidence-bundles/{bundle_id}",
                get(agent_edr_evidence_bundle),
            )
            .route(
                "/api/v1/agent/edr/evidence-bundles/{bundle_id}/archive",
                get(agent_edr_evidence_bundle_archive),
            )
            .route(
                "/api/v1/agent/edr/causal-graph",
                post(agent_edr_causal_graph),
            )
            .route(
                "/api/v1/agent/edr/causal-subgraph",
                post(agent_edr_causal_subgraph),
            )
            .route(
                "/api/v1/agent/edr/causal-context",
                post(agent_edr_causal_context),
            )
            .route(
                "/api/v1/agent/edr/graph-search",
                post(agent_edr_graph_search),
            )
            .route(
                "/api/v1/agent/edr/graph-slices/export",
                post(agent_edr_graph_slice_export),
            )
            .route(
                "/api/v1/agent/edr/agent-secret-touches",
                post(agent_edr_agent_secret_touches),
            )
            .route(
                "/api/v1/agent/edr/agent-secret-touches/fleet-publish",
                post(agent_edr_agent_secret_touches_fleet_publish),
            )
            .route(
                "/api/v1/agent/edr/policy-simulation",
                post(agent_edr_policy_simulation),
            )
            .route(
                "/api/v1/agent/edr/policy-replay",
                post(agent_edr_policy_replay),
            )
            .route(
                "/api/v1/agent/edr/detection-candidate",
                post(agent_edr_detection_candidate),
            )
            .route(
                "/api/v1/agent/edr/staged-detections",
                get(agent_edr_staged_detections).post(agent_edr_stage_detection),
            )
            .route(
                "/api/v1/agent/edr/policy-deltas",
                get(agent_edr_policy_deltas).post(agent_edr_policy_delta),
            )
            .route(
                "/api/v1/agent/edr/policy-deltas/{policy_delta_id}/apply",
                post(agent_edr_policy_delta_apply),
            )
            .route(
                "/api/v1/agent/edr/network-extension/egress-policy/proof",
                post(agent_edr_network_extension_egress_policy_proof),
            )
            .route(
                "/api/v1/agent/edr/response-action",
                post(agent_edr_response_action),
            )
            .route(
                "/api/v1/agent/edr/response-executions",
                get(agent_edr_response_executions),
            )
            .route(
                "/api/v1/agent/edr/response-executions/expire",
                post(agent_edr_response_execution_expire),
            )
            .route(
                "/api/v1/agent/edr/response-acknowledgements",
                get(agent_edr_response_acknowledgements),
            )
            .route(
                "/api/v1/agent/edr/control-ack-postbacks/retry",
                post(agent_edr_control_ack_postbacks_retry),
            )
            .route(
                "/api/v1/agent/edr/control-archive-uploads/retry",
                post(agent_edr_control_archive_uploads_retry),
            )
            .route(
                "/api/v1/agent/edr/control-receipt-uploads/retry",
                post(agent_edr_control_receipt_uploads_retry),
            )
            .route(
                "/api/v1/agent/edr/control-archive-uploads/backfill",
                post(agent_edr_control_archive_uploads_backfill),
            )
            .route(
                "/api/v1/agent/edr/response-executions/{execution_id}/cancel",
                post(agent_edr_response_execution_cancel),
            )
            .route(
                "/api/v1/agent/edr/response-executions/{execution_id}/rollback",
                post(agent_edr_response_execution_rollback),
            )
            .route(
                "/api/v1/agent/edr/response-executions/{execution_id}/acknowledge",
                post(agent_edr_response_execution_acknowledge),
            )
            .route(
                "/api/v1/agent/edr/response-executions/{execution_id}/proof",
                get(agent_edr_response_execution_proof),
            )
            .route(
                "/api/v1/agent/edr/response-executions/{execution_id}",
                get(agent_edr_response_execution),
            )
            .route(
                "/api/v1/agent/edr/deception-plan",
                post(agent_edr_deception_plan),
            )
            .route(
                "/api/v1/agent/edr/deception-plan/materialize",
                post(agent_edr_materialize_deception_plan),
            )
            .route(
                "/api/v1/agent/edr/deception-plan/cleanup",
                post(agent_edr_cleanup_deception_plan),
            )
            .route(
                "/api/v1/agent/edr/deception-plan/rotate",
                post(agent_edr_rotate_deception_plan),
            )
            .route(
                "/api/v1/openclaw/gateways",
                get(list_gateways).post(create_gateway),
            )
            .route(
                "/api/v1/openclaw/gateways/{id}",
                patch(patch_gateway).delete(delete_gateway),
            )
            .route(
                "/api/v1/openclaw/gateways/{id}/connect",
                post(connect_gateway),
            )
            .route(
                "/api/v1/openclaw/gateways/{id}/disconnect",
                post(disconnect_gateway),
            )
            .route("/api/v1/openclaw/active-gateway", put(set_active_gateway))
            .route("/api/v1/openclaw/discover", post(discover_gateways))
            .route("/api/v1/openclaw/probe", post(probe_gateway))
            .route("/api/v1/openclaw/request", post(gateway_request))
            .route(
                "/api/v1/openclaw/import-desktop-gateways",
                post(import_desktop_gateways),
            )
            .route("/api/v1/openclaw/events", get(openclaw_events))
            .route("/api/v1/approval/request", post(create_approval_request))
            .route("/api/v1/approval/{id}/status", get(get_approval_status))
            .route("/api/v1/approval/{id}/resolve", post(resolve_approval))
            .route("/api/v1/approval/pending", get(list_pending_approvals))
            .route("/api/v1/enroll", post(enroll_agent))
            .route("/api/v1/enrollment-status", get(enrollment_status))
            .route("/api/v1/ui/bootstrap/start", post(start_ui_bootstrap))
            .route(
                "/ui/bootstrap",
                get(ui_bootstrap_page).post(ui_bootstrap_verify),
            )
            .layer(axum::middleware::from_fn_with_state(
                self.state.clone(),
                route_rate_limit,
            ))
            .layer(DefaultBodyLimit::max(AGENT_API_MAX_BODY_BYTES))
            .with_state(self.state.clone());

        if let Some(dashboard_dist) = resolve_control_console_dist() {
            tracing::info!(
                path = %dashboard_dist.display(),
                "Serving control console from bundled assets"
            );
            let index_file = dashboard_dist.join("index.html");
            let ui_router = Router::new()
                .fallback_service(
                    ServeDir::new(dashboard_dist).not_found_service(ServeFile::new(index_file)),
                )
                .layer(axum::middleware::from_fn_with_state(
                    self.state.clone(),
                    attach_ui_auth_cookie,
                ));
            app = app.nest("/ui", ui_router);
        } else {
            tracing::warn!(
                "Control console assets were not found; serving fallback diagnostics page at /ui"
            );
            let ui_router = Router::new()
                .route("/", get(agent_web_ui_fallback))
                .route("/{*path}", get(agent_web_ui_fallback))
                .layer(axum::middleware::from_fn_with_state(
                    self.state.clone(),
                    attach_ui_auth_cookie,
                ));
            app = app.nest("/ui", ui_router);
        }

        let addr = SocketAddr::from(([127, 0, 0, 1], self.port));
        let listener = TcpListener::bind(addr)
            .await
            .with_context(|| format!("Failed to bind agent API server to {}", addr))?;

        {
            let settings = self.state.settings.read().await;
            if settings.local_api_security.mtls_enabled {
                let cert = settings
                    .local_api_security
                    .mtls_server_cert_path
                    .as_ref()
                    .is_some_and(|path| path.is_file());
                let key = settings
                    .local_api_security
                    .mtls_server_key_path
                    .as_ref()
                    .is_some_and(|path| path.is_file());
                let ca = settings
                    .local_api_security
                    .mtls_client_ca_path
                    .as_ref()
                    .is_some_and(|path| path.is_file());
                if cert && key && ca {
                    tracing::info!(
                        mtls_port = settings.local_api_security.mtls_port,
                        "Local API mTLS settings are configured"
                    );
                } else {
                    tracing::warn!(
                        "Local API mTLS is enabled but cert/key/CA files are missing or unreadable"
                    );
                }
            }
        }

        tracing::info!(address = %addr, "Agent API server listening");

        let rotation_state = self.state.clone();
        let mut token_rotation_shutdown = shutdown_rx.resubscribe();
        tokio::spawn(async move {
            token_rotation_loop(rotation_state, &mut token_rotation_shutdown).await;
        });

        let retry_drain_state = self.state.clone();
        let mut retry_drain_shutdown = shutdown_rx.resubscribe();
        tokio::spawn(async move {
            control_ack_postback_retry_drain_loop(retry_drain_state, &mut retry_drain_shutdown)
                .await;
        });

        let receipt_upload_drain_state = self.state.clone();
        let mut receipt_upload_drain_shutdown = shutdown_rx.resubscribe();
        tokio::spawn(async move {
            control_receipt_upload_retry_drain_loop(
                receipt_upload_drain_state,
                &mut receipt_upload_drain_shutdown,
            )
            .await;
        });

        let response_expiration_state = self.state.clone();
        let mut response_expiration_shutdown = shutdown_rx.resubscribe();
        tokio::spawn(async move {
            response_execution_expiration_sweep_loop(
                response_expiration_state,
                &mut response_expiration_shutdown,
            )
            .await;
        });

        if self.state.fleet_hunt_publisher.is_some() {
            let sync_state = self.state.clone();
            let mut sync_shutdown = shutdown_rx.resubscribe();
            tokio::spawn(async move {
                fleet_agent_secret_touch_sync_loop(sync_state, &mut sync_shutdown).await;
            });
        }

        axum::serve(listener, app)
            .with_graceful_shutdown(async move {
                let _ = shutdown_rx.recv().await;
                tracing::info!("Agent API server shutting down");
            })
            .await
            .with_context(|| "Agent API server error")?;

        Ok(())
    }
}

async fn agent_web_ui_fallback() -> Html<&'static str> {
    Html(
        r##"<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>Clawdstrike Agent Web UI</title>
  <style>
    :root {
      color-scheme: light dark;
      --bg: #0d1117;
      --fg: #e6edf3;
      --muted: #8b949e;
      --accent: #2f81f7;
      --card: #161b22;
      --line: #30363d;
    }
    body {
      margin: 0;
      padding: 24px;
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
      background: var(--bg);
      color: var(--fg);
    }
    main {
      max-width: 760px;
      margin: 0 auto;
      border: 1px solid var(--line);
      background: var(--card);
      border-radius: 10px;
      padding: 20px;
    }
    h1 { margin-top: 0; font-size: 1.4rem; }
    p { color: var(--muted); line-height: 1.5; }
    code {
      background: rgba(255, 255, 255, 0.08);
      border-radius: 6px;
      padding: 2px 6px;
    }
    .tabs {
      display: flex;
      gap: 8px;
      margin: 14px 0 16px;
      flex-wrap: wrap;
    }
    .tab {
      border: 1px solid var(--line);
      border-radius: 999px;
      padding: 6px 12px;
      font-size: 0.9rem;
      color: var(--muted);
      text-decoration: none;
    }
    .tab.active {
      border-color: var(--accent);
      color: #d7e8ff;
      background: rgba(47, 129, 247, 0.12);
    }
    .hidden {
      display: none;
    }
    .panel {
      border: 1px solid var(--line);
      border-radius: 8px;
      padding: 14px;
      background: rgba(255, 255, 255, 0.03);
    }
    h2 {
      margin: 0 0 8px;
      font-size: 1.05rem;
    }
    ul { margin: 0.75rem 0 0; padding-left: 1.2rem; }
    a { color: var(--accent); text-decoration: none; }
    a:hover { text-decoration: underline; }
  </style>
</head>
<body>
  <main>
    <h1>Clawdstrike Agent Web UI</h1>
    <p>This is the local fallback UI. If you expected the control console on <code>localhost:3100</code>, start it manually during development.</p>

    <nav class="tabs" aria-label="Agent web UI sections">
      <a href="#/" class="tab" data-route="/">Overview</a>
      <a href="#/settings/siem" class="tab" data-route="/settings/siem">SIEM Export</a>
      <a href="#/settings/webhooks" class="tab" data-route="/settings/webhooks">Webhooks</a>
    </nav>

    <section class="panel" data-view="/">
      <h2>Overview</h2>
      <ul>
        <li>Agent health (auth required): <a href="/api/v1/agent/health"><code>/api/v1/agent/health</code></a></li>
        <li>Agent settings (auth required): <a href="/api/v1/agent/settings"><code>/api/v1/agent/settings</code></a></li>
      </ul>
    </section>

    <section class="panel hidden" data-view="/settings/siem">
      <h2>SIEM Export</h2>
      <p>Configure SIEM providers from the control console when available. This fallback page confirms the requested route and keeps agent diagnostics available.</p>
      <ul>
        <li>Requested route: <code>#/settings/siem</code></li>
        <li>Preferred full dashboard URL: <code>http://127.0.0.1:3100/settings/siem</code></li>
      </ul>
    </section>

    <section class="panel hidden" data-view="/settings/webhooks">
      <h2>Webhooks</h2>
      <p>Configure webhook forwarding from the control console when available. This fallback page confirms the requested route and keeps agent diagnostics available.</p>
      <ul>
        <li>Requested route: <code>#/settings/webhooks</code></li>
        <li>Preferred full dashboard URL: <code>http://127.0.0.1:3100/settings/webhooks</code></li>
      </ul>
    </section>
  </main>
  <script>
    function normalizeRoute(hash) {
      if (!hash || hash === "#") return "/";
      const raw = hash.startsWith("#") ? hash.slice(1) : hash;
      return raw.startsWith("/") ? raw : `/${raw}`;
    }

    function renderRoute() {
      const route = normalizeRoute(window.location.hash);
      const tabs = document.querySelectorAll("[data-route]");
      const views = document.querySelectorAll("[data-view]");
      const knownRoutes = new Set(["/", "/settings/siem", "/settings/webhooks"]);
      const activeRoute = knownRoutes.has(route) ? route : "/";

      tabs.forEach((tab) => {
        tab.classList.toggle("active", tab.dataset.route === activeRoute);
      });
      views.forEach((view) => {
        view.classList.toggle("hidden", view.dataset.view !== activeRoute);
      });
    }

    window.addEventListener("hashchange", renderRoute);
    renderRoute();
  </script>
</body>
</html>"##,
    )
}

fn control_console_dist_candidates() -> Vec<PathBuf> {
    let mut candidates = Vec::new();

    if let Ok(override_path) = std::env::var("CLAWDSTRIKE_CONTROL_CONSOLE_DIST") {
        candidates.push(PathBuf::from(override_path));
    }

    if let Ok(exe_path) = std::env::current_exe() {
        if let Some(exe_dir) = exe_path.parent() {
            candidates.push(exe_dir.join("control-console"));
            candidates.push(exe_dir.join("resources").join("control-console"));

            if let Some(contents_dir) = exe_dir.parent() {
                candidates.push(contents_dir.join("Resources").join("control-console"));
                candidates.push(
                    contents_dir
                        .join("Resources")
                        .join("resources")
                        .join("control-console"),
                );
            }
        }
    }

    if let Ok(manifest_dir) = std::env::var("CARGO_MANIFEST_DIR") {
        let root = PathBuf::from(manifest_dir);
        candidates.push(root.join("resources").join("control-console"));
        candidates.push(root.join("../../control-console/dist"));
    }

    candidates
}

fn resolve_control_console_dist() -> Option<PathBuf> {
    control_console_dist_candidates()
        .into_iter()
        .find(|candidate| candidate.join("index.html").is_file())
}

fn build_daemon_proxy_target(daemon_url: &str, uri: &Uri) -> Result<String, (StatusCode, String)> {
    let path_and_query = uri
        .path_and_query()
        .map(|value| value.as_str())
        .unwrap_or_else(|| uri.path());

    if !path_and_query.starts_with('/') {
        return Err((StatusCode::BAD_REQUEST, "invalid proxy path".to_string()));
    }

    Ok(format!(
        "{}{}",
        daemon_url.trim_end_matches('/'),
        path_and_query
    ))
}

fn merged_authorization_header(
    request_headers: &HeaderMap,
    daemon_api_key: Option<&str>,
) -> Option<String> {
    if let Some(value) = request_headers
        .get(HUSHD_AUTHORIZATION_HEADER)
        .and_then(|value| value.to_str().ok())
        .map(str::trim)
        .filter(|value| !value.is_empty())
    {
        return Some(value.to_string());
    }

    if let Some(value) = request_headers
        .get(AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .map(str::trim)
        .filter(|value| !value.is_empty())
    {
        return Some(value.to_string());
    }

    daemon_api_key
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(|key| format!("Bearer {}", key))
}

fn auth_cookie_header_value(auth_token: &str, secure: bool) -> String {
    let secure_flag = if secure { "; Secure" } else { "" };
    format!(
        "{}={}; Path=/; HttpOnly; SameSite=Strict{}",
        AGENT_AUTH_COOKIE_NAME, auth_token, secure_flag
    )
}

fn set_ui_auth_cookie(response: &mut Response, auth_token: &str, secure: bool) {
    match HeaderValue::from_str(&auth_cookie_header_value(auth_token, secure)) {
        Ok(value) => {
            response.headers_mut().append(SET_COOKIE, value);
        }
        Err(err) => {
            tracing::warn!(error = %err, "Failed to build UI auth cookie header");
        }
    }
}

fn request_is_secure_uri(headers: &HeaderMap, uri: &Uri) -> bool {
    if uri.scheme_str() == Some("https") {
        return true;
    }
    if !is_local_host_header(headers) {
        return false;
    }
    headers
        .get("x-forwarded-proto")
        .and_then(|value| value.to_str().ok())
        .map(|value| value.eq_ignore_ascii_case("https"))
        .unwrap_or(false)
}

fn request_is_secure(headers: &HeaderMap, request: &Request) -> bool {
    request_is_secure_uri(headers, request.uri())
}

fn is_local_host_header(headers: &HeaderMap) -> bool {
    let Some(host) = headers
        .get("host")
        .and_then(|value| value.to_str().ok())
        .map(str::trim)
    else {
        return false;
    };

    let host_only = host
        .parse::<Authority>()
        .map(|authority| authority.host().to_ascii_lowercase())
        .unwrap_or_else(|_| host.to_ascii_lowercase());
    let host_only = host_only
        .trim_start_matches('[')
        .trim_end_matches(']')
        .to_string();

    host_only == "localhost" || host_only == "127.0.0.1" || host_only == "::1"
}

fn has_query_param(uri: &Uri, param_name: &str) -> bool {
    let Some(query) = uri.query() else {
        return false;
    };

    query.split('&').any(|pair| {
        if pair.is_empty() {
            return false;
        }
        let (name, _) = pair.split_once('=').unwrap_or((pair, ""));
        name == param_name
    })
}

async fn attach_ui_auth_cookie(
    State(state): State<Arc<AgentApiState>>,
    request: Request,
    next: Next,
) -> Response {
    let secure_cookie = request_is_secure(request.headers(), &request);
    if !secure_cookie && !is_local_host_header(request.headers()) {
        return (
            StatusCode::FORBIDDEN,
            "Non-localhost dashboard access requires HTTPS",
        )
            .into_response();
    }

    if has_query_param(request.uri(), "agent_token") {
        tracing::warn!(
            path = %request.uri().path(),
            "Rejected deprecated query-based UI bootstrap token"
        );
        return (
            StatusCode::BAD_REQUEST,
            "Query-based UI bootstrap is disabled",
        )
            .into_response();
    }

    if require_auth(request.headers(), &state).is_err() {
        return (
            StatusCode::UNAUTHORIZED,
            "Missing authorization token for /ui",
        )
            .into_response();
    }

    let mut response = next.run(request).await;
    let token = current_auth_token(&state);
    set_ui_auth_cookie(&mut response, &token, secure_cookie);
    response
}

fn query_param(uri: &Uri, param_name: &str) -> Option<String> {
    let query = uri.query()?;
    for pair in query.split('&') {
        if pair.is_empty() {
            continue;
        }
        let (name, value) = pair.split_once('=').unwrap_or((pair, ""));
        if name == param_name {
            let trimmed = value.trim();
            if trimmed.is_empty() {
                return None;
            }
            return Some(trimmed.to_string());
        }
    }
    None
}

fn sanitize_ui_next_path(candidate: Option<&str>) -> String {
    let raw = candidate.unwrap_or("/ui").trim();
    if raw.is_empty() {
        return "/ui".to_string();
    }
    if raw.contains('\n') || raw.contains('\r') {
        return "/ui".to_string();
    }
    if raw.starts_with("http://") || raw.starts_with("https://") {
        return "/ui".to_string();
    }
    if !raw.starts_with("/ui") {
        return "/ui".to_string();
    }
    raw.to_string()
}

fn normalize_bootstrap_code(raw: &str) -> Option<String> {
    let normalized: String = raw
        .chars()
        .filter(|ch| ch.is_ascii_alphanumeric())
        .map(|ch| ch.to_ascii_uppercase())
        .collect();
    if normalized.len() != 8 {
        return None;
    }
    Some(normalized)
}

fn generate_ui_bootstrap_code() -> (String, String) {
    let random = uuid::Uuid::new_v4()
        .simple()
        .to_string()
        .to_ascii_uppercase();
    let normalized = random.chars().take(8).collect::<String>();
    let display = format!("{}-{}", &normalized[..4], &normalized[4..]);
    (normalized, display)
}

fn is_valid_bootstrap_session_id(candidate: &str) -> bool {
    !candidate.is_empty()
        && candidate.len() <= 64
        && candidate
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || ch == '-')
}

fn prune_ui_bootstrap_sessions(sessions: &mut HashMap<String, UiBootstrapSession>, now: Instant) {
    sessions.retain(|_, session| {
        session.expires_at > now && session.attempts < UI_BOOTSTRAP_MAX_ATTEMPTS
    });
    while sessions.len() > UI_BOOTSTRAP_MAX_SESSIONS {
        let Some((oldest_key, _)) = sessions
            .iter()
            .min_by_key(|(_, session)| session.created_at)
            .map(|(id, session)| (id.clone(), session.created_at))
        else {
            break;
        };
        let _ = sessions.remove(&oldest_key);
    }
}

async fn start_ui_bootstrap(
    State(state): State<Arc<AgentApiState>>,
    headers: HeaderMap,
    Json(input): Json<UiBootstrapStartInput>,
) -> Result<Json<UiBootstrapStartResponse>, (StatusCode, String)> {
    require_auth(&headers, &state)?;

    let now = Instant::now();
    let session_id = uuid::Uuid::new_v4().to_string();
    let (code_normalized, user_code) = generate_ui_bootstrap_code();
    let next_path = sanitize_ui_next_path(input.next_path.as_deref());

    {
        let mut sessions = state.ui_bootstrap_sessions.lock().await;
        prune_ui_bootstrap_sessions(&mut sessions, now);
        sessions.insert(
            session_id.clone(),
            UiBootstrapSession {
                code_normalized,
                next_path,
                created_at: now,
                expires_at: now + UI_BOOTSTRAP_TTL,
                attempts: 0,
            },
        );
    }

    Ok(Json(UiBootstrapStartResponse {
        session_id,
        user_code,
        expires_in_seconds: UI_BOOTSTRAP_TTL.as_secs(),
    }))
}

async fn ui_bootstrap_page(uri: Uri) -> impl IntoResponse {
    let session_id = query_param(&uri, "session_id");
    let valid_session = session_id
        .as_deref()
        .map(is_valid_bootstrap_session_id)
        .unwrap_or(false);
    if !valid_session {
        return (
            StatusCode::BAD_REQUEST,
            "Missing or invalid bootstrap session id",
        )
            .into_response();
    }

    Html(
        r##"<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>Clawdstrike Agent Login</title>
  <style>
    body {
      margin: 0;
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
      background: #0f172a;
      color: #e2e8f0;
      min-height: 100vh;
      display: grid;
      place-items: center;
      padding: 24px;
      box-sizing: border-box;
    }
    .card {
      width: 100%;
      max-width: 420px;
      background: #111827;
      border: 1px solid #334155;
      border-radius: 12px;
      padding: 20px;
      box-shadow: 0 12px 28px rgba(2, 6, 23, 0.35);
    }
    h1 {
      margin: 0 0 10px 0;
      font-size: 1.25rem;
    }
    p {
      margin: 0 0 14px 0;
      color: #94a3b8;
      line-height: 1.4;
    }
    label {
      display: block;
      font-weight: 600;
      margin-bottom: 8px;
    }
    input[type="text"] {
      width: 100%;
      box-sizing: border-box;
      border: 1px solid #475569;
      background: #0b1220;
      color: #e2e8f0;
      border-radius: 8px;
      font-size: 1rem;
      padding: 10px 12px;
      letter-spacing: 0.08em;
      text-transform: uppercase;
    }
    button {
      margin-top: 14px;
      width: 100%;
      border: 0;
      border-radius: 8px;
      padding: 10px 12px;
      font-size: 0.95rem;
      font-weight: 600;
      background: #2563eb;
      color: #f8fafc;
      cursor: pointer;
    }
    .hint {
      margin-top: 12px;
      font-size: 0.85rem;
      color: #64748b;
    }
  </style>
</head>
<body>
  <main class="card">
    <h1>Verify Local Browser Session</h1>
    <p>Enter the one-time code shown by the agent tray to sign in.</p>
    <form method="post" action="/ui/bootstrap">
      <input id="session_id" type="hidden" name="session_id" />
      <label for="user_code">One-time code</label>
      <input id="user_code" name="user_code" type="text" required autocomplete="one-time-code" inputmode="latin-prose" />
      <button type="submit">Continue to Dashboard</button>
    </form>
    <div class="hint">Codes expire after 60 seconds and can only be used once.</div>
  </main>
  <script>
    const params = new URLSearchParams(window.location.search);
    const sessionId = params.get("session_id") || "";
    const field = document.getElementById("session_id");
    if (field) field.value = sessionId;
  </script>
</body>
</html>"##,
    )
    .into_response()
}

async fn ui_bootstrap_verify(
    State(state): State<Arc<AgentApiState>>,
    headers: HeaderMap,
    uri: Uri,
    Form(input): Form<UiBootstrapVerifyInput>,
) -> Response {
    let secure_cookie = request_is_secure_uri(&headers, &uri);
    if !secure_cookie && !is_local_host_header(&headers) {
        return (
            StatusCode::FORBIDDEN,
            "Non-localhost dashboard access requires HTTPS",
        )
            .into_response();
    }

    if !is_valid_bootstrap_session_id(input.session_id.trim()) {
        return (
            StatusCode::UNAUTHORIZED,
            "Invalid or expired bootstrap code",
        )
            .into_response();
    }
    let Some(code_normalized) = normalize_bootstrap_code(&input.user_code) else {
        return (
            StatusCode::UNAUTHORIZED,
            "Invalid or expired bootstrap code",
        )
            .into_response();
    };

    let now = Instant::now();
    let session_id = input.session_id.trim().to_string();

    let next_path = {
        let mut sessions = state.ui_bootstrap_sessions.lock().await;
        prune_ui_bootstrap_sessions(&mut sessions, now);

        let Some(session) = sessions.get_mut(&session_id) else {
            return (
                StatusCode::UNAUTHORIZED,
                "Invalid or expired bootstrap code",
            )
                .into_response();
        };
        if !constant_time_eq_token(&code_normalized, &session.code_normalized) {
            session.attempts = session.attempts.saturating_add(1);
            if session.attempts >= UI_BOOTSTRAP_MAX_ATTEMPTS {
                let _ = sessions.remove(&session_id);
            }
            return (
                StatusCode::UNAUTHORIZED,
                "Invalid or expired bootstrap code",
            )
                .into_response();
        }
        let next = session.next_path.clone();
        let _ = sessions.remove(&session_id);
        next
    };

    let mut response = StatusCode::SEE_OTHER.into_response();
    match HeaderValue::from_str(&next_path) {
        Ok(value) => {
            response.headers_mut().insert(LOCATION, value);
        }
        Err(err) => {
            tracing::warn!(
                error = %err,
                location = %next_path,
                "Failed to build bootstrap redirect location"
            );
            response
                .headers_mut()
                .insert(LOCATION, HeaderValue::from_static("/ui"));
        }
    }
    let token = current_auth_token(&state);
    set_ui_auth_cookie(&mut response, &token, secure_cookie);
    response
}

async fn send_daemon_get_request(
    state: &AgentApiState,
    request_headers: &HeaderMap,
    uri: &Uri,
) -> Result<reqwest::Response, (StatusCode, String)> {
    send_daemon_request(state, request_headers, reqwest::Method::GET, uri, None).await
}

async fn send_daemon_request(
    state: &AgentApiState,
    request_headers: &HeaderMap,
    method: reqwest::Method,
    uri: &Uri,
    body: Option<Vec<u8>>,
) -> Result<reqwest::Response, (StatusCode, String)> {
    let (daemon_url, daemon_api_key) = {
        let settings = state.settings.read().await;
        (settings.daemon_url(), settings.api_key.clone())
    };

    let target_url = build_daemon_proxy_target(&daemon_url, uri)?;
    let mut request = state.http_client.request(method, target_url);

    if let Some(value) = request_headers
        .get(ACCEPT)
        .and_then(|value| value.to_str().ok())
    {
        request = request.header(ACCEPT.as_str(), value);
    }
    if let Some(value) = request_headers
        .get(CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
    {
        request = request.header(CONTENT_TYPE.as_str(), value);
    }

    if let Some(auth_header) =
        merged_authorization_header(request_headers, daemon_api_key.as_deref())
    {
        request = request.header(AUTHORIZATION.as_str(), auth_header);
    }
    if let Some(body) = body {
        request = request.body(body);
    }

    request
        .send()
        .await
        .map_err(|err| internal_error(err.into()))
}

async fn proxy_http_response(
    response: reqwest::Response,
) -> Result<Response, (StatusCode, String)> {
    let status =
        StatusCode::from_u16(response.status().as_u16()).unwrap_or(StatusCode::BAD_GATEWAY);
    let content_type = response.headers().get(CONTENT_TYPE).cloned();
    let body = response
        .bytes()
        .await
        .map_err(|err| internal_error(err.into()))?;

    let mut headers = HeaderMap::new();
    if let Some(value) = content_type {
        headers.insert(CONTENT_TYPE, value);
    }

    Ok((status, headers, body).into_response())
}

async fn proxy_daemon_get(
    State(state): State<Arc<AgentApiState>>,
    mut headers: HeaderMap,
    uri: Uri,
) -> Result<Response, (StatusCode, String)> {
    require_auth(&headers, &state)?;
    // Do not forward the local agent auth token to hushd.
    // A caller can provide a daemon token via `X-Hushd-Authorization`; otherwise we
    // fall back to the configured daemon API key from settings.
    headers.remove(AUTHORIZATION);
    let response = send_daemon_get_request(&state, &headers, &uri).await?;
    proxy_http_response(response).await
}

async fn proxy_daemon_events(
    State(state): State<Arc<AgentApiState>>,
    mut headers: HeaderMap,
    uri: Uri,
) -> Result<Response, (StatusCode, String)> {
    require_auth(&headers, &state)?;
    // Do not forward the local agent auth token to hushd.
    // A caller can provide a daemon token via `X-Hushd-Authorization`; otherwise we
    // fall back to the configured daemon API key from settings.
    headers.remove(AUTHORIZATION);
    let response = send_daemon_get_request(&state, &headers, &uri).await?;
    let status =
        StatusCode::from_u16(response.status().as_u16()).unwrap_or(StatusCode::BAD_GATEWAY);

    if !status.is_success() {
        return proxy_http_response(response).await;
    }

    let content_type = response
        .headers()
        .get(CONTENT_TYPE)
        .cloned()
        .unwrap_or_else(|| HeaderValue::from_static("text/event-stream"));
    let stream = response.bytes_stream().map_err(std::io::Error::other);
    let body = Body::from_stream(stream);

    let mut out_headers = HeaderMap::new();
    out_headers.insert(CONTENT_TYPE, content_type);
    out_headers.insert(CACHE_CONTROL, HeaderValue::from_static("no-cache"));
    out_headers.insert(CONNECTION, HeaderValue::from_static("keep-alive"));

    Ok((status, out_headers, body).into_response())
}

async fn proxy_daemon_mutation(
    State(state): State<Arc<AgentApiState>>,
    mut headers: HeaderMap,
    uri: Uri,
    request: Request,
) -> Result<Response, (StatusCode, String)> {
    require_auth(&headers, &state)?;
    headers.remove(AUTHORIZATION);

    let method = reqwest::Method::from_bytes(request.method().as_str().as_bytes())
        .map_err(|err| internal_error(err.into()))?;
    let max_bytes = if uri.path().starts_with("/api/v1/broker/") {
        BROKER_MUTATION_MAX_BODY_BYTES
    } else {
        AGENT_API_MAX_BODY_BYTES
    };
    let body = axum::body::to_bytes(request.into_body(), max_bytes)
        .await
        .map_err(|err| internal_error(err.into()))?;
    let body = if body.is_empty() {
        None
    } else {
        Some(body.to_vec())
    };
    let response = send_daemon_request(&state, &headers, method, &uri, body).await?;
    proxy_http_response(response).await
}

fn normalize_integration_settings(settings: &mut IntegrationSettings) {
    settings.siem.provider = settings.siem.provider.trim().to_ascii_lowercase();
    if settings.siem.provider.is_empty() {
        settings.siem.provider = "datadog".to_string();
    }
    settings.siem.endpoint = settings.siem.endpoint.trim().to_string();
    settings.siem.api_key = settings.siem.api_key.trim().to_string();
    settings.webhooks.url = settings.webhooks.url.trim().to_string();
    settings.webhooks.secret = settings.webhooks.secret.trim().to_string();

    if settings.siem.endpoint.is_empty() && settings.siem.api_key.is_empty() {
        settings.siem.enabled = false;
    }
    if settings.webhooks.url.is_empty() {
        settings.webhooks.enabled = false;
    }
}

fn validate_integration_settings(
    settings: &IntegrationSettings,
) -> std::result::Result<(), String> {
    let provider = settings.siem.provider.as_str();
    let provider_supported = matches!(
        provider,
        "datadog" | "splunk" | "elastic" | "sumo_logic" | "custom"
    );
    if !provider_supported {
        return Err(format!(
            "Unsupported SIEM provider '{}'",
            settings.siem.provider
        ));
    }

    if settings.siem.enabled {
        if settings.siem.endpoint.is_empty() {
            return Err("SIEM endpoint is required when SIEM is enabled".to_string());
        }
        let key_required = matches!(provider, "datadog" | "splunk" | "elastic");
        if key_required && settings.siem.api_key.is_empty() {
            return Err(format!(
                "SIEM API key is required for provider '{}'",
                settings.siem.provider
            ));
        }
    }

    if settings.webhooks.enabled && settings.webhooks.url.is_empty() {
        return Err("Webhook URL is required when webhook forwarding is enabled".to_string());
    }

    Ok(())
}

async fn fetch_daemon_exporter_status(state: &AgentApiState) -> Option<Value> {
    let (daemon_url, daemon_api_key) = {
        let settings = state.settings.read().await;
        (settings.daemon_url(), settings.api_key.clone())
    };

    let url = format!("{}/api/v1/siem/exporters", daemon_url.trim_end_matches('/'));
    let mut request = state.http_client.get(url);

    if let Some(key) = daemon_api_key
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
    {
        request = request.header(AUTHORIZATION.as_str(), format!("Bearer {}", key));
    }

    let response = request.send().await.ok()?;
    if !response.status().is_success() {
        return None;
    }

    response.json::<Value>().await.ok()
}

async fn fetch_daemon_policy_version(state: &AgentApiState) -> Option<String> {
    let (daemon_url, daemon_api_key) = {
        let settings = state.settings.read().await;
        (settings.daemon_url(), settings.api_key.clone())
    };

    let url = format!("{}/api/v1/policy", daemon_url.trim_end_matches('/'));
    let mut request = state.http_client.get(url);

    if let Some(key) = daemon_api_key
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
    {
        request = request.header(AUTHORIZATION.as_str(), format!("Bearer {}", key));
    }

    let response = request.send().await.ok()?;
    if !response.status().is_success() {
        return None;
    }

    let json = response.json::<Value>().await.ok()?;
    json.get("version")
        .and_then(|value| value.as_str())
        .map(|value| value.to_string())
}

async fn cached_policy_version_for_health(state: &Arc<AgentApiState>) -> Option<String> {
    let (cached_value, should_refresh) = {
        let mut cache = state.policy_version_cache.write().await;
        let should_refresh = cache.mark_refresh_started_if_due(std::time::Instant::now());
        (cache.value.clone(), should_refresh)
    };

    if should_refresh {
        let state = state.clone();
        tokio::spawn(async move {
            let fetched = tokio::time::timeout(
                POLICY_VERSION_FETCH_TIMEOUT,
                fetch_daemon_policy_version(state.as_ref()),
            )
            .await
            .ok()
            .flatten();

            let mut cache = state.policy_version_cache.write().await;
            cache.finish_refresh(fetched, std::time::Instant::now());
        });
    }

    cached_value
}

#[derive(Debug, Serialize)]
pub(crate) struct AgentHealthResponse {
    status: &'static str,
    daemon: DaemonStatus,
    session: crate::session::SessionState,
    macos_host: CombinedSystemExtensionStatus,
    edr: EdrHealthSummary,
    openclaw: serde_json::Value,
    runtime_agents: usize,
    last_policy_version: Option<String>,
    endpoint_agent_id: String,
    last_heartbeat_at: Option<String>,
    heartbeat_age_secs: Option<i64>,
    endpoint_online: Option<bool>,
    policy_drift: Option<bool>,
    daemon_drift: Option<bool>,
    stale: Option<bool>,
    version: &'static str,
}

#[derive(Debug, Deserialize)]
struct DaemonAgentStatusResponse {
    endpoints: Vec<DaemonEndpointStatus>,
}

#[derive(Debug, Deserialize)]
struct DaemonEndpointStatus {
    #[serde(default)]
    last_heartbeat_at: Option<String>,
    #[serde(default)]
    seconds_since_heartbeat: Option<i64>,
    #[serde(default)]
    online: Option<bool>,
    #[serde(default)]
    drift: Option<DaemonEndpointDrift>,
}

fn macos_host_health_status(status: &CombinedSystemExtensionStatus) -> &'static str {
    let endpoint_active = matches!(
        status.endpoint_security.runtime,
        ProviderRuntimeState::Active
    );
    let network_active = matches!(
        status.network_extension.runtime,
        ProviderRuntimeState::Active
    );
    let endpoint_unknown = matches!(
        status.endpoint_security.runtime,
        ProviderRuntimeState::Unknown
    );
    let network_unknown = matches!(
        status.network_extension.runtime,
        ProviderRuntimeState::Unknown
    );
    let endpoint_inactive = matches!(
        status.endpoint_security.runtime,
        ProviderRuntimeState::Inactive
    );
    let network_inactive = matches!(
        status.network_extension.runtime,
        ProviderRuntimeState::Inactive
    );
    let endpoint_degraded = matches!(
        status.endpoint_security.runtime,
        ProviderRuntimeState::Degraded { .. }
    );
    let network_degraded = matches!(
        status.network_extension.runtime,
        ProviderRuntimeState::Degraded { .. }
    );

    if status.install_state == SystemExtensionInstallState::NotInstalled
        || status.approval == SystemExtensionApproval::ApprovalBlocked
        || endpoint_degraded
        || network_degraded
    {
        "degraded"
    } else if status.install_state == SystemExtensionInstallState::Unknown
        || status.approval == SystemExtensionApproval::Unknown
        || endpoint_unknown
        || network_unknown
        || endpoint_inactive
        || network_inactive
    {
        "pending"
    } else if status.install_state == SystemExtensionInstallState::Installed
        && status.approval == SystemExtensionApproval::Approved
        && endpoint_active
        && network_active
    {
        "ok"
    } else {
        "degraded"
    }
}

fn agent_health_status(status: &CombinedSystemExtensionStatus) -> &'static str {
    if cfg!(target_os = "macos") {
        macos_host_health_status(status)
    } else {
        "ok"
    }
}

async fn edr_health_summary(state: &Arc<AgentApiState>) -> EdrHealthSummary {
    let recorder = state.edr_flight_recorder.lock().await;
    let graph = recorder.graph().clone();
    let recent_finding_count = state.edr_recent_findings.lock().await.len();
    EdrHealthSummary {
        observation_count: recorder.observation_count(),
        graph_node_count: graph.nodes.len(),
        graph_edge_count: graph.edges.len(),
        recent_finding_count,
    }
}

#[derive(Debug, Deserialize)]
struct DaemonEndpointDrift {
    #[serde(default)]
    policy_drift: Option<bool>,
    #[serde(default)]
    daemon_drift: Option<bool>,
    #[serde(default)]
    stale: Option<bool>,
}

#[derive(Debug, Serialize)]
struct AgentSettingsResponse {
    daemon_port: u16,
    mcp_port: u16,
    agent_api_port: u16,
    enabled: bool,
    auto_start: bool,
    notifications_enabled: bool,
    notification_severity: String,
    dashboard_url: String,
    debug_include_daemon_error_body: bool,
    openclaw_active_gateway_id: Option<String>,
    ota_enabled: bool,
    ota_mode: String,
    ota_channel: String,
    ota_manifest_url: Option<String>,
    ota_allow_fallback_to_default: bool,
    ota_check_interval_minutes: u32,
    ota_pinned_public_keys: Vec<String>,
    ota_last_check_at: Option<String>,
    ota_last_result: Option<String>,
    ota_current_hushd_version: Option<String>,
    control_api: ControlApiSettingsResponse,
    local_api_security: LocalApiSecurityResponse,
}

#[derive(Debug, Serialize)]
struct ControlApiSettingsResponse {
    enabled: bool,
    url: Option<String>,
    api_key_configured: bool,
}

#[derive(Debug, Serialize)]
struct LocalApiSecurityResponse {
    token_rotation_interval_hours: u32,
    token_grace_minutes: u32,
    mtls_enabled: bool,
    mtls_port: u16,
    mtls_server_cert_path: Option<String>,
    mtls_server_key_path: Option<String>,
    mtls_client_ca_path: Option<String>,
}

#[derive(Debug, Deserialize)]
struct RuntimeRegisterInput {
    runtime_agent_kind: String,
    #[serde(default)]
    runtime_agent_id: Option<String>,
    #[serde(default)]
    endpoint_agent_id: Option<String>,
    #[serde(default)]
    display_name: Option<String>,
    #[serde(default)]
    metadata: Option<Value>,
}

#[derive(Debug, Serialize)]
struct RuntimeRegisterResponse {
    endpoint_agent_id: String,
    runtime_agent_id: String,
    runtime_agent_kind: String,
    external_runtime_id: Option<String>,
    first_seen_at: String,
    last_seen_at: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct AgentSettingsUpdate {
    enabled: Option<bool>,
    auto_start: Option<bool>,
    notifications_enabled: Option<bool>,
    notification_severity: Option<String>,
    dashboard_url: Option<String>,
    debug_include_daemon_error_body: Option<bool>,
    ota_enabled: Option<bool>,
    ota_mode: Option<String>,
    ota_channel: Option<String>,
    ota_manifest_url: Option<Option<String>>,
    ota_allow_fallback_to_default: Option<bool>,
    ota_check_interval_minutes: Option<u32>,
    ota_pinned_public_keys: Option<Vec<String>>,
    ota_last_check_at: Option<Option<String>>,
    ota_last_result: Option<Option<String>>,
    ota_current_hushd_version: Option<Option<String>>,
    control_api: Option<ControlApiSettingsUpdate>,
    #[serde(default, deserialize_with = "deserialize_optional_string_field")]
    openclaw_active_gateway_id: Option<Option<String>>,
    local_api_security: Option<LocalApiSecurityUpdate>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ControlApiSettingsUpdate {
    enabled: Option<bool>,
    url: Option<Option<String>>,
    api_key: Option<Option<String>>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct LocalApiSecurityUpdate {
    token_rotation_interval_hours: Option<u32>,
    token_grace_minutes: Option<u32>,
    mtls_enabled: Option<bool>,
    mtls_port: Option<u16>,
    mtls_server_cert_path: Option<Option<String>>,
    mtls_server_key_path: Option<Option<String>>,
    mtls_client_ca_path: Option<Option<String>>,
}

#[derive(Debug, Deserialize)]
struct GatewayPatchInput {
    label: Option<String>,
    gateway_url: Option<String>,
    token: Option<String>,
    device_token: Option<String>,
}

#[derive(Debug, Deserialize)]
struct ActiveGatewayUpdateInput {
    active_gateway_id: Option<String>,
}

#[derive(Debug, Deserialize)]
struct IntegrationsSettingsUpdateInput {
    #[serde(default)]
    siem: Option<SiemIntegrationUpdateInput>,
    #[serde(default)]
    webhooks: Option<WebhookIntegrationUpdateInput>,
    #[serde(default = "default_apply_integrations_changes")]
    apply: bool,
}

#[derive(Debug, Deserialize)]
struct SiemIntegrationUpdateInput {
    provider: Option<String>,
    endpoint: Option<String>,
    api_key: Option<String>,
    enabled: Option<bool>,
}

#[derive(Debug, Deserialize)]
struct WebhookIntegrationUpdateInput {
    url: Option<String>,
    secret: Option<String>,
    enabled: Option<bool>,
}

#[derive(Debug, Serialize)]
struct IntegrationsApplyResponse {
    integrations: IntegrationSettings,
    restarted: bool,
    daemon: DaemonStatus,
    exporter_status: Option<Value>,
    warning: Option<String>,
}

#[derive(Debug, Deserialize)]
struct IntegrationTestInput {
    target: String,
    #[serde(default)]
    max_retries: Option<u8>,
}

#[derive(Debug, Serialize)]
struct IntegrationTestResponse {
    target: String,
    endpoint: String,
    delivered: bool,
    status_code: Option<u16>,
    attempts: u8,
    retry_count: u8,
    latency_ms: u64,
    last_error: Option<String>,
    tested_at: String,
}

#[derive(Debug, Serialize)]
struct RotateLocalApiTokenResponse {
    rotated: bool,
    previous_token_valid_for_seconds: u64,
}

#[derive(Debug, Deserialize, Default)]
struct DiagnosticsBundleInput {
    #[serde(default)]
    include_logs: Option<bool>,
    #[serde(default)]
    log_lines: Option<usize>,
}

#[derive(Debug, Serialize)]
struct DiagnosticsBundleResponse {
    bundle_path: String,
    generated_at: String,
}

// identity_filter_matches moved to crate::edr::queries::causal

// PendingFindingGroup moved to crate::edr::queries::finding_groups

#[derive(Debug, Serialize)]
struct AgentPolicyCheckResponse {
    #[serde(flatten)]
    decision: PolicyCheckOutput,
    receipt: SignedReceipt,
}

// PendingGraphSearchMatch moved to crate::edr::queries::graph_search

pub(crate) async fn response_execution_record_with_attribution(
    state: &AgentApiState,
    execution: EndpointResponseExecutionReport,
) -> Result<EdrResponseExecutionRecord, (StatusCode, String)> {
    let mut records = response_execution_records_with_attribution(state, vec![execution]).await?;
    records
        .pop()
        .ok_or_else(|| internal_error(anyhow::anyhow!("missing response execution record")))
}

pub(crate) async fn response_execution_records_with_attribution(
    state: &AgentApiState,
    executions: Vec<EndpointResponseExecutionReport>,
) -> Result<Vec<EdrResponseExecutionRecord>, (StatusCode, String)> {
    let mut records = executions
        .into_iter()
        .map(EdrResponseExecutionRecord::from_execution)
        .collect::<Vec<_>>();
    hydrate_response_execution_record_attribution(state, &mut records).await?;
    Ok(records)
}

async fn hydrate_response_execution_record_attribution(
    state: &AgentApiState,
    records: &mut [EdrResponseExecutionRecord],
) -> Result<(), (StatusCode, String)> {
    let mut store = state.edr_evidence_bundle_store.lock().await;
    for record in records {
        let bundle_id = record.execution.evidence_bundle.bundle_id.as_str();
        match store.load(bundle_id) {
            Ok(Some(stored)) => record.hydrate_attribution(&stored.graph),
            Ok(None) => {}
            Err(err) => {
                tracing::warn!(
                    error = %err,
                    bundle_id,
                    execution_id = %record.execution.execution_id,
                    "failed to load response execution attribution bundle"
                );
            }
        }
    }
    Ok(())
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(default, rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct StoredEndpointEvidenceBundle {
    pub(crate) bundle: EndpointEvidenceBundleReference,
    pub(crate) path: Option<String>,
    pub(crate) byte_count: usize,
    pub(crate) graph: CausalGraph,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub(crate) struct ControlStoreReceiptRequest {
    pub(crate) timestamp: String,
    pub(crate) verdict: String,
    pub(crate) guard: String,
    pub(crate) policy_name: String,
    pub(crate) signature: String,
    pub(crate) public_key: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) chain_hash: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) evidence: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) metadata: Option<serde_json::Value>,
    pub(crate) signed_receipt: serde_json::Value,
}

#[derive(Debug, Serialize, Deserialize)]
pub(crate) struct ControlBatchStoreReceiptsRequest {
    pub(crate) receipts: Vec<ControlStoreReceiptRequest>,
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(default, rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct EndpointReceiptIndexRecord {
    pub(crate) receipt_id: Option<String>,
    pub(crate) timestamp: String,
    pub(crate) family: Option<String>,
    pub(crate) action: Option<String>,
    pub(crate) finding_id: Option<String>,
    pub(crate) rule_id: Option<String>,
    pub(crate) graph_slice_id: Option<String>,
    pub(crate) root_node_id: Option<String>,
    pub(crate) execution_id: Option<String>,
    pub(crate) execution_status: Option<String>,
    pub(crate) actor_endpoint_id: Option<String>,
    pub(crate) actor_user_id: Option<String>,
    pub(crate) actor_session_id: Option<String>,
    pub(crate) actor_agent_id: Option<String>,
    pub(crate) actor_workload_id: Option<String>,
    pub(crate) actor_approval_id: Option<String>,
    pub(crate) local_sequence: Option<u64>,
    pub(crate) byte_offset: u64,
    pub(crate) byte_len: u64,
}

fn default_apply_integrations_changes() -> bool {
    true
}

fn resolve_endpoint_agent_id_for_health(settings: &Settings) -> String {
    settings
        .nats
        .agent_id
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToString::to_string)
        .or_else(|| {
            settings
                .enrollment
                .agent_uuid
                .as_deref()
                .map(str::trim)
                .filter(|value| !value.is_empty())
                .map(ToString::to_string)
        })
        .or_else(|| {
            settings
                .local_agent_id
                .as_deref()
                .map(str::trim)
                .filter(|value| !value.is_empty())
                .map(ToString::to_string)
        })
        .unwrap_or_else(|| format!("endpoint-{}", crate::settings::hostname_best_effort()))
}

async fn fetch_daemon_endpoint_status_for_health(
    state: &Arc<AgentApiState>,
    settings: &Settings,
    endpoint_agent_id: &str,
    expected_policy_version: Option<&str>,
    expected_daemon_version: Option<&str>,
) -> Option<DaemonEndpointStatus> {
    let mut url =
        reqwest::Url::parse(&format!("{}/api/v1/agents/status", settings.daemon_url())).ok()?;
    {
        let mut query = url.query_pairs_mut();
        query.append_pair("endpoint_agent_id", endpoint_agent_id);
        query.append_pair("limit", "1");
        query.append_pair("include_stale", "true");
        if let Some(policy_version) = expected_policy_version {
            query.append_pair("expected_policy_version", policy_version);
        }
        if let Some(daemon_version) = expected_daemon_version {
            query.append_pair("expected_daemon_version", daemon_version);
        }
    }

    let mut request = state.http_client.get(url);
    if let Some(api_key) = settings
        .api_key
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
    {
        request = request.header(AUTHORIZATION.as_str(), format!("Bearer {}", api_key));
    }

    let response = request.send().await.ok()?;
    if !response.status().is_success() {
        return None;
    }

    let payload = response.json::<DaemonAgentStatusResponse>().await.ok()?;
    payload.endpoints.into_iter().next()
}

fn redact_settings_json(raw: &mut Value) {
    let Some(obj) = raw.as_object_mut() else {
        return;
    };

    for key in [
        "api_key",
        "token",
        "nkey_seed",
        "enrollment_token",
        "secret",
    ] {
        if let Some(value) = obj.get_mut(key) {
            *value = Value::String("[REDACTED]".to_string());
        }
    }

    if let Some(integrations) = obj.get_mut("integrations").and_then(Value::as_object_mut) {
        if let Some(siem) = integrations.get_mut("siem").and_then(Value::as_object_mut) {
            if let Some(value) = siem.get_mut("api_key") {
                *value = Value::String("[REDACTED]".to_string());
            }
        }
        if let Some(webhooks) = integrations
            .get_mut("webhooks")
            .and_then(Value::as_object_mut)
        {
            if let Some(value) = webhooks.get_mut("secret") {
                *value = Value::String("[REDACTED]".to_string());
            }
        }
    }

    if let Some(control_api) = obj.get_mut("control_api").and_then(Value::as_object_mut) {
        if let Some(value) = control_api.get_mut("api_key") {
            *value = Value::String("[REDACTED]".to_string());
        }
    }

    if let Some(nats) = obj.get_mut("nats").and_then(Value::as_object_mut) {
        for key in ["token", "nkey_seed", "creds_file"] {
            if let Some(value) = nats.get_mut(key) {
                *value = Value::String("[REDACTED]".to_string());
            }
        }
    }
}

fn trim_tail_lines(content: &str, lines: usize) -> String {
    if lines == 0 {
        return String::new();
    }
    let mut collected = content.lines().rev().take(lines).collect::<Vec<_>>();
    collected.reverse();
    collected.join("\n")
}

async fn write_diagnostics_bundle(
    state: Arc<AgentApiState>,
    input: DiagnosticsBundleInput,
) -> Result<DiagnosticsBundleResponse, (StatusCode, String)> {
    let include_logs = input.include_logs.unwrap_or(true);
    let log_lines = input.log_lines.unwrap_or(500).clamp(10, 5000);
    let settings_snapshot = state.settings.read().await.clone();
    let daemon_status = state.daemon_manager.status().await;
    let session_state = state.session_manager.state().await;
    let audit_queue_depth = state.audit_queue.len().await;
    let pending_approvals = state.approval_queue.pending_count().await;
    let last_policy_version = cached_policy_version_for_health(&state).await;
    let runtime_agents = settings_snapshot.runtime_registry.runtimes.clone();

    let mut settings_json = serde_json::to_value(&settings_snapshot)
        .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
    redact_settings_json(&mut settings_json);

    let daemon_url = settings_snapshot.daemon_url();
    let mut health_request = state.http_client.get(format!("{}/health", daemon_url));
    if let Some(api_key) = settings_snapshot
        .api_key
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
    {
        health_request =
            health_request.header(AUTHORIZATION.as_str(), format!("Bearer {}", api_key));
    }
    let daemon_health = match health_request.send().await {
        Ok(response) => {
            let status = response.status().as_u16();
            let body = response.text().await.unwrap_or_default();
            serde_json::json!({
                "reachable": status < 500,
                "status_code": status,
                "body_preview": trim_tail_lines(&body, 20),
            })
        }
        Err(err) => serde_json::json!({
            "reachable": false,
            "error": err.to_string(),
        }),
    };

    let diagnostics_root = crate::settings::get_config_dir().join("diagnostics");
    let generated_at = chrono::Utc::now();
    let bundle_dir =
        diagnostics_root.join(format!("bundle-{}", generated_at.format("%Y%m%dT%H%M%SZ")));
    let bundle_dir_for_write = bundle_dir.clone();
    let manifest = serde_json::json!({
        "generated_at": generated_at.to_rfc3339(),
        "agent_version": env!("CARGO_PKG_VERSION"),
        "bundle_dir": bundle_dir.display().to_string(),
    });
    let connectivity = serde_json::json!({
        "daemon_health": daemon_health,
        "session": {
            "session_id": session_state.session_id,
            "posture": session_state.posture,
        },
    });
    let version_matrix = serde_json::json!({
        "agent_version": env!("CARGO_PKG_VERSION"),
        "daemon_version": daemon_status.version,
        "last_policy_version": last_policy_version,
        "runtime_registry_count": runtime_agents.len(),
    });
    let queue_state = serde_json::json!({
        "audit_outbox_depth": audit_queue_depth,
        "pending_approvals": pending_approvals,
    });

    let agent_log_path = crate::settings::get_config_dir()
        .join("logs")
        .join("agent.log");
    let hushd_log_path = crate::settings::get_config_dir()
        .join("logs")
        .join("hushd.log");
    let agent_log = if include_logs {
        std::fs::read_to_string(&agent_log_path)
            .map(|content| trim_tail_lines(&content, log_lines))
            .unwrap_or_else(|_| "agent.log unavailable".to_string())
    } else {
        "logs omitted by request".to_string()
    };
    let hushd_log = if include_logs {
        std::fs::read_to_string(&hushd_log_path)
            .map(|content| trim_tail_lines(&content, log_lines))
            .unwrap_or_else(|_| "hushd.log unavailable".to_string())
    } else {
        "logs omitted by request".to_string()
    };

    tokio::task::spawn_blocking(move || -> Result<(), (StatusCode, String)> {
        std::fs::create_dir_all(bundle_dir_for_write.join("logs"))
            .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
        std::fs::write(
            bundle_dir_for_write.join("manifest.json"),
            serde_json::to_vec_pretty(&manifest)
                .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?,
        )
        .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
        std::fs::write(
            bundle_dir_for_write.join("settings.redacted.json"),
            serde_json::to_vec_pretty(&settings_json)
                .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?,
        )
        .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
        std::fs::write(
            bundle_dir_for_write.join("runtime_registry.json"),
            serde_json::to_vec_pretty(&runtime_agents)
                .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?,
        )
        .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
        std::fs::write(
            bundle_dir_for_write.join("connectivity_checks.json"),
            serde_json::to_vec_pretty(&connectivity)
                .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?,
        )
        .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
        std::fs::write(
            bundle_dir_for_write.join("version_matrix.json"),
            serde_json::to_vec_pretty(&version_matrix)
                .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?,
        )
        .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
        std::fs::write(
            bundle_dir_for_write.join("queue_state.json"),
            serde_json::to_vec_pretty(&queue_state)
                .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?,
        )
        .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
        std::fs::write(
            bundle_dir_for_write.join("logs").join("agent.tail.log"),
            agent_log,
        )
        .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
        std::fs::write(
            bundle_dir_for_write.join("logs").join("hushd.tail.log"),
            hushd_log,
        )
        .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
        Ok(())
    })
    .await
    .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))??;

    Ok(DiagnosticsBundleResponse {
        bundle_path: bundle_dir.display().to_string(),
        generated_at: generated_at.to_rfc3339(),
    })
}

async fn create_diagnostics_bundle(
    State(state): State<Arc<AgentApiState>>,
    headers: HeaderMap,
    payload: Option<Json<DiagnosticsBundleInput>>,
) -> Result<Json<DiagnosticsBundleResponse>, (StatusCode, String)> {
    require_auth(&headers, &state)?;
    let input = payload.map(|value| value.0).unwrap_or_default();
    let response = write_diagnostics_bundle(state, input).await?;
    Ok(Json(response))
}

async fn agent_health(
    State(state): State<Arc<AgentApiState>>,
    headers: HeaderMap,
) -> Result<Json<AgentHealthResponse>, (StatusCode, String)> {
    require_auth(&headers, &state)?;
    let settings_snapshot = state.settings.read().await.clone();
    let endpoint_agent_id = resolve_endpoint_agent_id_for_health(&settings_snapshot);
    let daemon = state.daemon_manager.status().await;
    let session = state.session_manager.state().await;
    let openclaw = state.openclaw.list_gateways().await;
    let runtime_agents = settings_snapshot.runtime_registry.runtimes.len();
    let last_policy_version = cached_policy_version_for_health(&state).await;
    let macos_host = state.macos_host.snapshot().await;
    let edr = edr_health_summary(&state).await;
    let daemon_status = fetch_daemon_endpoint_status_for_health(
        &state,
        &settings_snapshot,
        &endpoint_agent_id,
        last_policy_version.as_deref(),
        daemon.version.as_deref(),
    )
    .await;
    let (last_heartbeat_at, heartbeat_age_secs, endpoint_online, policy_drift, daemon_drift, stale) =
        if let Some(status) = daemon_status {
            (
                status.last_heartbeat_at,
                status.seconds_since_heartbeat,
                status.online,
                status.drift.as_ref().and_then(|value| value.policy_drift),
                status.drift.as_ref().and_then(|value| value.daemon_drift),
                status.drift.as_ref().and_then(|value| value.stale),
            )
        } else {
            (None, None, None, None, None, None)
        };

    Ok(Json(AgentHealthResponse {
        status: agent_health_status(&macos_host),
        daemon,
        session,
        macos_host,
        edr,
        openclaw: serde_json::to_value(openclaw)
            .unwrap_or_else(|_| serde_json::json!({"error":"serialize_failed"})),
        runtime_agents,
        last_policy_version,
        endpoint_agent_id,
        last_heartbeat_at,
        heartbeat_age_secs,
        endpoint_online,
        policy_drift,
        daemon_drift,
        stale,
        version: env!("CARGO_PKG_VERSION"),
    }))
}

async fn get_settings(
    State(state): State<Arc<AgentApiState>>,
    headers: HeaderMap,
) -> Result<Json<AgentSettingsResponse>, (StatusCode, String)> {
    require_auth(&headers, &state)?;
    let settings = state.settings.read().await;

    Ok(Json(AgentSettingsResponse {
        daemon_port: settings.daemon_port,
        mcp_port: settings.mcp_port,
        agent_api_port: settings.agent_api_port,
        enabled: settings.enabled,
        auto_start: settings.auto_start,
        notifications_enabled: settings.notifications_enabled,
        notification_severity: settings.notification_severity.clone(),
        dashboard_url: settings.dashboard_url.clone(),
        debug_include_daemon_error_body: settings.debug_include_daemon_error_body,
        openclaw_active_gateway_id: settings.openclaw.active_gateway_id.clone(),
        ota_enabled: settings.ota_enabled,
        ota_mode: settings.ota_mode.clone(),
        ota_channel: settings.ota_channel.clone(),
        ota_manifest_url: settings.ota_manifest_url.clone(),
        ota_allow_fallback_to_default: settings.ota_allow_fallback_to_default,
        ota_check_interval_minutes: settings.ota_check_interval_minutes,
        ota_pinned_public_keys: settings.ota_pinned_public_keys.clone(),
        ota_last_check_at: settings.ota_last_check_at.clone(),
        ota_last_result: settings.ota_last_result.clone(),
        ota_current_hushd_version: settings.ota_current_hushd_version.clone(),
        control_api: ControlApiSettingsResponse {
            enabled: settings.control_api.enabled,
            url: settings.control_api.url.clone(),
            api_key_configured: settings
                .control_api
                .api_key
                .as_deref()
                .map(str::trim)
                .is_some_and(|value| !value.is_empty()),
        },
        local_api_security: LocalApiSecurityResponse {
            token_rotation_interval_hours: settings
                .local_api_security
                .token_rotation_interval_hours,
            token_grace_minutes: settings.local_api_security.token_grace_minutes,
            mtls_enabled: settings.local_api_security.mtls_enabled,
            mtls_port: settings.local_api_security.mtls_port,
            mtls_server_cert_path: settings
                .local_api_security
                .mtls_server_cert_path
                .as_ref()
                .map(|path| path.display().to_string()),
            mtls_server_key_path: settings
                .local_api_security
                .mtls_server_key_path
                .as_ref()
                .map(|path| path.display().to_string()),
            mtls_client_ca_path: settings
                .local_api_security
                .mtls_client_ca_path
                .as_ref()
                .map(|path| path.display().to_string()),
        },
    }))
}

async fn list_runtime_agents(
    State(state): State<Arc<AgentApiState>>,
    headers: HeaderMap,
) -> Result<Json<Vec<RuntimeAgentRegistration>>, (StatusCode, String)> {
    require_auth(&headers, &state)?;
    let mut runtimes = {
        let settings = state.settings.read().await;
        settings.runtime_registry.runtimes.clone()
    };
    runtimes.sort_by(|a, b| b.last_seen_at.cmp(&a.last_seen_at));
    Ok(Json(runtimes))
}

async fn register_runtime_agent_route(
    State(state): State<Arc<AgentApiState>>,
    headers: HeaderMap,
    Json(input): Json<RuntimeRegisterInput>,
) -> Result<Json<RuntimeRegisterResponse>, (StatusCode, String)> {
    require_auth(&headers, &state)?;

    if input.runtime_agent_kind.trim().is_empty() {
        return Err((
            StatusCode::BAD_REQUEST,
            "runtime_agent_kind must be a non-empty string".to_string(),
        ));
    }

    let registration = {
        let mut settings = state.settings.write().await;
        let endpoint_agent_id =
            resolve_effective_endpoint_agent_id(&mut settings, input.endpoint_agent_id.as_deref());
        let registration = register_runtime_agent(
            &mut settings,
            RuntimeRegistrationInput {
                endpoint_agent_id,
                runtime_agent_kind: input.runtime_agent_kind.clone(),
                external_runtime_id: input.runtime_agent_id.clone(),
                display_name: input.display_name,
                metadata: input.metadata,
            },
        );
        settings
            .save()
            .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
        registration
    };

    Ok(Json(RuntimeRegisterResponse {
        endpoint_agent_id: registration.endpoint_agent_id,
        runtime_agent_id: registration.runtime_agent_id,
        runtime_agent_kind: registration.runtime_agent_kind,
        external_runtime_id: registration.external_runtime_id,
        first_seen_at: registration.first_seen_at,
        last_seen_at: registration.last_seen_at,
    }))
}

async fn update_settings(
    State(state): State<Arc<AgentApiState>>,
    headers: HeaderMap,
    Json(input): Json<AgentSettingsUpdate>,
) -> Result<Json<AgentSettingsResponse>, (StatusCode, String)> {
    require_auth(&headers, &state)?;

    {
        let mut settings = state.settings.write().await;
        let mut next_settings = settings.clone();

        if let Some(value) = input.enabled {
            next_settings.enabled = value;
        }
        if let Some(value) = input.auto_start {
            next_settings.auto_start = value;
        }
        if let Some(value) = input.notifications_enabled {
            next_settings.notifications_enabled = value;
        }
        if let Some(value) = input.notification_severity {
            next_settings.notification_severity = normalize_notification_severity_setting(&value)?;
        }
        if let Some(value) = input.dashboard_url {
            next_settings.dashboard_url = normalize_settings_url("dashboard_url", &value, true)?;
        }
        if let Some(value) = input.debug_include_daemon_error_body {
            next_settings.debug_include_daemon_error_body = value;
        }
        if let Some(value) = input.ota_enabled {
            next_settings.ota_enabled = value;
        }
        if let Some(value) = input.ota_mode {
            next_settings.ota_mode = normalize_ota_mode_setting(&value)?;
        }
        if let Some(value) = input.ota_channel {
            next_settings.ota_channel = normalize_ota_channel_setting(&value)?;
        }
        if let Some(value) = input.ota_manifest_url {
            next_settings.ota_manifest_url = value
                .as_deref()
                .map(|url| normalize_settings_url("ota_manifest_url", url, false))
                .transpose()?;
        }
        if let Some(value) = input.ota_allow_fallback_to_default {
            next_settings.ota_allow_fallback_to_default = value;
        }
        if let Some(value) = input.ota_check_interval_minutes {
            next_settings.ota_check_interval_minutes = bounded_u32_setting(
                "ota_check_interval_minutes",
                value,
                OTA_CHECK_INTERVAL_MIN_MINUTES,
                OTA_CHECK_INTERVAL_MAX_MINUTES,
            )?;
        }
        if let Some(value) = input.ota_pinned_public_keys {
            next_settings.ota_pinned_public_keys = value;
        }
        if let Some(value) = input.ota_last_check_at {
            next_settings.ota_last_check_at = value;
        }
        if let Some(value) = input.ota_last_result {
            next_settings.ota_last_result = value;
        }
        if let Some(value) = input.ota_current_hushd_version {
            next_settings.ota_current_hushd_version = value;
        }
        if let Some(control_api) = input.control_api {
            if let Some(value) = control_api.enabled {
                next_settings.control_api.enabled = value;
            }
            if let Some(value) = control_api.url {
                next_settings.control_api.url = value
                    .as_deref()
                    .map(|url| normalize_settings_url("control_api.url", url, false))
                    .transpose()?;
            }
            if let Some(value) = control_api.api_key {
                next_settings.control_api.api_key = value
                    .map(|api_key| api_key.trim().to_string())
                    .filter(|api_key| !api_key.is_empty());
            }
        }
        if let Some(value) = input.openclaw_active_gateway_id {
            next_settings.openclaw.active_gateway_id = value;
        }
        if let Some(local_api_security) = input.local_api_security {
            if let Some(value) = local_api_security.token_rotation_interval_hours {
                next_settings
                    .local_api_security
                    .token_rotation_interval_hours = bounded_u32_setting(
                    "local_api_security.token_rotation_interval_hours",
                    value,
                    LOCAL_API_TOKEN_ROTATION_MIN_HOURS,
                    LOCAL_API_TOKEN_ROTATION_MAX_HOURS,
                )?;
            }
            if let Some(value) = local_api_security.token_grace_minutes {
                next_settings.local_api_security.token_grace_minutes = bounded_u32_setting(
                    "local_api_security.token_grace_minutes",
                    value,
                    LOCAL_API_TOKEN_GRACE_MIN_MINUTES,
                    LOCAL_API_TOKEN_GRACE_MAX_MINUTES,
                )?;
            }
            if let Some(value) = local_api_security.mtls_enabled {
                next_settings.local_api_security.mtls_enabled = value;
            }
            if let Some(value) = local_api_security.mtls_port {
                next_settings.local_api_security.mtls_port = bounded_u16_setting(
                    "local_api_security.mtls_port",
                    value,
                    LOCAL_API_MTLS_MIN_PORT,
                    u16::MAX,
                )?;
            }
            if let Some(value) = local_api_security.mtls_server_cert_path {
                next_settings.local_api_security.mtls_server_cert_path = value
                    .as_deref()
                    .map(str::trim)
                    .filter(|raw| !raw.is_empty())
                    .map(PathBuf::from);
            }
            if let Some(value) = local_api_security.mtls_server_key_path {
                next_settings.local_api_security.mtls_server_key_path = value
                    .as_deref()
                    .map(str::trim)
                    .filter(|raw| !raw.is_empty())
                    .map(PathBuf::from);
            }
            if let Some(value) = local_api_security.mtls_client_ca_path {
                next_settings.local_api_security.mtls_client_ca_path = value
                    .as_deref()
                    .map(str::trim)
                    .filter(|raw| !raw.is_empty())
                    .map(PathBuf::from);
            }

            if next_settings.local_api_security.mtls_enabled {
                let cert = next_settings
                    .local_api_security
                    .mtls_server_cert_path
                    .as_ref()
                    .is_some_and(|path| path.is_file());
                let key = next_settings
                    .local_api_security
                    .mtls_server_key_path
                    .as_ref()
                    .is_some_and(|path| path.is_file());
                let ca = next_settings
                    .local_api_security
                    .mtls_client_ca_path
                    .as_ref()
                    .is_some_and(|path| path.is_file());
                if !(cert && key && ca) {
                    return Err((
                        StatusCode::BAD_REQUEST,
                        "mTLS enabled requires valid cert/key/CA file paths".to_string(),
                    ));
                }
            }
        }

        require_enrolled_edr_receipt_signer_for_settings(
            &state,
            &next_settings,
            "settings update enabling cloud/control EDR mode",
        )
        .await?;

        next_settings
            .save()
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

        let token_grace_minutes = next_settings.local_api_security.token_grace_minutes.max(1);
        *settings = next_settings;
        set_token_grace_minutes(&state, token_grace_minutes);
    }

    get_settings(State(state), headers).await
}

async fn get_integrations_settings(
    State(state): State<Arc<AgentApiState>>,
    headers: HeaderMap,
) -> Result<Json<IntegrationSettings>, (StatusCode, String)> {
    require_auth(&headers, &state)?;
    let settings = state.settings.read().await;
    Ok(Json(settings.integrations.clone()))
}

async fn update_integrations_settings(
    State(state): State<Arc<AgentApiState>>,
    headers: HeaderMap,
    Json(input): Json<IntegrationsSettingsUpdateInput>,
) -> Result<Json<IntegrationsApplyResponse>, (StatusCode, String)> {
    require_auth(&headers, &state)?;
    {
        let mut settings = state.settings.write().await;
        let mut next_integrations = settings.integrations.clone();

        if let Some(siem) = input.siem {
            if let Some(value) = siem.provider {
                next_integrations.siem.provider = value;
            }
            if let Some(value) = siem.endpoint {
                next_integrations.siem.endpoint = value;
            }
            if let Some(value) = siem.api_key {
                next_integrations.siem.api_key = value;
            }
            if let Some(value) = siem.enabled {
                next_integrations.siem.enabled = value;
            }
        }

        if let Some(webhooks) = input.webhooks {
            if let Some(value) = webhooks.url {
                next_integrations.webhooks.url = value;
            }
            if let Some(value) = webhooks.secret {
                next_integrations.webhooks.secret = value;
            }
            if let Some(value) = webhooks.enabled {
                next_integrations.webhooks.enabled = value;
            }
        }

        normalize_integration_settings(&mut next_integrations);
        validate_integration_settings(&next_integrations)
            .map_err(|err| (StatusCode::BAD_REQUEST, err))?;
        settings.integrations = next_integrations;

        settings
            .save()
            .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
    }

    let mut restarted = false;
    let mut warning = None;

    if input.apply {
        state
            .daemon_manager
            .restart()
            .await
            .map_err(internal_error)?;
        restarted = true;
    }

    let daemon = state.daemon_manager.status().await;
    let exporter_status = fetch_daemon_exporter_status(&state).await;
    let integrations = {
        let settings = state.settings.read().await;
        settings.integrations.clone()
    };
    if input.apply {
        if exporter_status.is_none() {
            warning = Some("hushd restarted but exporter status could not be fetched".to_string());
        } else {
            let export_enabled = exporter_status
                .as_ref()
                .and_then(|v| v.get("enabled"))
                .and_then(|v| v.as_bool())
                .unwrap_or(false);
            let exporter_count = exporter_status
                .as_ref()
                .and_then(|v| v.get("exporters"))
                .and_then(|v| v.as_array())
                .map(|v| v.len())
                .unwrap_or(0);

            let expected_exporters = integrations.siem.enabled || integrations.webhooks.enabled;
            if expected_exporters && (!export_enabled || exporter_count == 0) {
                warning = Some(
                    "Integration settings were saved, but hushd reports no active exporters after restart."
                        .to_string(),
                );
            }
        }
    }

    Ok(Json(IntegrationsApplyResponse {
        integrations,
        restarted,
        daemon,
        exporter_status,
        warning,
    }))
}

pub(crate) fn truncate_delivery_error(message: &str) -> String {
    const MAX_LEN: usize = 240;
    if message.chars().count() <= MAX_LEN {
        return message.to_string();
    }
    let mut out = message
        .chars()
        .take(MAX_LEN.saturating_sub(3))
        .collect::<String>();
    out.push_str("...");
    out
}

async fn test_integration_delivery(
    State(state): State<Arc<AgentApiState>>,
    headers: HeaderMap,
    Json(input): Json<IntegrationTestInput>,
) -> Result<Json<IntegrationTestResponse>, (StatusCode, String)> {
    require_auth(&headers, &state)?;

    let target = input.target.trim().to_ascii_lowercase();
    let max_retries = input.max_retries.unwrap_or(2).min(5);

    let (endpoint, enabled, provider, siem_api_key, webhook_secret, agent_id) = {
        let settings = state.settings.read().await;
        let integrations = &settings.integrations;
        let endpoint_agent_id = settings
            .local_agent_id
            .clone()
            .filter(|value| !value.trim().is_empty())
            .unwrap_or_else(|| "unknown-agent".to_string());

        match target.as_str() {
            "siem" => (
                integrations.siem.endpoint.clone(),
                integrations.siem.enabled,
                integrations.siem.provider.clone(),
                integrations.siem.api_key.clone(),
                String::new(),
                endpoint_agent_id,
            ),
            "webhook" | "webhooks" => (
                integrations.webhooks.url.clone(),
                integrations.webhooks.enabled,
                "webhook".to_string(),
                String::new(),
                integrations.webhooks.secret.clone(),
                endpoint_agent_id,
            ),
            other => {
                return Err((
                    StatusCode::BAD_REQUEST,
                    format!("unsupported test target '{}'", other),
                ))
            }
        }
    };

    if !enabled {
        return Err((
            StatusCode::BAD_REQUEST,
            format!("{} delivery is disabled", target),
        ));
    }

    if endpoint.trim().is_empty() {
        return Err((
            StatusCode::BAD_REQUEST,
            format!("{} endpoint is empty", target),
        ));
    }

    let normalized_endpoint = endpoint.trim().to_string();
    let payload = serde_json::json!({
        "event_type": "integration_test_delivery",
        "target": target,
        "provider": provider,
        "timestamp": chrono::Utc::now().to_rfc3339(),
        "endpoint_agent_id": agent_id,
        "message": "ClawdStrike integration delivery test event"
    });
    let payload_bytes = serde_json::to_vec(&payload).map_err(|err| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("failed to serialize test payload: {err}"),
        )
    })?;

    let started_at = Instant::now();
    let tested_at = chrono::Utc::now().to_rfc3339();
    let mut attempts: u8 = 0;
    let mut status_code: Option<u16> = None;
    let mut last_error: Option<String> = None;
    let mut delivered = false;

    for attempt in 0..=max_retries {
        attempts = attempt + 1;

        let mut request = state
            .http_client
            .post(normalized_endpoint.clone())
            .header(CONTENT_TYPE, "application/json")
            .header("x-clawdstrike-test-delivery", "1")
            .body(payload_bytes.clone());

        if target == "siem" && !siem_api_key.is_empty() {
            let auth_header = if provider.trim().eq_ignore_ascii_case("splunk") {
                format!("Splunk {}", siem_api_key)
            } else {
                format!("Bearer {}", siem_api_key)
            };
            request = request
                .header(AUTHORIZATION, auth_header)
                .header("dd-api-key", siem_api_key.clone());
        }

        if target.starts_with("webhook") && !webhook_secret.is_empty() {
            request = request
                .header("x-clawdstrike-secret-configured", "true")
                .header("x-clawdstrike-signature-scheme", "hmac-sha256");
        }

        match request.send().await {
            Ok(response) => {
                let status = response.status();
                status_code = Some(status.as_u16());
                if status.is_success() {
                    delivered = true;
                    last_error = None;
                    break;
                }
                let body = response.text().await.unwrap_or_default();
                let reason = if body.trim().is_empty() {
                    format!("HTTP {}", status.as_u16())
                } else {
                    format!("HTTP {}: {}", status.as_u16(), body.trim())
                };
                last_error = Some(truncate_delivery_error(&reason));
            }
            Err(err) => {
                last_error = Some(truncate_delivery_error(&err.to_string()));
            }
        }

        if attempt < max_retries {
            let backoff_ms = 250u64.saturating_mul((attempt + 1) as u64);
            tokio::time::sleep(Duration::from_millis(backoff_ms)).await;
        }
    }

    let elapsed_ms_u128 = started_at.elapsed().as_millis();
    let latency_ms = elapsed_ms_u128.min(u128::from(u64::MAX)) as u64;

    Ok(Json(IntegrationTestResponse {
        target: if target == "webhooks" {
            "webhook".to_string()
        } else {
            target
        },
        endpoint: normalized_endpoint,
        delivered,
        status_code,
        attempts,
        retry_count: attempts.saturating_sub(1),
        latency_ms,
        last_error,
        tested_at,
    }))
}

async fn get_ota_status(
    State(state): State<Arc<AgentApiState>>,
    headers: HeaderMap,
) -> Result<Json<OtaStatus>, (StatusCode, String)> {
    require_auth(&headers, &state)?;
    Ok(Json(state.updater.status().await))
}

async fn trigger_ota_check(
    State(state): State<Arc<AgentApiState>>,
    headers: HeaderMap,
) -> Result<Json<OtaStatus>, (StatusCode, String)> {
    require_auth(&headers, &state)?;
    state
        .updater
        .check_now()
        .await
        .map(Json)
        .map_err(internal_error)
}

async fn trigger_ota_apply(
    State(state): State<Arc<AgentApiState>>,
    headers: HeaderMap,
) -> Result<Json<OtaStatus>, (StatusCode, String)> {
    require_auth(&headers, &state)?;
    state
        .updater
        .apply_now()
        .await
        .map(Json)
        .map_err(internal_error)
}

async fn agent_policy_check(
    State(state): State<Arc<AgentApiState>>,
    headers: HeaderMap,
    Json(input): Json<PolicyCheckInput>,
) -> Result<Json<AgentPolicyCheckResponse>, (StatusCode, String)> {
    require_auth(&headers, &state)?;
    let session_id = state.session_manager.session_id().await;
    let receipt_input = input.clone();
    let output = match active_egress_restriction_for_policy_check(&state, &receipt_input).await {
        Some(restriction) => policy_output_for_active_egress_restriction(&restriction),
        None => {
            evaluate_policy_check(
                state.settings.clone(),
                &state.http_client,
                input,
                session_id.clone(),
                Some(state.audit_queue.clone()),
            )
            .await
        }
    };
    let receipt =
        emit_edr_policy_decision_receipt(&state, &receipt_input, &output, session_id.as_deref())
            .await
            .map_err(internal_error)?;
    Ok(Json(AgentPolicyCheckResponse {
        decision: output,
        receipt,
    }))
}

pub(crate) fn local_stable_id<'a>(
    prefix: &str,
    parts: impl IntoIterator<Item = &'a str>,
) -> String {
    let mut material = String::from(prefix);
    for part in parts {
        material.push('\0');
        material.push_str(part);
    }
    let hash = sha256(material.as_bytes()).to_hex_prefixed();
    let fragment = hash
        .trim_start_matches("0x")
        .chars()
        .take(32)
        .collect::<String>();
    format!("{prefix}-{fragment}")
}

pub(crate) fn resolve_causal_subgraph_root(
    input: &EdrCausalSubgraphInput,
) -> Result<String, (StatusCode, String)> {
    resolve_graph_root_from_selector(input.root_node_id.as_deref(), input.process.as_ref())
}

pub(crate) fn graph_slice_export_kind(value: Option<&str>) -> Result<String, (StatusCode, String)> {
    let kind = non_empty(value).unwrap_or("causal_subgraph");
    match kind {
        "causal_subgraph" | "causal_context" => Ok(kind.to_string()),
        _ => Err((
            StatusCode::BAD_REQUEST,
            "slice_kind must be causal_subgraph or causal_context".to_string(),
        )),
    }
}

pub(crate) fn graph_slice_for_export(
    graph: &CausalGraph,
    root_node_id: &str,
    slice_kind: &str,
    input: &EdrGraphSliceExportInput,
) -> Result<CausalGraph, (StatusCode, String)> {
    match slice_kind {
        "causal_context" => {
            let upstream_depth = bounded_graph_depth("upstreamDepth", input.upstream_depth)?;
            let downstream_depth = bounded_graph_depth("downstreamDepth", input.downstream_depth)?;
            graph
                .causal_context_around(root_node_id, upstream_depth, downstream_depth)
                .ok_or_else(|| {
                    (
                        StatusCode::NOT_FOUND,
                        format!("graph slice export root not found: {root_node_id}"),
                    )
                })
        }
        "causal_subgraph" => {
            let max_depth = bounded_graph_depth("maxDepth", input.max_depth)?;
            graph
                .causal_subgraph_from(root_node_id, max_depth)
                .ok_or_else(|| {
                    (
                        StatusCode::NOT_FOUND,
                        format!("graph slice export root not found: {root_node_id}"),
                    )
                })
        }
        _ => Err((
            StatusCode::BAD_REQUEST,
            "slice_kind must be causal_subgraph or causal_context".to_string(),
        )),
    }
}

pub(crate) fn evidence_bundle_for_graph_slice(
    root_node_id: &str,
    slice_kind: &str,
    reason: Option<&str>,
    graph: &CausalGraph,
) -> Result<EndpointEvidenceBundleReference> {
    let canonical_graph = canonical_evidence_graph(graph)?;
    let content_hash = canonical_graph.content_hash;
    let graph_ref = EndpointGraphReference::for_subgraph(root_node_id, graph);
    let graph_slice_id = graph_ref
        .graph_slice_id
        .ok_or_else(|| anyhow::anyhow!("exported graph slice id missing"))?;
    let reason = non_empty(reason).unwrap_or("operator_export");
    let bundle_id = local_stable_id(
        "evidence_bundle",
        [
            root_node_id,
            graph_slice_id.as_str(),
            slice_kind,
            reason,
            content_hash.as_str(),
        ],
    );
    Ok(EndpointEvidenceBundleReference {
        bundle_id,
        graph_slice_id,
        content_hash,
        node_count: graph.nodes.len(),
        edge_count: graph.edges.len(),
        created_at: chrono::Utc::now(),
    })
}

pub(crate) async fn collect_agent_secret_touches(
    state: &AgentApiState,
    input: EdrAgentSecretTouchesInput,
) -> Result<EdrAgentSecretTouchesResponse, (StatusCode, String)> {
    collect_agent_secret_touches_with_filter(state, input, |_| true).await
}

async fn collect_agent_secret_touches_with_filter<F>(
    state: &AgentApiState,
    input: EdrAgentSecretTouchesInput,
    mut include_credential: F,
) -> Result<EdrAgentSecretTouchesResponse, (StatusCode, String)>
where
    F: FnMut(&CausalNode) -> bool,
{
    let session_id = input
        .session_id
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToString::to_string);
    let credential_kind = input
        .credential_kind
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(|value| value.to_ascii_lowercase());
    let require_agent_context = input.require_agent_context.unwrap_or(true);
    let upstream_depth = bounded_graph_depth("upstreamDepth", input.upstream_depth)?;
    let downstream_depth =
        bounded_graph_depth("downstreamDepth", input.downstream_depth.or(Some(1)))?;
    let limit = bounded_request_limit("limit", input.limit, 50, EDR_MAX_STORED_FINDINGS)?;

    let graph = state.edr_flight_recorder.lock().await.graph().clone();
    let mut touches = Vec::new();
    for credential in graph
        .nodes
        .values()
        .filter(|node| node.kind == CausalNodeKind::Credential)
    {
        if !include_credential(credential) {
            continue;
        }
        if let Some(expected_kind) = credential_kind.as_deref() {
            let actual_kind = node_attribute_string(&credential.attributes, "credentialKind")
                .unwrap_or_default()
                .to_ascii_lowercase();
            if actual_kind != expected_kind {
                continue;
            }
        }

        let Some(context) =
            graph.causal_context_around(&credential.node_id, upstream_depth, downstream_depth)
        else {
            continue;
        };
        if let Some(session_id) = session_id.as_deref() {
            if !graph_context_has_attribute(&context, "sessionId", session_id) {
                continue;
            }
        }

        let (agent_node_ids, agent_labels) = graph_agent_context(&context);
        if require_agent_context && agent_node_ids.is_empty() {
            continue;
        }
        let process_node_ids = context
            .nodes
            .values()
            .filter(|node| node.kind == CausalNodeKind::Process)
            .map(|node| node.node_id.clone())
            .collect::<Vec<_>>();
        let receipt = emit_edr_graph_slice_receipt(
            state,
            &credential.node_id,
            "agent_secret_touch",
            &context,
        )
        .await
        .map_err(internal_error)?;
        touches.push(EdrAgentSecretTouch {
            credential_node_id: credential.node_id.clone(),
            credential_label: credential.label.clone(),
            credential_kind: node_attribute_string(&credential.attributes, "credentialKind"),
            path: node_attribute_string(&credential.attributes, "path"),
            name: node_attribute_string(&credential.attributes, "name"),
            agent_node_ids,
            agent_labels,
            process_node_ids,
            graph: context,
            receipt,
        });
        if touches.len() >= limit {
            break;
        }
    }

    Ok(EdrAgentSecretTouchesResponse {
        touch_count: touches.len(),
        touches,
    })
}

pub(crate) struct FleetHuntPublishContext {
    publisher: Arc<dyn FleetHuntEventPublisher>,
    tenant_id: String,
    endpoint_agent_id: String,
}

pub(crate) struct FleetHuntEventIdentity {
    pub(crate) publisher: Option<Arc<dyn FleetHuntEventPublisher>>,
    pub(crate) tenant_id: String,
    pub(crate) endpoint_agent_id: String,
}

pub(crate) async fn fleet_hunt_publish_context(
    state: &AgentApiState,
) -> Result<FleetHuntPublishContext, (StatusCode, String)> {
    let publisher = state
        .fleet_hunt_publisher
        .as_ref()
        .cloned()
        .ok_or_else(|| {
            (
                StatusCode::SERVICE_UNAVAILABLE,
                "fleet hunt publisher is unavailable because NATS is not connected".to_string(),
            )
        })?;
    let settings = state.settings.read().await;
    let tenant_id = settings.nats.tenant_id.clone().ok_or_else(|| {
        (
            StatusCode::SERVICE_UNAVAILABLE,
            "fleet hunt publisher is unavailable because nats.tenant_id is not configured"
                .to_string(),
        )
    })?;
    let endpoint_agent_id = settings
        .nats
        .agent_id
        .clone()
        .unwrap_or_else(|| publisher.agent_id().to_string());
    Ok(FleetHuntPublishContext {
        publisher,
        tenant_id,
        endpoint_agent_id,
    })
}

pub(crate) async fn fleet_hunt_event_identity(
    state: &AgentApiState,
) -> Result<FleetHuntEventIdentity, (StatusCode, String)> {
    let publisher = state.fleet_hunt_publisher.as_ref().cloned();
    let settings = state.settings.read().await;
    let tenant_id = settings.nats.tenant_id.clone().ok_or_else(|| {
        (
            StatusCode::SERVICE_UNAVAILABLE,
            "fleet hunt event identity is unavailable because nats.tenant_id is not configured"
                .to_string(),
        )
    })?;
    let endpoint_agent_id = settings
        .nats
        .agent_id
        .clone()
        .or_else(|| {
            publisher
                .as_ref()
                .map(|publisher| publisher.agent_id().to_string())
        })
        .ok_or_else(|| {
            (
                StatusCode::SERVICE_UNAVAILABLE,
                "fleet hunt event identity is unavailable because nats.agent_id is not configured"
                    .to_string(),
            )
        })?;
    Ok(FleetHuntEventIdentity {
        publisher,
        tenant_id,
        endpoint_agent_id,
    })
}

pub(crate) async fn enqueue_fleet_hunt_event_outbox(
    state: &AgentApiState,
    event: serde_json::Value,
    error: Option<&str>,
) -> Result<(String, chrono::DateTime<chrono::Utc>), (StatusCode, String)> {
    let event_id = event
        .get("eventId")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                "fleet hunt event is missing eventId".to_string(),
            )
        })?
        .to_string();
    let raw_ref = event
        .get("evidence")
        .and_then(|evidence| evidence.get("rawRef"))
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                "fleet hunt event is missing evidence.rawRef".to_string(),
            )
        })?
        .to_string();
    let now = chrono::Utc::now();
    let attempt_count = 1;
    let outbox_id = sha256(format!("{event_id}:{raw_ref}").as_bytes()).to_hex_prefixed();
    let next_attempt_at =
        now + chrono::Duration::seconds(control_ack_retry_backoff_seconds(attempt_count));
    let event = EndpointFleetHuntEventOutboxEntry {
        outbox_id: outbox_id.clone(),
        event_id,
        raw_ref,
        event,
        attempt_count,
        next_attempt_at,
        last_attempt_at: Some(now),
        last_error_hash: error.map(|error| sha256(error.as_bytes()).to_hex_prefixed()),
        created_at: now,
        updated_at: now,
    };
    state
        .edr_fleet_hunt_event_outbox
        .lock()
        .await
        .append(event)
        .map_err(internal_error)?;
    Ok((outbox_id, next_attempt_at))
}

pub(crate) struct FleetHuntEventRetryAttemptOutcome {
    delivered: bool,
    error_hash: Option<String>,
}

async fn send_fleet_hunt_event_outbox_retry(
    publisher: &dyn FleetHuntEventPublisher,
    event: &EndpointFleetHuntEventOutboxEntry,
) -> FleetHuntEventRetryAttemptOutcome {
    let payload = match serde_json::to_vec(&event.event) {
        Ok(payload) => payload,
        Err(err) => {
            let error = truncate_delivery_error(&format!("serialize fleet hunt event: {err}"));
            return FleetHuntEventRetryAttemptOutcome {
                delivered: false,
                error_hash: Some(sha256(error.as_bytes()).to_hex_prefixed()),
            };
        }
    };

    match publisher.publish_hunt_event(&payload).await {
        Ok(()) => FleetHuntEventRetryAttemptOutcome {
            delivered: true,
            error_hash: None,
        },
        Err(err) => {
            let error = truncate_delivery_error(&err.to_string());
            FleetHuntEventRetryAttemptOutcome {
                delivered: false,
                error_hash: Some(sha256(error.as_bytes()).to_hex_prefixed()),
            }
        }
    }
}

pub(crate) async fn drain_fleet_hunt_event_outbox(
    state: &AgentApiState,
    publisher: Arc<dyn FleetHuntEventPublisher>,
    limit: usize,
    force: bool,
) -> Result<EdrFleetHuntEventRetryResponse, (StatusCode, String)> {
    let limit = limit.clamp(1, 100);
    let now = chrono::Utc::now();
    let (path, pending_before, due) = {
        let outbox = state.edr_fleet_hunt_event_outbox.lock().await;
        (
            outbox.path().map(|path| path.display().to_string()),
            outbox.pending_count(),
            outbox.due(now, limit, force),
        )
    };

    let mut attempts = Vec::new();
    let mut delivered = 0usize;
    let mut failed = 0usize;
    for event in due {
        let outcome = send_fleet_hunt_event_outbox_retry(publisher.as_ref(), &event).await;
        let attempted_count = event.attempt_count.saturating_add(1);
        if outcome.delivered {
            delivered += 1;
            let mut outbox = state.edr_fleet_hunt_event_outbox.lock().await;
            outbox
                .mark_delivered(&event.outbox_id)
                .map_err(internal_error)?;
            attempts.push(EdrFleetHuntEventRetryAttemptRecord {
                outbox_id: event.outbox_id,
                event_id: event.event_id,
                raw_ref: event.raw_ref,
                delivered: true,
                attempt_count: attempted_count,
                next_attempt_at: None,
                error_hash: None,
            });
        } else {
            failed += 1;
            let mut outbox = state.edr_fleet_hunt_event_outbox.lock().await;
            let updated = outbox
                .mark_failed(
                    &event.outbox_id,
                    chrono::Utc::now(),
                    outcome.error_hash.clone(),
                )
                .map_err(internal_error)?
                .unwrap_or_else(|| event.clone());
            attempts.push(EdrFleetHuntEventRetryAttemptRecord {
                outbox_id: event.outbox_id,
                event_id: event.event_id,
                raw_ref: event.raw_ref,
                delivered: false,
                attempt_count: updated.attempt_count,
                next_attempt_at: Some(updated.next_attempt_at),
                error_hash: outcome.error_hash,
            });
        }
    }

    let pending = state
        .edr_fleet_hunt_event_outbox
        .lock()
        .await
        .pending_count();
    Ok(EdrFleetHuntEventRetryResponse {
        path,
        attempted: attempts.len(),
        delivered,
        failed,
        skipped: pending_before.saturating_sub(attempts.len()),
        pending,
        attempts,
    })
}

async fn drain_due_fleet_hunt_event_outbox_best_effort(
    state: &AgentApiState,
    source: &'static str,
) {
    let Some(publisher) = state.fleet_hunt_publisher.as_ref().cloned() else {
        return;
    };
    match drain_fleet_hunt_event_outbox(
        state,
        publisher,
        EDR_MAX_AUTO_FLEET_HUNT_EVENT_OUTBOX_RETRIES_PER_BATCH,
        false,
    )
    .await
    {
        Ok(response) if response.attempted > 0 => {
            tracing::info!(
                attempted = response.attempted,
                delivered = response.delivered,
                failed = response.failed,
                pending = response.pending,
                source,
                "Drained queued fleet hunt events"
            );
        }
        Ok(_) => {}
        Err((_, err)) => {
            tracing::warn!(
                error = %err,
                source,
                "Failed to drain queued fleet hunt events"
            );
        }
    }
}

pub(crate) async fn publish_agent_secret_touches_to_fleet(
    context: &FleetHuntPublishContext,
    touches: &[EdrAgentSecretTouch],
) -> Result<Vec<EdrPublishedHuntEvent>, (StatusCode, String)> {
    let mut events = Vec::new();
    for touch in touches {
        let event = fleet_hunt_event_for_agent_secret_touch(
            touch,
            &context.tenant_id,
            &context.endpoint_agent_id,
        );
        let event_id = event
            .get("eventId")
            .and_then(serde_json::Value::as_str)
            .unwrap_or("unknown")
            .to_string();
        let raw_ref = event
            .get("evidence")
            .and_then(|evidence| evidence.get("rawRef"))
            .and_then(serde_json::Value::as_str)
            .unwrap_or("unknown")
            .to_string();
        let payload = serde_json::to_vec(&event)
            .map_err(|err| internal_error(anyhow::anyhow!("serialize hunt event: {err}")))?;
        context
            .publisher
            .publish_hunt_event(&payload)
            .await
            .map_err(|err| {
                (
                    StatusCode::BAD_GATEWAY,
                    format!("failed to publish hunt event to NATS: {err}"),
                )
            })?;
        events.push(EdrPublishedHuntEvent {
            event_id,
            raw_ref,
            credential_node_id: touch.credential_node_id.clone(),
        });
    }
    Ok(events)
}

async fn publish_current_agent_secret_touches_to_fleet_best_effort(
    state: &AgentApiState,
    observations: &[EndpointObservation],
) {
    let credential_observations = observations
        .iter()
        .filter(|observation| is_credential_access_observation(observation))
        .collect::<Vec<_>>();
    if credential_observations.is_empty() {
        return;
    }
    publish_unpublished_agent_secret_touches_to_fleet_best_effort(
        state,
        Some(&credential_observations),
        "current_ingestion",
    )
    .await;
}

async fn publish_persisted_agent_secret_touches_to_fleet_best_effort(state: &AgentApiState) {
    publish_unpublished_agent_secret_touches_to_fleet_best_effort(
        state,
        None,
        "flight_recorder_sync",
    )
    .await;
}

async fn publish_unpublished_agent_secret_touches_to_fleet_best_effort(
    state: &AgentApiState,
    credential_observations: Option<&[&EndpointObservation]>,
    source: &'static str,
) {
    if state.fleet_hunt_publisher.is_none() {
        return;
    }
    let publish_context = match fleet_hunt_publish_context(state).await {
        Ok(context) => context,
        Err((_, err)) => {
            tracing::debug!(error = %err, source, "Skipping automatic fleet hunt publish");
            return;
        }
    };
    let (touches_to_publish, keys_by_credential_node) =
        match collect_unpublished_agent_secret_touches_for_fleet(
            state,
            credential_observations,
            EDR_MAX_AUTO_FLEET_AGENT_SECRET_TOUCHES_PER_BATCH,
        )
        .await
        {
            Ok(result) => result,
            Err((_, err)) => {
                tracing::warn!(
                    error = %err,
                    source,
                    "Failed to collect agent-secret-touch graph slices for automatic fleet publish"
                );
                return;
            }
        };
    if touches_to_publish.is_empty() {
        return;
    }

    match publish_agent_secret_touches_to_fleet(&publish_context, &touches_to_publish).await {
        Ok(published_events) => {
            let mut published = state
                .edr_auto_published_agent_secret_touch_keys
                .lock()
                .await;
            for event in &published_events {
                if let Some(keys) = keys_by_credential_node.get(&event.credential_node_id) {
                    published.extend(keys.iter().cloned());
                }
            }
            tracing::info!(
                published_count = published_events.len(),
                source,
                "Published agent-secret-touch hunt events to fleet"
            );
        }
        Err((_, err)) => {
            tracing::warn!(
                error = %err,
                source,
                "Failed to publish agent-secret-touch hunt events to fleet"
            );
        }
    }
}

async fn collect_unpublished_agent_secret_touches_for_fleet(
    state: &AgentApiState,
    credential_observations: Option<&[&EndpointObservation]>,
    limit: usize,
) -> Result<(Vec<EdrAgentSecretTouch>, BTreeMap<String, BTreeSet<String>>), (StatusCode, String)> {
    let limit = limit.clamp(1, EDR_MAX_STORED_FINDINGS);
    let published = state
        .edr_auto_published_agent_secret_touch_keys
        .lock()
        .await
        .clone();
    let observation_ids = credential_observations.map(|observations| {
        observations
            .iter()
            .map(|observation| observation.observation_id.as_str())
            .collect::<BTreeSet<_>>()
    });
    let graph = state.edr_flight_recorder.lock().await.graph().clone();
    let mut touches = Vec::new();
    let mut keys_by_credential_node = BTreeMap::new();

    for credential in graph
        .nodes
        .values()
        .filter(|node| node.kind == CausalNodeKind::Credential)
    {
        if let Some(observations) = credential_observations {
            if !observations.iter().any(|observation| {
                credential_node_matches_observation_credential(credential, observation)
            }) {
                continue;
            }
        }

        let Some(context) =
            graph.causal_context_around(&credential.node_id, EDR_MAX_CAUSAL_SUBGRAPH_DEPTH, 1)
        else {
            continue;
        };
        let (agent_node_ids, agent_labels) = graph_agent_context(&context);
        if agent_node_ids.is_empty() {
            continue;
        }
        let publish_keys = agent_secret_touch_publish_keys(
            &credential.node_id,
            &context,
            observation_ids.as_ref(),
        )
        .into_iter()
        .filter(|key| !published.contains(key))
        .collect::<BTreeSet<_>>();
        if publish_keys.is_empty() {
            continue;
        }

        let process_node_ids = context
            .nodes
            .values()
            .filter(|node| node.kind == CausalNodeKind::Process)
            .map(|node| node.node_id.clone())
            .collect::<Vec<_>>();
        let receipt = emit_edr_graph_slice_receipt(
            state,
            &credential.node_id,
            "agent_secret_touch",
            &context,
        )
        .await
        .map_err(internal_error)?;
        keys_by_credential_node.insert(credential.node_id.clone(), publish_keys);
        touches.push(EdrAgentSecretTouch {
            credential_node_id: credential.node_id.clone(),
            credential_label: credential.label.clone(),
            credential_kind: node_attribute_string(&credential.attributes, "credentialKind"),
            path: node_attribute_string(&credential.attributes, "path"),
            name: node_attribute_string(&credential.attributes, "name"),
            agent_node_ids,
            agent_labels,
            process_node_ids,
            graph: context,
            receipt,
        });
        if touches.len() >= limit {
            break;
        }
    }

    Ok((touches, keys_by_credential_node))
}

async fn fleet_agent_secret_touch_sync_loop(
    state: Arc<AgentApiState>,
    shutdown_rx: &mut broadcast::Receiver<()>,
) {
    drain_due_fleet_hunt_event_outbox_best_effort(state.as_ref(), "fleet_sync_startup").await;
    publish_persisted_agent_secret_touches_to_fleet_best_effort(state.as_ref()).await;
    let mut interval = tokio::time::interval(EDR_FLEET_AGENT_SECRET_TOUCH_SYNC_INTERVAL);
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    interval.tick().await;
    loop {
        tokio::select! {
            _ = interval.tick() => {
                drain_due_fleet_hunt_event_outbox_best_effort(
                    state.as_ref(),
                    "fleet_sync_interval",
                )
                .await;
                publish_persisted_agent_secret_touches_to_fleet_best_effort(state.as_ref()).await;
            }
            shutdown = shutdown_rx.recv() => {
                if shutdown.is_err() {
                    tracing::debug!("Fleet agent-secret-touch sync shutdown channel closed");
                }
                break;
            }
        }
    }
}

fn agent_secret_touch_publish_keys(
    credential_node_id: &str,
    graph: &CausalGraph,
    observation_ids: Option<&BTreeSet<&str>>,
) -> BTreeSet<String> {
    let Some(credential_node) = graph.nodes.get(credential_node_id) else {
        return BTreeSet::new();
    };
    if credential_node.kind != CausalNodeKind::Credential {
        return BTreeSet::new();
    }
    graph
        .edges
        .iter()
        .filter(|edge| {
            edge.kind == CausalEdgeKind::AccessedCredential
                && edge.to == credential_node_id
                && observation_ids
                    .map(|ids| ids.contains(edge.observation_id.as_str()))
                    .unwrap_or(true)
        })
        .map(|edge| format!("{}|{}", credential_node_id, edge.observation_id))
        .collect()
}

fn is_credential_access_observation(observation: &EndpointObservation) -> bool {
    matches!(&observation.event, EndpointEvent::CredentialAccess { .. })
}

fn credential_node_matches_observation_credential(
    node: &CausalNode,
    observation: &EndpointObservation,
) -> bool {
    let EndpointEvent::CredentialAccess { kind, path, name } = &observation.event else {
        return false;
    };
    let node_kind = node_attribute_string(&node.attributes, "credentialKind")
        .unwrap_or_default()
        .to_ascii_lowercase();
    if node_kind != kind.as_str() {
        return false;
    }
    if let Some(path) = path.as_deref() {
        return node_attribute_string(&node.attributes, "path").as_deref() == Some(path)
            || node.label == path;
    }
    if let Some(name) = name.as_deref() {
        return node_attribute_string(&node.attributes, "name").as_deref() == Some(name)
            || node.label == name;
    }
    true
}

fn fleet_hunt_event_for_agent_secret_touch(
    touch: &EdrAgentSecretTouch,
    tenant_id: &str,
    endpoint_agent_id: &str,
) -> serde_json::Value {
    let receipt_id = touch
        .receipt
        .receipt
        .receipt_id
        .clone()
        .unwrap_or_else(|| touch.credential_node_id.clone());
    let occurred_at = touch.receipt.receipt.timestamp.clone();
    let credential_kind = touch
        .credential_kind
        .clone()
        .unwrap_or_else(|| "credential".to_string());
    let session_id = first_graph_attribute(&touch.graph, "sessionId");
    serde_json::json!({
        "eventId": format!("agent-secret-touch:{endpoint_agent_id}:{receipt_id}"),
        "tenantId": tenant_id,
        "source": "receipt",
        "kind": "guard_decision",
        "occurredAt": occurred_at,
        "ingestedAt": chrono::Utc::now().to_rfc3339(),
        "severity": "high",
        "verdict": "warn",
        "summary": format!("AI agent touched {credential_kind}: {}", touch.credential_label),
        "actionType": "secret_access",
        "principal": {
            "endpointAgentId": endpoint_agent_id,
            "principalType": "endpoint_agent"
        },
        "sessionId": session_id,
        "detectionIds": ["agent_secret_touch"],
        "target": {
            "kind": "credential",
            "id": touch.credential_node_id,
            "name": touch.credential_label
        },
        "evidence": {
            "rawRef": format!("endpoint-receipt:{receipt_id}"),
            "schemaName": "clawdstrike.edr.agent_secret_touch.v1"
        },
        "attributes": {
            "credentialKind": credential_kind,
            "credentialPath": touch.path,
            "credentialName": touch.name,
            "agentNodeIds": touch.agent_node_ids,
            "agentLabels": touch.agent_labels,
            "processNodeIds": touch.process_node_ids,
            "graphNodeCount": touch.graph.nodes.len(),
            "graphEdgeCount": touch.graph.edges.len(),
            "endpointReceipt": touch.receipt
        }
    })
}

pub(crate) fn fleet_hunt_event_for_evidence_bundle_archive(
    archive_id: &str,
    archive_hash: &str,
    archive: &EdrEvidenceBundleArchive,
    verification: &EdrEvidenceBundleArchiveVerification,
    tenant_id: &str,
    endpoint_agent_id: &str,
) -> serde_json::Value {
    let receipt_ids = archive
        .receipts
        .iter()
        .filter_map(|receipt| receipt.receipt.receipt_id.clone())
        .collect::<Vec<_>>();
    let receipt_hashes = archive
        .receipts
        .iter()
        .filter_map(|receipt| {
            canonical_json_hash(receipt, "endpoint evidence bundle archive fleet receipt").ok()
        })
        .collect::<Vec<_>>();
    let receipt_families = archive
        .receipts
        .iter()
        .filter_map(|receipt| receipt_endpoint_decision_str(receipt, &["receiptFamily"]))
        .map(ToString::to_string)
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect::<Vec<_>>();
    let verification = serde_json::to_value(verification).unwrap_or_else(|_| {
        serde_json::json!({
            "verified": verification.verified,
            "receiptFailureCount": verification.receipt_failure_count
        })
    });

    serde_json::json!({
        "eventId": format!("evidence-bundle-archive:{endpoint_agent_id}:{archive_id}"),
        "tenantId": tenant_id,
        "source": "receipt",
        "kind": "detection_fired",
        "occurredAt": archive.bundle.created_at.to_rfc3339(),
        "ingestedAt": chrono::Utc::now().to_rfc3339(),
        "severity": "info",
        "verdict": "none",
        "summary": format!(
            "Endpoint evidence bundle archive ready: {}",
            archive.bundle.bundle_id
        ),
        "actionType": "evidence_bundle_archive",
        "principal": {
            "endpointAgentId": endpoint_agent_id,
            "principalType": "endpoint_agent"
        },
        "detectionIds": ["evidence_bundle_archive"],
        "target": {
            "kind": "evidence_bundle",
            "id": archive.bundle.bundle_id,
            "name": archive.bundle.graph_slice_id
        },
        "evidence": {
            "rawRef": evidence_bundle_archive_raw_ref(archive_id, archive_hash),
            "schemaName": "clawdstrike.edr.evidence_bundle_archive.v1"
        },
        "attributes": {
            "archiveId": archive_id,
            "archiveHash": archive_hash,
            "bundleId": archive.bundle.bundle_id,
            "graphSliceId": archive.bundle.graph_slice_id,
            "contentHash": archive.bundle.content_hash,
            "graphNodeCount": archive.bundle.node_count,
            "graphEdgeCount": archive.bundle.edge_count,
            "artifactByteCount": archive.artifact.byte_count,
            "receiptCount": archive.receipts.len(),
            "receiptIds": receipt_ids,
            "receiptHashes": receipt_hashes,
            "receiptFamilies": receipt_families,
            "verification": verification
        }
    })
}

pub(crate) fn evidence_bundle_archive_raw_ref(archive_id: &str, archive_hash: &str) -> String {
    format!("endpoint-evidence-bundle-archive:{archive_id}:{archive_hash}")
}

fn first_graph_attribute(graph: &CausalGraph, key: &str) -> Option<String> {
    graph
        .nodes
        .values()
        .find_map(|node| node_attribute_string(&node.attributes, key))
}

pub(crate) fn node_attribute_string(
    attributes: &std::collections::BTreeMap<String, serde_json::Value>,
    key: &str,
) -> Option<String> {
    attributes
        .get(key)
        .and_then(serde_json::Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToString::to_string)
}

pub(crate) fn non_empty(value: Option<&str>) -> Option<&str> {
    value.map(str::trim).filter(|value| !value.is_empty())
}

fn graph_context_has_attribute(context: &CausalGraph, key: &str, expected: &str) -> bool {
    context
        .nodes
        .values()
        .any(|node| node_attribute_string(&node.attributes, key).as_deref() == Some(expected))
        || context
            .edges
            .iter()
            .any(|edge| node_attribute_string(&edge.attributes, key).as_deref() == Some(expected))
}

fn graph_agent_context(context: &CausalGraph) -> (Vec<String>, Vec<String>) {
    let mut node_ids = BTreeSet::new();
    let mut labels = BTreeSet::new();
    for node in context.nodes.values() {
        if node.kind == CausalNodeKind::Tool {
            node_ids.insert(node.node_id.clone());
            labels.insert(node.label.clone());
            continue;
        }
        if node.kind == CausalNodeKind::Process {
            if let Some(agent_id) = node_attribute_string(&node.attributes, "agentId") {
                node_ids.insert(node.node_id.clone());
                labels.insert(agent_id);
            }
        }
    }
    (node_ids.into_iter().collect(), labels.into_iter().collect())
}

fn resolve_graph_root(
    root_node_id: Option<&str>,
    process: Option<&EndpointProcess>,
) -> Result<String, (StatusCode, String)> {
    if let Some(root_node_id) = root_node_id
        .map(str::trim)
        .filter(|value| !value.is_empty())
    {
        return Ok(root_node_id.to_string());
    }

    if let Some(process) = process {
        return Ok(process.stable_node_id());
    }

    Err((
        StatusCode::BAD_REQUEST,
        "root_node_id or process must be provided".to_string(),
    ))
}

fn graph_root_process_selector(input: &EdrGraphRootProcessSelectorInput) -> EndpointProcess {
    EndpointProcess {
        pid: input.pid,
        ppid: input.ppid,
        process_guid: trimmed_owned(input.process_guid.as_deref()),
        parent_process_guid: trimmed_owned(input.parent_process_guid.as_deref()),
        image: trimmed_owned(input.image.as_deref()),
        command_line: trimmed_owned(input.command_line.as_deref()),
        cwd: trimmed_owned(input.cwd.as_deref()),
        ..EndpointProcess::default()
    }
}

pub(crate) fn resolve_graph_root_from_selector(
    root_node_id: Option<&str>,
    process: Option<&EdrGraphRootProcessSelectorInput>,
) -> Result<String, (StatusCode, String)> {
    let process = process.map(graph_root_process_selector);
    resolve_graph_root(root_node_id, process.as_ref())
}

pub(crate) fn bounded_graph_depth(
    field: &str,
    depth: Option<usize>,
) -> Result<usize, (StatusCode, String)> {
    let depth = depth.unwrap_or(EDR_MAX_CAUSAL_SUBGRAPH_DEPTH);
    if depth <= EDR_MAX_CAUSAL_SUBGRAPH_DEPTH {
        return Ok(depth);
    }
    Err((
        StatusCode::BAD_REQUEST,
        format!("{field} must be at most {EDR_MAX_CAUSAL_SUBGRAPH_DEPTH}"),
    ))
}

pub(crate) fn bounded_request_limit(
    field: &str,
    limit: Option<usize>,
    default: usize,
    max: usize,
) -> Result<usize, (StatusCode, String)> {
    let limit = limit.unwrap_or(default);
    if (1..=max).contains(&limit) {
        return Ok(limit);
    }
    Err((
        StatusCode::BAD_REQUEST,
        format!("{field} must be between 1 and {max}"),
    ))
}

pub(crate) fn bounded_provider_timeout_ms(
    field: &str,
    timeout_ms: Option<u64>,
) -> Result<u64, (StatusCode, String)> {
    let timeout_ms = timeout_ms.unwrap_or(EDR_DEFAULT_PROVIDER_ACK_TIMEOUT_MS);
    if (1..=EDR_MAX_PROVIDER_ACK_TIMEOUT_MS).contains(&timeout_ms) {
        return Ok(timeout_ms);
    }
    Err((
        StatusCode::BAD_REQUEST,
        format!("{field} must be between 1 and {EDR_MAX_PROVIDER_ACK_TIMEOUT_MS}"),
    ))
}

fn bounded_u32_setting(
    field: &str,
    value: u32,
    min: u32,
    max: u32,
) -> Result<u32, (StatusCode, String)> {
    if (min..=max).contains(&value) {
        return Ok(value);
    }
    Err((
        StatusCode::BAD_REQUEST,
        format!("{field} must be between {min} and {max}"),
    ))
}

fn bounded_u16_setting(
    field: &str,
    value: u16,
    min: u16,
    max: u16,
) -> Result<u16, (StatusCode, String)> {
    if (min..=max).contains(&value) {
        return Ok(value);
    }
    Err((
        StatusCode::BAD_REQUEST,
        format!("{field} must be between {min} and {max}"),
    ))
}

fn normalize_settings_url(
    field: &str,
    value: &str,
    allow_non_loopback_http: bool,
) -> Result<String, (StatusCode, String)> {
    let trimmed = value.trim().trim_end_matches('/');
    if trimmed.is_empty() {
        return Err((
            StatusCode::BAD_REQUEST,
            format!("{field} must not be empty"),
        ));
    }
    let parsed = reqwest::Url::parse(trimmed).map_err(|err| {
        (
            StatusCode::BAD_REQUEST,
            format!("{field} must be a valid URL: {err}"),
        )
    })?;
    if parsed.host_str().is_none() {
        return Err((
            StatusCode::BAD_REQUEST,
            format!("{field} must include a host"),
        ));
    }
    if !parsed.username().is_empty() || parsed.password().is_some() {
        return Err((
            StatusCode::BAD_REQUEST,
            format!("{field} must not contain userinfo"),
        ));
    }
    match parsed.scheme() {
        "https" => {}
        "http" if allow_non_loopback_http || control_api_url_is_loopback(&parsed) => {}
        "http" => {
            return Err((
                StatusCode::BAD_REQUEST,
                format!("{field} may use http only for loopback hosts"),
            ));
        }
        other => {
            return Err((
                StatusCode::BAD_REQUEST,
                format!("{field} must use http or https, got {other}"),
            ));
        }
    }
    Ok(trimmed.to_string())
}

fn normalize_notification_severity_setting(value: &str) -> Result<String, (StatusCode, String)> {
    match value.trim().to_ascii_lowercase().as_str() {
        "info" | "allow" | "allowed" => Ok("info".to_string()),
        "warn" | "warning" | "medium" => Ok("warn".to_string()),
        "block" | "blocked" | "high" | "critical" => Ok("block".to_string()),
        _ => Err((
            StatusCode::BAD_REQUEST,
            "notification_severity must be one of info, warn, or block".to_string(),
        )),
    }
}

fn normalize_ota_mode_setting(value: &str) -> Result<String, (StatusCode, String)> {
    match value.trim().to_ascii_lowercase().as_str() {
        "auto" => Ok("auto".to_string()),
        "manual" => Ok("manual".to_string()),
        _ => Err((
            StatusCode::BAD_REQUEST,
            "ota_mode must be one of auto or manual".to_string(),
        )),
    }
}

fn normalize_ota_channel_setting(value: &str) -> Result<String, (StatusCode, String)> {
    match value.trim().to_ascii_lowercase().as_str() {
        "stable" => Ok("stable".to_string()),
        "beta" => Ok("beta".to_string()),
        _ => Err((
            StatusCode::BAD_REQUEST,
            "ota_channel must be one of stable or beta".to_string(),
        )),
    }
}

pub(crate) async fn build_edr_detection_candidate(
    state: &AgentApiState,
    input: EdrDetectionCandidateInput,
) -> Result<EdrDetectionCandidateResponse, (StatusCode, String)> {
    let root_node_id =
        resolve_graph_root_from_selector(input.root_node_id.as_deref(), input.process.as_ref())?;
    let max_depth = bounded_graph_depth("maxDepth", input.max_depth)?;
    let graph = state.edr_flight_recorder.lock().await.graph().clone();
    let subgraph = edr_policy_simulation_graph_slice(&graph, root_node_id.as_str(), max_depth)
        .ok_or_else(|| {
            (
                StatusCode::NOT_FOUND,
                format!("detection candidate target not found in causal graph: {root_node_id}"),
            )
        })?;
    let root_node = subgraph.nodes.get(&root_node_id).ok_or_else(|| {
        (
            StatusCode::NOT_FOUND,
            format!("detection candidate root not found in graph slice: {root_node_id}"),
        )
    })?;
    let action = input
        .action
        .unwrap_or_else(|| default_detection_candidate_action(root_node));
    if !supported_edr_simulation_action(&action) {
        return Err((
            StatusCode::BAD_REQUEST,
            format!(
                "unsupported endpoint detection candidate action: {}",
                action.as_str()
            ),
        ));
    }
    let rule_id = detection_candidate_rule_id(root_node, &action);
    let description = input
        .description
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToString::to_string)
        .unwrap_or_else(|| detection_candidate_description(root_node, &action));
    let rule = EndpointPolicySimulationRule {
        rule_id: rule_id.clone(),
        action: action.clone(),
        description: Some(description.clone()),
    };
    let simulation = EndpointPolicySimulationReport::for_rule(rule, &root_node_id, &subgraph);
    let receipt = emit_edr_simulation_receipt(state, &simulation, &subgraph)
        .await
        .map_err(internal_error)?;
    let recommended_stage = recommended_detection_stage(&simulation, &root_node.kind);
    let stage_plan =
        detection_candidate_stage_plan(&simulation, &root_node.kind, &recommended_stage);
    let candidate = EdrDetectionCandidate {
        rule_id,
        action,
        description,
        root_node_id: root_node_id.clone(),
        root_label: root_node.label.clone(),
        root_kind: root_node.kind.clone(),
        graph_slice_id: simulation.graph_slice_id.clone(),
    };

    Ok(EdrDetectionCandidateResponse {
        candidate,
        recommended_stage,
        stage_plan,
        simulation,
        graph: subgraph,
        receipt,
    })
}

pub(crate) fn policy_replay_rule_id(
    policy: &EndpointPolicySnapshot,
    node: &CausalNode,
    action: &EndpointDecisionAction,
) -> String {
    format!(
        "endpoint.current_policy_replay.epoch_{}.{}.{}.{}",
        policy.policy_epoch,
        action.as_str(),
        causal_node_kind_name(&node.kind),
        rule_id_fragment(&node.label)
    )
}

pub(crate) fn policy_replay_description(
    policy: &EndpointPolicySnapshot,
    node: &CausalNode,
    action: &EndpointDecisionAction,
) -> String {
    format!(
        "Replay current endpoint policy {} epoch {} against captured {} node {} with simulated {} enforcement.",
        policy.policy_version,
        policy.policy_epoch,
        causal_node_kind_name(&node.kind),
        node.label,
        action.as_str()
    )
}

pub(crate) fn edr_policy_simulation_graph_slice(
    graph: &CausalGraph,
    root_node_id: &str,
    max_depth: usize,
) -> Option<CausalGraph> {
    graph
        .causal_context_around(root_node_id, max_depth, max_depth)
        .or_else(|| graph.causal_subgraph_from(root_node_id, max_depth))
}

pub(crate) fn build_policy_replay_report(
    policy: EndpointPolicySnapshot,
    root_node: &CausalNode,
    flight_recorder_observation_count: usize,
    simulation: &EndpointPolicySimulationReport,
    graph: &CausalGraph,
) -> EdrPolicyReplayReport {
    let policy_epoch = policy.policy_epoch.to_string();
    let replay_id = local_stable_id(
        "policy_replay",
        [
            policy.policy_hash.as_str(),
            policy_epoch.as_str(),
            simulation.simulation_id.as_str(),
        ],
    );
    let observation_count = graph
        .edges
        .iter()
        .filter_map(|edge| {
            let observation_id = edge.observation_id.trim();
            (!observation_id.is_empty()).then_some(observation_id)
        })
        .collect::<BTreeSet<_>>()
        .len();
    let summary = format!(
        "Replayed graph slice {} under current endpoint policy {} epoch {}; {} would affect {} nodes and {} edges with developer breakage score {}/100.",
        simulation.graph_slice_id,
        policy.policy_version,
        policy.policy_epoch,
        simulation.rule_id,
        simulation.affected_node_count,
        simulation.affected_edge_count,
        simulation.developer_breakage_score
    );

    EdrPolicyReplayReport {
        replay_id,
        replayed_at: chrono::Utc::now(),
        mode: "current_policy_graph_replay".to_string(),
        policy,
        root_node_id: simulation.root_node_id.clone(),
        root_label: root_node.label.clone(),
        root_kind: root_node.kind.clone(),
        action: simulation.action.clone(),
        graph_slice_id: simulation.graph_slice_id.clone(),
        observation_count,
        node_count: graph.nodes.len(),
        edge_count: graph.edges.len(),
        flight_recorder_observation_count,
        would_enforce: simulation.would_block,
        developer_breakage_score: simulation.developer_breakage_score,
        impact_level: simulation.impact_level.clone(),
        summary,
    }
}

pub(crate) fn normalize_staged_detection_hash(
    field: &str,
    value: Option<String>,
) -> Result<Option<String>, (StatusCode, String)> {
    let Some(value) = value else {
        return Ok(None);
    };
    let value = value.trim();
    if value.is_empty() {
        return Ok(None);
    }
    if value.len() != 66 || !value.starts_with("0x") {
        return Err((
            StatusCode::BAD_REQUEST,
            format!("{field} must be a 0x-prefixed SHA-256 hex digest"),
        ));
    }
    if !value[2..].chars().all(|ch| ch.is_ascii_hexdigit()) {
        return Err((
            StatusCode::BAD_REQUEST,
            format!("{field} must be a 0x-prefixed SHA-256 hex digest"),
        ));
    }
    Ok(Some(value.to_ascii_lowercase()))
}

pub(crate) async fn remember_cross_window_promotion_validation(
    state: &Arc<AgentApiState>,
    impact: &EdrPolicyEventHistoryCrossWindowImpact,
    causal_impact: &EdrPolicyEventHistoryCausalImpact,
    policy_impact: &EdrPolicyEventImpactReport,
    history: &EdrPolicyEventHistoryReport,
) {
    if !impact.promotion_ready {
        return;
    }
    let recorded_at = chrono::Utc::now();
    let history_selector_hash = policy_event_history_selector_hash(history);
    let mut validations = state.edr_cross_window_promotion_validations.lock().await;
    for suggestion in &causal_impact.promotion_suggestions {
        if suggestion.selected_stage != impact.recommended_stage {
            continue;
        }
        validations.push_back(EdrCrossWindowPromotionValidation {
            recorded_at,
            impact_hash: impact.impact_hash.clone(),
            recommendation_hash: impact.recommendation_hash.clone(),
            current_policy_hash: policy_impact.current_policy.policy_hash.clone(),
            current_policy_epoch: policy_impact.current_policy.policy_epoch,
            proposed_policy_hash: policy_impact.proposed_policy.policy_hash.clone(),
            proposed_policy_epoch: policy_impact.proposed_policy.policy_epoch,
            event_stream_hash: policy_impact.event_stream_hash.clone(),
            current_result_hash: policy_impact.current_result_hash.clone(),
            proposed_result_hash: policy_impact.proposed_result_hash.clone(),
            history_selector_hash: history_selector_hash.clone(),
            newest_event_at: history.newest_timestamp,
            max_age_seconds: history.max_age_seconds,
            recommended_stage: impact.recommended_stage.clone(),
            root_node_id: suggestion.target_node_id.clone(),
            action: suggestion.action.clone(),
            promotion_ready: true,
        });
    }
    while validations.len() > EDR_CROSS_WINDOW_PROMOTION_VALIDATION_CACHE_LIMIT {
        let _ = validations.pop_front();
    }
}

pub(crate) async fn recent_cross_window_promotion_validation(
    state: &AgentApiState,
    stage: &str,
    root_node_id: &str,
    action: &EndpointDecisionAction,
    current_policy: &EndpointPolicySnapshot,
    cross_window_impact_hash: Option<&str>,
    cross_window_recommendation_hash: Option<&str>,
) -> Result<Option<EdrCrossWindowPromotionValidation>, (StatusCode, String)> {
    let (Some(cross_window_impact_hash), Some(cross_window_recommendation_hash)) =
        (cross_window_impact_hash, cross_window_recommendation_hash)
    else {
        return Ok(None);
    };
    let now = chrono::Utc::now();
    let validations = state.edr_cross_window_promotion_validations.lock().await;
    Ok(validations
        .iter()
        .rev()
        .find(|validation| {
            validation.promotion_ready
                && validation.recommended_stage == stage
                && validation.root_node_id == root_node_id
                && validation.action == *action
                && validation.impact_hash == cross_window_impact_hash
                && validation.recommendation_hash == cross_window_recommendation_hash
                && validation.current_policy_hash == current_policy.policy_hash
                && validation.current_policy_epoch == current_policy.policy_epoch
                && !validation.proposed_policy_hash.is_empty()
                && validation.proposed_policy_epoch > 0
                && !validation.event_stream_hash.is_empty()
                && !validation.current_result_hash.is_empty()
                && !validation.proposed_result_hash.is_empty()
                && !validation.history_selector_hash.is_empty()
                && validation.newest_event_at.is_some()
                && validation.max_age_seconds.is_some_and(|max_age_seconds| {
                    validation.newest_event_at.is_some_and(|newest_event_at| {
                        now.signed_duration_since(newest_event_at)
                            .num_seconds()
                            .max(0) as u64
                            <= max_age_seconds
                    })
                })
                && now
                    .signed_duration_since(validation.recorded_at)
                    .num_seconds()
                    <= EDR_CROSS_WINDOW_PROMOTION_VALIDATION_MAX_AGE_SECONDS
        })
        .cloned())
}

pub(crate) fn detection_stage_entry<'a>(
    stage: &str,
    stage_plan: &'a [EdrDetectionCandidateStage],
) -> Result<&'a EdrDetectionCandidateStage, (StatusCode, String)> {
    if let Some(candidate) = stage_plan.iter().find(|candidate| candidate.stage == stage) {
        return Ok(candidate);
    }
    Err((
        StatusCode::BAD_REQUEST,
        format!(
            "stage must be one of: {}",
            detection_stage_names(stage_plan)
        ),
    ))
}

pub(crate) fn validate_detection_stage_promotion_readiness(
    stage: &str,
    stage_entry: &EdrDetectionCandidateStage,
    cross_window_validation: Option<&EdrCrossWindowPromotionValidation>,
) -> Result<(), (StatusCode, String)> {
    if !policy_delta_stage_is_enforcing(stage, &stage_entry.action) {
        return Ok(());
    }
    if cross_window_validation.is_some() {
        return Ok(());
    }
    Err((
        StatusCode::BAD_REQUEST,
        format!(
            "{stage} is an enforcing endpoint policy stage for action {}; provide crossWindowImpactHash and crossWindowRecommendationHash from a recent promotionReady=true policy-events impact history response before staging enforcement",
            stage_entry.action.as_str()
        ),
    ))
}

fn detection_stage_names(stage_plan: &[EdrDetectionCandidateStage]) -> String {
    stage_plan
        .iter()
        .map(|candidate| candidate.stage.as_str())
        .collect::<Vec<_>>()
        .join(", ")
}

pub(crate) fn default_detection_candidate_action(
    node: &clawdstrike_policy_event::edr::CausalNode,
) -> EndpointDecisionAction {
    match node.kind {
        CausalNodeKind::Network => EndpointDecisionAction::RestrictEgress,
        CausalNodeKind::File | CausalNodeKind::BrowserDownload => {
            let path = PathBuf::from(node.label.trim());
            if path_is_bounded_persistence_target(&path) {
                EndpointDecisionAction::DisablePersistence
            } else {
                EndpointDecisionAction::QuarantineFile
            }
        }
        CausalNodeKind::BrowserExtension => EndpointDecisionAction::DisablePersistence,
        _ => EndpointDecisionAction::Block,
    }
}

fn detection_candidate_rule_id(
    node: &clawdstrike_policy_event::edr::CausalNode,
    action: &EndpointDecisionAction,
) -> String {
    format!(
        "endpoint.generated.{}.{}.{}",
        action.as_str(),
        causal_node_kind_name(&node.kind),
        rule_id_fragment(&node.label)
    )
}

fn detection_candidate_description(
    node: &clawdstrike_policy_event::edr::CausalNode,
    action: &EndpointDecisionAction,
) -> String {
    format!(
        "Generated staged endpoint detection candidate to {} {} node {} from local causal graph impact simulation.",
        action.as_str(),
        causal_node_kind_name(&node.kind),
        node.label
    )
}

fn detection_candidate_stage_plan(
    simulation: &EndpointPolicySimulationReport,
    root_kind: &CausalNodeKind,
    recommended_stage: &str,
) -> Vec<EdrDetectionCandidateStage> {
    let mut stages = vec![
        (
            "observe",
            EndpointDecisionAction::Observe,
            "record graph slices and receipts without user-visible enforcement",
        ),
        (
            "audit",
            EndpointDecisionAction::Alert,
            "review grouped causal evidence and simulation impact before notifying users",
        ),
        (
            "warn",
            EndpointDecisionAction::Warn,
            "warn affected users when developer breakage score is acceptable for workflow testing",
        ),
    ];
    if policy_delta_stage_materializes_guard(root_kind, &simulation.action) {
        stages.push((
            "limited_block",
            simulation.action.clone(),
            "enable bounded enforcement for matching graph roots with rollback or recovery path",
        ));
    }
    stages
        .into_iter()
        .map(
            |(stage, action, promotion_gate)| EdrDetectionCandidateStage {
                stage: stage.to_string(),
                action,
                promotion_gate: promotion_gate.to_string(),
                recommended: stage == recommended_stage,
            },
        )
        .collect()
}

fn recommended_detection_stage(
    simulation: &EndpointPolicySimulationReport,
    root_kind: &CausalNodeKind,
) -> String {
    if !simulation.would_block {
        return "observe".to_string();
    }
    if !policy_delta_stage_materializes_guard(root_kind, &simulation.action) {
        return "audit".to_string();
    }
    match simulation.developer_breakage_score {
        0..=45 => "limited_block",
        46..=70 => "warn",
        _ => "audit",
    }
    .to_string()
}

pub(crate) fn causal_node_kind_name(kind: &CausalNodeKind) -> &'static str {
    match kind {
        CausalNodeKind::Host => "host",
        CausalNodeKind::User => "user",
        CausalNodeKind::Session => "session",
        CausalNodeKind::Agent => "agent",
        CausalNodeKind::Workload => "workload",
        CausalNodeKind::Approval => "approval",
        CausalNodeKind::Process => "process",
        CausalNodeKind::File => "file",
        CausalNodeKind::Network => "network",
        CausalNodeKind::DnsName => "dns_name",
        CausalNodeKind::PackageScript => "package_script",
        CausalNodeKind::Credential => "credential",
        CausalNodeKind::BrowserDownload => "browser_download",
        CausalNodeKind::BrowserExtension => "browser_extension",
        CausalNodeKind::PolicyDecision => "policy_decision",
        CausalNodeKind::Tool => "tool",
        CausalNodeKind::DeceptionArtifact => "deception_artifact",
        CausalNodeKind::Other => "other",
    }
}

fn rule_id_fragment(value: &str) -> String {
    let mut fragment = value
        .chars()
        .take(64)
        .map(|ch| {
            if ch.is_ascii_alphanumeric() {
                ch.to_ascii_lowercase()
            } else {
                '_'
            }
        })
        .collect::<String>();
    while fragment.contains("__") {
        fragment = fragment.replace("__", "_");
    }
    let fragment = fragment.trim_matches('_').to_string();
    if fragment.is_empty() {
        "root".to_string()
    } else {
        fragment
    }
}

pub(crate) fn supported_edr_simulation_action(action: &EndpointDecisionAction) -> bool {
    matches!(
        action,
        EndpointDecisionAction::Block
            | EndpointDecisionAction::RestrictEgress
            | EndpointDecisionAction::SuspendProcessTree
            | EndpointDecisionAction::TerminateProcessTree
            | EndpointDecisionAction::QuarantineFile
            | EndpointDecisionAction::RevokeGrant
            | EndpointDecisionAction::DisablePersistence
    )
}

pub(crate) fn validate_response_action_actor(
    actor: Option<&EdrResponseActionActorInput>,
) -> Result<(), (StatusCode, String)> {
    let Some(actor) = actor else {
        return Err((
            StatusCode::BAD_REQUEST,
            "live response execution requires actor identity".to_string(),
        ));
    };
    if !response_action_actor_identity_present(actor) {
        return Err((
            StatusCode::BAD_REQUEST,
            "live response execution actor must include userId, sessionId, agentId, workloadId, or approvalId".to_string(),
        ));
    }
    if non_empty(actor.approval_id.as_deref()).is_none() {
        return Err((
            StatusCode::BAD_REQUEST,
            "live response execution requires actor approvalId".to_string(),
        ));
    }
    Ok(())
}

fn response_action_actor_identity_present(actor: &EdrResponseActionActorInput) -> bool {
    [
        actor.user_id.as_deref(),
        actor.session_id.as_deref(),
        actor.agent_id.as_deref(),
        actor.workload_id.as_deref(),
        actor.approval_id.as_deref(),
    ]
    .into_iter()
    .any(|value| non_empty(value).is_some())
}

pub(crate) fn validate_response_action_actor_fields(
    actor: Option<&EdrResponseActionActorInput>,
) -> Result<(), (StatusCode, String)> {
    let Some(actor) = actor else {
        return Ok(());
    };
    for (field, value) in [
        (
            "actor.endpointId",
            non_empty(Some(actor.endpoint_id.as_str())),
        ),
        ("actor.hostId", non_empty(actor.host_id.as_deref())),
        ("actor.userId", non_empty(actor.user_id.as_deref())),
        ("actor.sessionId", non_empty(actor.session_id.as_deref())),
        ("actor.posture", non_empty(actor.posture.as_deref())),
        ("actor.agentId", non_empty(actor.agent_id.as_deref())),
        ("actor.workloadId", non_empty(actor.workload_id.as_deref())),
        ("actor.approvalId", non_empty(actor.approval_id.as_deref())),
    ] {
        if value.is_some_and(|value| value.len() > EDR_MAX_RESPONSE_ACTOR_FIELD_BYTES) {
            return Err((
                StatusCode::BAD_REQUEST,
                format!("{field} must be at most {EDR_MAX_RESPONSE_ACTOR_FIELD_BYTES} bytes"),
            ));
        }
    }
    Ok(())
}

pub(crate) fn validate_response_action_ttl_seconds(
    ttl_seconds: Option<u64>,
) -> Result<u64, (StatusCode, String)> {
    let ttl_seconds = ttl_seconds.unwrap_or(EDR_DEFAULT_RESPONSE_TTL_SECONDS);
    if (1..=EDR_MAX_RESPONSE_TTL_SECONDS).contains(&ttl_seconds) {
        return Ok(ttl_seconds);
    }
    Err((
        StatusCode::BAD_REQUEST,
        format!("ttlSeconds must be between 1 and {EDR_MAX_RESPONSE_TTL_SECONDS} seconds"),
    ))
}

pub(crate) fn validate_response_reason(
    field: &str,
    reason: Option<&str>,
    default_reason: &'static str,
) -> Result<String, (StatusCode, String)> {
    let reason = reason
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .unwrap_or(default_reason);
    if reason.len() <= EDR_MAX_RESPONSE_REASON_BYTES {
        return Ok(reason.to_string());
    }
    Err((
        StatusCode::BAD_REQUEST,
        format!("{field} reason must be at most {EDR_MAX_RESPONSE_REASON_BYTES} bytes"),
    ))
}

pub(crate) fn default_response_action_reason(
    action: &EndpointDecisionAction,
    dry_run: bool,
) -> &'static str {
    if dry_run {
        return "endpoint response dry run";
    }
    match action {
        EndpointDecisionAction::CollectEvidence => "collect endpoint evidence",
        EndpointDecisionAction::RestrictEgress => "restrict endpoint egress",
        EndpointDecisionAction::QuarantineFile => "quarantine endpoint file",
        EndpointDecisionAction::DisablePersistence => "disable endpoint persistence item",
        EndpointDecisionAction::RevokeGrant => "revoke local endpoint grant",
        EndpointDecisionAction::SuspendProcessTree => "suspend endpoint process tree",
        EndpointDecisionAction::TerminateProcessTree => "terminate endpoint process tree",
        _ => "execute endpoint response",
    }
}

pub(crate) async fn execute_edr_response_action(
    state: &AgentApiState,
    plan: &EndpointResponsePlan,
    graph: &CausalGraph,
    actor: EndpointDecisionActor,
) -> Result<
    (
        EndpointResponseExecutionReport,
        StoredEndpointEvidenceBundle,
        SignedReceipt,
        SignedReceipt,
    ),
    (StatusCode, String),
> {
    match plan.action {
        EndpointDecisionAction::CollectEvidence => {
            execute_collect_evidence_response(state, plan, graph, actor).await
        }
        EndpointDecisionAction::RestrictEgress => {
            execute_restrict_egress_response(state, plan, graph, actor).await
        }
        EndpointDecisionAction::QuarantineFile => {
            execute_quarantine_file_response(state, plan, graph, actor).await
        }
        EndpointDecisionAction::DisablePersistence => {
            execute_disable_persistence_response(state, plan, graph, actor).await
        }
        EndpointDecisionAction::RevokeGrant => {
            execute_revoke_grant_response(state, plan, graph, actor).await
        }
        EndpointDecisionAction::SuspendProcessTree => {
            execute_suspend_process_tree_response(state, plan, graph, actor).await
        }
        _ => Err((
            StatusCode::BAD_REQUEST,
            format!(
                "unsupported endpoint response action for live executor: {}",
                plan.action.as_str()
            ),
        )),
    }
}

pub(crate) async fn record_failed_edr_response_execution(
    state: &AgentApiState,
    plan: &EndpointResponsePlan,
    graph: &CausalGraph,
    actor: EndpointDecisionActor,
    failure: &str,
) -> Result<(String, Option<String>), String> {
    let execution = EndpointResponseExecutionReport::failed(plan, graph, failure)
        .map_err(|err| format!("build failed response execution report: {err}"))?;
    let (execution, _stored_bundle, receipt, _bundle_receipt) =
        persist_edr_response_execution(state, execution, graph, actor)
            .await
            .map_err(|(_status, err)| err)?;
    Ok((execution.execution_id, receipt.receipt.receipt_id.clone()))
}

pub(crate) fn response_action_failure_error(
    status: StatusCode,
    message: String,
    failure_record: Result<(String, Option<String>), String>,
) -> (StatusCode, String) {
    match failure_record {
        Ok((execution_id, receipt_id)) => {
            let receipt = receipt_id.unwrap_or_else(|| "unknown".to_string());
            (
                status,
                format!(
                    "{message}; failed response execution recorded as {execution_id} with receipt {receipt}"
                ),
            )
        }
        Err(err) => (
            status,
            format!("{message}; failed to record response failure receipt: {err}"),
        ),
    }
}

pub(crate) fn sanitize_response_execution_failure(message: &str) -> String {
    let redacted = redact_developer_activity_command_line(message.trim());
    truncate_delivery_error(&redact_response_failure_secret_like_fragments(&redacted))
}

fn sanitize_provider_status_reason(reason: &str) -> String {
    sanitize_response_execution_failure(reason)
}

fn redact_response_failure_secret_like_fragments(message: &str) -> String {
    let bytes = message.as_bytes();
    let mut redacted = String::with_capacity(message.len());
    let mut index = 0;
    while index < bytes.len() {
        if let Some((start, end)) = response_failure_secret_like_range(message, index) {
            debug_assert_eq!(start, index);
            redacted.push_str("[REDACTED]");
            index = end;
            continue;
        }
        let Some(ch) = message[index..].chars().next() else {
            break;
        };
        redacted.push(ch);
        index += ch.len_utf8();
    }
    redacted
}

fn response_failure_secret_like_range(message: &str, index: usize) -> Option<(usize, usize)> {
    for prefix in [
        "ghp_", "gho_", "ghu_", "ghs_", "ghr_", "sk-", "xoxb-", "xoxa-", "xoxp-", "xoxr-", "xoxs-",
    ] {
        if !message[index..].starts_with(prefix) {
            continue;
        }
        let mut end = index + prefix.len();
        while end < message.len()
            && message
                .as_bytes()
                .get(end)
                .is_some_and(|byte| response_failure_token_byte(*byte))
        {
            end += 1;
        }
        if developer_activity_secret_like_value(&message[index..end]) {
            return Some((index, end));
        }
    }

    if message[index..].starts_with("AKIA") {
        let mut end = index + "AKIA".len();
        while end < message.len()
            && message
                .as_bytes()
                .get(end)
                .is_some_and(|byte| byte.is_ascii_alphanumeric())
        {
            end += 1;
        }
        if developer_activity_secret_like_value(&message[index..end]) {
            return Some((index, end));
        }
    }

    None
}

fn response_failure_token_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.')
}

async fn execute_collect_evidence_response(
    state: &AgentApiState,
    plan: &EndpointResponsePlan,
    graph: &CausalGraph,
    actor: EndpointDecisionActor,
) -> Result<
    (
        EndpointResponseExecutionReport,
        StoredEndpointEvidenceBundle,
        SignedReceipt,
        SignedReceipt,
    ),
    (StatusCode, String),
> {
    let execution =
        EndpointResponseExecutionReport::collect_evidence(plan, graph).map_err(internal_error)?;
    persist_edr_response_execution(state, execution, graph, actor).await
}

async fn execute_restrict_egress_response(
    state: &AgentApiState,
    plan: &EndpointResponsePlan,
    graph: &CausalGraph,
    actor: EndpointDecisionActor,
) -> Result<
    (
        EndpointResponseExecutionReport,
        StoredEndpointEvidenceBundle,
        SignedReceipt,
        SignedReceipt,
    ),
    (StatusCode, String),
> {
    let targets = restrict_egress_targets(plan, graph).map_err(|err| {
        (
            StatusCode::BAD_REQUEST,
            format!("invalid egress restriction target: {err}"),
        )
    })?;
    ensure_network_extension_ready_for_restrict_egress(state).await?;
    let execution = EndpointResponseExecutionReport::restrict_egress(plan, graph, &targets)
        .map_err(internal_error)?;
    emit_pre_effect_response_execution_receipt(
        state,
        &execution,
        graph,
        actor.clone(),
        "pre_effect_restrict_egress",
    )
    .await?;
    let reload_proof = append_edr_egress_restrictions(state, &execution, &targets).await?;
    ensure_network_extension_reload_proof_succeeded(&reload_proof).map_err(|message| {
        (
            StatusCode::CONFLICT,
            format!("NetworkExtension did not activate egress restrictions: {message}"),
        )
    })?;
    let additional_evidence = network_extension_reload_request_evidence(&reload_proof);
    persist_edr_response_execution_with_evidence(
        state,
        execution,
        graph,
        actor,
        &additional_evidence,
    )
    .await
}

async fn execute_quarantine_file_response(
    state: &AgentApiState,
    plan: &EndpointResponsePlan,
    graph: &CausalGraph,
    actor: EndpointDecisionActor,
) -> Result<
    (
        EndpointResponseExecutionReport,
        StoredEndpointEvidenceBundle,
        SignedReceipt,
        SignedReceipt,
    ),
    (StatusCode, String),
> {
    let source_path = quarantine_file_target_path(plan, graph).map_err(|err| {
        (
            StatusCode::BAD_REQUEST,
            format!("invalid quarantine target: {err}"),
        )
    })?;
    validate_quarantine_source_path(&source_path).map_err(|err| {
        (
            StatusCode::BAD_REQUEST,
            format!("unsafe quarantine target: {err}"),
        )
    })?;
    let bytes = fs::read(&source_path)
        .with_context(|| format!("read quarantine target {}", source_path.display()))
        .map_err(internal_error)?;
    let byte_count = bytes.len() as u64;
    let content_hash = sha256(&bytes).to_hex_prefixed();
    let quarantine_root = state.edr_quarantine_root.as_ref();
    fs::create_dir_all(quarantine_root)
        .with_context(|| format!("create quarantine directory {}", quarantine_root.display()))
        .map_err(internal_error)?;
    let quarantine_path =
        quarantine_destination_path(quarantine_root, plan, &source_path, &content_hash);
    if quarantine_path.exists() {
        return Err((
            StatusCode::CONFLICT,
            format!(
                "quarantine artifact already exists: {}",
                quarantine_path.display()
            ),
        ));
    }
    let mut execution = EndpointResponseExecutionReport::quarantine_file(
        plan,
        graph,
        source_path.display().to_string(),
        quarantine_path.display().to_string(),
        &content_hash,
        byte_count,
    )
    .map_err(internal_error)?;
    execution.actor = Some(actor.clone());
    let stored_bundle = state
        .edr_evidence_bundle_store
        .lock()
        .await
        .store(&execution.evidence_bundle, graph)
        .map_err(internal_error)?;
    emit_pre_effect_response_execution_receipt(
        state,
        &execution,
        graph,
        actor.clone(),
        "pre_effect_quarantine_file",
    )
    .await?;
    fs::rename(&source_path, &quarantine_path)
        .with_context(|| {
            format!(
                "move quarantine target {} to {}",
                source_path.display(),
                quarantine_path.display()
            )
        })
        .map_err(internal_error)?;
    let (execution_receipt, evidence_bundle_receipt) =
        append_and_receipt_edr_response_execution(state, &execution, graph, Some(actor), &[])
            .await?;
    Ok((
        execution,
        stored_bundle,
        execution_receipt,
        evidence_bundle_receipt,
    ))
}

async fn execute_disable_persistence_response(
    state: &AgentApiState,
    plan: &EndpointResponsePlan,
    graph: &CausalGraph,
    actor: EndpointDecisionActor,
) -> Result<
    (
        EndpointResponseExecutionReport,
        StoredEndpointEvidenceBundle,
        SignedReceipt,
        SignedReceipt,
    ),
    (StatusCode, String),
> {
    let source_path = disable_persistence_target_path(plan, graph).map_err(|err| {
        (
            StatusCode::BAD_REQUEST,
            format!("invalid persistence target: {err}"),
        )
    })?;
    validate_disable_persistence_source_path(&source_path).map_err(|err| {
        (
            StatusCode::BAD_REQUEST,
            format!("unsafe persistence target: {err}"),
        )
    })?;
    let bytes = fs::read(&source_path)
        .with_context(|| format!("read persistence target {}", source_path.display()))
        .map_err(internal_error)?;
    let byte_count = bytes.len() as u64;
    let content_hash = sha256(&bytes).to_hex_prefixed();
    let quarantine_root = state.edr_quarantine_root.as_ref();
    fs::create_dir_all(quarantine_root)
        .with_context(|| {
            format!(
                "create persistence disable directory {}",
                quarantine_root.display()
            )
        })
        .map_err(internal_error)?;
    let disabled_path =
        persistence_disable_destination_path(quarantine_root, plan, &source_path, &content_hash);
    if disabled_path.exists() {
        return Err((
            StatusCode::CONFLICT,
            format!(
                "disabled persistence artifact already exists: {}",
                disabled_path.display()
            ),
        ));
    }
    let mut execution = EndpointResponseExecutionReport::disable_persistence(
        plan,
        graph,
        source_path.display().to_string(),
        disabled_path.display().to_string(),
        &content_hash,
        byte_count,
    )
    .map_err(internal_error)?;
    execution.actor = Some(actor.clone());
    let stored_bundle = state
        .edr_evidence_bundle_store
        .lock()
        .await
        .store(&execution.evidence_bundle, graph)
        .map_err(internal_error)?;
    emit_pre_effect_response_execution_receipt(
        state,
        &execution,
        graph,
        actor.clone(),
        "pre_effect_disable_persistence",
    )
    .await?;
    fs::rename(&source_path, &disabled_path)
        .with_context(|| {
            format!(
                "move persistence target {} to {}",
                source_path.display(),
                disabled_path.display()
            )
        })
        .map_err(internal_error)?;
    let (execution_receipt, evidence_bundle_receipt) =
        append_and_receipt_edr_response_execution(state, &execution, graph, Some(actor), &[])
            .await?;
    Ok((
        execution,
        stored_bundle,
        execution_receipt,
        evidence_bundle_receipt,
    ))
}

async fn execute_revoke_grant_response(
    state: &AgentApiState,
    plan: &EndpointResponsePlan,
    graph: &CausalGraph,
    actor: EndpointDecisionActor,
) -> Result<
    (
        EndpointResponseExecutionReport,
        StoredEndpointEvidenceBundle,
        SignedReceipt,
        SignedReceipt,
    ),
    (StatusCode, String),
> {
    let grant_target = revoke_grant_target(plan, graph).map_err(|err| {
        (
            StatusCode::BAD_REQUEST,
            format!("invalid revoke grant target: {err}"),
        )
    })?;
    let (grant_target, revoked_grant_hash) = match grant_target {
        RevokeGrantTarget::LocalApiAuthToken => {
            return Err((
                StatusCode::CONFLICT,
                "local API auth token revocation is not safe for autonomous response without durable replacement-token handoff and recovery"
                    .to_string(),
            ));
        }
        RevokeGrantTarget::BrokerCapability { capability_id } => {
            let revocation = revoke_broker_capability_grant(state, &capability_id).await?;
            let revoked_grant_hash =
                canonical_json_hash(&revocation, "broker capability revoke result")
                    .map_err(internal_error)?;
            (
                format!("broker_capability:{capability_id}"),
                revoked_grant_hash,
            )
        }
        RevokeGrantTarget::LocalIntegrationSecret { secret } => {
            let revocation = revoke_local_integration_secret_grant(state, secret).await?;
            let revoked_grant_hash =
                canonical_json_hash(&revocation, "local integration secret revoke result")
                    .map_err(internal_error)?;
            (
                format!("local_integration_secret:{}", secret.target_suffix()),
                revoked_grant_hash,
            )
        }
    };
    let execution = EndpointResponseExecutionReport::revoke_grant(
        plan,
        graph,
        grant_target,
        revoked_grant_hash,
    )
    .map_err(internal_error)?;
    persist_edr_response_execution(state, execution, graph, actor).await
}

async fn execute_suspend_process_tree_response(
    state: &AgentApiState,
    plan: &EndpointResponsePlan,
    graph: &CausalGraph,
    actor: EndpointDecisionActor,
) -> Result<
    (
        EndpointResponseExecutionReport,
        StoredEndpointEvidenceBundle,
        SignedReceipt,
        SignedReceipt,
    ),
    (StatusCode, String),
> {
    let targets = suspend_process_tree_targets(plan, graph).map_err(|err| {
        (
            StatusCode::BAD_REQUEST,
            format!("invalid process tree target: {err}"),
        )
    })?;
    validate_process_signal_targets(&targets).map_err(|err| {
        (
            StatusCode::BAD_REQUEST,
            format!("unsafe process tree target: {err}"),
        )
    })?;
    for target in &targets {
        validate_process_signal_target_before_signal(target).map_err(|err| {
            (
                StatusCode::CONFLICT,
                format!("process {} cannot be signalled safely: {err}", target.pid),
            )
        })?;
    }

    let root_pid = targets.first().map(|target| target.pid).ok_or_else(|| {
        (
            StatusCode::BAD_REQUEST,
            "process tree target is empty".to_string(),
        )
    })?;
    let identity_bindings = targets
        .iter()
        .map(|target| EndpointResponseProcessIdentityBinding {
            pid: target.pid,
            process_identity_key: target.process_identity_key.clone(),
        })
        .collect::<Vec<_>>();
    let execution = EndpointResponseExecutionReport::suspend_process_tree_with_identity_bindings(
        plan,
        graph,
        root_pid,
        &identity_bindings,
    )
    .map_err(internal_error)?;
    emit_pre_effect_response_execution_receipt(
        state,
        &execution,
        graph,
        actor.clone(),
        "pre_effect_suspend_process_tree",
    )
    .await?;

    let mut suspended = Vec::new();
    for target in targets.iter().rev() {
        validate_process_signal_target_before_signal(target).map_err(|err| {
            (
                StatusCode::CONFLICT,
                format!(
                    "process {} identity changed before suspend signal: {err}",
                    target.pid
                ),
            )
        })?;
        if let Err(err) = signal_process(target.pid, process_suspend_signal()) {
            let mut resume_errors = Vec::new();
            for pid in &suspended {
                if let Err(resume_err) = signal_process(*pid, process_resume_signal()) {
                    resume_errors.push(format!(
                        "failed to resume partially suspended pid {pid}: {resume_err}"
                    ));
                }
            }
            let cleanup_reason = format!(
                "suspend process tree failed while signalling pid {}; partial suspend cleanup ran",
                target.pid
            );
            if resume_errors.is_empty() {
                let compensated = EndpointResponseExecutionReport::rolled_back_from(
                    &execution,
                    cleanup_reason.as_str(),
                    chrono::Utc::now(),
                );
                {
                    let mut ledger = state.edr_response_execution_ledger.lock().await;
                    ledger.append(&compensated).map_err(internal_error)?;
                }
                let _ = emit_edr_response_execution_receipt(
                    state,
                    &compensated,
                    graph,
                    compensated.actor.clone(),
                    &[EndpointReceiptEvidence::hashed(
                        "partialSuspendCleanupForExecutionId",
                        execution.execution_id.as_str(),
                    )],
                )
                .await;
            } else {
                let failure = resume_errors.join("; ");
                let _ = record_edr_response_rollback_failure(
                    state,
                    &execution,
                    cleanup_reason.as_str(),
                    failure.as_str(),
                    graph,
                )
                .await;
            }
            let cleanup_suffix = if resume_errors.is_empty() {
                "; partially suspended processes were resumed and a rollback transition was recorded".to_string()
            } else {
                format!(
                    "; partial suspend cleanup failed and remains rollbackable: {}",
                    resume_errors.join("; ")
                )
            };
            return Err((
                StatusCode::CONFLICT,
                format!(
                    "failed to suspend process {}: {err}{cleanup_suffix}",
                    target.pid
                ),
            ));
        }
        suspended.push(target.pid);
    }
    persist_edr_response_execution(state, execution, graph, actor).await
}

pub(crate) async fn execute_restrict_egress_rollback(
    state: &AgentApiState,
    execution: &EndpointResponseExecutionReport,
    reason: &str,
) -> Result<EndpointResponseRollbackReport, (StatusCode, String)> {
    let rollback =
        EndpointResponseRollbackReport::restrict_egress(execution, reason, chrono::Utc::now())
            .map_err(internal_error)?;
    {
        let mut ledger = state.edr_egress_restriction_ledger.lock().await;
        ledger
            .deactivate_execution(&execution.execution_id, rollback.completed_at)
            .map_err(internal_error)?;
    }
    sync_edr_network_extension_egress_policy(state, rollback.completed_at).await?;
    Ok(rollback)
}

pub(crate) fn response_execution_expires_with_rollback(action: &EndpointDecisionAction) -> bool {
    matches!(
        action,
        &EndpointDecisionAction::RestrictEgress
            | &EndpointDecisionAction::QuarantineFile
            | &EndpointDecisionAction::DisablePersistence
            | &EndpointDecisionAction::SuspendProcessTree
    )
}

pub(crate) async fn execute_response_expiration_rollback(
    state: &AgentApiState,
    execution: &EndpointResponseExecutionReport,
) -> Result<EndpointResponseRollbackReport, (StatusCode, String)> {
    let reason = format!("response execution {} TTL expired", execution.execution_id);
    match execution.action {
        EndpointDecisionAction::RestrictEgress => {
            execute_restrict_egress_rollback(state, execution, &reason).await
        }
        EndpointDecisionAction::QuarantineFile => {
            execute_quarantine_file_rollback(state, execution, &reason)
        }
        EndpointDecisionAction::DisablePersistence => {
            execute_disable_persistence_rollback(state, execution, &reason)
        }
        EndpointDecisionAction::SuspendProcessTree => {
            execute_suspend_process_tree_rollback(execution, &reason)
        }
        _ => Err((
            StatusCode::BAD_REQUEST,
            format!(
                "response execution {} is not rollback-capable at expiration time",
                execution.execution_id
            ),
        )),
    }
}

pub(crate) fn execute_quarantine_file_rollback(
    state: &AgentApiState,
    execution: &EndpointResponseExecutionReport,
    reason: &str,
) -> Result<EndpointResponseRollbackReport, (StatusCode, String)> {
    let effect = quarantine_file_effect(execution).map_err(|err| {
        (
            StatusCode::BAD_REQUEST,
            format!("invalid quarantine execution effect: {err}"),
        )
    })?;
    let target_path = PathBuf::from(effect.target.as_str());
    validate_quarantine_restore_target_path(&target_path).map_err(|err| {
        (
            StatusCode::BAD_REQUEST,
            format!("unsafe rollback target: {err}"),
        )
    })?;
    if target_path.exists() {
        return Err((
            StatusCode::CONFLICT,
            format!(
                "rollback target already exists, refusing overwrite: {}",
                target_path.display()
            ),
        ));
    }
    let artifact_path = effect
        .artifact
        .as_deref()
        .map(PathBuf::from)
        .ok_or_else(|| {
            (
                StatusCode::BAD_REQUEST,
                "quarantine effect is missing artifact path".to_string(),
            )
        })?;
    validate_quarantine_artifact_path(state.edr_quarantine_root.as_ref(), &artifact_path)?;
    let artifact_bytes = fs::read(&artifact_path)
        .with_context(|| format!("read quarantine artifact {}", artifact_path.display()))
        .map_err(internal_error)?;
    let artifact_hash = sha256(&artifact_bytes).to_hex_prefixed();
    let expected_hash = effect.content_hash.as_deref().ok_or_else(|| {
        (
            StatusCode::BAD_REQUEST,
            "quarantine effect is missing content hash".to_string(),
        )
    })?;
    if artifact_hash != expected_hash {
        return Err((
            StatusCode::CONFLICT,
            format!(
                "quarantine artifact hash mismatch: expected {expected_hash}, got {artifact_hash}"
            ),
        ));
    }
    if let Some(expected_bytes) = effect.byte_count {
        if artifact_bytes.len() as u64 != expected_bytes {
            return Err((
                StatusCode::CONFLICT,
                format!(
                    "quarantine artifact byte count mismatch: expected {expected_bytes}, got {}",
                    artifact_bytes.len()
                ),
            ));
        }
    }
    if let Some(parent) = target_path.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("create rollback target directory {}", parent.display()))
            .map_err(internal_error)?;
    }
    let rollback =
        EndpointResponseRollbackReport::quarantine_file(execution, reason, chrono::Utc::now())
            .map_err(internal_error)?;
    fs::rename(&artifact_path, &target_path)
        .with_context(|| {
            format!(
                "restore quarantine artifact {} to {}",
                artifact_path.display(),
                target_path.display()
            )
        })
        .map_err(internal_error)?;
    Ok(rollback)
}

pub(crate) fn execute_disable_persistence_rollback(
    state: &AgentApiState,
    execution: &EndpointResponseExecutionReport,
    reason: &str,
) -> Result<EndpointResponseRollbackReport, (StatusCode, String)> {
    let effect = disable_persistence_effect(execution).map_err(|err| {
        (
            StatusCode::BAD_REQUEST,
            format!("invalid persistence execution effect: {err}"),
        )
    })?;
    let target_path = PathBuf::from(effect.target.as_str());
    validate_disable_persistence_restore_target_path(&target_path).map_err(|err| {
        (
            StatusCode::BAD_REQUEST,
            format!("unsafe persistence rollback target: {err}"),
        )
    })?;
    if target_path.exists() {
        return Err((
            StatusCode::CONFLICT,
            format!(
                "persistence rollback target already exists, refusing overwrite: {}",
                target_path.display()
            ),
        ));
    }
    let artifact_path = effect
        .artifact
        .as_deref()
        .map(PathBuf::from)
        .ok_or_else(|| {
            (
                StatusCode::BAD_REQUEST,
                "disable_persistence effect is missing artifact path".to_string(),
            )
        })?;
    validate_quarantine_artifact_path(state.edr_quarantine_root.as_ref(), &artifact_path)?;
    let artifact_bytes = fs::read(&artifact_path)
        .with_context(|| {
            format!(
                "read disabled persistence artifact {}",
                artifact_path.display()
            )
        })
        .map_err(internal_error)?;
    let artifact_hash = sha256(&artifact_bytes).to_hex_prefixed();
    let expected_hash = effect.content_hash.as_deref().ok_or_else(|| {
        (
            StatusCode::BAD_REQUEST,
            "disable_persistence effect is missing content hash".to_string(),
        )
    })?;
    if artifact_hash != expected_hash {
        return Err((
            StatusCode::CONFLICT,
            format!(
                "disabled persistence artifact hash mismatch: expected {expected_hash}, got {artifact_hash}"
            ),
        ));
    }
    if let Some(expected_bytes) = effect.byte_count {
        if artifact_bytes.len() as u64 != expected_bytes {
            return Err((
                StatusCode::CONFLICT,
                format!(
                    "disabled persistence artifact byte count mismatch: expected {expected_bytes}, got {}",
                    artifact_bytes.len()
                ),
            ));
        }
    }
    if let Some(parent) = target_path.parent() {
        fs::create_dir_all(parent)
            .with_context(|| {
                format!(
                    "create persistence rollback target directory {}",
                    parent.display()
                )
            })
            .map_err(internal_error)?;
    }
    let rollback =
        EndpointResponseRollbackReport::disable_persistence(execution, reason, chrono::Utc::now())
            .map_err(internal_error)?;
    fs::rename(&artifact_path, &target_path)
        .with_context(|| {
            format!(
                "restore disabled persistence artifact {} to {}",
                artifact_path.display(),
                target_path.display()
            )
        })
        .map_err(internal_error)?;
    Ok(rollback)
}

pub(crate) fn execute_suspend_process_tree_rollback(
    execution: &EndpointResponseExecutionReport,
    reason: &str,
) -> Result<EndpointResponseRollbackReport, (StatusCode, String)> {
    let effect = suspend_process_tree_effect(execution).map_err(|err| {
        (
            StatusCode::BAD_REQUEST,
            format!("invalid process tree execution effect: {err}"),
        )
    })?;
    let targets = process_tree_effect_signal_targets(effect).map_err(|err| {
        (
            StatusCode::BAD_REQUEST,
            format!("invalid process tree pid set: {err}"),
        )
    })?;
    let rollback =
        EndpointResponseRollbackReport::suspend_process_tree(execution, reason, chrono::Utc::now())
            .map_err(internal_error)?;
    for target in &targets {
        validate_process_effect_signal_target_before_signal(target).map_err(|err| {
            (
                StatusCode::CONFLICT,
                format!(
                    "process {} identity changed before resume signal: {err}",
                    target.pid
                ),
            )
        })?;
        signal_process(target.pid, process_resume_signal()).map_err(|err| {
            (
                StatusCode::CONFLICT,
                format!("failed to resume suspended process {}: {err}", target.pid),
            )
        })?;
    }
    Ok(rollback)
}

async fn persist_edr_response_execution(
    state: &AgentApiState,
    execution: EndpointResponseExecutionReport,
    graph: &CausalGraph,
    actor: EndpointDecisionActor,
) -> Result<
    (
        EndpointResponseExecutionReport,
        StoredEndpointEvidenceBundle,
        SignedReceipt,
        SignedReceipt,
    ),
    (StatusCode, String),
> {
    persist_edr_response_execution_with_evidence(state, execution, graph, actor, &[]).await
}

async fn emit_pre_effect_response_execution_receipt(
    state: &AgentApiState,
    execution: &EndpointResponseExecutionReport,
    graph: &CausalGraph,
    actor: EndpointDecisionActor,
    phase: &str,
) -> Result<SignedReceipt, (StatusCode, String)> {
    let mut prepared = execution.clone();
    prepared.status = EndpointResponseExecutionStatus::Partial;
    prepared.completed_at = chrono::Utc::now();
    prepared.summary = format!(
        "Durably recorded {} response execution intent before local side effects.",
        execution.action.as_str()
    );
    let reason_hash = sha256(prepared.reason.as_bytes()).to_hex_prefixed();
    prepared.execution_id = response_execution_transition_id(
        "response_execution_partial",
        prepared.action_id.as_str(),
        prepared.evidence_bundle.bundle_id.as_str(),
        prepared.rollback_ref.as_str(),
        reason_hash.as_str(),
    );
    let evidence = [EndpointReceiptEvidence::hashed("executionPhase", phase)];
    state
        .edr_response_execution_ledger
        .lock()
        .await
        .append(&prepared)
        .map_err(internal_error)?;
    emit_edr_response_execution_receipt(state, &prepared, graph, Some(actor), &evidence)
        .await
        .map_err(internal_error)
}

pub(crate) async fn record_edr_response_rollback_intent(
    state: &AgentApiState,
    execution: &EndpointResponseExecutionReport,
    reason: &str,
    graph: &CausalGraph,
) -> Result<(EndpointResponseExecutionReport, SignedReceipt), (StatusCode, String)> {
    let pending = EndpointResponseExecutionReport::rollback_pending_from(
        execution,
        reason,
        chrono::Utc::now(),
    );
    {
        let mut ledger = state.edr_response_execution_ledger.lock().await;
        ledger.append(&pending).map_err(internal_error)?;
    }
    let receipt = emit_edr_response_execution_receipt(
        state,
        &pending,
        graph,
        pending.actor.clone(),
        &[EndpointReceiptEvidence::hashed(
            "rollbackIntentForExecutionId",
            execution.execution_id.as_str(),
        )],
    )
    .await
    .map_err(internal_error)?;
    Ok((pending, receipt))
}

pub(crate) async fn record_edr_response_rollback_failure(
    state: &AgentApiState,
    execution: &EndpointResponseExecutionReport,
    reason: &str,
    failure: &str,
    graph: &CausalGraph,
) -> Result<(EndpointResponseExecutionReport, SignedReceipt), (StatusCode, String)> {
    let failed = EndpointResponseExecutionReport::rollback_failed_from(
        execution,
        reason,
        failure,
        chrono::Utc::now(),
    );
    {
        let mut ledger = state.edr_response_execution_ledger.lock().await;
        ledger.append(&failed).map_err(internal_error)?;
    }
    let receipt = emit_edr_response_execution_receipt(
        state,
        &failed,
        graph,
        failed.actor.clone(),
        &[EndpointReceiptEvidence::hashed(
            "rollbackFailureForExecutionId",
            execution.execution_id.as_str(),
        )],
    )
    .await
    .map_err(internal_error)?;
    Ok((failed, receipt))
}

fn response_execution_transition_id(
    prefix: &str,
    response_action_id: &str,
    evidence_bundle_id: &str,
    rollback_ref: &str,
    reason_hash: &str,
) -> String {
    edr_fnv_stable_id(
        prefix,
        [
            response_action_id,
            evidence_bundle_id,
            rollback_ref,
            reason_hash,
        ],
    )
}

fn edr_fnv_stable_id<'a>(prefix: &str, parts: impl IntoIterator<Item = &'a str>) -> String {
    const FNV_OFFSET: u64 = 0xcbf2_9ce4_8422_2325;
    const FNV_PRIME: u64 = 0x0000_0100_0000_01b3;
    let mut hash = FNV_OFFSET;
    for part in parts {
        for byte in part.as_bytes() {
            hash ^= u64::from(*byte);
            hash = hash.wrapping_mul(FNV_PRIME);
        }
        hash ^= 0xff;
        hash = hash.wrapping_mul(FNV_PRIME);
    }
    format!("{prefix}:{hash:016x}")
}

async fn persist_edr_response_execution_with_evidence(
    state: &AgentApiState,
    mut execution: EndpointResponseExecutionReport,
    graph: &CausalGraph,
    actor: EndpointDecisionActor,
    additional_evidence: &[EndpointReceiptEvidence],
) -> Result<
    (
        EndpointResponseExecutionReport,
        StoredEndpointEvidenceBundle,
        SignedReceipt,
        SignedReceipt,
    ),
    (StatusCode, String),
> {
    execution.actor = Some(actor.clone());
    let stored_bundle = state
        .edr_evidence_bundle_store
        .lock()
        .await
        .store(&execution.evidence_bundle, graph)
        .map_err(internal_error)?;
    let (execution_receipt, evidence_bundle_receipt) = append_and_receipt_edr_response_execution(
        state,
        &execution,
        graph,
        Some(actor),
        additional_evidence,
    )
    .await?;
    Ok((
        execution,
        stored_bundle,
        execution_receipt,
        evidence_bundle_receipt,
    ))
}

async fn append_and_receipt_edr_response_execution(
    state: &AgentApiState,
    execution: &EndpointResponseExecutionReport,
    graph: &CausalGraph,
    actor: Option<EndpointDecisionActor>,
    additional_evidence: &[EndpointReceiptEvidence],
) -> Result<(SignedReceipt, SignedReceipt), (StatusCode, String)> {
    state
        .edr_response_execution_ledger
        .lock()
        .await
        .append(execution)
        .map_err(internal_error)?;
    let receipt =
        emit_edr_response_execution_receipt(state, execution, graph, actor, additional_evidence)
            .await
            .map_err(internal_error)?;
    let bundle_receipt = emit_edr_evidence_bundle_manifest_receipt(state, execution, graph)
        .await
        .map_err(internal_error)?;
    Ok((receipt, bundle_receipt))
}

pub(crate) async fn append_edr_response_acknowledgement(
    state: &AgentApiState,
    acknowledgement: &EndpointResponseAcknowledgementReport,
) -> Result<Option<String>, (StatusCode, String)> {
    let mut ledger = state.edr_response_acknowledgement_ledger.lock().await;
    let path = ledger.path().map(|path| path.display().to_string());
    ledger.append(acknowledgement).map_err(internal_error)?;
    Ok(path)
}

async fn append_edr_egress_restrictions(
    state: &AgentApiState,
    execution: &EndpointResponseExecutionReport,
    targets: &[String],
) -> Result<NetworkExtensionReloadRequestProof, (StatusCode, String)> {
    let now = execution.completed_at;
    let expires_at = execution.expires_at();
    let restrictions = targets
        .iter()
        .map(|target| EndpointEgressRestriction::active(execution, target, now, expires_at))
        .collect::<Vec<_>>();
    {
        let mut ledger = state.edr_egress_restriction_ledger.lock().await;
        ledger.append(&restrictions).map_err(internal_error)?;
    }
    let reload_proof = match sync_edr_network_extension_egress_policy(state, now).await {
        Ok(reload_proof) => reload_proof,
        Err(err) => {
            rollback_egress_restrictions_after_failed_reload(state, execution, now).await?;
            return Err(err);
        }
    };
    if let Err(message) = ensure_network_extension_reload_proof_succeeded(&reload_proof) {
        rollback_egress_restrictions_after_failed_reload(state, execution, now).await?;
        return Err((
            StatusCode::CONFLICT,
            format!("NetworkExtension egress policy reload failed: {message}"),
        ));
    }
    Ok(reload_proof)
}

async fn rollback_egress_restrictions_after_failed_reload(
    state: &AgentApiState,
    execution: &EndpointResponseExecutionReport,
    now: chrono::DateTime<chrono::Utc>,
) -> Result<(), (StatusCode, String)> {
    {
        let mut ledger = state.edr_egress_restriction_ledger.lock().await;
        ledger
            .deactivate_execution(&execution.execution_id, now)
            .map_err(internal_error)?;
    }
    match sync_edr_network_extension_egress_policy(state, now).await {
        Ok(rollback_proof) => {
            if let Err(message) = ensure_network_extension_reload_proof_succeeded(&rollback_proof) {
                tracing::warn!(
                    execution_id = %execution.execution_id,
                    action_id = %execution.action_id,
                    error = %message,
                    "NetworkExtension egress restriction rollback snapshot was written but reload did not acknowledge"
                );
            }
        }
        Err((status, message)) => {
            tracing::warn!(
                execution_id = %execution.execution_id,
                action_id = %execution.action_id,
                status = %status,
                error = %message,
                "NetworkExtension egress restriction rollback sync failed"
            );
        }
    }
    Ok(())
}

fn ensure_network_extension_reload_proof_succeeded(
    proof: &NetworkExtensionReloadRequestProof,
) -> Result<(), String> {
    if proof.requested
        && proof.saved
        && proof.error.is_none()
        && proof.provider_reload_matched
        && proof.provider_policy_synced == Some(true)
        && proof.provider_enforcement_ready == Some(true)
    {
        return Ok(());
    }
    let reason = proof
        .error
        .as_deref()
        .filter(|value| !value.trim().is_empty())
        .unwrap_or("reload request was not acknowledged by the provider");
    Err(format!(
        "requested={}, saved={}, observed={}, matched={}, policy_synced={:?}, enforcement_ready={:?}, generation={}, reason={reason}",
        proof.requested,
        proof.saved,
        proof.provider_reload_observed,
        proof.provider_reload_matched,
        proof.provider_policy_synced,
        proof.provider_enforcement_ready,
        proof.generation
    ))
}

pub(crate) async fn deactivate_expired_egress_restrictions(
    state: &AgentApiState,
    expired: &[EndpointResponseExecutionReport],
    now: chrono::DateTime<chrono::Utc>,
) -> Result<(), (StatusCode, String)> {
    for execution in expired {
        if execution.action == EndpointDecisionAction::RestrictEgress {
            deactivate_egress_restrictions_if_active(state, &execution.action_id, now).await?;
        }
    }
    Ok(())
}

pub(crate) async fn deactivate_egress_restrictions_if_active(
    state: &AgentApiState,
    action_id: &str,
    now: chrono::DateTime<chrono::Utc>,
) -> Result<(), (StatusCode, String)> {
    {
        let mut ledger = state.edr_egress_restriction_ledger.lock().await;
        ledger
            .deactivate_action_if_active(action_id, now)
            .map_err(internal_error)?;
    }
    sync_edr_network_extension_egress_policy(state, now)
        .await
        .map(|_| ())
}

async fn sync_edr_network_extension_egress_policy(
    state: &AgentApiState,
    now: chrono::DateTime<chrono::Utc>,
) -> Result<NetworkExtensionReloadRequestProof, (StatusCode, String)> {
    let restrictions = active_network_extension_egress_restrictions(state, now, Vec::new()).await;
    write_network_extension_egress_policy_snapshot(
        state.edr_network_extension_egress_policy_path.as_ref(),
        &restrictions,
        now,
    )
    .map_err(internal_error)?;
    Ok(request_network_extension_egress_policy_reload(state, now).await)
}

async fn request_network_extension_egress_policy_reload(
    state: &AgentApiState,
    now: chrono::DateTime<chrono::Utc>,
) -> NetworkExtensionReloadRequestProof {
    let generation = network_extension_reload_generation(now);
    request_network_extension_reload_for_path(
        state,
        state
            .edr_network_extension_egress_policy_path
            .as_ref()
            .clone(),
        generation,
        Duration::from_millis(EDR_DEFAULT_PROVIDER_ACK_TIMEOUT_MS),
        "egress policy sync",
    )
    .await
}

async fn request_policy_delta_network_extension_reload(
    state: &AgentApiState,
    settings: &Settings,
    local_policy: &EndpointPolicySnapshot,
    policy_delta_artifact: Option<&EdrPolicyDeltaArtifact>,
    timeout_ms: u64,
) -> Result<NetworkExtensionReloadRequestProof> {
    let now = chrono::Utc::now();
    let policy_restrictions =
        policy_egress_block_restrictions_from_settings(settings, local_policy, now)?;
    ensure_policy_delta_network_extension_target_represented(
        policy_delta_artifact,
        &policy_restrictions,
    )?;
    let restrictions =
        active_network_extension_egress_restrictions(state, now, policy_restrictions).await;
    write_network_extension_egress_policy_snapshot(
        state.edr_network_extension_egress_policy_path.as_ref(),
        &restrictions,
        now,
    )?;
    let generation = network_extension_reload_generation(now);
    Ok(request_network_extension_reload_for_path(
        state,
        state
            .edr_network_extension_egress_policy_path
            .as_ref()
            .clone(),
        generation,
        Duration::from_millis(timeout_ms),
        "policy delta apply",
    )
    .await)
}

async fn active_network_extension_egress_restrictions(
    state: &AgentApiState,
    now: chrono::DateTime<chrono::Utc>,
    policy_restrictions: Vec<EndpointEgressRestriction>,
) -> Vec<EndpointEgressRestriction> {
    let mut restrictions = {
        let ledger = state.edr_egress_restriction_ledger.lock().await;
        ledger.active_entries(now)
    };
    let mut targets = restrictions
        .iter()
        .map(|restriction| restriction.target.clone())
        .collect::<BTreeSet<_>>();
    for restriction in policy_restrictions {
        if targets.insert(restriction.target.clone()) {
            restrictions.push(restriction);
        }
    }
    restrictions
}

fn policy_egress_block_restrictions_from_settings(
    settings: &Settings,
    local_policy: &EndpointPolicySnapshot,
    now: chrono::DateTime<chrono::Utc>,
) -> Result<Vec<EndpointEgressRestriction>> {
    let policy_bytes = fs::read(&settings.policy_path).with_context(|| {
        format!(
            "read local policy for NetworkExtension egress snapshot {}",
            settings.policy_path.display()
        )
    })?;
    let targets = policy_egress_block_targets_from_policy_bytes(&policy_bytes)?;
    let epoch = local_policy.policy_epoch.to_string();
    let policy_id = local_stable_id(
        "policy_egress",
        [
            local_policy.policy_hash.as_str(),
            epoch.as_str(),
            local_policy.policy_version.as_str(),
        ],
    );
    let expires_at = now + chrono::Duration::days(3650);
    Ok(targets
        .into_iter()
        .map(|target| {
            let restriction_id = local_stable_id(
                "policy_egress_restriction",
                [
                    local_policy.policy_hash.as_str(),
                    epoch.as_str(),
                    target.as_str(),
                ],
            );
            EndpointEgressRestriction {
                restriction_id,
                execution_id: policy_id.clone(),
                action_id: policy_id.clone(),
                graph_slice_id: "local-policy-egress-allowlist".to_string(),
                rollback_ref: format!(
                    "policy:{}@{}",
                    local_policy.policy_version, local_policy.policy_epoch
                ),
                target_hash: sha256(target.as_bytes()).to_hex_prefixed(),
                target,
                active: true,
                created_at: now,
                expires_at,
                updated_at: now,
            }
        })
        .collect())
}

fn policy_egress_block_targets_from_policy_bytes(policy_bytes: &[u8]) -> Result<Vec<String>> {
    let policy: serde_yaml::Value = serde_yaml::from_slice(policy_bytes)
        .context("parse local policy yaml for NetworkExtension egress snapshot")?;
    let Some(egress_allowlist) = policy
        .get("guards")
        .and_then(|guards| guards.get("egress_allowlist"))
    else {
        return Ok(Vec::new());
    };

    let mut targets = Vec::new();
    collect_policy_egress_targets(
        egress_allowlist.get("block"),
        "guards.egress_allowlist.block",
        &mut targets,
    )?;
    collect_policy_egress_targets(
        egress_allowlist.get("additional_block"),
        "guards.egress_allowlist.additional_block",
        &mut targets,
    )?;
    targets.sort();
    targets.dedup();
    Ok(targets)
}

fn collect_policy_egress_targets(
    value: Option<&serde_yaml::Value>,
    path: &str,
    targets: &mut Vec<String>,
) -> Result<()> {
    let Some(value) = value else {
        return Ok(());
    };
    match value {
        serde_yaml::Value::Sequence(items) => {
            for (index, item) in items.iter().enumerate() {
                collect_policy_egress_target(item, format!("{path}[{index}]").as_str(), targets)?;
            }
            Ok(())
        }
        serde_yaml::Value::Null => Ok(()),
        _ => collect_policy_egress_target(value, path, targets),
    }
}

fn collect_policy_egress_target(
    value: &serde_yaml::Value,
    path: &str,
    targets: &mut Vec<String>,
) -> Result<()> {
    let Some(raw_target) = value
        .as_str()
        .map(str::trim)
        .filter(|target| !target.is_empty())
    else {
        return Err(anyhow::anyhow!(
            "{path} must contain string egress targets for NetworkExtension policy sync"
        ));
    };
    match normalize_egress_target(raw_target) {
        Ok(target) => {
            targets.push(target);
        }
        Err(err) => {
            tracing::debug!(
                path,
                target = raw_target,
                error = %err,
                "skipping policy egress target that cannot be represented as a literal NetworkExtension restriction"
            );
        }
    }
    Ok(())
}

fn ensure_policy_delta_network_extension_target_represented(
    artifact: Option<&EdrPolicyDeltaArtifact>,
    restrictions: &[EndpointEgressRestriction],
) -> Result<()> {
    let Some(artifact) = artifact else {
        return Ok(());
    };
    if !matches!(
        (&artifact.candidate.root_kind, &artifact.rollout.action),
        (
            CausalNodeKind::Network,
            EndpointDecisionAction::RestrictEgress | EndpointDecisionAction::Block
        )
    ) {
        return Ok(());
    }

    let target =
        normalize_egress_target(artifact.candidate.root_label.as_str()).with_context(|| {
            format!(
                "normalize policy delta NetworkExtension egress target {}",
                artifact.candidate.root_label
            )
        })?;
    if restrictions
        .iter()
        .any(|restriction| restriction.active && restriction.target == target)
    {
        return Ok(());
    }
    Err(anyhow::anyhow!(
        "policy delta NetworkExtension snapshot does not contain enforced egress target {target}"
    ))
}

async fn request_network_extension_reload_for_path(
    state: &AgentApiState,
    policy_snapshot_path: PathBuf,
    generation: u64,
    timeout: Duration,
    context: &str,
) -> NetworkExtensionReloadRequestProof {
    let policy_snapshot_path_display = policy_snapshot_path.display().to_string();
    match state
        .macos_host
        .request_network_extension_reload(policy_snapshot_path, generation, timeout)
        .await
    {
        Ok(result) => {
            let mut proof = NetworkExtensionReloadRequestProof {
                requested: result.requested,
                saved: result.saved,
                request_id: Some(result.request_id),
                policy_snapshot_path: result.policy_snapshot_path,
                generation: result.generation,
                provider_reload_observed: false,
                provider_reload_matched: false,
                provider_reload_request_id_matches: false,
                provider_reload_generation_matches: false,
                provider_reload_policy_snapshot_path_matches: false,
                provider_reloaded: None,
                provider_policy_synced: None,
                provider_enforcement_ready: None,
                provider_reload_elapsed_ms: 0,
                provider_reload_attempts: 0,
                error: None,
            };
            if proof.requested && proof.saved {
                wait_for_network_extension_reload_delivery(state, &mut proof, timeout).await;
            }
            proof
        }
        Err(err) => {
            tracing::warn!(
                error = %err,
                policy_snapshot_path = %policy_snapshot_path_display,
                generation,
                context,
                "NetworkExtension reload request failed"
            );
            NetworkExtensionReloadRequestProof {
                requested: false,
                saved: false,
                request_id: None,
                policy_snapshot_path: policy_snapshot_path_display,
                generation,
                provider_reload_observed: false,
                provider_reload_matched: false,
                provider_reload_request_id_matches: false,
                provider_reload_generation_matches: false,
                provider_reload_policy_snapshot_path_matches: false,
                provider_reloaded: None,
                provider_policy_synced: None,
                provider_enforcement_ready: None,
                provider_reload_elapsed_ms: 0,
                provider_reload_attempts: 0,
                error: Some(err.to_string()),
            }
        }
    }
}

async fn wait_for_network_extension_reload_delivery(
    state: &AgentApiState,
    proof: &mut NetworkExtensionReloadRequestProof,
    timeout: Duration,
) {
    let started = Instant::now();
    let mut attempts = 0u64;

    loop {
        attempts = attempts.saturating_add(1);
        let elapsed = started.elapsed();
        let remaining = timeout.saturating_sub(elapsed);
        let status = match state
            .macos_host
            .request_refresh(remaining.min(EDR_PROVIDER_ACK_POLL_INTERVAL))
            .await
        {
            Ok(status) => status,
            Err(_) => state.macos_host.snapshot().await,
        };
        update_network_extension_reload_delivery(proof, &status, started.elapsed(), attempts);

        if proof.provider_reload_matched || started.elapsed() >= timeout {
            return;
        }

        let remaining = timeout.saturating_sub(started.elapsed());
        if remaining.is_zero() {
            return;
        }
        tokio::time::sleep(remaining.min(EDR_PROVIDER_ACK_POLL_INTERVAL)).await;
    }
}

fn update_network_extension_reload_delivery(
    proof: &mut NetworkExtensionReloadRequestProof,
    status: &CombinedSystemExtensionStatus,
    elapsed: Duration,
    attempts: u64,
) {
    let provider = &status.network_extension;
    let observation = provider.last_reload_observation.as_ref();
    let request_id_matches = observation
        .and_then(|observation| observation.request_id.as_deref())
        .zip(proof.request_id.as_deref())
        .is_some_and(|(observed, expected)| observed == expected);
    let generation_matches = observation
        .and_then(|observation| observation.generation)
        .is_some_and(|observed| observed == proof.generation);
    let policy_snapshot_path_matches = observation
        .and_then(|observation| observation.policy_snapshot_path.as_deref())
        .is_some_and(|observed| observed == proof.policy_snapshot_path);
    let provider_reloaded = observation.and_then(|observation| observation.reloaded);
    proof.provider_reload_observed = observation.is_some();
    proof.provider_reload_request_id_matches = request_id_matches;
    proof.provider_reload_generation_matches = generation_matches;
    proof.provider_reload_policy_snapshot_path_matches = policy_snapshot_path_matches;
    proof.provider_reloaded = provider_reloaded;
    proof.provider_policy_synced = provider.policy_synced;
    proof.provider_enforcement_ready = provider.enforcement_ready;
    proof.provider_reload_elapsed_ms = elapsed.as_millis().min(u128::from(u64::MAX)) as u64;
    proof.provider_reload_attempts = attempts;
    proof.provider_reload_matched = proof.requested
        && proof.saved
        && proof.error.is_none()
        && request_id_matches
        && generation_matches
        && policy_snapshot_path_matches
        && provider_reloaded == Some(true)
        && provider.policy_synced == Some(true)
        && provider.enforcement_ready == Some(true);
}

fn network_extension_reload_generation(now: chrono::DateTime<chrono::Utc>) -> u64 {
    u64::try_from(now.timestamp_millis()).unwrap_or(0)
}

async fn active_egress_restriction_for_policy_check(
    state: &AgentApiState,
    input: &PolicyCheckInput,
) -> Option<EndpointEgressRestriction> {
    let target = normalize_egress_policy_target(&input.action_type, &input.target)?;
    let ledger = state.edr_egress_restriction_ledger.lock().await;
    ledger.active_match(&target, chrono::Utc::now())
}

fn policy_output_for_active_egress_restriction(
    restriction: &EndpointEgressRestriction,
) -> PolicyCheckOutput {
    PolicyCheckOutput {
        allowed: false,
        guard: Some("edr_restrict_egress".to_string()),
        severity: Some("high".to_string()),
        message: Some(format!(
            "Egress to {} denied by active EDR response execution {}",
            restriction.target, restriction.execution_id
        )),
        details: Some(serde_json::json!({
            "reason": "active_edr_egress_restriction",
            "target": restriction.target.clone(),
            "executionId": restriction.execution_id.clone(),
            "actionId": restriction.action_id.clone(),
            "rollbackRef": restriction.rollback_ref.clone(),
            "graphSliceId": restriction.graph_slice_id.clone(),
            "expiresAt": restriction.expires_at,
        })),
    }
}

fn restrict_egress_targets(
    plan: &EndpointResponsePlan,
    graph: &CausalGraph,
) -> Result<Vec<String>> {
    let root = graph
        .nodes
        .get(&plan.root_node_id)
        .ok_or_else(|| anyhow::anyhow!("root node not found: {}", plan.root_node_id))?;
    let root_target = if root.kind == CausalNodeKind::Network {
        Some(egress_target_from_node(root)?)
    } else {
        None
    };

    let mut targets = graph
        .nodes
        .values()
        .filter(|node| node.kind == CausalNodeKind::Network)
        .map(egress_target_from_node)
        .collect::<Result<Vec<_>>>()?;
    targets.sort();
    targets.dedup();
    if targets.is_empty() {
        return Err(anyhow::anyhow!(
            "restrict_egress requires at least one network node in the graph slice"
        ));
    }
    if let Some(root_target) = root_target {
        targets.retain(|target| target != &root_target);
        targets.insert(0, root_target);
    }
    Ok(targets)
}

fn egress_target_from_node(node: &clawdstrike_policy_event::edr::CausalNode) -> Result<String> {
    normalize_egress_target(node.label.as_str())
        .with_context(|| format!("normalize network node target {}", node.label))
}

fn normalize_egress_policy_target(action_type: &str, target: &str) -> Option<String> {
    let action = action_type.trim().to_ascii_lowercase();
    if action != "egress" && action != "network" {
        return None;
    }
    let target = target.trim();
    let lower = target.to_ascii_lowercase();
    let target = if lower.starts_with("http://")
        || lower.starts_with("https://")
        || lower.starts_with("ws://")
        || lower.starts_with("wss://")
    {
        let url = reqwest::Url::parse(target).ok()?;
        let host = url.host_str()?;
        let port = url.port_or_known_default()?;
        if host.contains(':') {
            format!("[{host}]:{port}")
        } else {
            format!("{host}:{port}")
        }
    } else {
        target.to_string()
    };
    normalize_egress_target(target.as_str()).ok()
}

fn normalize_egress_target(target: &str) -> Result<String> {
    let target = target.trim();
    if target.is_empty() {
        return Err(anyhow::anyhow!("egress target must not be empty"));
    }
    if target.len() > 512 {
        return Err(anyhow::anyhow!("egress target must be at most 512 bytes"));
    }
    if target
        .chars()
        .any(|ch| ch.is_ascii_whitespace() || matches!(ch, '*' | ',' | '/'))
    {
        return Err(anyhow::anyhow!(
            "egress target must be a literal host:port without wildcards or paths"
        ));
    }
    let (host, port) = split_egress_host_port(target)?;
    let port: u16 = port
        .parse()
        .with_context(|| format!("parse egress target port {port}"))?;
    if port == 0 {
        return Err(anyhow::anyhow!("egress target port must be non-zero"));
    }
    let normalized_host = host.trim_matches(['[', ']']).to_ascii_lowercase();
    if normalized_host.is_empty() {
        return Err(anyhow::anyhow!("egress target host must not be empty"));
    }
    if matches!(
        normalized_host.as_str(),
        "localhost" | "localhost.localdomain"
    ) {
        return Err(anyhow::anyhow!("refusing to restrict local host egress"));
    }
    if let Ok(ip) = normalized_host.parse::<IpAddr>() {
        validate_egress_restriction_ip(ip)?;
    }
    if normalized_host.contains(':') {
        Ok(format!("[{normalized_host}]:{port}"))
    } else {
        Ok(format!("{normalized_host}:{port}"))
    }
}

fn split_egress_host_port(target: &str) -> Result<(&str, &str)> {
    if let Some(rest) = target.strip_prefix('[') {
        let (host, port) = rest
            .split_once("]:")
            .ok_or_else(|| anyhow::anyhow!("bracketed egress target must be [host]:port"))?;
        return Ok((host, port));
    }
    target
        .rsplit_once(':')
        .ok_or_else(|| anyhow::anyhow!("egress target must include a port"))
}

fn validate_egress_restriction_ip(ip: IpAddr) -> Result<()> {
    let blocked = match ip {
        IpAddr::V4(ip) => {
            ip.is_loopback()
                || ip.is_private()
                || ip.is_link_local()
                || ip.is_broadcast()
                || ip.is_documentation()
                || ip.is_unspecified()
        }
        IpAddr::V6(ip) => {
            ip.is_loopback()
                || ip.is_unspecified()
                || ipv6_is_unique_local(&ip)
                || ipv6_is_unicast_link_local(&ip)
                || ip.is_multicast()
        }
    };
    if blocked {
        return Err(anyhow::anyhow!(
            "refusing to restrict local, private, link-local, multicast, or documentation egress target {ip}"
        ));
    }
    Ok(())
}

fn ipv6_is_unique_local(ip: &std::net::Ipv6Addr) -> bool {
    (ip.segments()[0] & 0xfe00) == 0xfc00
}

fn ipv6_is_unicast_link_local(ip: &std::net::Ipv6Addr) -> bool {
    (ip.segments()[0] & 0xffc0) == 0xfe80
}

// quarantine_file_target_path moved to crate::edr::response
fn disable_persistence_target_path(
    plan: &EndpointResponsePlan,
    graph: &CausalGraph,
) -> Result<PathBuf> {
    let node = graph
        .nodes
        .get(&plan.root_node_id)
        .ok_or_else(|| anyhow::anyhow!("root node not found: {}", plan.root_node_id))?;
    let path = match node.kind {
        CausalNodeKind::File => PathBuf::from(node.label.trim()),
        CausalNodeKind::BrowserExtension => {
            browser_extension_manifest_target_path(PathBuf::from(node.label.trim()))
        }
        _ => {
            return Err(anyhow::anyhow!(
                "root node must be a file or browser_extension node for disable_persistence, got {:?}",
                node.kind
            ));
        }
    };
    if !path.is_absolute() {
        return Err(anyhow::anyhow!(
            "persistence target path must be absolute: {}",
            node.label
        ));
    }
    if !path_is_bounded_persistence_target(&path) {
        return Err(anyhow::anyhow!(
            "persistence target must be a bounded LaunchAgent/LaunchDaemon plist, systemd user/system unit or drop-in, XDG autostart desktop entry, KDE Plasma env/autostart script, shell startup file, system profile drop-in, user cron spool file, system cron drop-in, or browser extension manifest: {}",
            path.display()
        ));
    }
    Ok(path)
}

fn browser_extension_manifest_target_path(path: PathBuf) -> PathBuf {
    if path
        .file_name()
        .and_then(|value| value.to_str())
        .is_some_and(|file_name| file_name.eq_ignore_ascii_case("manifest.json"))
    {
        path
    } else {
        path.join("manifest.json")
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum RevokeGrantTarget {
    LocalApiAuthToken,
    BrokerCapability { capability_id: String },
    LocalIntegrationSecret { secret: LocalIntegrationSecretKind },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub(crate) struct BrokerCapabilityRevokeReport {
    capability_id: String,
    revoked: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    provider_revocation: Option<BrokerProviderTokenRevocationReport>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub(crate) struct BrokerProviderTokenRevocationReport {
    provider: String,
    secret_ref_id: String,
    attempted: bool,
    supported: bool,
    revoked: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    status_code: Option<u16>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    provider_token_hash: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    response_body_sha256: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    reason: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum LocalIntegrationSecretKind {
    #[serde(rename = "siem.api_key")]
    SiemApiKey,
    #[serde(rename = "webhooks.secret")]
    WebhooksSecret,
}

impl LocalIntegrationSecretKind {
    fn target_suffix(self) -> &'static str {
        match self {
            Self::SiemApiKey => "siem.api_key",
            Self::WebhooksSecret => "webhooks.secret",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct LocalIntegrationSecretRevokeReport {
    secret: LocalIntegrationSecretKind,
    previous_secret_hash: String,
    integration_disabled: bool,
    revoked: bool,
}

fn revoke_grant_target(
    plan: &EndpointResponsePlan,
    graph: &CausalGraph,
) -> Result<RevokeGrantTarget> {
    let root = graph
        .nodes
        .get(&plan.root_node_id)
        .ok_or_else(|| anyhow::anyhow!("root node not found: {}", plan.root_node_id))?;
    if let Some(root_target) = revoke_grant_target_from_credential_node(root) {
        return Ok(root_target);
    }

    let mut targets = Vec::new();
    for node in graph.nodes.values() {
        let Some(target) = revoke_grant_target_from_credential_node(node) else {
            continue;
        };
        if !targets.contains(&target) {
            targets.push(target);
        }
    }
    if targets.len() == 1 {
        return Ok(targets.remove(0));
    }
    if targets.len() > 1 {
        return Err(anyhow::anyhow!(
            "ambiguous live revoke_grant target: graph contains multiple revocable credential targets; select the specific credential root node"
        ));
    }

    Err(anyhow::anyhow!(
        "live revoke_grant currently supports graph targets containing a local agent API token credential, local broker capability credential, or local integration secret credential"
    ))
}

fn revoke_grant_target_from_credential_node(
    node: &clawdstrike_policy_event::edr::CausalNode,
) -> Option<RevokeGrantTarget> {
    if credential_node_is_local_api_grant(node) {
        return Some(RevokeGrantTarget::LocalApiAuthToken);
    }
    if let Some(capability_id) = broker_capability_id_from_credential_node(node) {
        return Some(RevokeGrantTarget::BrokerCapability { capability_id });
    }
    local_integration_secret_from_credential_node(node)
        .map(|secret| RevokeGrantTarget::LocalIntegrationSecret { secret })
}

fn credential_node_is_local_api_grant(node: &clawdstrike_policy_event::edr::CausalNode) -> bool {
    if node.kind != CausalNodeKind::Credential {
        return false;
    }
    let mut values = vec![node.label.as_str()];
    for key in ["path", "name", "credentialKind"] {
        if let Some(value) = node.attributes.get(key).and_then(Value::as_str) {
            values.push(value);
        }
    }
    values.iter().any(|value| {
        let normalized = value.to_ascii_lowercase();
        normalized.contains("agent-local-token")
            || normalized.contains("clawdstrike_agent_auth")
            || normalized.contains("clawdstrike-local-api-token")
            || normalized.contains("local_api_auth_token")
    })
}

fn broker_capability_id_from_credential_node(
    node: &clawdstrike_policy_event::edr::CausalNode,
) -> Option<String> {
    if node.kind != CausalNodeKind::Credential {
        return None;
    }

    for key in ["capabilityId", "capability_id", "brokerCapabilityId"] {
        if let Some(value) = node.attributes.get(key).and_then(Value::as_str) {
            if let Some(capability_id) = normalize_broker_capability_id(value) {
                return Some(capability_id);
            }
        }
    }

    let values = credential_node_string_values(node);
    for value in &values {
        if let Some(capability_id) = extract_prefixed_broker_capability_id(value) {
            return Some(capability_id);
        }
    }

    let credential_kind = node
        .attributes
        .get("credentialKind")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_ascii_lowercase()
        .replace(['-', ' '], "_");
    let is_broker_capability = matches!(
        credential_kind.as_str(),
        "broker_capability" | "clawdstrike_broker_capability" | "brokerd_capability"
    );
    if !is_broker_capability {
        return None;
    }

    values
        .iter()
        .filter(|value| !broker_capability_value_is_kind_sentinel(value))
        .find_map(|value| normalize_broker_capability_id(value))
}

fn credential_node_string_values(node: &clawdstrike_policy_event::edr::CausalNode) -> Vec<String> {
    let mut values = vec![node.label.clone()];
    for key in ["path", "name"] {
        if let Some(value) = node.attributes.get(key).and_then(Value::as_str) {
            values.push(value.to_string());
        }
    }
    values
}

fn local_integration_secret_from_credential_node(
    node: &clawdstrike_policy_event::edr::CausalNode,
) -> Option<LocalIntegrationSecretKind> {
    if node.kind != CausalNodeKind::Credential {
        return None;
    }

    if let Some(secret) = local_integration_secret_kind_from_structured_attributes(&node.attributes)
    {
        return Some(secret);
    }

    let values = credential_node_string_values(node);
    values
        .iter()
        .find_map(|value| local_integration_secret_kind_from_value(value))
}

fn local_integration_secret_kind_from_structured_attributes(
    attributes: &BTreeMap<String, Value>,
) -> Option<LocalIntegrationSecretKind> {
    const STRUCTURED_SECRET_KEYS: &[&str] = &[
        "credentialKind",
        "credential_kind",
        "integrationSecret",
        "integration_secret",
        "integrationSecretKind",
        "integration_secret_kind",
        "localIntegrationSecret",
        "local_integration_secret",
        "settingKey",
        "setting_key",
        "settingsKey",
        "settings_key",
        "configKey",
        "config_key",
        "secretRef",
        "secret_ref",
        "secretRefId",
        "secret_ref_id",
    ];

    STRUCTURED_SECRET_KEYS
        .iter()
        .filter_map(|key| attributes.get(*key))
        .find_map(local_integration_secret_kind_from_attribute_value)
}

fn local_integration_secret_kind_from_attribute_value(
    value: &Value,
) -> Option<LocalIntegrationSecretKind> {
    match value {
        Value::String(value) => local_integration_secret_kind_from_value(value),
        Value::Array(items) => items
            .iter()
            .find_map(local_integration_secret_kind_from_attribute_value),
        Value::Object(object) => [
            "kind",
            "secretKind",
            "secret_kind",
            "settingKey",
            "setting_key",
            "settingsKey",
            "settings_key",
            "configKey",
            "config_key",
            "ref",
            "id",
            "name",
            "path",
        ]
        .iter()
        .filter_map(|key| object.get(*key))
        .find_map(local_integration_secret_kind_from_attribute_value),
        _ => None,
    }
}

fn local_integration_secret_kind_from_value(value: &str) -> Option<LocalIntegrationSecretKind> {
    let normalized = normalize_secret_identifier(value);
    if matches!(
        normalized.as_str(),
        "siem_api_key"
            | "integrations_siem_api_key"
            | "integration_siem_api_key"
            | "clawdstrike_integrations_siem_api_key"
    ) || normalized.contains("clawdstrike_integrations_siem_api_key")
        || normalized.contains("agent_integrations_siem_api_key")
        || normalized.contains("integration_siem_api_key")
        || normalized.contains("integrations_siem_api_key")
        || normalized.contains("local_siem_api_key")
        || normalized.contains("clawdstrike_siem_api_key")
        || normalized.contains("datadog_api_key")
        || normalized.contains("splunk_token")
        || normalized.contains("elastic_api_key")
    {
        return Some(LocalIntegrationSecretKind::SiemApiKey);
    }
    if matches!(
        normalized.as_str(),
        "webhook_secret"
            | "webhooks_secret"
            | "integrations_webhook_secret"
            | "integrations_webhooks_secret"
            | "clawdstrike_integrations_webhooks_secret"
    ) || normalized.contains("clawdstrike_integrations_webhooks_secret")
        || normalized.contains("agent_integrations_webhooks_secret")
        || normalized.contains("integration_webhook_secret")
        || normalized.contains("integrations_webhook_secret")
        || normalized.contains("integrations_webhooks_secret")
        || normalized.contains("local_webhook_secret")
        || normalized.contains("clawdstrike_webhook_secret")
        || normalized.contains("webhook_signing_secret")
        || normalized.contains("webhook_secret")
    {
        return Some(LocalIntegrationSecretKind::WebhooksSecret);
    }
    None
}

fn normalize_secret_identifier(value: &str) -> String {
    let mut normalized = String::with_capacity(value.len());
    let mut last_was_separator = false;
    for byte in value.bytes() {
        let next = if byte.is_ascii_alphanumeric() {
            last_was_separator = false;
            Some(byte.to_ascii_lowercase() as char)
        } else if !last_was_separator {
            last_was_separator = true;
            Some('_')
        } else {
            None
        };
        if let Some(next) = next {
            normalized.push(next);
        }
    }
    normalized.trim_matches('_').to_string()
}

fn extract_prefixed_broker_capability_id(value: &str) -> Option<String> {
    let trimmed = value.trim();
    let normalized = trimmed.to_ascii_lowercase();
    for prefix in [
        "credential:broker-capability:",
        "credential:broker_capability:",
        "broker-capability:",
        "broker_capability:",
        "broker capability:",
        "capability:",
    ] {
        if normalized.starts_with(prefix) {
            return normalize_broker_capability_id(&trimmed[prefix.len()..]);
        }
    }
    None
}

fn normalize_broker_capability_id(value: &str) -> Option<String> {
    let trimmed = value.trim();
    if !broker_capability_id_is_safe_for_path(trimmed) {
        return None;
    }
    Some(trimmed.to_string())
}

fn broker_capability_value_is_kind_sentinel(value: &str) -> bool {
    let normalized = value.trim().to_ascii_lowercase().replace(['-', ' '], "_");
    matches!(
        normalized.as_str(),
        "broker_capability" | "clawdstrike_broker_capability" | "brokerd_capability"
    )
}

fn broker_capability_id_is_safe_for_path(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 256
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
}

async fn revoke_broker_capability_grant(
    state: &AgentApiState,
    capability_id: &str,
) -> Result<BrokerCapabilityRevokeReport, (StatusCode, String)> {
    if !broker_capability_id_is_safe_for_path(capability_id) {
        return Err((
            StatusCode::BAD_REQUEST,
            format!("unsafe broker capability id for revoke_grant: {capability_id}"),
        ));
    }

    let (enabled, port, admin_token) = {
        let settings = state.settings.read().await;
        (
            settings.brokerd.enabled,
            settings.brokerd.port,
            settings.brokerd.admin_token.clone(),
        )
    };
    if !enabled {
        return Err((
            StatusCode::BAD_REQUEST,
            "brokerd is disabled; cannot revoke broker capability grant".to_string(),
        ));
    }

    let url = format!("http://127.0.0.1:{port}/v1/capabilities/{capability_id}/revoke");
    let mut request = state.http_client.post(url);
    if let Some(token) = admin_token
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
    {
        request = request.header(AUTHORIZATION.as_str(), format!("Bearer {token}"));
    }

    let response = request.send().await.map_err(|err| {
        (
            StatusCode::BAD_GATEWAY,
            format!("brokerd capability revoke request failed: {err}"),
        )
    })?;
    let status =
        StatusCode::from_u16(response.status().as_u16()).unwrap_or(StatusCode::BAD_GATEWAY);
    if !status.is_success() {
        let body = response.text().await.unwrap_or_else(|_| String::new());
        let detail = if body.trim().is_empty() {
            format!("brokerd capability revoke returned HTTP {status}")
        } else {
            format!(
                "brokerd capability revoke returned HTTP {status}: {}",
                sanitize_brokerd_error_body(&body)
            )
        };
        return Err((status, detail));
    }

    let body = response.text().await.map_err(|err| {
        (
            StatusCode::BAD_GATEWAY,
            format!("brokerd capability revoke response body could not be read: {err}"),
        )
    })?;
    serde_json::from_str::<BrokerCapabilityRevokeReport>(&body).map_err(|err| {
        (
            StatusCode::BAD_GATEWAY,
            format!("brokerd capability revoke response was invalid: {err}"),
        )
    })
}

fn sanitize_brokerd_error_body(body: &str) -> String {
    sanitize_response_execution_failure(body)
}

async fn revoke_local_integration_secret_grant(
    state: &AgentApiState,
    secret: LocalIntegrationSecretKind,
) -> Result<LocalIntegrationSecretRevokeReport, (StatusCode, String)> {
    let mut settings = state.settings.write().await;
    let mut next_integrations = settings.integrations.clone();
    let (previous_secret, integration_disabled) = match secret {
        LocalIntegrationSecretKind::SiemApiKey => {
            let previous_secret = next_integrations.siem.api_key.trim().to_string();
            let integration_disabled = next_integrations.siem.enabled;
            next_integrations.siem.api_key.clear();
            next_integrations.siem.enabled = false;
            (previous_secret, integration_disabled)
        }
        LocalIntegrationSecretKind::WebhooksSecret => {
            let previous_secret = next_integrations.webhooks.secret.trim().to_string();
            let integration_disabled = next_integrations.webhooks.enabled;
            next_integrations.webhooks.secret.clear();
            next_integrations.webhooks.enabled = false;
            (previous_secret, integration_disabled)
        }
    };

    if previous_secret.is_empty() {
        return Err((
            StatusCode::BAD_REQUEST,
            format!(
                "local integration secret {} is not configured; cannot revoke grant",
                secret.target_suffix()
            ),
        ));
    }

    let previous_secret_hash = sha256(previous_secret.as_bytes()).to_hex_prefixed();
    let mut next_settings = settings.clone();
    next_settings.integrations = next_integrations.clone();
    next_settings
        .save()
        .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
    settings.integrations = next_integrations;

    Ok(LocalIntegrationSecretRevokeReport {
        secret,
        previous_secret_hash,
        integration_disabled,
        revoked: true,
    })
}

// ProcessSignalTarget, suspend_process_tree_targets moved to crate::edr::response
// process_node_pid moved to crate::edr::response
fn validate_process_signal_targets(targets: &[ProcessSignalTarget]) -> Result<()> {
    if targets.is_empty() {
        return Err(anyhow::anyhow!(
            "process tree has no signalable process nodes"
        ));
    }
    let current_pid = std::process::id();
    let parent_pid = current_parent_pid();
    for target in targets {
        if target.pid == 0 || target.pid == 1 {
            return Err(anyhow::anyhow!(
                "refusing to signal protected pid {}",
                target.pid
            ));
        }
        if target.pid == current_pid {
            return Err(anyhow::anyhow!("refusing to signal current agent process"));
        }
        if Some(target.pid) == parent_pid {
            return Err(anyhow::anyhow!("refusing to signal parent process"));
        }
        if process_label_is_protected(&target.label) {
            return Err(anyhow::anyhow!(
                "refusing to signal protected process label {}",
                target.label
            ));
        }
    }
    Ok(())
}

fn validate_process_signal_target_before_signal(target: &ProcessSignalTarget) -> Result<()> {
    validate_process_identity_binding(target.pid, Some(target.process_identity_key.as_str()))?;
    check_process_signalable(target.pid)
}

fn validate_process_effect_signal_target_before_signal(
    target: &ProcessTreeEffectSignalTarget,
) -> Result<()> {
    validate_process_identity_binding(target.pid, target.process_identity_key.as_deref())?;
    check_process_signalable(target.pid)
}

fn validate_process_identity_binding(pid: u32, identity_key: Option<&str>) -> Result<()> {
    let identity_key = identity_key
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| anyhow::anyhow!("missing durable process identity binding"))?;
    if !identity_key.starts_with("guid:") {
        return Err(anyhow::anyhow!(
            "process identity binding is not durable: {identity_key}"
        ));
    }
    if let Some(rest) = identity_key.strip_prefix("guid:macos:") {
        let Some(identity_pid) = rest.split(':').next() else {
            return Err(anyhow::anyhow!("macOS process identity is missing pid"));
        };
        let identity_pid = identity_pid
            .parse::<u32>()
            .with_context(|| format!("parse macOS process identity pid {identity_pid}"))?;
        if identity_pid != pid {
            return Err(anyhow::anyhow!(
                "macOS process identity pid {identity_pid} does not match live target pid {pid}"
            ));
        }
    }
    Ok(())
}

fn process_label_is_protected(label: &str) -> bool {
    let normalized = label.to_ascii_lowercase();
    [
        "kernel_task",
        "launchd",
        "loginwindow",
        "windowserver",
        "systemuiserver",
        "tccd",
        "syspolicyd",
        "systemextensiond",
        "networkextensiond",
        "clawdstrike",
    ]
    .iter()
    .any(|protected| normalized.contains(protected))
}

#[cfg(unix)]
fn current_parent_pid() -> Option<u32> {
    let pid = unsafe { libc::getppid() };
    u32::try_from(pid).ok()
}

#[cfg(not(unix))]
fn current_parent_pid() -> Option<u32> {
    None
}

#[cfg(unix)]
fn process_suspend_signal() -> i32 {
    libc::SIGSTOP
}

#[cfg(not(unix))]
fn process_suspend_signal() -> i32 {
    0
}

#[cfg(unix)]
fn process_resume_signal() -> i32 {
    libc::SIGCONT
}

#[cfg(not(unix))]
fn process_resume_signal() -> i32 {
    0
}

#[cfg(unix)]
fn check_process_signalable(pid: u32) -> Result<()> {
    signal_process(pid, 0)
}

#[cfg(not(unix))]
fn check_process_signalable(_pid: u32) -> Result<()> {
    Err(anyhow::anyhow!(
        "process signalling is only supported on Unix platforms"
    ))
}

#[cfg(unix)]
fn signal_process(pid: u32, signal: i32) -> Result<()> {
    let pid = i32::try_from(pid).context("pid exceeds platform signal range")?;
    let result = unsafe { libc::kill(pid, signal) };
    if result == 0 {
        Ok(())
    } else {
        Err(std::io::Error::last_os_error()).with_context(|| {
            if signal == 0 {
                format!("check signal permission for pid {pid}")
            } else {
                format!("send signal {signal} to pid {pid}")
            }
        })
    }
}

#[cfg(not(unix))]
fn signal_process(_pid: u32, _signal: i32) -> Result<()> {
    Err(anyhow::anyhow!(
        "process signalling is only supported on Unix platforms"
    ))
}

fn validate_quarantine_source_path(path: &FsPath) -> Result<()> {
    let metadata = fs::symlink_metadata(path)
        .with_context(|| format!("stat quarantine target {}", path.display()))?;
    if metadata.file_type().is_symlink() {
        return Err(anyhow::anyhow!(
            "quarantine target must not be a symlink: {}",
            path.display()
        ));
    }
    if !metadata.is_file() {
        return Err(anyhow::anyhow!(
            "quarantine target must be a regular file: {}",
            path.display()
        ));
    }
    if !path_is_bounded_quarantine_source(path) {
        return Err(anyhow::anyhow!(
            "quarantine target must be in a temp, download, cache, node_modules, or build-output path: {}",
            path.display()
        ));
    }
    Ok(())
}

fn validate_disable_persistence_source_path(path: &FsPath) -> Result<()> {
    let metadata = fs::symlink_metadata(path)
        .with_context(|| format!("stat persistence target {}", path.display()))?;
    if metadata.file_type().is_symlink() {
        return Err(anyhow::anyhow!(
            "persistence target must not be a symlink: {}",
            path.display()
        ));
    }
    if !metadata.is_file() {
        return Err(anyhow::anyhow!(
            "persistence target must be a regular file: {}",
            path.display()
        ));
    }
    if !path_is_bounded_persistence_target(path) {
        return Err(anyhow::anyhow!(
            "persistence target must be a bounded LaunchAgent/LaunchDaemon plist, systemd user/system unit or drop-in, XDG autostart desktop entry, KDE Plasma env/autostart script, shell startup file, system profile drop-in, user cron spool file, system cron drop-in, or browser extension manifest: {}",
            path.display()
        ));
    }
    Ok(())
}

fn validate_disable_persistence_restore_target_path(path: &FsPath) -> Result<()> {
    if !path.is_absolute() {
        return Err(anyhow::anyhow!(
            "persistence rollback target path must be absolute: {}",
            path.display()
        ));
    }
    if !path_is_bounded_persistence_target(path) {
        return Err(anyhow::anyhow!(
            "persistence rollback target must be a bounded LaunchAgent/LaunchDaemon plist, systemd user/system unit or drop-in, XDG autostart desktop entry, KDE Plasma env/autostart script, shell startup file, system profile drop-in, user cron spool file, system cron drop-in, or browser extension manifest: {}",
            path.display()
        ));
    }
    if let Ok(metadata) = fs::symlink_metadata(path) {
        if metadata.file_type().is_symlink() {
            return Err(anyhow::anyhow!(
                "persistence rollback target must not be a symlink: {}",
                path.display()
            ));
        }
    }
    Ok(())
}

fn validate_quarantine_restore_target_path(path: &FsPath) -> Result<()> {
    if !path.is_absolute() {
        return Err(anyhow::anyhow!(
            "rollback target path must be absolute: {}",
            path.display()
        ));
    }
    if !path_is_bounded_quarantine_source(path) {
        return Err(anyhow::anyhow!(
            "rollback target must be in a temp, download, cache, node_modules, or build-output path: {}",
            path.display()
        ));
    }
    if let Ok(metadata) = fs::symlink_metadata(path) {
        if metadata.file_type().is_symlink() {
            return Err(anyhow::anyhow!(
                "rollback target must not be a symlink: {}",
                path.display()
            ));
        }
    }
    Ok(())
}

fn validate_quarantine_artifact_path(
    quarantine_root: &FsPath,
    artifact_path: &FsPath,
) -> Result<(), (StatusCode, String)> {
    let root = fs::canonicalize(quarantine_root)
        .with_context(|| format!("canonicalize quarantine root {}", quarantine_root.display()))
        .map_err(internal_error)?;
    let artifact = fs::canonicalize(artifact_path)
        .with_context(|| {
            format!(
                "canonicalize quarantine artifact {}",
                artifact_path.display()
            )
        })
        .map_err(internal_error)?;
    if !artifact.starts_with(root.as_path()) {
        return Err((
            StatusCode::BAD_REQUEST,
            format!(
                "quarantine artifact is outside quarantine root: {}",
                artifact_path.display()
            ),
        ));
    }
    let metadata = fs::symlink_metadata(artifact_path)
        .with_context(|| format!("stat quarantine artifact {}", artifact_path.display()))
        .map_err(internal_error)?;
    if metadata.file_type().is_symlink() {
        return Err((
            StatusCode::BAD_REQUEST,
            format!(
                "quarantine artifact must not be a symlink: {}",
                artifact_path.display()
            ),
        ));
    }
    if !metadata.is_file() {
        return Err((
            StatusCode::BAD_REQUEST,
            format!(
                "quarantine artifact must be a regular file: {}",
                artifact_path.display()
            ),
        ));
    }
    Ok(())
}

fn path_is_bounded_quarantine_source(path: &FsPath) -> bool {
    let normalized = path.display().to_string().replace('\\', "/");
    let temp_dir = std::env::temp_dir()
        .display()
        .to_string()
        .replace('\\', "/");
    normalized.starts_with(temp_dir.as_str())
        || normalized.starts_with("/tmp/")
        || normalized.starts_with("/private/tmp/")
        || normalized.starts_with("/var/folders/")
        || normalized.contains("/Downloads/")
        || normalized.contains("/Library/Caches/")
        || normalized.contains("/.cache/")
        || normalized.contains("/node_modules/")
        || normalized.contains("/target/debug/")
        || normalized.contains("/target/release/")
}

fn path_is_bounded_persistence_target(path: &FsPath) -> bool {
    path_is_bounded_launch_persistence_target(path)
        || path_is_bounded_systemd_user_persistence_target(path)
        || path_is_bounded_systemd_system_persistence_target(path)
        || path_is_bounded_systemd_user_dropin_persistence_target(path)
        || path_is_bounded_systemd_system_dropin_persistence_target(path)
        || path_is_bounded_xdg_autostart_persistence_target(path)
        || path_is_bounded_plasma_env_persistence_target(path)
        || path_is_bounded_kde_autostart_script_persistence_target(path)
        || path_is_bounded_shell_startup_persistence_target(path)
        || path_is_bounded_profile_d_persistence_target(path)
        || path_is_bounded_cron_persistence_target(path)
        || path_is_bounded_system_cron_dropin_persistence_target(path)
        || path_is_bounded_browser_extension_manifest_target(path)
}

fn path_is_bounded_launch_persistence_target(path: &FsPath) -> bool {
    let normalized = path.display().to_string().replace('\\', "/");
    if !normalized.ends_with(".plist")
        || !normalized.contains("/Library/LaunchAgents/")
            && !normalized.contains("/Library/LaunchDaemons/")
    {
        return false;
    }
    if let Some(file_name) = path.file_name().and_then(|value| value.to_str()) {
        let normalized_file = file_name.to_ascii_lowercase();
        if normalized_file.starts_with("com.apple.")
            || normalized_file.starts_with("com.clawdstrike.")
            || normalized_file.starts_with("io.clawdstrike.")
        {
            return false;
        }
    }
    let temp_dir = std::env::temp_dir()
        .display()
        .to_string()
        .replace('\\', "/");
    normalized.starts_with(temp_dir.as_str())
        || normalized.starts_with("/tmp/")
        || normalized.starts_with("/private/tmp/")
        || normalized.starts_with("/var/folders/")
        || normalized.starts_with("/Library/LaunchAgents/")
        || normalized.starts_with("/Library/LaunchDaemons/")
        || (normalized.starts_with("/Users/") && !normalized.contains("/../"))
}

fn path_is_bounded_systemd_user_persistence_target(path: &FsPath) -> bool {
    let normalized = path.display().to_string().replace('\\', "/");
    if normalized.contains("/../") {
        return false;
    }
    let Some(file_name) = path.file_name().and_then(|value| value.to_str()) else {
        return false;
    };
    if !systemd_unit_file_name_is_safe(file_name) {
        return false;
    }

    let temp_dir = std::env::temp_dir()
        .display()
        .to_string()
        .replace('\\', "/");
    let temp_like = normalized.starts_with(temp_dir.as_str())
        || normalized.starts_with("/tmp/")
        || normalized.starts_with("/private/tmp/")
        || normalized.starts_with("/var/folders/");
    let user_home_like = normalized.starts_with("/home/") || normalized.starts_with("/Users/");
    if !temp_like && !user_home_like {
        return false;
    }

    let components = normalized
        .trim_start_matches('/')
        .split('/')
        .filter(|component| !component.is_empty())
        .collect::<Vec<_>>();
    systemd_user_unit_components_are_bounded(&components, file_name)
}

fn systemd_user_unit_components_are_bounded(components: &[&str], file_name: &str) -> bool {
    if components.len() < 6 {
        return false;
    }
    let base = components.len() - 6;
    let home_component = components[base];
    let user = components[base + 1];
    matches!(home_component, "home" | "Users")
        && cron_spool_user_name_is_safe(user)
        && components[base + 2] == ".config"
        && components[base + 3] == "systemd"
        && components[base + 4] == "user"
        && components[base + 5] == file_name
}

fn path_is_bounded_systemd_user_dropin_persistence_target(path: &FsPath) -> bool {
    let normalized = path.display().to_string().replace('\\', "/");
    if normalized.contains("/../") {
        return false;
    }
    let Some(file_name) = path.file_name().and_then(|value| value.to_str()) else {
        return false;
    };
    if !systemd_dropin_file_name_is_safe(file_name) {
        return false;
    }

    let temp_dir = std::env::temp_dir()
        .display()
        .to_string()
        .replace('\\', "/");
    let temp_like = normalized.starts_with(temp_dir.as_str())
        || normalized.starts_with("/tmp/")
        || normalized.starts_with("/private/tmp/")
        || normalized.starts_with("/var/folders/");
    let user_home_like = normalized.starts_with("/home/") || normalized.starts_with("/Users/");
    if !temp_like && !user_home_like {
        return false;
    }

    let components = normalized
        .trim_start_matches('/')
        .split('/')
        .filter(|component| !component.is_empty())
        .collect::<Vec<_>>();
    systemd_user_dropin_components_are_bounded(&components, file_name)
}

fn systemd_user_dropin_components_are_bounded(components: &[&str], file_name: &str) -> bool {
    if components.len() < 7 {
        return false;
    }
    let base = components.len() - 7;
    let home_component = components[base];
    let user = components[base + 1];
    let unit_dir = components[base + 5];
    matches!(home_component, "home" | "Users")
        && cron_spool_user_name_is_safe(user)
        && components[base + 2] == ".config"
        && components[base + 3] == "systemd"
        && components[base + 4] == "user"
        && systemd_unit_dropin_dir_name_is_safe(unit_dir)
        && components[base + 6] == file_name
}

fn path_is_bounded_systemd_system_persistence_target(path: &FsPath) -> bool {
    let normalized = path.display().to_string().replace('\\', "/");
    if normalized.contains("/../") {
        return false;
    }
    let Some(file_name) = path.file_name().and_then(|value| value.to_str()) else {
        return false;
    };
    if !systemd_system_unit_file_name_is_safe(file_name) {
        return false;
    }

    let temp_dir = std::env::temp_dir()
        .display()
        .to_string()
        .replace('\\', "/");
    let temp_like = normalized.starts_with(temp_dir.as_str())
        || normalized.starts_with("/tmp/")
        || normalized.starts_with("/private/tmp/")
        || normalized.starts_with("/var/folders/");
    let system_unit_like = normalized.starts_with("/etc/systemd/system/");
    if !temp_like && !system_unit_like {
        return false;
    }

    let components = normalized
        .trim_start_matches('/')
        .split('/')
        .filter(|component| !component.is_empty())
        .collect::<Vec<_>>();
    cron_spool_components_end_with(&components, &["etc", "systemd", "system", file_name])
}

fn path_is_bounded_systemd_system_dropin_persistence_target(path: &FsPath) -> bool {
    let normalized = path.display().to_string().replace('\\', "/");
    if normalized.contains("/../") {
        return false;
    }
    let Some(file_name) = path.file_name().and_then(|value| value.to_str()) else {
        return false;
    };
    if !systemd_dropin_file_name_is_safe(file_name) {
        return false;
    }

    let temp_dir = std::env::temp_dir()
        .display()
        .to_string()
        .replace('\\', "/");
    let temp_like = normalized.starts_with(temp_dir.as_str())
        || normalized.starts_with("/tmp/")
        || normalized.starts_with("/private/tmp/")
        || normalized.starts_with("/var/folders/");
    let system_unit_like = normalized.starts_with("/etc/systemd/system/");
    if !temp_like && !system_unit_like {
        return false;
    }

    let components = normalized
        .trim_start_matches('/')
        .split('/')
        .filter(|component| !component.is_empty())
        .collect::<Vec<_>>();
    systemd_system_dropin_components_are_bounded(&components, file_name)
}

fn systemd_system_dropin_components_are_bounded(components: &[&str], file_name: &str) -> bool {
    if components.len() < 5 {
        return false;
    }
    let base = components.len() - 5;
    let unit_dir = components[base + 3];
    components[base] == "etc"
        && components[base + 1] == "systemd"
        && components[base + 2] == "system"
        && systemd_system_unit_dropin_dir_name_is_safe(unit_dir)
        && components[base + 4] == file_name
}

fn systemd_unit_file_name_is_safe(file_name: &str) -> bool {
    let Some((stem, extension)) = file_name.rsplit_once('.') else {
        return false;
    };
    matches!(extension, "service" | "timer" | "socket")
        && !stem.is_empty()
        && stem.len() <= 128
        && !stem.starts_with('.')
        && !stem.eq_ignore_ascii_case("clawdstrike")
        && !stem.to_ascii_lowercase().starts_with("clawdstrike.")
        && stem
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b'@'))
}

fn systemd_unit_dropin_dir_name_is_safe(dir_name: &str) -> bool {
    dir_name
        .strip_suffix(".d")
        .is_some_and(systemd_unit_file_name_is_safe)
}

fn systemd_system_unit_dropin_dir_name_is_safe(dir_name: &str) -> bool {
    dir_name
        .strip_suffix(".d")
        .is_some_and(systemd_system_unit_file_name_is_safe)
}

fn systemd_dropin_file_name_is_safe(file_name: &str) -> bool {
    let Some((stem, extension)) = file_name.rsplit_once('.') else {
        return false;
    };
    extension == "conf"
        && !stem.is_empty()
        && stem.len() <= 128
        && !stem.starts_with('.')
        && !stem.eq_ignore_ascii_case("clawdstrike")
        && !stem.to_ascii_lowercase().starts_with("clawdstrike.")
        && stem
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b'@'))
}

fn systemd_system_unit_file_name_is_safe(file_name: &str) -> bool {
    if !systemd_unit_file_name_is_safe(file_name) {
        return false;
    }
    let stem = file_name
        .rsplit_once('.')
        .map(|(stem, _)| stem)
        .unwrap_or(file_name);
    let normalized_stem = stem.to_ascii_lowercase();
    if normalized_stem.starts_with("systemd")
        || normalized_stem.starts_with("getty")
        || normalized_stem.starts_with("serial-getty")
        || normalized_stem.starts_with("clawdstrike")
        || normalized_stem.starts_with("com.clawdstrike")
        || normalized_stem.starts_with("io.clawdstrike")
    {
        return false;
    }
    !matches!(
        normalized_stem.as_str(),
        "ssh"
            | "sshd"
            | "cron"
            | "crond"
            | "dbus"
            | "networkmanager"
            | "networking"
            | "containerd"
            | "docker"
            | "kubelet"
            | "login"
            | "sudo"
            | "polkit"
    )
}

fn path_is_bounded_xdg_autostart_persistence_target(path: &FsPath) -> bool {
    let normalized = path.display().to_string().replace('\\', "/");
    if normalized.contains("/../") {
        return false;
    }
    let Some(file_name) = path.file_name().and_then(|value| value.to_str()) else {
        return false;
    };
    if !xdg_autostart_desktop_file_name_is_safe(file_name) {
        return false;
    }

    let temp_dir = std::env::temp_dir()
        .display()
        .to_string()
        .replace('\\', "/");
    let temp_like = normalized.starts_with(temp_dir.as_str())
        || normalized.starts_with("/tmp/")
        || normalized.starts_with("/private/tmp/")
        || normalized.starts_with("/var/folders/");
    let user_home_like = normalized.starts_with("/home/") || normalized.starts_with("/Users/");
    let system_autostart_like = normalized.starts_with("/etc/xdg/autostart/");
    if !temp_like && !user_home_like && !system_autostart_like {
        return false;
    }

    let components = normalized
        .trim_start_matches('/')
        .split('/')
        .filter(|component| !component.is_empty())
        .collect::<Vec<_>>();
    xdg_user_autostart_components_are_bounded(&components, file_name)
        || xdg_system_autostart_components_are_bounded(&components, file_name)
}

fn xdg_user_autostart_components_are_bounded(components: &[&str], file_name: &str) -> bool {
    if components.len() < 5 {
        return false;
    }
    let base = components.len() - 5;
    let home_component = components[base];
    let user = components[base + 1];
    matches!(home_component, "home" | "Users")
        && cron_spool_user_name_is_safe(user)
        && components[base + 2] == ".config"
        && components[base + 3] == "autostart"
        && components[base + 4] == file_name
}

fn xdg_system_autostart_components_are_bounded(components: &[&str], file_name: &str) -> bool {
    cron_spool_components_end_with(components, &["etc", "xdg", "autostart", file_name])
        && xdg_system_autostart_desktop_file_name_is_safe(file_name)
}

fn xdg_autostart_desktop_file_name_is_safe(file_name: &str) -> bool {
    let Some((stem, extension)) = file_name.rsplit_once('.') else {
        return false;
    };
    extension == "desktop"
        && !stem.is_empty()
        && stem.len() <= 128
        && !stem.starts_with('.')
        && !stem.eq_ignore_ascii_case("clawdstrike")
        && !stem.to_ascii_lowercase().starts_with("clawdstrike.")
        && stem
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
}

fn xdg_system_autostart_desktop_file_name_is_safe(file_name: &str) -> bool {
    if !xdg_autostart_desktop_file_name_is_safe(file_name) {
        return false;
    }
    let stem = file_name
        .rsplit_once('.')
        .map(|(stem, _)| stem)
        .unwrap_or(file_name)
        .to_ascii_lowercase();
    if stem.starts_with("org.gnome.")
        || stem.starts_with("org.kde.")
        || stem.starts_with("org.freedesktop.")
        || stem.starts_with("gnome-keyring")
        || stem.starts_with("clawdstrike")
    {
        return false;
    }
    !matches!(
        stem.as_str(),
        "polkit" | "dbus" | "ssh-agent" | "at-spi-dbus-bus" | "xdg-user-dirs" | "nm-applet"
    )
}

fn path_is_bounded_plasma_env_persistence_target(path: &FsPath) -> bool {
    let normalized = path.display().to_string().replace('\\', "/");
    if normalized.contains("/../") {
        return false;
    }
    let Some(file_name) = path.file_name().and_then(|value| value.to_str()) else {
        return false;
    };
    if !plasma_env_script_file_name_is_safe(file_name) {
        return false;
    }

    let temp_dir = std::env::temp_dir()
        .display()
        .to_string()
        .replace('\\', "/");
    let temp_like = normalized.starts_with(temp_dir.as_str())
        || normalized.starts_with("/tmp/")
        || normalized.starts_with("/private/tmp/")
        || normalized.starts_with("/var/folders/");
    let user_home_like = normalized.starts_with("/home/") || normalized.starts_with("/Users/");
    if !temp_like && !user_home_like {
        return false;
    }

    let components = normalized
        .trim_start_matches('/')
        .split('/')
        .filter(|component| !component.is_empty())
        .collect::<Vec<_>>();
    plasma_env_components_are_bounded(&components, file_name)
}

fn plasma_env_components_are_bounded(components: &[&str], file_name: &str) -> bool {
    if components.len() < 6 {
        return false;
    }
    let base = components.len() - 6;
    let home_component = components[base];
    let user = components[base + 1];
    matches!(home_component, "home" | "Users")
        && cron_spool_user_name_is_safe(user)
        && components[base + 2] == ".config"
        && components[base + 3] == "plasma-workspace"
        && components[base + 4] == "env"
        && components[base + 5] == file_name
}

fn plasma_env_script_file_name_is_safe(file_name: &str) -> bool {
    let Some((stem, extension)) = file_name.rsplit_once('.') else {
        return false;
    };
    extension == "sh"
        && !stem.is_empty()
        && stem.len() <= 128
        && !stem.starts_with('.')
        && !stem.eq_ignore_ascii_case("clawdstrike")
        && !stem.to_ascii_lowercase().starts_with("clawdstrike.")
        && stem
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
}

fn path_is_bounded_kde_autostart_script_persistence_target(path: &FsPath) -> bool {
    let normalized = path.display().to_string().replace('\\', "/");
    if normalized.contains("/../") {
        return false;
    }
    let Some(file_name) = path.file_name().and_then(|value| value.to_str()) else {
        return false;
    };
    if !plasma_env_script_file_name_is_safe(file_name) {
        return false;
    }

    let temp_dir = std::env::temp_dir()
        .display()
        .to_string()
        .replace('\\', "/");
    let temp_like = normalized.starts_with(temp_dir.as_str())
        || normalized.starts_with("/tmp/")
        || normalized.starts_with("/private/tmp/")
        || normalized.starts_with("/var/folders/");
    let user_home_like = normalized.starts_with("/home/") || normalized.starts_with("/Users/");
    if !temp_like && !user_home_like {
        return false;
    }

    let components = normalized
        .trim_start_matches('/')
        .split('/')
        .filter(|component| !component.is_empty())
        .collect::<Vec<_>>();
    kde_autostart_script_components_are_bounded(&components, file_name)
}

fn kde_autostart_script_components_are_bounded(components: &[&str], file_name: &str) -> bool {
    if components.len() < 5 {
        return false;
    }
    let base = components.len() - 5;
    let home_component = components[base];
    let user = components[base + 1];
    matches!(home_component, "home" | "Users")
        && cron_spool_user_name_is_safe(user)
        && components[base + 2] == ".config"
        && components[base + 3] == "autostart-scripts"
        && components[base + 4] == file_name
}

fn path_is_bounded_shell_startup_persistence_target(path: &FsPath) -> bool {
    let normalized = path.display().to_string().replace('\\', "/");
    if normalized.contains("/../") {
        return false;
    }
    let temp_dir = std::env::temp_dir()
        .display()
        .to_string()
        .replace('\\', "/");
    let temp_like = normalized.starts_with(temp_dir.as_str())
        || normalized.starts_with("/tmp/")
        || normalized.starts_with("/private/tmp/")
        || normalized.starts_with("/var/folders/");
    let user_home_like = normalized.starts_with("/Users/") || normalized.starts_with("/home/");
    if !temp_like && !user_home_like {
        return false;
    }

    let components = normalized
        .trim_start_matches('/')
        .split('/')
        .filter(|component| !component.is_empty())
        .collect::<Vec<_>>();
    shell_startup_components_are_bounded(&components)
}

fn shell_startup_components_are_bounded(components: &[&str]) -> bool {
    let home_shell_file = if components.len() >= 3 {
        let base = components.len() - 3;
        let home_component = components[base];
        let user = components[base + 1];
        let file = components[base + 2];
        matches!(home_component, "Users" | "home")
            && cron_spool_user_name_is_safe(user)
            && matches!(
                file,
                ".bashrc" | ".bash_profile" | ".zshrc" | ".zprofile" | ".profile"
            )
    } else {
        false
    };
    let fish_config = if components.len() >= 5 {
        let base = components.len() - 5;
        let home_component = components[base];
        let user = components[base + 1];
        matches!(home_component, "Users" | "home")
            && cron_spool_user_name_is_safe(user)
            && components[base + 2] == ".config"
            && components[base + 3] == "fish"
            && components[base + 4] == "config.fish"
    } else {
        false
    };
    let fish_conf_d = if components.len() >= 6 {
        let base = components.len() - 6;
        let home_component = components[base];
        let user = components[base + 1];
        let file = components[base + 5];
        matches!(home_component, "Users" | "home")
            && cron_spool_user_name_is_safe(user)
            && components[base + 2] == ".config"
            && components[base + 3] == "fish"
            && components[base + 4] == "conf.d"
            && fish_conf_d_file_name_is_safe(file)
    } else {
        false
    };

    home_shell_file || fish_config || fish_conf_d
}

fn fish_conf_d_file_name_is_safe(file_name: &str) -> bool {
    let Some((stem, extension)) = file_name.rsplit_once('.') else {
        return false;
    };
    extension == "fish"
        && !stem.is_empty()
        && stem.len() <= 128
        && !stem.starts_with('.')
        && !stem.eq_ignore_ascii_case("clawdstrike")
        && !matches!(stem.to_ascii_lowercase().as_str(), "config" | "conf")
        && !stem.to_ascii_lowercase().starts_with("clawdstrike.")
        && stem
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
}

fn path_is_bounded_profile_d_persistence_target(path: &FsPath) -> bool {
    let normalized = path.display().to_string().replace('\\', "/");
    if normalized.contains("/../") {
        return false;
    }
    let Some(file_name) = path.file_name().and_then(|value| value.to_str()) else {
        return false;
    };
    if !profile_d_script_file_name_is_safe(file_name) {
        return false;
    }

    let temp_dir = std::env::temp_dir()
        .display()
        .to_string()
        .replace('\\', "/");
    let temp_like = normalized.starts_with(temp_dir.as_str())
        || normalized.starts_with("/tmp/")
        || normalized.starts_with("/private/tmp/")
        || normalized.starts_with("/var/folders/");
    let system_profile_like = normalized.starts_with("/etc/profile.d/");
    if !temp_like && !system_profile_like {
        return false;
    }

    let components = normalized
        .trim_start_matches('/')
        .split('/')
        .filter(|component| !component.is_empty())
        .collect::<Vec<_>>();
    cron_spool_components_end_with(&components, &["etc", "profile.d", file_name])
}

fn path_is_bounded_cron_persistence_target(path: &FsPath) -> bool {
    let normalized = path.display().to_string().replace('\\', "/");
    if normalized.contains("/../") {
        return false;
    }
    let Some(user) = path.file_name().and_then(|value| value.to_str()) else {
        return false;
    };
    if !cron_spool_user_name_is_safe(user) {
        return false;
    }

    let temp_dir = std::env::temp_dir()
        .display()
        .to_string()
        .replace('\\', "/");
    let temp_like = normalized.starts_with(temp_dir.as_str())
        || normalized.starts_with("/tmp/")
        || normalized.starts_with("/private/tmp/")
        || normalized.starts_with("/var/folders/");
    let system_cron_like =
        normalized.starts_with("/var/spool/cron/") || normalized.starts_with("/usr/lib/cron/tabs/");
    if !temp_like && !system_cron_like {
        return false;
    }

    let components = normalized
        .trim_start_matches('/')
        .split('/')
        .filter(|component| !component.is_empty())
        .collect::<Vec<_>>();
    cron_spool_components_end_with(&components, &["var", "spool", "cron", "crontabs", user])
        || cron_spool_components_end_with(&components, &["var", "spool", "cron", user])
        || cron_spool_components_end_with(&components, &["usr", "lib", "cron", "tabs", user])
}

fn path_is_bounded_system_cron_dropin_persistence_target(path: &FsPath) -> bool {
    let normalized = path.display().to_string().replace('\\', "/");
    if normalized.contains("/../") {
        return false;
    }
    let Some(file_name) = path.file_name().and_then(|value| value.to_str()) else {
        return false;
    };
    if !cron_dropin_file_name_is_safe(file_name) {
        return false;
    }

    let temp_dir = std::env::temp_dir()
        .display()
        .to_string()
        .replace('\\', "/");
    let temp_like = normalized.starts_with(temp_dir.as_str())
        || normalized.starts_with("/tmp/")
        || normalized.starts_with("/private/tmp/")
        || normalized.starts_with("/var/folders/");
    let system_cron_dropin_like = normalized.starts_with("/etc/cron.d/");
    if !temp_like && !system_cron_dropin_like {
        return false;
    }

    let components = normalized
        .trim_start_matches('/')
        .split('/')
        .filter(|component| !component.is_empty())
        .collect::<Vec<_>>();
    cron_spool_components_end_with(&components, &["etc", "cron.d", file_name])
}

fn path_is_bounded_browser_extension_manifest_target(path: &FsPath) -> bool {
    let normalized = path.display().to_string().replace('\\', "/");
    if normalized.contains("/../") {
        return false;
    }
    let Some(file_name) = path.file_name().and_then(|value| value.to_str()) else {
        return false;
    };
    if !file_name.eq_ignore_ascii_case("manifest.json") {
        return false;
    }

    let temp_dir = std::env::temp_dir()
        .display()
        .to_string()
        .replace('\\', "/");
    let allowed_root = normalized.starts_with(temp_dir.as_str())
        || normalized.starts_with("/tmp/")
        || normalized.starts_with("/private/tmp/")
        || normalized.starts_with("/var/folders/")
        || normalized.starts_with("/home/")
        || normalized.starts_with("/Users/");
    if !allowed_root {
        return false;
    }

    let chromium_manifest = [
        "/Library/Application Support/Google/Chrome/",
        "/Library/Application Support/Chromium/",
        "/Library/Application Support/Microsoft Edge/",
        "/Library/Application Support/BraveSoftware/Brave-Browser/",
    ]
    .iter()
    .any(|marker| normalized.contains(marker))
        && normalized.contains("/Extensions/")
        && chromium_browser_extension_manifest_components_are_bounded(&normalized);
    let firefox_manifest = [
        "/Library/Application Support/Firefox/Profiles/",
        "/.mozilla/firefox/",
    ]
    .iter()
    .any(|marker| firefox_browser_extension_manifest_components_are_bounded(&normalized, marker));

    chromium_manifest || firefox_manifest
}

fn chromium_browser_extension_manifest_components_are_bounded(normalized: &str) -> bool {
    let Some((_, extension_suffix)) = normalized.rsplit_once("/Extensions/") else {
        return false;
    };
    let components = extension_suffix
        .split('/')
        .filter(|component| !component.is_empty())
        .collect::<Vec<_>>();
    components.len() == 3
        && components.last() == Some(&"manifest.json")
        && browser_extension_path_component_is_safe(components[0])
        && browser_extension_path_component_is_safe(components[1])
}

fn firefox_browser_extension_manifest_components_are_bounded(
    normalized: &str,
    profile_marker: &str,
) -> bool {
    let Some((_, profile_suffix)) = normalized.rsplit_once(profile_marker) else {
        return false;
    };
    let components = profile_suffix
        .split('/')
        .filter(|component| !component.is_empty())
        .collect::<Vec<_>>();
    components.len() == 4
        && components[1] == "extensions"
        && components[3].eq_ignore_ascii_case("manifest.json")
        && browser_extension_path_component_is_safe(components[0])
        && firefox_extension_path_component_is_safe(components[2])
}

fn browser_extension_path_component_is_safe(component: &str) -> bool {
    !component.is_empty()
        && component.len() <= 128
        && !component.starts_with('.')
        && component
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
}

fn firefox_extension_path_component_is_safe(component: &str) -> bool {
    !component.is_empty()
        && component.len() <= 128
        && !component.starts_with('.')
        && component.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b'@' | b'{' | b'}')
        })
}

fn cron_spool_components_end_with(components: &[&str], suffix: &[&str]) -> bool {
    components.len() >= suffix.len()
        && components[components.len() - suffix.len()..]
            .iter()
            .zip(suffix.iter())
            .all(|(left, right)| left == right)
}

fn cron_spool_user_name_is_safe(user: &str) -> bool {
    !user.is_empty()
        && user.len() <= 64
        && !user.starts_with('.')
        && !matches!(user, "root" | "daemon" | "nobody")
        && user
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
}

fn cron_dropin_file_name_is_safe(file_name: &str) -> bool {
    let normalized = file_name.to_ascii_lowercase();
    !file_name.is_empty()
        && file_name.len() <= 128
        && !file_name.starts_with('.')
        && !matches!(
            normalized.as_str(),
            "0hourly" | "anacron" | "cron" | "cronie" | "clawdstrike"
        )
        && !normalized.starts_with("clawdstrike.")
        && !normalized.starts_with("com.clawdstrike.")
        && file_name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
}

fn profile_d_script_file_name_is_safe(file_name: &str) -> bool {
    let Some((stem, extension)) = file_name.rsplit_once('.') else {
        return false;
    };
    let normalized_stem = stem.to_ascii_lowercase();
    extension == "sh"
        && !stem.is_empty()
        && stem.len() <= 128
        && !stem.starts_with('.')
        && !stem.eq_ignore_ascii_case("clawdstrike")
        && !normalized_stem.starts_with("clawdstrike.")
        && !normalized_stem.starts_with("com.clawdstrike.")
        && !matches!(
            normalized_stem.as_str(),
            "bash_completion"
                | "colorgrep"
                | "colorls"
                | "lang"
                | "locale"
                | "proxy"
                | "ssh-agent"
                | "systemd"
        )
        && stem
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
}

// quarantine_file_effect, disable_persistence_effect, suspend_process_tree_effect,
// process_tree_effect_pids moved to crate::edr::response
// quarantine_destination_path, safe_filename_fragment moved to crate::edr::response

fn persistence_disable_destination_path(
    quarantine_root: &FsPath,
    plan: &EndpointResponsePlan,
    source_path: &FsPath,
    content_hash: &str,
) -> PathBuf {
    let hash_fragment = content_hash
        .trim_start_matches("0x")
        .chars()
        .take(16)
        .collect::<String>();
    let source_name = source_path
        .file_name()
        .and_then(|value| value.to_str())
        .unwrap_or("launch-agent.plist");
    quarantine_root.join(format!(
        "{}-{}-{}.disabled-persistence",
        safe_filename_fragment(&plan.action_id),
        safe_filename_fragment(&hash_fragment),
        safe_filename_fragment(source_name)
    ))
}

pub(crate) fn supported_edr_response_action(action: &EndpointDecisionAction) -> bool {
    matches!(
        action,
        EndpointDecisionAction::RestrictEgress
            | EndpointDecisionAction::SuspendProcessTree
            | EndpointDecisionAction::TerminateProcessTree
            | EndpointDecisionAction::QuarantineFile
            | EndpointDecisionAction::RevokeGrant
            | EndpointDecisionAction::DisablePersistence
            | EndpointDecisionAction::CollectEvidence
    )
}

// endpoint_security_event_* helpers moved to crate::edr::conversion::endpoint_security

pub(crate) fn network_extension_event_observations(
    event: &EdrNetworkExtensionFlowEvent,
    index: usize,
) -> Result<Vec<EndpointObservation>, (StatusCode, String)> {
    let host = required_network_extension_event_string(event, "host", event.host.as_deref())?;
    if event.port == 0 {
        return Err(bad_network_extension_event_request(
            event,
            "port must be greater than zero",
        ));
    }
    let decision =
        normalized_network_extension_verdict(event.verdict.as_str()).ok_or_else(|| {
            bad_network_extension_event_request(event, "verdict must be allow or block")
        })?;
    let timestamp = event.observed_at.unwrap_or_else(chrono::Utc::now);
    let target = format!("{}:{}", host, event.port);
    let observation_id = trimmed_owned(event.event_id.as_deref()).unwrap_or_else(|| {
        let index = index.to_string();
        local_stable_id(
            "neflow",
            [
                event.session_id.as_deref().unwrap_or_default(),
                event.flow_id.as_deref().unwrap_or_default(),
                host.as_str(),
                index.as_str(),
            ],
        )
    });
    let process = network_extension_event_process(event, target.as_str(), decision);
    let metadata = network_extension_event_metadata(event, decision);
    let mut observations = Vec::with_capacity(if event.dns_query.is_some() { 3 } else { 2 });

    if let Some(query) = trimmed_owned(event.dns_query.as_deref()) {
        let mut dns_metadata = metadata.clone();
        dns_metadata.insert(
            "networkExtensionObservationKind".to_string(),
            serde_json::Value::String("dns_lookup".to_string()),
        );
        observations.push(EndpointObservation {
            observation_id: format!("{observation_id}:dns"),
            timestamp,
            host_id: trimmed_owned(event.host_id.as_deref()),
            user_id: trimmed_owned(event.user_id.as_deref()),
            session_id: trimmed_owned(event.session_id.as_deref()),
            process: process.clone(),
            event: EndpointEvent::DnsLookup {
                query,
                record_type: trimmed_owned(event.dns_record_type.as_deref()),
                answers: event
                    .dns_answers
                    .iter()
                    .filter_map(|answer| trimmed_owned(Some(answer.as_str())))
                    .collect(),
                resolver: trimmed_owned(event.dns_resolver.as_deref()),
                status: trimmed_owned(event.dns_status.as_deref()),
            },
            metadata: dns_metadata,
        });
    }

    observations.push(EndpointObservation {
        observation_id: observation_id.clone(),
        timestamp,
        host_id: trimmed_owned(event.host_id.as_deref()),
        user_id: trimmed_owned(event.user_id.as_deref()),
        session_id: trimmed_owned(event.session_id.as_deref()),
        process: process.clone(),
        event: EndpointEvent::NetworkFlow {
            host: host.clone(),
            port: event.port,
            protocol: trimmed_owned(event.protocol.as_deref()),
            url: trimmed_owned(event.url.as_deref()),
        },
        metadata: metadata.clone(),
    });
    observations.push(EndpointObservation {
        observation_id: format!("{observation_id}:decision"),
        timestamp,
        host_id: trimmed_owned(event.host_id.as_deref()),
        user_id: trimmed_owned(event.user_id.as_deref()),
        session_id: trimmed_owned(event.session_id.as_deref()),
        process,
        event: EndpointEvent::PolicyDecision {
            action: "network_extension_egress".to_string(),
            target: Some(target),
            decision: decision.to_string(),
            guard: Some("network_extension_content_filter".to_string()),
            severity: Some(
                if decision == "blocked" {
                    "high"
                } else {
                    "info"
                }
                .to_string(),
            ),
        },
        metadata,
    });
    Ok(observations)
}

fn network_extension_event_process(
    event: &EdrNetworkExtensionFlowEvent,
    target: &str,
    decision: &str,
) -> EndpointProcess {
    let mut process = event.process.clone().unwrap_or_default();
    if let Some(command_line) = trimmed_owned(process.command_line.as_deref()) {
        process.command_line = Some(redact_developer_activity_command_line(&command_line));
    }
    if process.pid.is_none() {
        process.pid = event.pid;
    }
    if trimmed_owned(process.process_guid.as_deref()).is_none() {
        process.process_guid = trimmed_owned(event.process_guid.as_deref());
    }
    if trimmed_owned(process.parent_process_guid.as_deref()).is_none() {
        process.parent_process_guid = trimmed_owned(event.parent_process_guid.as_deref());
    }
    if trimmed_owned(process.image.as_deref()).is_none() {
        process.image = trimmed_owned(event.source_app_path.as_deref())
            .or_else(|| trimmed_owned(event.source_app.as_deref()))
            .or_else(|| Some("network-extension-provider".to_string()));
    }
    if trimmed_owned(process.command_line.as_deref()).is_none() {
        process.command_line = Some(format!("network_extension_flow {target} {decision}"));
    }
    process
}

fn network_extension_event_metadata(
    event: &EdrNetworkExtensionFlowEvent,
    decision: &str,
) -> BTreeMap<String, serde_json::Value> {
    let mut metadata = redact_endpoint_observation_metadata(&event.metadata);
    metadata.insert(
        "collectorKind".to_string(),
        serde_json::Value::String("network_extension".to_string()),
    );
    metadata.insert(
        "providerId".to_string(),
        serde_json::Value::String("macos.network_extension".to_string()),
    );
    metadata.insert(
        "networkExtensionVerdict".to_string(),
        serde_json::Value::String(decision.to_string()),
    );
    for (key, value) in [
        ("flowId", event.flow_id.as_deref()),
        ("sourceApp", event.source_app.as_deref()),
        ("sourceAppPath", event.source_app_path.as_deref()),
        ("networkExtensionReason", event.reason.as_deref()),
        ("policySnapshotPath", event.policy_snapshot_path.as_deref()),
        ("policySnapshotHash", event.policy_snapshot_hash.as_deref()),
    ] {
        if let Some(value) = trimmed_owned(value) {
            metadata.insert(key.to_string(), serde_json::Value::String(value));
        }
    }
    for (key, value) in [
        ("generation", event.generation),
        ("remediationRequests", event.remediation_requests),
        ("blockedFlows", event.blocked_flows),
        ("allowedFlows", event.allowed_flows),
    ] {
        if let Some(value) = value {
            metadata.insert(key.to_string(), serde_json::json!(value));
        }
    }
    metadata
}

fn normalized_network_extension_verdict(value: &str) -> Option<&'static str> {
    match value.trim().to_ascii_lowercase().as_str() {
        "allow" | "allowed" | "pass" | "passed" | "permit" | "permitted" => Some("allowed"),
        "block" | "blocked" | "deny" | "denied" | "drop" | "dropped" => Some("blocked"),
        _ => None,
    }
}

fn required_network_extension_event_string(
    event: &EdrNetworkExtensionFlowEvent,
    field: &str,
    value: Option<&str>,
) -> Result<String, (StatusCode, String)> {
    trimmed_owned(value).ok_or_else(|| {
        bad_network_extension_event_request(
            event,
            &format!("{field} is required for NetworkExtension flow events"),
        )
    })
}

fn bad_network_extension_event_request(
    event: &EdrNetworkExtensionFlowEvent,
    message: &str,
) -> (StatusCode, String) {
    let event_id = event
        .event_id
        .as_deref()
        .and_then(|value| non_empty(Some(value)))
        .unwrap_or("unknown");
    (
        StatusCode::BAD_REQUEST,
        format!("invalid NetworkExtension flow event {event_id}: {message}"),
    )
}

pub(crate) fn package_manager_event_observation(
    event: &EdrPackageManagerEvent,
    index: usize,
) -> Result<EndpointObservation, (StatusCode, String)> {
    let phase = required_package_manager_event_string(event, "phase", Some(event.phase.as_str()))?;
    let script =
        required_package_manager_event_string(event, "script", Some(event.script.as_str()))?;
    let script = redact_developer_activity_command_line(&script);
    let observation_id = trimmed_owned(event.event_id.as_deref()).unwrap_or_else(|| {
        let index = index.to_string();
        local_stable_id(
            "pkgscript",
            [
                event.manager.as_str(),
                phase.as_str(),
                event.package.as_deref().unwrap_or_default(),
                event.working_directory.as_deref().unwrap_or_default(),
                index.as_str(),
            ],
        )
    });

    Ok(EndpointObservation {
        observation_id,
        timestamp: event.observed_at.unwrap_or_else(chrono::Utc::now),
        host_id: trimmed_owned(event.host_id.as_deref()),
        user_id: trimmed_owned(event.user_id.as_deref()),
        session_id: trimmed_owned(event.session_id.as_deref()),
        process: package_manager_event_process(event, &phase, &script),
        event: EndpointEvent::PackageScript {
            manager: event.manager.clone(),
            package: trimmed_owned(event.package.as_deref()),
            phase,
            script,
            working_directory: trimmed_owned(event.working_directory.as_deref()),
        },
        metadata: package_manager_event_metadata(event),
    })
}

fn package_manager_event_process(
    event: &EdrPackageManagerEvent,
    phase: &str,
    script: &str,
) -> EndpointProcess {
    let mut process = event.process.clone().unwrap_or_default();
    if let Some(command_line) = trimmed_owned(process.command_line.as_deref()) {
        process.command_line = Some(redact_developer_activity_command_line(&command_line));
    }
    if trimmed_owned(process.image.as_deref()).is_none() {
        process.image = Some(event.manager.as_str().to_string());
    }
    if trimmed_owned(process.command_line.as_deref()).is_none() {
        process.command_line = Some(format!("{} {phase} {script}", event.manager.as_str()));
    }
    if trimmed_owned(process.cwd.as_deref()).is_none() {
        process.cwd = trimmed_owned(event.working_directory.as_deref());
    }
    process
}

fn package_manager_event_metadata(
    event: &EdrPackageManagerEvent,
) -> BTreeMap<String, serde_json::Value> {
    let mut metadata = redact_developer_activity_metadata(&event.metadata);
    metadata.insert(
        "collectorKind".to_string(),
        serde_json::Value::String("package_manager".to_string()),
    );
    metadata.insert(
        "providerId".to_string(),
        serde_json::Value::String(format!("package_manager.{}", event.manager.as_str())),
    );
    metadata.insert(
        "packageManager".to_string(),
        serde_json::Value::String(event.manager.as_str().to_string()),
    );
    for (key, value) in [
        ("agentId", event.agent_id.as_deref()),
        ("workloadId", event.workload_id.as_deref()),
        ("approvalId", event.approval_id.as_deref()),
        ("toolCallId", event.tool_call_id.as_deref()),
        ("packageName", event.package.as_deref()),
        ("packageManagerPhase", Some(event.phase.as_str())),
        ("workingDirectory", event.working_directory.as_deref()),
    ] {
        if let Some(value) = trimmed_owned(value) {
            metadata.insert(key.to_string(), serde_json::Value::String(value));
        }
    }
    metadata
}

fn required_package_manager_event_string(
    event: &EdrPackageManagerEvent,
    field: &str,
    value: Option<&str>,
) -> Result<String, (StatusCode, String)> {
    trimmed_owned(value).ok_or_else(|| {
        let event_id = event
            .event_id
            .as_deref()
            .and_then(|value| non_empty(Some(value)))
            .unwrap_or("unknown");
        (
            StatusCode::BAD_REQUEST,
            format!("invalid package-manager event {event_id}: {field} is required"),
        )
    })
}

pub(crate) fn developer_activity_observation(
    activity: &EdrDeveloperActivity,
    index: usize,
) -> Result<EndpointObservation, (StatusCode, String)> {
    let event = developer_activity_event(activity)?;
    let process = developer_activity_process(activity, &event)?;
    let metadata = developer_activity_metadata(activity);
    let activity_id = non_empty(activity.activity_id.as_deref())
        .map(ToString::to_string)
        .unwrap_or_else(|| developer_activity_stable_id(activity, index));

    Ok(EndpointObservation {
        observation_id: activity_id,
        timestamp: activity.observed_at.unwrap_or_else(chrono::Utc::now),
        host_id: trimmed_owned(activity.host_id.as_deref()),
        user_id: trimmed_owned(activity.user_id.as_deref()),
        session_id: trimmed_owned(activity.session_id.as_deref()),
        process,
        event,
        metadata,
    })
}

fn developer_activity_event(
    activity: &EdrDeveloperActivity,
) -> Result<EndpointEvent, (StatusCode, String)> {
    match activity.kind {
        EdrDeveloperActivityKind::McpTool => Ok(EndpointEvent::ToolCall {
            tool_name: required_activity_string(
                activity,
                "toolName",
                activity.tool_name.as_deref(),
            )?,
            parameters: developer_activity_parameters(activity),
        }),
        EdrDeveloperActivityKind::BrowserAutomation => {
            let action = required_activity_string(activity, "action", activity.action.as_deref())?;
            let tool_name = activity
                .tool_name
                .as_deref()
                .and_then(|value| non_empty(Some(value)))
                .map(ToString::to_string)
                .unwrap_or_else(|| format!("browser.{action}"));
            Ok(EndpointEvent::ToolCall {
                tool_name,
                parameters: developer_activity_parameters(activity),
            })
        }
        EdrDeveloperActivityKind::BrowserDownload => Ok(EndpointEvent::BrowserDownload {
            browser: required_activity_string(activity, "browser", activity.browser.as_deref())?,
            path: required_activity_string(activity, "path", activity.path.as_deref())?,
            source_url: trimmed_owned(activity.source_url.as_deref()),
            content_hash: trimmed_owned(activity.content_hash.as_deref()),
            byte_count: developer_activity_byte_count(activity),
        }),
        EdrDeveloperActivityKind::BrowserExtension => Ok(EndpointEvent::BrowserExtensionInstall {
            browser: required_activity_string(activity, "browser", activity.browser.as_deref())?,
            extension_id: trimmed_owned(activity.extension_id.as_deref()),
            path: required_activity_string(activity, "path", activity.path.as_deref())?,
            source: trimmed_owned(activity.source.as_deref()),
        }),
        EdrDeveloperActivityKind::DnsLookup => Ok(EndpointEvent::DnsLookup {
            query: required_activity_string(
                activity,
                "query",
                activity.query.as_deref().or(activity.target.as_deref()),
            )?,
            record_type: trimmed_owned(activity.record_type.as_deref()),
            answers: activity
                .answers
                .iter()
                .filter_map(|answer| trimmed_owned(Some(answer.as_str())))
                .collect(),
            resolver: trimmed_owned(activity.resolver.as_deref()),
            status: trimmed_owned(activity.status.as_deref()),
        }),
        EdrDeveloperActivityKind::NetworkEgress => Ok(EndpointEvent::NetworkFlow {
            host: required_activity_string(activity, "host", activity.host.as_deref())?,
            port: activity.port.ok_or_else(|| {
                bad_activity_request(activity, "port is required for network_egress")
            })?,
            protocol: trimmed_owned(activity.protocol.as_deref()),
            url: trimmed_owned(activity.url.as_deref()),
        }),
        EdrDeveloperActivityKind::FileRead | EdrDeveloperActivityKind::FileWrite => {
            let fallback = if matches!(activity.kind, EdrDeveloperActivityKind::FileRead) {
                FileOperation::Read
            } else {
                FileOperation::Write
            };
            Ok(EndpointEvent::FileAccess {
                operation: developer_activity_file_operation(activity, fallback),
                path: required_activity_string(activity, "path", activity.path.as_deref())?,
                source_url: trimmed_owned(activity.source_url.as_deref()),
                content_preview: None,
            })
        }
        EdrDeveloperActivityKind::PatchApply => Ok(EndpointEvent::FileAccess {
            operation: FileOperation::Write,
            path: required_activity_string(activity, "path", activity.path.as_deref())?,
            source_url: None,
            content_preview: None,
        }),
        EdrDeveloperActivityKind::PersistenceChange => Ok(EndpointEvent::LaunchPersistence {
            path: required_activity_string(
                activity,
                "target",
                activity.target.as_deref().or(activity.path.as_deref()),
            )?,
            label: trimmed_owned(activity.name.as_deref()),
            operation: developer_activity_file_operation(activity, FileOperation::Write),
        }),
        EdrDeveloperActivityKind::PackageScript => Ok(EndpointEvent::PackageScript {
            manager: activity.manager.clone().ok_or_else(|| {
                bad_activity_request(activity, "manager is required for package_script")
            })?,
            package: trimmed_owned(activity.package.as_deref()),
            phase: required_activity_string(activity, "phase", activity.phase.as_deref())?,
            script: redact_developer_activity_command_line(&required_activity_string(
                activity,
                "script",
                activity.script.as_deref(),
            )?),
            working_directory: trimmed_owned(activity.working_directory.as_deref()),
        }),
        EdrDeveloperActivityKind::CloudCli => {
            let provider =
                required_activity_string(activity, "provider", activity.provider.as_deref())?;
            let operation =
                required_activity_string(activity, "operation", activity.operation.as_deref())?;
            let mut args = Vec::with_capacity(activity.args.len() + 1);
            args.push(operation);
            args.extend(activity.args.iter().cloned());
            let args = redact_developer_activity_args(&args);
            Ok(EndpointEvent::ProcessExec {
                image: activity
                    .image
                    .as_deref()
                    .and_then(|value| non_empty(Some(value)))
                    .map(ToString::to_string)
                    .unwrap_or(provider),
                args,
                env: BTreeMap::new(),
            })
        }
        EdrDeveloperActivityKind::ShellCommand => Ok(EndpointEvent::ProcessExec {
            image: required_activity_string(activity, "image", activity.image.as_deref())?,
            args: redact_developer_activity_args(&activity.args),
            env: BTreeMap::new(),
        }),
        EdrDeveloperActivityKind::RepoSecret => Ok(EndpointEvent::CredentialAccess {
            kind: activity
                .credential_kind
                .clone()
                .unwrap_or(CredentialKind::ApiToken),
            path: trimmed_owned(activity.path.as_deref()),
            name: trimmed_owned(activity.name.as_deref()),
        }),
        EdrDeveloperActivityKind::CiToken => Ok(EndpointEvent::CredentialAccess {
            kind: activity
                .credential_kind
                .clone()
                .unwrap_or(CredentialKind::ApiToken),
            path: trimmed_owned(activity.path.as_deref()),
            name: Some(required_activity_string(
                activity,
                "name",
                activity.name.as_deref(),
            )?),
        }),
        EdrDeveloperActivityKind::LocalApiKey => Ok(EndpointEvent::CredentialAccess {
            kind: activity
                .credential_kind
                .clone()
                .unwrap_or(CredentialKind::ApiToken),
            path: trimmed_owned(activity.path.as_deref()),
            name: trimmed_owned(activity.name.as_deref()),
        }),
        EdrDeveloperActivityKind::BrowserCookie => Ok(EndpointEvent::CredentialAccess {
            kind: CredentialKind::BrowserCookie,
            path: trimmed_owned(activity.path.as_deref()),
            name: Some(required_activity_string(
                activity,
                "name",
                activity.name.as_deref(),
            )?),
        }),
    }
}

fn developer_activity_process(
    activity: &EdrDeveloperActivity,
    event: &EndpointEvent,
) -> Result<EndpointProcess, (StatusCode, String)> {
    let mut process = activity.process.clone().unwrap_or_default();
    if let Some(command_line) = trimmed_owned(process.command_line.as_deref()) {
        process.command_line = Some(redact_developer_activity_command_line(&command_line));
    }
    if process.pid.is_none() {
        process.pid = activity.pid;
    }
    if process.ppid.is_none() {
        process.ppid = activity.ppid;
    }
    if trimmed_owned(process.process_guid.as_deref()).is_none() {
        process.process_guid = trimmed_owned(activity.process_guid.as_deref());
    }
    if trimmed_owned(process.parent_process_guid.as_deref()).is_none() {
        process.parent_process_guid = trimmed_owned(activity.parent_process_guid.as_deref());
    }
    if trimmed_owned(process.image.as_deref()).is_none() {
        process.image = trimmed_owned(activity.process_image.as_deref());
    }
    if trimmed_owned(process.command_line.as_deref()).is_none() {
        process.command_line = trimmed_owned(activity.process_command_line.as_deref())
            .map(|command_line| redact_developer_activity_command_line(&command_line));
    }
    if trimmed_owned(process.cwd.as_deref()).is_none() {
        process.cwd = trimmed_owned(activity.process_cwd.as_deref());
    }
    if trimmed_owned(process.image.as_deref()).is_none() {
        process.image = developer_activity_default_process_image(activity, event);
    }
    if trimmed_owned(process.command_line.as_deref()).is_none() {
        process.command_line = developer_activity_command_line(activity, event)
            .map(|command_line| redact_developer_activity_command_line(&command_line));
    }
    if trimmed_owned(process.cwd.as_deref()).is_none() {
        process.cwd = trimmed_owned(activity.working_directory.as_deref());
    }
    if trimmed_owned(process.image.as_deref()).is_none()
        && trimmed_owned(process.command_line.as_deref()).is_none()
    {
        return Err(bad_activity_request(
            activity,
            "activity must provide process.image, image, or enough collector fields to infer a process",
        ));
    }
    Ok(process)
}

pub(crate) fn redact_developer_activity_command_line(command_line: &str) -> String {
    let command_line = redact_developer_activity_jsonish_secret_fields(command_line);
    let parts = command_line
        .split_whitespace()
        .map(ToString::to_string)
        .collect::<Vec<_>>();
    let redacted = redact_developer_activity_args(&parts).join(" ");

    if redacted != command_line.as_str() {
        redacted
    } else if developer_activity_secret_like_value(&command_line) {
        "[REDACTED]".to_string()
    } else {
        redacted
    }
}

pub(crate) fn redact_developer_activity_args(args: &[String]) -> Vec<String> {
    let mut redacted = Vec::with_capacity(args.len());
    let mut index = 0;
    while index < args.len() {
        let arg = &args[index];
        if let Some(redacted_arg) = redact_developer_activity_userinfo_flag_assignment(arg) {
            redacted.push(redacted_arg);
            index += 1;
            continue;
        }
        if let Some(redacted_arg) = redact_developer_activity_compact_userinfo_flag(arg) {
            redacted.push(redacted_arg);
            index += 1;
            continue;
        }
        if let Some(header) = redact_developer_activity_header_flag_assignment_value(arg) {
            redacted.push(header.redacted);
            index += 1;
            if header.consumes_next_token && index < args.len() {
                index += 1;
            }
            continue;
        }
        if let Some(header) = redact_developer_activity_authorization_header_value(arg) {
            redacted.push(header.redacted);
            index += 1;
            if header.consumes_next_token && index < args.len() {
                index += 1;
            }
            continue;
        }
        if developer_activity_authorization_header_key(arg) {
            redacted.push(arg.clone());
            index += 1;
            if index < args.len() && developer_activity_authorization_scheme_marker(&args[index]) {
                redacted.push(args[index].clone());
                index += 1;
            }
            if index < args.len() {
                redacted.push("[REDACTED]".to_string());
                index += 1;
            }
            continue;
        }
        if developer_activity_userinfo_flag_without_value(arg) {
            redacted.push(arg.clone());
            index += 1;
            if index < args.len() {
                redacted.push(redact_developer_activity_userinfo_credential(&args[index]));
                index += 1;
            }
            continue;
        }
        if developer_activity_sensitive_flag_without_value(arg) {
            redacted.push(arg.clone());
            index += 1;
            if index < args.len() && developer_activity_authorization_scheme_marker(&args[index]) {
                redacted.push(args[index].clone());
                index += 1;
            }
            if index < args.len() {
                redacted.push("[REDACTED]".to_string());
                index += 1;
            }
            continue;
        }
        if developer_activity_authorization_scheme_marker(arg) {
            redacted.push(arg.clone());
            index += 1;
            if index < args.len() {
                redacted.push("[REDACTED]".to_string());
                index += 1;
            }
            continue;
        }
        if let Some(assignment) = redact_developer_activity_sensitive_assignment(arg) {
            redacted.push(assignment.redacted);
            index += 1;
            if assignment.consumes_next_token && index < args.len() {
                redacted.push("[REDACTED]".to_string());
                index += 1;
            }
            continue;
        }
        redacted.push(redact_developer_activity_command_part(arg));
        index += 1;
    }
    redacted
}

pub(crate) struct RedactedAuthorizationHeader {
    redacted: String,
    consumes_next_token: bool,
}

pub(crate) struct RedactedSensitiveAssignment {
    redacted: String,
    consumes_next_token: bool,
}

fn developer_activity_authorization_header_key(part: &str) -> bool {
    let normalized = part.trim_end_matches(':');
    if normalized.eq_ignore_ascii_case("authorization")
        || normalized.eq_ignore_ascii_case("proxy-authorization")
        || normalized.eq_ignore_ascii_case("cookie")
        || normalized.eq_ignore_ascii_case("set-cookie")
    {
        return true;
    }
    if normalized.contains(['?', '&', '/', '\\', '=']) {
        return false;
    }
    developer_activity_sensitive_key(normalized)
        || developer_activity_sensitive_auth_header_key(normalized)
}

fn developer_activity_sensitive_auth_header_key(key: &str) -> bool {
    let normalized_key = key
        .trim_start_matches('-')
        .to_ascii_lowercase()
        .replace(['-', '_'], "");
    normalized_key == "auth"
        || normalized_key.ends_with("auth")
        || normalized_key.ends_with("authentication")
        || normalized_key.ends_with("authorization")
}

fn developer_activity_userinfo_flag_key(part: &str) -> bool {
    let normalized = part
        .trim_start_matches('-')
        .to_ascii_lowercase()
        .replace('_', "-");
    matches!(
        normalized.as_str(),
        "u" | "user" | "proxy-user" | "proxyuser"
    )
}

fn developer_activity_userinfo_flag_without_value(part: &str) -> bool {
    let trimmed = part.trim_end_matches(':');
    if trimmed.contains('=') || !trimmed.starts_with('-') {
        return false;
    }
    developer_activity_userinfo_flag_key(trimmed)
}

fn redact_developer_activity_userinfo_flag_assignment(part: &str) -> Option<String> {
    let (flag, credential) = part.split_once('=')?;
    if !developer_activity_userinfo_flag_key(flag) {
        return None;
    }
    Some(format!(
        "{flag}={}",
        redact_developer_activity_userinfo_credential(credential)
    ))
}

fn redact_developer_activity_compact_userinfo_flag(part: &str) -> Option<String> {
    if part.len() <= 2 || !(part.starts_with("-u") || part.starts_with("-U")) {
        return None;
    }
    let credential = &part[2..];
    if credential.starts_with('-') || !credential.contains(':') {
        return None;
    }
    Some(format!(
        "{}{}",
        &part[..2],
        redact_developer_activity_userinfo_credential(credential)
    ))
}

fn redact_developer_activity_userinfo_credential(credential: &str) -> String {
    let Some((user, password)) = credential.split_once(':') else {
        return if developer_activity_secret_like_value(credential) {
            "[REDACTED]".to_string()
        } else {
            credential.to_string()
        };
    };
    if password.is_empty() {
        credential.to_string()
    } else {
        format!("{user}:[REDACTED]")
    }
}

fn developer_activity_header_flag_key(part: &str) -> bool {
    let normalized = part
        .trim_start_matches('-')
        .to_ascii_lowercase()
        .replace('_', "-");
    matches!(
        normalized.as_str(),
        "h" | "header" | "proxy-header" | "proxyheader"
    )
}

fn redact_developer_activity_header_flag_assignment_value(
    part: &str,
) -> Option<RedactedAuthorizationHeader> {
    let (flag, header) = part.split_once('=')?;
    if !developer_activity_header_flag_key(flag) {
        return None;
    }
    let header = header.trim();
    let redacted_header =
        redact_developer_activity_authorization_header_value(header).or_else(|| {
            let header_key = header.trim_end_matches(':');
            if developer_activity_authorization_header_key(header_key) {
                Some(RedactedAuthorizationHeader {
                    redacted: format!("{header_key}: [REDACTED]"),
                    consumes_next_token: true,
                })
            } else {
                None
            }
        })?;
    Some(RedactedAuthorizationHeader {
        redacted: format!("{flag}={}", redacted_header.redacted),
        consumes_next_token: redacted_header.consumes_next_token,
    })
}

fn redact_developer_activity_authorization_header_value(
    part: &str,
) -> Option<RedactedAuthorizationHeader> {
    let (key, value) = part.split_once(':')?;
    if !developer_activity_authorization_header_key(key) {
        return None;
    }
    let trimmed_value = value.trim();
    if trimmed_value.is_empty() {
        return None;
    }
    let mut value_parts = trimmed_value.split_whitespace();
    let first = value_parts.next()?;
    if developer_activity_authorization_scheme_marker(first) {
        Some(RedactedAuthorizationHeader {
            redacted: format!("{key}: {first} [REDACTED]"),
            consumes_next_token: value_parts.next().is_none(),
        })
    } else {
        Some(RedactedAuthorizationHeader {
            redacted: format!("{key}: [REDACTED]"),
            consumes_next_token: false,
        })
    }
}

fn developer_activity_authorization_scheme_marker(part: &str) -> bool {
    let normalized = part.trim_end_matches(':');
    matches!(
        normalized.to_ascii_lowercase().as_str(),
        "apikey"
            | "api-key"
            | "aws4-hmac-sha256"
            | "basic"
            | "bearer"
            | "digest"
            | "hawk"
            | "mac"
            | "negotiate"
            | "ntlm"
            | "oauth"
            | "oauth2"
            | "sharedkey"
            | "signature"
            | "token"
    )
}

fn developer_activity_sensitive_flag_without_value(part: &str) -> bool {
    let trimmed = part.trim_end_matches(':');
    if trimmed.contains('=') || !trimmed.starts_with('-') {
        return false;
    }
    developer_activity_sensitive_key(trimmed)
}

fn redact_developer_activity_sensitive_assignment(
    part: &str,
) -> Option<RedactedSensitiveAssignment> {
    let (key, value) = part.split_once('=')?;
    if key.is_empty()
        || key.contains(['?', '&', ';', '/', '\\'])
        || !developer_activity_sensitive_key(key)
    {
        return None;
    }
    if developer_activity_authorization_scheme_marker(value) {
        Some(RedactedSensitiveAssignment {
            redacted: part.to_string(),
            consumes_next_token: true,
        })
    } else {
        Some(RedactedSensitiveAssignment {
            redacted: format!("{key}=[REDACTED]"),
            consumes_next_token: false,
        })
    }
}

fn redact_developer_activity_command_part(part: &str) -> String {
    let part = redact_developer_activity_url_userinfo(part);
    let part = redact_developer_activity_jsonish_secret_fields(&part);
    if !part.contains('=') {
        return if developer_activity_secret_like_value(&part) {
            "[REDACTED]".to_string()
        } else {
            part
        };
    }
    let mut redacted = String::with_capacity(part.len());
    let mut remaining = part.as_str();
    while let Some(equal_index) = remaining.find('=') {
        let before_equal = &remaining[..equal_index];
        let key_start = before_equal
            .rfind(['?', '&', ';', '/', '\\'])
            .map_or(0, |position| position + 1);
        let key = &before_equal[key_start..];
        if key.is_empty() || !developer_activity_sensitive_key(key) {
            redacted.push_str(&remaining[..=equal_index]);
            remaining = &remaining[equal_index + 1..];
            continue;
        }

        redacted.push_str(before_equal);
        redacted.push_str("=[REDACTED]");
        let value_start = equal_index + 1;
        let value_end = remaining[value_start..]
            .find(['&', ';'])
            .map_or(remaining.len(), |offset| value_start + offset);
        remaining = &remaining[value_end..];
    }
    redacted.push_str(remaining);
    redacted
}

fn redact_developer_activity_jsonish_secret_fields(part: &str) -> String {
    let bytes = part.as_bytes();
    let mut redacted = String::with_capacity(part.len());
    let mut cursor = 0;
    let mut index = 0;
    while index < bytes.len() {
        let quote = bytes[index];
        if quote != b'\'' && quote != b'"' {
            index += 1;
            continue;
        }
        let Some(key_end) = find_unescaped_ascii_quote(bytes, index + 1, quote) else {
            break;
        };
        let key = &part[index + 1..key_end];
        let mut colon_index = key_end + 1;
        while colon_index < bytes.len() && bytes[colon_index].is_ascii_whitespace() {
            colon_index += 1;
        }
        if colon_index >= bytes.len()
            || bytes[colon_index] != b':'
            || !developer_activity_sensitive_metadata_key(key)
        {
            index += 1;
            continue;
        }

        let mut value_start = colon_index + 1;
        while value_start < bytes.len() && bytes[value_start].is_ascii_whitespace() {
            value_start += 1;
        }
        if value_start >= bytes.len() {
            index = value_start;
            continue;
        }

        redacted.push_str(&part[cursor..value_start]);
        let value_quote = bytes[value_start];
        if value_quote == b'\'' || value_quote == b'"' {
            redacted.push(value_quote as char);
            redacted.push_str("[REDACTED]");
            let Some(value_end) = find_unescaped_ascii_quote(bytes, value_start + 1, value_quote)
            else {
                cursor = bytes.len();
                break;
            };
            redacted.push(value_quote as char);
            cursor = value_end + 1;
            index = cursor;
        } else {
            redacted.push_str("[REDACTED]");
            let value_end = bytes[value_start..]
                .iter()
                .position(|byte| byte.is_ascii_whitespace() || matches!(byte, b',' | b'}' | b']'))
                .map_or(bytes.len(), |offset| value_start + offset);
            cursor = value_end;
            index = cursor;
        }
    }
    if cursor == 0 {
        part.to_string()
    } else {
        redacted.push_str(&part[cursor..]);
        redacted
    }
}

fn find_unescaped_ascii_quote(bytes: &[u8], start: usize, quote: u8) -> Option<usize> {
    let mut escaped = false;
    for (offset, byte) in bytes.iter().enumerate().skip(start) {
        if escaped {
            escaped = false;
        } else if *byte == b'\\' {
            escaped = true;
        } else if *byte == quote {
            return Some(offset);
        }
    }
    None
}

fn redact_developer_activity_url_userinfo(part: &str) -> String {
    let Some(scheme_end) = part.find("://") else {
        return part.to_string();
    };
    let authority_start = scheme_end + 3;
    let authority_end = part[authority_start..]
        .find(['/', '?', '#'])
        .map_or(part.len(), |offset| authority_start + offset);
    let authority = &part[authority_start..authority_end];
    let Some(at_index) = authority.rfind('@') else {
        return part.to_string();
    };
    let userinfo = &authority[..at_index];
    let Some(colon_index) = userinfo.find(':') else {
        return format!(
            "{}[REDACTED]{}",
            &part[..authority_start],
            &part[authority_start + at_index..]
        );
    };
    let password = &userinfo[colon_index + 1..];
    if password.is_empty() {
        return part.to_string();
    }

    let password_start = authority_start + colon_index + 1;
    let password_end = authority_start + at_index;
    format!(
        "{}[REDACTED]{}",
        &part[..password_start],
        &part[password_end..]
    )
}

fn developer_activity_sensitive_key(key: &str) -> bool {
    let normalized_key = key
        .trim_start_matches('-')
        .rsplit(['?', '&', '/', '\\'])
        .next()
        .unwrap_or(key)
        .to_ascii_lowercase()
        .replace(['-', '_'], "");
    matches!(normalized_key.as_str(), "p" | "passwd")
        || normalized_key == "authorization"
        || normalized_key == "cookie"
        || normalized_key.ends_with("token")
        || normalized_key.ends_with("secret")
        || normalized_key.ends_with("password")
        || normalized_key.ends_with("credential")
        || normalized_key.ends_with("credentials")
        || normalized_key.ends_with("apikey")
        || normalized_key.ends_with("authkey")
        || normalized_key.ends_with("privatekey")
        || (normalized_key.contains("secret") && normalized_key.ends_with("key"))
}

fn developer_activity_secret_like_value(value: &str) -> bool {
    let value = value.trim();
    if value.contains("-----BEGIN ") && value.contains("PRIVATE KEY-----") {
        return true;
    }
    if value.starts_with("AKIA")
        && value.len() >= 20
        && value
            .chars()
            .skip(4)
            .take(16)
            .all(|ch| ch.is_ascii_uppercase() || ch.is_ascii_digit())
    {
        return true;
    }
    [
        "ghp_", "gho_", "ghu_", "ghs_", "ghr_", "sk-", "xoxb-", "xoxa-", "xoxp-", "xoxr-", "xoxs-",
    ]
    .iter()
    .any(|prefix| value.starts_with(prefix) && value.len() >= prefix.len() + 20)
}

fn developer_activity_default_process_image(
    activity: &EdrDeveloperActivity,
    event: &EndpointEvent,
) -> Option<String> {
    if let Some(image) = trimmed_owned(activity.image.as_deref()) {
        return Some(image);
    }
    match event {
        EndpointEvent::ToolCall { tool_name, .. } => Some(tool_name.clone()),
        EndpointEvent::PackageScript { manager, .. } => Some(manager.as_str().to_string()),
        EndpointEvent::ProcessExec { image, .. } => Some(image.clone()),
        EndpointEvent::BrowserDownload { browser, .. }
        | EndpointEvent::BrowserExtensionInstall { browser, .. } => Some(browser.clone()),
        EndpointEvent::DnsLookup { .. } => Some("dns-collector".to_string()),
        EndpointEvent::CredentialAccess { .. } => activity
            .agent_id
            .as_deref()
            .and_then(|value| non_empty(Some(value)))
            .map(ToString::to_string)
            .or_else(|| Some("developer-collector".to_string())),
        _ => Some("developer-collector".to_string()),
    }
}

fn developer_activity_command_line(
    activity: &EdrDeveloperActivity,
    event: &EndpointEvent,
) -> Option<String> {
    if let Some(command_line) = trimmed_owned(activity.command_line.as_deref()) {
        return Some(command_line);
    }
    match event {
        EndpointEvent::ProcessExec { image, args, .. } if args.is_empty() => Some(image.clone()),
        EndpointEvent::ProcessExec { image, args, .. } => {
            Some(format!("{image} {}", args.join(" ")))
        }
        EndpointEvent::PackageScript {
            manager,
            phase,
            script,
            ..
        } => Some(format!("{} {phase} {script}", manager.as_str())),
        EndpointEvent::ToolCall { tool_name, .. } => Some(tool_name.clone()),
        EndpointEvent::CredentialAccess { path, name, .. } => path
            .clone()
            .or_else(|| name.clone())
            .map(|target| format!("credential_access {target}")),
        EndpointEvent::FileAccess {
            operation, path, ..
        } => Some(format!(
            "file_access {} {path}",
            file_operation_name(operation)
        )),
        EndpointEvent::NetworkFlow {
            host, port, url, ..
        } => Some(format!(
            "network_egress {}",
            url.clone().unwrap_or_else(|| format!("{host}:{port}"))
        )),
        EndpointEvent::LaunchPersistence {
            operation, path, ..
        } => Some(format!(
            "persistence_change {} {path}",
            file_operation_name(operation)
        )),
        EndpointEvent::BrowserDownload { path, .. } => Some(format!("browser_download {path}")),
        EndpointEvent::BrowserExtensionInstall { path, .. } => {
            Some(format!("browser_extension {path}"))
        }
        EndpointEvent::DnsLookup { query, .. } => Some(format!("dns_lookup {query}")),
        _ => None,
    }
}

fn developer_activity_metadata(
    activity: &EdrDeveloperActivity,
) -> BTreeMap<String, serde_json::Value> {
    let mut metadata = redact_developer_activity_metadata(&activity.metadata);
    metadata.insert(
        "collectorKind".to_string(),
        serde_json::Value::String("developer_activity".to_string()),
    );
    metadata.insert(
        "developerActivityKind".to_string(),
        serde_json::Value::String(activity.kind.as_str().to_string()),
    );
    let tool_kind = match activity.kind {
        EdrDeveloperActivityKind::McpTool => Some("mcp"),
        EdrDeveloperActivityKind::BrowserAutomation => Some("browser_automation"),
        _ => None,
    };
    if let Some(tool_kind) = tool_kind {
        metadata
            .entry("toolKind".to_string())
            .or_insert_with(|| serde_json::Value::String(tool_kind.to_string()));
    }
    for (key, value) in [
        ("agentId", activity.agent_id.as_deref()),
        ("workloadId", activity.workload_id.as_deref()),
        ("approvalId", activity.approval_id.as_deref()),
        ("toolCallId", activity.tool_call_id.as_deref()),
        ("method", activity.method.as_deref()),
        ("contentHash", activity.content_hash.as_deref()),
        ("patchHash", activity.patch_hash.as_deref()),
        ("mechanism", activity.mechanism.as_deref()),
    ] {
        if let Some(value) = trimmed_owned(value) {
            metadata
                .entry(key.to_string())
                .or_insert_with(|| serde_json::Value::String(value));
        }
    }
    if let Some(patch_bytes) = activity.patch_bytes {
        metadata
            .entry("patchBytes".to_string())
            .or_insert_with(|| serde_json::Value::from(patch_bytes));
    }
    if let Some(byte_count) = developer_activity_byte_count(activity) {
        metadata.insert(
            "downloadByteCount".to_string(),
            serde_json::Value::from(byte_count),
        );
    }
    metadata
}

fn developer_activity_byte_count(activity: &EdrDeveloperActivity) -> Option<u64> {
    activity.byte_count.or_else(|| {
        metadata_u64(
            &activity.metadata,
            &[
                "downloadByteCount",
                "download_byte_count",
                "byteCount",
                "byte_count",
                "fileSize",
                "file_size",
                "transferSize",
                "transfer_size",
            ],
        )
    })
}

fn metadata_u64(metadata: &BTreeMap<String, serde_json::Value>, keys: &[&str]) -> Option<u64> {
    for key in keys {
        let Some(value) = metadata.get(*key) else {
            continue;
        };
        if let Some(number) = value.as_u64() {
            return Some(number);
        }
        if let Some(text) = value.as_str().map(str::trim) {
            if text.is_empty() || !text.chars().all(|ch| ch.is_ascii_digit()) {
                continue;
            }
            if let Ok(number) = text.parse::<u64>() {
                return Some(number);
            }
        }
    }
    None
}

fn redact_developer_activity_metadata(
    metadata: &BTreeMap<String, serde_json::Value>,
) -> BTreeMap<String, serde_json::Value> {
    redact_endpoint_observation_metadata(metadata)
}

pub(crate) fn redact_endpoint_observations(
    observations: &[EndpointObservation],
) -> Vec<EndpointObservation> {
    observations
        .iter()
        .map(redact_endpoint_observation)
        .collect()
}

fn redact_endpoint_observation(observation: &EndpointObservation) -> EndpointObservation {
    let mut redacted = observation.clone();
    redacted.process = redact_endpoint_process(&redacted.process);
    redacted.event = redact_endpoint_event(&redacted.event);
    redacted.metadata = redact_endpoint_observation_metadata(&redacted.metadata);
    redacted
}

fn redact_endpoint_process(process: &EndpointProcess) -> EndpointProcess {
    let mut redacted = process.clone();
    if let Some(command_line) = trimmed_owned(redacted.command_line.as_deref()) {
        redacted.command_line = Some(redact_developer_activity_command_line(&command_line));
    }
    redacted
}

fn redact_endpoint_event(event: &EndpointEvent) -> EndpointEvent {
    match event {
        EndpointEvent::ProcessExec { image, args, env } => EndpointEvent::ProcessExec {
            image: image.clone(),
            args: redact_developer_activity_args(args),
            env: env
                .iter()
                .map(|(key, value)| {
                    let value = if developer_activity_sensitive_metadata_key(key) {
                        "[REDACTED]".to_string()
                    } else {
                        redact_developer_activity_command_line(value)
                    };
                    (key.clone(), value)
                })
                .collect(),
        },
        EndpointEvent::FileAccess {
            operation,
            path,
            source_url,
            content_preview,
        } => EndpointEvent::FileAccess {
            operation: operation.clone(),
            path: path.clone(),
            source_url: source_url
                .as_deref()
                .map(redact_developer_activity_command_line),
            content_preview: content_preview.as_ref().map(|_| "[REDACTED]".to_string()),
        },
        EndpointEvent::NetworkFlow {
            host,
            port,
            protocol,
            url,
        } => EndpointEvent::NetworkFlow {
            host: host.clone(),
            port: *port,
            protocol: protocol.clone(),
            url: url.as_deref().map(redact_developer_activity_command_line),
        },
        EndpointEvent::PackageScript {
            manager,
            package,
            phase,
            script,
            working_directory,
        } => EndpointEvent::PackageScript {
            manager: manager.clone(),
            package: package.clone(),
            phase: phase.clone(),
            script: redact_developer_activity_command_line(script),
            working_directory: working_directory.clone(),
        },
        EndpointEvent::BrowserExtensionInstall {
            browser,
            extension_id,
            path,
            source,
        } => EndpointEvent::BrowserExtensionInstall {
            browser: browser.clone(),
            extension_id: extension_id.clone(),
            path: path.clone(),
            source: source
                .as_deref()
                .map(redact_developer_activity_command_line),
        },
        EndpointEvent::BrowserDownload {
            browser,
            path,
            source_url,
            content_hash,
            byte_count,
        } => EndpointEvent::BrowserDownload {
            browser: browser.clone(),
            path: path.clone(),
            source_url: source_url
                .as_deref()
                .map(redact_developer_activity_command_line),
            content_hash: content_hash.clone(),
            byte_count: *byte_count,
        },
        EndpointEvent::ToolCall {
            tool_name,
            parameters,
        } => EndpointEvent::ToolCall {
            tool_name: tool_name.clone(),
            parameters: redact_developer_activity_metadata_value("parameters", parameters),
        },
        EndpointEvent::PolicyDecision {
            action,
            target,
            decision,
            guard,
            severity,
        } => EndpointEvent::PolicyDecision {
            action: action.clone(),
            target: target
                .as_deref()
                .map(redact_developer_activity_command_line),
            decision: decision.clone(),
            guard: guard.clone(),
            severity: severity.clone(),
        },
        EndpointEvent::Other { category, fields } => EndpointEvent::Other {
            category: category.clone(),
            fields: redact_endpoint_observation_metadata(fields),
        },
        _ => event.clone(),
    }
}

pub(crate) fn redact_endpoint_observation_metadata(
    metadata: &BTreeMap<String, serde_json::Value>,
) -> BTreeMap<String, serde_json::Value> {
    metadata
        .iter()
        .map(|(key, value)| {
            (
                key.clone(),
                redact_developer_activity_metadata_value(key, value),
            )
        })
        .collect()
}

fn redact_developer_activity_metadata_value(
    key: &str,
    value: &serde_json::Value,
) -> serde_json::Value {
    if developer_activity_sensitive_metadata_key(key) {
        return serde_json::Value::String("[REDACTED]".to_string());
    }
    match value {
        serde_json::Value::String(value) => {
            serde_json::Value::String(redact_developer_activity_command_line(value))
        }
        serde_json::Value::Array(values) => serde_json::Value::Array(
            values
                .iter()
                .map(|value| redact_developer_activity_metadata_value(key, value))
                .collect(),
        ),
        serde_json::Value::Object(values) => serde_json::Value::Object(
            values
                .iter()
                .map(|(nested_key, value)| {
                    (
                        nested_key.clone(),
                        redact_developer_activity_metadata_value(nested_key, value),
                    )
                })
                .collect(),
        ),
        _ => value.clone(),
    }
}

fn developer_activity_sensitive_metadata_key(key: &str) -> bool {
    let normalized_key = key
        .trim_start_matches('-')
        .rsplit(['?', '&', '/', '\\'])
        .next()
        .unwrap_or(key)
        .to_ascii_lowercase()
        .replace(['-', '_'], "");
    developer_activity_sensitive_key(key)
        || normalized_key.ends_with("token")
        || normalized_key.ends_with("secret")
        || normalized_key.ends_with("password")
        || normalized_key.ends_with("apikey")
        || matches!(
            normalized_key.as_str(),
            "authorization" | "auth" | "credential" | "credentials"
        )
}

fn developer_activity_file_operation(
    activity: &EdrDeveloperActivity,
    fallback: FileOperation,
) -> FileOperation {
    match activity
        .operation
        .as_deref()
        .map(str::trim)
        .map(str::to_ascii_lowercase)
        .as_deref()
    {
        Some("read" | "open" | "file_read") => FileOperation::Read,
        Some("write" | "file_write") => FileOperation::Write,
        Some("create") => FileOperation::Create,
        Some("delete" | "unlink") => FileOperation::Delete,
        Some("rename" | "move") => FileOperation::Rename,
        Some("execute" | "exec") => FileOperation::Execute,
        Some("chmod") => FileOperation::Chmod,
        Some(_) | None => fallback,
    }
}

fn file_operation_name(operation: &FileOperation) -> &'static str {
    match operation {
        FileOperation::Read => "read",
        FileOperation::Write => "write",
        FileOperation::Create => "create",
        FileOperation::Delete => "delete",
        FileOperation::Rename => "rename",
        FileOperation::Execute => "execute",
        FileOperation::Chmod => "chmod",
        FileOperation::Unknown => "unknown",
    }
}

fn developer_activity_parameters(activity: &EdrDeveloperActivity) -> serde_json::Value {
    let mut parameters = activity.parameters.clone().unwrap_or_else(|| {
        serde_json::Value::Object(serde_json::Map::<String, serde_json::Value>::new())
    });
    if let serde_json::Value::Object(object) = &mut parameters {
        for (key, value) in [
            ("action", activity.action.as_deref()),
            ("target", activity.target.as_deref()),
            ("browser", activity.browser.as_deref()),
            ("path", activity.path.as_deref()),
            ("sourceUrl", activity.source_url.as_deref()),
            ("query", activity.query.as_deref()),
            ("recordType", activity.record_type.as_deref()),
            ("resolver", activity.resolver.as_deref()),
            ("status", activity.status.as_deref()),
        ] {
            if let Some(value) = trimmed_owned(value) {
                object
                    .entry(key.to_string())
                    .or_insert(serde_json::Value::String(value));
            }
        }
        if !activity.answers.is_empty() {
            let answers = activity
                .answers
                .iter()
                .filter_map(|answer| trimmed_owned(Some(answer.as_str())))
                .map(serde_json::Value::String)
                .collect::<Vec<_>>();
            if !answers.is_empty() {
                object
                    .entry("answers".to_string())
                    .or_insert(serde_json::Value::Array(answers));
            }
        }
    }
    parameters
}

fn developer_activity_stable_id(activity: &EdrDeveloperActivity, index: usize) -> String {
    let index = index.to_string();
    let primary = activity
        .path
        .as_deref()
        .or(activity.name.as_deref())
        .or(activity.query.as_deref())
        .or(activity.host.as_deref())
        .or(activity.url.as_deref())
        .or(activity.target.as_deref())
        .or(activity.tool_name.as_deref())
        .or(activity.operation.as_deref())
        .or(activity.script.as_deref())
        .unwrap_or_default();
    local_stable_id(
        "devact",
        [
            activity.kind.as_str(),
            activity.session_id.as_deref().unwrap_or_default(),
            activity.agent_id.as_deref().unwrap_or_default(),
            primary,
            index.as_str(),
        ],
    )
}

fn required_activity_string(
    activity: &EdrDeveloperActivity,
    field: &str,
    value: Option<&str>,
) -> Result<String, (StatusCode, String)> {
    trimmed_owned(value).ok_or_else(|| {
        bad_activity_request(
            activity,
            &format!("{field} is required for {}", activity.kind.as_str()),
        )
    })
}

pub(crate) fn trimmed_owned(value: Option<&str>) -> Option<String> {
    non_empty(value).map(ToString::to_string)
}

fn bad_activity_request(activity: &EdrDeveloperActivity, message: &str) -> (StatusCode, String) {
    (
        StatusCode::BAD_REQUEST,
        format!(
            "invalid {} developer activity: {message}",
            activity.kind.as_str()
        ),
    )
}

pub(crate) async fn evaluate_record_and_receipt_edr_observations(
    state: &AgentApiState,
    detection_observations: &[EndpointObservation],
    recorded_observations: &[EndpointObservation],
    submitted_honey_artifacts: Vec<HoneyArtifact>,
) -> Result<EdrEvaluatedFindings, (StatusCode, String)> {
    validate_edr_request_sizes(recorded_observations.len(), submitted_honey_artifacts.len())?;
    if detection_observations.len() != recorded_observations.len() {
        return Err((
            StatusCode::BAD_REQUEST,
            "detection and recording observation counts must match".to_string(),
        ));
    }

    let honey_artifacts = state
        .edr_honey_registry
        .lock()
        .await
        .load()
        .map_err(internal_error)?;
    require_submitted_honey_artifacts_registered(&submitted_honey_artifacts, &honey_artifacts)?;
    validate_edr_request_sizes(recorded_observations.len(), honey_artifacts.len())?;

    let guard = SupplyChainRuntimeGuard::with_honey_artifacts(honey_artifacts);
    let mut findings = Vec::new();
    for (detection_observation, recorded_observation) in
        detection_observations.iter().zip(recorded_observations)
    {
        findings.extend(guard.evaluate(recorded_observation));

        for finding in guard
            .evaluate(detection_observation)
            .into_iter()
            .filter(is_local_only_honey_marker_finding)
        {
            if !findings
                .iter()
                .any(|existing| existing.finding_id == finding.finding_id)
            {
                findings.push(finding);
            }
        }
    }
    record_edr_observations(state, recorded_observations).await?;
    let graph = state.edr_flight_recorder.lock().await.graph().clone();
    let receipts = emit_edr_detection_receipts(state, recorded_observations, &findings, &graph)
        .await
        .map_err(internal_error)?;
    append_recent_edr_findings(state, &findings).await;
    publish_current_agent_secret_touches_to_fleet_best_effort(state, recorded_observations).await;

    Ok(EdrEvaluatedFindings { findings, receipts })
}

fn require_submitted_honey_artifacts_registered(
    submitted_honey_artifacts: &[HoneyArtifact],
    registered_honey_artifacts: &[HoneyArtifact],
) -> Result<(), (StatusCode, String)> {
    for submitted in submitted_honey_artifacts {
        let Some(registered) = registered_honey_artifacts
            .iter()
            .find(|artifact| artifact.artifact_id == submitted.artifact_id)
        else {
            return Err((
                StatusCode::BAD_REQUEST,
                format!(
                    "submitted honey artifact {} is not a registered honey artifact",
                    submitted.artifact_id
                ),
            ));
        };

        if registered != submitted {
            return Err((
                StatusCode::BAD_REQUEST,
                format!(
                    "submitted honey artifact {} does not match the registered honey artifact",
                    submitted.artifact_id
                ),
            ));
        }
    }
    Ok(())
}

fn is_local_only_honey_marker_finding(finding: &DetectionFinding) -> bool {
    finding.rule_id == "deception.honey_artifact_touched"
        && finding
            .evidence
            .iter()
            .any(|item| item.key == "matchType" && item.value == "marker")
}

pub(crate) fn parse_policy_event_jsonl(
    body: &str,
) -> Result<Vec<PolicyEvent>, (StatusCode, String)> {
    let mut events = Vec::new();
    for (line_index, line) in body.lines().enumerate() {
        let line_number = line_index + 1;
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        let event = serde_json::from_str::<PolicyEvent>(trimmed).map_err(|err| {
            (
                StatusCode::BAD_REQUEST,
                format!("invalid PolicyEvent JSONL at line {line_number}: {err}"),
            )
        })?;
        validate_policy_event_submission(&event, Some(line_number))?;
        events.push(event);
        validate_edr_request_sizes(events.len(), 0)?;
    }
    Ok(events)
}

pub(crate) async fn select_policy_event_history_from_flight_recorder(
    state: &AgentApiState,
    input: EdrPolicyEventHistoryReplayInput,
) -> Result<EdrPolicyEventHistorySelection, (StatusCode, String)> {
    let limit = input.limit.unwrap_or(EDR_MAX_OBSERVATIONS_PER_REQUEST);
    if limit == 0 {
        return Err((
            StatusCode::BAD_REQUEST,
            "history replay limit must be greater than zero".to_string(),
        ));
    }
    if limit > EDR_MAX_OBSERVATIONS_PER_REQUEST {
        return Err((
            StatusCode::BAD_REQUEST,
            format!(
                "history replay limit exceeds max {}",
                EDR_MAX_OBSERVATIONS_PER_REQUEST
            ),
        ));
    }
    if let (Some(since), Some(until)) = (input.since, input.until) {
        if since > until {
            return Err((
                StatusCode::BAD_REQUEST,
                "history replay since must be earlier than until".to_string(),
            ));
        }
    }
    let event_kinds = normalize_history_event_kinds(&input.event_kinds)?;
    let identity_filters = normalize_history_identity_filters(input.identity_filters())?;
    let process_filters = normalize_history_process_filters(input.process_filters())?;
    let target_filters = normalize_history_target_filters(input.target_filters())?;

    let now = chrono::Utc::now();
    let (path, history_window) = {
        let recorder = state.edr_flight_recorder.lock().await;
        let path = recorder.path().map(|path| path.display().to_string());
        if path.is_none() {
            return Err((
                StatusCode::CONFLICT,
                "policy-event history replay requires a durable flight recorder path".to_string(),
            ));
        }
        let history_window = recorder
            .read_indexed_observation_window(limit, |entry| {
                let time_matches = match input.since {
                    Some(since) => entry.timestamp >= since,
                    None => true,
                } && match input.until {
                    Some(until) => entry.timestamp <= until,
                    None => true,
                } && match input.max_age_seconds {
                    Some(max_age_seconds) => {
                        let age_seconds = now
                            .signed_duration_since(entry.timestamp)
                            .num_seconds()
                            .max(0) as u64;
                        age_seconds <= max_age_seconds
                    }
                    None => true,
                };
                let event_kind_matches =
                    event_kinds.is_empty() || event_kinds.contains(entry.event_kind.as_str());
                let identity_matches = identity_filters.matches_index_entry(entry);
                let process_matches = process_filters.matches_index_entry(entry);
                let target_matches = target_filters.matches_index_entry(entry);
                time_matches
                    && event_kind_matches
                    && identity_matches
                    && process_matches
                    && target_matches
            })
            .map_err(internal_error)?;
        (path, history_window)
    };
    let total_observation_count = history_window.total_observation_count;
    let matched_observation_count = history_window.matched_observation_count;
    let matched = history_window.selected_observations;
    if matched.is_empty() {
        return Err((
            StatusCode::BAD_REQUEST,
            "flight recorder history selection produced no observations".to_string(),
        ));
    }
    validate_edr_request_sizes(matched.len(), 0)?;

    let oldest_timestamp = matched
        .iter()
        .map(|observation| observation.timestamp)
        .min();
    let newest_timestamp = matched
        .iter()
        .map(|observation| observation.timestamp)
        .max();
    let events = matched
        .iter()
        .map(EndpointObservation::to_policy_event_projection)
        .collect::<Vec<_>>();
    validate_policy_event_replay_events(&events)?;
    let event_stream_hash =
        canonical_json_hash(&events, "policy event history replay event stream")
            .map_err(internal_error)?;
    let summary = format!(
        "Projected {} selected flight-recorder observations into {} PolicyEvent candidates from {} matched observations.",
        matched.len(),
        events.len(),
        matched_observation_count
    );
    let report = EdrPolicyEventHistoryReport {
        source: "endpoint_flight_recorder".to_string(),
        projection_mode: "endpoint_observation_policy_event_projection".to_string(),
        selection_mode: history_window.selection_mode,
        path,
        index_path: history_window
            .index_path
            .map(|path| path.display().to_string()),
        total_observation_count,
        matched_observation_count,
        selected_observation_count: matched.len(),
        policy_event_count: events.len(),
        limit,
        since: input.since,
        until: input.until,
        max_age_seconds: input.max_age_seconds,
        event_kinds: event_kinds.iter().cloned().collect(),
        identity_filters,
        process_filters,
        target_filters,
        oldest_timestamp,
        newest_timestamp,
        event_stream_hash,
        summary,
    };

    Ok(EdrPolicyEventHistorySelection {
        report,
        events,
        observations: matched,
    })
}

fn normalize_history_event_kinds(
    event_kinds: &[String],
) -> Result<BTreeSet<String>, (StatusCode, String)> {
    if event_kinds.len() > 64 {
        return Err((
            StatusCode::BAD_REQUEST,
            "history replay eventKinds must contain at most 64 entries".to_string(),
        ));
    }
    let mut normalized = BTreeSet::new();
    for event_kind in event_kinds {
        let event_kind = event_kind.trim().replace('-', "_").to_ascii_lowercase();
        if event_kind.is_empty() {
            continue;
        }
        if !event_kind
            .chars()
            .all(|ch| ch.is_ascii_lowercase() || ch.is_ascii_digit() || ch == '_')
        {
            return Err((
                StatusCode::BAD_REQUEST,
                format!("invalid history replay event kind: {event_kind}"),
            ));
        }
        normalized.insert(event_kind);
    }
    Ok(normalized)
}

fn normalize_history_identity_filters(
    filters: EdrPolicyEventHistoryIdentityFilters,
) -> Result<EdrPolicyEventHistoryIdentityFilters, (StatusCode, String)> {
    Ok(EdrPolicyEventHistoryIdentityFilters {
        host_id: normalize_history_identity_filter("hostId", filters.host_id)?,
        user_id: normalize_history_identity_filter("userId", filters.user_id)?,
        session_id: normalize_history_identity_filter("sessionId", filters.session_id)?,
        process_guid: normalize_history_identity_filter("processGuid", filters.process_guid)?,
        parent_process_guid: normalize_history_identity_filter(
            "parentProcessGuid",
            filters.parent_process_guid,
        )?,
        agent_id: normalize_history_identity_filter("agentId", filters.agent_id)?,
        workload_id: normalize_history_identity_filter("workloadId", filters.workload_id)?,
        approval_id: normalize_history_identity_filter("approvalId", filters.approval_id)?,
        tool_name: normalize_history_identity_filter("toolName", filters.tool_name)?,
        tool_call_id: normalize_history_identity_filter("toolCallId", filters.tool_call_id)?,
        credential_kind: normalize_history_identity_filter(
            "credentialKind",
            filters.credential_kind,
        )?,
    })
}

fn normalize_history_target_filters(
    filters: EdrPolicyEventHistoryTargetFilters,
) -> Result<EdrPolicyEventHistoryTargetFilters, (StatusCode, String)> {
    Ok(EdrPolicyEventHistoryTargetFilters {
        event_target: normalize_history_target_filter("eventTarget", filters.event_target)?,
        event_target_hash: normalize_history_hash_filter(
            "eventTargetHash",
            filters.event_target_hash,
        )?,
    })
}

fn normalize_history_process_filters(
    filters: EdrPolicyEventHistoryProcessFilters,
) -> Result<EdrPolicyEventHistoryProcessFilters, (StatusCode, String)> {
    Ok(EdrPolicyEventHistoryProcessFilters {
        process_image_hash: normalize_history_hash_filter(
            "processImageHash",
            filters.process_image_hash,
        )?,
        process_command_line_hash: normalize_history_hash_filter(
            "processCommandLineHash",
            filters.process_command_line_hash,
        )?,
    })
}

pub(crate) fn normalize_policy_event_history_validation_window_seconds(
    value: Option<u64>,
) -> Result<Option<u64>, (StatusCode, String)> {
    let Some(window_seconds) = value else {
        return Ok(None);
    };
    if window_seconds == 0 {
        return Err((
            StatusCode::BAD_REQUEST,
            "history impact validationWindowSeconds must be greater than zero".to_string(),
        ));
    }
    if window_seconds > EDR_MAX_POLICY_EVENT_IMPACT_VALIDATION_WINDOW_SECONDS {
        return Err((
            StatusCode::BAD_REQUEST,
            format!(
                "history impact validationWindowSeconds exceeds max {}",
                EDR_MAX_POLICY_EVENT_IMPACT_VALIDATION_WINDOW_SECONDS
            ),
        ));
    }
    Ok(Some(window_seconds))
}

fn normalize_history_target_filter(
    field: &str,
    value: Option<String>,
) -> Result<Option<String>, (StatusCode, String)> {
    let Some(value) = value else {
        return Ok(None);
    };
    let value = value.trim();
    if value.is_empty() {
        return Ok(None);
    }
    if value.len() > 2048 {
        return Err((
            StatusCode::BAD_REQUEST,
            format!("history replay {field} exceeds 2048 bytes"),
        ));
    }
    if value.chars().any(char::is_control) {
        return Err((
            StatusCode::BAD_REQUEST,
            format!("history replay {field} cannot contain control characters"),
        ));
    }
    Ok(Some(value.to_string()))
}

fn normalize_history_hash_filter(
    field: &str,
    value: Option<String>,
) -> Result<Option<String>, (StatusCode, String)> {
    let Some(value) = value else {
        return Ok(None);
    };
    let value = value.trim();
    if value.is_empty() {
        return Ok(None);
    }
    if value.len() > 128 {
        return Err((
            StatusCode::BAD_REQUEST,
            format!("history replay {field} exceeds 128 bytes"),
        ));
    }
    if value.chars().any(char::is_control) {
        return Err((
            StatusCode::BAD_REQUEST,
            format!("history replay {field} cannot contain control characters"),
        ));
    }
    let normalized = value.to_ascii_lowercase();
    let Some(hex) = normalized
        .strip_prefix("0x")
        .or_else(|| normalized.strip_prefix("sha256:"))
    else {
        return Err((
            StatusCode::BAD_REQUEST,
            format!("history replay {field} must be a sha256 hash"),
        ));
    };
    if hex.len() != 64 || !hex.chars().all(|ch| ch.is_ascii_hexdigit()) {
        return Err((
            StatusCode::BAD_REQUEST,
            format!("history replay {field} must be a sha256 hash"),
        ));
    }
    Ok(Some(format!("0x{hex}")))
}

fn normalize_history_identity_filter(
    field: &str,
    value: Option<String>,
) -> Result<Option<String>, (StatusCode, String)> {
    let Some(value) = value else {
        return Ok(None);
    };
    let value = value.trim();
    if value.is_empty() {
        return Ok(None);
    }
    if value.len() > 512 {
        return Err((
            StatusCode::BAD_REQUEST,
            format!("history replay {field} exceeds 512 bytes"),
        ));
    }
    if value.chars().any(char::is_control) {
        return Err((
            StatusCode::BAD_REQUEST,
            format!("history replay {field} cannot contain control characters"),
        ));
    }
    Ok(Some(value.to_string()))
}

pub(crate) fn build_policy_event_history_cross_window_impact(
    selection: &EdrPolicyEventHistorySelection,
    policy_impact: &EdrPolicyEventImpactReport,
    changes: &[EdrPolicyEventImpactEntry],
    window_seconds: u64,
) -> EdrPolicyEventHistoryCrossWindowImpact {
    let timestamps = selection
        .observations
        .iter()
        .map(|observation| (observation.observation_id.as_str(), observation.timestamp))
        .collect::<BTreeMap<_, _>>();
    let window_seconds = window_seconds.max(1);
    let window_seconds_i64 = i64::try_from(window_seconds).unwrap_or(i64::MAX);
    let mut windows = BTreeMap::<i64, EdrPolicyEventHistoryImpactWindowAccumulator>::new();

    for change in changes {
        let Some(timestamp) = timestamps.get(change.event_id.as_str()).copied() else {
            continue;
        };
        let window_index = timestamp.timestamp().div_euclid(window_seconds_i64);
        let window = windows.entry(window_index).or_default();
        window.window_start = Some(
            window
                .window_start
                .map_or(timestamp, |current| current.min(timestamp)),
        );
        window.window_end = Some(
            window
                .window_end
                .map_or(timestamp, |current| current.max(timestamp)),
        );
        window.event_count = window.event_count.saturating_add(1);
        if change.changed {
            window.changed_count = window.changed_count.saturating_add(1);
            if change.proposed_outcome == "blocked" {
                window.blocking_change_count = window.blocking_change_count.saturating_add(1);
            }
            if window.sample_event_ids.len() < EDR_MAX_POLICY_EVENT_IMPACT_CHAIN_DRIVER_SAMPLES {
                window.sample_event_ids.push(change.event_id.clone());
            }
        }
    }

    let windows = windows
        .into_iter()
        .filter_map(|(window_index, window)| {
            let window_start = window.window_start?;
            let window_end = window.window_end?;
            Some(EdrPolicyEventHistoryImpactWindow {
                window_index,
                window_start,
                window_end,
                event_count: window.event_count,
                changed_count: window.changed_count,
                blocking_change_count: window.blocking_change_count,
                sample_event_ids: window.sample_event_ids,
            })
        })
        .collect::<Vec<_>>();
    let total_event_count = windows.iter().map(|window| window.event_count).sum::<u64>();
    let total_changed_count = windows
        .iter()
        .map(|window| window.changed_count)
        .sum::<u64>();
    let total_blocking_change_count = windows
        .iter()
        .map(|window| window.blocking_change_count)
        .sum::<u64>();
    let changed_window_count = windows
        .iter()
        .filter(|window| window.changed_count > 0)
        .count();
    let blocking_window_count = windows
        .iter()
        .filter(|window| window.blocking_change_count > 0)
        .count();
    let (repeatability, recommended_stage, promotion_ready, recommendation_reason) =
        cross_window_impact_recommendation(
            windows.len(),
            changed_window_count,
            blocking_window_count,
            total_blocking_change_count,
        );
    let history_selector_hash = policy_event_history_selector_hash(&selection.report);
    let impact_hash = cross_window_impact_hash(CrossWindowImpactHashInput {
        window_seconds,
        total_event_count,
        total_changed_count,
        total_blocking_change_count,
        windows: &windows,
        event_stream_hash: selection.report.event_stream_hash.as_str(),
        current_policy_hash: policy_impact.current_policy.policy_hash.as_str(),
        current_policy_epoch: policy_impact.current_policy.policy_epoch,
        proposed_policy_hash: policy_impact.proposed_policy.policy_hash.as_str(),
        proposed_policy_epoch: policy_impact.proposed_policy.policy_epoch,
        current_result_hash: policy_impact.current_result_hash.as_str(),
        proposed_result_hash: policy_impact.proposed_result_hash.as_str(),
        history_selector_hash: history_selector_hash.as_str(),
    });
    let recommendation_hash = cross_window_recommendation_hash(
        impact_hash.as_str(),
        repeatability.as_str(),
        recommended_stage.as_str(),
        promotion_ready,
        recommendation_reason.as_str(),
    );

    EdrPolicyEventHistoryCrossWindowImpact {
        window_seconds,
        window_count: windows.len(),
        changed_window_count,
        blocking_window_count,
        total_event_count,
        total_changed_count,
        total_blocking_change_count,
        impact_hash,
        event_stream_hash: selection.report.event_stream_hash.clone(),
        current_policy_hash: policy_impact.current_policy.policy_hash.clone(),
        current_policy_epoch: policy_impact.current_policy.policy_epoch,
        proposed_policy_hash: policy_impact.proposed_policy.policy_hash.clone(),
        proposed_policy_epoch: policy_impact.proposed_policy.policy_epoch,
        current_result_hash: policy_impact.current_result_hash.clone(),
        proposed_result_hash: policy_impact.proposed_result_hash.clone(),
        history_selector_hash,
        repeatability,
        recommended_stage,
        promotion_ready,
        recommendation_hash,
        recommendation_reason,
        windows,
    }
}

pub(crate) struct CrossWindowImpactHashInput<'a> {
    pub(crate) window_seconds: u64,
    pub(crate) total_event_count: u64,
    pub(crate) total_changed_count: u64,
    pub(crate) total_blocking_change_count: u64,
    pub(crate) windows: &'a [EdrPolicyEventHistoryImpactWindow],
    pub(crate) event_stream_hash: &'a str,
    pub(crate) current_policy_hash: &'a str,
    pub(crate) current_policy_epoch: u64,
    pub(crate) proposed_policy_hash: &'a str,
    pub(crate) proposed_policy_epoch: u64,
    pub(crate) current_result_hash: &'a str,
    pub(crate) proposed_result_hash: &'a str,
    pub(crate) history_selector_hash: &'a str,
}

pub(crate) fn cross_window_impact_hash(input: CrossWindowImpactHashInput<'_>) -> String {
    let mut material = format!(
        "window_seconds={}\ntotal_event_count={}\ntotal_changed_count={}\ntotal_blocking_change_count={}\nevent_stream_hash={}\ncurrent_policy_hash={}\ncurrent_policy_epoch={}\nproposed_policy_hash={}\nproposed_policy_epoch={}\ncurrent_result_hash={}\nproposed_result_hash={}\nhistory_selector_hash={}\n",
        input.window_seconds,
        input.total_event_count,
        input.total_changed_count,
        input.total_blocking_change_count,
        input.event_stream_hash,
        input.current_policy_hash,
        input.current_policy_epoch,
        input.proposed_policy_hash,
        input.proposed_policy_epoch,
        input.current_result_hash,
        input.proposed_result_hash,
        input.history_selector_hash,
    );
    for window in input.windows {
        material.push_str(&format!(
            "window_index={};start={};end={};events={};changed={};blocking={};samples={}\n",
            window.window_index,
            window.window_start.to_rfc3339(),
            window.window_end.to_rfc3339(),
            window.event_count,
            window.changed_count,
            window.blocking_change_count,
            window.sample_event_ids.join(",")
        ));
    }
    sha256(material.as_bytes()).to_hex_prefixed()
}

pub(crate) fn cross_window_recommendation_hash(
    impact_hash: &str,
    repeatability: &str,
    recommended_stage: &str,
    promotion_ready: bool,
    recommendation_reason: &str,
) -> String {
    let material = format!(
        "impact_hash={impact_hash}\nrepeatability={repeatability}\nrecommended_stage={recommended_stage}\npromotion_ready={promotion_ready}\nrecommendation_reason={recommendation_reason}\n"
    );
    sha256(material.as_bytes()).to_hex_prefixed()
}

fn policy_event_history_selector_hash(history: &EdrPolicyEventHistoryReport) -> String {
    let selector = serde_json::json!({
        "source": &history.source,
        "projectionMode": &history.projection_mode,
        "selectionMode": &history.selection_mode,
        "limit": history.limit,
        "since": history.since,
        "until": history.until,
        "maxAgeSeconds": history.max_age_seconds,
        "eventKinds": &history.event_kinds,
        "identityFilters": &history.identity_filters,
        "processFilters": &history.process_filters,
        "targetFilters": &history.target_filters,
        "oldestTimestamp": history.oldest_timestamp,
        "newestTimestamp": history.newest_timestamp,
        "eventStreamHash": &history.event_stream_hash,
    });
    canonical_json_hash(&selector, "policy event history selector")
        .unwrap_or_else(|_| sha256(history.event_stream_hash.as_bytes()).to_hex_prefixed())
}

fn cross_window_impact_recommendation(
    window_count: usize,
    changed_window_count: usize,
    blocking_window_count: usize,
    total_blocking_change_count: u64,
) -> (String, String, bool, String) {
    if total_blocking_change_count == 0 {
        return (
            "none".to_string(),
            "observe".to_string(),
            false,
            format!(
                "No blocking rule diff appeared across {window_count} validation windows; keep observing before promotion."
            ),
        );
    }

    if blocking_window_count < 2 {
        return (
            "single_window".to_string(),
            "audit".to_string(),
            false,
            format!(
                "Blocking impact appeared in {blocking_window_count} of {window_count} validation windows; keep the candidate in audit until repeated history supports promotion."
            ),
        );
    }

    let repeatability = if changed_window_count == window_count {
        "all_windows"
    } else {
        "repeated_windows"
    };
    let recommended_stage = if blocking_window_count == window_count {
        "limited_block"
    } else {
        "warn"
    };
    (
        repeatability.to_string(),
        recommended_stage.to_string(),
        true,
        format!(
            "Blocking impact appeared in {blocking_window_count} of {window_count} validation windows; repeated local history supports {recommended_stage} staging with receipts and rollback gates."
        ),
    )
}

pub(crate) fn build_policy_event_history_causal_impact(
    selection: &EdrPolicyEventHistorySelection,
    changes: &[EdrPolicyEventImpactEntry],
    graph: &CausalGraph,
    context_depth: usize,
    promotion_stage: Option<&str>,
    cross_window_hashes: Option<(&str, &str)>,
) -> EdrPolicyEventHistoryCausalImpact {
    let observations = selection
        .observations
        .iter()
        .map(|observation| (observation.observation_id.as_str(), observation))
        .collect::<BTreeMap<_, _>>();
    let changed = changes
        .iter()
        .filter(|change| change.changed)
        .collect::<Vec<_>>();
    let mut contexts = Vec::new();
    let mut union_node_ids = BTreeSet::new();
    let mut missing_graph_context_count = 0usize;

    for change in changed
        .iter()
        .take(EDR_MAX_POLICY_EVENT_IMPACT_CONTEXTS)
        .copied()
    {
        let Some(observation) = observations.get(change.event_id.as_str()) else {
            missing_graph_context_count = missing_graph_context_count.saturating_add(1);
            continue;
        };
        let touched_node_ids = graph_node_ids_for_observation(graph, &observation.observation_id);
        let Some(root_node_id) =
            finding_group_root_node_id(graph, &observation.observation_id, &touched_node_ids)
        else {
            missing_graph_context_count = missing_graph_context_count.saturating_add(1);
            continue;
        };
        let context = graph
            .causal_context_around(&root_node_id, context_depth, context_depth)
            .unwrap_or_else(|| {
                graph_slice_for_node_ids(graph, &BTreeSet::from([root_node_id.clone()]))
            });
        union_node_ids.extend(context.nodes.keys().cloned());
        let root_label = graph
            .nodes
            .get(&root_node_id)
            .map(|node| node.label.clone())
            .unwrap_or_else(|| root_node_id.clone());
        let chains =
            causal_chains_for_changed_observation(&context, &root_node_id, &touched_node_ids);
        contexts.push(EdrPolicyEventHistoryCausalContext {
            event_id: change.event_id.clone(),
            current_outcome: change.current_outcome.clone(),
            proposed_outcome: change.proposed_outcome.clone(),
            current_guard: change.current_decision.guard.clone(),
            proposed_guard: change.proposed_decision.guard.clone(),
            current_reason_code: change.current_decision.reason_code.clone(),
            proposed_reason_code: change.proposed_decision.reason_code.clone(),
            root_node_id,
            root_label,
            node_count: context.nodes.len(),
            edge_count: context.edges.len(),
            chain_count: chains.len(),
            chains,
            node_kinds: causal_node_kind_counts(&context),
            graph: context,
        });
    }

    let union_graph = graph_slice_for_node_ids(graph, &union_node_ids);
    let omitted_context_count = (changed.len())
        .saturating_sub(contexts.len())
        .saturating_sub(missing_graph_context_count);
    let chain_drivers = causal_chain_drivers_for_contexts(&contexts);
    let promotion_suggestions = promotion_suggestions_for_causal_impact(
        &contexts,
        context_depth,
        promotion_stage,
        cross_window_hashes,
    );
    let affected_identities = affected_identities_for_causal_impact(&union_graph);
    let affected_identity_count = affected_identities.count();
    let affected_tools = affected_tools_for_causal_impact(&union_graph);
    let affected_tool_count = affected_tools.len();
    let blocking_change_count = changed
        .iter()
        .filter(|change| change.proposed_outcome == "blocked")
        .count() as u64;
    let mut breakage_drivers = breakage_drivers_for_causal_impact(&union_graph);
    let developer_breakage_score = if blocking_change_count > 0 {
        score_policy_event_history_breakage(&breakage_drivers, &union_graph)
    } else {
        0
    };
    let impact_level = policy_event_history_impact_level_for_score(developer_breakage_score);
    let breakage_driver_count = breakage_drivers.len();
    breakage_drivers.truncate(EDR_MAX_POLICY_EVENT_IMPACT_BREAKAGE_DRIVERS);

    EdrPolicyEventHistoryCausalImpact {
        changed_event_count: changed.len() as u64,
        context_count: contexts.len(),
        chain_count: contexts.iter().map(|context| context.chain_count).sum(),
        chain_driver_count: chain_drivers.len(),
        promotion_suggestion_count: promotion_suggestions.len(),
        affected_identity_count,
        affected_tool_count,
        blocking_change_count,
        developer_breakage_score,
        impact_level,
        breakage_driver_count,
        omitted_context_count,
        missing_graph_context_count,
        context_depth,
        node_count: union_graph.nodes.len(),
        edge_count: union_graph.edges.len(),
        node_kinds: causal_node_kind_counts(&union_graph),
        affected_identities,
        affected_tools,
        top_breakage_drivers: breakage_drivers,
        contexts,
        chain_drivers,
        promotion_suggestions,
        receipt: None,
    }
}

// affected_identities_for_causal_impact and push_affected_identity moved to crate::edr::queries::causal
pub(crate) fn affected_tools_for_causal_impact(
    graph: &CausalGraph,
) -> Vec<EdrPolicyEventHistoryAffectedTool> {
    graph
        .nodes
        .values()
        .filter(|node| node.kind == CausalNodeKind::Tool)
        .map(|node| EdrPolicyEventHistoryAffectedTool {
            node_id: node.node_id.clone(),
            label: node.label.clone(),
            tool_name: node.label.clone(),
        })
        .collect()
}

fn breakage_drivers_for_causal_impact(
    graph: &CausalGraph,
) -> Vec<EdrPolicyEventHistoryBreakageDriver> {
    let mut drivers = graph
        .nodes
        .values()
        .map(policy_event_history_breakage_driver)
        .collect::<Vec<_>>();
    drivers.sort_by(|left, right| {
        right
            .breakage_score
            .cmp(&left.breakage_score)
            .then_with(|| left.node_id.cmp(&right.node_id))
    });
    drivers
}

fn policy_event_history_breakage_driver(node: &CausalNode) -> EdrPolicyEventHistoryBreakageDriver {
    let (breakage_score, reason) = match node.kind {
        CausalNodeKind::Host => (
            25,
            "blocking this host affects endpoint-wide local activity",
        ),
        CausalNodeKind::User => (
            48,
            "blocking this user identity can disrupt every local workflow for that principal",
        ),
        CausalNodeKind::Session => (
            36,
            "blocking this session can disrupt the active user or agent workflow",
        ),
        CausalNodeKind::Agent => (
            42,
            "blocking this agent identity can disrupt local automation workflows",
        ),
        CausalNodeKind::Workload => (
            42,
            "blocking this workload identity can disrupt delegated automation or service activity",
        ),
        CausalNodeKind::Approval => (
            18,
            "blocking this approval context affects authorized workflow bookkeeping",
        ),
        CausalNodeKind::Process => (30, "blocking this process affects local execution"),
        CausalNodeKind::File => (18, "blocking this file interaction may affect local files"),
        CausalNodeKind::Network => (24, "blocking this network target may affect egress"),
        CausalNodeKind::DnsName => (
            26,
            "blocking this DNS name may affect name resolution for local or developer workflows",
        ),
        CausalNodeKind::PackageScript => (
            55,
            "blocking this package-manager lifecycle script can break dependency installation",
        ),
        CausalNodeKind::Credential => (
            50,
            "blocking this credential access can break authenticated developer or cloud workflows",
        ),
        CausalNodeKind::Tool => (
            42,
            "blocking this tool call can break local agent or automation workflows",
        ),
        CausalNodeKind::BrowserDownload => (
            22,
            "blocking this browser download may affect a user-sourced artifact",
        ),
        CausalNodeKind::BrowserExtension => (
            28,
            "blocking this browser extension change may affect browser functionality",
        ),
        CausalNodeKind::PolicyDecision => (
            12,
            "blocking this policy decision node affects enforcement bookkeeping",
        ),
        CausalNodeKind::DeceptionArtifact => (
            5,
            "blocking deception material should have minimal legitimate workflow impact",
        ),
        CausalNodeKind::Other => (10, "blocking this node has unknown local workflow impact"),
    };

    EdrPolicyEventHistoryBreakageDriver {
        node_id: node.node_id.clone(),
        kind: node.kind.clone(),
        label: node.label.clone(),
        workflow_category: policy_event_history_workflow_category(node).to_string(),
        breakage_score,
        reason: reason.to_string(),
    }
}

fn policy_event_history_workflow_category(node: &CausalNode) -> &'static str {
    match node.kind {
        CausalNodeKind::Host => "endpoint_identity",
        CausalNodeKind::User => "user_identity",
        CausalNodeKind::Session => "session_identity",
        CausalNodeKind::Agent => "agent_identity",
        CausalNodeKind::Workload => "workload_identity",
        CausalNodeKind::Approval => "approval_context",
        CausalNodeKind::Process => "process_execution",
        CausalNodeKind::File => "file_activity",
        CausalNodeKind::Network => "network_egress",
        CausalNodeKind::DnsName => "dns_resolution",
        CausalNodeKind::PackageScript => "package_manager_script",
        CausalNodeKind::Credential => "credential_access",
        CausalNodeKind::Tool => {
            if node.label.starts_with("mcp__") {
                "mcp_tool_call"
            } else if node.label.contains("browser") {
                "browser_automation_tool"
            } else if node.label.contains("shell") || node.label.contains("terminal") {
                "shell_tool_call"
            } else {
                "agent_tool_call"
            }
        }
        CausalNodeKind::BrowserDownload => "browser_download",
        CausalNodeKind::BrowserExtension => "browser_extension",
        CausalNodeKind::PolicyDecision => "policy_decision",
        CausalNodeKind::DeceptionArtifact => "endpoint_deception",
        CausalNodeKind::Other => "other_endpoint_activity",
    }
}

fn score_policy_event_history_breakage(
    drivers: &[EdrPolicyEventHistoryBreakageDriver],
    graph: &CausalGraph,
) -> u8 {
    let max_node_score = drivers
        .iter()
        .map(|driver| driver.breakage_score)
        .max()
        .unwrap_or(0);
    let breadth = graph
        .nodes
        .len()
        .saturating_sub(1)
        .saturating_mul(4)
        .min(24) as u8;
    let edge_weight = graph.edges.len().saturating_mul(2).min(16) as u8;
    let process_weight = count_causal_nodes_by_kind(graph, CausalNodeKind::Process)
        .saturating_sub(1)
        .saturating_mul(6)
        .min(18) as u8;
    let credential_weight = if count_causal_nodes_by_kind(graph, CausalNodeKind::Credential) > 0 {
        10
    } else {
        0
    };

    max_node_score
        .saturating_add(breadth)
        .saturating_add(edge_weight)
        .saturating_add(process_weight)
        .saturating_add(credential_weight)
        .min(100)
}

fn policy_event_history_impact_level_for_score(score: u8) -> EndpointSimulationImpactLevel {
    match score {
        0 => EndpointSimulationImpactLevel::None,
        1..=24 => EndpointSimulationImpactLevel::Low,
        25..=49 => EndpointSimulationImpactLevel::Medium,
        50..=74 => EndpointSimulationImpactLevel::High,
        _ => EndpointSimulationImpactLevel::Critical,
    }
}

fn count_causal_nodes_by_kind(graph: &CausalGraph, kind: CausalNodeKind) -> usize {
    graph
        .nodes
        .values()
        .filter(|node| node.kind == kind)
        .count()
}

fn causal_chain_drivers_for_contexts(
    contexts: &[EdrPolicyEventHistoryCausalContext],
) -> Vec<EdrPolicyEventHistoryCausalChainDriver> {
    let mut buckets = BTreeMap::<
        EdrPolicyEventHistoryCausalChainDriverKey,
        EdrPolicyEventHistoryCausalChainDriverBucket,
    >::new();

    for context in contexts {
        for chain in &context.chains {
            let Some(target_node) = context.graph.nodes.get(&chain.target_node_id) else {
                continue;
            };
            let action = default_detection_candidate_action(target_node);
            if !supported_edr_simulation_action(&action) {
                continue;
            }
            let key = EdrPolicyEventHistoryCausalChainDriverKey {
                current_outcome: context.current_outcome.clone(),
                proposed_outcome: context.proposed_outcome.clone(),
                current_guard: context.current_guard.clone(),
                proposed_guard: context.proposed_guard.clone(),
                current_reason_code: context.current_reason_code.clone(),
                proposed_reason_code: context.proposed_reason_code.clone(),
                target_kind: chain.target_kind.clone(),
                action: action.as_str().to_string(),
                edge_kinds: chain.edge_kinds.clone(),
            };
            let bucket = buckets.entry(key).or_default();
            bucket.count = bucket.count.saturating_add(1);
            push_limited_unique_chain_driver_sample(
                &mut bucket.sample_event_ids,
                context.event_id.clone(),
            );
            push_limited_unique_chain_driver_sample(
                &mut bucket.sample_target_node_ids,
                chain.target_node_id.clone(),
            );
            push_limited_unique_chain_driver_sample(
                &mut bucket.sample_target_labels,
                chain.target_label.clone(),
            );
        }
    }

    let mut drivers = buckets
        .into_iter()
        .filter_map(|(key, bucket)| {
            let action = endpoint_decision_action_from_str(&key.action)?;
            let edge_kinds_material = key.edge_kinds.join(">");
            let driver_id = local_stable_id(
                "chain_driver",
                [
                    key.current_outcome.as_str(),
                    key.proposed_outcome.as_str(),
                    key.current_guard.as_deref().unwrap_or(""),
                    key.proposed_guard.as_deref().unwrap_or(""),
                    key.current_reason_code.as_str(),
                    key.proposed_reason_code.as_str(),
                    key.target_kind.as_str(),
                    key.action.as_str(),
                    edge_kinds_material.as_str(),
                ],
            );
            Some(EdrPolicyEventHistoryCausalChainDriver {
                driver_id,
                current_outcome: key.current_outcome,
                proposed_outcome: key.proposed_outcome,
                current_guard: key.current_guard,
                proposed_guard: key.proposed_guard,
                current_reason_code: key.current_reason_code,
                proposed_reason_code: key.proposed_reason_code,
                target_kind: key.target_kind,
                action,
                edge_kinds: key.edge_kinds,
                count: bucket.count,
                sample_event_ids: bucket.sample_event_ids,
                sample_target_node_ids: bucket.sample_target_node_ids,
                sample_target_labels: bucket.sample_target_labels,
            })
        })
        .collect::<Vec<_>>();
    drivers.sort_by(|left, right| {
        right
            .count
            .cmp(&left.count)
            .then_with(|| left.target_kind.cmp(&right.target_kind))
            .then_with(|| left.action.as_str().cmp(right.action.as_str()))
            .then_with(|| left.edge_kinds.cmp(&right.edge_kinds))
            .then_with(|| left.driver_id.cmp(&right.driver_id))
    });
    drivers
}

fn push_limited_unique_chain_driver_sample(samples: &mut Vec<String>, sample: String) {
    if samples.len() >= EDR_MAX_POLICY_EVENT_IMPACT_CHAIN_DRIVER_SAMPLES {
        return;
    }
    if samples.iter().any(|existing| existing == &sample) {
        return;
    }
    samples.push(sample);
}

fn endpoint_decision_action_from_str(value: &str) -> Option<EndpointDecisionAction> {
    match value {
        "allow" => Some(EndpointDecisionAction::Allow),
        "observe" => Some(EndpointDecisionAction::Observe),
        "warn" => Some(EndpointDecisionAction::Warn),
        "alert" => Some(EndpointDecisionAction::Alert),
        "block" => Some(EndpointDecisionAction::Block),
        "restrict_egress" => Some(EndpointDecisionAction::RestrictEgress),
        "suspend_process_tree" => Some(EndpointDecisionAction::SuspendProcessTree),
        "terminate_process_tree" => Some(EndpointDecisionAction::TerminateProcessTree),
        "quarantine_file" => Some(EndpointDecisionAction::QuarantineFile),
        "revoke_grant" => Some(EndpointDecisionAction::RevokeGrant),
        "disable_persistence" => Some(EndpointDecisionAction::DisablePersistence),
        "collect_evidence" => Some(EndpointDecisionAction::CollectEvidence),
        _ => None,
    }
}

fn promotion_suggestions_for_causal_impact(
    contexts: &[EdrPolicyEventHistoryCausalContext],
    max_depth: usize,
    selected_stage: Option<&str>,
    cross_window_hashes: Option<(&str, &str)>,
) -> Vec<EdrPolicyEventHistoryPromotionSuggestion> {
    let mut suggestions = Vec::new();
    let mut seen = BTreeSet::new();
    let selected_stage = selected_stage.unwrap_or("audit").to_string();
    let cross_window_impact_hash =
        cross_window_hashes.map(|(impact_hash, _)| impact_hash.to_string());
    let cross_window_recommendation_hash =
        cross_window_hashes.map(|(_, recommendation_hash)| recommendation_hash.to_string());

    for context in contexts {
        for chain in &context.chains {
            if suggestions.len() >= EDR_MAX_POLICY_EVENT_IMPACT_PROMOTION_SUGGESTIONS {
                return suggestions;
            }
            let Some(target_node) = context.graph.nodes.get(&chain.target_node_id) else {
                continue;
            };
            let action = default_detection_candidate_action(target_node);
            if !supported_edr_simulation_action(&action) {
                continue;
            }
            let dedupe_key = format!("{}:{}", chain.target_node_id, action.as_str());
            if !seen.insert(dedupe_key) {
                continue;
            }
            let description = detection_candidate_description(target_node, &action);
            let note = format!(
                "Stage candidate from history impact event {} ({} -> {}) for review before enforcement.",
                context.event_id, context.current_outcome, context.proposed_outcome
            );
            let suggestion_id = local_stable_id(
                "impact_promotion",
                [
                    context.event_id.as_str(),
                    chain.target_node_id.as_str(),
                    action.as_str(),
                    selected_stage.as_str(),
                ],
            );
            suggestions.push(EdrPolicyEventHistoryPromotionSuggestion {
                suggestion_id,
                event_id: context.event_id.clone(),
                target_node_id: chain.target_node_id.clone(),
                target_label: chain.target_label.clone(),
                target_kind: chain.target_kind.clone(),
                action: action.clone(),
                selected_stage: selected_stage.clone(),
                cross_window_impact_hash: cross_window_impact_hash.clone(),
                cross_window_recommendation_hash: cross_window_recommendation_hash.clone(),
                reason: format!(
                    "Changed verdict {} -> {} on {} chain target {}; simulate and stage through the existing detection-candidate workflow.",
                    context.current_outcome,
                    context.proposed_outcome,
                    chain.target_kind,
                    chain.target_label
                ),
                candidate_endpoint: "/api/v1/agent/edr/detection-candidate".to_string(),
                candidate_request: EdrPolicyEventHistoryPromotionCandidateRequest {
                    root_node_id: chain.target_node_id.clone(),
                    action: action.clone(),
                    max_depth,
                    description: description.clone(),
                },
                stage_endpoint: "/api/v1/agent/edr/staged-detections".to_string(),
                stage_request: EdrPolicyEventHistoryPromotionStageRequest {
                    root_node_id: chain.target_node_id.clone(),
                    action,
                    max_depth,
                    selected_stage: selected_stage.clone(),
                    cross_window_impact_hash: cross_window_impact_hash.clone(),
                    cross_window_recommendation_hash: cross_window_recommendation_hash.clone(),
                    staged_by: "operator".to_string(),
                    note,
                },
            });
        }
    }

    suggestions
}

fn causal_chains_for_changed_observation(
    graph: &CausalGraph,
    root_node_id: &str,
    touched_node_ids: &BTreeSet<String>,
) -> Vec<EdrPolicyEventHistoryCausalChain> {
    let mut chains = Vec::new();
    for target_node_id in touched_node_ids
        .iter()
        .filter(|node_id| node_id.as_str() != root_node_id)
        .filter(|node_id| graph.nodes.contains_key(*node_id))
        .take(EDR_MAX_POLICY_EVENT_IMPACT_CHAINS_PER_CONTEXT)
    {
        let Some(path_node_ids) = causal_path_node_ids(graph, root_node_id, target_node_id) else {
            continue;
        };
        let Some(target_node) = graph.nodes.get(target_node_id) else {
            continue;
        };
        let nodes = path_node_ids
            .iter()
            .filter_map(|node_id| {
                graph
                    .nodes
                    .get(node_id)
                    .map(|node| EdrPolicyEventHistoryCausalChainNode {
                        node_id: node_id.clone(),
                        kind: causal_node_kind_name(&node.kind).to_string(),
                        label: node.label.clone(),
                    })
            })
            .collect::<Vec<_>>();
        let edge_kinds = path_node_ids
            .windows(2)
            .filter_map(|window| {
                graph
                    .edges
                    .iter()
                    .find(|edge| edge.from == window[0] && edge.to == window[1])
                    .map(|edge| causal_edge_kind_name(&edge.kind).to_string())
            })
            .collect::<Vec<_>>();

        chains.push(EdrPolicyEventHistoryCausalChain {
            target_node_id: target_node_id.clone(),
            target_label: target_node.label.clone(),
            target_kind: causal_node_kind_name(&target_node.kind).to_string(),
            path_node_count: nodes.len(),
            path_edge_count: edge_kinds.len(),
            nodes,
            edge_kinds,
        });
    }
    chains
}

fn causal_path_node_ids(graph: &CausalGraph, from: &str, to: &str) -> Option<Vec<String>> {
    if !graph.nodes.contains_key(from) || !graph.nodes.contains_key(to) {
        return None;
    }
    if from == to {
        return Some(vec![from.to_string()]);
    }

    let mut queue = VecDeque::from([from.to_string()]);
    let mut seen = BTreeSet::from([from.to_string()]);
    let mut previous: BTreeMap<String, String> = BTreeMap::new();

    while let Some(node_id) = queue.pop_front() {
        for edge in graph.edges.iter().filter(|edge| edge.from == node_id) {
            if !seen.insert(edge.to.clone()) {
                continue;
            }
            previous.insert(edge.to.clone(), node_id.clone());
            if edge.to == to {
                let mut path = vec![to.to_string()];
                let mut current = to;
                while let Some(parent) = previous.get(current) {
                    path.push(parent.clone());
                    if parent == from {
                        break;
                    }
                    current = parent;
                }
                path.reverse();
                return Some(path);
            }
            queue.push_back(edge.to.clone());
        }
    }

    None
}

pub(crate) fn causal_impact_receipt_graph(
    impact: &EdrPolicyEventHistoryCausalImpact,
) -> Option<(String, CausalGraph)> {
    let root_node_id = impact.contexts.first()?.root_node_id.clone();
    let mut nodes = BTreeMap::new();
    let mut edges = BTreeMap::new();

    for context in &impact.contexts {
        for (node_id, node) in &context.graph.nodes {
            nodes.insert(node_id.clone(), node.clone());
        }
        for edge in &context.graph.edges {
            edges.insert(edge.edge_id.clone(), edge.clone());
        }
    }

    Some((
        root_node_id,
        CausalGraph {
            nodes,
            edges: edges.into_values().collect(),
        },
    ))
}

fn causal_node_kind_counts(graph: &CausalGraph) -> BTreeMap<String, u64> {
    let mut counts = BTreeMap::new();
    for node in graph.nodes.values() {
        *counts
            .entry(causal_node_kind_name(&node.kind).to_string())
            .or_insert(0) += 1;
    }
    counts
}

fn causal_edge_kind_name(kind: &CausalEdgeKind) -> &'static str {
    match kind {
        CausalEdgeKind::ObservedOn => "observed_on",
        CausalEdgeKind::RanAs => "ran_as",
        CausalEdgeKind::InSession => "in_session",
        CausalEdgeKind::UsedAgent => "used_agent",
        CausalEdgeKind::UsedWorkload => "used_workload",
        CausalEdgeKind::AuthorizedBy => "authorized_by",
        CausalEdgeKind::Spawned => "spawned",
        CausalEdgeKind::Executed => "executed",
        CausalEdgeKind::Read => "read",
        CausalEdgeKind::Wrote => "wrote",
        CausalEdgeKind::Connected => "connected",
        CausalEdgeKind::ResolvedDns => "resolved_dns",
        CausalEdgeKind::RanScript => "ran_script",
        CausalEdgeKind::LoadedLibrary => "loaded_library",
        CausalEdgeKind::CreatedPersistence => "created_persistence",
        CausalEdgeKind::InstalledExtension => "installed_extension",
        CausalEdgeKind::Downloaded => "downloaded",
        CausalEdgeKind::AccessedCredential => "accessed_credential",
        CausalEdgeKind::MadeDecision => "made_decision",
        CausalEdgeKind::InvokedTool => "invoked_tool",
        CausalEdgeKind::TemporalNext => "temporal_next",
        CausalEdgeKind::TouchedHoney => "touched_honey",
        CausalEdgeKind::Related => "related",
    }
}

pub(crate) async fn replay_policy_events_under_current_policy(
    state: &AgentApiState,
    events: Vec<PolicyEvent>,
    source: &str,
    track_posture: bool,
) -> Result<EdrPolicyEventReplayResponse, (StatusCode, String)> {
    validate_policy_event_replay_events(&events)?;
    let settings = state.settings.read().await.clone();
    let policy_bytes = fs::read(&settings.policy_path).with_context(|| {
        format!(
            "read local policy for policy event replay {}",
            settings.policy_path.display()
        )
    });
    let policy_bytes = policy_bytes.map_err(internal_error)?;
    let policy = endpoint_policy_snapshot_from_policy_bytes(&policy_bytes, &settings.policy_path)
        .map_err(internal_error)?;
    let replay_policy_yaml = policy_yaml_for_replay(&policy_bytes).map_err(internal_error)?;
    let event_stream_hash =
        canonical_json_hash(&events, "policy event replay event stream").map_err(internal_error)?;
    let result = replay_events(&replay_policy_yaml, &events, track_posture)
        .await
        .map_err(internal_error)?;
    let result_hash =
        canonical_json_hash(&result, "policy event replay result").map_err(internal_error)?;
    let replay = build_policy_event_replay_report(
        policy,
        source,
        events.len(),
        track_posture,
        event_stream_hash,
        result_hash,
        &result,
    );
    let receipt = emit_edr_policy_event_replay_receipt(state, &settings, &replay)
        .await
        .map_err(internal_error)?;

    Ok(EdrPolicyEventReplayResponse {
        replay,
        result,
        receipt,
    })
}

fn validate_policy_event_replay_events(events: &[PolicyEvent]) -> Result<(), (StatusCode, String)> {
    if events.is_empty() {
        return Err((
            StatusCode::BAD_REQUEST,
            "at least one PolicyEvent must be provided for replay".to_string(),
        ));
    }
    validate_edr_request_sizes(events.len(), 0)?;
    for event in events {
        validate_policy_event_submission(event, None)?;
    }
    Ok(())
}

fn policy_yaml_for_replay(policy_bytes: &[u8]) -> Result<String> {
    let mut value = serde_yaml::from_slice::<serde_yaml::Value>(policy_bytes)
        .context("parse local policy YAML for policy event replay")?;
    remove_yaml_policy_epoch_metadata(&mut value);
    serde_yaml::to_string(&value).context("serialize replay policy YAML")
}

fn remove_yaml_policy_epoch_metadata(value: &mut serde_yaml::Value) {
    let serde_yaml::Value::Mapping(map) = value else {
        return;
    };
    for key in ["policy_epoch", "policyEpoch", "epoch"] {
        map.remove(serde_yaml::Value::String(key.to_string()));
    }
    for container in ["policy", "metadata", "bundle"] {
        let key = serde_yaml::Value::String(container.to_string());
        let mut empty_after_strip = false;
        if let Some(serde_yaml::Value::Mapping(child)) = map.get_mut(&key) {
            for epoch_key in ["policy_epoch", "policyEpoch", "epoch"] {
                child.remove(serde_yaml::Value::String(epoch_key.to_string()));
            }
            empty_after_strip = child.is_empty();
        }
        if empty_after_strip {
            map.remove(&key);
        }
    }
}

pub(crate) fn canonical_json_hash(value: &impl Serialize, label: &str) -> Result<String> {
    let value = serde_json::to_value(value).with_context(|| format!("serialize {label}"))?;
    let canonical = canonicalize_json(&value).with_context(|| format!("canonicalize {label}"))?;
    Ok(sha256(canonical.as_bytes()).to_hex_prefixed())
}

// build_policy_event_replay_report, build_policy_event_impact_changes,
// build_policy_event_impact_drivers, build_policy_event_impact_report
// moved to crate::edr::policy_events

pub(crate) async fn analyze_policy_event_impact_under_proposed_policy(
    state: &AgentApiState,
    events: Vec<PolicyEvent>,
    source: &str,
    proposed_policy_yaml: String,
    track_posture: bool,
) -> Result<EdrPolicyEventImpactResponse, (StatusCode, String)> {
    validate_policy_event_replay_events(&events)?;
    if proposed_policy_yaml.trim().is_empty() {
        return Err((
            StatusCode::BAD_REQUEST,
            "proposedPolicyYaml must be provided".to_string(),
        ));
    }

    let settings = state.settings.read().await.clone();
    let current_policy_bytes = fs::read(&settings.policy_path).with_context(|| {
        format!(
            "read local policy for policy event impact {}",
            settings.policy_path.display()
        )
    });
    let current_policy_bytes = current_policy_bytes.map_err(internal_error)?;
    let current_policy =
        endpoint_policy_snapshot_from_policy_bytes(&current_policy_bytes, &settings.policy_path)
            .map_err(internal_error)?;
    let proposed_policy =
        endpoint_policy_snapshot_from_memory_policy_bytes(proposed_policy_yaml.as_bytes())
            .map_err(internal_error)?;
    let current_replay_yaml =
        policy_yaml_for_replay(&current_policy_bytes).map_err(internal_error)?;
    let proposed_replay_yaml =
        policy_yaml_for_replay(proposed_policy_yaml.as_bytes()).map_err(internal_error)?;
    let event_stream_hash =
        canonical_json_hash(&events, "policy event impact event stream").map_err(internal_error)?;
    let current_result = replay_events(&current_replay_yaml, &events, track_posture)
        .await
        .map_err(internal_error)?;
    let proposed_result = replay_events(&proposed_replay_yaml, &events, track_posture)
        .await
        .map_err(internal_error)?;
    let current_result_hash = canonical_json_hash(&current_result, "current policy impact result")
        .map_err(internal_error)?;
    let proposed_result_hash =
        canonical_json_hash(&proposed_result, "proposed policy impact result")
            .map_err(internal_error)?;
    let (summary, changes, drivers) =
        build_policy_event_impact_changes(&current_result, &proposed_result);
    let impact_hash = canonical_json_hash(
        &(serde_json::json!({
            "summary": &summary,
            "changes": &changes,
        })),
        "policy event impact report",
    )
    .map_err(internal_error)?;
    let impact = build_policy_event_impact_report(
        current_policy,
        proposed_policy,
        source,
        track_posture,
        event_stream_hash,
        current_result_hash,
        proposed_result_hash,
        impact_hash,
        &summary,
    );
    let receipt = emit_edr_policy_event_impact_receipt(state, &settings, &impact)
        .await
        .map_err(internal_error)?;

    Ok(EdrPolicyEventImpactResponse {
        impact,
        summary,
        drivers,
        changes,
        current_result,
        proposed_result,
        receipt,
    })
}

pub(crate) fn validate_policy_event_submission(
    event: &PolicyEvent,
    jsonl_line: Option<usize>,
) -> Result<(), (StatusCode, String)> {
    event.validate().map_err(|err| {
        let message = match jsonl_line {
            Some(line_number) => {
                format!("invalid PolicyEvent JSONL at line {line_number}: {err}")
            }
            None => err.to_string(),
        };
        (StatusCode::BAD_REQUEST, message)
    })
}

pub(crate) async fn record_edr_observations(
    state: &AgentApiState,
    observations: &[EndpointObservation],
) -> Result<(), (StatusCode, String)> {
    let mut recorder = state.edr_flight_recorder.lock().await;
    recorder
        .append_observations(observations)
        .map_err(internal_error)?;
    Ok(())
}

pub(crate) fn query_value(value: &Option<String>) -> Option<&str> {
    value
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
}

pub(crate) async fn evidence_bundle_archive_response(
    state: &AgentApiState,
    bundle_id: &str,
) -> Result<EdrEvidenceBundleArchiveResponse, (StatusCode, String)> {
    let bundle_id = bundle_id.trim();
    if bundle_id.is_empty() {
        return Err((
            StatusCode::BAD_REQUEST,
            "evidence bundle id must not be empty".to_string(),
        ));
    }

    let stored = {
        let mut store = state.edr_evidence_bundle_store.lock().await;
        store
            .load(bundle_id)
            .map_err(internal_error)?
            .ok_or_else(|| {
                (
                    StatusCode::NOT_FOUND,
                    format!("evidence bundle not found: {bundle_id}"),
                )
            })?
    };
    let receipts = evidence_bundle_archive_receipts(state, &stored).await?;
    let archive = EdrEvidenceBundleArchive {
        bundle: stored.bundle.clone(),
        artifact: EdrEvidenceBundleArtifact::from_stored(&stored),
        graph: stored.graph,
        receipts,
    };
    let verification = evidence_bundle_archive_verification(&archive).map_err(internal_error)?;
    let archive_hash = canonical_json_hash(&archive, "endpoint evidence bundle archive")
        .map_err(internal_error)?;
    let archive_id = local_stable_id(
        "evidence_bundle_archive",
        [
            archive.bundle.bundle_id.as_str(),
            archive.bundle.content_hash.as_str(),
            archive_hash.as_str(),
        ],
    );

    Ok(EdrEvidenceBundleArchiveResponse {
        archive_id,
        generated_at: chrono::Utc::now(),
        archive_hash,
        receipt_count: archive.receipts.len(),
        verification,
        archive,
    })
}

pub(crate) fn archive_newest_receipt_timestamp(
    archive: &EdrEvidenceBundleArchive,
) -> Option<chrono::DateTime<chrono::Utc>> {
    archive
        .receipts
        .iter()
        .map(|receipt| {
            chrono::DateTime::parse_from_rfc3339(&receipt.receipt.timestamp)
                .map(|timestamp| timestamp.with_timezone(&chrono::Utc))
                .ok()
        })
        .collect::<Option<Vec<_>>>()
        .and_then(|timestamps| timestamps.into_iter().max())
}

pub(crate) async fn active_response_evidence_bundle_ids(
    state: &AgentApiState,
    now: chrono::DateTime<chrono::Utc>,
) -> Result<BTreeSet<String>, (StatusCode, String)> {
    let ledger = state.edr_response_execution_ledger.lock().await;
    ledger
        .active_evidence_bundle_ids(now)
        .map_err(internal_error)
}

pub(crate) async fn evidence_bundle_archive_receipts(
    state: &AgentApiState,
    stored: &StoredEndpointEvidenceBundle,
) -> Result<Vec<SignedReceipt>, (StatusCode, String)> {
    let ledger = state.edr_receipt_ledger.lock().await;
    let mut receipts = Vec::new();
    let mut seen_receipt_ids = BTreeSet::new();
    let filters = [
        EdrReceiptFilter {
            graph_slice_id: Some(stored.bundle.graph_slice_id.as_str()),
            ..EdrReceiptFilter::default()
        },
        EdrReceiptFilter {
            family: Some("evidence_bundle_manifest"),
            finding_id: Some(stored.bundle.bundle_id.as_str()),
            ..EdrReceiptFilter::default()
        },
    ];

    for filter in filters {
        for receipt in ledger
            .read_recent(EDR_MAX_RECEIPT_QUERY_LIMIT, filter)
            .map_err(internal_error)?
        {
            let receipt_key = receipt.receipt.receipt_id.clone().unwrap_or_else(|| {
                format!(
                    "missing-receipt-id:{}:{}",
                    receipt.receipt.timestamp,
                    receipts.len()
                )
            });
            if seen_receipt_ids.insert(receipt_key) {
                receipts.push(receipt);
            }
        }
    }
    receipts.sort_by(|left, right| {
        left.receipt
            .timestamp
            .cmp(&right.receipt.timestamp)
            .then_with(|| left.receipt.receipt_id.cmp(&right.receipt.receipt_id))
    });
    Ok(receipts)
}

pub(crate) fn evidence_bundle_archive_verification(
    archive: &EdrEvidenceBundleArchive,
) -> Result<EdrEvidenceBundleArchiveVerification> {
    let canonical_graph = canonical_evidence_graph(&archive.graph)?;
    let graph_content_hash = canonical_graph.content_hash.clone();
    let content_hash_matches = graph_content_hash == archive.bundle.content_hash;
    let expected_bundle_id_evidence = sha256(archive.bundle.bundle_id.as_bytes()).to_hex_prefixed();
    let expected_content_hash_evidence =
        sha256(archive.bundle.content_hash.as_bytes()).to_hex_prefixed();
    let expected_node_count_evidence = archive.bundle.node_count.to_string();
    let expected_edge_count_evidence = archive.bundle.edge_count.to_string();
    let mut receipt_failures = Vec::new();
    let mut matching_content_hash_receipts = 0usize;
    let mut receipt_families = BTreeSet::new();
    let mut receipt_family_counts = BTreeMap::new();
    let mut response_actor_hashes = Vec::new();
    let mut receipt_endpoint_ids = BTreeSet::new();
    let mut receipt_root_node_ids = BTreeSet::new();
    let mut policy_hashes = Vec::new();
    let mut sensor_provider_sets = Vec::new();
    let mut receipt_ids = BTreeSet::new();
    let mut receipt_local_sequences = BTreeSet::new();
    let mut receipt_sequence_timestamps = BTreeMap::new();
    let mut receipt_signer_public_keys = BTreeSet::new();
    let actual_node_count = archive.graph.nodes.len();
    let actual_edge_count = archive.graph.edges.len();
    if archive.bundle.node_count != actual_node_count {
        receipt_failures.push(format!(
            "bundle_node_count_mismatch:{}:{actual_node_count}",
            archive.bundle.node_count
        ));
    }
    if archive.bundle.edge_count != actual_edge_count {
        receipt_failures.push(format!(
            "bundle_edge_count_mismatch:{}:{actual_edge_count}",
            archive.bundle.edge_count
        ));
    }
    if archive.artifact.bundle_id != archive.bundle.bundle_id {
        receipt_failures.push(format!(
            "artifact_bundle_id_mismatch:{}",
            archive.artifact.bundle_id
        ));
    }
    if archive.artifact.content_hash != archive.bundle.content_hash {
        receipt_failures.push(format!(
            "artifact_content_hash_mismatch:{}",
            archive.artifact.content_hash
        ));
    }
    if archive.artifact.byte_count != canonical_graph.byte_count {
        receipt_failures.push(format!(
            "artifact_byte_count_mismatch:{}:{}",
            archive.artifact.byte_count, canonical_graph.byte_count
        ));
    }

    for receipt in &archive.receipts {
        let receipt_label = receipt
            .receipt
            .receipt_id
            .as_deref()
            .unwrap_or("<missing-receipt-id>");
        match receipt
            .receipt
            .receipt_id
            .as_deref()
            .map(str::trim)
            .filter(|receipt_id| !receipt_id.is_empty())
        {
            Some(receipt_id) => {
                if !receipt_ids.insert(receipt_id.to_string()) {
                    receipt_failures.push(format!("duplicate_receipt_id:{receipt_id}"));
                }
            }
            None => receipt_failures.push(format!("{receipt_label}:missing_receipt_id")),
        }
        let receipt_sequence = receipt_local_sequence(receipt);
        let receipt_timestamp =
            match chrono::DateTime::parse_from_rfc3339(&receipt.receipt.timestamp) {
                Ok(timestamp) => Some(timestamp.with_timezone(&chrono::Utc)),
                Err(_) => {
                    receipt_failures.push(format!("{receipt_label}:invalid_receipt_timestamp"));
                    None
                }
            };
        match receipt_sequence {
            Some(local_sequence) => {
                if !receipt_local_sequences.insert(local_sequence) {
                    receipt_failures
                        .push(format!("duplicate_receipt_local_sequence:{local_sequence}"));
                }
                if let Some(timestamp) = receipt_timestamp {
                    receipt_sequence_timestamps.insert(local_sequence, timestamp);
                }
            }
            None => {
                receipt_failures.push(format!("{receipt_label}:missing_receipt_local_sequence"))
            }
        }
        match receipt_endpoint_decision_str(receipt, &["actor", "endpointId"])
            .map(str::trim)
            .filter(|endpoint_id| !endpoint_id.is_empty())
        {
            Some(endpoint_id) => {
                receipt_endpoint_ids.insert(endpoint_id.to_string());
            }
            None => receipt_failures.push(format!("{receipt_label}:missing_actor_endpoint_id")),
        }
        let receipt_root_node_id =
            receipt_endpoint_decision_str(receipt, &["graph", "processNodeId"])
                .map(str::trim)
                .filter(|root_node_id| !root_node_id.is_empty());
        match receipt_root_node_id {
            Some(root_node_id) => {
                receipt_root_node_ids.insert(root_node_id.to_string());
            }
            None => receipt_failures.push(format!("{receipt_label}:missing_root_node")),
        }
        let receipt_family = receipt_endpoint_decision_str(receipt, &["receiptFamily"]);
        match receipt_family {
            Some(
                family @ ("graph_slice"
                | "evidence_bundle_manifest"
                | "response_request"
                | "response_execution"
                | "response_rollback"
                | "response_acknowledgement"),
            ) => {
                receipt_families.insert(family.to_string());
                *receipt_family_counts.entry(family.to_string()).or_insert(0) += 1;
                if let Some(root_node_id) = receipt_root_node_id {
                    if family != "evidence_bundle_manifest" {
                        push_archive_receipt_evidence_hash_failure(
                            &mut receipt_failures,
                            receipt,
                            receipt_label,
                            "rootNodeId",
                            root_node_id,
                            "root_node",
                        );
                    }
                }
                push_archive_policy_failures(
                    &mut receipt_failures,
                    &mut policy_hashes,
                    receipt,
                    receipt_label,
                    family,
                )?;
                push_archive_sensor_state_failures(
                    &mut receipt_failures,
                    &mut sensor_provider_sets,
                    receipt,
                    receipt_label,
                    family,
                )?;
                if family == "evidence_bundle_manifest" {
                    match receipt_endpoint_decision_str(receipt, &["decision", "findingId"]) {
                        Some(actual) if actual == archive.bundle.bundle_id => {}
                        Some(actual) => receipt_failures.push(format!(
                            "{receipt_label}:manifest_finding_id_mismatch:{actual}"
                        )),
                        None => receipt_failures
                            .push(format!("{receipt_label}:missing_manifest_finding_id")),
                    }
                    push_archive_receipt_evidence_hash_failure(
                        &mut receipt_failures,
                        receipt,
                        receipt_label,
                        "graphSliceId",
                        &archive.bundle.graph_slice_id,
                        "graph_slice_evidence",
                    );
                    push_archive_receipt_evidence_hash_failure(
                        &mut receipt_failures,
                        receipt,
                        receipt_label,
                        "contentHash",
                        &archive.bundle.content_hash,
                        "content_hash",
                    );
                    push_archive_receipt_evidence_hash_failure(
                        &mut receipt_failures,
                        receipt,
                        receipt_label,
                        "nodeCount",
                        &expected_node_count_evidence,
                        "node_count",
                    );
                    push_archive_receipt_evidence_hash_failure(
                        &mut receipt_failures,
                        receipt,
                        receipt_label,
                        "edgeCount",
                        &expected_edge_count_evidence,
                        "edge_count",
                    );
                }
                if family == "graph_slice" {
                    push_archive_receipt_evidence_hash_failure(
                        &mut receipt_failures,
                        receipt,
                        receipt_label,
                        "graphSliceId",
                        &archive.bundle.graph_slice_id,
                        "graph_slice_evidence",
                    );
                    push_archive_receipt_evidence_hash_failure(
                        &mut receipt_failures,
                        receipt,
                        receipt_label,
                        "contentHash",
                        &archive.bundle.content_hash,
                        "content_hash",
                    );
                    push_archive_receipt_evidence_hash_failure(
                        &mut receipt_failures,
                        receipt,
                        receipt_label,
                        "nodeCount",
                        &expected_node_count_evidence,
                        "node_count",
                    );
                    push_archive_receipt_evidence_hash_failure(
                        &mut receipt_failures,
                        receipt,
                        receipt_label,
                        "edgeCount",
                        &expected_edge_count_evidence,
                        "edge_count",
                    );
                }
                if family == "response_request" {
                    push_archive_response_actor_failures(
                        &mut receipt_failures,
                        &mut response_actor_hashes,
                        receipt,
                        receipt_label,
                        family,
                        &["actorHash"],
                    )?;
                    push_archive_receipt_evidence_hash_failure(
                        &mut receipt_failures,
                        receipt,
                        receipt_label,
                        "graphSliceId",
                        &archive.bundle.graph_slice_id,
                        "graph_slice_evidence",
                    );
                }
                if family == "response_execution" {
                    push_archive_response_actor_failures(
                        &mut receipt_failures,
                        &mut response_actor_hashes,
                        receipt,
                        receipt_label,
                        family,
                        &["actorHash", "executionActorHash"],
                    )?;
                    push_archive_receipt_evidence_hash_failure(
                        &mut receipt_failures,
                        receipt,
                        receipt_label,
                        "graphSliceId",
                        &archive.bundle.graph_slice_id,
                        "graph_slice_evidence",
                    );
                    push_archive_receipt_evidence_hash_failure(
                        &mut receipt_failures,
                        receipt,
                        receipt_label,
                        "evidenceBundleContentHash",
                        &archive.bundle.content_hash,
                        "content_hash",
                    );
                }
            }
            Some(actual) => {
                receipt_failures.push(format!(
                    "{receipt_label}:unexpected_receipt_family:{actual}"
                ));
            }
            None => receipt_failures.push(format!("{receipt_label}:missing_receipt_family")),
        }
        match receipt_evidence_hash_value(receipt, "evidenceBundleId") {
            Some(actual) if actual == expected_bundle_id_evidence => {}
            Some(actual) => receipt_failures.push(format!(
                "{receipt_label}:evidence_bundle_id_mismatch:{actual}"
            )),
            None => {
                if matches!(
                    receipt_family,
                    Some("evidence_bundle_manifest" | "response_execution")
                ) {
                    receipt_failures.push(format!("{receipt_label}:missing_evidence_bundle_id"));
                }
            }
        }
        let signer_public_key =
            receipt_endpoint_decision_str(receipt, &["signer", "signerPublicKey"])
                .map(str::trim)
                .filter(|signer_public_key| !signer_public_key.is_empty());
        match signer_public_key {
            Some(signer_public_key) => {
                receipt_signer_public_keys.insert(signer_public_key.to_string());
                match hush_core::PublicKey::from_hex(signer_public_key) {
                    Ok(public_key) => {
                        let verification =
                            receipt.verify(&hush_core::receipt::PublicKeySet::new(public_key));
                        if !verification.valid {
                            receipt_failures.push(format!("{receipt_label}:signature_invalid"));
                        }
                    }
                    Err(_) => {
                        receipt_failures.push(format!("{receipt_label}:invalid_signer_public_key"));
                    }
                }
                if let Err(reason) =
                    verify_endpoint_receipt_signature(receipt, receipt_label, signer_public_key)
                {
                    receipt_failures.push(format!(
                        "{receipt_label}:endpoint_decision_binding_invalid:{reason}"
                    ));
                }
            }
            None => receipt_failures.push(format!("{receipt_label}:missing_signer_public_key")),
        }
        match receipt_endpoint_decision_str(receipt, &["graph", "graphSliceId"]) {
            Some(actual) if actual == archive.bundle.graph_slice_id => {}
            Some(actual) => {
                receipt_failures.push(format!("{receipt_label}:graph_slice_mismatch:{actual}"))
            }
            None => receipt_failures.push(format!("{receipt_label}:missing_graph_slice")),
        }
        if let Some(evidence) =
            receipt_endpoint_decision_value(receipt, &["evidence"]).and_then(Value::as_array)
        {
            for item in evidence.iter().filter(|item| {
                item.get("key")
                    .and_then(Value::as_str)
                    .is_some_and(|key| key == "contentHash" || key == "evidenceBundleContentHash")
            }) {
                match item.get("valueHash").and_then(Value::as_str) {
                    Some(actual) if actual == expected_content_hash_evidence => {
                        matching_content_hash_receipts =
                            matching_content_hash_receipts.saturating_add(1);
                    }
                    Some(actual) => receipt_failures
                        .push(format!("{receipt_label}:content_hash_mismatch:{actual}")),
                    None => receipt_failures.push(format!("{receipt_label}:missing_content_hash")),
                }
            }
        }
    }

    if archive.receipts.is_empty() {
        receipt_failures.push("missing_archive_receipts".to_string());
    }
    if receipt_signer_public_keys.is_empty() {
        receipt_failures.push("missing_receipt_signer_public_key_set".to_string());
    } else if receipt_signer_public_keys.len() > 1 {
        receipt_failures.push(format!(
            "receipt_signer_continuity_mismatch:{}",
            receipt_signer_public_keys.len()
        ));
    }
    if receipt_endpoint_ids.is_empty() {
        receipt_failures.push("missing_receipt_endpoint_identity_set".to_string());
    } else if receipt_endpoint_ids.len() > 1 {
        receipt_failures.push(format!(
            "receipt_endpoint_identity_mismatch:{}",
            receipt_endpoint_ids.len()
        ));
    }
    if receipt_root_node_ids.is_empty() {
        receipt_failures.push("missing_receipt_root_node_set".to_string());
    } else if receipt_root_node_ids.len() > 1 {
        receipt_failures.push(format!(
            "receipt_root_node_continuity_mismatch:{}",
            receipt_root_node_ids.len()
        ));
    }
    for (family, count) in &receipt_family_counts {
        if *count > 1 && !receipt_family_allows_multiple_archive_members(family) {
            receipt_failures.push(format!("duplicate_receipt_family:{family}:{count}"));
        }
    }
    let mut previous_sequence_timestamp = None;
    for (sequence, timestamp) in &receipt_sequence_timestamps {
        if let Some((previous_sequence, previous_timestamp)) = previous_sequence_timestamp {
            if timestamp < previous_timestamp {
                receipt_failures.push(format!(
                    "receipt_chronology_inversion:{previous_sequence}:{sequence}"
                ));
                break;
            }
        }
        previous_sequence_timestamp = Some((*sequence, timestamp));
    }

    let distinct_response_actor_hashes = response_actor_hashes
        .iter()
        .map(|(_, actor_hash)| actor_hash)
        .collect::<BTreeSet<_>>();
    if distinct_response_actor_hashes.len() > 1 {
        let actor_families = response_actor_hashes
            .iter()
            .map(|(family, _)| family.as_str())
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect::<Vec<_>>()
            .join(",");
        receipt_failures.push(format!(
            "response_actor_continuity_mismatch:{actor_families}"
        ));
    }
    let distinct_policy_hashes = policy_hashes
        .iter()
        .map(|(_, policy_hash)| policy_hash)
        .collect::<BTreeSet<_>>();
    if distinct_policy_hashes.len() > 1 {
        let policy_families = policy_hashes
            .iter()
            .map(|(family, _)| family.as_str())
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect::<Vec<_>>()
            .join(",");
        receipt_failures.push(format!("policy_continuity_mismatch:{policy_families}"));
    }
    if let Some((_, execution_providers)) = sensor_provider_sets
        .iter()
        .find(|(family, _)| family == "response_execution")
    {
        for (family, providers) in &sensor_provider_sets {
            if family != "response_execution" && !providers.is_subset(execution_providers) {
                receipt_failures.push(format!("sensor_state_continuity_mismatch:{family}"));
            }
        }
    }

    receipt_failures.sort();
    receipt_failures.dedup();
    let receipt_count = archive.receipts.len();
    let receipt_families_valid = !receipt_failures
        .iter()
        .any(|failure| failure.contains("receipt_family"));
    let present_receipt_families = receipt_families.iter().cloned().collect::<Vec<_>>();
    let receipt_family_cardinality_valid = !receipt_failures
        .iter()
        .any(|failure| failure.starts_with("duplicate_receipt_family:"));
    let mut required_receipt_families = Vec::new();
    let mut missing_required_receipt_families = Vec::new();
    let mut required_receipt_family_contract_known = true;
    match required_archive_receipt_families(&archive.bundle.bundle_id) {
        Some(required_family_contract) => {
            required_receipt_families = required_family_contract
                .iter()
                .map(|family| (*family).to_string())
                .collect();
            for family in required_family_contract {
                if !receipt_families.contains(family) {
                    receipt_failures.push(format!("missing_required_family:{family}"));
                    missing_required_receipt_families.push(family.to_string());
                }
            }
        }
        None => {
            required_receipt_family_contract_known = false;
            receipt_failures.push(format!(
                "unknown_required_family_contract:{}",
                archive.bundle.bundle_id
            ));
        }
    }
    receipt_failures.sort();
    receipt_failures.dedup();
    let required_receipt_families_present =
        required_receipt_family_contract_known && missing_required_receipt_families.is_empty();
    let artifact_matches_bundle = !receipt_failures
        .iter()
        .any(|failure| failure.contains("artifact_"));
    let artifact_byte_count_matches = !receipt_failures
        .iter()
        .any(|failure| failure.contains("artifact_byte_count_mismatch"));
    let receipts_bind_bundle_id = !receipt_failures.iter().any(|failure| {
        failure.contains("evidence_bundle_id") || failure.contains("manifest_finding_id")
    });
    let receipts_bind_actor = !receipt_failures.iter().any(|failure| {
        failure.contains("actor_hash")
            || failure.contains("execution_actor_hash")
            || failure.contains("actor_decode")
            || failure.contains("response_actor_continuity")
    });
    let receipts_bind_policy = !receipt_failures.iter().any(|failure| {
        failure.contains("policy_decode")
            || failure.contains("invalid_policy")
            || failure.contains("policy_continuity")
    });
    let receipts_bind_sensor_state = !receipt_failures.iter().any(|failure| {
        failure.contains("sensor_state_decode")
            || failure.contains("sensor_state_missing")
            || failure.contains("sensor_state_continuity")
    });
    let receipts_bind_endpoint_decision = !receipt_failures
        .iter()
        .any(|failure| failure.contains("endpoint_decision_binding"));
    let receipt_endpoint_ids = receipt_endpoint_ids.into_iter().collect::<Vec<_>>();
    let receipts_bind_endpoint_identity = receipt_count > 0
        && receipt_endpoint_ids.len() == 1
        && !receipt_failures.iter().any(|failure| {
            failure.contains("actor_endpoint_id") || failure.contains("receipt_endpoint_identity")
        });
    let receipt_root_node_ids = receipt_root_node_ids.into_iter().collect::<Vec<_>>();
    let receipts_bind_root_node = receipt_count > 0
        && receipt_root_node_ids.len() == 1
        && !receipt_failures
            .iter()
            .any(|failure| failure.contains("root_node") || failure.contains("missing_root_node"));
    let graph_counts_match = !receipt_failures.iter().any(|failure| {
        failure.starts_with("bundle_node_count_mismatch")
            || failure.starts_with("bundle_edge_count_mismatch")
            || failure.contains(":node_count")
            || failure.contains(":edge_count")
    });
    let receipt_ids_unique = !receipt_failures.iter().any(|failure| {
        failure.starts_with("duplicate_receipt_id:") || failure.contains(":missing_receipt_id")
    });
    let receipt_local_sequences = receipt_local_sequences.into_iter().collect::<Vec<_>>();
    let receipt_local_sequences_present = receipt_count > 0
        && !receipt_failures
            .iter()
            .any(|failure| failure.contains(":missing_receipt_local_sequence"));
    let receipt_local_sequences_unique = receipt_count > 0
        && receipt_local_sequences.len() == receipt_count
        && !receipt_failures
            .iter()
            .any(|failure| failure.starts_with("duplicate_receipt_local_sequence:"));
    let receipt_timestamps_parse = receipt_count > 0
        && !receipt_failures
            .iter()
            .any(|failure| failure.contains(":invalid_receipt_timestamp"));
    let receipt_chronology_consistent = receipt_timestamps_parse
        && receipt_local_sequences_unique
        && receipt_sequence_timestamps.len() == receipt_count
        && !receipt_failures
            .iter()
            .any(|failure| failure.starts_with("receipt_chronology_inversion:"));
    let receipt_signatures_valid = !receipt_failures
        .iter()
        .any(|failure| failure.contains("signature") || failure.contains("signer_public_key"));
    let receipt_signers_consistent =
        receipt_signer_public_keys.len() == 1 && receipt_signatures_valid;
    let receipts_bind_graph_slice = !receipt_failures.iter().any(|failure| {
        failure.contains(":graph_slice_mismatch")
            || failure.contains(":missing_graph_slice")
            || failure.contains(":graph_slice_evidence_mismatch")
            || failure.contains(":missing_graph_slice_evidence")
    });
    let receipts_bind_content_hash = matching_content_hash_receipts > 0
        && !receipt_failures
            .iter()
            .any(|failure| failure.contains("content_hash"));
    let verified = content_hash_matches
        && artifact_matches_bundle
        && artifact_byte_count_matches
        && receipts_bind_bundle_id
        && receipts_bind_actor
        && receipts_bind_policy
        && receipts_bind_sensor_state
        && receipts_bind_endpoint_decision
        && receipts_bind_endpoint_identity
        && receipts_bind_root_node
        && graph_counts_match
        && receipt_count > 0
        && receipt_ids_unique
        && receipt_local_sequences_present
        && receipt_local_sequences_unique
        && receipt_timestamps_parse
        && receipt_chronology_consistent
        && receipt_families_valid
        && receipt_family_cardinality_valid
        && required_receipt_families_present
        && receipt_signatures_valid
        && receipt_signers_consistent
        && receipts_bind_graph_slice
        && receipts_bind_content_hash;

    Ok(EdrEvidenceBundleArchiveVerification {
        verified,
        graph_content_hash,
        content_hash_matches,
        artifact_matches_bundle,
        artifact_byte_count_matches,
        receipts_bind_bundle_id,
        receipts_bind_actor,
        receipts_bind_policy,
        receipts_bind_sensor_state,
        receipts_bind_endpoint_decision,
        receipt_endpoint_ids,
        receipts_bind_endpoint_identity,
        receipt_root_node_ids,
        receipts_bind_root_node,
        graph_counts_match,
        receipt_count,
        receipt_ids_unique,
        receipt_local_sequences,
        receipt_local_sequences_present,
        receipt_local_sequences_unique,
        receipt_timestamps_parse,
        receipt_chronology_consistent,
        receipt_families_valid,
        present_receipt_families,
        receipt_family_counts,
        receipt_family_cardinality_valid,
        required_receipt_families,
        required_receipt_families_present,
        missing_required_receipt_families,
        receipt_signatures_valid,
        receipt_signers_consistent,
        receipts_bind_graph_slice,
        receipts_bind_content_hash,
        receipt_failure_count: receipt_failures.len(),
        receipt_failures,
    })
}

fn receipt_family_allows_multiple_archive_members(family: &str) -> bool {
    family == "response_execution"
}

fn push_archive_receipt_evidence_hash_failure(
    receipt_failures: &mut Vec<String>,
    receipt: &SignedReceipt,
    receipt_label: &str,
    key: &str,
    raw_value: &str,
    failure_key: &str,
) {
    let expected_hash = sha256(raw_value.as_bytes()).to_hex_prefixed();
    match receipt_evidence_hash_value(receipt, key) {
        Some(actual) if actual == expected_hash => {}
        Some(actual) => {
            receipt_failures.push(format!("{receipt_label}:{failure_key}_mismatch:{actual}"));
        }
        None => receipt_failures.push(format!("{receipt_label}:missing_{failure_key}")),
    }
}

fn push_archive_response_actor_failures(
    receipt_failures: &mut Vec<String>,
    response_actor_hashes: &mut Vec<(String, String)>,
    receipt: &SignedReceipt,
    receipt_label: &str,
    receipt_family: &str,
    required_hash_keys: &[&str],
) -> Result<()> {
    let actor = match receipt_endpoint_decision_actor(receipt) {
        Ok(actor) => actor,
        Err(reason) => {
            receipt_failures.push(format!("{receipt_label}:actor_decode_failed:{reason}"));
            return Ok(());
        }
    };
    let actor_hash = canonical_json_hash(&actor, "archive response receipt actor")?;
    response_actor_hashes.push((receipt_family.to_string(), actor_hash.clone()));
    for key in required_hash_keys {
        push_archive_receipt_evidence_hash_failure(
            receipt_failures,
            receipt,
            receipt_label,
            key,
            &actor_hash,
            &archive_actor_failure_key(key),
        );
    }
    Ok(())
}

fn push_archive_policy_failures(
    receipt_failures: &mut Vec<String>,
    policy_hashes: &mut Vec<(String, String)>,
    receipt: &SignedReceipt,
    receipt_label: &str,
    receipt_family: &str,
) -> Result<()> {
    let policy = match receipt_endpoint_decision_policy(receipt) {
        Ok(policy) => policy,
        Err(reason) => {
            receipt_failures.push(format!("{receipt_label}:policy_decode_failed:{reason}"));
            return Ok(());
        }
    };
    if policy.policy_version.trim().is_empty() {
        receipt_failures.push(format!("{receipt_label}:invalid_policy_version"));
    }
    if !policy.policy_hash.starts_with("0x") {
        receipt_failures.push(format!(
            "{receipt_label}:invalid_policy_hash:{}",
            policy.policy_hash
        ));
    }
    if policy.policy_epoch == 0 {
        receipt_failures.push(format!("{receipt_label}:invalid_policy_epoch"));
    }
    let policy_hash = canonical_json_hash(&policy, "archive receipt policy snapshot")?;
    policy_hashes.push((receipt_family.to_string(), policy_hash));
    Ok(())
}

fn push_archive_sensor_state_failures(
    receipt_failures: &mut Vec<String>,
    sensor_provider_sets: &mut Vec<(String, BTreeSet<String>)>,
    receipt: &SignedReceipt,
    receipt_label: &str,
    receipt_family: &str,
) -> Result<()> {
    let sensor_state = match receipt_endpoint_decision_sensor_state(receipt) {
        Ok(sensor_state) => sensor_state,
        Err(reason) => {
            receipt_failures.push(format!(
                "{receipt_label}:sensor_state_decode_failed:{reason}"
            ));
            return Ok(());
        }
    };
    if sensor_state.providers.is_empty() {
        receipt_failures.push(format!("{receipt_label}:sensor_state_missing_providers"));
    }
    let mut providers = BTreeSet::new();
    for provider in &sensor_state.providers {
        if provider.provider_id.trim().is_empty() {
            receipt_failures.push(format!("{receipt_label}:sensor_state_missing_provider_id"));
        } else {
            providers.insert(provider.provider_id.clone());
        }
    }
    sensor_provider_sets.push((receipt_family.to_string(), providers));
    Ok(())
}

fn archive_actor_failure_key(key: &str) -> String {
    let mut failure_key = String::new();
    for (index, ch) in key.chars().enumerate() {
        if ch.is_ascii_uppercase() {
            if index > 0 {
                failure_key.push('_');
            }
            failure_key.push(ch.to_ascii_lowercase());
        } else {
            failure_key.push(ch);
        }
    }
    failure_key
}

fn required_archive_receipt_families(bundle_id: &str) -> Option<Vec<&'static str>> {
    if bundle_id.starts_with("evidence_bundle:") {
        Some(vec![
            "response_request",
            "response_execution",
            "evidence_bundle_manifest",
        ])
    } else if bundle_id.starts_with("evidence_bundle-") {
        Some(vec!["graph_slice"])
    } else {
        None
    }
}

pub(crate) fn evidence_bundle_record(
    stored: StoredEndpointEvidenceBundle,
    now: chrono::DateTime<chrono::Utc>,
    protected_bundle_ids: &BTreeSet<String>,
) -> EdrEvidenceBundleRecord {
    let protected_by_active_response = protected_bundle_ids.contains(&stored.bundle.bundle_id);
    EdrEvidenceBundleRecord {
        age_seconds: evidence_bundle_age_seconds(&stored, now),
        bundle: stored.bundle,
        path: stored.path,
        byte_count: stored.byte_count,
        protected_by_active_response,
    }
}

pub(crate) fn evidence_bundle_age_seconds(
    stored: &StoredEndpointEvidenceBundle,
    now: chrono::DateTime<chrono::Utc>,
) -> u64 {
    now.signed_duration_since(stored.bundle.created_at)
        .num_seconds()
        .max(0) as u64
}

fn required_control_ack_field(
    field: &str,
    value: Option<&str>,
    max_len: usize,
) -> Result<String, (StatusCode, String)> {
    let value = non_empty(value).ok_or_else(|| {
        (
            StatusCode::BAD_REQUEST,
            format!("control response acknowledgement {field} is required"),
        )
    })?;
    if value.len() > max_len {
        return Err((
            StatusCode::BAD_REQUEST,
            format!("control response acknowledgement {field} must be at most {max_len} bytes"),
        ));
    }
    Ok(value.to_string())
}

fn optional_control_ack_field(
    field: &str,
    value: Option<&str>,
    max_len: usize,
) -> Result<Option<String>, (StatusCode, String)> {
    let Some(value) = non_empty(value) else {
        return Ok(None);
    };
    if value.len() > max_len {
        return Err((
            StatusCode::BAD_REQUEST,
            format!("control response acknowledgement {field} must be at most {max_len} bytes"),
        ));
    }
    Ok(Some(value.to_string()))
}

fn validate_control_ack_uuid(field: &str, value: &str) -> Result<(), (StatusCode, String)> {
    uuid::Uuid::parse_str(value).map(|_| ()).map_err(|_| {
        (
            StatusCode::BAD_REQUEST,
            format!("control response acknowledgement {field} must be a UUID"),
        )
    })
}

fn default_control_ack_status(status: &EndpointResponseExecutionStatus) -> &'static str {
    match status {
        EndpointResponseExecutionStatus::Failed
        | EndpointResponseExecutionStatus::RollbackFailed => "failed",
        EndpointResponseExecutionStatus::Expired => "expired",
        EndpointResponseExecutionStatus::RolledBack => "rolled_back",
        _ => "acknowledged",
    }
}

fn normalize_control_ack_status(
    status: Option<&str>,
    execution_status: &EndpointResponseExecutionStatus,
) -> Result<String, (StatusCode, String)> {
    let status = non_empty(status).unwrap_or_else(|| default_control_ack_status(execution_status));
    match status {
        "acknowledged" | "rejected" | "failed" | "expired" | "rolled_back" => {
            Ok(status.to_string())
        }
        _ => Err((
            StatusCode::BAD_REQUEST,
            format!(
                "unsupported control response acknowledgement status; allowed values: {EDR_CONTROL_ACK_STATUS_ALLOWLIST}"
            ),
        )),
    }
}

fn normalize_control_ack_target_kind(target_kind: &str) -> Result<String, (StatusCode, String)> {
    match target_kind {
        "endpoint" | "runtime" | "session" | "principal" | "grant" | "swarm" | "project" => {
            Ok(target_kind.to_string())
        }
        _ => Err((
            StatusCode::BAD_REQUEST,
            format!(
                "unsupported control response acknowledgement targetKind; allowed values: {EDR_CONTROL_ACK_TARGET_KIND_ALLOWLIST}"
            ),
        )),
    }
}

pub(crate) fn endpoint_response_control_correlation(
    input: Option<&EdrResponseControlAcknowledgementInput>,
    execution: &EndpointResponseExecutionReport,
) -> Result<Option<EndpointResponseControlCorrelation>, (StatusCode, String)> {
    let Some(input) = input else {
        return Ok(None);
    };

    let response_action_id =
        required_control_ack_field("responseActionId", input.response_action_id.as_deref(), 128)?;
    validate_control_ack_uuid("responseActionId", &response_action_id)?;
    let delivery_id = optional_control_ack_field("deliveryId", input.delivery_id.as_deref(), 128)?;
    if let Some(delivery_id) = delivery_id.as_deref() {
        validate_control_ack_uuid("deliveryId", delivery_id)?;
    }
    let target_kind = required_control_ack_field("targetKind", input.target_kind.as_deref(), 64)?;
    let target_kind = normalize_control_ack_target_kind(&target_kind)?;
    let target_id = required_control_ack_field("targetId", input.target_id.as_deref(), 256)?;
    let ack_token = required_control_ack_field("ackToken", input.ack_token.as_deref(), 1024)?;
    let ack_status = normalize_control_ack_status(input.status.as_deref(), &execution.status)?;
    let resulting_state =
        optional_control_ack_field("resultingState", input.resulting_state.as_deref(), 256)?
            .or_else(|| Some(execution.status.as_str().to_string()));

    Ok(Some(EndpointResponseControlCorrelation {
        response_action_id,
        delivery_id,
        target_kind,
        target_id,
        ack_token_hash: sha256(ack_token.as_bytes()).to_hex_prefixed(),
        ack_status,
        resulting_state,
    }))
}

fn control_api_ack_postback_url(
    control_api_url: &str,
    response_action_id: &str,
    route: ControlResponseAckPostbackRoute,
) -> Result<String, (StatusCode, String)> {
    let trimmed = control_api_url.trim().trim_end_matches('/');
    if trimmed.is_empty() {
        return Err((
            StatusCode::BAD_REQUEST,
            "control response acknowledgement controlApiUrl must not be empty".to_string(),
        ));
    }
    let parsed = reqwest::Url::parse(trimmed).map_err(|err| {
        (
            StatusCode::BAD_REQUEST,
            format!("control response acknowledgement controlApiUrl is invalid: {err}"),
        )
    })?;
    if !parsed.username().is_empty() || parsed.password().is_some() {
        return Err((
            StatusCode::BAD_REQUEST,
            "control response acknowledgement controlApiUrl must not contain userinfo".to_string(),
        ));
    }
    match parsed.scheme() {
        "https" => {}
        "http" if control_api_url_is_loopback(&parsed) => {}
        "http" => {
            return Err((
                StatusCode::BAD_REQUEST,
                "control response acknowledgement controlApiUrl may use http only for loopback hosts"
                    .to_string(),
            ));
        }
        other => {
            return Err((
                StatusCode::BAD_REQUEST,
                format!(
                    "control response acknowledgement controlApiUrl must use http or https, got {other}"
                ),
            ));
        }
    }
    Ok(format!(
        "{trimmed}/api/v1/response-actions/{response_action_id}/{}",
        route.path_segment()
    ))
}

fn control_api_url_is_loopback(url: &reqwest::Url) -> bool {
    let Some(host) = url.host_str() else {
        return false;
    };
    host.eq_ignore_ascii_case("localhost")
        || host
            .parse::<IpAddr>()
            .map(|addr| addr.is_loopback())
            .unwrap_or(false)
}

fn control_api_endpoint_archive_upload_url(
    control_api_url: &str,
) -> Result<String, (StatusCode, String)> {
    let trimmed = control_api_url.trim().trim_end_matches('/');
    if trimmed.is_empty() {
        return Err((
            StatusCode::BAD_REQUEST,
            "endpoint evidence archive controlApiUrl must not be empty".to_string(),
        ));
    }
    let parsed = reqwest::Url::parse(trimmed).map_err(|err| {
        (
            StatusCode::BAD_REQUEST,
            format!("endpoint evidence archive controlApiUrl is invalid: {err}"),
        )
    })?;
    if !parsed.username().is_empty() || parsed.password().is_some() {
        return Err((
            StatusCode::BAD_REQUEST,
            "endpoint evidence archive controlApiUrl must not contain userinfo".to_string(),
        ));
    }
    match parsed.scheme() {
        "https" => {}
        "http" if control_api_url_is_loopback(&parsed) => {}
        "http" => {
            return Err((
                StatusCode::BAD_REQUEST,
                "endpoint evidence archive controlApiUrl may use http only for loopback hosts"
                    .to_string(),
            ));
        }
        other => {
            return Err((
                StatusCode::BAD_REQUEST,
                format!(
                    "endpoint evidence archive controlApiUrl must use http or https, got {other}"
                ),
            ));
        }
    }
    Ok(format!("{trimmed}/api/v1/hunt/evidence-bundle-archives"))
}

pub(crate) fn control_api_receipt_batch_upload_url(
    control_api_url: &str,
) -> Result<String, (StatusCode, String)> {
    let trimmed = control_api_url.trim().trim_end_matches('/');
    if trimmed.is_empty() {
        return Err((
            StatusCode::BAD_REQUEST,
            "endpoint receipt upload control API URL must not be empty".to_string(),
        ));
    }
    let parsed = reqwest::Url::parse(trimmed).map_err(|err| {
        (
            StatusCode::BAD_REQUEST,
            format!("endpoint receipt upload control API URL is invalid: {err}"),
        )
    })?;
    if !parsed.username().is_empty() || parsed.password().is_some() {
        return Err((
            StatusCode::BAD_REQUEST,
            "endpoint receipt upload control API URL must not contain userinfo".to_string(),
        ));
    }
    match parsed.scheme() {
        "https" => {}
        "http" if control_api_url_is_loopback(&parsed) => {}
        "http" => {
            return Err((
                StatusCode::BAD_REQUEST,
                "endpoint receipt upload control API URL may use http only for loopback hosts"
                    .to_string(),
            ));
        }
        other => {
            return Err((
                StatusCode::BAD_REQUEST,
                format!(
                    "endpoint receipt upload control API URL must use http or https, got {other}"
                ),
            ));
        }
    }
    Ok(format!("{trimmed}/api/v1/receipts/batch"))
}

pub(crate) struct ControlReceiptUploadAttemptFailure {
    http_status: Option<u16>,
    response_hash: Option<String>,
    error_hash: Option<String>,
}

async fn enqueue_control_receipt_upload_retry(
    state: &AgentApiState,
    control_api_url: &str,
    receipt: &ControlStoreReceiptRequest,
    failure: ControlReceiptUploadAttemptFailure,
) -> Result<(String, chrono::DateTime<chrono::Utc>), (StatusCode, String)> {
    let receipt_hash = canonical_json_hash(
        &receipt.signed_receipt,
        "control receipt upload signed receipt",
    )
    .map_err(internal_error)?;
    let receipt_id = receipt
        .metadata
        .as_ref()
        .and_then(|metadata| metadata.get("receiptId"))
        .and_then(serde_json::Value::as_str)
        .map(str::to_string);
    let control_api_url = control_api_url.trim().trim_end_matches('/').to_string();
    let now = chrono::Utc::now();
    let attempt_count = 1;
    let retry_id = sha256(format!("{control_api_url}:{receipt_hash}").as_bytes()).to_hex_prefixed();
    let next_attempt_at =
        now + chrono::Duration::seconds(control_ack_retry_backoff_seconds(attempt_count));
    let retry = EndpointControlReceiptUploadRetry {
        retry_id: retry_id.clone(),
        control_api_url,
        receipt_id,
        receipt_hash,
        payload: receipt.clone(),
        attempt_count,
        next_attempt_at,
        last_attempt_at: Some(now),
        last_http_status: failure.http_status,
        last_response_hash: failure.response_hash,
        last_error_hash: failure.error_hash,
        created_at: now,
        updated_at: now,
    };
    state
        .edr_control_receipt_upload_retry_ledger
        .lock()
        .await
        .append(retry)
        .map_err(internal_error)?;
    Ok((retry_id, next_attempt_at))
}

async fn resolve_control_receipt_upload_api_key(
    state: &AgentApiState,
    retry: &EndpointControlReceiptUploadRetry,
) -> Option<String> {
    let settings = state.settings.read().await;
    let configured_url = settings
        .control_api
        .url
        .as_deref()
        .map(str::trim)
        .map(|url| url.trim_end_matches('/'));
    let retry_url = retry.control_api_url.trim().trim_end_matches('/');
    if settings.control_api.enabled && configured_url == Some(retry_url) {
        non_empty(settings.control_api.api_key.as_deref()).map(ToString::to_string)
    } else {
        None
    }
}

pub(crate) struct ControlReceiptUploadRetryAttemptOutcome {
    accepted: bool,
    http_status: Option<u16>,
    response_hash: Option<String>,
    error_hash: Option<String>,
}

async fn send_control_receipt_upload_retry(
    state: &AgentApiState,
    retry: &EndpointControlReceiptUploadRetry,
) -> ControlReceiptUploadRetryAttemptOutcome {
    if let Err((_status, message)) =
        require_cloud_mode_enrolled_receipt_signer(state, "endpoint receipt upload retry").await
    {
        let error = truncate_delivery_error(&message);
        return ControlReceiptUploadRetryAttemptOutcome {
            accepted: false,
            http_status: None,
            response_hash: None,
            error_hash: Some(sha256(error.as_bytes()).to_hex_prefixed()),
        };
    }
    let settings = state.settings.read().await.clone();
    if edr_receipt_signer_requires_enrollment(&settings) {
        let signer_public_key = {
            let ledger = state.edr_receipt_ledger.lock().await;
            ledger.signer_public_key.clone()
        };
        if retry.payload.public_key != signer_public_key {
            let error = truncate_delivery_error(
                "endpoint receipt upload retry payload is not signed by the current enrolled EDR signer",
            );
            return ControlReceiptUploadRetryAttemptOutcome {
                accepted: false,
                http_status: None,
                response_hash: None,
                error_hash: Some(sha256(error.as_bytes()).to_hex_prefixed()),
            };
        }
    }
    let Some(api_key) = resolve_control_receipt_upload_api_key(state, retry).await else {
        let error = truncate_delivery_error(
            "control API key is unavailable or URL no longer matches for endpoint receipt upload retry",
        );
        return ControlReceiptUploadRetryAttemptOutcome {
            accepted: false,
            http_status: None,
            response_hash: None,
            error_hash: Some(sha256(error.as_bytes()).to_hex_prefixed()),
        };
    };
    let url = match control_api_receipt_batch_upload_url(&retry.control_api_url) {
        Ok(url) => url,
        Err((_status, message)) => {
            let error = truncate_delivery_error(&message);
            return ControlReceiptUploadRetryAttemptOutcome {
                accepted: false,
                http_status: None,
                response_hash: None,
                error_hash: Some(sha256(error.as_bytes()).to_hex_prefixed()),
            };
        }
    };
    let payload = ControlBatchStoreReceiptsRequest {
        receipts: vec![retry.payload.clone()],
    };
    let response = match state
        .http_client
        .post(url)
        .header("x-api-key", api_key)
        .json(&payload)
        .timeout(EDR_CONTROL_RECEIPT_UPLOAD_REQUEST_TIMEOUT)
        .send()
        .await
    {
        Ok(response) => response,
        Err(err) => {
            let error = truncate_delivery_error(&err.to_string());
            return ControlReceiptUploadRetryAttemptOutcome {
                accepted: false,
                http_status: None,
                response_hash: None,
                error_hash: Some(sha256(error.as_bytes()).to_hex_prefixed()),
            };
        }
    };
    let status =
        StatusCode::from_u16(response.status().as_u16()).unwrap_or(StatusCode::BAD_GATEWAY);
    match response.bytes().await {
        Ok(bytes) => ControlReceiptUploadRetryAttemptOutcome {
            accepted: status.is_success(),
            http_status: Some(status.as_u16()),
            response_hash: Some(sha256(&bytes).to_hex_prefixed()),
            error_hash: None,
        },
        Err(err) => {
            let error = truncate_delivery_error(&err.to_string());
            ControlReceiptUploadRetryAttemptOutcome {
                accepted: false,
                http_status: Some(status.as_u16()),
                response_hash: None,
                error_hash: Some(sha256(error.as_bytes()).to_hex_prefixed()),
            }
        }
    }
}

async fn post_control_endpoint_receipts_best_effort(
    state: &AgentApiState,
    receipts: &[SignedReceipt],
    upload_path: &str,
) {
    if receipts.is_empty() {
        return;
    }
    let settings = state.settings.read().await.clone();
    if !settings.control_api.enabled {
        return;
    }
    if let Err((_status, err)) =
        require_cloud_mode_enrolled_receipt_signer(state, "automatic endpoint receipt upload").await
    {
        tracing::warn!(
            error = %err,
            upload_path,
            "Skipping automatic endpoint receipt upload because the EDR signer is not enrolled"
        );
        return;
    }
    if let Err((_status, err)) = require_cloud_mode_receipts_signed_by_current_signer(
        state,
        receipts,
        "automatic endpoint receipt upload",
    )
    .await
    {
        tracing::warn!(
            error = %err,
            upload_path,
            "Skipping automatic endpoint receipt upload because a receipt is not signed by the current enrolled signer"
        );
        return;
    }
    let Some(control_api_url) =
        non_empty(settings.control_api.url.as_deref()).map(ToString::to_string)
    else {
        return;
    };
    let Some(api_key) = non_empty(settings.control_api.api_key.as_deref()).map(ToString::to_string)
    else {
        return;
    };
    let url = match control_api_receipt_batch_upload_url(&control_api_url) {
        Ok(url) => url,
        Err((_status, err)) => {
            tracing::warn!(
                error = %err,
                upload_path,
                "Skipping automatic endpoint receipt upload because Control API URL is invalid"
            );
            return;
        }
    };
    let mut control_receipts = Vec::with_capacity(receipts.len());
    for receipt in receipts {
        match control_store_receipt_from_endpoint_receipt(receipt) {
            Ok(control_receipt) => control_receipts.push(control_receipt),
            Err(err) => {
                tracing::warn!(
                    error = %err,
                    receipt_id = receipt.receipt.receipt_id.as_deref().unwrap_or("<missing>"),
                    upload_path,
                    "Skipping invalid automatic endpoint receipt upload candidate"
                );
            }
        }
    }
    if control_receipts.is_empty() {
        return;
    }
    let payload = ControlBatchStoreReceiptsRequest {
        receipts: control_receipts.clone(),
    };
    let response = match state
        .http_client
        .post(url)
        .header("x-api-key", api_key)
        .json(&payload)
        .timeout(EDR_CONTROL_RECEIPT_UPLOAD_REQUEST_TIMEOUT)
        .send()
        .await
    {
        Ok(response) => response,
        Err(err) => {
            let error = truncate_delivery_error(&err.to_string());
            let error_hash = Some(sha256(error.as_bytes()).to_hex_prefixed());
            for receipt in &control_receipts {
                if let Err((_status, enqueue_err)) = enqueue_control_receipt_upload_retry(
                    state,
                    &control_api_url,
                    receipt,
                    ControlReceiptUploadAttemptFailure {
                        http_status: None,
                        response_hash: None,
                        error_hash: error_hash.clone(),
                    },
                )
                .await
                {
                    tracing::warn!(
                        error = %enqueue_err,
                        upload_path,
                        "Failed to queue automatic endpoint receipt upload retry"
                    );
                }
            }
            return;
        }
    };
    let status =
        StatusCode::from_u16(response.status().as_u16()).unwrap_or(StatusCode::BAD_GATEWAY);
    let response_hash = match response.bytes().await {
        Ok(bytes) => Some(sha256(&bytes).to_hex_prefixed()),
        Err(err) => Some(sha256(err.to_string().as_bytes()).to_hex_prefixed()),
    };
    if status.is_success() {
        tracing::debug!(
            count = control_receipts.len(),
            upload_path,
            "Uploaded endpoint receipts to Control API"
        );
        return;
    }
    for receipt in &control_receipts {
        if let Err((_status, enqueue_err)) = enqueue_control_receipt_upload_retry(
            state,
            &control_api_url,
            receipt,
            ControlReceiptUploadAttemptFailure {
                http_status: Some(status.as_u16()),
                response_hash: response_hash.clone(),
                error_hash: None,
            },
        )
        .await
        {
            tracing::warn!(
                error = %enqueue_err,
                upload_path,
                "Failed to queue automatic endpoint receipt upload retry"
            );
        }
    }
}

fn skipped_control_endpoint_archive_upload_report(
    control_api_url: Option<String>,
    raw_policy: EdrRawArtifactUploadPolicy,
    raw_artifact_approval: Option<&EdrRawArtifactApproval>,
    reason: impl Into<String>,
) -> EdrEvidenceBundleControlUploadReport {
    let reason = reason.into();
    let effective_raw_artifact_approval = raw_policy
        .allowed
        .then_some(raw_artifact_approval)
        .flatten();
    EdrEvidenceBundleControlUploadReport {
        control_api_url,
        attempted: false,
        accepted: false,
        raw_artifact_upload_allowed: raw_policy.allowed,
        raw_artifact_approval_required: raw_policy.allowed,
        raw_artifact_approval_provided: raw_artifact_approval.is_some(),
        raw_artifact_approval_id: effective_raw_artifact_approval
            .map(|approval| approval.approval_id.clone()),
        raw_artifact_approval_reason_hash: effective_raw_artifact_approval
            .map(|approval| approval.reason_hash.clone()),
        policy_source: raw_policy.source,
        skipped_reason: Some(reason.clone()),
        http_status: None,
        response_hash: None,
        error_hash: Some(sha256(reason.as_bytes()).to_hex_prefixed()),
        error: None,
        retry_queued: false,
        retry_id: None,
        next_retry_at: None,
    }
}

pub(crate) struct ControlArchiveUploadAttemptFailure {
    http_status: Option<u16>,
    response_hash: Option<String>,
    error_hash: Option<String>,
}

fn required_control_archive_retry_payload_string(
    payload: &serde_json::Value,
    key: &str,
) -> Result<String, (StatusCode, String)> {
    payload
        .get(key)
        .and_then(serde_json::Value::as_str)
        .and_then(|value| non_empty(Some(value)))
        .map(ToString::to_string)
        .ok_or_else(|| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("endpoint evidence archive retry payload is missing {key}"),
            )
        })
}

fn control_archive_retry_payload_has_raw_artifact_approval(payload: &serde_json::Value) -> bool {
    payload
        .get("rawArtifactApprovalId")
        .and_then(serde_json::Value::as_str)
        .and_then(|value| non_empty(Some(value)))
        .is_some()
        && payload
            .get("rawArtifactApprovalReasonHash")
            .and_then(serde_json::Value::as_str)
            .and_then(|value| non_empty(Some(value)))
            .is_some_and(|hash| hash.starts_with("0x"))
}

async fn enqueue_control_archive_upload_retry(
    state: &AgentApiState,
    control_api_url: &str,
    payload: serde_json::Value,
    failure: ControlArchiveUploadAttemptFailure,
) -> Result<(String, chrono::DateTime<chrono::Utc>), (StatusCode, String)> {
    let archive_id = required_control_archive_retry_payload_string(&payload, "archiveId")?;
    let archive_hash = required_control_archive_retry_payload_string(&payload, "archiveHash")?;
    let raw_ref = required_control_archive_retry_payload_string(&payload, "rawRef")?;
    let bundle_id = required_control_archive_retry_payload_string(&payload, "bundleId")?;
    let control_api_url = control_api_url.trim().trim_end_matches('/').to_string();
    let now = chrono::Utc::now();
    let attempt_count = 1;
    let retry_id =
        sha256(format!("{control_api_url}:{archive_id}:{archive_hash}:{raw_ref}").as_bytes())
            .to_hex_prefixed();
    let next_attempt_at =
        now + chrono::Duration::seconds(control_ack_retry_backoff_seconds(attempt_count));
    let retry = EndpointControlArchiveUploadRetry {
        retry_id: retry_id.clone(),
        control_api_url,
        archive_id,
        archive_hash,
        raw_ref,
        bundle_id,
        payload,
        attempt_count,
        next_attempt_at,
        last_attempt_at: Some(now),
        last_http_status: failure.http_status,
        last_response_hash: failure.response_hash,
        last_error_hash: failure.error_hash,
        created_at: now,
        updated_at: now,
    };
    state
        .edr_control_archive_upload_retry_ledger
        .lock()
        .await
        .append(retry)
        .map_err(internal_error)?;
    Ok((retry_id, next_attempt_at))
}

pub(crate) async fn post_control_endpoint_evidence_archive(
    state: &AgentApiState,
    archive_response: &EdrEvidenceBundleArchiveResponse,
    endpoint_agent_id: &str,
    event_id: &str,
    raw_ref: &str,
    upload_path: &str,
    raw_artifact_approval: Option<&EdrRawArtifactApproval>,
) -> Result<Option<EdrEvidenceBundleControlUploadReport>, (StatusCode, String)> {
    let settings = state.settings.read().await.clone();
    if !settings.control_api.enabled {
        return Ok(None);
    }
    require_cloud_mode_enrolled_receipt_signer(state, "raw endpoint evidence archive upload")
        .await?;
    require_cloud_mode_receipts_signed_by_current_signer(
        state,
        &archive_response.archive.receipts,
        "raw endpoint evidence archive upload",
    )
    .await?;

    let raw_policy = edr_raw_artifact_upload_policy(&settings).map_err(internal_error)?;
    let control_api_url = non_empty(settings.control_api.url.as_deref()).map(ToString::to_string);
    if !raw_policy.allowed {
        return Ok(Some(skipped_control_endpoint_archive_upload_report(
            control_api_url,
            raw_policy,
            raw_artifact_approval,
            "local policy does not allow raw endpoint evidence archive upload",
        )));
    }
    let Some(raw_artifact_approval) = raw_artifact_approval else {
        return Ok(Some(skipped_control_endpoint_archive_upload_report(
            control_api_url,
            raw_policy,
            None,
            "raw endpoint evidence archive upload requires rawArtifactApprovalId and rawArtifactApprovalReason",
        )));
    };
    let Some(control_api_url) = control_api_url else {
        return Ok(Some(skipped_control_endpoint_archive_upload_report(
            None,
            raw_policy,
            Some(raw_artifact_approval),
            "control API URL is not configured",
        )));
    };
    let Some(api_key) = non_empty(settings.control_api.api_key.as_deref()).map(ToString::to_string)
    else {
        return Ok(Some(skipped_control_endpoint_archive_upload_report(
            Some(control_api_url),
            raw_policy,
            Some(raw_artifact_approval),
            "control API key is not configured for raw endpoint evidence archive upload",
        )));
    };
    let url = control_api_endpoint_archive_upload_url(&control_api_url)?;
    let payload = serde_json::json!({
        "archiveId": archive_response.archive_id,
        "archiveHash": archive_response.archive_hash,
        "rawRef": raw_ref,
        "bundleId": archive_response.archive.bundle.bundle_id,
        "endpointAgentId": endpoint_agent_id,
        "eventId": event_id,
        "rawArtifactApprovalId": raw_artifact_approval.approval_id.as_str(),
        "rawArtifactApprovalReasonHash": raw_artifact_approval.reason_hash.as_str(),
        "archive": archive_response.archive,
        "verification": archive_response.verification,
        "metadata": {
            "source": "clawdstrike-agent",
            "uploadPath": upload_path,
            "generatedAt": archive_response.generated_at,
            "receiptCount": archive_response.receipt_count,
            "rawArtifactApprovalId": raw_artifact_approval.approval_id.as_str(),
            "rawArtifactApprovalReasonHash": raw_artifact_approval.reason_hash.as_str(),
        }
    });

    let response = match state
        .http_client
        .post(url)
        .header("x-api-key", api_key)
        .json(&payload)
        .send()
        .await
    {
        Ok(response) => response,
        Err(err) => {
            let error = truncate_delivery_error(&err.to_string());
            let error_hash = Some(sha256(error.as_bytes()).to_hex_prefixed());
            let (retry_id, next_retry_at) = enqueue_control_archive_upload_retry(
                state,
                &control_api_url,
                payload,
                ControlArchiveUploadAttemptFailure {
                    http_status: None,
                    response_hash: None,
                    error_hash: error_hash.clone(),
                },
            )
            .await?;
            return Ok(Some(EdrEvidenceBundleControlUploadReport {
                control_api_url: Some(control_api_url),
                attempted: true,
                accepted: false,
                raw_artifact_upload_allowed: raw_policy.allowed,
                raw_artifact_approval_required: true,
                raw_artifact_approval_provided: true,
                raw_artifact_approval_id: Some(raw_artifact_approval.approval_id.clone()),
                raw_artifact_approval_reason_hash: Some(raw_artifact_approval.reason_hash.clone()),
                policy_source: raw_policy.source,
                skipped_reason: None,
                http_status: None,
                response_hash: None,
                error_hash,
                error: Some(error),
                retry_queued: true,
                retry_id: Some(retry_id),
                next_retry_at: Some(next_retry_at),
            }));
        }
    };
    let status =
        StatusCode::from_u16(response.status().as_u16()).unwrap_or(StatusCode::BAD_GATEWAY);
    let (response_hash, error_hash, error) = match response.bytes().await {
        Ok(bytes) => (Some(sha256(&bytes).to_hex_prefixed()), None, None),
        Err(err) => {
            let error = truncate_delivery_error(&format!(
                "endpoint evidence archive upload response body read failed: {err}"
            ));
            (
                None,
                Some(sha256(error.as_bytes()).to_hex_prefixed()),
                Some(error),
            )
        }
    };
    let (retry_queued, retry_id, next_retry_at) = if status.is_success() {
        (false, None, None)
    } else {
        let (retry_id, next_retry_at) = enqueue_control_archive_upload_retry(
            state,
            &control_api_url,
            payload,
            ControlArchiveUploadAttemptFailure {
                http_status: Some(status.as_u16()),
                response_hash: response_hash.clone(),
                error_hash: error_hash.clone(),
            },
        )
        .await?;
        (true, Some(retry_id), Some(next_retry_at))
    };
    Ok(Some(EdrEvidenceBundleControlUploadReport {
        control_api_url: Some(control_api_url),
        attempted: true,
        accepted: status.is_success(),
        raw_artifact_upload_allowed: raw_policy.allowed,
        raw_artifact_approval_required: true,
        raw_artifact_approval_provided: true,
        raw_artifact_approval_id: Some(raw_artifact_approval.approval_id.clone()),
        raw_artifact_approval_reason_hash: Some(raw_artifact_approval.reason_hash.clone()),
        policy_source: raw_policy.source,
        skipped_reason: None,
        http_status: Some(status.as_u16()),
        response_hash,
        error_hash,
        error,
        retry_queued,
        retry_id,
        next_retry_at,
    }))
}

async fn resolve_control_archive_upload_retry_api_key(
    state: &AgentApiState,
    retry: &EndpointControlArchiveUploadRetry,
) -> Option<String> {
    let settings = state.settings.read().await;
    let configured_url = settings
        .control_api
        .url
        .as_deref()
        .map(str::trim)
        .map(|url| url.trim_end_matches('/'));
    let retry_url = retry.control_api_url.trim().trim_end_matches('/');
    if settings.control_api.enabled && configured_url == Some(retry_url) {
        non_empty(settings.control_api.api_key.as_deref()).map(ToString::to_string)
    } else {
        None
    }
}

pub(crate) struct ControlArchiveUploadRetryAttemptOutcome {
    pub(crate) accepted: bool,
    pub(crate) http_status: Option<u16>,
    pub(crate) response_hash: Option<String>,
    pub(crate) error_hash: Option<String>,
}

pub(crate) async fn send_control_archive_upload_retry(
    state: &AgentApiState,
    retry: &EndpointControlArchiveUploadRetry,
) -> ControlArchiveUploadRetryAttemptOutcome {
    if let Err((_status, message)) =
        require_cloud_mode_enrolled_receipt_signer(state, "raw endpoint evidence archive retry")
            .await
    {
        let error = truncate_delivery_error(&message);
        return ControlArchiveUploadRetryAttemptOutcome {
            accepted: false,
            http_status: None,
            response_hash: None,
            error_hash: Some(sha256(error.as_bytes()).to_hex_prefixed()),
        };
    }
    if let Some(receipts_value) = retry
        .payload
        .get("archive")
        .and_then(|archive| archive.get("receipts"))
    {
        let receipts = match serde_json::from_value::<Vec<SignedReceipt>>(receipts_value.clone()) {
            Ok(receipts) => receipts,
            Err(err) => {
                let error = truncate_delivery_error(&format!(
                    "raw endpoint evidence archive retry payload receipts are invalid: {err}"
                ));
                return ControlArchiveUploadRetryAttemptOutcome {
                    accepted: false,
                    http_status: None,
                    response_hash: None,
                    error_hash: Some(sha256(error.as_bytes()).to_hex_prefixed()),
                };
            }
        };
        if let Err((_status, message)) = require_cloud_mode_receipts_signed_by_current_signer(
            state,
            &receipts,
            "raw endpoint evidence archive retry",
        )
        .await
        {
            let error = truncate_delivery_error(&message);
            return ControlArchiveUploadRetryAttemptOutcome {
                accepted: false,
                http_status: None,
                response_hash: None,
                error_hash: Some(sha256(error.as_bytes()).to_hex_prefixed()),
            };
        }
    }
    if !control_archive_retry_payload_has_raw_artifact_approval(&retry.payload) {
        let error = truncate_delivery_error(
            "raw endpoint evidence archive retry payload is missing raw artifact approval evidence",
        );
        return ControlArchiveUploadRetryAttemptOutcome {
            accepted: false,
            http_status: None,
            response_hash: None,
            error_hash: Some(sha256(error.as_bytes()).to_hex_prefixed()),
        };
    }
    let Some(api_key) = resolve_control_archive_upload_retry_api_key(state, retry).await else {
        let error = truncate_delivery_error(
            "control API key is unavailable or URL no longer matches for raw endpoint evidence archive retry",
        );
        return ControlArchiveUploadRetryAttemptOutcome {
            accepted: false,
            http_status: None,
            response_hash: None,
            error_hash: Some(sha256(error.as_bytes()).to_hex_prefixed()),
        };
    };
    let url = match control_api_endpoint_archive_upload_url(&retry.control_api_url) {
        Ok(url) => url,
        Err((_status, message)) => {
            let error = truncate_delivery_error(&message);
            return ControlArchiveUploadRetryAttemptOutcome {
                accepted: false,
                http_status: None,
                response_hash: None,
                error_hash: Some(sha256(error.as_bytes()).to_hex_prefixed()),
            };
        }
    };
    let response = match state
        .http_client
        .post(url)
        .header("x-api-key", api_key)
        .json(&retry.payload)
        .send()
        .await
    {
        Ok(response) => response,
        Err(err) => {
            let error = truncate_delivery_error(&err.to_string());
            return ControlArchiveUploadRetryAttemptOutcome {
                accepted: false,
                http_status: None,
                response_hash: None,
                error_hash: Some(sha256(error.as_bytes()).to_hex_prefixed()),
            };
        }
    };
    let status =
        StatusCode::from_u16(response.status().as_u16()).unwrap_or(StatusCode::BAD_GATEWAY);
    match response.bytes().await {
        Ok(bytes) => ControlArchiveUploadRetryAttemptOutcome {
            accepted: status.is_success(),
            http_status: Some(status.as_u16()),
            response_hash: Some(sha256(&bytes).to_hex_prefixed()),
            error_hash: None,
        },
        Err(err) => {
            let error = truncate_delivery_error(&err.to_string());
            ControlArchiveUploadRetryAttemptOutcome {
                accepted: false,
                http_status: Some(status.as_u16()),
                response_hash: None,
                error_hash: Some(sha256(error.as_bytes()).to_hex_prefixed()),
            }
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum ControlResponseAckPostbackRoute {
    AuthenticatedAcks,
    AgentAcks,
}

impl ControlResponseAckPostbackRoute {
    fn path_segment(self) -> &'static str {
        match self {
            Self::AuthenticatedAcks => "acks",
            Self::AgentAcks => "agent-acks",
        }
    }
}

pub(crate) struct ControlResponseAckPostbackConfig {
    control_api_url: String,
    api_key: Option<String>,
    route: ControlResponseAckPostbackRoute,
}

async fn resolve_control_response_ack_postback_config(
    state: &AgentApiState,
    input: &EdrResponseControlAcknowledgementInput,
) -> Result<Option<ControlResponseAckPostbackConfig>, (StatusCode, String)> {
    let explicit_url = non_empty(input.control_api_url.as_deref()).map(ToString::to_string);
    let explicit_api_key = non_empty(input.control_api_token.as_deref()).map(ToString::to_string);

    if let Some(control_api_url) = explicit_url {
        let configured_api_key = {
            let settings = state.settings.read().await;
            if settings.control_api.enabled {
                non_empty(settings.control_api.api_key.as_deref()).map(ToString::to_string)
            } else {
                None
            }
        };
        let api_key = explicit_api_key.or(configured_api_key);
        return Ok(Some(ControlResponseAckPostbackConfig {
            control_api_url,
            route: if api_key.is_some() {
                ControlResponseAckPostbackRoute::AuthenticatedAcks
            } else {
                ControlResponseAckPostbackRoute::AgentAcks
            },
            api_key,
        }));
    }

    let settings = state.settings.read().await;
    if !settings.control_api.enabled {
        return Ok(None);
    }
    let Some(control_api_url) =
        non_empty(settings.control_api.url.as_deref()).map(ToString::to_string)
    else {
        return Ok(None);
    };
    let Some(api_key) = non_empty(settings.control_api.api_key.as_deref()).map(ToString::to_string)
    else {
        return Ok(Some(ControlResponseAckPostbackConfig {
            control_api_url,
            api_key: None,
            route: ControlResponseAckPostbackRoute::AgentAcks,
        }));
    };
    Ok(Some(ControlResponseAckPostbackConfig {
        control_api_url,
        api_key: Some(api_key),
        route: ControlResponseAckPostbackRoute::AuthenticatedAcks,
    }))
}

pub(crate) fn control_ack_retry_backoff_seconds(attempt_count: u32) -> i64 {
    let exponent = attempt_count.saturating_sub(1).min(4);
    let multiplier = 1_i64.checked_shl(exponent).unwrap_or(16);
    EDR_CONTROL_ACK_RETRY_INITIAL_BACKOFF_SECONDS
        .saturating_mul(multiplier)
        .min(EDR_CONTROL_ACK_RETRY_MAX_BACKOFF_SECONDS)
}

pub(crate) struct ControlAckPostbackPayloadInput<'a> {
    target_kind: &'a str,
    target_id: &'a str,
    ack_token: &'a str,
    status: &'a str,
    observed_at: chrono::DateTime<chrono::Utc>,
    message: Option<&'a str>,
    resulting_state: Option<&'a str>,
    raw_payload: serde_json::Value,
}

fn control_ack_postback_payload(input: ControlAckPostbackPayloadInput<'_>) -> serde_json::Value {
    serde_json::json!({
        "targetKind": input.target_kind,
        "targetId": input.target_id,
        "ackToken": input.ack_token,
        "status": input.status,
        "observedAt": input.observed_at,
        "message": input.message,
        "resultingState": input.resulting_state,
        "rawPayload": input.raw_payload,
    })
}

pub(crate) struct ControlAckPostbackRetryEnqueueInput<'a> {
    postback_config: &'a ControlResponseAckPostbackConfig,
    response_action_id: &'a str,
    ack_token: &'a str,
    acknowledgement: &'a EndpointResponseAcknowledgementReport,
    control: &'a EndpointResponseControlCorrelation,
    raw_payload: serde_json::Value,
    failure: ControlAckPostbackAttemptFailure,
}

async fn enqueue_control_ack_postback_retry(
    state: &AgentApiState,
    input: ControlAckPostbackRetryEnqueueInput<'_>,
) -> Result<(String, chrono::DateTime<chrono::Utc>), (StatusCode, String)> {
    let now = chrono::Utc::now();
    let attempt_count = 1;
    let retry_id = sha256(
        format!(
            "{}:{}:{}:{}:{}",
            input.acknowledgement.acknowledgement_id,
            input.response_action_id,
            input.control.target_kind,
            input.control.target_id,
            input.control.ack_token_hash
        )
        .as_bytes(),
    )
    .to_hex_prefixed();
    let next_attempt_at =
        now + chrono::Duration::seconds(control_ack_retry_backoff_seconds(attempt_count));
    let retry = EndpointControlAckPostbackRetry {
        retry_id: retry_id.clone(),
        response_action_id: input.response_action_id.to_string(),
        control_api_url: input.postback_config.control_api_url.clone(),
        preferred_route: input.postback_config.route,
        target_kind: input.control.target_kind.clone(),
        target_id: input.control.target_id.clone(),
        ack_token: input.ack_token.to_string(),
        ack_token_hash: input.control.ack_token_hash.clone(),
        status: input.control.ack_status.clone(),
        observed_at: input.acknowledgement.acknowledged_at,
        message: input.acknowledgement.note.clone(),
        resulting_state: input.control.resulting_state.clone(),
        raw_payload: input.raw_payload,
        attempt_count,
        next_attempt_at,
        last_attempt_at: Some(now),
        last_http_status: input.failure.http_status,
        last_response_hash: input.failure.response_hash,
        last_error_hash: input.failure.error_hash,
        created_at: now,
        updated_at: now,
    };
    state
        .edr_control_ack_postback_retry_ledger
        .lock()
        .await
        .append(retry)
        .map_err(internal_error)?;
    Ok((retry_id, next_attempt_at))
}

impl ControlAckPostbackRetrySink {
    pub async fn sign_response_acknowledgement_receipt(
        &self,
        acknowledgement: &EndpointResponseAcknowledgementReport,
    ) -> Result<SignedReceipt> {
        append_edr_response_acknowledgement(&self.state, acknowledgement)
            .await
            .map_err(|(status, message)| {
                anyhow::anyhow!(
                    "append response acknowledgement ledger entry failed with HTTP {}: {}",
                    status.as_u16(),
                    message
                )
            })?;
        let graph = CausalGraph::default();
        emit_edr_response_acknowledgement_receipt(&self.state, acknowledgement, &graph).await
    }

    pub async fn enqueue(&self, input: ControlAckPostbackRetryRequest) -> Result<()> {
        let now = chrono::Utc::now();
        let attempt_count = 1;
        let ack_token_hash = sha256(input.ack_token.as_bytes()).to_hex_prefixed();
        let retry_id = sha256(
            format!(
                "{}:{}:{}:{}",
                input.response_action_id, input.target_kind, input.target_id, ack_token_hash
            )
            .as_bytes(),
        )
        .to_hex_prefixed();
        let next_attempt_at =
            now + chrono::Duration::seconds(control_ack_retry_backoff_seconds(attempt_count));
        let failure = truncate_delivery_error(&input.failure_message);
        let retry = EndpointControlAckPostbackRetry {
            retry_id: retry_id.clone(),
            response_action_id: input.response_action_id,
            control_api_url: input
                .control_api_url
                .trim()
                .trim_end_matches('/')
                .to_string(),
            preferred_route: if input.use_authenticated_route {
                ControlResponseAckPostbackRoute::AuthenticatedAcks
            } else {
                ControlResponseAckPostbackRoute::AgentAcks
            },
            target_kind: input.target_kind,
            target_id: input.target_id,
            ack_token: input.ack_token,
            ack_token_hash,
            status: input.status,
            observed_at: input.observed_at,
            message: input.message,
            resulting_state: input.resulting_state,
            raw_payload: input.raw_payload,
            attempt_count,
            next_attempt_at,
            last_attempt_at: Some(now),
            last_http_status: None,
            last_response_hash: None,
            last_error_hash: Some(sha256(failure.as_bytes()).to_hex_prefixed()),
            created_at: now,
            updated_at: now,
        };
        self.state
            .edr_control_ack_postback_retry_ledger
            .lock()
            .await
            .append(retry)?;
        Ok(())
    }
}

pub(crate) struct ControlAckPostbackAttemptFailure {
    http_status: Option<u16>,
    response_hash: Option<String>,
    error_hash: Option<String>,
}

pub(crate) struct ControlAckPostbackRetryAttemptOutcome {
    route: ControlResponseAckPostbackRoute,
    accepted: bool,
    http_status: Option<u16>,
    response_hash: Option<String>,
    error_hash: Option<String>,
}

async fn resolve_control_ack_retry_route(
    state: &AgentApiState,
    retry: &EndpointControlAckPostbackRetry,
) -> (ControlResponseAckPostbackRoute, Option<String>) {
    let settings = state.settings.read().await;
    let configured_url = settings
        .control_api
        .url
        .as_deref()
        .map(str::trim)
        .map(|url| url.trim_end_matches('/'));
    let retry_url = retry.control_api_url.trim().trim_end_matches('/');
    if settings.control_api.enabled && configured_url == Some(retry_url) {
        if let Some(api_key) = non_empty(settings.control_api.api_key.as_deref()) {
            return (
                ControlResponseAckPostbackRoute::AuthenticatedAcks,
                Some(api_key.to_string()),
            );
        }
    }
    (ControlResponseAckPostbackRoute::AgentAcks, None)
}

async fn send_control_ack_postback_retry(
    state: &AgentApiState,
    retry: &EndpointControlAckPostbackRetry,
) -> ControlAckPostbackRetryAttemptOutcome {
    let (route, api_key) = resolve_control_ack_retry_route(state, retry).await;
    let url = match control_api_ack_postback_url(
        &retry.control_api_url,
        &retry.response_action_id,
        route,
    ) {
        Ok(url) => url,
        Err((_status, message)) => {
            let error = truncate_delivery_error(&message);
            return ControlAckPostbackRetryAttemptOutcome {
                route,
                accepted: false,
                http_status: None,
                response_hash: None,
                error_hash: Some(sha256(error.as_bytes()).to_hex_prefixed()),
            };
        }
    };
    let payload = control_ack_postback_payload(ControlAckPostbackPayloadInput {
        target_kind: &retry.target_kind,
        target_id: &retry.target_id,
        ack_token: &retry.ack_token,
        status: &retry.status,
        observed_at: retry.observed_at,
        message: retry.message.as_deref(),
        resulting_state: retry.resulting_state.as_deref(),
        raw_payload: retry.raw_payload.clone(),
    });
    let mut request = state.http_client.post(&url).json(&payload);
    if let Some(api_key) = api_key {
        request = request.header("x-api-key", api_key);
    }
    let response = match request.send().await {
        Ok(response) => response,
        Err(err) => {
            let error = truncate_delivery_error(&err.to_string());
            return ControlAckPostbackRetryAttemptOutcome {
                route,
                accepted: false,
                http_status: None,
                response_hash: None,
                error_hash: Some(sha256(error.as_bytes()).to_hex_prefixed()),
            };
        }
    };
    let status =
        StatusCode::from_u16(response.status().as_u16()).unwrap_or(StatusCode::BAD_GATEWAY);
    let bytes = match response.bytes().await {
        Ok(bytes) => bytes,
        Err(err) => {
            let error = truncate_delivery_error(&err.to_string());
            return ControlAckPostbackRetryAttemptOutcome {
                route,
                accepted: false,
                http_status: Some(status.as_u16()),
                response_hash: None,
                error_hash: Some(sha256(error.as_bytes()).to_hex_prefixed()),
            };
        }
    };
    ControlAckPostbackRetryAttemptOutcome {
        route,
        accepted: status.is_success(),
        http_status: Some(status.as_u16()),
        response_hash: Some(sha256(&bytes).to_hex_prefixed()),
        error_hash: None,
    }
}

pub(crate) async fn post_control_response_acknowledgement(
    state: &AgentApiState,
    input: &EdrResponseControlAcknowledgementInput,
    acknowledgement: &EndpointResponseAcknowledgementReport,
    receipt: &SignedReceipt,
) -> Result<Option<EdrResponseControlPostbackReport>, (StatusCode, String)> {
    let Some(postback_config) = resolve_control_response_ack_postback_config(state, input).await?
    else {
        return Ok(None);
    };
    let response_action_id =
        required_control_ack_field("responseActionId", input.response_action_id.as_deref(), 128)?;
    validate_control_ack_uuid("responseActionId", &response_action_id)?;
    let ack_token = required_control_ack_field("ackToken", input.ack_token.as_deref(), 1024)?;
    let url = control_api_ack_postback_url(
        &postback_config.control_api_url,
        &response_action_id,
        postback_config.route,
    )?;
    let control = acknowledgement
        .control_correlation
        .as_ref()
        .ok_or_else(|| {
            (
                StatusCode::BAD_REQUEST,
                "control response acknowledgement correlation is required for postback".to_string(),
            )
        })?;
    let local_receipt_hash =
        canonical_json_hash(receipt, "response acknowledgement control postback receipt")
            .map_err(internal_error)?;
    let raw_payload = serde_json::json!({
        "source": "clawdstrike-agent",
        "localAcknowledgementId": acknowledgement.acknowledgement_id,
        "localExecutionId": acknowledgement.execution_id,
        "localActionId": acknowledgement.action_id,
        "localGraphSliceId": acknowledgement.graph_slice_id,
        "localReceiptHash": local_receipt_hash,
        "signedReceipt": receipt,
        "localEffectCount": acknowledgement.effects.len(),
    });
    let payload = control_ack_postback_payload(ControlAckPostbackPayloadInput {
        target_kind: &control.target_kind,
        target_id: &control.target_id,
        ack_token: &ack_token,
        status: &control.ack_status,
        observed_at: acknowledgement.acknowledged_at,
        message: acknowledgement.note.as_deref(),
        resulting_state: control.resulting_state.as_deref(),
        raw_payload: raw_payload.clone(),
    });

    let mut request = state.http_client.post(&url).json(&payload);
    if let Some(api_key) = postback_config.api_key.as_deref() {
        request = request.header("x-api-key", api_key);
    }
    let response = match request.send().await {
        Ok(response) => response,
        Err(err) => {
            let error = truncate_delivery_error(&err.to_string());
            let error_hash = sha256(error.as_bytes()).to_hex_prefixed();
            let (retry_id, next_retry_at) = enqueue_control_ack_postback_retry(
                state,
                ControlAckPostbackRetryEnqueueInput {
                    postback_config: &postback_config,
                    response_action_id: &response_action_id,
                    ack_token: &ack_token,
                    acknowledgement,
                    control,
                    raw_payload,
                    failure: ControlAckPostbackAttemptFailure {
                        http_status: None,
                        response_hash: None,
                        error_hash: Some(error_hash.clone()),
                    },
                },
            )
            .await?;
            return Ok(Some(EdrResponseControlPostbackReport {
                control_api_url: postback_config.control_api_url,
                response_action_id,
                accepted: false,
                retry_queued: true,
                retry_id: Some(retry_id),
                next_retry_at: Some(next_retry_at),
                http_status: None,
                response_hash: None,
                error_hash: Some(error_hash),
                error: Some(error),
            }));
        }
    };
    let status =
        StatusCode::from_u16(response.status().as_u16()).unwrap_or(StatusCode::BAD_GATEWAY);
    let bytes = response.bytes().await.map_err(|err| {
        (
            StatusCode::BAD_GATEWAY,
            format!("control response acknowledgement postback body read failed: {err}"),
        )
    })?;
    let response_hash = sha256(&bytes).to_hex_prefixed();
    let (retry_queued, retry_id, next_retry_at) = if status.is_success() {
        (false, None, None)
    } else {
        let (retry_id, next_retry_at) = enqueue_control_ack_postback_retry(
            state,
            ControlAckPostbackRetryEnqueueInput {
                postback_config: &postback_config,
                response_action_id: &response_action_id,
                ack_token: &ack_token,
                acknowledgement,
                control,
                raw_payload,
                failure: ControlAckPostbackAttemptFailure {
                    http_status: Some(status.as_u16()),
                    response_hash: Some(response_hash.clone()),
                    error_hash: None,
                },
            },
        )
        .await?;
        (true, Some(retry_id), Some(next_retry_at))
    };
    Ok(Some(EdrResponseControlPostbackReport {
        control_api_url: postback_config.control_api_url,
        response_action_id,
        accepted: status.is_success(),
        retry_queued,
        retry_id,
        next_retry_at,
        http_status: Some(status.as_u16()),
        response_hash: Some(response_hash),
        error_hash: None,
        error: None,
    }))
}

pub(crate) async fn local_endpoint_agent_id(state: &AgentApiState) -> String {
    let mut settings = state.settings.write().await;
    resolve_effective_endpoint_agent_id(&mut settings, None)
}

pub(crate) async fn control_archive_backfill_bundle_ids(
    state: &AgentApiState,
    input: &EdrControlArchiveUploadBackfillInput,
    limit: usize,
) -> Result<Vec<String>, (StatusCode, String)> {
    if let Some(bundle_id) = input.bundle_id.as_deref() {
        let bundle_id = bundle_id.trim();
        if bundle_id.is_empty() {
            return Err((
                StatusCode::BAD_REQUEST,
                "bundleId must not be empty when provided".to_string(),
            ));
        }
        return Ok(vec![bundle_id.to_string()]);
    }

    let mut store = state.edr_evidence_bundle_store.lock().await;
    let bundles = store.list().map_err(internal_error)?;
    Ok(bundles
        .into_iter()
        .take(limit)
        .map(|stored| stored.bundle.bundle_id)
        .collect())
}

pub(crate) async fn drain_control_receipt_upload_retries(
    state: &Arc<AgentApiState>,
    limit: usize,
    force: bool,
) -> Result<EdrControlReceiptUploadRetryResponse, (StatusCode, String)> {
    let limit = limit.clamp(1, 100);
    let now = chrono::Utc::now();
    let (path, pending_before, due) = {
        let ledger = state.edr_control_receipt_upload_retry_ledger.lock().await;
        (
            ledger.path().map(|path| path.display().to_string()),
            ledger.pending_count(),
            ledger.due(now, limit, force),
        )
    };

    let mut attempts = Vec::new();
    let mut delivered = 0usize;
    let mut failed = 0usize;
    for retry in due {
        let outcome = send_control_receipt_upload_retry(state, &retry).await;
        let attempted_count = retry.attempt_count.saturating_add(1);
        if outcome.accepted {
            delivered += 1;
            let mut ledger = state.edr_control_receipt_upload_retry_ledger.lock().await;
            ledger
                .mark_delivered(&retry.retry_id)
                .map_err(internal_error)?;
            attempts.push(EdrControlReceiptUploadRetryAttemptRecord {
                retry_id: retry.retry_id,
                receipt_id: retry.receipt_id,
                receipt_hash: retry.receipt_hash,
                control_api_url: retry.control_api_url,
                delivered: true,
                attempt_count: attempted_count,
                next_attempt_at: None,
                http_status: outcome.http_status,
                response_hash: outcome.response_hash,
                error_hash: outcome.error_hash,
            });
        } else {
            failed += 1;
            let mut ledger = state.edr_control_receipt_upload_retry_ledger.lock().await;
            let updated = ledger
                .mark_failed(
                    &retry.retry_id,
                    chrono::Utc::now(),
                    outcome.http_status,
                    outcome.response_hash.clone(),
                    outcome.error_hash.clone(),
                )
                .map_err(internal_error)?
                .unwrap_or_else(|| retry.clone());
            attempts.push(EdrControlReceiptUploadRetryAttemptRecord {
                retry_id: retry.retry_id,
                receipt_id: retry.receipt_id,
                receipt_hash: retry.receipt_hash,
                control_api_url: retry.control_api_url,
                delivered: false,
                attempt_count: updated.attempt_count,
                next_attempt_at: Some(updated.next_attempt_at),
                http_status: outcome.http_status,
                response_hash: outcome.response_hash,
                error_hash: outcome.error_hash,
            });
        }
    }

    let pending = state
        .edr_control_receipt_upload_retry_ledger
        .lock()
        .await
        .pending_count();
    Ok(EdrControlReceiptUploadRetryResponse {
        path,
        attempted: attempts.len(),
        delivered,
        failed,
        skipped: pending_before.saturating_sub(attempts.len()),
        pending,
        attempts,
    })
}

pub(crate) async fn drain_control_ack_postback_retries(
    state: &Arc<AgentApiState>,
    limit: usize,
    force: bool,
) -> Result<EdrControlAckPostbackRetryResponse, (StatusCode, String)> {
    let limit = limit.clamp(1, 100);
    let now = chrono::Utc::now();
    let (path, pending_before, due) = {
        let ledger = state.edr_control_ack_postback_retry_ledger.lock().await;
        (
            ledger.path().map(|path| path.display().to_string()),
            ledger.pending_count(),
            ledger.due(now, limit, force),
        )
    };

    let mut attempts = Vec::new();
    let mut delivered = 0usize;
    let mut failed = 0usize;
    for retry in due {
        let outcome = send_control_ack_postback_retry(state, &retry).await;
        let attempted_count = retry.attempt_count.saturating_add(1);
        if outcome.accepted {
            delivered += 1;
            let mut ledger = state.edr_control_ack_postback_retry_ledger.lock().await;
            ledger
                .mark_delivered(&retry.retry_id)
                .map_err(internal_error)?;
            attempts.push(EdrControlAckPostbackRetryAttemptRecord {
                retry_id: retry.retry_id,
                response_action_id: retry.response_action_id,
                control_api_url: retry.control_api_url,
                route: outcome.route,
                delivered: true,
                attempt_count: attempted_count,
                next_attempt_at: None,
                http_status: outcome.http_status,
                response_hash: outcome.response_hash,
                error_hash: outcome.error_hash,
            });
        } else {
            failed += 1;
            let mut ledger = state.edr_control_ack_postback_retry_ledger.lock().await;
            let updated = ledger
                .mark_failed(
                    &retry.retry_id,
                    chrono::Utc::now(),
                    outcome.http_status,
                    outcome.response_hash.clone(),
                    outcome.error_hash.clone(),
                )
                .map_err(internal_error)?
                .unwrap_or_else(|| retry.clone());
            attempts.push(EdrControlAckPostbackRetryAttemptRecord {
                retry_id: retry.retry_id,
                response_action_id: retry.response_action_id,
                control_api_url: retry.control_api_url,
                route: outcome.route,
                delivered: false,
                attempt_count: updated.attempt_count,
                next_attempt_at: Some(updated.next_attempt_at),
                http_status: outcome.http_status,
                response_hash: outcome.response_hash,
                error_hash: outcome.error_hash,
            });
        }
    }

    let pending = state
        .edr_control_ack_postback_retry_ledger
        .lock()
        .await
        .pending_count();
    Ok(EdrControlAckPostbackRetryResponse {
        path,
        attempted: attempts.len(),
        delivered,
        failed,
        skipped: pending_before.saturating_sub(attempts.len()),
        pending,
        attempts,
    })
}

pub(crate) use crate::edr::ledger::{
    endpoint_receipt_compaction_manifest_path, DeceptionCleanupReceiptSigningInput,
    DeceptionRotationReceiptSigningInput, EdrPolicyDeltaReceiptSigningInput, EndpointReceiptLedger,
    PolicyDecisionReceiptSigningInput, ResponseExecutionReceiptSigningInput,
};

pub(crate) async fn emit_edr_detection_receipts(
    state: &AgentApiState,
    observations: &[EndpointObservation],
    findings: &[DetectionFinding],
    graph: &CausalGraph,
) -> Result<Vec<SignedReceipt>> {
    if findings.is_empty() {
        return Ok(Vec::new());
    }

    let settings = state.settings.read().await.clone();
    let policy = endpoint_policy_snapshot_from_settings(&settings)?;
    let sensor_state = EndpointSensorState::single_active_agent("agent-api");
    let mut ledger = state.edr_receipt_ledger.lock().await;
    let receipts = ledger.sign_detection_receipts(
        &settings,
        policy,
        sensor_state,
        observations,
        findings,
        graph,
    )?;
    drop(ledger);
    post_control_endpoint_receipts_best_effort(state, &receipts, "detection").await;
    Ok(receipts)
}

pub(crate) async fn emit_edr_provider_observation_receipts(
    state: &AgentApiState,
    observations: &[EndpointObservation],
    upload_path: &str,
) -> Result<Vec<SignedReceipt>> {
    if observations.is_empty() {
        return Ok(Vec::new());
    }

    let settings = state.settings.read().await.clone();
    let policy = endpoint_policy_snapshot_from_settings(&settings)?;
    let graph = graph_for_observations(observations);
    let mut ledger = state.edr_receipt_ledger.lock().await;
    let receipts = ledger.sign_observation_receipts(&settings, policy, observations, &graph)?;
    drop(ledger);
    post_control_endpoint_receipts_best_effort(state, &receipts, upload_path).await;
    Ok(receipts)
}

fn graph_for_observations(observations: &[EndpointObservation]) -> CausalGraph {
    let mut recorder = CausalGraphRecorder::new();
    for observation in observations {
        recorder.record_observation(observation);
    }
    recorder.into_graph()
}

pub(crate) async fn emit_edr_sensor_state_receipt(
    state: &AgentApiState,
    policy: EndpointPolicySnapshot,
    sensor_state: EndpointSensorState,
    reason: &str,
) -> Result<SignedReceipt> {
    let settings = state.settings.read().await.clone();
    let mut ledger = state.edr_receipt_ledger.lock().await;
    let receipt = ledger.sign_sensor_state_receipt(&settings, policy, sensor_state, reason)?;
    drop(ledger);
    post_control_endpoint_receipts_best_effort(
        state,
        std::slice::from_ref(&receipt),
        "sensor_state",
    )
    .await;
    Ok(receipt)
}

pub(crate) async fn emit_edr_sensor_state_receipt_with_evidence(
    state: &AgentApiState,
    policy: EndpointPolicySnapshot,
    sensor_state: EndpointSensorState,
    reason: &str,
    additional_evidence: &[EndpointReceiptEvidence],
) -> Result<SignedReceipt> {
    let settings = state.settings.read().await.clone();
    let mut ledger = state.edr_receipt_ledger.lock().await;
    let receipt = ledger.sign_sensor_state_receipt_with_evidence(
        &settings,
        policy,
        sensor_state,
        reason,
        additional_evidence,
    )?;
    drop(ledger);
    post_control_endpoint_receipts_best_effort(
        state,
        std::slice::from_ref(&receipt),
        "sensor_state",
    )
    .await;
    Ok(receipt)
}

pub(crate) async fn emit_edr_telemetry_privacy_receipt(
    state: &AgentApiState,
    report: &EndpointTelemetryPrivacyReport,
) -> Result<SignedReceipt> {
    let settings = state.settings.read().await.clone();
    let policy = endpoint_policy_snapshot_from_settings(&settings)?;
    let sensor_state = EndpointSensorState::single_active_agent("agent-api");
    let mut ledger = state.edr_receipt_ledger.lock().await;
    let receipt = ledger.sign_telemetry_privacy_receipt(&settings, policy, sensor_state, report)?;
    drop(ledger);
    post_control_endpoint_receipts_best_effort(
        state,
        std::slice::from_ref(&receipt),
        "privacy_report",
    )
    .await;
    Ok(receipt)
}

pub(crate) async fn emit_edr_provider_degradation_receipts(
    state: &AgentApiState,
    policy: EndpointPolicySnapshot,
    sensor_state: EndpointSensorState,
) -> Result<Vec<SignedReceipt>> {
    let settings = state.settings.read().await.clone();
    let mut ledger = state.edr_receipt_ledger.lock().await;
    let receipts = ledger.sign_provider_degradation_receipts(&settings, policy, sensor_state)?;
    drop(ledger);
    post_control_endpoint_receipts_best_effort(state, &receipts, "provider_degradation").await;
    Ok(receipts)
}

async fn emit_edr_policy_decision_receipt(
    state: &AgentApiState,
    input: &PolicyCheckInput,
    decision: &PolicyCheckOutput,
    session_id: Option<&str>,
) -> Result<SignedReceipt> {
    let settings = state.settings.read().await.clone();
    let session_state = state.session_manager.state().await;
    let policy = endpoint_policy_snapshot_from_settings(&settings)?;
    let sensor_state = EndpointSensorState::single_active_agent("agent-api");
    let receipt_observation =
        policy_check_receipt_observation(&settings, input, decision, &session_state, session_id);
    record_edr_observations(state, std::slice::from_ref(&receipt_observation))
        .await
        .map_err(|(_, err)| anyhow::anyhow!(err))?;
    let graph = state.edr_flight_recorder.lock().await.graph().clone();
    let actor = EndpointDecisionActor {
        endpoint_id: endpoint_id_for_settings(&settings),
        session_id: session_id
            .map(ToString::to_string)
            .or_else(|| session_state.session_id.clone()),
        posture: Some(session_state.posture),
        agent_id: input
            .runtime_agent_id
            .clone()
            .or_else(|| input.endpoint_agent_id.clone())
            .or_else(|| input.agent_id.clone()),
        workload_id: input.runtime_agent_kind.clone(),
        ..EndpointDecisionActor::default()
    };
    let mut ledger = state.edr_receipt_ledger.lock().await;
    let receipt = ledger.sign_policy_decision_receipt(PolicyDecisionReceiptSigningInput {
        actor,
        policy,
        sensor_state,
        observation: &receipt_observation,
        graph: &graph,
        action_type: input.action_type.as_str(),
        target: input.target.as_str(),
        decision,
    })?;
    drop(ledger);
    post_control_endpoint_receipts_best_effort(
        state,
        std::slice::from_ref(&receipt),
        "policy_decision",
    )
    .await;
    Ok(receipt)
}

fn policy_check_receipt_observation(
    settings: &Settings,
    input: &PolicyCheckInput,
    decision: &PolicyCheckOutput,
    session_state: &SessionState,
    session_id: Option<&str>,
) -> EndpointObservation {
    let now = chrono::Utc::now();
    let endpoint_id = endpoint_id_for_settings(settings);
    let allowed_text = if decision.allowed {
        "allowed"
    } else {
        "blocked"
    };
    let observed_at = now.to_rfc3339();
    let observation_id = local_stable_id(
        "policy_decision_observation",
        [
            endpoint_id.as_str(),
            input.action_type.as_str(),
            input.target.as_str(),
            allowed_text,
            observed_at.as_str(),
        ],
    );
    let process_guid = local_stable_id("process", [endpoint_id.as_str(), "agent-api-policy-check"]);
    let mut metadata = BTreeMap::new();
    metadata.insert(
        "receiptSource".to_string(),
        serde_json::json!("agent_policy_check"),
    );
    metadata.insert(
        "policyCheckActionType".to_string(),
        serde_json::json!(input.action_type),
    );
    metadata.insert(
        "policyCheckTargetHash".to_string(),
        serde_json::json!(sha256(input.target.as_bytes()).to_hex_prefixed()),
    );
    if let Some(runtime_agent_id) = input
        .runtime_agent_id
        .as_deref()
        .or(input.endpoint_agent_id.as_deref())
        .or(input.agent_id.as_deref())
    {
        metadata.insert("agentId".to_string(), serde_json::json!(runtime_agent_id));
    }
    if let Some(runtime_agent_kind) = input.runtime_agent_kind.as_deref() {
        metadata.insert(
            "workloadId".to_string(),
            serde_json::json!(runtime_agent_kind),
        );
    }

    EndpointObservation {
        observation_id,
        timestamp: now,
        host_id: Some(endpoint_id),
        user_id: None,
        session_id: session_id
            .map(ToString::to_string)
            .or_else(|| session_state.session_id.clone()),
        process: EndpointProcess {
            process_guid: Some(process_guid),
            image: Some("agent-api".to_string()),
            command_line: Some("agent-api policy-check".to_string()),
            ..EndpointProcess::default()
        },
        event: EndpointEvent::PolicyDecision {
            action: input.action_type.clone(),
            target: Some(input.target.clone()),
            decision: allowed_text.to_string(),
            guard: decision.guard.clone(),
            severity: decision.severity.clone(),
        },
        metadata,
    }
}

pub(crate) struct ProviderPolicyDecisionReceiptCandidate {
    actor: EndpointDecisionActor,
    sensor_state: EndpointSensorState,
    observation: EndpointObservation,
    action_type: String,
    target: String,
    decision: PolicyCheckOutput,
}

pub(crate) async fn emit_edr_provider_policy_decision_receipts(
    state: &AgentApiState,
    observations: &[EndpointObservation],
    upload_path: &str,
) -> Result<Vec<SignedReceipt>> {
    let settings = state.settings.read().await.clone();
    let policy = endpoint_policy_snapshot_from_settings(&settings)?;
    let mut candidates = Vec::new();

    for observation in observations {
        let EndpointEvent::PolicyDecision {
            action,
            target,
            decision,
            guard,
            severity,
        } = &observation.event
        else {
            continue;
        };
        let Some(action_type) = trimmed_owned(Some(action.as_str())) else {
            continue;
        };
        let Some(target) = target
            .as_deref()
            .and_then(|value| trimmed_owned(Some(value)))
        else {
            continue;
        };
        let Some(allowed) = provider_policy_decision_allowed(decision) else {
            tracing::warn!(
                observation_id = %observation.observation_id,
                decision = decision.as_str(),
                "Skipping provider policy-decision receipt with unrecognized decision value"
            );
            continue;
        };
        let provider = provider_policy_decision_provider_state(observation);
        let details = provider_policy_decision_details(observation, &provider);
        candidates.push(ProviderPolicyDecisionReceiptCandidate {
            actor: EndpointDecisionActor::from_observation(
                endpoint_id_for_observation(&settings, observation),
                observation,
            ),
            sensor_state: EndpointSensorState {
                providers: vec![provider],
            },
            observation: observation.clone(),
            action_type,
            target,
            decision: PolicyCheckOutput {
                allowed,
                guard: guard
                    .clone()
                    .and_then(|value| trimmed_owned(Some(value.as_str()))),
                severity: severity
                    .clone()
                    .and_then(|value| trimmed_owned(Some(value.as_str()))),
                message: Some(if allowed {
                    "Provider policy decision allowed".to_string()
                } else {
                    "Provider policy decision blocked".to_string()
                }),
                details: Some(details),
            },
        });
    }

    if candidates.is_empty() {
        return Ok(Vec::new());
    }

    let mut receipts = Vec::with_capacity(candidates.len());
    let graph = state.edr_flight_recorder.lock().await.graph().clone();
    let mut ledger = state.edr_receipt_ledger.lock().await;
    for candidate in candidates {
        receipts.push(
            ledger.sign_policy_decision_receipt(PolicyDecisionReceiptSigningInput {
                actor: candidate.actor,
                policy: policy.clone(),
                sensor_state: candidate.sensor_state,
                observation: &candidate.observation,
                graph: &graph,
                action_type: candidate.action_type.as_str(),
                target: candidate.target.as_str(),
                decision: &candidate.decision,
            })?,
        );
    }
    drop(ledger);
    post_control_endpoint_receipts_best_effort(state, &receipts, upload_path).await;
    Ok(receipts)
}

fn provider_policy_decision_allowed(decision: &str) -> Option<bool> {
    match decision.trim().to_ascii_lowercase().as_str() {
        "allow" | "allowed" | "pass" | "passed" | "permit" | "permitted" => Some(true),
        "block" | "blocked" | "deny" | "denied" | "drop" | "dropped" => Some(false),
        _ => None,
    }
}

pub(crate) fn provider_policy_decision_provider_state(
    observation: &EndpointObservation,
) -> EndpointProviderState {
    let collector_kind = observation_metadata_string(observation, "collectorKind");
    let provider_id = observation_metadata_string(observation, "providerId")
        .unwrap_or_else(|| "provider.policy_decision".to_string());
    let provider_kind = match collector_kind.as_deref() {
        Some("endpoint_security") => EndpointProviderKind::EndpointSecurity,
        Some("network_extension") => EndpointProviderKind::NetworkExtension,
        Some("darwin_bridge") => EndpointProviderKind::DarwinBridge,
        Some("policy_engine") => EndpointProviderKind::PolicyEngine,
        Some("agent_api") => EndpointProviderKind::AgentApi,
        _ => EndpointProviderKind::Other,
    };

    EndpointProviderState {
        provider_id,
        provider_kind,
        installed: true,
        active: true,
        healthy: true,
        degraded: false,
        degradation_reasons: Vec::new(),
        dropped_event_count: 0,
        deadline_miss_count: 0,
        full_disk_access: None,
        last_seen: Some(observation.timestamp),
    }
}

fn provider_policy_decision_details(
    observation: &EndpointObservation,
    provider: &EndpointProviderState,
) -> serde_json::Value {
    serde_json::json!({
        "source": "provider_policy_decision_observation",
        "observationId": observation.observation_id.as_str(),
        "providerId": provider.provider_id.as_str(),
        "providerKind": &provider.provider_kind,
        "collectorKind": observation_metadata_string(observation, "collectorKind"),
        "process": {
            "pid": observation.process.pid,
            "ppid": observation.process.ppid,
            "processGuid": observation.process.process_guid.as_deref(),
            "parentProcessGuid": observation.process.parent_process_guid.as_deref(),
            "image": observation.process.image.as_deref(),
            "commandLine": observation.process.command_line.as_deref(),
        },
        "metadata": &observation.metadata,
    })
}

fn observation_metadata_string(observation: &EndpointObservation, key: &str) -> Option<String> {
    observation
        .metadata
        .get(key)
        .and_then(serde_json::Value::as_str)
        .and_then(|value| trimmed_owned(Some(value)))
}

pub(crate) async fn emit_edr_graph_slice_receipt(
    state: &AgentApiState,
    root_node_id: &str,
    slice_kind: &str,
    graph: &CausalGraph,
) -> Result<SignedReceipt> {
    let settings = state.settings.read().await.clone();
    let policy = endpoint_policy_snapshot_from_settings(&settings)?;
    let sensor_state = EndpointSensorState::single_active_agent("agent-api");
    let mut ledger = state.edr_receipt_ledger.lock().await;
    let receipt = ledger.sign_graph_slice_receipt(
        &settings,
        policy,
        sensor_state,
        root_node_id,
        slice_kind,
        graph,
    )?;
    drop(ledger);
    post_control_endpoint_receipts_best_effort(
        state,
        std::slice::from_ref(&receipt),
        "graph_slice",
    )
    .await;
    Ok(receipt)
}

pub(crate) async fn emit_edr_simulation_receipt(
    state: &AgentApiState,
    simulation: &EndpointPolicySimulationReport,
    graph: &CausalGraph,
) -> Result<SignedReceipt> {
    let settings = state.settings.read().await.clone();
    let policy = endpoint_policy_snapshot_from_settings(&settings)?;
    emit_edr_simulation_receipt_with_policy(state, &settings, policy, simulation, graph).await
}

pub(crate) async fn emit_edr_simulation_receipt_with_policy(
    state: &AgentApiState,
    settings: &Settings,
    policy: EndpointPolicySnapshot,
    simulation: &EndpointPolicySimulationReport,
    graph: &CausalGraph,
) -> Result<SignedReceipt> {
    let sensor_state = EndpointSensorState::single_active_agent("agent-api");
    let mut ledger = state.edr_receipt_ledger.lock().await;
    let receipt =
        ledger.sign_simulation_receipt(settings, policy, sensor_state, simulation, graph)?;
    drop(ledger);
    post_control_endpoint_receipts_best_effort(state, std::slice::from_ref(&receipt), "simulation")
        .await;
    Ok(receipt)
}

pub(crate) async fn emit_edr_policy_event_replay_receipt(
    state: &AgentApiState,
    settings: &Settings,
    replay: &EdrPolicyEventReplayReport,
) -> Result<SignedReceipt> {
    let policy = replay.policy.clone();
    let sensor_state = EndpointSensorState::single_active_agent("agent-api");
    let mut ledger = state.edr_receipt_ledger.lock().await;
    let receipt =
        ledger.sign_policy_event_replay_receipt(settings, policy, sensor_state, replay)?;
    drop(ledger);
    post_control_endpoint_receipts_best_effort(
        state,
        std::slice::from_ref(&receipt),
        "policy_event_replay",
    )
    .await;
    Ok(receipt)
}

pub(crate) async fn emit_edr_policy_event_impact_receipt(
    state: &AgentApiState,
    settings: &Settings,
    impact: &EdrPolicyEventImpactReport,
) -> Result<SignedReceipt> {
    let policy = impact.current_policy.clone();
    let sensor_state = EndpointSensorState::single_active_agent("agent-api");
    let mut ledger = state.edr_receipt_ledger.lock().await;
    let receipt =
        ledger.sign_policy_event_impact_receipt(settings, policy, sensor_state, impact)?;
    drop(ledger);
    post_control_endpoint_receipts_best_effort(
        state,
        std::slice::from_ref(&receipt),
        "policy_event_impact",
    )
    .await;
    Ok(receipt)
}

pub(crate) async fn emit_edr_deception_materialization_receipt(
    state: &AgentApiState,
    plan: &DeceptionPlan,
    report: &DeceptionMaterializationReport,
    registered_artifact_count: usize,
) -> Result<SignedReceipt> {
    let settings = state.settings.read().await.clone();
    let policy = endpoint_policy_snapshot_from_settings(&settings)?;
    let sensor_state = EndpointSensorState::single_active_agent("agent-api");
    let mut ledger = state.edr_receipt_ledger.lock().await;
    let receipt = ledger.sign_deception_materialization_receipt(
        &settings,
        policy,
        sensor_state,
        plan,
        report,
        registered_artifact_count,
    )?;
    drop(ledger);
    post_control_endpoint_receipts_best_effort(
        state,
        std::slice::from_ref(&receipt),
        "deception_materialization",
    )
    .await;
    Ok(receipt)
}

pub(crate) async fn emit_edr_deception_cleanup_receipt(
    state: &AgentApiState,
    plan: &DeceptionPlan,
    report: &DeceptionCleanupReport,
    deregistered_artifact_count: usize,
    remaining_registered_artifact_count: usize,
) -> Result<SignedReceipt> {
    let settings = state.settings.read().await.clone();
    let policy = endpoint_policy_snapshot_from_settings(&settings)?;
    let sensor_state = EndpointSensorState::single_active_agent("agent-api");
    let mut ledger = state.edr_receipt_ledger.lock().await;
    let receipt = ledger.sign_deception_cleanup_receipt(DeceptionCleanupReceiptSigningInput {
        settings: &settings,
        policy,
        sensor_state,
        plan,
        report,
        deregistered_artifact_count,
        remaining_registered_artifact_count,
    })?;
    drop(ledger);
    post_control_endpoint_receipts_best_effort(
        state,
        std::slice::from_ref(&receipt),
        "deception_cleanup",
    )
    .await;
    Ok(receipt)
}

pub(crate) async fn emit_edr_deception_rotation_receipt(
    state: &AgentApiState,
    old_plan: &DeceptionPlan,
    new_plan: &DeceptionPlan,
    report: &DeceptionRotationReport,
) -> Result<SignedReceipt> {
    let settings = state.settings.read().await.clone();
    let policy = endpoint_policy_snapshot_from_settings(&settings)?;
    let sensor_state = EndpointSensorState::single_active_agent("agent-api");
    let mut ledger = state.edr_receipt_ledger.lock().await;
    let receipt = ledger.sign_deception_rotation_receipt(DeceptionRotationReceiptSigningInput {
        settings: &settings,
        policy,
        sensor_state,
        old_plan,
        new_plan,
        report,
    })?;
    drop(ledger);
    post_control_endpoint_receipts_best_effort(
        state,
        std::slice::from_ref(&receipt),
        "deception_rotation",
    )
    .await;
    Ok(receipt)
}

pub(crate) async fn emit_edr_response_receipt(
    state: &AgentApiState,
    actor: EndpointDecisionActor,
    plan: &EndpointResponsePlan,
    graph: &CausalGraph,
) -> Result<SignedReceipt> {
    let settings = state.settings.read().await.clone();
    let policy = endpoint_policy_snapshot_from_settings(&settings)?;
    let sensor_state = EndpointSensorState::single_active_agent("agent-api");
    let mut ledger = state.edr_receipt_ledger.lock().await;
    let receipt =
        ledger.sign_response_receipt(&settings, actor, policy, sensor_state, plan, graph)?;
    drop(ledger);
    post_control_endpoint_receipts_best_effort(
        state,
        std::slice::from_ref(&receipt),
        "response_request",
    )
    .await;
    Ok(receipt)
}

pub(crate) async fn emit_edr_response_execution_receipt(
    state: &AgentApiState,
    execution: &EndpointResponseExecutionReport,
    graph: &CausalGraph,
    actor: Option<EndpointDecisionActor>,
    extra_evidence: &[EndpointReceiptEvidence],
) -> Result<SignedReceipt> {
    let settings = state.settings.read().await.clone();
    let actor = if let Some(actor) = actor {
        actor
    } else {
        let session_state = state.session_manager.state().await;
        endpoint_response_actor_from_session(&settings, &session_state, "agent-api")
    };
    let policy = endpoint_policy_snapshot_from_settings(&settings)?;
    let macos_host = state.macos_host.snapshot().await;
    let sensor_state = endpoint_sensor_state_from_macos_host(&macos_host);
    let mut additional_evidence = if execution.action == EndpointDecisionAction::RestrictEgress {
        network_extension_response_execution_evidence(&macos_host.network_extension)
    } else {
        Vec::new()
    };
    additional_evidence.extend(extra_evidence.iter().cloned());
    let mut ledger = state.edr_receipt_ledger.lock().await;
    let receipt = ledger.sign_response_execution_receipt(ResponseExecutionReceiptSigningInput {
        settings: &settings,
        actor,
        policy,
        sensor_state,
        execution,
        graph,
        additional_evidence: &additional_evidence,
    })?;
    drop(ledger);
    post_control_endpoint_receipts_best_effort(
        state,
        std::slice::from_ref(&receipt),
        "response_execution",
    )
    .await;
    Ok(receipt)
}

pub(crate) async fn emit_edr_response_rollback_receipt(
    state: &AgentApiState,
    rollback: &EndpointResponseRollbackReport,
    graph: &CausalGraph,
) -> Result<SignedReceipt> {
    let settings = state.settings.read().await.clone();
    let session_state = state.session_manager.state().await;
    let actor = endpoint_response_actor_from_session(&settings, &session_state, "agent-api");
    let policy = endpoint_policy_snapshot_from_settings(&settings)?;
    let sensor_state = EndpointSensorState::single_active_agent("agent-api");
    let mut ledger = state.edr_receipt_ledger.lock().await;
    let receipt = ledger.sign_response_rollback_receipt(
        &settings,
        actor,
        policy,
        sensor_state,
        rollback,
        graph,
    )?;
    drop(ledger);
    post_control_endpoint_receipts_best_effort(
        state,
        std::slice::from_ref(&receipt),
        "response_rollback",
    )
    .await;
    Ok(receipt)
}

pub(crate) async fn emit_edr_response_acknowledgement_receipt(
    state: &AgentApiState,
    acknowledgement: &EndpointResponseAcknowledgementReport,
    graph: &CausalGraph,
) -> Result<SignedReceipt> {
    let settings = state.settings.read().await.clone();
    let session_state = state.session_manager.state().await;
    let actor = endpoint_response_actor_from_session(
        &settings,
        &session_state,
        acknowledgement.acknowledged_by.as_str(),
    );
    let policy = endpoint_policy_snapshot_from_settings(&settings)?;
    let sensor_state = EndpointSensorState::single_active_agent("agent-api");
    let mut ledger = state.edr_receipt_ledger.lock().await;
    let receipt = ledger.sign_response_acknowledgement_receipt(
        &settings,
        actor,
        policy,
        sensor_state,
        acknowledgement,
        graph,
    )?;
    drop(ledger);
    post_control_endpoint_receipts_best_effort(
        state,
        std::slice::from_ref(&receipt),
        "response_acknowledgement",
    )
    .await;
    Ok(receipt)
}

async fn emit_edr_evidence_bundle_manifest_receipt(
    state: &AgentApiState,
    execution: &EndpointResponseExecutionReport,
    graph: &CausalGraph,
) -> Result<SignedReceipt> {
    let settings = state.settings.read().await.clone();
    let policy = endpoint_policy_snapshot_from_settings(&settings)?;
    let sensor_state = EndpointSensorState::single_active_agent("agent-api");
    let mut ledger = state.edr_receipt_ledger.lock().await;
    let receipt = ledger.sign_evidence_bundle_manifest_receipt(
        &settings,
        policy,
        sensor_state,
        execution,
        graph,
    )?;
    drop(ledger);
    post_control_endpoint_receipts_best_effort(
        state,
        std::slice::from_ref(&receipt),
        "evidence_bundle_manifest",
    )
    .await;
    Ok(receipt)
}

pub(crate) fn receipt_matches_filter(
    receipt: &SignedReceipt,
    filter: EdrReceiptFilter<'_>,
) -> bool {
    if let Some(expected) = filter.receipt_id {
        if !receipt
            .receipt
            .receipt_id
            .as_deref()
            .map(|actual| actual == expected)
            .unwrap_or(false)
        {
            return false;
        }
    }
    if let Some(expected) = filter.family {
        if !receipt_family(receipt)
            .map(|actual| actual == expected)
            .unwrap_or(false)
        {
            return false;
        }
    }
    if let Some(expected) = filter.action {
        if !receipt_endpoint_decision_str(receipt, &["decision", "action"])
            .map(|actual| actual == expected)
            .unwrap_or(false)
        {
            return false;
        }
    }
    if let Some(expected) = filter.finding_id {
        if !receipt_endpoint_decision_str(receipt, &["decision", "findingId"])
            .map(|actual| actual == expected)
            .unwrap_or(false)
        {
            return false;
        }
    }
    if let Some(expected) = filter.rule_id {
        if !receipt_endpoint_decision_str(receipt, &["decision", "ruleId"])
            .map(|actual| actual == expected)
            .unwrap_or(false)
        {
            return false;
        }
    }
    if let Some(expected) = filter.graph_slice_id {
        if !receipt_endpoint_decision_str(receipt, &["graph", "graphSliceId"])
            .map(|actual| actual == expected)
            .unwrap_or(false)
        {
            return false;
        }
    }
    if let Some(expected) = filter.root_node_id {
        if !receipt_endpoint_decision_str(receipt, &["graph", "processNodeId"])
            .map(|actual| actual == expected)
            .unwrap_or(false)
        {
            return false;
        }
    }
    if let Some(expected) = filter.execution_id {
        if !receipt_endpoint_decision_str(receipt, &["decision", "findingId"])
            .map(|actual| actual == expected)
            .unwrap_or(false)
            && !receipt_evidence_hash_matches(receipt, "executionId", expected)
        {
            return false;
        }
    }
    if let Some(expected) = filter.status {
        if !receipt_evidence_hash_matches(receipt, "executionStatus", expected) {
            return false;
        }
    }
    if let Some(expected) = filter.actor_endpoint_id {
        if !receipt_endpoint_decision_str(receipt, &["actor", "endpointId"])
            .map(|actual| actual == expected)
            .unwrap_or(false)
        {
            return false;
        }
    }
    if let Some(expected) = filter.actor_user_id {
        if !receipt_endpoint_decision_str(receipt, &["actor", "userId"])
            .map(|actual| actual == expected)
            .unwrap_or(false)
        {
            return false;
        }
    }
    if let Some(expected) = filter.actor_session_id {
        if !receipt_endpoint_decision_str(receipt, &["actor", "sessionId"])
            .map(|actual| actual == expected)
            .unwrap_or(false)
        {
            return false;
        }
    }
    if let Some(expected) = filter.actor_agent_id {
        if !receipt_endpoint_decision_str(receipt, &["actor", "agentId"])
            .map(|actual| actual == expected)
            .unwrap_or(false)
        {
            return false;
        }
    }
    if let Some(expected) = filter.actor_workload_id {
        if !receipt_endpoint_decision_str(receipt, &["actor", "workloadId"])
            .map(|actual| actual == expected)
            .unwrap_or(false)
        {
            return false;
        }
    }
    if let Some(expected) = filter.actor_approval_id {
        if !receipt_endpoint_decision_str(receipt, &["actor", "approvalId"])
            .map(|actual| actual == expected)
            .unwrap_or(false)
        {
            return false;
        }
    }
    if let Some(expected) = filter.local_sequence {
        if receipt_local_sequence(receipt) != Some(expected) {
            return false;
        }
    }
    true
}

fn receipt_evidence_hash_matches(receipt: &SignedReceipt, key: &str, raw_value: &str) -> bool {
    let expected_hash = sha256(raw_value.as_bytes()).to_hex_prefixed();
    receipt_evidence_hash_value(receipt, key) == Some(expected_hash.as_str())
}

fn receipt_evidence_hash_value<'a>(receipt: &'a SignedReceipt, key: &str) -> Option<&'a str> {
    receipt_endpoint_decision_value(receipt, &["evidence"])
        .and_then(serde_json::Value::as_array)
        .and_then(|items| {
            items.iter().find_map(|item| {
                if item.get("key").and_then(serde_json::Value::as_str) == Some(key) {
                    item.get("valueHash").and_then(serde_json::Value::as_str)
                } else {
                    None
                }
            })
        })
}

pub(crate) fn verify_response_execution_proof_contract(
    execution: &EndpointResponseExecutionReport,
    request_receipt: &SignedReceipt,
    execution_receipt: &SignedReceipt,
    evidence_bundle_receipt: &SignedReceipt,
    transition_receipts: &[SignedReceipt],
    rollback_receipts: &[SignedReceipt],
    acknowledgement_receipts: &[SignedReceipt],
) -> Result<(), (StatusCode, String)> {
    require_proof_receipt_decision_str(
        request_receipt,
        "response request receipt",
        &["decision", "action"],
        execution.action.as_str(),
    )?;
    require_proof_receipt_decision_str(
        request_receipt,
        "response request receipt",
        &["decision", "rollbackRef"],
        execution.rollback_ref.as_str(),
    )?;
    for (key, raw_value) in [
        ("responseActionId", execution.action_id.as_str()),
        ("rootNodeId", execution.root_node_id.as_str()),
        ("graphSliceId", execution.graph_slice_id.as_str()),
        ("rollbackRef", execution.rollback_ref.as_str()),
        ("dryRun", "false"),
    ] {
        require_proof_receipt_evidence_hash(
            request_receipt,
            "response request receipt",
            key,
            raw_value,
        )?;
    }
    require_proof_receipt_evidence_hash(
        request_receipt,
        "response request receipt",
        "ttlSeconds",
        execution.ttl_seconds.to_string().as_str(),
    )?;

    verify_response_execution_receipt_contract(
        execution,
        execution_receipt,
        "response execution receipt",
        ResponseExecutionProofReceiptKind::Primary,
    )?;

    require_proof_receipt_decision_str(
        evidence_bundle_receipt,
        "evidence bundle manifest receipt",
        &["decision", "findingId"],
        execution.evidence_bundle.bundle_id.as_str(),
    )?;
    for (key, raw_value) in [
        (
            "evidenceBundleId",
            execution.evidence_bundle.bundle_id.as_str(),
        ),
        (
            "graphSliceId",
            execution.evidence_bundle.graph_slice_id.as_str(),
        ),
        (
            "contentHash",
            execution.evidence_bundle.content_hash.as_str(),
        ),
    ] {
        require_proof_receipt_evidence_hash(
            evidence_bundle_receipt,
            "evidence bundle manifest receipt",
            key,
            raw_value,
        )?;
    }
    require_proof_receipt_evidence_hash(
        evidence_bundle_receipt,
        "evidence bundle manifest receipt",
        "nodeCount",
        execution.evidence_bundle.node_count.to_string().as_str(),
    )?;
    require_proof_receipt_evidence_hash(
        evidence_bundle_receipt,
        "evidence bundle manifest receipt",
        "edgeCount",
        execution.evidence_bundle.edge_count.to_string().as_str(),
    )?;
    for receipt in transition_receipts {
        verify_response_execution_receipt_contract(
            execution,
            receipt,
            "response execution transition receipt",
            ResponseExecutionProofReceiptKind::TerminalTransition,
        )?;
    }
    for receipt in rollback_receipts {
        verify_response_lifecycle_receipt_contract(
            execution,
            receipt,
            "response rollback receipt",
        )?;
        require_proof_receipt_evidence_hash(
            receipt,
            "response rollback receipt",
            "executionId",
            execution.execution_id.as_str(),
        )?;
        let rollback_effects = expected_response_rollback_effects(execution)?;
        verify_response_effects_proof_contract(
            receipt,
            "response rollback receipt",
            "rollbackEffect",
            &rollback_effects,
        )?;
    }
    for receipt in acknowledgement_receipts {
        verify_response_lifecycle_receipt_contract(
            execution,
            receipt,
            "response acknowledgement receipt",
        )?;
        require_proof_receipt_evidence_hash(
            receipt,
            "response acknowledgement receipt",
            "executionId",
            execution.execution_id.as_str(),
        )?;
        require_proof_receipt_evidence_hash(
            receipt,
            "response acknowledgement receipt",
            "acknowledgedStatus",
            execution.status.as_str(),
        )?;
        verify_response_effects_proof_contract(
            receipt,
            "response acknowledgement receipt",
            "acknowledgementEffect",
            &execution.effects,
        )?;
    }
    Ok(())
}

pub(crate) fn verify_response_execution_proof_evidence_bundle(
    execution: &EndpointResponseExecutionReport,
    stored: &StoredEndpointEvidenceBundle,
) -> Result<(), (StatusCode, String)> {
    for (label, expected, actual) in [
        (
            "bundle_id",
            execution.evidence_bundle.bundle_id.as_str(),
            stored.bundle.bundle_id.as_str(),
        ),
        (
            "graph_slice_id",
            execution.evidence_bundle.graph_slice_id.as_str(),
            stored.bundle.graph_slice_id.as_str(),
        ),
        (
            "content_hash",
            execution.evidence_bundle.content_hash.as_str(),
            stored.bundle.content_hash.as_str(),
        ),
    ] {
        if expected != actual {
            return Err(response_proof_contract_conflict(format!(
                "evidence bundle artifact {label} does not match response execution proof contract"
            )));
        }
    }
    if execution.evidence_bundle.node_count != stored.bundle.node_count
        || execution.evidence_bundle.node_count != stored.graph.nodes.len()
    {
        return Err(response_proof_contract_conflict(
            "evidence bundle artifact node count does not match response execution proof contract",
        ));
    }
    if execution.evidence_bundle.edge_count != stored.bundle.edge_count
        || execution.evidence_bundle.edge_count != stored.graph.edges.len()
    {
        return Err(response_proof_contract_conflict(
            "evidence bundle artifact edge count does not match response execution proof contract",
        ));
    }
    let canonical_graph = canonical_evidence_graph(&stored.graph).map_err(internal_error)?;
    if canonical_graph.content_hash != execution.evidence_bundle.content_hash {
        return Err(response_proof_contract_conflict(
            "evidence bundle artifact content hash does not match response execution proof contract",
        ));
    }
    if stored.byte_count != canonical_graph.byte_count {
        return Err(response_proof_contract_conflict(
            "evidence bundle artifact byte count does not match response execution proof contract",
        ));
    }
    Ok(())
}

#[derive(Clone, Copy)]
pub(crate) enum ResponseExecutionProofReceiptKind {
    Primary,
    TerminalTransition,
}

fn verify_response_execution_receipt_contract(
    execution: &EndpointResponseExecutionReport,
    receipt: &SignedReceipt,
    label: &str,
    kind: ResponseExecutionProofReceiptKind,
) -> Result<(), (StatusCode, String)> {
    verify_response_lifecycle_receipt_contract(execution, receipt, label)?;
    match kind {
        ResponseExecutionProofReceiptKind::Primary => {
            require_proof_receipt_decision_str(
                receipt,
                label,
                &["decision", "findingId"],
                execution.execution_id.as_str(),
            )?;
            require_proof_receipt_evidence_hash(
                receipt,
                label,
                "executionId",
                execution.execution_id.as_str(),
            )?;
            require_proof_receipt_evidence_hash(
                receipt,
                label,
                "executionStatus",
                execution.status.as_str(),
            )?;
        }
        ResponseExecutionProofReceiptKind::TerminalTransition => {
            if receipt_endpoint_decision_str(receipt, &["decision", "findingId"])
                == Some(execution.execution_id.as_str())
            {
                return Err((
                    StatusCode::CONFLICT,
                    format!("{label} does not match response execution proof contract"),
                ));
            }
            if !receipt_evidence_hash_matches(receipt, "executionStatus", "expired")
                && !receipt_evidence_hash_matches(receipt, "executionStatus", "cancelled")
                && !receipt_evidence_hash_matches(receipt, "executionStatus", "rollback_failed")
                && !receipt_evidence_hash_matches(receipt, "executionStatus", "rolled_back")
            {
                return Err((
                    StatusCode::CONFLICT,
                    format!(
                        "{label} executionStatus does not match response execution proof contract"
                    ),
                ));
            }
        }
    }
    for (key, raw_value) in [
        (
            "evidenceBundleId",
            execution.evidence_bundle.bundle_id.as_str(),
        ),
        (
            "evidenceBundleContentHash",
            execution.evidence_bundle.content_hash.as_str(),
        ),
    ] {
        require_proof_receipt_evidence_hash(receipt, label, key, raw_value)?;
    }
    require_proof_receipt_evidence_hash(
        receipt,
        label,
        "dryRun",
        execution.dry_run.to_string().as_str(),
    )?;
    verify_response_effects_proof_contract(receipt, label, "executionEffect", &execution.effects)?;
    Ok(())
}

fn verify_response_lifecycle_receipt_contract(
    execution: &EndpointResponseExecutionReport,
    receipt: &SignedReceipt,
    label: &str,
) -> Result<(), (StatusCode, String)> {
    require_proof_receipt_decision_str(
        receipt,
        label,
        &["decision", "action"],
        execution.action.as_str(),
    )?;
    require_proof_receipt_decision_str(
        receipt,
        label,
        &["decision", "rollbackRef"],
        execution.rollback_ref.as_str(),
    )?;
    for (key, raw_value) in [
        ("responseActionId", execution.action_id.as_str()),
        ("rootNodeId", execution.root_node_id.as_str()),
        ("graphSliceId", execution.graph_slice_id.as_str()),
        ("rollbackRef", execution.rollback_ref.as_str()),
    ] {
        require_proof_receipt_evidence_hash(receipt, label, key, raw_value)?;
    }
    require_proof_receipt_evidence_hash(
        receipt,
        label,
        "ttlSeconds",
        execution.ttl_seconds.to_string().as_str(),
    )?;
    Ok(())
}

fn response_effect_proof_contract_value(
    effect: &EndpointResponseExecutionEffect,
) -> Result<String, (StatusCode, String)> {
    let value = serde_json::to_value(effect)
        .map_err(|err| internal_error(anyhow::anyhow!("serialize response effect: {err}")))?;
    canonicalize_json(&value)
        .map_err(|err| internal_error(anyhow::anyhow!("canonicalize response effect: {err}")))
}

fn verify_response_effects_proof_contract(
    receipt: &SignedReceipt,
    label: &str,
    prefix: &str,
    effects: &[EndpointResponseExecutionEffect],
) -> Result<(), (StatusCode, String)> {
    require_proof_receipt_evidence_hash(
        receipt,
        label,
        "effectCount",
        effects.len().to_string().as_str(),
    )?;
    for effect in effects {
        let effect_value = response_effect_proof_contract_value(effect)?;
        require_proof_receipt_evidence_hash(
            receipt,
            label,
            format!("{prefix}:{}", effect.effect_id).as_str(),
            effect_value.as_str(),
        )?;
        require_proof_receipt_evidence_hash(
            receipt,
            label,
            format!("{prefix}Type:{}", effect.effect_id).as_str(),
            effect.effect_type.as_str(),
        )?;
    }
    Ok(())
}

fn expected_response_rollback_effects(
    execution: &EndpointResponseExecutionReport,
) -> Result<Vec<EndpointResponseExecutionEffect>, (StatusCode, String)> {
    match execution.action {
        EndpointDecisionAction::RestrictEgress => {
            let effect = require_execution_effect_for_rollback(execution, "restrict_egress")?;
            let primary_target =
                effect
                    .target
                    .strip_prefix("egress:")
                    .ok_or_else(|| {
                        response_proof_contract_conflict(
                            "response rollback receipt target does not match response execution proof contract",
                        )
                    })?;
            let targets = response_proof_contract_string_artifact(effect)?;
            let rollback_effect =
                EndpointResponseExecutionEffect::restore_egress(primary_target, &targets);
            verify_rollback_effect_matches_execution_effect(&rollback_effect, effect)?;
            Ok(vec![rollback_effect])
        }
        EndpointDecisionAction::QuarantineFile => {
            let effect = require_execution_effect_for_rollback(execution, "quarantine_file")?;
            let artifact = response_proof_contract_required_effect_field(
                effect.artifact.as_deref(),
                "response rollback receipt artifact does not match response execution proof contract",
            )?;
            let content_hash = response_proof_contract_required_effect_field(
                effect.content_hash.as_deref(),
                "response rollback receipt content hash does not match response execution proof contract",
            )?;
            let byte_count = effect.byte_count.ok_or_else(|| {
                response_proof_contract_conflict(
                    "response rollback receipt byte count does not match response execution proof contract",
                )
            })?;
            Ok(vec![
                EndpointResponseExecutionEffect::restore_quarantine_file(
                    effect.target.as_str(),
                    artifact,
                    content_hash,
                    byte_count,
                ),
            ])
        }
        EndpointDecisionAction::DisablePersistence => {
            let effect = require_execution_effect_for_rollback(execution, "disable_persistence")?;
            let artifact = response_proof_contract_required_effect_field(
                effect.artifact.as_deref(),
                "response rollback receipt artifact does not match response execution proof contract",
            )?;
            let content_hash = response_proof_contract_required_effect_field(
                effect.content_hash.as_deref(),
                "response rollback receipt content hash does not match response execution proof contract",
            )?;
            let byte_count = effect.byte_count.ok_or_else(|| {
                response_proof_contract_conflict(
                    "response rollback receipt byte count does not match response execution proof contract",
                )
            })?;
            Ok(vec![
                EndpointResponseExecutionEffect::restore_persistence_file(
                    effect.target.as_str(),
                    artifact,
                    content_hash,
                    byte_count,
                ),
            ])
        }
        EndpointDecisionAction::SuspendProcessTree => {
            let effect = require_execution_effect_for_rollback(execution, "suspend_process_tree")?;
            let root_pid = effect
                .target
                .strip_prefix("pid:")
                .ok_or_else(|| {
                    response_proof_contract_conflict(
                        "response rollback receipt target does not match response execution proof contract",
                    )
                })?
                .parse::<u32>()
                .map_err(|_| {
                    response_proof_contract_conflict(
                        "response rollback receipt target does not match response execution proof contract",
                    )
                })?;
            let artifact = response_proof_contract_required_effect_field(
                effect.artifact.as_deref(),
                "response rollback receipt artifact does not match response execution proof contract",
            )?;
            let rollback_effect =
                EndpointResponseExecutionEffect::resume_process_tree_from_artifact(
                    root_pid, artifact,
                );
            verify_rollback_effect_matches_execution_effect(&rollback_effect, effect)?;
            Ok(vec![rollback_effect])
        }
        _ => Err(response_proof_contract_conflict(
            "response rollback receipt is not valid for this response execution action",
        )),
    }
}

fn require_execution_effect_for_rollback<'a>(
    execution: &'a EndpointResponseExecutionReport,
    effect_type: &str,
) -> Result<&'a EndpointResponseExecutionEffect, (StatusCode, String)> {
    execution
        .effects
        .iter()
        .find(|effect| effect.effect_type == effect_type)
        .ok_or_else(|| {
            response_proof_contract_conflict(
                "response rollback receipt effect does not match response execution proof contract",
            )
        })
}

fn response_proof_contract_string_artifact(
    effect: &EndpointResponseExecutionEffect,
) -> Result<Vec<String>, (StatusCode, String)> {
    let artifact = response_proof_contract_required_effect_field(
        effect.artifact.as_deref(),
        "response rollback receipt artifact does not match response execution proof contract",
    )?;
    let values = artifact
        .split(',')
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned)
        .collect::<Vec<_>>();
    if values.is_empty() {
        return Err(response_proof_contract_conflict(
            "response rollback receipt artifact does not match response execution proof contract",
        ));
    }
    Ok(values)
}

fn response_proof_contract_required_effect_field<'a>(
    value: Option<&'a str>,
    message: &'static str,
) -> Result<&'a str, (StatusCode, String)> {
    value
        .filter(|value| !value.trim().is_empty())
        .ok_or_else(|| response_proof_contract_conflict(message))
}

fn verify_rollback_effect_matches_execution_effect(
    rollback_effect: &EndpointResponseExecutionEffect,
    execution_effect: &EndpointResponseExecutionEffect,
) -> Result<(), (StatusCode, String)> {
    if rollback_effect.target == execution_effect.target
        && rollback_effect.artifact == execution_effect.artifact
        && rollback_effect.content_hash == execution_effect.content_hash
        && rollback_effect.byte_count == execution_effect.byte_count
    {
        return Ok(());
    }
    Err(response_proof_contract_conflict(
        "response rollback receipt effect does not match response execution proof contract",
    ))
}

fn response_proof_contract_conflict(message: impl Into<String>) -> (StatusCode, String) {
    (StatusCode::CONFLICT, message.into())
}

fn require_proof_receipt_decision_str(
    receipt: &SignedReceipt,
    label: &str,
    path: &[&str],
    expected: &str,
) -> Result<(), (StatusCode, String)> {
    if receipt_endpoint_decision_str(receipt, path) == Some(expected) {
        return Ok(());
    }
    Err((
        StatusCode::CONFLICT,
        format!("{label} does not match response execution proof contract"),
    ))
}

fn require_proof_receipt_evidence_hash(
    receipt: &SignedReceipt,
    label: &str,
    key: &str,
    raw_value: &str,
) -> Result<(), (StatusCode, String)> {
    if receipt_evidence_hash_matches(receipt, key, raw_value) {
        return Ok(());
    }
    Err((
        StatusCode::CONFLICT,
        format!("{label} {key} does not match response execution proof contract"),
    ))
}

pub(crate) fn verify_response_execution_proof_actor_continuity(
    execution: &EndpointResponseExecutionReport,
    request_receipt: &SignedReceipt,
    execution_receipt: &SignedReceipt,
    transition_receipts: &[SignedReceipt],
) -> Result<(), (StatusCode, String)> {
    let actor = execution.actor.as_ref().ok_or_else(|| {
        (
            StatusCode::CONFLICT,
            format!(
                "response execution proof actor validation failed for {}: execution ledger is missing actor identity",
                execution.execution_id
            ),
        )
    })?;
    let actor_hash =
        canonical_json_hash(actor, "response execution proof actor").map_err(internal_error)?;
    verify_response_execution_proof_receipt_actor(
        "response request receipt",
        request_receipt,
        actor,
        &actor_hash,
        &["actorHash"],
    )?;
    verify_response_execution_proof_receipt_actor(
        "response execution receipt",
        execution_receipt,
        actor,
        &actor_hash,
        &["actorHash", "executionActorHash"],
    )?;
    for receipt in transition_receipts {
        verify_response_execution_proof_receipt_actor(
            "response execution transition receipt",
            receipt,
            actor,
            &actor_hash,
            &["actorHash", "executionActorHash"],
        )?;
    }
    Ok(())
}

fn verify_response_execution_proof_receipt_actor(
    label: &str,
    receipt: &SignedReceipt,
    expected_actor: &EndpointDecisionActor,
    expected_actor_hash: &str,
    required_hash_keys: &[&str],
) -> Result<(), (StatusCode, String)> {
    let receipt_actor = receipt_endpoint_decision_actor(receipt).map_err(|reason| {
        (
            StatusCode::CONFLICT,
            format!("{label} failed actor validation: {reason}"),
        )
    })?;
    if &receipt_actor != expected_actor {
        return Err((
            StatusCode::CONFLICT,
            format!("{label} actor does not match response execution ledger actor"),
        ));
    }
    for key in required_hash_keys {
        if !receipt_evidence_hash_matches(receipt, key, expected_actor_hash) {
            return Err((
                StatusCode::CONFLICT,
                format!("{label} {key} does not match response execution ledger actor"),
            ));
        }
    }
    Ok(())
}

pub(crate) struct ResponseExecutionLifecycleReceipts {
    pub(crate) transition_receipts: Vec<SignedReceipt>,
    pub(crate) rollback_receipts: Vec<SignedReceipt>,
    pub(crate) acknowledgement_receipts: Vec<SignedReceipt>,
}

pub(crate) fn response_execution_lifecycle_receipts(
    ledger: &EndpointReceiptLedger,
    execution: &EndpointResponseExecutionReport,
) -> Result<ResponseExecutionLifecycleReceipts, (StatusCode, String)> {
    let mut transition_receipts = Vec::new();
    let mut rollback_receipts = Vec::new();
    let mut acknowledgement_receipts = Vec::new();

    for receipt in ledger.all().map_err(internal_error)? {
        match receipt_family(&receipt) {
            Some("response_execution")
                if response_lifecycle_receipt_matches_execution(&receipt, execution)
                    && response_execution_receipt_is_terminal_transition(&receipt)
                    && receipt_endpoint_decision_str(&receipt, &["decision", "findingId"])
                        != Some(execution.execution_id.as_str()) =>
            {
                verify_proof_receipt_signature(
                    &receipt,
                    "response execution transition receipt",
                    &ledger.signer_public_key,
                )?;
                transition_receipts.push(receipt);
            }
            Some("response_rollback")
                if response_lifecycle_receipt_matches_execution(&receipt, execution)
                    && receipt_evidence_hash_matches(
                        &receipt,
                        "executionId",
                        execution.execution_id.as_str(),
                    ) =>
            {
                verify_proof_receipt_signature(
                    &receipt,
                    "response rollback receipt",
                    &ledger.signer_public_key,
                )?;
                rollback_receipts.push(receipt);
            }
            Some("response_acknowledgement")
                if response_lifecycle_receipt_matches_execution(&receipt, execution)
                    && receipt_evidence_hash_matches(
                        &receipt,
                        "executionId",
                        execution.execution_id.as_str(),
                    ) =>
            {
                verify_proof_receipt_signature(
                    &receipt,
                    "response acknowledgement receipt",
                    &ledger.signer_public_key,
                )?;
                acknowledgement_receipts.push(receipt);
            }
            _ => {}
        }
    }

    transition_receipts.sort_by(endpoint_receipt_proof_order);
    rollback_receipts.sort_by(endpoint_receipt_proof_order);
    acknowledgement_receipts.sort_by(endpoint_receipt_proof_order);
    Ok(ResponseExecutionLifecycleReceipts {
        transition_receipts,
        rollback_receipts,
        acknowledgement_receipts,
    })
}

fn response_lifecycle_receipt_matches_execution(
    receipt: &SignedReceipt,
    execution: &EndpointResponseExecutionReport,
) -> bool {
    receipt_endpoint_decision_str(receipt, &["decision", "action"])
        == Some(execution.action.as_str())
        && receipt_endpoint_decision_str(receipt, &["decision", "rollbackRef"])
            == Some(execution.rollback_ref.as_str())
        && receipt_evidence_hash_matches(receipt, "responseActionId", &execution.action_id)
        && receipt_evidence_hash_matches(receipt, "rootNodeId", &execution.root_node_id)
        && receipt_evidence_hash_matches(receipt, "graphSliceId", &execution.graph_slice_id)
}

fn response_execution_receipt_is_terminal_transition(receipt: &SignedReceipt) -> bool {
    receipt_evidence_hash_matches(receipt, "executionStatus", "expired")
        || receipt_evidence_hash_matches(receipt, "executionStatus", "cancelled")
        || receipt_evidence_hash_matches(receipt, "executionStatus", "rollback_failed")
        || receipt_evidence_hash_matches(receipt, "executionStatus", "rolled_back")
}

fn endpoint_receipt_proof_order(left: &SignedReceipt, right: &SignedReceipt) -> std::cmp::Ordering {
    left.receipt
        .timestamp
        .cmp(&right.receipt.timestamp)
        .then_with(|| left.receipt.receipt_id.cmp(&right.receipt.receipt_id))
}

pub(crate) fn latest_required_receipt(
    ledger: &EndpointReceiptLedger,
    family: &str,
    finding_id: &str,
    label: &str,
) -> Result<SignedReceipt, (StatusCode, String)> {
    let filter = EdrReceiptFilter {
        receipt_id: None,
        family: Some(family),
        action: None,
        finding_id: Some(finding_id),
        rule_id: None,
        graph_slice_id: None,
        root_node_id: None,
        execution_id: None,
        status: None,
        actor_endpoint_id: None,
        actor_user_id: None,
        actor_session_id: None,
        actor_agent_id: None,
        actor_workload_id: None,
        actor_approval_id: None,
        local_sequence: None,
    };
    let mut receipts = ledger.read_recent(1, filter).map_err(internal_error)?;
    let receipt = receipts.pop().ok_or_else(|| {
        (
            StatusCode::NOT_FOUND,
            format!("{label} not found for response execution proof target {finding_id}"),
        )
    })?;
    verify_proof_receipt_signature(&receipt, label, &ledger.signer_public_key)?;
    Ok(receipt)
}

pub(crate) fn latest_required_receipt_by_execution_id(
    ledger: &EndpointReceiptLedger,
    family: &str,
    execution_id: &str,
    label: &str,
) -> Result<SignedReceipt, (StatusCode, String)> {
    let filter = EdrReceiptFilter {
        receipt_id: None,
        family: Some(family),
        action: None,
        finding_id: None,
        rule_id: None,
        graph_slice_id: None,
        root_node_id: None,
        execution_id: Some(execution_id),
        status: None,
        actor_endpoint_id: None,
        actor_user_id: None,
        actor_session_id: None,
        actor_agent_id: None,
        actor_workload_id: None,
        actor_approval_id: None,
        local_sequence: None,
    };
    let mut receipts = ledger.read_recent(1, filter).map_err(internal_error)?;
    let receipt = receipts.pop().ok_or_else(|| {
        (
            StatusCode::NOT_FOUND,
            format!("{label} not found for response execution proof target {execution_id}"),
        )
    })?;
    verify_proof_receipt_signature(&receipt, label, &ledger.signer_public_key)?;
    Ok(receipt)
}

fn verify_proof_receipt_signature(
    receipt: &SignedReceipt,
    label: &str,
    expected_signer_public_key: &str,
) -> Result<(), (StatusCode, String)> {
    verify_endpoint_receipt_signature(receipt, label, expected_signer_public_key).map_err(
        |reason| {
            (
                StatusCode::CONFLICT,
                format!("{label} failed signature verification: {reason}"),
            )
        },
    )
}

fn verify_endpoint_receipt_signature(
    receipt: &SignedReceipt,
    label: &str,
    expected_signer_public_key: &str,
) -> Result<(), String> {
    let public_key = receipt_endpoint_decision_str(receipt, &["signer", "signerPublicKey"])
        .ok_or_else(|| format!("{label} is missing signer public key"))?;
    if public_key != expected_signer_public_key {
        return Err(format!("{label} signer public key is not trusted"));
    }
    let public_key = hush_core::PublicKey::from_hex(public_key)
        .map_err(|err| format!("{label} signer public key is invalid: {err}"))?;
    let verification = receipt.verify(&hush_core::receipt::PublicKeySet::new(public_key));
    if !verification.valid {
        return Err(format!("{label} signature is invalid"));
    }
    let endpoint_decision_value = receipt
        .receipt
        .metadata
        .as_ref()
        .and_then(|metadata| metadata.get("endpointDecision"))
        .ok_or_else(|| format!("{label} is missing endpoint decision metadata"))?;
    let canonical_endpoint_decision =
        canonicalize_json(endpoint_decision_value).map_err(|err| {
            format!("{label} endpoint decision metadata is not canonicalizable: {err}")
        })?;
    let expected_content_hash = sha256(canonical_endpoint_decision.as_bytes());
    if receipt.receipt.content_hash != expected_content_hash {
        return Err(format!(
            "{label} endpoint decision metadata content hash does not match receipt content hash"
        ));
    }
    let endpoint_decision: EndpointDecisionReceipt =
        serde_json::from_value(endpoint_decision_value.clone())
            .map_err(|err| format!("{label} endpoint decision metadata is invalid: {err}"))?;
    endpoint_decision
        .validate()
        .map_err(|err| format!("{label} endpoint decision metadata is invalid: {err}"))?;
    let expected_receipt_id = endpoint_decision.receipt_id();
    if receipt.receipt.receipt_id.as_deref() != Some(expected_receipt_id.as_str()) {
        return Err(format!(
            "{label} endpoint decision metadata receipt id does not match receipt id"
        ));
    }
    Ok(())
}

pub(crate) fn control_store_receipt_from_endpoint_receipt(
    receipt: &SignedReceipt,
) -> Result<ControlStoreReceiptRequest, String> {
    let public_key = receipt_endpoint_decision_str(receipt, &["signer", "signerPublicKey"])
        .ok_or_else(|| "endpoint receipt is missing signer public key".to_string())?;
    verify_endpoint_receipt_signature(receipt, "endpoint receipt upload candidate", public_key)?;
    let policy_name = receipt
        .receipt
        .provenance
        .as_ref()
        .and_then(|provenance| non_empty(provenance.ruleset.as_deref()))
        .or_else(|| receipt_endpoint_decision_str(receipt, &["policy", "policyVersion"]))
        .ok_or_else(|| "endpoint receipt is missing policy name".to_string())?;
    let guard = receipt
        .receipt
        .verdict
        .gate_id
        .as_deref()
        .and_then(|value| non_empty(Some(value)))
        .or_else(|| receipt_family(receipt))
        .unwrap_or("endpoint_decision");
    let endpoint_decision = receipt
        .receipt
        .metadata
        .as_ref()
        .and_then(|metadata| metadata.get("endpointDecision"))
        .ok_or_else(|| "endpoint receipt is missing endpoint decision metadata".to_string())?;
    let evidence = endpoint_decision
        .get("evidence")
        .and_then(|value| {
            value
                .as_array()
                .filter(|items| !items.is_empty())
                .map(|_| value)
        })
        .cloned();
    let signed_receipt = serde_json::to_value(receipt)
        .map_err(|err| format!("serialize endpoint receipt for upload: {err}"))?;

    Ok(ControlStoreReceiptRequest {
        timestamp: receipt.receipt.timestamp.clone(),
        verdict: control_store_receipt_verdict(receipt).to_string(),
        guard: guard.to_string(),
        policy_name: policy_name.to_string(),
        signature: receipt.signatures.signer.to_hex(),
        public_key: public_key.to_string(),
        chain_hash: None,
        evidence,
        metadata: Some(serde_json::json!({
            "source": "clawdstrike-agent",
            "receiptId": receipt.receipt.receipt_id.as_deref(),
            "receiptFamily": receipt_family(receipt),
            "localSequence": receipt_local_sequence(receipt),
            "endpointId": receipt_endpoint_decision_str(receipt, &["actor", "endpointId"]),
            "policyHash": receipt_endpoint_decision_str(receipt, &["policy", "policyHash"]),
        })),
        signed_receipt,
    })
}

fn control_store_receipt_verdict(receipt: &SignedReceipt) -> &'static str {
    if receipt.receipt.verdict.passed {
        "allow"
    } else if receipt_endpoint_decision_str(receipt, &["decision", "action"]) == Some("warn") {
        "warn"
    } else {
        "deny"
    }
}

pub(crate) fn receipt_compaction_record(
    receipt: &SignedReceipt,
    age_seconds: u64,
    removed: bool,
    reason: String,
) -> EdrReceiptCompactionRecord {
    EdrReceiptCompactionRecord {
        receipt_id: receipt.receipt.receipt_id.clone(),
        timestamp: receipt.receipt.timestamp.clone(),
        age_seconds,
        family: receipt_family(receipt).map(ToString::to_string),
        action: receipt_endpoint_decision_str(receipt, &["decision", "action"])
            .map(ToString::to_string),
        finding_id: receipt_endpoint_decision_str(receipt, &["decision", "findingId"])
            .map(ToString::to_string),
        rule_id: receipt_endpoint_decision_str(receipt, &["decision", "ruleId"])
            .map(ToString::to_string),
        graph_slice_id: receipt_endpoint_decision_str(receipt, &["graph", "graphSliceId"])
            .map(ToString::to_string),
        root_node_id: receipt_endpoint_decision_str(receipt, &["graph", "processNodeId"])
            .map(ToString::to_string),
        local_sequence: receipt_local_sequence(receipt),
        removed,
        reason,
    }
}

pub(crate) fn receipt_age_seconds(
    receipt: &SignedReceipt,
    now: chrono::DateTime<chrono::Utc>,
) -> u64 {
    chrono::DateTime::parse_from_rfc3339(&receipt.receipt.timestamp)
        .map(|timestamp| {
            now.signed_duration_since(timestamp.with_timezone(&chrono::Utc))
                .num_seconds()
                .max(0) as u64
        })
        .unwrap_or(0)
}

pub(crate) fn receipt_local_sequence(receipt: &SignedReceipt) -> Option<u64> {
    receipt
        .receipt
        .metadata
        .as_ref()?
        .get("endpointDecision")?
        .get("localSequence")?
        .as_u64()
}

pub(crate) fn receipt_family(receipt: &SignedReceipt) -> Option<&str> {
    receipt_endpoint_decision_str(receipt, &["receiptFamily"])
}

pub(crate) fn receipt_endpoint_decision_graph(
    receipt: &SignedReceipt,
) -> Result<EndpointGraphReference> {
    let graph = receipt_endpoint_decision_value(receipt, &["graph"])
        .ok_or_else(|| anyhow::anyhow!("endpoint receipt is missing graph reference"))?;
    serde_json::from_value(graph.clone()).context("decode endpoint receipt graph reference")
}

pub(crate) fn receipt_endpoint_decision_sensor_state(
    receipt: &SignedReceipt,
) -> Result<EndpointSensorState> {
    let sensor_state = receipt_endpoint_decision_value(receipt, &["sensorState"])
        .ok_or_else(|| anyhow::anyhow!("endpoint receipt is missing sensor state"))?;
    serde_json::from_value(sensor_state.clone()).context("decode endpoint receipt sensor state")
}

fn receipt_endpoint_decision_policy(receipt: &SignedReceipt) -> Result<EndpointPolicySnapshot> {
    let policy = receipt_endpoint_decision_value(receipt, &["policy"])
        .ok_or_else(|| anyhow::anyhow!("endpoint receipt is missing policy snapshot"))?;
    serde_json::from_value(policy.clone()).context("decode endpoint receipt policy snapshot")
}

fn receipt_endpoint_decision_actor(receipt: &SignedReceipt) -> Result<EndpointDecisionActor> {
    let actor = receipt_endpoint_decision_value(receipt, &["actor"])
        .ok_or_else(|| anyhow::anyhow!("endpoint receipt is missing actor"))?;
    serde_json::from_value(actor.clone()).context("decode endpoint receipt actor")
}

pub(crate) fn receipt_endpoint_decision_str<'a>(
    receipt: &'a SignedReceipt,
    path: &[&str],
) -> Option<&'a str> {
    receipt_endpoint_decision_value(receipt, path)?.as_str()
}

fn receipt_endpoint_decision_value<'a>(
    receipt: &'a SignedReceipt,
    path: &[&str],
) -> Option<&'a Value> {
    let mut value = receipt.receipt.metadata.as_ref()?.get("endpointDecision")?;
    for key in path {
        value = value.get(*key)?;
    }
    Some(value)
}

pub(crate) fn protected_observation_ids_for_receipts(
    receipts: &[SignedReceipt],
    graph: &CausalGraph,
) -> BTreeSet<String> {
    let mut observation_ids = BTreeSet::new();
    let mut graph_node_ids = BTreeSet::new();
    let mut graph_edge_ids = BTreeSet::new();

    for receipt in receipts {
        let Some(endpoint_decision) = receipt
            .receipt
            .metadata
            .as_ref()
            .and_then(|metadata| metadata.get("endpointDecision"))
        else {
            continue;
        };

        if let Some(observation_id) = endpoint_decision
            .get("decision")
            .and_then(|decision| decision.get("observationId"))
            .and_then(serde_json::Value::as_str)
            .map(str::trim)
            .filter(|value| !value.is_empty())
        {
            observation_ids.insert(observation_id.to_string());
        }

        let Some(graph_ref) = endpoint_decision.get("graph") else {
            continue;
        };
        if let Some(node_id) = graph_ref
            .get("processNodeId")
            .and_then(serde_json::Value::as_str)
            .map(str::trim)
            .filter(|value| !value.is_empty())
        {
            graph_node_ids.insert(node_id.to_string());
        }
        if let Some(node_ids) = graph_ref
            .get("nodeIds")
            .and_then(serde_json::Value::as_array)
        {
            graph_node_ids.extend(
                node_ids
                    .iter()
                    .filter_map(serde_json::Value::as_str)
                    .map(str::trim)
                    .filter(|value| !value.is_empty())
                    .map(ToString::to_string),
            );
        }
        if let Some(edge_ids) = graph_ref
            .get("edgeIds")
            .and_then(serde_json::Value::as_array)
        {
            graph_edge_ids.extend(
                edge_ids
                    .iter()
                    .filter_map(serde_json::Value::as_str)
                    .map(str::trim)
                    .filter(|value| !value.is_empty())
                    .map(ToString::to_string),
            );
        }
    }

    for edge in &graph.edges {
        if graph_edge_ids.contains(&edge.edge_id)
            || graph_node_ids.contains(&edge.from)
            || graph_node_ids.contains(&edge.to)
        {
            observation_ids.insert(edge.observation_id.clone());
        }
    }

    observation_ids
}

pub(crate) fn detection_severity_from_policy_label(
    value: Option<&str>,
) -> Option<DetectionSeverity> {
    match value?.trim().to_ascii_lowercase().as_str() {
        "info" => Some(DetectionSeverity::Info),
        "low" => Some(DetectionSeverity::Low),
        "medium" => Some(DetectionSeverity::Medium),
        "high" => Some(DetectionSeverity::High),
        "critical" => Some(DetectionSeverity::Critical),
        _ => None,
    }
}

const EDR_RAW_ARTIFACT_POLICY_PATHS: &[(&[&str], &str)] = &[
    (
        &["edr", "telemetry", "raw_artifact_upload"],
        "edr.telemetry.raw_artifact_upload",
    ),
    (
        &["edr", "telemetry", "rawArtifactUpload"],
        "edr.telemetry.rawArtifactUpload",
    ),
    (
        &["endpoint_telemetry", "raw_artifact_upload"],
        "endpoint_telemetry.raw_artifact_upload",
    ),
    (
        &["endpointTelemetry", "rawArtifactUpload"],
        "endpointTelemetry.rawArtifactUpload",
    ),
];

const EDR_POLICY_EPOCH_YAML_PATHS: &[&[&str]] = &[
    &["policy_epoch"],
    &["policyEpoch"],
    &["epoch"],
    &["policy", "epoch"],
    &["policy", "policy_epoch"],
    &["policy", "policyEpoch"],
    &["metadata", "policy_epoch"],
    &["metadata", "policyEpoch"],
    &["bundle", "epoch"],
    &["bundle", "policy_epoch"],
    &["bundle", "policyEpoch"],
];

pub(crate) fn edr_privacy_policy_decision(
    settings: &Settings,
    requested_privacy_mode: EndpointTelemetryPrivacyMode,
    raw_artifact_approval: Option<&EdrRawArtifactApproval>,
) -> Result<EdrPrivacyPolicyDecision> {
    let raw_policy = edr_raw_artifact_upload_policy(settings)?;
    let raw_artifact_upload_requested = requested_privacy_mode.permits_raw_artifacts();
    let raw_artifact_approval_required = raw_artifact_upload_requested && raw_policy.allowed;
    let denied_reason = if raw_artifact_upload_requested && !raw_policy.allowed {
        Some(
            "raw_artifact_permitted was requested, but the local policy does not allow raw artifact upload"
                .to_string(),
        )
    } else if raw_artifact_approval_required && raw_artifact_approval.is_none() {
        Some(
            "raw_artifact_permitted was requested and local policy allows raw artifact upload, but rawArtifactApprovalId and rawArtifactApprovalReason are required"
                .to_string(),
        )
    } else {
        None
    };
    let effective_privacy_mode = if denied_reason.is_some() {
        EndpointTelemetryPrivacyMode::HashesFeatures
    } else {
        requested_privacy_mode.clone()
    };
    let effective_raw_artifact_approval = effective_privacy_mode
        .permits_raw_artifacts()
        .then_some(raw_artifact_approval)
        .flatten();

    Ok(EdrPrivacyPolicyDecision {
        requested_privacy_mode,
        effective_privacy_mode,
        raw_artifact_upload_requested,
        raw_artifact_upload_allowed: raw_policy.allowed,
        raw_artifact_approval_required,
        raw_artifact_approval_provided: raw_artifact_approval.is_some(),
        raw_artifact_approval_id: effective_raw_artifact_approval
            .map(|approval| approval.approval_id.clone()),
        raw_artifact_approval_reason_hash: effective_raw_artifact_approval
            .map(|approval| approval.reason_hash.clone()),
        policy_source: raw_policy.source,
        denied_reason,
    })
}

pub(crate) fn validate_raw_artifact_approval(
    input: &EdrPrivacyReportInput,
) -> Result<Option<EdrRawArtifactApproval>, (StatusCode, String)> {
    validate_raw_artifact_approval_fields(
        input.raw_artifact_approval_id.as_deref(),
        input.raw_artifact_approval_reason.as_deref(),
    )
}

pub(crate) fn validate_raw_artifact_approval_fields(
    approval_id: Option<&str>,
    approval_reason: Option<&str>,
) -> Result<Option<EdrRawArtifactApproval>, (StatusCode, String)> {
    let approval_id = trimmed_owned(approval_id);
    let approval_reason = trimmed_owned(approval_reason);
    if let Some(approval_id) = approval_id.as_deref() {
        if approval_id.len() > EDR_MAX_RAW_ARTIFACT_APPROVAL_ID_BYTES {
            return Err((
                StatusCode::BAD_REQUEST,
                format!(
                    "rawArtifactApprovalId must be at most {EDR_MAX_RAW_ARTIFACT_APPROVAL_ID_BYTES} bytes"
                ),
            ));
        }
    }
    if let Some(reason) = approval_reason.as_deref() {
        if reason.len() > EDR_MAX_RAW_ARTIFACT_APPROVAL_REASON_BYTES {
            return Err((
                StatusCode::BAD_REQUEST,
                format!(
                    "rawArtifactApprovalReason must be at most {EDR_MAX_RAW_ARTIFACT_APPROVAL_REASON_BYTES} bytes"
                ),
            ));
        }
    }

    match (approval_id, approval_reason) {
        (Some(approval_id), Some(approval_reason)) => Ok(Some(EdrRawArtifactApproval {
            approval_id,
            reason_hash: sha256(approval_reason.as_bytes()).to_hex_prefixed(),
        })),
        (None, None) => Ok(None),
        _ => Err((
            StatusCode::BAD_REQUEST,
            "rawArtifactApprovalId and rawArtifactApprovalReason must be provided together"
                .to_string(),
        )),
    }
}

pub(crate) fn raw_artifact_approval_resource_for_privacy_report() -> String {
    format!("{EDR_RAW_ARTIFACT_UPLOAD_GUARD}:privacy_report")
}

pub(crate) fn raw_artifact_approval_resource_for_evidence_bundle_fleet_publish(
    bundle_id: &str,
) -> String {
    format!(
        "{EDR_RAW_ARTIFACT_UPLOAD_GUARD}:evidence_bundle_fleet_publish:{}",
        bundle_id.trim()
    )
}

pub(crate) fn raw_artifact_approval_resource_for_control_archive_backfill(
    bundle_id: Option<&str>,
) -> String {
    match bundle_id.and_then(|value| trimmed_owned(Some(value))) {
        Some(bundle_id) => {
            format!("{EDR_RAW_ARTIFACT_UPLOAD_GUARD}:control_archive_backfill:{bundle_id}")
        }
        None => format!("{EDR_RAW_ARTIFACT_UPLOAD_GUARD}:control_archive_backfill_batch"),
    }
}

pub(crate) async fn validate_resolved_raw_artifact_approval(
    state: &AgentApiState,
    raw_artifact_approval: Option<EdrRawArtifactApproval>,
    expected_resource: &str,
) -> Result<Option<EdrRawArtifactApproval>, (StatusCode, String)> {
    let Some(raw_artifact_approval) = raw_artifact_approval else {
        return Ok(None);
    };
    let approval_status = state
        .approval_queue
        .get_status(&raw_artifact_approval.approval_id)
        .await
        .ok_or_else(|| {
            (
                StatusCode::CONFLICT,
                "rawArtifactApprovalId does not reference a local approval request".to_string(),
            )
        })?;
    if approval_status.status != ApprovalStatus::Resolved {
        return Err((
            StatusCode::CONFLICT,
            "rawArtifactApprovalId must reference a resolved local approval request".to_string(),
        ));
    }
    match approval_status.resolution {
        Some(
            ApprovalResolution::AllowOnce
            | ApprovalResolution::AllowSession
            | ApprovalResolution::AllowAlways,
        ) => {}
        Some(ApprovalResolution::Deny) | None => {
            return Err((
                StatusCode::CONFLICT,
                "rawArtifactApprovalId must reference an allowed local approval request"
                    .to_string(),
            ));
        }
    }
    if !approval_status.resolved_by_trusted_authority {
        return Err((
            StatusCode::CONFLICT,
            "rawArtifactApprovalId must be resolved by a trusted UI or signed control-plane authority"
                .to_string(),
        ));
    }
    if approval_status.guard != EDR_RAW_ARTIFACT_UPLOAD_GUARD {
        return Err((
            StatusCode::CONFLICT,
            "rawArtifactApprovalId must reference an endpoint.telemetry.raw_artifact_upload approval"
                .to_string(),
        ));
    }
    if approval_status.resource != expected_resource {
        return Err((
            StatusCode::CONFLICT,
            format!(
                "rawArtifactApprovalId must reference resource {expected_resource} for this raw artifact upload"
            ),
        ));
    }
    let expected_reason_hash = sha256(approval_status.reason.as_bytes()).to_hex_prefixed();
    if raw_artifact_approval.reason_hash != expected_reason_hash {
        return Err((
            StatusCode::CONFLICT,
            "rawArtifactApprovalReason does not match the resolved approval request".to_string(),
        ));
    }
    state
        .approval_queue
        .consume_allow_once(&raw_artifact_approval.approval_id)
        .await
        .map_err(|err| {
            (
                StatusCode::CONFLICT,
                format!("rawArtifactApprovalId could not be consumed: {err}"),
            )
        })?;
    Ok(Some(raw_artifact_approval))
}

fn edr_raw_artifact_upload_policy(settings: &Settings) -> Result<EdrRawArtifactUploadPolicy> {
    let bytes = fs::read(&settings.policy_path).with_context(|| {
        format!(
            "read local policy for endpoint telemetry privacy {}",
            settings.policy_path.display()
        )
    })?;
    let policy_prefix = format!("policy:{}#", settings.policy_path.display());
    let value = match serde_yaml::from_slice::<serde_yaml::Value>(&bytes) {
        Ok(value) => value,
        Err(_) => {
            return Ok(EdrRawArtifactUploadPolicy {
                allowed: false,
                source: format!("{policy_prefix}default-deny-invalid-yaml"),
            });
        }
    };

    for (path, label) in EDR_RAW_ARTIFACT_POLICY_PATHS {
        if let Some(allowed) = yaml_bool_at_path(&value, path) {
            return Ok(EdrRawArtifactUploadPolicy {
                allowed,
                source: format!("{policy_prefix}{label}"),
            });
        }
    }

    Ok(EdrRawArtifactUploadPolicy {
        allowed: false,
        source: format!("{policy_prefix}default-deny"),
    })
}

fn yaml_bool_at_path(value: &serde_yaml::Value, path: &[&str]) -> Option<bool> {
    let mut current = value;
    for segment in path {
        current = current.get(*segment)?;
    }
    yaml_bool_value(current)
}

fn yaml_bool_value(value: &serde_yaml::Value) -> Option<bool> {
    match value {
        serde_yaml::Value::Bool(value) => Some(*value),
        serde_yaml::Value::String(value) => match value.trim().to_ascii_lowercase().as_str() {
            "true" | "allow" | "allowed" | "enabled" | "yes" => Some(true),
            "false" | "deny" | "denied" | "disabled" | "no" => Some(false),
            _ => None,
        },
        _ => None,
    }
}

pub(crate) fn endpoint_policy_snapshot_from_settings(
    settings: &Settings,
) -> Result<EndpointPolicySnapshot> {
    let bytes = fs::read(&settings.policy_path).with_context(|| {
        format!(
            "read local policy for endpoint receipt {}",
            settings.policy_path.display()
        )
    })?;
    endpoint_policy_snapshot_from_policy_bytes(&bytes, &settings.policy_path)
}

pub(crate) fn endpoint_policy_snapshot_from_policy_bytes(
    bytes: &[u8],
    policy_path: &FsPath,
) -> Result<EndpointPolicySnapshot> {
    let policy_hash = sha256(bytes).to_hex_prefixed();
    let policy_version =
        policy_version_from_yaml(bytes).unwrap_or_else(|| format!("local-policy:{policy_hash}"));
    let policy_epoch = policy_epoch_from_yaml(bytes)
        .or_else(|| policy_epoch_from_file(policy_path))
        .unwrap_or(1)
        .max(1);
    Ok(EndpointPolicySnapshot {
        policy_version,
        policy_hash,
        policy_epoch,
    })
}

fn endpoint_policy_snapshot_from_memory_policy_bytes(
    bytes: &[u8],
) -> Result<EndpointPolicySnapshot> {
    let policy_hash = sha256(bytes).to_hex_prefixed();
    let policy_version =
        policy_version_from_yaml(bytes).unwrap_or_else(|| format!("local-policy:{policy_hash}"));
    let policy_epoch = policy_epoch_from_yaml(bytes).ok_or_else(|| {
        anyhow::anyhow!("proposedPolicyYaml must declare a positive policy_epoch")
    })?;
    Ok(EndpointPolicySnapshot {
        policy_version,
        policy_hash,
        policy_epoch,
    })
}

fn policy_version_from_yaml(bytes: &[u8]) -> Option<String> {
    let value = serde_yaml::from_slice::<serde_yaml::Value>(bytes).ok()?;
    value
        .get("version")
        .and_then(serde_yaml::Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToString::to_string)
}

pub(crate) fn policy_epoch_from_yaml(bytes: &[u8]) -> Option<u64> {
    let value = serde_yaml::from_slice::<serde_yaml::Value>(bytes).ok()?;
    EDR_POLICY_EPOCH_YAML_PATHS
        .iter()
        .filter_map(|path| yaml_u64_at_path(&value, path))
        .find(|epoch| *epoch > 0)
}

fn yaml_u64_at_path(value: &serde_yaml::Value, path: &[&str]) -> Option<u64> {
    let mut current = value;
    for segment in path {
        current = current.get(*segment)?;
    }
    yaml_u64_value(current)
}

fn yaml_u64_value(value: &serde_yaml::Value) -> Option<u64> {
    match value {
        serde_yaml::Value::Number(value) => value.as_u64(),
        serde_yaml::Value::String(value) => value.trim().parse::<u64>().ok(),
        _ => None,
    }
}

fn policy_epoch_from_file(path: &FsPath) -> Option<u64> {
    let modified = fs::metadata(path).ok()?.modified().ok()?;
    let since_epoch = modified.duration_since(std::time::UNIX_EPOCH).ok()?;
    Some(since_epoch.as_secs())
}

pub(crate) fn endpoint_id_for_observation(
    settings: &Settings,
    observation: &EndpointObservation,
) -> String {
    settings
        .enrollment
        .agent_uuid
        .clone()
        .or_else(|| settings.local_agent_id.clone())
        .or_else(|| observation.host_id.clone())
        .unwrap_or_else(crate::settings::hostname_best_effort)
}

pub(crate) fn endpoint_id_for_settings(settings: &Settings) -> String {
    settings
        .enrollment
        .agent_uuid
        .clone()
        .or_else(|| settings.local_agent_id.clone())
        .unwrap_or_else(crate::settings::hostname_best_effort)
}

fn endpoint_response_actor_from_session(
    settings: &Settings,
    session_state: &SessionState,
    agent_id: &str,
) -> EndpointDecisionActor {
    EndpointDecisionActor {
        endpoint_id: endpoint_id_for_settings(settings),
        session_id: session_state.session_id.clone(),
        posture: Some(session_state.posture.clone()),
        agent_id: Some(agent_id.to_string()),
        workload_id: Some("endpoint-response-engine".to_string()),
        ..EndpointDecisionActor::default()
    }
}

pub(crate) fn endpoint_response_actor_from_action_input(
    settings: &Settings,
    session_state: &SessionState,
    agent_id: &str,
    input: Option<&EdrResponseActionActorInput>,
) -> EndpointDecisionActor {
    let mut actor = endpoint_response_actor_from_session(settings, session_state, agent_id);
    let Some(input) = input else {
        return actor;
    };

    if let Some(endpoint_id) = trimmed_owned(Some(input.endpoint_id.as_str())) {
        actor.endpoint_id = endpoint_id;
    }
    if let Some(host_id) = trimmed_owned(input.host_id.as_deref()) {
        actor.host_id = Some(host_id);
    }
    if let Some(user_id) = trimmed_owned(input.user_id.as_deref()) {
        actor.user_id = Some(user_id);
    }
    if let Some(session_id) = trimmed_owned(input.session_id.as_deref()) {
        actor.session_id = Some(session_id);
    }
    if let Some(posture) = trimmed_owned(input.posture.as_deref()) {
        actor.posture = Some(posture);
    }
    if let Some(agent_id) = trimmed_owned(input.agent_id.as_deref()) {
        actor.agent_id = Some(agent_id);
    }
    if let Some(workload_id) = trimmed_owned(input.workload_id.as_deref()) {
        actor.workload_id = Some(workload_id);
    }
    if let Some(approval_id) = trimmed_owned(input.approval_id.as_deref()) {
        actor.approval_id = Some(approval_id);
    }
    actor
}

pub(crate) fn endpoint_sensor_state_from_macos_host(
    status: &CombinedSystemExtensionStatus,
) -> EndpointSensorState {
    EndpointSensorState {
        providers: vec![
            EndpointProviderState {
                provider_id: "agent-api".to_string(),
                provider_kind: EndpointProviderKind::AgentApi,
                installed: true,
                active: true,
                healthy: true,
                degraded: false,
                degradation_reasons: Vec::new(),
                dropped_event_count: 0,
                deadline_miss_count: 0,
                full_disk_access: None,
                last_seen: Some(chrono::Utc::now()),
            },
            endpoint_provider_state_from_macos_provider(
                "macos.endpoint_security",
                EndpointProviderKind::EndpointSecurity,
                status,
                &status.endpoint_security,
            ),
            endpoint_provider_state_from_macos_provider(
                "macos.network_extension",
                EndpointProviderKind::NetworkExtension,
                status,
                &status.network_extension,
            ),
        ],
    }
}

pub(crate) fn endpoint_provider_recoveries(
    previous_status: Option<&CombinedSystemExtensionStatus>,
    current_sensor_state: &EndpointSensorState,
) -> Vec<EdrProviderRecovery> {
    let Some(previous_status) = previous_status else {
        return Vec::new();
    };
    let previous_sensor_state = endpoint_sensor_state_from_macos_host(previous_status);
    let previous_providers = previous_sensor_state
        .providers
        .into_iter()
        .map(|provider| (provider.provider_id.clone(), provider))
        .collect::<BTreeMap<_, _>>();
    let mut recoveries = current_sensor_state
        .providers
        .iter()
        .filter_map(|current| {
            let previous = previous_providers.get(&current.provider_id)?;
            if !previous.installed
                || !previous.degraded
                || current.degraded
                || !current.healthy
                || !current.active
            {
                return None;
            }
            Some(EdrProviderRecovery {
                provider_id: current.provider_id.clone(),
                provider_kind: current.provider_kind.clone(),
                previous_active: previous.active,
                previous_healthy: previous.healthy,
                previous_degraded: previous.degraded,
                previous_degradation_reasons: previous.degradation_reasons.clone(),
                current_active: current.active,
                current_healthy: current.healthy,
                current_degraded: current.degraded,
                recovered_at: current.last_seen,
            })
        })
        .collect::<Vec<_>>();
    recoveries.sort_by(|left, right| left.provider_id.cmp(&right.provider_id));
    recoveries
}

pub(crate) fn provider_recovery_receipt_evidence(
    recoveries: &[EdrProviderRecovery],
) -> Vec<EndpointReceiptEvidence> {
    if recoveries.is_empty() {
        return Vec::new();
    }
    let recovered_ids = recoveries
        .iter()
        .map(|recovery| recovery.provider_id.as_str())
        .collect::<Vec<_>>()
        .join(",");
    vec![
        EndpointReceiptEvidence::hashed("providerRecoveryCount", recoveries.len().to_string()),
        EndpointReceiptEvidence::hashed("providerRecoveredIds", recovered_ids),
    ]
}

fn network_extension_response_execution_evidence(
    provider: &ProviderStatus,
) -> Vec<EndpointReceiptEvidence> {
    let mut evidence = vec![
        EndpointReceiptEvidence::hashed(
            "networkExtensionRuntime",
            provider_runtime_evidence_value(&provider.runtime),
        ),
        EndpointReceiptEvidence::hashed(
            "networkExtensionPolicySynced",
            optional_bool_evidence_value(provider.policy_synced),
        ),
        EndpointReceiptEvidence::hashed(
            "networkExtensionEnforcementReady",
            optional_bool_evidence_value(provider.enforcement_ready),
        ),
        EndpointReceiptEvidence::hashed(
            "networkExtensionPolicyEpoch",
            optional_u64_evidence_value(provider.policy_epoch),
        ),
        EndpointReceiptEvidence::hashed(
            "networkExtensionFlowsObserved",
            provider_counter(provider, &["flows_observed"]).to_string(),
        ),
        EndpointReceiptEvidence::hashed(
            "networkExtensionFlowsBlocked",
            provider_counter(provider, &["flows_blocked"]).to_string(),
        ),
        EndpointReceiptEvidence::hashed(
            "networkExtensionRemediationRequests",
            provider_counter(provider, &["remediation_requests"]).to_string(),
        ),
        EndpointReceiptEvidence::hashed(
            "networkExtensionDroppedVerdicts",
            provider_counter(provider, &["dropped_verdicts"]).to_string(),
        ),
        EndpointReceiptEvidence::hashed(
            "networkExtensionReloadObserved",
            provider.last_reload_observation.is_some().to_string(),
        ),
    ];
    if let Some(observation) = provider.last_reload_observation.as_ref() {
        if let Some(command) = observation
            .command
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
        {
            evidence.push(EndpointReceiptEvidence::hashed(
                "networkExtensionReloadObservedCommand",
                command,
            ));
        }
        if let Some(request_id) = observation
            .request_id
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
        {
            evidence.push(EndpointReceiptEvidence::hashed(
                "networkExtensionReloadObservedRequestId",
                request_id,
            ));
        }
        if let Some(policy_snapshot_path) = observation
            .policy_snapshot_path
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
        {
            evidence.push(EndpointReceiptEvidence::hashed(
                "networkExtensionReloadObservedPolicySnapshotPath",
                policy_snapshot_path,
            ));
        }
        if let Some(generation) = observation.generation {
            evidence.push(EndpointReceiptEvidence::hashed(
                "networkExtensionReloadObservedGeneration",
                generation.to_string(),
            ));
        }
        if let Some(accepted) = observation.accepted {
            evidence.push(EndpointReceiptEvidence::hashed(
                "networkExtensionReloadObservedAccepted",
                accepted.to_string(),
            ));
        }
        if let Some(reloaded) = observation.reloaded {
            evidence.push(EndpointReceiptEvidence::hashed(
                "networkExtensionReloadObservedReloaded",
                reloaded.to_string(),
            ));
        }
        if let Some(error) = observation
            .error
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
        {
            evidence.push(EndpointReceiptEvidence::hashed(
                "networkExtensionReloadObservedError",
                error,
            ));
        }
    }
    if let Some(last_error) = provider
        .last_error
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
    {
        evidence.push(EndpointReceiptEvidence::hashed(
            "networkExtensionLastError",
            last_error,
        ));
    }
    evidence
}

pub(crate) struct NetworkExtensionFlowCounterSummary {
    pub(crate) flow_counter_observed: bool,
    pub(crate) observed_flow_count: u64,
    pub(crate) blocked_flow_count: u64,
    pub(crate) remediation_request_count: u64,
    pub(crate) dropped_verdict_count: u64,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct NetworkExtensionReloadRequestProof {
    pub(crate) requested: bool,
    pub(crate) saved: bool,
    pub(crate) request_id: Option<String>,
    pub(crate) policy_snapshot_path: String,
    pub(crate) generation: u64,
    pub(crate) provider_reload_observed: bool,
    pub(crate) provider_reload_matched: bool,
    pub(crate) provider_reload_request_id_matches: bool,
    pub(crate) provider_reload_generation_matches: bool,
    pub(crate) provider_reload_policy_snapshot_path_matches: bool,
    pub(crate) provider_reloaded: Option<bool>,
    pub(crate) provider_policy_synced: Option<bool>,
    pub(crate) provider_enforcement_ready: Option<bool>,
    pub(crate) provider_reload_elapsed_ms: u64,
    pub(crate) provider_reload_attempts: u64,
    pub(crate) error: Option<String>,
}

pub(crate) fn network_extension_flow_counter_summary(
    provider: &ProviderStatus,
) -> NetworkExtensionFlowCounterSummary {
    let observed_flow_count = provider_counter(provider, &["flows_observed"]);
    let blocked_flow_count = provider_counter(provider, &["flows_blocked"]);
    let remediation_request_count = provider_counter(provider, &["remediation_requests"]);
    let dropped_verdict_count = provider_counter(provider, &["dropped_verdicts"]);
    NetworkExtensionFlowCounterSummary {
        flow_counter_observed: observed_flow_count > 0 || blocked_flow_count > 0,
        observed_flow_count,
        blocked_flow_count,
        remediation_request_count,
        dropped_verdict_count,
    }
}

pub(crate) struct NetworkExtensionLiveEnforcementProof {
    pub(crate) proven: bool,
    pub(crate) reasons: Vec<String>,
}

pub(crate) struct NetworkExtensionLiveEnforcementProofInput<'a> {
    pub(crate) snapshot_present: bool,
    pub(crate) snapshot_decodable: bool,
    pub(crate) active_restriction_count: usize,
    pub(crate) enforcement_ready: bool,
    pub(crate) flow_counters: &'a NetworkExtensionFlowCounterSummary,
    pub(crate) execution_id_provided: bool,
    pub(crate) provider_reload_delivery: Option<&'a EdrNetworkExtensionReloadDeliveryProof>,
}

pub(crate) fn network_extension_live_enforcement_proof(
    input: NetworkExtensionLiveEnforcementProofInput<'_>,
) -> NetworkExtensionLiveEnforcementProof {
    let mut reasons = Vec::new();
    if !input.snapshot_present {
        reasons.push("snapshot_missing".to_string());
    }
    if !input.snapshot_decodable {
        reasons.push("snapshot_not_decodable".to_string());
    }
    if input.active_restriction_count == 0 {
        reasons.push("no_active_restrictions".to_string());
    }
    if !input.enforcement_ready {
        reasons.push("provider_not_enforcement_ready".to_string());
    }
    if !input.flow_counters.flow_counter_observed {
        reasons.push("flow_counters_not_observed".to_string());
    }
    if input.flow_counters.blocked_flow_count == 0 {
        reasons.push("blocked_flow_counter_zero".to_string());
    }
    if input.flow_counters.dropped_verdict_count > 0 {
        reasons.push("dropped_verdicts_observed".to_string());
    }
    if !input.execution_id_provided {
        reasons.push("execution_id_required".to_string());
    }
    match input.provider_reload_delivery {
        Some(delivery) if delivery.matched => {}
        Some(_) => reasons.push("reload_delivery_not_matched".to_string()),
        None => reasons.push("reload_delivery_missing".to_string()),
    }
    reasons.sort();
    reasons.dedup();

    NetworkExtensionLiveEnforcementProof {
        proven: reasons.is_empty(),
        reasons,
    }
}

fn network_extension_reload_request_evidence(
    proof: &NetworkExtensionReloadRequestProof,
) -> Vec<EndpointReceiptEvidence> {
    let mut evidence = vec![
        EndpointReceiptEvidence::hashed(
            "networkExtensionReloadRequested",
            proof.requested.to_string(),
        ),
        EndpointReceiptEvidence::hashed("networkExtensionReloadSaved", proof.saved.to_string()),
        EndpointReceiptEvidence::hashed(
            "networkExtensionReloadGeneration",
            proof.generation.to_string(),
        ),
        EndpointReceiptEvidence::hashed(
            "networkExtensionReloadPolicySnapshotPath",
            proof.policy_snapshot_path.as_str(),
        ),
        EndpointReceiptEvidence::hashed(
            "networkExtensionReloadProviderObserved",
            proof.provider_reload_observed.to_string(),
        ),
        EndpointReceiptEvidence::hashed(
            "networkExtensionReloadProviderMatched",
            proof.provider_reload_matched.to_string(),
        ),
        EndpointReceiptEvidence::hashed(
            "networkExtensionReloadProviderRequestIdMatches",
            proof.provider_reload_request_id_matches.to_string(),
        ),
        EndpointReceiptEvidence::hashed(
            "networkExtensionReloadProviderGenerationMatches",
            proof.provider_reload_generation_matches.to_string(),
        ),
        EndpointReceiptEvidence::hashed(
            "networkExtensionReloadProviderPolicySnapshotPathMatches",
            proof
                .provider_reload_policy_snapshot_path_matches
                .to_string(),
        ),
        EndpointReceiptEvidence::hashed(
            "networkExtensionReloadProviderAttempts",
            proof.provider_reload_attempts.to_string(),
        ),
        EndpointReceiptEvidence::hashed(
            "networkExtensionReloadProviderElapsedMs",
            proof.provider_reload_elapsed_ms.to_string(),
        ),
    ];
    if let Some(reloaded) = proof.provider_reloaded {
        evidence.push(EndpointReceiptEvidence::hashed(
            "networkExtensionReloadProviderReloaded",
            reloaded.to_string(),
        ));
    }
    if let Some(policy_synced) = proof.provider_policy_synced {
        evidence.push(EndpointReceiptEvidence::hashed(
            "networkExtensionReloadProviderPolicySynced",
            policy_synced.to_string(),
        ));
    }
    if let Some(enforcement_ready) = proof.provider_enforcement_ready {
        evidence.push(EndpointReceiptEvidence::hashed(
            "networkExtensionReloadProviderEnforcementReady",
            enforcement_ready.to_string(),
        ));
    }
    if let Some(request_id) = proof.request_id.as_deref() {
        evidence.push(EndpointReceiptEvidence::hashed(
            "networkExtensionReloadRequestId",
            request_id,
        ));
    }
    if let Some(error) = proof.error.as_deref() {
        evidence.push(EndpointReceiptEvidence::hashed(
            "networkExtensionReloadError",
            error,
        ));
    }
    evidence
}

pub(crate) async fn network_extension_reload_delivery_for_execution(
    state: &AgentApiState,
    execution_id: Option<&str>,
    provider: &ProviderStatus,
) -> Result<Option<EdrNetworkExtensionReloadDeliveryProof>, (StatusCode, String)> {
    let Some(execution_id) = execution_id
        .map(str::trim)
        .filter(|value| !value.is_empty())
    else {
        return Ok(None);
    };
    let execution = {
        let ledger = state.edr_response_execution_ledger.lock().await;
        ledger
            .get(execution_id)
            .map_err(internal_error)?
            .ok_or_else(|| {
                (
                    StatusCode::NOT_FOUND,
                    format!("response execution not found: {execution_id}"),
                )
            })?
    };
    if execution.action != EndpointDecisionAction::RestrictEgress {
        return Err((
            StatusCode::CONFLICT,
            format!(
                "response execution {} is {}, not restrict_egress",
                execution.execution_id,
                execution.action.as_str()
            ),
        ));
    }
    let execution_receipt = {
        let ledger = state.edr_receipt_ledger.lock().await;
        latest_required_receipt(
            &ledger,
            "response_execution",
            execution.execution_id.as_str(),
            "response execution receipt",
        )
        .or_else(|err| {
            if err.0 == StatusCode::NOT_FOUND {
                latest_required_receipt_by_execution_id(
                    &ledger,
                    "response_execution",
                    execution.execution_id.as_str(),
                    "response execution receipt",
                )
            } else {
                Err(err)
            }
        })?
    };

    let observation = provider.last_reload_observation.as_ref();
    let request_id_matches = observation
        .and_then(|observation| observation.request_id.as_deref())
        .is_some_and(|request_id| {
            receipt_evidence_hash_matches(
                &execution_receipt,
                "networkExtensionReloadRequestId",
                request_id,
            )
        });
    let generation_matches = observation
        .and_then(|observation| observation.generation)
        .is_some_and(|generation| {
            receipt_evidence_hash_matches(
                &execution_receipt,
                "networkExtensionReloadGeneration",
                generation.to_string().as_str(),
            )
        });
    let policy_snapshot_path_matches = observation
        .and_then(|observation| observation.policy_snapshot_path.as_deref())
        .is_some_and(|policy_snapshot_path| {
            receipt_evidence_hash_matches(
                &execution_receipt,
                "networkExtensionReloadPolicySnapshotPath",
                policy_snapshot_path,
            )
        });
    let requested = receipt_evidence_hash_matches(
        &execution_receipt,
        "networkExtensionReloadRequested",
        "true",
    );
    let saved =
        receipt_evidence_hash_matches(&execution_receipt, "networkExtensionReloadSaved", "true");
    let provider_reloaded = observation.and_then(|observation| observation.reloaded);
    let matched = requested
        && saved
        && request_id_matches
        && generation_matches
        && policy_snapshot_path_matches
        && provider_reloaded == Some(true);

    Ok(Some(EdrNetworkExtensionReloadDeliveryProof {
        execution_id: execution.execution_id,
        observed: observation.is_some(),
        matched,
        request_id_matches,
        generation_matches,
        policy_snapshot_path_matches,
        provider_reloaded,
    }))
}

pub(crate) struct NetworkExtensionEgressPolicyProofEvidenceInput<'a> {
    pub(crate) provider_policy_path: &'a FsPath,
    pub(crate) snapshot_present: bool,
    pub(crate) snapshot_decodable: bool,
    pub(crate) snapshot_hash: Option<&'a str>,
    pub(crate) generated_at: Option<&'a chrono::DateTime<chrono::Utc>>,
    pub(crate) restriction_count: usize,
    pub(crate) active_restriction_count: usize,
    pub(crate) expired_restriction_count: usize,
    pub(crate) enforcement_ready: bool,
    pub(crate) live_enforcement_proven: bool,
    pub(crate) live_enforcement_proof_reasons: &'a [String],
    pub(crate) flow_counter_observed: bool,
    pub(crate) provider: &'a ProviderStatus,
    pub(crate) provider_status_refresh: &'a EdrProviderStatusRefreshResult,
    pub(crate) provider_reload_delivery: Option<&'a EdrNetworkExtensionReloadDeliveryProof>,
}

pub(crate) fn network_extension_egress_policy_proof_evidence(
    input: NetworkExtensionEgressPolicyProofEvidenceInput<'_>,
) -> Vec<EndpointReceiptEvidence> {
    let mut evidence = vec![
        EndpointReceiptEvidence::hashed(
            "networkExtensionEgressPolicyPath",
            input.provider_policy_path.display().to_string(),
        ),
        EndpointReceiptEvidence::hashed(
            "networkExtensionEgressPolicySnapshotPresent",
            input.snapshot_present.to_string(),
        ),
        EndpointReceiptEvidence::hashed(
            "networkExtensionEgressPolicySnapshotDecodable",
            input.snapshot_decodable.to_string(),
        ),
        EndpointReceiptEvidence::hashed(
            "networkExtensionEgressPolicyRestrictionCount",
            input.restriction_count.to_string(),
        ),
        EndpointReceiptEvidence::hashed(
            "networkExtensionEgressPolicyActiveRestrictionCount",
            input.active_restriction_count.to_string(),
        ),
        EndpointReceiptEvidence::hashed(
            "networkExtensionEgressPolicyExpiredRestrictionCount",
            input.expired_restriction_count.to_string(),
        ),
        EndpointReceiptEvidence::hashed(
            "networkExtensionEgressPolicyEnforcementReady",
            input.enforcement_ready.to_string(),
        ),
        EndpointReceiptEvidence::hashed(
            "networkExtensionLiveEnforcementProven",
            input.live_enforcement_proven.to_string(),
        ),
        EndpointReceiptEvidence::hashed(
            "networkExtensionLiveEnforcementProofReasons",
            input.live_enforcement_proof_reasons.join(","),
        ),
        EndpointReceiptEvidence::hashed(
            "networkExtensionFlowCounterObserved",
            input.flow_counter_observed.to_string(),
        ),
        EndpointReceiptEvidence::hashed(
            "networkExtensionEgressPolicyProviderRefreshRequested",
            input.provider_status_refresh.requested.to_string(),
        ),
        EndpointReceiptEvidence::hashed(
            "networkExtensionEgressPolicyProviderRefreshRefreshed",
            input.provider_status_refresh.refreshed.to_string(),
        ),
        EndpointReceiptEvidence::hashed(
            "networkExtensionEgressPolicyProviderRefreshTimeoutMs",
            input.provider_status_refresh.timeout_ms.to_string(),
        ),
        EndpointReceiptEvidence::hashed(
            "networkExtensionEgressPolicyProviderRefreshElapsedMs",
            input.provider_status_refresh.elapsed_ms.to_string(),
        ),
    ];
    if let Some(snapshot_hash) = input.snapshot_hash.filter(|value| !value.trim().is_empty()) {
        evidence.push(EndpointReceiptEvidence {
            key: "networkExtensionEgressPolicySnapshotHash".to_string(),
            value_hash: snapshot_hash.to_string(),
            redaction_class: EndpointEvidenceRedactionClass::HashOnly,
            raw_value: None,
        });
    }
    if let Some(generated_at) = input.generated_at {
        evidence.push(EndpointReceiptEvidence::hashed(
            "networkExtensionEgressPolicyGeneratedAt",
            generated_at.to_rfc3339(),
        ));
    }
    if let Some(error) = input.provider_status_refresh.error.as_deref() {
        evidence.push(EndpointReceiptEvidence::hashed(
            "networkExtensionEgressPolicyProviderRefreshError",
            error,
        ));
    }
    if let Some(delivery) = input.provider_reload_delivery {
        evidence.extend([
            EndpointReceiptEvidence::hashed(
                "networkExtensionReloadDeliveryExecutionId",
                delivery.execution_id.as_str(),
            ),
            EndpointReceiptEvidence::hashed(
                "networkExtensionReloadDeliveryObserved",
                delivery.observed.to_string(),
            ),
            EndpointReceiptEvidence::hashed(
                "networkExtensionReloadDeliveryMatched",
                delivery.matched.to_string(),
            ),
            EndpointReceiptEvidence::hashed(
                "networkExtensionReloadDeliveryRequestIdMatches",
                delivery.request_id_matches.to_string(),
            ),
            EndpointReceiptEvidence::hashed(
                "networkExtensionReloadDeliveryGenerationMatches",
                delivery.generation_matches.to_string(),
            ),
            EndpointReceiptEvidence::hashed(
                "networkExtensionReloadDeliveryPolicySnapshotPathMatches",
                delivery.policy_snapshot_path_matches.to_string(),
            ),
            EndpointReceiptEvidence::hashed(
                "networkExtensionReloadDeliveryProviderReloaded",
                optional_bool_evidence_value(delivery.provider_reloaded),
            ),
        ]);
    }
    evidence.extend(network_extension_response_execution_evidence(
        input.provider,
    ));
    evidence
}

fn provider_runtime_evidence_value(runtime: &ProviderRuntimeState) -> String {
    match runtime {
        ProviderRuntimeState::Unknown => "unknown".to_string(),
        ProviderRuntimeState::Inactive => "inactive".to_string(),
        ProviderRuntimeState::Active => "active".to_string(),
        ProviderRuntimeState::Degraded { reason } => {
            format!("degraded:{}", sanitize_provider_status_reason(reason))
        }
    }
}

fn optional_bool_evidence_value(value: Option<bool>) -> &'static str {
    match value {
        Some(true) => "true",
        Some(false) => "false",
        None => "unknown",
    }
}

fn optional_u64_evidence_value(value: Option<u64>) -> String {
    value
        .map(|value| value.to_string())
        .unwrap_or_else(|| "unknown".to_string())
}

fn endpoint_provider_state_from_macos_provider(
    provider_id: &str,
    provider_kind: EndpointProviderKind,
    host_status: &CombinedSystemExtensionStatus,
    provider: &ProviderStatus,
) -> EndpointProviderState {
    let installed = host_status.install_state == SystemExtensionInstallState::Installed
        || provider
            .provider_state
            .as_ref()
            .map(|state| state.installed)
            .unwrap_or(false);
    let active = matches!(provider.runtime, ProviderRuntimeState::Active)
        || provider
            .provider_state
            .as_ref()
            .map(|state| state.active)
            .unwrap_or(false);
    let dropped_event_count = provider_counter(
        provider,
        &["dropped_event_count", "dropped_events", "dropped"],
    );
    let deadline_miss_count =
        provider_counter(provider, &["deadline_miss_count", "deadline_misses"]);
    let full_disk_access = provider_full_disk_access(&provider_kind, provider);
    let provider_attestation_degraded = provider.provider_state.as_ref().is_some_and(|state| {
        !state.installed
            || !state.active
            || !state.healthy
            || matches!(
                state.availability,
                ProviderAvailability::Unavailable
                    | ProviderAvailability::Inactive
                    | ProviderAvailability::Degraded
            )
            || !state.degraded_reasons.is_empty()
    });
    let degraded = matches!(
        provider.runtime,
        ProviderRuntimeState::Unknown
            | ProviderRuntimeState::Inactive
            | ProviderRuntimeState::Degraded { .. }
    ) || !installed
        || !active
        || host_status.approval == SystemExtensionApproval::ApprovalBlocked
        || provider_attestation_degraded
        || dropped_event_count > 0
        || deadline_miss_count > 0
        || full_disk_access == Some(false)
        || provider.policy_synced == Some(false)
        || provider.enforcement_ready == Some(false)
        || provider.last_error.is_some();
    let mut degradation_reasons = macos_provider_degradation_reasons(
        host_status,
        provider,
        dropped_event_count,
        deadline_miss_count,
        full_disk_access,
    );
    if degraded && degradation_reasons.is_empty() {
        degradation_reasons.push("provider degraded without a specific reason".to_string());
    }
    let healthy = active && !degraded;

    EndpointProviderState {
        provider_id: provider_id.to_string(),
        provider_kind,
        installed,
        active,
        healthy,
        degraded,
        degradation_reasons,
        dropped_event_count,
        deadline_miss_count,
        full_disk_access,
        last_seen: provider_last_seen(provider).or_else(|| active.then(chrono::Utc::now)),
    }
}

fn macos_provider_degradation_reasons(
    host_status: &CombinedSystemExtensionStatus,
    provider: &ProviderStatus,
    dropped_event_count: u64,
    deadline_miss_count: u64,
    full_disk_access: Option<bool>,
) -> Vec<String> {
    let mut reasons = Vec::new();
    match provider.runtime.clone() {
        ProviderRuntimeState::Degraded { reason } if !reason.trim().is_empty() => {
            reasons.push(sanitize_provider_status_reason(&reason));
        }
        ProviderRuntimeState::Unknown => reasons.push("provider runtime unknown".to_string()),
        ProviderRuntimeState::Inactive => reasons.push("provider runtime inactive".to_string()),
        _ => {}
    }
    if host_status.install_state == SystemExtensionInstallState::NotInstalled {
        reasons.push("system extension not installed".to_string());
    }
    if host_status.approval == SystemExtensionApproval::ApprovalBlocked {
        reasons.push("system extension approval blocked".to_string());
    }
    if let Some(last_error) = provider
        .last_error
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
    {
        reasons.push(sanitize_provider_status_reason(last_error));
    }
    if provider.policy_synced == Some(false) {
        reasons.push("provider policy not synced".to_string());
    }
    if provider.enforcement_ready == Some(false) {
        reasons.push("provider enforcement not ready".to_string());
    }
    if let Some(provider_state) = &provider.provider_state {
        if !provider_state.installed {
            reasons.push("provider attestation reports not installed".to_string());
        }
        if !provider_state.active {
            reasons.push("provider attestation reports inactive".to_string());
        }
        if !provider_state.healthy {
            reasons.push("provider attestation reports unhealthy".to_string());
        }
        match provider_state.availability {
            ProviderAvailability::Unavailable => {
                reasons.push("provider attestation reports unavailable".to_string());
            }
            ProviderAvailability::Inactive => {
                reasons.push("provider attestation reports inactive".to_string());
            }
            ProviderAvailability::Active => {}
            ProviderAvailability::Degraded => {
                reasons.push("provider attestation reports degraded".to_string());
            }
        }
        reasons.extend(
            provider_state
                .degraded_reasons
                .iter()
                .map(|reason| sanitize_provider_status_reason(reason)),
        );
    }
    if dropped_event_count > 0 {
        reasons.push("provider dropped enforcement events".to_string());
    }
    if deadline_miss_count > 0 {
        reasons.push("provider authorization deadline misses".to_string());
    }
    if full_disk_access == Some(false) {
        reasons.push("missing_full_disk_access".to_string());
    }
    reasons.sort();
    reasons.dedup();
    reasons
}

fn provider_full_disk_access(
    provider_kind: &EndpointProviderKind,
    provider: &ProviderStatus,
) -> Option<bool> {
    if provider_kind != &EndpointProviderKind::EndpointSecurity {
        return None;
    }
    if provider_reports_missing_full_disk_access(provider) {
        Some(false)
    } else {
        None
    }
}

fn provider_reports_missing_full_disk_access(provider: &ProviderStatus) -> bool {
    matches!(
        &provider.runtime,
        ProviderRuntimeState::Degraded { reason } if is_missing_full_disk_access_signal(reason)
    ) || provider.provider_state.as_ref().is_some_and(|state| {
        state
            .degraded_reasons
            .iter()
            .any(|reason| is_missing_full_disk_access_signal(reason))
    }) || provider
        .evidence_paths
        .iter()
        .any(|artifact| is_missing_full_disk_access_signal(&artifact.kind))
}

fn is_missing_full_disk_access_signal(value: &str) -> bool {
    let normalized = value
        .trim()
        .chars()
        .map(|ch| match ch {
            ' ' | '-' => '_',
            _ => ch.to_ascii_lowercase(),
        })
        .collect::<String>();
    normalized == "missing_full_disk_access"
}

fn provider_counter(provider: &ProviderStatus, keys: &[&str]) -> u64 {
    keys.iter()
        .find_map(|key| provider.counters.get(*key).copied())
        .unwrap_or(0)
}

fn provider_last_seen(provider: &ProviderStatus) -> Option<chrono::DateTime<chrono::Utc>> {
    provider
        .last_healthy_timestamp
        .as_deref()
        .and_then(|value| chrono::DateTime::parse_from_rfc3339(value).ok())
        .map(|value| value.with_timezone(&chrono::Utc))
}

pub(crate) fn next_receipt_sequence(path: &FsPath) -> Result<u64> {
    Ok(read_endpoint_receipt_ledger(path)?
        .iter()
        .filter_map(receipt_local_sequence)
        .max()
        .unwrap_or(0)
        .saturating_add(1)
        .max(1))
}

pub(crate) fn read_endpoint_receipt_ledger(path: &FsPath) -> Result<Vec<SignedReceipt>> {
    let contents = match fs::read_to_string(path) {
        Ok(contents) => contents,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(err) => {
            return Err(err)
                .with_context(|| format!("read endpoint receipt ledger {}", path.display()));
        }
    };
    let mut receipts = Vec::new();
    for (index, line) in contents.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let receipt: SignedReceipt = serde_json::from_str(line).with_context(|| {
            format!(
                "parse endpoint receipt ledger line {} from {}",
                index + 1,
                path.display()
            )
        })?;
        receipts.push(receipt);
    }
    Ok(receipts)
}

pub(crate) fn endpoint_receipt_index_path(path: &FsPath) -> PathBuf {
    let mut filename = path
        .file_name()
        .map(|value| value.to_os_string())
        .unwrap_or_else(|| "decision-receipts.jsonl".into());
    filename.push(".index.jsonl");
    path.with_file_name(filename)
}

fn read_endpoint_receipt_index(path: &FsPath) -> Result<Vec<EndpointReceiptIndexRecord>> {
    let contents = match fs::read_to_string(path) {
        Ok(contents) => contents,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(err) => {
            return Err(err)
                .with_context(|| format!("read endpoint receipt index {}", path.display()));
        }
    };
    let mut records = Vec::new();
    for (index, line) in contents.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let record: EndpointReceiptIndexRecord = serde_json::from_str(line).with_context(|| {
            format!(
                "parse endpoint receipt index line {} from {}",
                index + 1,
                path.display()
            )
        })?;
        records.push(record);
    }
    Ok(records)
}

pub(crate) fn read_recent_indexed_endpoint_receipts(
    path: &FsPath,
    limit: usize,
    filter: EdrReceiptFilter<'_>,
) -> Result<Option<Vec<SignedReceipt>>> {
    let index_path = endpoint_receipt_index_path(path);
    if !index_path.exists() {
        if !path.exists() {
            return Ok(None);
        }
        rebuild_endpoint_receipt_index(path)?;
    }
    let mut records = read_endpoint_receipt_index_or_rebuild(path, &index_path)?;
    if records.is_empty() {
        if endpoint_receipt_ledger_len(path)? > 0 {
            rebuild_endpoint_receipt_index(path)?;
            records = read_endpoint_receipt_index(&index_path)?;
            if !records.is_empty() {
                return read_recent_indexed_endpoint_receipts_from_records(
                    path, limit, filter, records,
                )
                .map(Some);
            }
        }
        return Ok(Some(Vec::new()));
    }
    if !endpoint_receipt_index_is_current(path, &records)? {
        rebuild_endpoint_receipt_index(path)?;
        records = read_endpoint_receipt_index(&index_path)?;
        if records.is_empty() {
            return Ok(Some(Vec::new()));
        }
    }
    read_recent_indexed_endpoint_receipts_from_records(path, limit, filter, records).map(Some)
}

fn read_endpoint_receipt_index_or_rebuild(
    path: &FsPath,
    index_path: &FsPath,
) -> Result<Vec<EndpointReceiptIndexRecord>> {
    match read_endpoint_receipt_index(index_path) {
        Ok(records) => Ok(records),
        Err(index_error) => {
            let index_error = index_error.to_string();
            rebuild_endpoint_receipt_index(path).with_context(|| {
                format!("rebuild endpoint receipt index after index read failed: {index_error}")
            })?;
            read_endpoint_receipt_index(index_path).with_context(|| {
                format!("read endpoint receipt index after rebuilding corrupt index: {index_error}")
            })
        }
    }
}

fn read_recent_indexed_endpoint_receipts_from_records(
    path: &FsPath,
    limit: usize,
    filter: EdrReceiptFilter<'_>,
    records: Vec<EndpointReceiptIndexRecord>,
) -> Result<Vec<SignedReceipt>> {
    let records = match validate_endpoint_receipt_index_records(path, records) {
        Ok(records) => records,
        Err(index_error) => {
            let index_error = index_error.to_string();
            let rebuild_error_context =
                format!("rebuild endpoint receipt index after validation failed: {index_error}");
            rebuild_endpoint_receipt_index(path).with_context(|| rebuild_error_context)?;
            read_endpoint_receipt_index(&endpoint_receipt_index_path(path)).with_context(|| {
                format!("read endpoint receipt index after rebuilding stale index: {index_error}")
            })?
        }
    };
    let selected = select_endpoint_receipt_index_records(records, limit, filter);
    match read_endpoint_receipts_by_index(path, &selected) {
        Ok(receipts) => Ok(receipts),
        Err(index_error) => {
            let index_error = index_error.to_string();
            let rebuild_error_context =
                format!("rebuild endpoint receipt index after indexed read failed: {index_error}");
            rebuild_endpoint_receipt_index(path).with_context(|| rebuild_error_context)?;
            let rebuilt_records = read_endpoint_receipt_index(&endpoint_receipt_index_path(path))?;
            let selected = select_endpoint_receipt_index_records(rebuilt_records, limit, filter);
            let read_error_context = format!(
                "read endpoint receipts after rebuilding corrupt receipt index: {index_error}"
            );
            read_endpoint_receipts_by_index(path, &selected).with_context(|| read_error_context)
        }
    }
}

fn validate_endpoint_receipt_index_records(
    path: &FsPath,
    records: Vec<EndpointReceiptIndexRecord>,
) -> Result<Vec<EndpointReceiptIndexRecord>> {
    read_endpoint_receipts_by_index(path, &records)?;
    Ok(records)
}

fn select_endpoint_receipt_index_records(
    records: Vec<EndpointReceiptIndexRecord>,
    limit: usize,
    filter: EdrReceiptFilter<'_>,
) -> Vec<EndpointReceiptIndexRecord> {
    records
        .into_iter()
        .filter(|record| receipt_index_matches_filter(record, filter))
        .rev()
        .take(limit)
        .collect::<Vec<_>>()
        .into_iter()
        .rev()
        .collect::<Vec<_>>()
}

fn endpoint_receipt_ledger_len(path: &FsPath) -> Result<u64> {
    match fs::metadata(path) {
        Ok(metadata) => Ok(metadata.len()),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(0),
        Err(err) => {
            Err(err).with_context(|| format!("stat endpoint receipt ledger {}", path.display()))
        }
    }
}

fn endpoint_receipt_index_is_current(
    path: &FsPath,
    records: &[EndpointReceiptIndexRecord],
) -> Result<bool> {
    let ledger_len = endpoint_receipt_ledger_len(path)?;
    let Some(last) = records.last() else {
        return Ok(ledger_len == 0);
    };
    let last_record_end = last.byte_offset.saturating_add(last.byte_len);
    Ok(ledger_len == last_record_end || ledger_len == last_record_end.saturating_add(1))
}

fn read_endpoint_receipts_by_index(
    path: &FsPath,
    records: &[EndpointReceiptIndexRecord],
) -> Result<Vec<SignedReceipt>> {
    let mut file = fs::File::open(path)
        .with_context(|| format!("open endpoint receipt ledger {}", path.display()))?;
    let mut receipts = Vec::with_capacity(records.len());
    for record in records {
        file.seek(SeekFrom::Start(record.byte_offset))
            .with_context(|| format!("seek endpoint receipt ledger {}", path.display()))?;
        let mut bytes = vec![0u8; record.byte_len as usize];
        file.read_exact(&mut bytes)
            .with_context(|| format!("read endpoint receipt ledger {}", path.display()))?;
        let receipt: SignedReceipt = serde_json::from_slice(&bytes).with_context(|| {
            format!(
                "parse endpoint receipt {} at byte offset {} from {}",
                record
                    .receipt_id
                    .as_deref()
                    .unwrap_or("<missing-receipt-id>"),
                record.byte_offset,
                path.display()
            )
        })?;
        validate_endpoint_receipt_index_record(path, record, &receipt)?;
        receipts.push(receipt);
    }
    Ok(receipts)
}

fn validate_endpoint_receipt_index_record(
    path: &FsPath,
    record: &EndpointReceiptIndexRecord,
    receipt: &SignedReceipt,
) -> Result<()> {
    let actual = endpoint_receipt_index_record(receipt, record.byte_offset, record.byte_len);
    if actual != *record {
        return Err(anyhow::anyhow!(
            "endpoint receipt index metadata mismatch at {} byte offset {}: expected receipt {:?} family {:?}, found receipt {:?} family {:?}",
            path.display(),
            record.byte_offset,
            record.receipt_id,
            record.family,
            actual.receipt_id,
            actual.family
        ));
    }
    Ok(())
}

pub(crate) fn rebuild_endpoint_receipt_index(path: &FsPath) -> Result<()> {
    let contents = match fs::read_to_string(path) {
        Ok(contents) => contents,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
            let _ = fs::remove_file(endpoint_receipt_index_path(path));
            return Ok(());
        }
        Err(err) => {
            return Err(err)
                .with_context(|| format!("read endpoint receipt ledger {}", path.display()));
        }
    };
    let mut records = Vec::new();
    let mut byte_offset = 0u64;
    for segment in contents.split_inclusive('\n') {
        let line_without_newline = segment.trim_end_matches('\n');
        let line = line_without_newline.trim();
        if !line.is_empty() {
            let receipt: SignedReceipt = serde_json::from_str(line).with_context(|| {
                format!(
                    "parse endpoint receipt ledger at byte offset {} from {}",
                    byte_offset,
                    path.display()
                )
            })?;
            records.push(endpoint_receipt_index_record(
                &receipt,
                byte_offset,
                line_without_newline.len() as u64,
            ));
        }
        byte_offset = byte_offset.saturating_add(segment.len() as u64);
    }
    let mut contents = String::new();
    for record in &records {
        let line =
            serde_json::to_string(record).context("serialize endpoint receipt index record")?;
        contents.push_str(&line);
        contents.push('\n');
    }
    let index_path = endpoint_receipt_index_path(path);
    crate::security::fs::write_private_atomic(
        &index_path,
        contents.as_bytes(),
        "endpoint receipt index",
    )
}

pub(crate) fn endpoint_receipt_index_record(
    receipt: &SignedReceipt,
    byte_offset: u64,
    byte_len: u64,
) -> EndpointReceiptIndexRecord {
    let family = receipt_family(receipt).map(ToString::to_string);
    let finding_id =
        receipt_endpoint_decision_str(receipt, &["decision", "findingId"]).map(ToString::to_string);
    EndpointReceiptIndexRecord {
        receipt_id: receipt.receipt.receipt_id.clone(),
        timestamp: receipt.receipt.timestamp.clone(),
        family: family.clone(),
        action: receipt_endpoint_decision_str(receipt, &["decision", "action"])
            .map(ToString::to_string),
        finding_id: finding_id.clone(),
        rule_id: receipt_endpoint_decision_str(receipt, &["decision", "ruleId"])
            .map(ToString::to_string),
        graph_slice_id: receipt_endpoint_decision_str(receipt, &["graph", "graphSliceId"])
            .map(ToString::to_string),
        root_node_id: receipt_endpoint_decision_str(receipt, &["graph", "processNodeId"])
            .map(ToString::to_string),
        execution_id: (family.as_deref() == Some("response_execution"))
            .then(|| finding_id.clone())
            .flatten(),
        execution_status: response_execution_status_from_receipt(receipt),
        actor_endpoint_id: receipt_endpoint_decision_str(receipt, &["actor", "endpointId"])
            .map(ToString::to_string),
        actor_user_id: receipt_endpoint_decision_str(receipt, &["actor", "userId"])
            .map(ToString::to_string),
        actor_session_id: receipt_endpoint_decision_str(receipt, &["actor", "sessionId"])
            .map(ToString::to_string),
        actor_agent_id: receipt_endpoint_decision_str(receipt, &["actor", "agentId"])
            .map(ToString::to_string),
        actor_workload_id: receipt_endpoint_decision_str(receipt, &["actor", "workloadId"])
            .map(ToString::to_string),
        actor_approval_id: receipt_endpoint_decision_str(receipt, &["actor", "approvalId"])
            .map(ToString::to_string),
        local_sequence: receipt_local_sequence(receipt),
        byte_offset,
        byte_len,
    }
}

fn response_execution_status_from_receipt(receipt: &SignedReceipt) -> Option<String> {
    [
        "succeeded",
        "failed",
        "partial",
        "rollback_pending",
        "rollback_failed",
        "expired",
        "cancelled",
        "rolled_back",
    ]
    .into_iter()
    .find(|status| receipt_evidence_hash_matches(receipt, "executionStatus", status))
    .map(ToString::to_string)
}

fn receipt_index_matches_filter(
    record: &EndpointReceiptIndexRecord,
    filter: EdrReceiptFilter<'_>,
) -> bool {
    string_filter_matches(record.receipt_id.as_deref(), filter.receipt_id)
        && string_filter_matches(record.family.as_deref(), filter.family)
        && string_filter_matches(record.action.as_deref(), filter.action)
        && string_filter_matches(record.finding_id.as_deref(), filter.finding_id)
        && string_filter_matches(record.rule_id.as_deref(), filter.rule_id)
        && string_filter_matches(record.graph_slice_id.as_deref(), filter.graph_slice_id)
        && string_filter_matches(record.root_node_id.as_deref(), filter.root_node_id)
        && string_filter_matches(record.execution_id.as_deref(), filter.execution_id)
        && string_filter_matches(record.execution_status.as_deref(), filter.status)
        && string_filter_matches(
            record.actor_endpoint_id.as_deref(),
            filter.actor_endpoint_id,
        )
        && string_filter_matches(record.actor_user_id.as_deref(), filter.actor_user_id)
        && string_filter_matches(record.actor_session_id.as_deref(), filter.actor_session_id)
        && string_filter_matches(record.actor_agent_id.as_deref(), filter.actor_agent_id)
        && string_filter_matches(
            record.actor_workload_id.as_deref(),
            filter.actor_workload_id,
        )
        && string_filter_matches(
            record.actor_approval_id.as_deref(),
            filter.actor_approval_id,
        )
        && filter
            .local_sequence
            .map_or(true, |expected| record.local_sequence == Some(expected))
}

fn string_filter_matches(actual: Option<&str>, expected: Option<&str>) -> bool {
    expected.map_or(true, |expected| actual == Some(expected))
}

pub(crate) fn load_or_create_edr_receipt_signer_with_requirement(
    require_enrolled_signer: bool,
) -> Result<(Keypair, String)> {
    if let Some(key_hex) = crate::enrollment::load_enrollment_key_hex()
        .with_context(|| "load enrollment key for endpoint receipt signer")?
    {
        let keypair = Keypair::from_hex(key_hex.trim())
            .with_context(|| "parse enrollment key for endpoint receipt signer")?;
        let signer_identity = format!("agent-enrollment:{}", keypair.public_key().to_hex());
        return Ok((keypair, signer_identity));
    }

    if require_enrolled_signer {
        anyhow::bail!(
            "endpoint receipt signer requires an enrolled agent key; refusing local EDR signer fallback"
        );
    }

    let path = default_edr_receipt_signing_key_path();
    if path.exists() {
        let key_hex = fs::read_to_string(&path)
            .with_context(|| format!("read endpoint receipt signing key {}", path.display()))?;
        let keypair = Keypair::from_hex(key_hex.trim())
            .with_context(|| "parse endpoint receipt signing key")?;
        let signer_identity = format!("local-edr:{}", keypair.public_key().to_hex());
        return Ok((keypair, signer_identity));
    }

    let keypair = Keypair::generate();
    crate::security::fs::write_private_atomic(
        &path,
        format!("{}\n", keypair.to_hex()).as_bytes(),
        "endpoint receipt signing key",
    )?;
    let signer_identity = format!("local-edr:{}", keypair.public_key().to_hex());
    Ok((keypair, signer_identity))
}

fn default_edr_flight_recorder_path() -> PathBuf {
    crate::settings::get_config_dir()
        .join("edr")
        .join("flight-recorder.jsonl")
}

fn default_edr_flight_recorder() -> Result<EndpointFlightRecorder> {
    let path = default_edr_flight_recorder_path();
    EndpointFlightRecorder::open(&path)
        .with_context(|| format!("open durable endpoint flight recorder {}", path.display()))
}

fn default_edr_receipt_ledger_path() -> PathBuf {
    crate::settings::get_config_dir()
        .join("edr")
        .join("decision-receipts.jsonl")
}

fn default_edr_honey_registry_path() -> PathBuf {
    crate::settings::get_config_dir()
        .join("edr")
        .join("honey-artifacts.jsonl")
}

fn default_edr_evidence_bundle_dir() -> PathBuf {
    crate::settings::get_config_dir()
        .join("edr")
        .join("evidence-bundles")
}

fn default_edr_quarantine_dir() -> PathBuf {
    crate::settings::get_config_dir()
        .join("edr")
        .join("quarantine")
}

fn default_edr_response_execution_ledger_path() -> PathBuf {
    crate::settings::get_config_dir()
        .join("edr")
        .join("response-executions.jsonl")
}

fn default_edr_response_acknowledgement_ledger_path() -> PathBuf {
    crate::settings::get_config_dir()
        .join("edr")
        .join("response-acknowledgements.jsonl")
}

fn default_edr_control_ack_postback_retry_ledger_path() -> PathBuf {
    crate::settings::get_config_dir()
        .join("edr")
        .join("control-ack-postback-retries.json")
}

fn default_edr_control_archive_upload_retry_ledger_path() -> PathBuf {
    crate::settings::get_config_dir()
        .join("edr")
        .join("control-archive-upload-retries.json")
}

fn default_edr_control_receipt_upload_retry_ledger_path() -> PathBuf {
    crate::settings::get_config_dir()
        .join("edr")
        .join("control-receipt-upload-retries.json")
}

fn default_edr_fleet_hunt_event_outbox_path() -> PathBuf {
    crate::settings::get_config_dir()
        .join("edr")
        .join("fleet-hunt-event-outbox.json")
}

fn default_edr_egress_restriction_ledger_path() -> PathBuf {
    crate::settings::get_config_dir()
        .join("edr")
        .join("egress-restrictions.jsonl")
}

fn default_edr_staged_detection_ledger_path() -> PathBuf {
    crate::settings::get_config_dir()
        .join("edr")
        .join("staged-detections.jsonl")
}

fn default_edr_policy_delta_dir() -> PathBuf {
    crate::settings::get_config_dir()
        .join("edr")
        .join("policy-deltas")
}

fn default_edr_network_extension_egress_policy_path() -> PathBuf {
    crate::settings::get_config_dir()
        .join("edr")
        .join("network-extension-egress-policy.json")
}

fn default_edr_receipt_signing_key_path() -> PathBuf {
    crate::settings::get_config_dir()
        .join("edr")
        .join("receipt-signing.key")
}

fn edr_receipt_signer_requires_enrollment(settings: &Settings) -> bool {
    settings.enrollment.enrolled || settings.nats.enabled || settings.control_api.enabled
}

pub(crate) async fn require_cloud_mode_enrolled_receipt_signer(
    state: &AgentApiState,
    label: &str,
) -> Result<(), (StatusCode, String)> {
    let settings = state.settings.read().await.clone();
    if !edr_receipt_signer_requires_enrollment(&settings) {
        return Ok(());
    }
    require_enrolled_edr_receipt_signer_for_settings(state, &settings, label).await
}

async fn require_enrolled_edr_receipt_signer_for_settings(
    state: &AgentApiState,
    settings: &Settings,
    label: &str,
) -> Result<(), (StatusCode, String)> {
    if !edr_receipt_signer_requires_enrollment(settings) {
        return Ok(());
    }
    let (signer_identity, signer_public_key) = {
        let ledger = state.edr_receipt_ledger.lock().await;
        (
            ledger.signer_identity.clone(),
            ledger.signer_public_key.clone(),
        )
    };
    let expected_identity = format!("agent-enrollment:{signer_public_key}");
    if signer_identity != expected_identity {
        return Err((
            StatusCode::CONFLICT,
            format!("{label} requires an enrolled EDR receipt signer in cloud/control mode"),
        ));
    }
    if let Some(key_hex) = crate::enrollment::load_enrollment_key_hex().map_err(internal_error)? {
        let enrollment_public_key = Keypair::from_hex(key_hex.trim())
            .map_err(|err| internal_error(anyhow::anyhow!("parse enrollment key: {err}")))?
            .public_key()
            .to_hex();
        if signer_public_key != enrollment_public_key {
            return Err((
                StatusCode::CONFLICT,
                format!("{label} signer does not match the enrolled agent key"),
            ));
        }
    }
    Ok(())
}

pub(crate) async fn require_cloud_mode_receipts_signed_by_current_signer(
    state: &AgentApiState,
    receipts: &[SignedReceipt],
    label: &str,
) -> Result<(), (StatusCode, String)> {
    let settings = state.settings.read().await.clone();
    if !edr_receipt_signer_requires_enrollment(&settings) {
        return Ok(());
    }
    require_enrolled_edr_receipt_signer_for_settings(state, &settings, label).await?;
    let (signer_identity, signer_public_key) = {
        let ledger = state.edr_receipt_ledger.lock().await;
        (
            ledger.signer_identity.clone(),
            ledger.signer_public_key.clone(),
        )
    };
    for receipt in receipts {
        let receipt_id = receipt.receipt.receipt_id.as_deref().unwrap_or("<missing>");
        if receipt_endpoint_decision_str(receipt, &["signer", "signerIdentity"])
            != Some(signer_identity.as_str())
        {
            return Err((
                StatusCode::CONFLICT,
                format!("{label} contains receipt {receipt_id} from a non-current EDR signer"),
            ));
        }
        if receipt_endpoint_decision_str(receipt, &["signer", "signerPublicKey"])
            != Some(signer_public_key.as_str())
        {
            return Err((
                StatusCode::CONFLICT,
                format!("{label} contains receipt {receipt_id} from an untrusted EDR signer"),
            ));
        }
    }
    Ok(())
}

fn default_edr_receipt_ledger(
    require_enrolled_receipt_signer: bool,
) -> Result<EndpointReceiptLedger> {
    let path = default_edr_receipt_ledger_path();
    let ledger = if require_enrolled_receipt_signer {
        EndpointReceiptLedger::open_require_enrollment(&path)
    } else {
        EndpointReceiptLedger::open(&path)
    };
    ledger.with_context(|| format!("open durable endpoint receipt ledger {}", path.display()))
}

fn default_edr_honey_registry() -> Result<EndpointHoneyRegistry> {
    let path = default_edr_honey_registry_path();
    EndpointHoneyRegistry::open(&path)
        .with_context(|| format!("open durable endpoint honey registry {}", path.display()))
}

fn default_edr_evidence_bundle_store() -> Result<EndpointEvidenceBundleStore> {
    let root = default_edr_evidence_bundle_dir();
    EndpointEvidenceBundleStore::open(&root).with_context(|| {
        format!(
            "open durable endpoint evidence bundle store {}",
            root.display()
        )
    })
}

fn default_edr_response_execution_ledger() -> Result<EndpointResponseExecutionLedger> {
    let path = default_edr_response_execution_ledger_path();
    EndpointResponseExecutionLedger::open(&path).with_context(|| {
        format!(
            "open durable endpoint response execution ledger {}",
            path.display()
        )
    })
}

fn default_edr_response_acknowledgement_ledger() -> Result<EndpointResponseAcknowledgementLedger> {
    let path = default_edr_response_acknowledgement_ledger_path();
    EndpointResponseAcknowledgementLedger::open(&path).with_context(|| {
        format!(
            "open durable endpoint response acknowledgement ledger {}",
            path.display()
        )
    })
}

fn default_edr_control_ack_postback_retry_ledger() -> Result<EndpointControlAckPostbackRetryLedger>
{
    let path = default_edr_control_ack_postback_retry_ledger_path();
    EndpointControlAckPostbackRetryLedger::open(&path).with_context(|| {
        format!(
            "open durable endpoint Control API acknowledgement retry queue {}",
            path.display()
        )
    })
}

fn default_edr_control_archive_upload_retry_ledger(
) -> Result<EndpointControlArchiveUploadRetryLedger> {
    let path = default_edr_control_archive_upload_retry_ledger_path();
    EndpointControlArchiveUploadRetryLedger::open(&path).with_context(|| {
        format!(
            "open durable endpoint Control API archive upload retry queue {}",
            path.display()
        )
    })
}

fn default_edr_control_receipt_upload_retry_ledger(
) -> Result<EndpointControlReceiptUploadRetryLedger> {
    let path = default_edr_control_receipt_upload_retry_ledger_path();
    EndpointControlReceiptUploadRetryLedger::open(&path).with_context(|| {
        format!(
            "open durable endpoint Control API receipt upload retry queue {}",
            path.display()
        )
    })
}

fn default_edr_fleet_hunt_event_outbox() -> Result<EndpointFleetHuntEventOutbox> {
    let path = default_edr_fleet_hunt_event_outbox_path();
    EndpointFleetHuntEventOutbox::open(&path).with_context(|| {
        format!(
            "open durable endpoint fleet hunt-event outbox {}",
            path.display()
        )
    })
}

fn default_edr_egress_restriction_ledger() -> Result<EndpointEgressRestrictionLedger> {
    let path = default_edr_egress_restriction_ledger_path();
    EndpointEgressRestrictionLedger::open(&path).with_context(|| {
        format!(
            "open durable endpoint egress restriction ledger {}",
            path.display()
        )
    })
}

fn default_edr_staged_detection_ledger() -> Result<EndpointStagedDetectionLedger> {
    let path = default_edr_staged_detection_ledger_path();
    EndpointStagedDetectionLedger::open(&path).with_context(|| {
        format!(
            "open durable endpoint staged detection ledger {}",
            path.display()
        )
    })
}

fn default_edr_policy_delta_store() -> Result<EndpointPolicyDeltaStore> {
    let root = default_edr_policy_delta_dir();
    EndpointPolicyDeltaStore::open(&root).with_context(|| {
        format!(
            "open durable endpoint policy delta store {}",
            root.display()
        )
    })
}

async fn append_recent_edr_findings(state: &AgentApiState, findings: &[DetectionFinding]) {
    let mut recent = state.edr_recent_findings.lock().await;
    for finding in findings {
        recent.push_back(finding.clone());
    }
    while recent.len() > EDR_MAX_STORED_FINDINGS {
        let _ = recent.pop_front();
    }
}

pub(crate) use crate::edr::ledger::evidence_bundle::canonical_evidence_graph;
pub(crate) use crate::edr::ledger::EndpointEvidenceBundleStore;

pub(crate) use crate::edr::ledger::EndpointStagedDetectionLedger;

pub(crate) use crate::edr::ledger::EndpointPolicyDeltaStore;

pub(crate) use crate::edr::ledger::EndpointResponseExecutionLedger;

pub(crate) use crate::edr::ledger::{
    write_network_extension_egress_policy_snapshot, EndpointEgressRestriction,
    EndpointEgressRestrictionLedger, NetworkExtensionEgressPolicySnapshot,
};
// read_*_ledger free functions are used only in mod tests { use super::* }
#[allow(unused_imports)]
pub(crate) use crate::edr::ledger::read_egress_restriction_ledger;

pub(crate) use crate::edr::ledger::EndpointResponseAcknowledgementLedger;

#[allow(unused_imports)]
pub(crate) use crate::edr::ledger::read_fleet_hunt_event_outbox;
pub(crate) use crate::edr::ledger::{
    EndpointFleetHuntEventOutbox, EndpointFleetHuntEventOutboxEntry,
};

#[allow(unused_imports)]
pub(crate) use crate::edr::ledger::read_control_ack_postback_retry_ledger;
pub(crate) use crate::edr::ledger::{
    EndpointControlAckPostbackRetry, EndpointControlAckPostbackRetryLedger,
};

#[allow(unused_imports)]
pub(crate) use crate::edr::ledger::read_control_receipt_upload_retry_ledger;
pub(crate) use crate::edr::ledger::{
    EndpointControlReceiptUploadRetry, EndpointControlReceiptUploadRetryLedger,
};

#[allow(unused_imports)]
pub(crate) use crate::edr::ledger::read_control_archive_upload_retry_ledger;
pub(crate) use crate::edr::ledger::{
    EndpointControlArchiveUploadRetry, EndpointControlArchiveUploadRetryLedger,
};

pub(crate) use crate::edr::ledger::EndpointHoneyRegistry;

pub(crate) fn validate_deception_cleanup_plan(
    plan: &DeceptionPlan,
) -> std::result::Result<(), String> {
    if !plan.root.is_absolute() {
        return Err(format!(
            "deception cleanup root must be absolute: {}",
            plan.root.display()
        ));
    }
    for artifact in &plan.artifacts {
        validate_deception_cleanup_relative_path(&artifact.relative_path)?;
    }
    Ok(())
}

fn validate_deception_cleanup_relative_path(path: &FsPath) -> std::result::Result<(), String> {
    if path.is_absolute() {
        return Err(format!(
            "honey artifact cleanup path must be relative: {}",
            path.display()
        ));
    }
    for component in path.components() {
        if matches!(
            component,
            Component::ParentDir | Component::RootDir | Component::Prefix(_)
        ) {
            return Err(format!(
                "honey artifact cleanup path contains unsafe component: {}",
                path.display()
            ));
        }
    }
    Ok(())
}

pub(crate) fn cleanup_deception_plan(
    plan: &DeceptionPlan,
    registered_ids: &BTreeSet<String>,
    dry_run: bool,
) -> Result<(DeceptionCleanupReport, BTreeSet<String>)> {
    let mut report = DeceptionCleanupReport {
        dry_run,
        removed: Vec::new(),
        would_remove: Vec::new(),
        missing: Vec::new(),
        refused: Vec::new(),
    };
    let mut artifact_ids_to_deregister = BTreeSet::new();

    for artifact in &plan.artifacts {
        let path = artifact.absolute_path(&plan.root);
        let path_text = path.display().to_string();
        if !registered_ids.contains(&artifact.artifact_id) {
            report.refused.push(format!(
                "{}: unregistered honey artifact {}",
                path_text, artifact.artifact_id
            ));
            continue;
        }

        let metadata = match fs::symlink_metadata(&path) {
            Ok(metadata) => metadata,
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
                report.missing.push(path_text);
                artifact_ids_to_deregister.insert(artifact.artifact_id.clone());
                continue;
            }
            Err(err) => {
                return Err(err)
                    .with_context(|| format!("inspect honey artifact {}", path.display()));
            }
        };
        if metadata.file_type().is_symlink() {
            report
                .refused
                .push(format!("{path_text}: refusing to remove symlink"));
            continue;
        }
        if !metadata.is_file() {
            report
                .refused
                .push(format!("{path_text}: refusing to remove non-file"));
            continue;
        }

        let contents = fs::read(&path)
            .with_context(|| format!("read honey artifact before cleanup {}", path.display()))?;
        if contents != artifact.contents.as_bytes() {
            report.refused.push(format!(
                "{path_text}: content does not match registered honey artifact"
            ));
            continue;
        }

        if dry_run {
            report.would_remove.push(path_text);
        } else {
            fs::remove_file(&path)
                .with_context(|| format!("remove honey artifact {}", path.display()))?;
            report.removed.push(path_text);
            artifact_ids_to_deregister.insert(artifact.artifact_id.clone());
        }
    }

    Ok((report, artifact_ids_to_deregister))
}

pub(crate) fn validate_edr_request_sizes(
    observation_count: usize,
    honey_artifact_count: usize,
) -> Result<(), (StatusCode, String)> {
    if observation_count > EDR_MAX_OBSERVATIONS_PER_REQUEST {
        return Err((
            StatusCode::BAD_REQUEST,
            format!(
                "too many observations: max {}",
                EDR_MAX_OBSERVATIONS_PER_REQUEST
            ),
        ));
    }
    if honey_artifact_count > EDR_MAX_HONEY_ARTIFACTS_PER_REQUEST {
        return Err((
            StatusCode::BAD_REQUEST,
            format!(
                "too many honey artifacts: max {}",
                EDR_MAX_HONEY_ARTIFACTS_PER_REQUEST
            ),
        ));
    }
    Ok(())
}

async fn list_gateways(
    State(state): State<Arc<AgentApiState>>,
    headers: HeaderMap,
) -> Result<Json<crate::openclaw::GatewayListResponse>, (StatusCode, String)> {
    require_auth(&headers, &state)?;
    Ok(Json(state.openclaw.list_gateways().await))
}

async fn create_gateway(
    State(state): State<Arc<AgentApiState>>,
    headers: HeaderMap,
    Json(input): Json<GatewayUpsertRequest>,
) -> Result<Json<crate::openclaw::manager::GatewayView>, (StatusCode, String)> {
    require_auth(&headers, &state)?;
    let created = state
        .openclaw
        .upsert_gateway(input)
        .await
        .map_err(map_openclaw_error)?;
    Ok(Json(created))
}

async fn patch_gateway(
    State(state): State<Arc<AgentApiState>>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Json(patch): Json<GatewayPatchInput>,
) -> Result<Json<crate::openclaw::manager::GatewayView>, (StatusCode, String)> {
    require_auth(&headers, &state)?;

    let current = state
        .openclaw
        .list_gateways()
        .await
        .gateways
        .into_iter()
        .find(|g| g.id == id)
        .ok_or_else(|| (StatusCode::NOT_FOUND, "gateway not found".to_string()))?;

    let updated = state
        .openclaw
        .upsert_gateway(GatewayUpsertRequest {
            id: Some(current.id),
            label: patch.label.unwrap_or(current.label),
            gateway_url: patch.gateway_url.unwrap_or(current.gateway_url),
            token: patch.token,
            device_token: patch.device_token,
        })
        .await
        .map_err(map_openclaw_error)?;

    Ok(Json(updated))
}

async fn delete_gateway(
    State(state): State<Arc<AgentApiState>>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    require_auth(&headers, &state)?;
    state
        .openclaw
        .delete_gateway(&id)
        .await
        .map_err(internal_error)?;
    Ok(StatusCode::NO_CONTENT)
}

async fn connect_gateway(
    State(state): State<Arc<AgentApiState>>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Result<Json<Value>, (StatusCode, String)> {
    require_auth(&headers, &state)?;
    state
        .openclaw
        .connect_gateway(&id)
        .await
        .map_err(internal_error)?;
    Ok(Json(serde_json::json!({"ok": true})))
}

async fn disconnect_gateway(
    State(state): State<Arc<AgentApiState>>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Result<Json<Value>, (StatusCode, String)> {
    require_auth(&headers, &state)?;
    state
        .openclaw
        .disconnect_gateway(&id)
        .await
        .map_err(internal_error)?;
    Ok(Json(serde_json::json!({"ok": true})))
}

async fn set_active_gateway(
    State(state): State<Arc<AgentApiState>>,
    headers: HeaderMap,
    Json(input): Json<ActiveGatewayUpdateInput>,
) -> Result<Json<Value>, (StatusCode, String)> {
    require_auth(&headers, &state)?;
    state
        .openclaw
        .set_active_gateway(input.active_gateway_id.clone())
        .await
        .map_err(internal_error)?;
    Ok(Json(serde_json::json!({
        "ok": true,
        "active_gateway_id": input.active_gateway_id,
    })))
}

async fn discover_gateways(
    State(state): State<Arc<AgentApiState>>,
    headers: HeaderMap,
    Json(input): Json<GatewayDiscoverInput>,
) -> Result<Json<Value>, (StatusCode, String)> {
    require_auth(&headers, &state)?;
    let payload = state
        .openclaw
        .gateway_discover(input.timeout_ms)
        .await
        .map_err(internal_error)?;
    Ok(Json(payload))
}

async fn probe_gateway(
    State(state): State<Arc<AgentApiState>>,
    headers: HeaderMap,
    Json(input): Json<GatewayDiscoverInput>,
) -> Result<Json<Value>, (StatusCode, String)> {
    require_auth(&headers, &state)?;
    let payload = state
        .openclaw
        .gateway_probe(input.timeout_ms)
        .await
        .map_err(internal_error)?;
    Ok(Json(payload))
}

async fn gateway_request(
    State(state): State<Arc<AgentApiState>>,
    headers: HeaderMap,
    Json(input): Json<GatewayRequestInput>,
) -> Result<Json<Value>, (StatusCode, String)> {
    require_auth(&headers, &state)?;
    let session_id = state.session_manager.session_id().await;
    let policy = evaluate_policy_check(
        state.settings.clone(),
        &state.http_client,
        PolicyCheckInput {
            action_type: "mcp_tool".to_string(),
            target: format!("openclaw.{}", input.method.trim().to_ascii_lowercase()),
            content: None,
            args: Some({
                let mut args = std::collections::HashMap::new();
                args.insert(
                    "gateway_id".to_string(),
                    serde_json::Value::String(input.gateway_id.clone()),
                );
                args.insert(
                    "method".to_string(),
                    serde_json::Value::String(input.method.clone()),
                );
                if let Some(params) = input.params.as_ref() {
                    args.insert("params".to_string(), params.clone());
                }
                args
            }),
            agent_id: None,
            endpoint_agent_id: None,
            runtime_agent_id: Some(format!("gateway:{}", input.gateway_id)),
            runtime_agent_kind: Some("openclaw".to_string()),
        },
        session_id,
        Some(state.audit_queue.clone()),
    )
    .await;
    if !policy.allowed {
        let message = policy
            .message
            .unwrap_or_else(|| "OpenClaw request blocked by policy".to_string());
        return Err((StatusCode::FORBIDDEN, message));
    }

    let timeout_ms = input.timeout_ms.unwrap_or(12_000);

    let payload = state
        .openclaw
        .request_gateway(&input.gateway_id, input.method, input.params, timeout_ms)
        .await
        .map_err(internal_error)?;

    Ok(Json(payload))
}

async fn import_desktop_gateways(
    State(state): State<Arc<AgentApiState>>,
    headers: HeaderMap,
    Json(payload): Json<ImportGatewayRequest>,
) -> Result<Json<crate::openclaw::ImportGatewayResponse>, (StatusCode, String)> {
    require_auth(&headers, &state)?;
    let result = state
        .openclaw
        .import_desktop_gateways(payload)
        .await
        .map_err(map_openclaw_error)?;
    Ok(Json(result))
}

async fn openclaw_events(
    State(state): State<Arc<AgentApiState>>,
    headers: HeaderMap,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    require_auth(&headers, &state)?;

    let rx = state.openclaw.subscribe();
    let stream = sse_stream(rx);

    Ok(Sse::new(stream).keep_alive(
        KeepAlive::new()
            .interval(Duration::from_secs(15))
            .text("keepalive"),
    ))
}

fn sse_stream(
    rx: broadcast::Receiver<crate::openclaw::OpenClawAgentEvent>,
) -> impl Stream<Item = Result<Event, std::convert::Infallible>> {
    BroadcastStream::new(rx).filter_map(|msg| async move {
        match msg {
            Ok(event) => {
                let payload = serde_json::to_string(&event)
                    .unwrap_or_else(|_| "{\"type\":\"serialize_error\"}".to_string());
                Some(Ok(Event::default().data(payload)))
            }
            Err(_) => None,
        }
    })
}

async fn create_approval_request(
    State(state): State<Arc<AgentApiState>>,
    headers: HeaderMap,
    Json(input): Json<ApprovalRequestInput>,
) -> Result<Json<ApprovalStatusResponse>, (StatusCode, String)> {
    require_auth(&headers, &state)?;

    let retry_after_secs = {
        let mut limiter = state.approval_rate_limiter.lock().await;
        limiter.allow_now(Instant::now()).err()
    };
    if let Some(retry_after) = retry_after_secs {
        return Err((
            StatusCode::TOO_MANY_REQUESTS,
            format!(
                "Approval request rate limit exceeded; retry in {}s",
                retry_after
            ),
        ));
    }

    // Reject critical severity actions -- they are not approvable.
    if input.severity.eq_ignore_ascii_case("critical") {
        return Err((
            StatusCode::UNPROCESSABLE_ENTITY,
            "Critical severity actions are not approvable".to_string(),
        ));
    }

    let request = state
        .approval_queue
        .submit(input)
        .await
        .map_err(|err| match err {
            crate::approval::ApprovalError::QueueFull => {
                (StatusCode::SERVICE_UNAVAILABLE, err.to_string())
            }
            other => (StatusCode::INTERNAL_SERVER_ERROR, other.to_string()),
        })?;
    Ok(Json(ApprovalStatusResponse::from(&request)))
}

async fn get_approval_status(
    State(state): State<Arc<AgentApiState>>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Result<Json<ApprovalStatusResponse>, (StatusCode, String)> {
    require_auth(&headers, &state)?;

    let status = state.approval_queue.get_status(&id).await.ok_or_else(|| {
        (
            StatusCode::NOT_FOUND,
            "Approval request not found".to_string(),
        )
    })?;

    Ok(Json(status))
}

async fn resolve_approval(
    State(state): State<Arc<AgentApiState>>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Json(input): Json<ApprovalResolveInput>,
) -> Result<Json<ApprovalStatusResponse>, (StatusCode, String)> {
    require_auth(&headers, &state)?;

    let result = state
        .approval_queue
        .resolve_local_api(&id, input.resolution)
        .await
        .map_err(|err| match err {
            crate::approval::ApprovalError::NotFound => (
                StatusCode::NOT_FOUND,
                "Approval request not found".to_string(),
            ),
            crate::approval::ApprovalError::AlreadyResolved => (
                StatusCode::CONFLICT,
                "Approval request already resolved".to_string(),
            ),
            crate::approval::ApprovalError::Expired => {
                (StatusCode::GONE, "Approval request expired".to_string())
            }
            crate::approval::ApprovalError::QueueFull => (
                StatusCode::SERVICE_UNAVAILABLE,
                "Approval queue is full".to_string(),
            ),
        })?;

    Ok(Json(result))
}

async fn list_pending_approvals(
    State(state): State<Arc<AgentApiState>>,
    headers: HeaderMap,
) -> Result<Json<Vec<ApprovalStatusResponse>>, (StatusCode, String)> {
    require_auth(&headers, &state)?;
    let pending = state.approval_queue.list_pending().await;
    Ok(Json(pending))
}

// --- Enrollment endpoints ---

#[derive(Deserialize)]
struct EnrollAgentInput {
    control_api_url: String,
    enrollment_token: String,
}

async fn enroll_agent(
    State(state): State<Arc<AgentApiState>>,
    headers: HeaderMap,
    Json(input): Json<EnrollAgentInput>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    require_auth(&headers, &state)?;

    let manager = crate::enrollment::EnrollmentManager::new(state.settings.clone());
    match manager
        .enroll(&input.control_api_url, &input.enrollment_token)
        .await
    {
        Ok(result) => {
            tracing::info!(
                agent_uuid = %result.agent_uuid,
                "Enrollment complete — agent restart required to activate NATS enterprise features"
            );
            Ok(Json(serde_json::json!({
                "status": "enrolled",
                "agent_uuid": result.agent_uuid,
                "tenant_id": result.tenant_id,
                "restart_required": true,
                "message": "Restart the agent to activate enterprise features (policy sync, telemetry, posture commands)",
            })))
        }
        Err(err) => Err((
            StatusCode::BAD_REQUEST,
            format!("Enrollment failed: {}", err),
        )),
    }
}

async fn enrollment_status(
    State(state): State<Arc<AgentApiState>>,
    headers: HeaderMap,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    require_auth(&headers, &state)?;

    let settings = state.settings.read().await;
    let enrollment = &settings.enrollment;
    Ok(Json(serde_json::json!({
        "enrolled": enrollment.enrolled,
        "agent_uuid": enrollment.agent_uuid,
        "tenant_id": enrollment.tenant_id,
        "enrollment_in_progress": enrollment.enrollment_in_progress,
    })))
}

fn current_auth_token(state: &AgentApiState) -> String {
    let guard = state
        .auth_token
        .read()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    guard.clone()
}

fn current_token_grace_minutes(state: &AgentApiState) -> u32 {
    let guard = state
        .token_grace_minutes
        .read()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    (*guard).max(1)
}

fn set_token_grace_minutes(state: &AgentApiState, value: u32) {
    let mut guard = state
        .token_grace_minutes
        .write()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    *guard = value.max(1);
}

fn rotate_local_api_token_with_grace(state: &AgentApiState) -> Result<u64, (StatusCode, String)> {
    let old_token = current_auth_token(state);
    let new_token = rotate_local_api_token().map_err(internal_error)?;
    {
        let mut guard = state
            .auth_token
            .write()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        *guard = new_token;
    }

    let grace_secs = u64::from(current_token_grace_minutes(state)) * 60;
    {
        let mut previous = state
            .previous_auth_token
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        *previous = Some(PreviousAuthToken {
            token: old_token,
            expires_at: Instant::now() + Duration::from_secs(grace_secs),
        });
    }

    Ok(grace_secs)
}

fn auth_token_matches(candidate: &str, state: &AgentApiState) -> bool {
    let current = state
        .auth_token
        .read()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    if constant_time_eq_token(candidate, current.as_str()) {
        return true;
    }
    drop(current);

    let mut previous = state
        .previous_auth_token
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    if let Some(prev) = previous.as_ref() {
        if Instant::now() > prev.expires_at {
            *previous = None;
            return false;
        }
        return constant_time_eq_token(candidate, &prev.token);
    }

    false
}

async fn route_rate_limit(
    State(state): State<Arc<AgentApiState>>,
    request: Request,
    next: Next,
) -> Response {
    let path = request.uri().path();
    let method = request.method().clone();
    let now = Instant::now();

    let limited = if path == "/api/v1/ui/bootstrap/start" {
        let mut limiter = state.ui_bootstrap_start_rate_limiter.lock().await;
        limiter
            .allow_now(
                now,
                ROUTE_RATE_LIMIT_WINDOW,
                ROUTE_RATE_LIMIT_UI_BOOTSTRAP_START,
            )
            .err()
    } else if path == "/ui/bootstrap" && method == axum::http::Method::POST {
        let mut limiter = state.ui_bootstrap_verify_rate_limiter.lock().await;
        limiter
            .allow_now(
                now,
                ROUTE_RATE_LIMIT_WINDOW,
                ROUTE_RATE_LIMIT_UI_BOOTSTRAP_VERIFY,
            )
            .err()
    } else if path == "/api/v1/agent/policy-check" {
        let mut limiter = state.policy_check_rate_limiter.lock().await;
        limiter
            .allow_now(now, ROUTE_RATE_LIMIT_WINDOW, ROUTE_RATE_LIMIT_POLICY_CHECK)
            .err()
    } else if path == "/api/v1/agent/integrations/test" {
        let mut limiter = state.integration_test_rate_limiter.lock().await;
        limiter
            .allow_now(
                now,
                ROUTE_RATE_LIMIT_WINDOW,
                ROUTE_RATE_LIMIT_INTEGRATION_TEST,
            )
            .err()
    } else if path == "/api/v1/openclaw/request" {
        let mut limiter = state.openclaw_request_rate_limiter.lock().await;
        limiter
            .allow_now(
                now,
                ROUTE_RATE_LIMIT_WINDOW,
                ROUTE_RATE_LIMIT_OPENCLAW_REQUEST,
            )
            .err()
    } else {
        None
    };

    if let Some(retry_after) = limited {
        return (
            StatusCode::TOO_MANY_REQUESTS,
            format!("Rate limit exceeded; retry in {}s", retry_after),
        )
            .into_response();
    }

    next.run(request).await
}

async fn rotate_local_api_token_route(
    State(state): State<Arc<AgentApiState>>,
    headers: HeaderMap,
) -> Result<Json<RotateLocalApiTokenResponse>, (StatusCode, String)> {
    require_auth(&headers, &state)?;

    let grace_secs = rotate_local_api_token_with_grace(&state)?;

    Ok(Json(RotateLocalApiTokenResponse {
        rotated: true,
        previous_token_valid_for_seconds: grace_secs,
    }))
}

async fn token_rotation_loop(state: Arc<AgentApiState>, shutdown_rx: &mut broadcast::Receiver<()>) {
    loop {
        let interval_hours = {
            let settings = state.settings.read().await;
            settings
                .local_api_security
                .token_rotation_interval_hours
                .max(1)
        };
        let sleep_for = Duration::from_secs(u64::from(interval_hours) * 60 * 60);
        tokio::select! {
            _ = shutdown_rx.recv() => {
                tracing::debug!("Local API token rotation loop shutting down");
                break;
            }
            _ = tokio::time::sleep(sleep_for) => {}
        }

        match rotate_local_api_token_with_grace(&state) {
            Ok(grace_secs) => {
                tracing::info!(grace_secs, "Rotated local API auth token on schedule");
            }
            Err((status, err)) => {
                tracing::warn!(
                    status = %status,
                    error = %err,
                    "Scheduled local API token rotation failed"
                );
            }
        }
    }
}

async fn control_ack_postback_retry_drain_loop(
    state: Arc<AgentApiState>,
    shutdown_rx: &mut broadcast::Receiver<()>,
) {
    loop {
        match drain_control_ack_postback_retries(
            &state,
            EDR_CONTROL_ACK_RETRY_BACKGROUND_LIMIT,
            false,
        )
        .await
        {
            Ok(response) if response.attempted > 0 => {
                if response.failed > 0 {
                    tracing::warn!(
                        attempted = response.attempted,
                        delivered = response.delivered,
                        failed = response.failed,
                        pending = response.pending,
                        "Control API acknowledgement retry drain completed with failures"
                    );
                } else {
                    tracing::info!(
                        attempted = response.attempted,
                        delivered = response.delivered,
                        pending = response.pending,
                        "Drained queued Control API acknowledgement postbacks"
                    );
                }
            }
            Ok(_) => {}
            Err((status, err)) => {
                tracing::warn!(
                    status = %status,
                    error = %err,
                    "Scheduled Control API acknowledgement retry drain failed"
                );
            }
        }

        tokio::select! {
            _ = shutdown_rx.recv() => {
                tracing::debug!("Control API acknowledgement retry drain loop shutting down");
                break;
            }
            _ = tokio::time::sleep(EDR_CONTROL_ACK_RETRY_DRAIN_INTERVAL) => {}
        }
    }
}

async fn control_receipt_upload_retry_drain_loop(
    state: Arc<AgentApiState>,
    shutdown_rx: &mut broadcast::Receiver<()>,
) {
    loop {
        match drain_control_receipt_upload_retries(
            &state,
            EDR_CONTROL_RECEIPT_UPLOAD_BACKGROUND_LIMIT,
            false,
        )
        .await
        {
            Ok(response) if response.attempted > 0 => {
                if response.failed > 0 {
                    tracing::warn!(
                        attempted = response.attempted,
                        delivered = response.delivered,
                        failed = response.failed,
                        pending = response.pending,
                        "Control API receipt upload retry drain completed with failures"
                    );
                } else {
                    tracing::info!(
                        attempted = response.attempted,
                        delivered = response.delivered,
                        pending = response.pending,
                        "Drained queued Control API receipt uploads"
                    );
                }
            }
            Ok(_) => {}
            Err((status, err)) => {
                tracing::warn!(
                    status = %status,
                    error = %err,
                    "Scheduled Control API receipt upload retry drain failed"
                );
            }
        }

        tokio::select! {
            _ = shutdown_rx.recv() => {
                tracing::debug!("Control API receipt upload retry drain loop shutting down");
                break;
            }
            _ = tokio::time::sleep(EDR_CONTROL_ACK_RETRY_DRAIN_INTERVAL) => {}
        }
    }
}

async fn response_execution_expiration_sweep_loop(
    state: Arc<AgentApiState>,
    shutdown_rx: &mut broadcast::Receiver<()>,
) {
    loop {
        match expire_edr_response_executions(&state).await {
            Ok(response) if response.expired_count > 0 || response.rollback_count > 0 => {
                tracing::info!(
                    expired_count = response.expired_count,
                    rollback_count = response.rollback_count,
                    "Expired due EDR response executions"
                );
            }
            Ok(_) => {}
            Err((status, err)) => {
                tracing::warn!(
                    status = %status,
                    error = %err,
                    "Scheduled EDR response execution expiration sweep failed"
                );
            }
        }

        tokio::select! {
            _ = shutdown_rx.recv() => {
                tracing::debug!("EDR response execution expiration sweep loop shutting down");
                break;
            }
            _ = tokio::time::sleep(EDR_RESPONSE_EXPIRATION_SWEEP_INTERVAL) => {}
        }
    }
}

fn auth_token_from_cookie(headers: &HeaderMap) -> Option<String> {
    let cookie_header = headers.get(COOKIE)?.to_str().ok()?;
    for cookie in cookie_header.split(';') {
        let Some((name, value)) = cookie.trim().split_once('=') else {
            continue;
        };
        if name.trim() == AGENT_AUTH_COOKIE_NAME {
            let token = value.trim();
            if !token.is_empty() {
                return Some(token.to_string());
            }
        }
    }
    None
}

pub(crate) fn require_auth(
    headers: &HeaderMap,
    state: &AgentApiState,
) -> Result<(), (StatusCode, String)> {
    let auth_header = headers
        .get(AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .map(str::trim);

    if let Some(auth) = auth_header {
        if let Some(token) = auth.strip_prefix("Bearer ") {
            if auth_token_matches(token.trim(), state) {
                return Ok(());
            }
        }
    }

    if let Some(cookie_token) = auth_token_from_cookie(headers) {
        if auth_token_matches(cookie_token.trim(), state) {
            return Ok(());
        }
    }

    let err = match auth_header {
        None => "missing authorization header".to_string(),
        Some(auth) if !auth.starts_with("Bearer ") => "invalid authorization scheme".to_string(),
        Some(_) => "invalid authorization token".to_string(),
    };
    Err((StatusCode::UNAUTHORIZED, err))
}

pub(crate) fn internal_error(err: anyhow::Error) -> (StatusCode, String) {
    tracing::error!(error = %err, "Agent API error");
    (StatusCode::INTERNAL_SERVER_ERROR, err.to_string())
}

fn map_openclaw_error(err: anyhow::Error) -> (StatusCode, String) {
    let message = err.to_string();
    if message.contains("gateway_url")
        || message.contains("wss://")
        || message.contains("private/link-local")
        || message.contains("failed to resolve gateway host")
        || message.contains("pinned allowlist")
    {
        return (StatusCode::BAD_REQUEST, message);
    }
    internal_error(err)
}

fn deserialize_optional_string_field<'de, D>(
    deserializer: D,
) -> std::result::Result<Option<Option<String>>, D::Error>
where
    D: Deserializer<'de>,
{
    let value = Option::<serde_json::Value>::deserialize(deserializer)?;
    match value {
        None => Ok(Some(None)),
        Some(serde_json::Value::String(value)) => Ok(Some(Some(value))),
        Some(other) => Err(serde::de::Error::custom(format!(
            "expected string or null, got {}",
            other
        ))),
    }
}

#[cfg(test)]
mod tests;
