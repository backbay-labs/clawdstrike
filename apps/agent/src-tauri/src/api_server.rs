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

mod control_sync;
pub(crate) use control_sync::*;
mod evidence_archives;
pub(crate) use evidence_archives::*;
mod observations;
pub(crate) use observations::*;
mod policy_delta;
pub(crate) use policy_delta::*;
mod policy_history;
pub(crate) use policy_history::*;
mod receipts;
pub(crate) use receipts::*;
mod response_actions;
pub(crate) use response_actions::*;

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
            Ok(Some(stored)) => {
                crate::edr::dto::hydrate_response_execution_record_attribution(
                    record,
                    &stored.graph,
                );
            }
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

pub(crate) fn query_value(value: &Option<String>) -> Option<&str> {
    value
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
}

#[cfg(test)]
pub(crate) use crate::edr::ledger::receipt::endpoint_receipt_compaction_manifest_path;
pub(crate) use crate::edr::ledger::{
    DeceptionCleanupReceiptSigningInput, DeceptionRotationReceiptSigningInput,
    EdrPolicyDeltaReceiptSigningInput, EndpointReceiptLedger, PolicyDecisionReceiptSigningInput,
    ResponseExecutionReceiptSigningInput,
};

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
