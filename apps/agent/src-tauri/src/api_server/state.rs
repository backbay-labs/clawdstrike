//! State, dependency, and rate-limiter type definitions for the agent API server.
//!
//! This module holds the long-lived shared state shared across all route handlers,
//! the wire-level dependency container (`AgentApiServerDeps`), the rate-limiting
//! helpers, the per-request UI bootstrap session record, and the public
//! `AgentApiServer` handle plus its companion types.

use super::*;
use anyhow::Result;
use axum::http::StatusCode;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeSet, HashMap, VecDeque};
use std::future::Future;
use std::path::PathBuf;
use std::pin::Pin;
use std::sync::{Arc, Mutex as StdMutex, RwLock as StdRwLock};
use std::time::{Duration, Instant};
use tokio::sync::{Mutex, RwLock};

use crate::approval::ApprovalQueue;
use crate::daemon::{AuditQueue, DaemonManager};
use crate::macos::MacosHostService;
use crate::openclaw::OpenClawManager;
use crate::session::SessionManager;
use crate::settings::Settings;
use crate::telemetry_publisher::TelemetryPublisher;
use crate::updater::HushdUpdater;
use clawdstrike_policy_event::edr::{
    CausalGraph, DetectionFinding, EndpointDecisionAction, EndpointEvidenceBundleReference,
    EndpointFlightRecorder,
};

pub(crate) const HUSHD_AUTHORIZATION_HEADER: &str = "x-hushd-authorization";
pub(crate) const AGENT_AUTH_COOKIE_NAME: &str = "clawdstrike_agent_auth";
pub(crate) const POLICY_VERSION_CACHE_REFRESH_INTERVAL: Duration = Duration::from_secs(5);
pub(crate) const POLICY_VERSION_FETCH_TIMEOUT: Duration = Duration::from_millis(200);
pub(crate) const POLICY_VERSION_REFRESH_IN_FLIGHT_TIMEOUT: Duration = Duration::from_secs(20);
pub(crate) const AGENT_API_MAX_BODY_BYTES: usize = 256 * 1024;
pub(crate) const BROKER_MUTATION_MAX_BODY_BYTES: usize = 2 * 1024 * 1024;
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
pub(crate) const APPROVAL_RATE_LIMIT_WINDOW: Duration = Duration::from_secs(60);
pub(crate) const APPROVAL_RATE_LIMIT_BURST_WINDOW: Duration = Duration::from_secs(1);
pub(crate) const APPROVAL_RATE_LIMIT_PER_MINUTE: usize = 30;
pub(crate) const APPROVAL_RATE_LIMIT_BURST: usize = 10;
pub(crate) const ROUTE_RATE_LIMIT_WINDOW: Duration = Duration::from_secs(60);
pub(crate) const ROUTE_RATE_LIMIT_UI_BOOTSTRAP_START: usize = 20;
pub(crate) const ROUTE_RATE_LIMIT_UI_BOOTSTRAP_VERIFY: usize = 60;
pub(crate) const ROUTE_RATE_LIMIT_POLICY_CHECK: usize = 1200;
pub(crate) const ROUTE_RATE_LIMIT_INTEGRATION_TEST: usize = 30;
pub(crate) const ROUTE_RATE_LIMIT_OPENCLAW_REQUEST: usize = 120;
pub(crate) const UI_BOOTSTRAP_TTL: Duration = Duration::from_secs(60);
pub(crate) const UI_BOOTSTRAP_MAX_ATTEMPTS: u8 = 5;
pub(crate) const UI_BOOTSTRAP_MAX_SESSIONS: usize = 32;
pub(crate) const LOCAL_API_TOKEN_ROTATION_MIN_HOURS: u32 = 1;
pub(crate) const LOCAL_API_TOKEN_ROTATION_MAX_HOURS: u32 = 24 * 30;
pub(crate) const LOCAL_API_TOKEN_GRACE_MIN_MINUTES: u32 = 1;
pub(crate) const LOCAL_API_TOKEN_GRACE_MAX_MINUTES: u32 = 120;
pub(crate) const LOCAL_API_MTLS_MIN_PORT: u16 = 1024;
pub(crate) const OTA_CHECK_INTERVAL_MIN_MINUTES: u32 = 5;
pub(crate) const OTA_CHECK_INTERVAL_MAX_MINUTES: u32 = 60 * 24 * 7;

#[derive(Clone)]
pub struct AgentApiServer {
    pub(crate) port: u16,
    pub(crate) state: Arc<AgentApiState>,
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
    pub(crate) value: Option<String>,
    pub(crate) last_refresh_at: Option<std::time::Instant>,
    pub(crate) refresh_in_flight: bool,
    pub(crate) refresh_started_at: Option<std::time::Instant>,
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

    pub(crate) fn finish_refresh(&mut self, fetched: Option<String>, now: std::time::Instant) {
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
    pub(crate) minute_events: VecDeque<Instant>,
    pub(crate) burst_events: VecDeque<Instant>,
}

#[derive(Debug, Clone)]
pub(crate) struct UiBootstrapSession {
    pub(crate) code_normalized: String,
    pub(crate) next_path: String,
    pub(crate) created_at: Instant,
    pub(crate) expires_at: Instant,
    pub(crate) attempts: u8,
}

#[derive(Debug, Clone)]
pub(crate) struct PreviousAuthToken {
    pub(crate) token: String,
    pub(crate) expires_at: Instant,
}

#[derive(Debug, Default)]
pub(crate) struct RouteRateLimiter {
    pub(crate) events: VecDeque<Instant>,
}

impl ApprovalSubmissionLimiter {
    pub(crate) fn allow_now(&mut self, now: Instant) -> std::result::Result<(), u64> {
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
    pub(crate) fn allow_now(
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

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(default, rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct StoredEndpointEvidenceBundle {
    pub(crate) bundle: EndpointEvidenceBundleReference,
    pub(crate) path: Option<String>,
    pub(crate) byte_count: usize,
    pub(crate) graph: CausalGraph,
}

/// Wire DTOs for the Control API used to live here as duplicates of the types
/// in `crates/services/control-api/src/routes/receipts.rs`. They now live in
/// the shared `clawdstrike-control-protocol` crate so the agent (producer) and
/// `control-api` (consumer) share a single source of truth.
pub(crate) use clawdstrike_control_protocol::{
    ControlBatchStoreReceiptsRequest, ControlStoreReceiptRequest, EndpointReceiptIndexRecord,
};

pub(crate) fn default_apply_integrations_changes() -> bool {
    true
}

pub(crate) fn deserialize_optional_string_field<'de, D>(
    deserializer: D,
) -> std::result::Result<Option<Option<String>>, D::Error>
where
    D: serde::Deserializer<'de>,
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

pub(crate) fn internal_error(err: anyhow::Error) -> (StatusCode, String) {
    tracing::error!(error = %err, "Agent API error");
    (StatusCode::INTERNAL_SERVER_ERROR, err.to_string())
}

pub(crate) fn map_openclaw_error(err: anyhow::Error) -> (StatusCode, String) {
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
