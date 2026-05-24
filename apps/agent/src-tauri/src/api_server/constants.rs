//! Tuneables and limits that govern the agent API surface.
//!
//! Anything `pub(crate)` is referenced either by sibling submodules
//! (`auth`, `daemon_proxy`, `ui_bootstrap`, `rate_limit`) or by code under
//! `crate::edr::{handlers, ledger, queries}` that imports them through
//! `use crate::api_server::*`. The plain `const` entries are scoped to
//! request/handler validation in api_server.rs itself.

use std::time::Duration;

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
pub(crate) const EDR_MAX_AUTO_FLEET_AGENT_SECRET_TOUCHES_PER_BATCH: usize = 100;
pub(crate) const EDR_MAX_AUTO_FLEET_HUNT_EVENT_OUTBOX_RETRIES_PER_BATCH: usize = 100;
pub(crate) const EDR_FLEET_AGENT_SECRET_TOUCH_SYNC_INTERVAL: Duration = Duration::from_secs(60);
pub(crate) const EDR_DEFAULT_PROVIDER_ACK_TIMEOUT_MS: u64 = 750;
pub(crate) const EDR_MAX_PROVIDER_ACK_TIMEOUT_MS: u64 = 5_000;
pub(crate) const EDR_PROVIDER_ACK_POLL_INTERVAL: Duration = Duration::from_millis(50);
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
