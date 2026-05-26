//! Authenticated local API server for agent control and OpenClaw transport.
//!
//! This is the agent-facing local HTTP API: it forwards requests to hushd,
//! exposes EDR ingestion + queries, drives the OpenClaw gateway connections,
//! and serves the bundled control console. All endpoints require a local
//! bearer token (rotated periodically) or the matching UI auth cookie.
//!
//! The implementation is split across the submodules declared below — this
//! file re-exports their contents so callers outside this crate (and the
//! pre-existing `#[cfg(test)] mod tests` block that uses `use super::*`)
//! continue to resolve every symbol via `crate::api_server::*`.

// Top-level imports are kept here so the legacy sibling submodules
// (`control_sync`, `receipts`, `response_actions`, ...) continue to compile
// via their `use super::*` lines. Some of them are unused at this level but
// consumed only inside those sibling submodules.
#![allow(unused_imports)]

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

pub(crate) mod default_paths;
pub(crate) mod fleet_publish;
pub(crate) mod helpers;
pub(crate) mod middleware;
pub(crate) mod proxy;
pub(crate) mod routes;
pub(crate) mod server;
pub(crate) mod state;
pub(crate) mod ui_bootstrap;
pub(crate) mod ui_bootstrap_html;
pub(crate) mod util;

#[cfg(test)]
mod tests;

// Re-export the public API surface so callers outside this crate can keep using
// `crate::api_server::AgentApiServer` etc. without knowing about the submodule
// layout, and so `#[cfg(test)] mod tests` (which uses `use super::*`) keeps
// resolving every helper and type the split files now own.
pub(crate) use default_paths::*;
pub(crate) use fleet_publish::*;
pub(crate) use helpers::*;
pub(crate) use middleware::*;
pub(crate) use proxy::*;
pub(crate) use routes::*;
pub(crate) use state::*;
pub(crate) use ui_bootstrap::*;
pub(crate) use util::*;

// `server` only contains the `impl AgentApiServer` block. The impl is reached
// via `AgentApiServer` (re-exported above through `state::*`) — no explicit
// re-export needed.

pub(crate) use crate::edr::ledger::evidence_bundle::canonical_evidence_graph;
#[cfg(test)]
pub(crate) use crate::edr::ledger::receipt::endpoint_receipt_compaction_manifest_path;
pub(crate) use crate::edr::ledger::EndpointEvidenceBundleStore;
pub(crate) use crate::edr::ledger::EndpointHoneyRegistry;
pub(crate) use crate::edr::ledger::EndpointPolicyDeltaStore;
pub(crate) use crate::edr::ledger::EndpointResponseAcknowledgementLedger;
pub(crate) use crate::edr::ledger::EndpointResponseExecutionLedger;
pub(crate) use crate::edr::ledger::EndpointStagedDetectionLedger;
pub(crate) use crate::edr::ledger::{
    write_network_extension_egress_policy_snapshot, EndpointEgressRestriction,
    EndpointEgressRestrictionLedger, NetworkExtensionEgressPolicySnapshot,
};
pub(crate) use crate::edr::ledger::{
    DeceptionCleanupReceiptSigningInput, DeceptionRotationReceiptSigningInput,
    EdrPolicyDeltaReceiptSigningInput, EndpointReceiptLedger, PolicyDecisionReceiptSigningInput,
    ResponseExecutionReceiptSigningInput,
};
pub(crate) use crate::edr::ledger::{
    EndpointControlAckPostbackRetry, EndpointControlAckPostbackRetryLedger,
};
pub(crate) use crate::edr::ledger::{
    EndpointControlArchiveUploadRetry, EndpointControlArchiveUploadRetryLedger,
};
pub(crate) use crate::edr::ledger::{
    EndpointControlReceiptUploadRetry, EndpointControlReceiptUploadRetryLedger,
};
pub(crate) use crate::edr::ledger::{
    EndpointFleetHuntEventOutbox, EndpointFleetHuntEventOutboxEntry,
};
// read_*_ledger free functions are used only in mod tests { use super::* }
#[allow(unused_imports)]
pub(crate) use crate::edr::ledger::read_control_ack_postback_retry_ledger;
#[allow(unused_imports)]
pub(crate) use crate::edr::ledger::read_control_archive_upload_retry_ledger;
#[allow(unused_imports)]
pub(crate) use crate::edr::ledger::read_control_receipt_upload_retry_ledger;
#[allow(unused_imports)]
pub(crate) use crate::edr::ledger::read_egress_restriction_ledger;
#[allow(unused_imports)]
pub(crate) use crate::edr::ledger::read_fleet_hunt_event_outbox;
