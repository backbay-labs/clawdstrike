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
// via their `use super::*` lines. The submodules now own most of the
// route-level imports — anything still pulled in here is either consumed by
// a sibling via `super::*`, by the colocated `#[cfg(test)] mod tests`, or by
// the re-export block below.

use crate::approval::{ApprovalResolution, ApprovalStatus};
use crate::macos::status::{
    CombinedSystemExtensionStatus, ProviderAvailability, ProviderRuntimeState, ProviderStatus,
    SystemExtensionApproval, SystemExtensionInstallState,
};
use crate::policy::{PolicyCheckInput, PolicyCheckOutput};
use crate::runtime_registry::resolve_effective_endpoint_agent_id;
use crate::session::SessionState;
use crate::settings::Settings;
use anyhow::{Context, Result};
use axum::http::header::AUTHORIZATION;
use axum::http::StatusCode;
use clawdstrike_policy_event::edr::{
    CausalEdgeKind, CausalGraph, CausalGraphRecorder, CausalNode, CausalNodeKind, CredentialKind,
    DeceptionCleanupReport, DeceptionMaterializationReport, DeceptionPlan, DeceptionRotationReport,
    DetectionFinding, DetectionSeverity, EndpointDecisionAction, EndpointDecisionActor,
    EndpointDecisionReceipt, EndpointEvent, EndpointEvidenceRedactionClass, EndpointGraphReference,
    EndpointObservation, EndpointPolicySimulationReport, EndpointPolicySnapshot, EndpointProcess,
    EndpointProviderKind, EndpointProviderState, EndpointReceiptEvidence,
    EndpointResponseAcknowledgementReport, EndpointResponseControlCorrelation,
    EndpointResponseExecutionEffect, EndpointResponseExecutionReport,
    EndpointResponseExecutionStatus, EndpointResponsePlan, EndpointResponseProcessIdentityBinding,
    EndpointResponseRollbackReport, EndpointSensorState, EndpointSimulationImpactLevel,
    EndpointTelemetryPrivacyMode, EndpointTelemetryPrivacyReport, FileOperation, HoneyArtifact,
    SupplyChainRuntimeGuard,
};
use clawdstrike_policy_event::event::PolicyEvent;
use clawdstrike_policy_event::simulate::replay_events;
use hush_core::{canonicalize_json, sha256, Keypair, SignedReceipt};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::fs;
use std::io::{Read as _, Seek as _, SeekFrom};
use std::net::IpAddr;
use std::path::{Path as FsPath, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};

// The colocated `#[cfg(test)] mod tests` resolves these via `use super::*`.
// Kept here (rather than in the test files) because the test sources predate
// the api_server split and rely on every helper being in scope from the
// parent module.
#[cfg(test)]
use crate::approval::ApprovalRequestInput;
#[cfg(test)]
use crate::daemon::DaemonManager;
#[cfg(test)]
use crate::macos::MacosHostService;
#[cfg(test)]
use crate::openclaw::OpenClawManager;
#[cfg(test)]
use crate::settings::IntegrationSettings;
#[cfg(test)]
use axum::extract::{Path, State};
#[cfg(test)]
use axum::http::header::{CONTENT_TYPE, COOKIE, LOCATION, SET_COOKIE};
#[cfg(test)]
use axum::http::{HeaderMap, Uri};
#[cfg(test)]
use axum::response::{IntoResponse, Response};
#[cfg(test)]
use axum::routing::{get, post};
#[cfg(test)]
use axum::{Json, Router};
#[cfg(test)]
use clawdstrike_policy_event::edr::{
    EndpointDeceptionCleanupReceiptInput, EndpointEvidenceBundleManifestReceiptInput,
    EndpointEvidenceBundleReference, EndpointFlightRecorder,
    EndpointResponseAcknowledgementReceiptInput, EndpointResponseExecutionReceiptInput,
    EndpointResponseReceiptInput, EndpointResponseRollbackReceiptInput,
    EndpointSensorStateReceiptInput,
};
#[cfg(test)]
use std::collections::HashMap;
#[cfg(test)]
use std::sync::{Mutex as StdMutex, RwLock as StdRwLock};
#[cfg(test)]
use tokio::net::TcpListener;
#[cfg(test)]
use tokio::sync::{broadcast, Mutex, RwLock};

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
// `read_*_ledger` free functions are used only in `mod tests { use super::* }`,
// but `crate::edr::ledger` re-exports them unconditionally — keep the
// re-exports here so the unused-warning lives in one place.
#[allow(unused_imports)]
pub(crate) use crate::edr::ledger::{
    read_control_ack_postback_retry_ledger, read_control_archive_upload_retry_ledger,
    read_control_receipt_upload_retry_ledger, read_egress_restriction_ledger,
    read_fleet_hunt_event_outbox,
};
