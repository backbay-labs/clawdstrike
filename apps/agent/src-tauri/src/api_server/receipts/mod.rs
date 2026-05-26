//! Endpoint decision receipt subsystem: emission, verification, ledger I/O,
//! and policy/actor helpers used by the agent API server.
//!
//! Submodules are organized by responsibility:
//!
//! - `emit_*` — async helpers that sign and best-effort upload endpoint
//!   receipts to the control plane.
//! - `verify_*` — pure proof-contract verifiers for response execution
//!   receipts.
//! - `filter` / `accessors` — shared helpers for traversing
//!   `endpointDecision` metadata.
//! - `provider_evidence` / `network_extension` — sensor-state and
//!   network-extension evidence builders.
//! - `ledger_index` — JSONL-backed receipt ledger and index file
//!   maintenance.
//! - `raw_artifact_approval` — privacy/approval policy enforcement helpers.
//! - `control_store` — wire conversion from signed endpoint receipts to
//!   control-API upload payloads.
//! - `signer` — endpoint receipt signing key loader.
//!
//! Each submodule pulls in `api_server` scope via `use super::super::*;`
//! to keep call sites of moved helpers stable. `api_server.rs` continues to
//! re-export this module's contents via `pub(crate) use receipts::*;`.

mod accessors;
mod actor;
mod compaction;
mod control_store;
mod emit_deception;
mod emit_detection;
mod emit_lifecycle;
mod emit_policy;
mod emit_response;
mod filter;
mod ledger_index;
mod network_extension;
mod policy_snapshot;
mod provider_evidence;
mod raw_artifact_approval;
mod severity;
mod signer;
mod verify_actor;
mod verify_effects;
mod verify_execution;
mod verify_lifecycle;
mod verify_lifecycle_lookup;
mod verify_rollback;
mod verify_signature;

pub(crate) use accessors::*;
pub(crate) use actor::*;
pub(crate) use compaction::*;
pub(crate) use control_store::*;
pub(crate) use emit_deception::*;
pub(crate) use emit_detection::*;
pub(crate) use emit_lifecycle::*;
pub(crate) use emit_policy::*;
pub(crate) use emit_response::*;
pub(crate) use filter::*;
pub(crate) use ledger_index::*;
pub(crate) use network_extension::*;
pub(crate) use policy_snapshot::*;
pub(crate) use provider_evidence::*;
pub(crate) use raw_artifact_approval::*;
pub(crate) use severity::*;
pub(crate) use signer::*;
pub(crate) use verify_actor::*;
pub(crate) use verify_effects::*;
pub(crate) use verify_execution::*;
pub(crate) use verify_lifecycle::*;
pub(crate) use verify_lifecycle_lookup::*;
pub(crate) use verify_rollback::*;
pub(crate) use verify_signature::*;
