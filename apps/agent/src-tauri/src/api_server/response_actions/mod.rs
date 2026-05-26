//! Response action handling for EDR endpoint decisions.
//!
//! Split into focused sub-modules:
//! - `validate` -- request validation (actor identity, ttl, reasons)
//! - `dispatch` -- live action dispatcher and action support predicates
//! - `failure` -- failure sanitization, redaction, and failed-execution recording
//! - `persistence` -- ledger append, receipt emission, transition IDs
//! - `network_extension` -- NetworkExtension reload requests and proof tracking
//! - `egress_match` -- egress target normalization and active-restriction lookup
//! - `broker_revocation` -- broker capability and integration secret revocation
//! - `process_signal` -- process tree signal validation and Unix signal helpers
//! - `execute/*` -- per-action execution paths
//! - `rollback/*` -- per-action rollback paths and TTL expiration handling
//!
//! Path-bounded persistence checks are provided by the external
//! `clawdstrike-fs-policy-paths` crate (extracted in Phase 1).
//!
//! Sub-files import the parent api_server scope via `use super::*;`, which
//! sees `super::*` here -- making the parent api_server symbols visible inside
//! `response_actions` without re-broadcasting them back through this module.

use super::*;

pub(crate) use clawdstrike_fs_policy_paths::path_is_bounded_persistence_target;

mod broker_revocation;
mod dispatch;
mod egress_match;
mod execute;
mod failure;
mod network_extension;
mod persistence;
mod process_signal;
mod rollback;
mod validate;

pub(crate) use broker_revocation::*;
pub(crate) use dispatch::*;
pub(crate) use egress_match::*;
pub(crate) use execute::*;
pub(crate) use failure::*;
pub(crate) use network_extension::*;
pub(crate) use persistence::*;
pub(crate) use process_signal::*;
pub(crate) use rollback::*;
pub(crate) use validate::*;
