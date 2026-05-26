//! Shared wire-format DTOs exchanged between the Clawdstrike agent and the
//! Control API.
//!
//! These types are the single source of truth for the HTTP/JSON contract.
//! Before this crate existed, the agent and `control-api` each defined their
//! own structs for the same payloads, which had drifted byte-for-byte (e.g.
//! `signed_receipt` was required by the agent but optional in `control-api`).
//! Both sides now serialize/deserialize the same struct definition.
//!
//! ## Modules
//!
//! - [`receipt`] — Single-receipt and batched-receipt upload bodies for
//!   `POST /api/v1/receipts` and `POST /api/v1/receipts/batch`.
//! - [`ledger`] — Append-only on-disk index record written by the agent's
//!   receipt ledger. Stable JSON-Lines schema persisted to local storage.
//! - [`response_action`] — Acknowledgement postback envelope the agent sends
//!   to `POST /api/v1/response-actions/{id}/acks` (or the unauthenticated
//!   agent-ack route) once a control-plane response action has executed.
//! - [`archive`] — Raw evidence-bundle archive upload envelope sent to
//!   `POST /api/v1/hunt/evidence-bundle-archives` after a fleet event archive
//!   has been generated and approved for upload.
//!
//! ## Conventions
//!
//! All wire types use `#[serde(rename_all = "camelCase")]` and
//! `#[serde(deny_unknown_fields)]` to fail-closed on schema drift. Optional
//! fields are flagged with `#[serde(default, skip_serializing_if = "Option::is_none")]`
//! so omitted-field JSON is symmetric in both directions.

#![cfg_attr(test, allow(clippy::expect_used, clippy::unwrap_used))]
#![deny(missing_docs)]

pub mod archive;
pub mod ledger;
pub mod receipt;
pub mod response_action;

pub use archive::*;
pub use ledger::*;
pub use receipt::*;
pub use response_action::*;
