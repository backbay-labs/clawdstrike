//! Endpoint detection and response runtime modules.
//!
//! Hosts the durable ledgers, request/response DTOs, conversion helpers,
//! response executors, and route handlers that back the local endpoint
//! decision engine API. See `docs/plans/clawdstrike/endpoint-decision-engine/`
//! for the product framing.

pub(crate) mod conversion;
pub(crate) mod dto;
pub(crate) mod handlers;
pub(crate) mod helpers;
pub(crate) mod ledger;
pub(crate) mod policy_events;
pub(crate) mod queries;
pub(crate) mod response;
