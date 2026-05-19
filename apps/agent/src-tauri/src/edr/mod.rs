//! Endpoint detection and response runtime modules.
//!
//! Hosts the durable ledgers, request/response DTOs, conversion helpers,
//! response executors, and route handlers that back the local endpoint
//! decision engine API. See `docs/plans/clawdstrike/endpoint-decision-engine/`
//! for the product framing.

pub(crate) mod ledger;
