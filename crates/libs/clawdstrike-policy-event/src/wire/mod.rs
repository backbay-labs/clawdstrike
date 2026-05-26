//! Wire-format request/response DTOs for the endpoint decision engine API.
//!
//! These types are deserialized from incoming HTTP requests and serialized
//! into outgoing HTTP responses for the local endpoint decision engine API
//! hosted by the desktop agent. They intentionally stay close to the wire
//! shape; richer internal representations live in the [`edr`](super::edr)
//! module.
//!
//! All types are public so consumers (control-api, the agent binary, and
//! cross-language SDKs) can share a single source of truth for the EDR
//! protocol. Visibility was widened from `pub(crate)` to `pub` during the
//! extraction; field semantics, serde derives, and renames are preserved
//! verbatim from the agent's original `apps/agent/src-tauri/src/edr/dto.rs`.

#![allow(dead_code)]

pub mod causal_graph;
pub mod control_upload;
pub mod daemon;
pub mod deception;
pub mod developer_activity;
pub mod endpoint_security;
pub mod evidence_bundles;
pub mod findings;
pub mod health;
pub mod network_extension;
pub mod package_manager;
pub mod policy_delta;
pub mod policy_event_history;
pub mod policy_event_history_causal;
pub mod policy_events;
pub mod privacy;
pub mod protection_state;
pub mod receipts;
pub mod response_actions;
pub mod secret_touches;
pub mod simulation;

pub use causal_graph::*;
pub use control_upload::*;
pub use daemon::*;
pub use deception::*;
pub use developer_activity::*;
pub use endpoint_security::*;
pub use evidence_bundles::*;
pub use findings::*;
pub use health::*;
pub use network_extension::*;
pub use package_manager::*;
pub use policy_delta::*;
pub use policy_event_history::*;
pub use policy_event_history_causal::*;
pub use policy_events::*;
pub use privacy::*;
pub use protection_state::*;
pub use receipts::*;
pub use response_actions::*;
pub use secret_touches::*;
pub use simulation::*;
