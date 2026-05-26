//! OpenClaw agent-owned transport and state.

pub mod manager;
pub mod protocol;
pub mod secret_store;

mod backoff;
mod command;
mod connection;
mod device_proof;
mod dto;
mod identity;
mod runtime_state;
mod session;
mod url_validation;
mod util;

#[cfg(test)]
mod tests;

pub use dto::{
    GatewayDiscoverInput, GatewayListResponse, GatewayRequestInput, GatewayUpsertRequest,
    ImportGatewayRequest, ImportGatewayResponse, OpenClawAgentEvent,
};
pub use manager::OpenClawManager;
