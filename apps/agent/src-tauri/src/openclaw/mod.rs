//! OpenClaw agent-owned transport and state.

pub mod manager;
pub mod protocol;
pub mod secret_store;

pub use manager::{
    GatewayDiscoverInput, GatewayListResponse, GatewayRequestInput, GatewayUpsertRequest,
    ImportGatewayRequest, ImportGatewayResponse, OpenClawAgentEvent, OpenClawManager,
};
