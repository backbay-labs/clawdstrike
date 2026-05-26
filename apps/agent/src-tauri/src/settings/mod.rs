//! Settings management for Clawdstrike Agent.
//!
//! Persistent configuration stored in ~/.config/clawdstrike/agent.json.

mod brokerd;
mod control_api;
mod defaults;
mod enrollment;
mod integrations;
mod local_api;
mod nats;
mod openclaw;
mod paths;
mod runtime_registry;
mod store;

#[cfg(test)]
mod tests;

#[allow(unused_imports)]
pub use brokerd::{BrokerdSecretBackendSettings, BrokerdSettings};
#[allow(unused_imports)]
pub use control_api::ControlApiSettings;
pub use enrollment::EnrollmentState;
#[allow(unused_imports)]
pub use integrations::{IntegrationSettings, SiemIntegrationSettings, WebhookIntegrationSettings};
#[allow(unused_imports)]
pub use local_api::LocalApiSecuritySettings;
pub use nats::NatsSettings;
#[allow(unused_imports)]
pub use openclaw::{OpenClawGatewayMetadata, OpenClawSettings};
#[cfg(unix)]
pub(crate) use paths::enforce_private_mode;
#[allow(unused_imports)]
pub use paths::{
    ensure_default_policy, get_agent_token_path, get_config_dir, get_settings_path,
    hostname_best_effort,
};
#[allow(unused_imports)]
pub use runtime_registry::{RuntimeAgentRegistration, RuntimeRegistrySettings};
pub use store::Settings;
