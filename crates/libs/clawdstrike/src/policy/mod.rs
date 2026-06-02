//! Policy configuration and rulesets

use std::sync::OnceLock;

use crate::error::Result;

mod async_config;
mod broker;
mod guard_configs;
mod guards;
mod load;
mod merge;
mod origins;
mod resolver;
mod ruleset;
mod settings;
mod types;
mod validate;

pub use async_config::{
    AsyncCachePolicyConfig, AsyncCircuitBreakerPolicyConfig, AsyncExecutionMode,
    AsyncGuardPolicyConfig, AsyncRateLimitPolicyConfig, AsyncRetryPolicyConfig, TimeoutBehavior,
};
pub use broker::{BrokerConfig, BrokerMethod, BrokerProviderPolicy};
pub use guard_configs::GuardConfigs;
pub use origins::{
    BridgePolicy, BridgeTarget, OriginBudgets, OriginDataPolicy, OriginDefaultBehavior,
    OriginMatch, OriginProfile, OriginsConfig,
};
pub use resolver::{
    LocalPolicyResolver, PolicyCustomGuardSpec, PolicyLocation, PolicyResolver,
    ResolvedPolicySource,
};
pub use ruleset::RuleSet;
pub use settings::{CustomGuardSpec, PolicySettings, VerificationSettings};
pub use types::{MergeStrategy, Policy, PolicyLoadVerificationInput, PolicyValidationOptions};
pub use validate::{policy_version_supports_broker, policy_version_supports_origins};

pub(crate) use guards::PolicyGuards;
pub(crate) use settings::merge_verification_settings;

/// Current policy schema version.
///
/// This is a schema compatibility boundary (not the crate version). Runtimes should fail closed on
/// unsupported versions to prevent silent drift.
pub const POLICY_SCHEMA_VERSION: &str = "1.5.0";
pub const POLICY_SUPPORTED_SCHEMA_VERSIONS: &[&str] =
    &["1.1.0", "1.2.0", "1.3.0", "1.4.0", "1.5.0"];

pub(crate) type PolicyLoadVerifier =
    dyn Fn(&PolicyLoadVerificationInput) -> Result<()> + Send + Sync + 'static;

pub(crate) static POLICY_LOAD_VERIFIER: OnceLock<Box<PolicyLoadVerifier>> = OnceLock::new();

pub fn install_policy_load_verifier<F>(verifier: F) -> bool
where
    F: Fn(&PolicyLoadVerificationInput) -> Result<()> + Send + Sync + 'static,
{
    POLICY_LOAD_VERIFIER.set(Box::new(verifier)).is_ok()
}

#[cfg(test)]
mod tests;
