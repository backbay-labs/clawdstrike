//! Core policy types: `Policy`, merge strategy, validation options, and the
//! load-verification input passed to the optional verifier hook.

use serde::{Deserialize, Serialize};

use super::{
    BrokerConfig, GuardConfigs, OriginsConfig, PolicyCustomGuardSpec, PolicySettings,
    POLICY_SCHEMA_VERSION,
};
use crate::posture::PostureConfig;

/// Options controlling how strictly a policy is validated.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PolicyValidationOptions {
    /// Whether placeholders like `${VAR}` must reference an existing environment variable.
    ///
    /// When `false`, placeholder syntax is still validated, but missing env vars are allowed.
    pub require_env: bool,
}

impl PolicyValidationOptions {
    pub const STRICT: Self = Self { require_env: true };
    pub const LAX: Self = Self { require_env: false };
}

impl Default for PolicyValidationOptions {
    fn default() -> Self {
        Self::STRICT
    }
}

/// Strategy for merging policies when using extends
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MergeStrategy {
    /// Replace base entirely with child values
    Replace,
    /// Shallow merge: child values override base at top level
    Merge,
    /// Deep merge: recursively merge nested structures
    #[default]
    DeepMerge,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Policy {
    #[serde(default = "default_version")]
    pub version: String,
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub description: String,
    #[serde(default)]
    pub extends: Option<String>,
    #[serde(default)]
    pub merge_strategy: MergeStrategy,
    #[serde(default)]
    pub guards: GuardConfigs,
    #[serde(default)]
    pub custom_guards: Vec<PolicyCustomGuardSpec>,
    #[serde(default)]
    pub settings: PolicySettings,
    #[serde(default)]
    pub posture: Option<PostureConfig>,
    #[serde(default)]
    pub origins: Option<OriginsConfig>,
    #[serde(default)]
    pub broker: Option<BrokerConfig>,
}

/// Fully materialized policy load context passed to an optional verifier hook.
///
/// `effective_policy` is the validated policy that will be returned to the
/// caller. For inherited policies, `source_policy` is the raw child policy and
/// `parent_policy` is the resolved base policy that was merged into it.
#[derive(Clone, Debug)]
pub struct PolicyLoadVerificationInput {
    pub effective_policy: Policy,
    pub source_policy: Option<Policy>,
    pub parent_policy: Option<Policy>,
}

pub(super) fn default_version() -> String {
    POLICY_SCHEMA_VERSION.to_string()
}

impl Default for Policy {
    fn default() -> Self {
        Self {
            version: default_version(),
            name: String::new(),
            description: String::new(),
            extends: None,
            merge_strategy: MergeStrategy::default(),
            guards: GuardConfigs::default(),
            custom_guards: Vec::new(),
            settings: PolicySettings::default(),
            posture: None,
            origins: None,
            broker: None,
        }
    }
}
