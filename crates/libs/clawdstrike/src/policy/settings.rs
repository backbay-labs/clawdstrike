//! Policy settings, verification settings, and custom-guard specs.

use serde::{Deserialize, Serialize};

use super::async_config::AsyncGuardPolicyConfig;

fn default_custom_guard_enabled() -> bool {
    true
}

/// A plugin-shaped guard reference in policy (`guards.custom[]`).
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CustomGuardSpec {
    pub package: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub registry: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    #[serde(default = "default_custom_guard_enabled")]
    pub enabled: bool,
    #[serde(default)]
    pub config: serde_json::Value,
    #[serde(default, rename = "async", skip_serializing_if = "Option::is_none")]
    pub async_config: Option<AsyncGuardPolicyConfig>,
}

#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicySettings {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fail_fast: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub verbose_logging: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session_timeout_secs: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub verification: Option<VerificationSettings>,
}

/// Load-time formal verification settings (consistency, completeness,
/// inheritance soundness). When `strict` is true, failure blocks policy loading.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VerificationSettings {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub strict: bool,
    /// Cache results by content hash. Default: `true`.
    #[serde(default = "default_cache_enabled")]
    pub cache: bool,
}

fn default_cache_enabled() -> bool {
    true
}

impl Default for VerificationSettings {
    fn default() -> Self {
        Self {
            enabled: false,
            strict: false,
            cache: true,
        }
    }
}

impl VerificationSettings {
    pub fn merge_with(&self, child: &Self) -> Self {
        Self {
            // Verification settings are monotonic across extends: a child may
            // request stronger verification, but cannot weaken a parent gate.
            enabled: self.enabled || child.enabled,
            strict: self.strict || child.strict,
            // Cache disablement is also monotonic for safety: if either side
            // opts out of caching, the merged policy stays uncached.
            cache: self.cache && child.cache,
        }
    }
}

pub(crate) fn merge_verification_settings(
    base: &Option<VerificationSettings>,
    child: &Option<VerificationSettings>,
) -> Option<VerificationSettings> {
    match (base, child) {
        (Some(base), Some(child_cfg)) => Some(base.merge_with(child_cfg)),
        (Some(base), None) => Some(base.clone()),
        (None, Some(child_cfg)) => Some(child_cfg.clone()),
        (None, None) => None,
    }
}

fn default_timeout() -> u64 {
    3600 // 1 hour
}

impl PolicySettings {
    pub fn effective_fail_fast(&self) -> bool {
        self.fail_fast.unwrap_or(false)
    }

    pub fn effective_verbose_logging(&self) -> bool {
        self.verbose_logging.unwrap_or(false)
    }

    pub fn effective_session_timeout_secs(&self) -> u64 {
        self.session_timeout_secs.unwrap_or(default_timeout())
    }

    pub fn effective_verification(&self) -> VerificationSettings {
        self.verification.clone().unwrap_or_default()
    }

    pub fn merge_with(&self, child: &Self) -> Self {
        Self {
            fail_fast: child.fail_fast.or(self.fail_fast),
            verbose_logging: child.verbose_logging.or(self.verbose_logging),
            session_timeout_secs: child.session_timeout_secs.or(self.session_timeout_secs),
            verification: merge_verification_settings(&self.verification, &child.verification),
        }
    }
}
