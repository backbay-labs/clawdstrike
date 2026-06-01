//! Origin-aware policy enforcement schema (`origins:` block).

use serde::{Deserialize, Serialize};

use crate::guards::{EgressAllowlistConfig, McpToolConfig};
use crate::origin::{OriginProvider, ProvenanceConfidence, SpaceType, Visibility};

/// Default behavior when no origin profile matches.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OriginDefaultBehavior {
    /// Deny all actions from unmatched origins.
    #[default]
    Deny,
    /// Apply a minimal read-only profile.
    MinimalProfile,
}

/// Configuration for origin-aware policy enforcement.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OriginsConfig {
    /// Default behavior when no profile matches.
    /// `None` means the field was omitted (inherits from parent during merge).
    /// Defaults to `Deny` at resolution time.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub default_behavior: Option<OriginDefaultBehavior>,
    /// Named origin profiles.
    #[serde(default)]
    pub profiles: Vec<OriginProfile>,
}

impl OriginsConfig {
    /// Returns the effective default behavior, defaulting to `Deny` if unset.
    pub fn effective_default_behavior(&self) -> &OriginDefaultBehavior {
        self.default_behavior
            .as_ref()
            .unwrap_or(&OriginDefaultBehavior::Deny)
    }

    /// Merge with a child config: child profiles replace base profiles by ID, or append if new.
    /// Child's `default_behavior` takes precedence only if explicitly set; otherwise
    /// the base value is preserved.
    pub fn merge_with(&self, child: &Self) -> Self {
        let mut profiles = self.profiles.clone();
        for child_profile in &child.profiles {
            if let Some(pos) = profiles.iter().position(|p| p.id == child_profile.id) {
                profiles[pos] = child_profile.clone();
            } else {
                profiles.push(child_profile.clone());
            }
        }
        Self {
            default_behavior: child
                .default_behavior
                .clone()
                .or_else(|| self.default_behavior.clone()),
            profiles,
        }
    }
}

/// An origin profile defining security posture for a matched origin.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OriginProfile {
    /// Unique profile identifier.
    pub id: String,
    /// Match rules for this profile.
    pub match_rules: OriginMatch,
    /// Optional posture state name to initialize (must reference a state in PostureConfig).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub posture: Option<String>,
    /// MCP tool surface projection for this origin.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mcp: Option<McpToolConfig>,
    /// Egress policy for this origin.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub egress: Option<EgressAllowlistConfig>,
    /// Data policy for this origin.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub data: Option<OriginDataPolicy>,
    /// Budget overrides for this origin.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub budgets: Option<OriginBudgets>,
    /// Bridge policy for cross-origin transitions.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bridge_policy: Option<BridgePolicy>,
    /// Human-readable explanation of this profile's purpose.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub explanation: Option<String>,
}

/// Match rules for selecting an origin profile.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OriginMatch {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub provider: Option<OriginProvider>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tenant_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub space_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub space_type: Option<SpaceType>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub thread_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub visibility: Option<Visibility>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub external_participants: Option<bool>,
    #[serde(default)]
    pub tags: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sensitivity: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub actor_role: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub provenance_confidence: Option<ProvenanceConfidence>,
}

/// Data handling policy for an origin.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OriginDataPolicy {
    #[serde(default)]
    pub allow_external_sharing: bool,
    #[serde(default)]
    pub redact_before_send: bool,
    #[serde(default)]
    pub block_sensitive_outputs: bool,
}

/// Budget overrides for an origin.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OriginBudgets {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mcp_tool_calls: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub egress_calls: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub shell_commands: Option<u64>,
}

/// Bridge policy controlling cross-origin transitions.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BridgePolicy {
    #[serde(default)]
    pub allow_cross_origin: bool,
    #[serde(default)]
    pub allowed_targets: Vec<BridgeTarget>,
    #[serde(default)]
    pub require_approval: bool,
}

/// A target specification for bridge transitions.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BridgeTarget {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub provider: Option<OriginProvider>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub space_type: Option<SpaceType>,
    #[serde(default)]
    pub tags: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub visibility: Option<Visibility>,
}
