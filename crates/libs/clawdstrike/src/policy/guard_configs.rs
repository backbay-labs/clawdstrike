//! The `GuardConfigs` schema struct (13 guard-config wrappers + presence sidecars).

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};

use super::CustomGuardSpec;
use crate::guards::{
    ComputerUseConfig, EgressAllowlistConfig, ForbiddenPathConfig, InputInjectionCapabilityConfig,
    JailbreakConfig, McpToolConfig, PatchIntegrityConfig, PathAllowlistConfig,
    PromptInjectionConfig, RemoteDesktopSideChannelConfig, SecretLeakConfig, ShellCommandConfig,
};

#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GuardConfigs {
    #[serde(default)]
    pub forbidden_path: Option<ForbiddenPathConfig>,
    #[serde(default)]
    pub path_allowlist: Option<PathAllowlistConfig>,
    #[serde(default)]
    pub egress_allowlist: Option<EgressAllowlistConfig>,
    #[serde(default)]
    pub secret_leak: Option<SecretLeakConfig>,
    #[serde(default)]
    pub patch_integrity: Option<PatchIntegrityConfig>,
    #[serde(default)]
    pub shell_command: Option<ShellCommandConfig>,
    #[serde(default)]
    pub mcp_tool: Option<McpToolConfig>,
    #[serde(default)]
    pub prompt_injection: Option<PromptInjectionConfig>,
    /// Tracks explicitly provided prompt-injection object keys when compiling
    /// partial HushSpec overlays so merge preserves inherited values.
    #[serde(skip)]
    pub prompt_injection_present_fields: BTreeSet<String>,
    #[serde(default)]
    pub jailbreak: Option<JailbreakConfig>,
    /// Tracks explicitly provided jailbreak object keys when compiling partial
    /// HushSpec overlays so merge preserves inherited values.
    #[serde(skip)]
    pub jailbreak_present_fields: BTreeSet<String>,
    #[serde(default)]
    pub computer_use: Option<ComputerUseConfig>,
    #[serde(default)]
    pub remote_desktop_side_channel: Option<RemoteDesktopSideChannelConfig>,
    #[serde(default)]
    pub input_injection_capability: Option<InputInjectionCapabilityConfig>,
    #[cfg(feature = "full")]
    #[serde(default)]
    pub spider_sense: Option<crate::async_guards::threat_intel::SpiderSensePolicyConfig>,
    /// Tracks explicitly provided spider_sense object keys during YAML parse.
    /// This is used to preserve deep-merge semantics for default-valued fields.
    #[cfg(feature = "full")]
    #[serde(skip)]
    pub spider_sense_present_fields: BTreeSet<String>,
    /// Spider-Sense passthrough config in `policy-event` builds.
    ///
    /// `policy-event` consumers only need schema compatibility and should not
    /// reject valid 1.3 policies because runtime-only Spider-Sense types are
    /// unavailable outside `full` builds.
    #[cfg(all(feature = "policy-event", not(feature = "full")))]
    #[serde(default)]
    pub spider_sense: Option<serde_json::Value>,
    /// Custom (plugin-shaped) guards.
    ///
    /// Note: for now, only a small reserved set of built-in packages is supported. Unknown
    /// packages must fail closed.
    #[serde(default)]
    pub custom: Vec<CustomGuardSpec>,
}
