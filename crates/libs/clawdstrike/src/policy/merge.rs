//! Policy and guard-config merge logic (`extends` inheritance).

use std::collections::BTreeSet;

use super::{
    merge_verification_settings, GuardConfigs, MergeStrategy, Policy, PolicyCustomGuardSpec,
    PolicySettings,
};
use crate::guards::{
    EgressAllowlistConfig, ForbiddenPathConfig, JailbreakConfig, McpToolConfig,
    PromptInjectionConfig, SecretLeakConfig,
};

impl GuardConfigs {
    pub fn merge_with(&self, child: &Self) -> Self {
        Self {
            forbidden_path: match (&self.forbidden_path, &child.forbidden_path) {
                (Some(base), Some(child_cfg)) => Some(base.merge_with(child_cfg)),
                (Some(base), None) => Some(base.clone()),
                // When base is None, merge child with default to apply additional_patterns
                (None, Some(child_cfg)) => {
                    Some(ForbiddenPathConfig::default().merge_with(child_cfg))
                }
                (None, None) => None,
            },
            path_allowlist: match (&self.path_allowlist, &child.path_allowlist) {
                (Some(base), Some(child_cfg)) => Some(base.merge_with(child_cfg)),
                (Some(base), None) => Some(base.clone()),
                (None, Some(child_cfg)) => Some(child_cfg.clone()),
                (None, None) => None,
            },
            egress_allowlist: match (&self.egress_allowlist, &child.egress_allowlist) {
                (Some(base), Some(child_cfg)) => Some(base.merge_with(child_cfg)),
                (Some(base), None) => Some(base.clone()),
                (None, Some(child_cfg)) => {
                    Some(EgressAllowlistConfig::default().merge_with(child_cfg))
                }
                (None, None) => None,
            },
            secret_leak: match (&self.secret_leak, &child.secret_leak) {
                (Some(base), Some(child_cfg)) => Some(base.merge_with(child_cfg)),
                (Some(base), None) => Some(base.clone()),
                (None, Some(child_cfg)) => Some(SecretLeakConfig::default().merge_with(child_cfg)),
                (None, None) => None,
            },
            patch_integrity: child
                .patch_integrity
                .clone()
                .or_else(|| self.patch_integrity.clone()),
            shell_command: child
                .shell_command
                .clone()
                .or_else(|| self.shell_command.clone()),
            mcp_tool: match (&self.mcp_tool, &child.mcp_tool) {
                (Some(base), Some(child_cfg)) => Some(base.merge_with(child_cfg)),
                (Some(base), None) => Some(base.clone()),
                (None, Some(child_cfg)) => Some(McpToolConfig::default().merge_with(child_cfg)),
                (None, None) => None,
            },
            prompt_injection: match (&self.prompt_injection, &child.prompt_injection) {
                (Some(base), Some(child_cfg))
                    if child.prompt_injection_present_fields.is_empty() =>
                {
                    Some(child_cfg.clone())
                }
                (Some(base), Some(child_cfg)) => Some(merge_prompt_injection_config(
                    base,
                    child_cfg,
                    &child.prompt_injection_present_fields,
                )),
                (Some(base), None) => Some(base.clone()),
                (None, Some(child_cfg)) => Some(child_cfg.clone()),
                (None, None) => None,
            },
            prompt_injection_present_fields: if child.prompt_injection.is_some() {
                BTreeSet::new()
            } else {
                self.prompt_injection_present_fields.clone()
            },
            jailbreak: match (&self.jailbreak, &child.jailbreak) {
                (Some(base), Some(child_cfg)) if child.jailbreak_present_fields.is_empty() => {
                    Some(child_cfg.clone())
                }
                (Some(base), Some(child_cfg)) => Some(merge_jailbreak_config(
                    base,
                    child_cfg,
                    &child.jailbreak_present_fields,
                )),
                (Some(base), None) => Some(base.clone()),
                (None, Some(child_cfg)) => Some(child_cfg.clone()),
                (None, None) => None,
            },
            jailbreak_present_fields: if child.jailbreak.is_some() {
                BTreeSet::new()
            } else {
                self.jailbreak_present_fields.clone()
            },
            computer_use: child
                .computer_use
                .clone()
                .or_else(|| self.computer_use.clone()),
            remote_desktop_side_channel: child
                .remote_desktop_side_channel
                .clone()
                .or_else(|| self.remote_desktop_side_channel.clone()),
            input_injection_capability: child
                .input_injection_capability
                .clone()
                .or_else(|| self.input_injection_capability.clone()),
            #[cfg(feature = "full")]
            spider_sense: match (&self.spider_sense, &child.spider_sense) {
                (Some(base), Some(child_cfg)) => Some(
                    base.merge_with_present_fields(child_cfg, &child.spider_sense_present_fields),
                ),
                (Some(base), None) => Some(base.clone()),
                (None, Some(child_cfg)) => Some(child_cfg.clone()),
                (None, None) => None,
            },
            #[cfg(feature = "full")]
            spider_sense_present_fields: if child.spider_sense.is_some() {
                child.spider_sense_present_fields.clone()
            } else {
                self.spider_sense_present_fields.clone()
            },
            #[cfg(all(feature = "policy-event", not(feature = "full")))]
            spider_sense: child
                .spider_sense
                .clone()
                .or_else(|| self.spider_sense.clone()),
            custom: if !child.custom.is_empty() {
                child.custom.clone()
            } else {
                self.custom.clone()
            },
        }
    }
}

fn merge_prompt_injection_config(
    base: &PromptInjectionConfig,
    child: &PromptInjectionConfig,
    present_fields: &BTreeSet<String>,
) -> PromptInjectionConfig {
    let mut merged = base.clone();
    if present_fields.contains("enabled") {
        merged.enabled = child.enabled;
    }
    if present_fields.contains("warn_at_or_above") {
        merged.warn_at_or_above = child.warn_at_or_above;
    }
    if present_fields.contains("block_at_or_above") {
        merged.block_at_or_above = child.block_at_or_above;
    }
    if present_fields.contains("max_scan_bytes") {
        merged.max_scan_bytes = child.max_scan_bytes;
    }
    merged
}

fn merge_jailbreak_config(
    base: &JailbreakConfig,
    child: &JailbreakConfig,
    present_fields: &BTreeSet<String>,
) -> JailbreakConfig {
    let mut merged = base.clone();
    if present_fields.contains("enabled") {
        merged.enabled = child.enabled;
    }
    if present_fields.contains("block_threshold") {
        merged.detector.block_threshold = child.detector.block_threshold;
    }
    if present_fields.contains("warn_threshold") {
        merged.detector.warn_threshold = child.detector.warn_threshold;
    }
    if present_fields.contains("max_input_bytes") {
        merged.detector.max_input_bytes = child.detector.max_input_bytes;
    }
    merged
}

impl Policy {
    /// Merge this policy with a child policy
    ///
    /// Uses child's merge_strategy to determine how to combine.
    pub fn merge(&self, child: &Policy) -> Self {
        match child.merge_strategy {
            MergeStrategy::Replace => {
                let mut replaced = child.clone();
                replaced.extends = None;
                replaced.merge_strategy = MergeStrategy::default();
                replaced.settings.verification = merge_verification_settings(
                    &self.settings.verification,
                    &child.settings.verification,
                );
                replaced
            }
            MergeStrategy::Merge => {
                let mut settings = if child.settings != PolicySettings::default() {
                    child.settings.clone()
                } else {
                    self.settings.clone()
                };
                settings.verification = merge_verification_settings(
                    &self.settings.verification,
                    &settings.verification,
                );

                Self {
                    version: if child.version != self.version {
                        child.version.clone()
                    } else {
                        self.version.clone()
                    },
                    name: if !child.name.is_empty() {
                        child.name.clone()
                    } else {
                        self.name.clone()
                    },
                    description: if !child.description.is_empty() {
                        child.description.clone()
                    } else {
                        self.description.clone()
                    },
                    extends: None, // Don't propagate extends
                    merge_strategy: MergeStrategy::default(),
                    guards: if child.guards != GuardConfigs::default() {
                        child.guards.clone()
                    } else {
                        self.guards.clone()
                    },
                    custom_guards: if !child.custom_guards.is_empty() {
                        child.custom_guards.clone()
                    } else {
                        self.custom_guards.clone()
                    },
                    settings,
                    posture: child.posture.clone().or_else(|| self.posture.clone()),
                    origins: child.origins.clone().or_else(|| self.origins.clone()),
                    broker: child.broker.clone().or_else(|| self.broker.clone()),
                }
            }
            MergeStrategy::DeepMerge => Self {
                version: if child.version != self.version {
                    child.version.clone()
                } else {
                    self.version.clone()
                },
                name: if !child.name.is_empty() {
                    child.name.clone()
                } else {
                    self.name.clone()
                },
                description: if !child.description.is_empty() {
                    child.description.clone()
                } else {
                    self.description.clone()
                },
                extends: None,
                merge_strategy: MergeStrategy::default(),
                guards: self.guards.merge_with(&child.guards),
                custom_guards: merge_custom_guards(&self.custom_guards, &child.custom_guards),
                settings: self.settings.merge_with(&child.settings),
                posture: match (&self.posture, &child.posture) {
                    (Some(base), Some(child_posture)) => Some(base.merge_with(child_posture)),
                    (Some(base), None) => Some(base.clone()),
                    (None, Some(child_posture)) => Some(child_posture.clone()),
                    (None, None) => None,
                },
                origins: match (&self.origins, &child.origins) {
                    (Some(base), Some(child_cfg)) => Some(base.merge_with(child_cfg)),
                    (Some(base), None) => Some(base.clone()),
                    (None, Some(child_cfg)) => Some(child_cfg.clone()),
                    (None, None) => None,
                },
                broker: match (&self.broker, &child.broker) {
                    (Some(base), Some(child_cfg)) => Some(base.merge_with(child_cfg)),
                    (Some(base), None) => Some(base.clone()),
                    (None, Some(child_cfg)) => Some(child_cfg.clone()),
                    (None, None) => None,
                },
            },
        }
    }
}

fn merge_custom_guards(
    base: &[PolicyCustomGuardSpec],
    child: &[PolicyCustomGuardSpec],
) -> Vec<PolicyCustomGuardSpec> {
    crate::core::merge::merge_keyed_vec(base, child, |cg| cg.id.clone())
}
