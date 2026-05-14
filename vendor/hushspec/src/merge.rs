use crate::extensions::{
    DetectionExtension, Extensions, JailbreakDetection, OriginsExtension, PostureExtension,
    PromptInjectionDetection, ThreatIntelDetection,
};
use crate::rules::Rules;
use crate::schema::{HushSpec, MergeStrategy};

#[must_use = "merged spec is returned, not applied in place"]
pub fn merge(base: &HushSpec, child: &HushSpec) -> HushSpec {
    let strategy = child.merge_strategy.unwrap_or_default();
    match strategy {
        MergeStrategy::Replace => {
            let mut result = child.clone();
            result.extends = None;
            result
        }
        MergeStrategy::Merge => merge_with_strategy(base, child, false),
        MergeStrategy::DeepMerge => merge_with_strategy(base, child, true),
    }
}

fn merge_with_strategy(base: &HushSpec, child: &HushSpec, deep: bool) -> HushSpec {
    HushSpec {
        hushspec: child.hushspec.clone(),
        name: child.name.clone().or_else(|| base.name.clone()),
        description: child
            .description
            .clone()
            .or_else(|| base.description.clone()),
        extends: None,
        merge_strategy: child.merge_strategy,
        rules: merge_rules(&base.rules, &child.rules),
        extensions: if deep {
            merge_extensions_deep(&base.extensions, &child.extensions)
        } else {
            merge_extensions_merge(&base.extensions, &child.extensions)
        },
        metadata: child.metadata.clone().or_else(|| base.metadata.clone()),
    }
}

fn merge_rules(base: &Option<Rules>, child: &Option<Rules>) -> Option<Rules> {
    match (base, child) {
        (_, Some(child_rules)) => {
            let base_rules = base.as_ref().cloned().unwrap_or_default();
            Some(Rules {
                forbidden_paths: child_rules
                    .forbidden_paths
                    .clone()
                    .or(base_rules.forbidden_paths),
                path_allowlist: child_rules
                    .path_allowlist
                    .clone()
                    .or(base_rules.path_allowlist),
                egress: child_rules.egress.clone().or(base_rules.egress),
                secret_patterns: child_rules
                    .secret_patterns
                    .clone()
                    .or(base_rules.secret_patterns),
                patch_integrity: child_rules
                    .patch_integrity
                    .clone()
                    .or(base_rules.patch_integrity),
                shell_commands: child_rules
                    .shell_commands
                    .clone()
                    .or(base_rules.shell_commands),
                tool_access: child_rules.tool_access.clone().or(base_rules.tool_access),
                computer_use: child_rules.computer_use.clone().or(base_rules.computer_use),
                remote_desktop_channels: child_rules
                    .remote_desktop_channels
                    .clone()
                    .or(base_rules.remote_desktop_channels),
                input_injection: child_rules
                    .input_injection
                    .clone()
                    .or(base_rules.input_injection),
            })
        }
        (Some(base_rules), None) => Some(base_rules.clone()),
        (None, None) => None,
    }
}

fn merge_extensions_merge(
    base: &Option<Extensions>,
    child: &Option<Extensions>,
) -> Option<Extensions> {
    match (base, child) {
        (_, Some(child_ext)) => {
            let base_ext = base.as_ref().cloned().unwrap_or_default();
            Some(Extensions {
                posture: child_ext.posture.clone().or(base_ext.posture),
                origins: child_ext.origins.clone().or(base_ext.origins),
                detection: child_ext.detection.clone().or(base_ext.detection),
            })
        }
        (Some(base_ext), None) => Some(base_ext.clone()),
        (None, None) => None,
    }
}

fn merge_extensions_deep(
    base: &Option<Extensions>,
    child: &Option<Extensions>,
) -> Option<Extensions> {
    match (base, child) {
        (_, Some(child_ext)) => {
            let base_ext = base.as_ref().cloned().unwrap_or_default();
            Some(Extensions {
                posture: merge_posture(&base_ext.posture, &child_ext.posture),
                origins: merge_origins(&base_ext.origins, &child_ext.origins),
                detection: merge_detection(&base_ext.detection, &child_ext.detection),
            })
        }
        (Some(base_ext), None) => Some(base_ext.clone()),
        (None, None) => None,
    }
}

fn merge_posture(
    base: &Option<PostureExtension>,
    child: &Option<PostureExtension>,
) -> Option<PostureExtension> {
    match (base, child) {
        (_, Some(child_posture)) => {
            if let Some(base_posture) = base {
                let mut states = base_posture.states.clone();
                for (name, state) in &child_posture.states {
                    states.insert(name.clone(), state.clone());
                }

                Some(PostureExtension {
                    initial: child_posture.initial.clone(),
                    states,
                    transitions: child_posture.transitions.clone(),
                })
            } else {
                Some(child_posture.clone())
            }
        }
        (Some(base_posture), None) => Some(base_posture.clone()),
        (None, None) => None,
    }
}

fn merge_origins(
    base: &Option<OriginsExtension>,
    child: &Option<OriginsExtension>,
) -> Option<OriginsExtension> {
    match (base, child) {
        (_, Some(child_origins)) => {
            if let Some(base_origins) = base {
                let mut merged_profiles = base_origins.profiles.clone();
                for child_profile in &child_origins.profiles {
                    if let Some(pos) = merged_profiles
                        .iter()
                        .position(|profile| profile.id == child_profile.id)
                    {
                        merged_profiles[pos] = child_profile.clone();
                    } else {
                        merged_profiles.push(child_profile.clone());
                    }
                }

                Some(OriginsExtension {
                    default_behavior: child_origins
                        .default_behavior
                        .or(base_origins.default_behavior),
                    profiles: merged_profiles,
                })
            } else {
                Some(child_origins.clone())
            }
        }
        (Some(base_origins), None) => Some(base_origins.clone()),
        (None, None) => None,
    }
}

fn merge_detection(
    base: &Option<DetectionExtension>,
    child: &Option<DetectionExtension>,
) -> Option<DetectionExtension> {
    match (base, child) {
        (_, Some(child_detection)) => {
            if let Some(base_detection) = base {
                Some(DetectionExtension {
                    prompt_injection: merge_prompt_injection(
                        &base_detection.prompt_injection,
                        &child_detection.prompt_injection,
                    ),
                    jailbreak: merge_jailbreak(
                        &base_detection.jailbreak,
                        &child_detection.jailbreak,
                    ),
                    threat_intel: merge_threat_intel(
                        &base_detection.threat_intel,
                        &child_detection.threat_intel,
                    ),
                })
            } else {
                Some(child_detection.clone())
            }
        }
        (Some(base_detection), None) => Some(base_detection.clone()),
        (None, None) => None,
    }
}

fn merge_prompt_injection(
    base: &Option<PromptInjectionDetection>,
    child: &Option<PromptInjectionDetection>,
) -> Option<PromptInjectionDetection> {
    match (base, child) {
        (_, Some(child_prompt)) => {
            if let Some(base_prompt) = base {
                Some(PromptInjectionDetection {
                    enabled: child_prompt.enabled.or(base_prompt.enabled),
                    warn_at_or_above: child_prompt
                        .warn_at_or_above
                        .or(base_prompt.warn_at_or_above),
                    block_at_or_above: child_prompt
                        .block_at_or_above
                        .or(base_prompt.block_at_or_above),
                    max_scan_bytes: child_prompt.max_scan_bytes.or(base_prompt.max_scan_bytes),
                })
            } else {
                Some(child_prompt.clone())
            }
        }
        (Some(base_prompt), None) => Some(base_prompt.clone()),
        (None, None) => None,
    }
}

fn merge_jailbreak(
    base: &Option<JailbreakDetection>,
    child: &Option<JailbreakDetection>,
) -> Option<JailbreakDetection> {
    match (base, child) {
        (_, Some(child_jailbreak)) => {
            if let Some(base_jailbreak) = base {
                Some(JailbreakDetection {
                    enabled: child_jailbreak.enabled.or(base_jailbreak.enabled),
                    block_threshold: child_jailbreak
                        .block_threshold
                        .or(base_jailbreak.block_threshold),
                    warn_threshold: child_jailbreak
                        .warn_threshold
                        .or(base_jailbreak.warn_threshold),
                    max_input_bytes: child_jailbreak
                        .max_input_bytes
                        .or(base_jailbreak.max_input_bytes),
                })
            } else {
                Some(child_jailbreak.clone())
            }
        }
        (Some(base_jailbreak), None) => Some(base_jailbreak.clone()),
        (None, None) => None,
    }
}

fn merge_threat_intel(
    base: &Option<ThreatIntelDetection>,
    child: &Option<ThreatIntelDetection>,
) -> Option<ThreatIntelDetection> {
    match (base, child) {
        (_, Some(child_threat_intel)) => {
            if let Some(base_threat_intel) = base {
                Some(ThreatIntelDetection {
                    enabled: child_threat_intel.enabled.or(base_threat_intel.enabled),
                    pattern_db: child_threat_intel
                        .pattern_db
                        .clone()
                        .or_else(|| base_threat_intel.pattern_db.clone()),
                    similarity_threshold: child_threat_intel
                        .similarity_threshold
                        .or(base_threat_intel.similarity_threshold),
                    top_k: child_threat_intel.top_k.or(base_threat_intel.top_k),
                })
            } else {
                Some(child_threat_intel.clone())
            }
        }
        (Some(base_threat_intel), None) => Some(base_threat_intel.clone()),
        (None, None) => None,
    }
}
