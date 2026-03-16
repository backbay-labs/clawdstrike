//! HushSpec -> Clawdstrike Policy compiler
//!
//! Converts a portable HushSpec document into a Clawdstrike-native Policy,
//! and vice versa.

use crate::error::{Error, Result};
use crate::guards::{
    ComputerUseConfig, ComputerUseMode, EgressAllowlistConfig, ForbiddenPathConfig,
    InputInjectionCapabilityConfig, JailbreakConfig, McpDefaultAction, McpToolConfig,
    PatchIntegrityConfig, PathAllowlistConfig, PromptInjectionConfig,
    RemoteDesktopSideChannelConfig, SecretLeakConfig, SecretPattern, Severity, ShellCommandConfig,
};
use crate::hygiene::PromptInjectionLevel;
use crate::jailbreak::JailbreakGuardConfig;
use crate::origin::{OriginProvider, SpaceType, Visibility};
use crate::policy::{
    BridgePolicy, BridgeTarget, GuardConfigs, MergeStrategy, OriginBudgets, OriginDataPolicy,
    OriginDefaultBehavior, OriginMatch, OriginProfile, OriginsConfig, Policy, PolicySettings,
    POLICY_SCHEMA_VERSION,
};
use crate::posture;

use hush_proxy::policy::PolicyAction;

/// Returns true if the YAML string appears to be a HushSpec document (starts with `hushspec:`).
///
/// Leading blank lines and comment lines (`# ...`) are skipped before checking.
pub fn is_hushspec(yaml: &str) -> bool {
    for line in yaml.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') || trimmed == "---" || trimmed == "..." {
            continue;
        }
        return trimmed.starts_with("hushspec:");
    }
    false
}

/// Compile a HushSpec document into a Clawdstrike Policy.
///
/// Converts portable HushSpec rules, extensions (posture, origins, detection), and
/// merge strategy into Clawdstrike-native types. In `policy-event`-only builds,
/// threat-intel config is preserved via the raw `guards.spider_sense` passthrough.
///
/// Note: this function does **not** call `policy.validate()`; callers that need
/// validation should use [`compile_hushspec`] or validate the resulting policy
/// separately.
pub fn compile(spec: &hushspec::HushSpec) -> Result<Policy> {
    let mut guards = GuardConfigs::default();

    // Compile core rules
    if let Some(rules) = &spec.rules {
        compile_rules(rules, &mut guards);
    }

    // Compile extensions
    let mut posture_config = None;
    let mut origins_config = None;

    if let Some(ext) = &spec.extensions {
        if let Some(posture_ext) = &ext.posture {
            posture_config = Some(compile_posture(posture_ext));
        }
        if let Some(origins_ext) = &ext.origins {
            origins_config = Some(compile_origins(origins_ext));
        }
        if let Some(detection_ext) = &ext.detection {
            compile_detection(detection_ext, &mut guards)?;
        }
    }

    let merge_strategy = spec
        .merge_strategy
        .as_ref()
        .map(|ms| match ms {
            hushspec::schema::MergeStrategy::Replace => MergeStrategy::Replace,
            hushspec::schema::MergeStrategy::Merge => MergeStrategy::Merge,
            hushspec::schema::MergeStrategy::DeepMerge => MergeStrategy::DeepMerge,
        })
        .unwrap_or_default();

    Ok(Policy {
        version: POLICY_SCHEMA_VERSION.to_string(),
        name: spec.name.clone().unwrap_or_default(),
        description: spec.description.clone().unwrap_or_default(),
        extends: spec.extends.as_ref().map(|e| {
            // Convert hushspec:X references to clawdstrike ruleset names
            e.strip_prefix("hushspec:").unwrap_or(e).to_string()
        }),
        merge_strategy,
        guards,
        custom_guards: Vec::new(),
        settings: PolicySettings::default(),
        posture: posture_config,
        origins: origins_config,
        broker: None,
    })
}

/// Parse, validate, and compile a HushSpec YAML document into a Clawdstrike Policy.
///
/// This is the recommended entry point for loading HushSpec documents. It parses
/// the YAML, runs HushSpec schema validation, and compiles the result into a
/// validated Clawdstrike [`Policy`]. Returns an error if parsing or validation
/// fails at either the HushSpec or Clawdstrike layer.
pub fn compile_hushspec(yaml: &str) -> Result<Policy> {
    let spec = hushspec::HushSpec::parse(yaml)
        .map_err(|e| Error::ConfigError(format!("Failed to parse HushSpec YAML: {e}")))?;
    let validation = hushspec::validate(&spec);
    if !validation.is_valid() {
        let errors: Vec<String> = validation.errors.iter().map(|e| e.to_string()).collect();
        return Err(Error::ConfigError(format!(
            "HushSpec validation failed: {}",
            errors.join(", ")
        )));
    }
    let policy = compile(&spec)?;
    policy.validate()?;
    Ok(policy)
}

/// Decompile a Clawdstrike Policy back into a HushSpec document.
///
/// Engine-only fields (settings, broker, custom_guards, async config, merge helpers)
/// are dropped since they have no HushSpec representation. Detection guards
/// (prompt injection, jailbreak, Spider Sense) are mapped to the detection extension.
pub fn decompile(policy: &Policy) -> hushspec::HushSpec {
    let mut rules = hushspec::Rules::default();
    let mut has_rules = false;

    // Decompile guards -> rules
    if let Some(fp) = &policy.guards.forbidden_path {
        has_rules = true;
        rules.forbidden_paths = Some(hushspec::ForbiddenPathsRule {
            enabled: fp.enabled,
            patterns: decompile_forbidden_path_patterns(fp),
            exceptions: fp.exceptions.clone(),
        });
    }

    if let Some(pa) = &policy.guards.path_allowlist {
        has_rules = true;
        rules.path_allowlist = Some(hushspec::PathAllowlistRule {
            enabled: pa.enabled,
            read: pa.file_access_allow.clone(),
            write: pa.file_write_allow.clone(),
            patch: pa.patch_allow.clone(),
        });
    }

    if let Some(eg) = &policy.guards.egress_allowlist {
        has_rules = true;
        rules.egress = Some(hushspec::EgressRule {
            enabled: eg.enabled,
            allow: eg.allow.clone(),
            block: eg.block.clone(),
            default: match eg.default_action {
                Some(PolicyAction::Allow) | Some(PolicyAction::Log) => {
                    hushspec::DefaultAction::Allow
                }
                Some(PolicyAction::Block) | None => hushspec::DefaultAction::Block,
            },
        });
    }

    if let Some(sl) = &policy.guards.secret_leak {
        has_rules = true;
        rules.secret_patterns = Some(hushspec::SecretPatternsRule {
            enabled: sl.enabled,
            patterns: sl
                .effective_patterns()
                .iter()
                .map(|p| hushspec::rules::SecretPattern {
                    name: p.name.clone(),
                    pattern: p.pattern.clone(),
                    severity: deconvert_severity(&p.severity),
                    description: p.description.clone(),
                })
                .collect(),
            skip_paths: sl.skip_paths.clone(),
        });
    }

    if let Some(pi) = &policy.guards.patch_integrity {
        has_rules = true;
        rules.patch_integrity = Some(hushspec::PatchIntegrityRule {
            enabled: pi.enabled,
            max_additions: pi.max_additions,
            max_deletions: pi.max_deletions,
            forbidden_patterns: pi.forbidden_patterns.clone(),
            require_balance: pi.require_balance,
            max_imbalance_ratio: pi.max_imbalance_ratio,
        });
    }

    if let Some(sc) = &policy.guards.shell_command {
        has_rules = true;
        rules.shell_commands = Some(hushspec::ShellCommandsRule {
            enabled: sc.enabled,
            forbidden_patterns: sc.forbidden_patterns.clone(),
        });
    }

    if let Some(mt) = &policy.guards.mcp_tool {
        has_rules = true;
        rules.tool_access = Some(hushspec::ToolAccessRule {
            enabled: mt.enabled,
            allow: mt.allow.clone(),
            block: mt.block.clone(),
            require_confirmation: mt.require_confirmation.clone(),
            default: mt
                .default_action
                .as_ref()
                .map(|a| match a {
                    McpDefaultAction::Allow => hushspec::DefaultAction::Allow,
                    McpDefaultAction::Block => hushspec::DefaultAction::Block,
                })
                .unwrap_or(hushspec::DefaultAction::Allow),
            max_args_size: mt.max_args_size,
        });
    }

    if let Some(cu) = &policy.guards.computer_use {
        has_rules = true;
        rules.computer_use = Some(hushspec::ComputerUseRule {
            enabled: cu.enabled,
            mode: match cu.mode {
                ComputerUseMode::Observe => hushspec::ComputerUseMode::Observe,
                ComputerUseMode::Guardrail => hushspec::ComputerUseMode::Guardrail,
                ComputerUseMode::FailClosed => hushspec::ComputerUseMode::FailClosed,
            },
            allowed_actions: cu.allowed_actions.clone(),
        });
    }

    if let Some(rd) = &policy.guards.remote_desktop_side_channel {
        has_rules = true;
        rules.remote_desktop_channels = Some(hushspec::RemoteDesktopChannelsRule {
            enabled: rd.enabled,
            clipboard: rd.clipboard_enabled,
            file_transfer: rd.file_transfer_enabled,
            audio: rd.audio_enabled,
            drive_mapping: rd.drive_mapping_enabled,
        });
    }

    if let Some(ii) = &policy.guards.input_injection_capability {
        has_rules = true;
        rules.input_injection = Some(hushspec::InputInjectionRule {
            enabled: ii.enabled,
            allowed_types: ii.allowed_input_types.clone(),
            require_postcondition_probe: ii.require_postcondition_probe,
        });
    }

    // Build extensions
    let mut extensions = hushspec::Extensions::default();
    let mut has_extensions = false;

    // Decompile posture
    if let Some(posture_cfg) = &policy.posture {
        has_extensions = true;
        extensions.posture = Some(hushspec::extensions::PostureExtension {
            initial: posture_cfg.initial.clone(),
            states: posture_cfg
                .states
                .iter()
                .map(|(name, state)| {
                    (
                        name.clone(),
                        hushspec::extensions::PostureState {
                            description: state.description.clone(),
                            capabilities: state.capabilities.clone(),
                            budgets: state.budgets.iter().map(|(k, v)| (k.clone(), *v)).collect(),
                        },
                    )
                })
                .collect(),
            transitions: posture_cfg
                .transitions
                .iter()
                .map(|t| hushspec::extensions::PostureTransition {
                    from: t.from.clone(),
                    to: t.to.clone(),
                    on: transition_trigger_to_hushspec(&t.on),
                    after: t.after.clone(),
                })
                .collect(),
        });
    }

    // Decompile origins
    if let Some(origins_cfg) = &policy.origins {
        has_extensions = true;
        extensions.origins = Some(decompile_origins(origins_cfg));
    }

    // Decompile detection guards -> detection extension
    let mut detection = hushspec::extensions::DetectionExtension {
        prompt_injection: None,
        jailbreak: None,
        threat_intel: None,
    };
    let mut has_detection = false;

    if let Some(pi) = &policy.guards.prompt_injection {
        has_detection = true;
        detection.prompt_injection = Some(hushspec::extensions::PromptInjectionDetection {
            enabled: pi.enabled,
            warn_at_or_above: prompt_level_to_detection_level(pi.warn_at_or_above),
            block_at_or_above: prompt_level_to_detection_level(pi.block_at_or_above),
            max_scan_bytes: pi.max_scan_bytes,
        });
    }

    if let Some(jb) = &policy.guards.jailbreak {
        has_detection = true;
        detection.jailbreak = Some(hushspec::extensions::JailbreakDetection {
            enabled: jb.enabled,
            block_threshold: u32::from(jb.detector.block_threshold),
            warn_threshold: u32::from(jb.detector.warn_threshold),
            max_input_bytes: jb.detector.max_input_bytes,
        });
    }

    #[cfg(feature = "full")]
    {
        if let Some(ref ss) = policy.guards.spider_sense {
            has_detection = true;
            detection.threat_intel = Some(hushspec::extensions::ThreatIntelDetection {
                enabled: ss.enabled,
                pattern_db: if ss.pattern_db_path.is_empty() {
                    None
                } else {
                    Some(ss.pattern_db_path.clone())
                },
                similarity_threshold: ss.similarity_threshold,
                top_k: ss.top_k,
            });
        }
    }

    #[cfg(all(feature = "policy-event", not(feature = "full")))]
    {
        if let Some(ref ss) = policy.guards.spider_sense {
            if let Some(ti) = decompile_policy_event_threat_intel_passthrough(ss) {
                has_detection = true;
                detection.threat_intel = Some(ti);
            }
        }
    }

    if has_detection {
        has_extensions = true;
        extensions.detection = Some(detection);
    }

    let merge_strategy = match &policy.merge_strategy {
        MergeStrategy::Replace => Some(hushspec::schema::MergeStrategy::Replace),
        MergeStrategy::Merge => Some(hushspec::schema::MergeStrategy::Merge),
        MergeStrategy::DeepMerge => None,
    };

    hushspec::HushSpec {
        hushspec: hushspec::HUSHSPEC_VERSION.to_string(),
        name: if policy.name.is_empty() {
            None
        } else {
            Some(policy.name.clone())
        },
        description: if policy.description.is_empty() {
            None
        } else {
            Some(policy.description.clone())
        },
        extends: policy.extends.clone(),
        merge_strategy,
        rules: if has_rules { Some(rules) } else { None },
        extensions: if has_extensions {
            Some(extensions)
        } else {
            None
        },
    }
}

// ---------------------------------------------------------------------------
// Internal helpers: compile direction (HushSpec -> Clawdstrike)
// ---------------------------------------------------------------------------

fn decompile_forbidden_path_patterns(fp: &ForbiddenPathConfig) -> Vec<String> {
    if fp.patterns.is_none() && fp.additional_patterns.is_empty() && fp.remove_patterns.is_empty() {
        return Vec::new();
    }

    fp.effective_patterns()
}

#[cfg(all(feature = "policy-event", not(feature = "full")))]
fn compile_policy_event_threat_intel_passthrough(
    ti: &hushspec::extensions::ThreatIntelDetection,
) -> serde_json::Value {
    serde_json::json!({
        "enabled": ti.enabled,
        "pattern_db_path": ti.pattern_db.clone().unwrap_or_default(),
        "similarity_threshold": ti.similarity_threshold,
        "top_k": ti.top_k,
    })
}

#[cfg(all(feature = "policy-event", not(feature = "full")))]
fn decompile_policy_event_threat_intel_passthrough(
    spider_sense: &serde_json::Value,
) -> Option<hushspec::extensions::ThreatIntelDetection> {
    let obj = spider_sense.as_object()?;

    let enabled = obj.get("enabled").and_then(|v| v.as_bool()).unwrap_or(true);
    let pattern_db = obj
        .get("pattern_db_path")
        .and_then(|v| v.as_str())
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned);
    let similarity_threshold = obj
        .get("similarity_threshold")
        .and_then(|v| v.as_f64())
        .unwrap_or(0.85);
    let top_k = obj
        .get("top_k")
        .and_then(|v| v.as_u64())
        .and_then(|v| usize::try_from(v).ok())
        .unwrap_or(5);

    Some(hushspec::extensions::ThreatIntelDetection {
        enabled,
        pattern_db,
        similarity_threshold,
        top_k,
    })
}

fn compile_rules(rules: &hushspec::rules::Rules, guards: &mut GuardConfigs) {
    if let Some(fp) = &rules.forbidden_paths {
        guards.forbidden_path = Some(ForbiddenPathConfig {
            enabled: fp.enabled,
            patterns: if fp.patterns.is_empty() {
                None
            } else {
                Some(fp.patterns.clone())
            },
            exceptions: fp.exceptions.clone(),
            additional_patterns: vec![],
            remove_patterns: vec![],
        });
    }

    if let Some(pa) = &rules.path_allowlist {
        guards.path_allowlist = Some(PathAllowlistConfig {
            enabled: pa.enabled,
            file_access_allow: pa.read.clone(),
            file_write_allow: pa.write.clone(),
            patch_allow: pa.patch.clone(),
        });
    }

    if let Some(eg) = &rules.egress {
        guards.egress_allowlist = Some(EgressAllowlistConfig {
            enabled: eg.enabled,
            allow: eg.allow.clone(),
            block: eg.block.clone(),
            default_action: Some(match eg.default {
                hushspec::DefaultAction::Allow => PolicyAction::Allow,
                hushspec::DefaultAction::Block => PolicyAction::Block,
            }),
            additional_allow: vec![],
            remove_allow: vec![],
            additional_block: vec![],
            remove_block: vec![],
        });
    }

    if let Some(sp) = &rules.secret_patterns {
        guards.secret_leak = Some(SecretLeakConfig {
            enabled: sp.enabled,
            redact: true,
            severity_threshold: Severity::Error,
            patterns: sp
                .patterns
                .iter()
                .map(|p| SecretPattern {
                    name: p.name.clone(),
                    pattern: p.pattern.clone(),
                    severity: convert_severity(&p.severity),
                    description: p.description.clone(),
                    luhn_check: false,
                    masking: None,
                })
                .collect(),
            additional_patterns: vec![],
            remove_patterns: vec![],
            skip_paths: sp.skip_paths.clone(),
        });
    }

    if let Some(pi) = &rules.patch_integrity {
        guards.patch_integrity = Some(PatchIntegrityConfig {
            enabled: pi.enabled,
            max_additions: pi.max_additions,
            max_deletions: pi.max_deletions,
            forbidden_patterns: pi.forbidden_patterns.clone(),
            require_balance: pi.require_balance,
            max_imbalance_ratio: pi.max_imbalance_ratio,
        });
    }

    if let Some(sc) = &rules.shell_commands {
        guards.shell_command = Some(ShellCommandConfig {
            enabled: sc.enabled,
            forbidden_patterns: sc.forbidden_patterns.clone(),
            enforce_forbidden_paths: true,
        });
    }

    if let Some(ta) = &rules.tool_access {
        guards.mcp_tool = Some(McpToolConfig {
            enabled: ta.enabled,
            allow: ta.allow.clone(),
            block: ta.block.clone(),
            require_confirmation: ta.require_confirmation.clone(),
            default_action: Some(match ta.default {
                hushspec::DefaultAction::Allow => McpDefaultAction::Allow,
                hushspec::DefaultAction::Block => McpDefaultAction::Block,
            }),
            max_args_size: ta.max_args_size,
            additional_allow: vec![],
            remove_allow: vec![],
            additional_block: vec![],
            remove_block: vec![],
        });
    }

    if let Some(cu) = &rules.computer_use {
        guards.computer_use = Some(ComputerUseConfig {
            enabled: cu.enabled,
            allowed_actions: cu.allowed_actions.clone(),
            mode: match cu.mode {
                hushspec::ComputerUseMode::Observe => ComputerUseMode::Observe,
                hushspec::ComputerUseMode::Guardrail => ComputerUseMode::Guardrail,
                hushspec::ComputerUseMode::FailClosed => ComputerUseMode::FailClosed,
            },
        });
    }

    if let Some(rd) = &rules.remote_desktop_channels {
        guards.remote_desktop_side_channel = Some(RemoteDesktopSideChannelConfig {
            enabled: rd.enabled,
            clipboard_enabled: rd.clipboard,
            file_transfer_enabled: rd.file_transfer,
            session_share_enabled: false,
            audio_enabled: rd.audio,
            drive_mapping_enabled: rd.drive_mapping,
            printing_enabled: true,
            max_transfer_size_bytes: None,
        });
    }

    if let Some(ii) = &rules.input_injection {
        guards.input_injection_capability = Some(InputInjectionCapabilityConfig {
            enabled: ii.enabled,
            allowed_input_types: ii.allowed_types.clone(),
            require_postcondition_probe: ii.require_postcondition_probe,
        });
    }
}

fn compile_posture(ext: &hushspec::extensions::PostureExtension) -> posture::PostureConfig {
    posture::PostureConfig {
        initial: ext.initial.clone(),
        states: ext
            .states
            .iter()
            .map(|(name, state)| {
                (
                    name.clone(),
                    posture::PostureState {
                        description: state.description.clone(),
                        capabilities: state.capabilities.clone(),
                        budgets: state.budgets.iter().map(|(k, v)| (k.clone(), *v)).collect(),
                    },
                )
            })
            .collect(),
        transitions: ext
            .transitions
            .iter()
            .map(|t| posture::PostureTransition {
                from: t.from.clone(),
                to: t.to.clone(),
                on: hushspec_trigger_to_posture(&t.on),
                after: t.after.clone(),
                requires: Vec::new(),
            })
            .collect(),
    }
}

fn compile_origins(ext: &hushspec::extensions::OriginsExtension) -> OriginsConfig {
    let default_behavior = Some(match ext.default_behavior {
        hushspec::extensions::OriginDefaultBehavior::Deny => OriginDefaultBehavior::Deny,
        hushspec::extensions::OriginDefaultBehavior::MinimalProfile => {
            OriginDefaultBehavior::MinimalProfile
        }
    });

    let profiles = ext
        .profiles
        .iter()
        .map(|p| {
            let match_rules = if let Some(m) = &p.match_rules {
                OriginMatch {
                    provider: m.provider.as_ref().map(|s| parse_origin_provider(s)),
                    tenant_id: m.tenant_id.clone(),
                    space_id: m.space_id.clone(),
                    space_type: m.space_type.as_ref().map(|s| parse_space_type(s)),
                    visibility: m.visibility.as_ref().map(|s| parse_visibility(s)),
                    external_participants: m.external_participants,
                    tags: m.tags.clone(),
                    sensitivity: m.sensitivity.clone(),
                    actor_role: m.actor_role.clone(),
                    thread_id: None,
                    provenance_confidence: None,
                }
            } else {
                OriginMatch::default()
            };

            let mcp = p.tool_access.as_ref().map(|ta| McpToolConfig {
                enabled: ta.enabled,
                allow: ta.allow.clone(),
                block: ta.block.clone(),
                require_confirmation: ta.require_confirmation.clone(),
                default_action: Some(match ta.default {
                    hushspec::DefaultAction::Allow => McpDefaultAction::Allow,
                    hushspec::DefaultAction::Block => McpDefaultAction::Block,
                }),
                max_args_size: ta.max_args_size,
                additional_allow: vec![],
                remove_allow: vec![],
                additional_block: vec![],
                remove_block: vec![],
            });

            let egress = p.egress.as_ref().map(|eg| EgressAllowlistConfig {
                enabled: eg.enabled,
                allow: eg.allow.clone(),
                block: eg.block.clone(),
                default_action: Some(match eg.default {
                    hushspec::DefaultAction::Allow => PolicyAction::Allow,
                    hushspec::DefaultAction::Block => PolicyAction::Block,
                }),
                additional_allow: vec![],
                remove_allow: vec![],
                additional_block: vec![],
                remove_block: vec![],
            });

            let data = p.data.as_ref().map(|d| OriginDataPolicy {
                allow_external_sharing: d.allow_external_sharing,
                redact_before_send: d.redact_before_send,
                block_sensitive_outputs: d.block_sensitive_outputs,
            });

            let budgets = p.budgets.as_ref().map(|b| OriginBudgets {
                mcp_tool_calls: b.tool_calls,
                egress_calls: b.egress_calls,
                shell_commands: b.shell_commands,
            });

            let bridge_policy = p.bridge.as_ref().map(|b| BridgePolicy {
                allow_cross_origin: b.allow_cross_origin,
                allowed_targets: b
                    .allowed_targets
                    .iter()
                    .map(|t| BridgeTarget {
                        provider: t.provider.as_ref().map(|s| parse_origin_provider(s)),
                        space_type: t.space_type.as_ref().map(|s| parse_space_type(s)),
                        tags: t.tags.clone(),
                        visibility: t.visibility.as_ref().map(|s| parse_visibility(s)),
                    })
                    .collect(),
                require_approval: b.require_approval,
            });

            OriginProfile {
                id: p.id.clone(),
                match_rules,
                posture: p.posture.clone(),
                mcp,
                egress,
                data,
                budgets,
                bridge_policy,
                explanation: p.explanation.clone(),
            }
        })
        .collect();

    OriginsConfig {
        default_behavior,
        profiles,
    }
}

fn compile_detection(
    ext: &hushspec::extensions::DetectionExtension,
    guards: &mut GuardConfigs,
) -> Result<()> {
    if let Some(pi) = &ext.prompt_injection {
        guards.prompt_injection = Some(PromptInjectionConfig {
            enabled: pi.enabled,
            warn_at_or_above: detection_level_to_prompt_level(pi.warn_at_or_above),
            block_at_or_above: detection_level_to_prompt_level(pi.block_at_or_above),
            max_scan_bytes: pi.max_scan_bytes,
        });
    }

    if let Some(jb) = &ext.jailbreak {
        if jb.block_threshold > 255 {
            return Err(Error::ConfigError(format!(
                "jailbreak block_threshold {} exceeds maximum value 255",
                jb.block_threshold
            )));
        }
        if jb.warn_threshold > 255 {
            return Err(Error::ConfigError(format!(
                "jailbreak warn_threshold {} exceeds maximum value 255",
                jb.warn_threshold
            )));
        }
        guards.jailbreak = Some(JailbreakConfig {
            enabled: jb.enabled,
            detector: JailbreakGuardConfig {
                block_threshold: jb.block_threshold as u8,
                warn_threshold: jb.warn_threshold as u8,
                max_input_bytes: jb.max_input_bytes,
                ..Default::default()
            },
        });
    }

    // Spider Sense mapping is feature-gated.
    #[cfg(feature = "full")]
    if let Some(ti) = &ext.threat_intel {
        let mut cfg = crate::async_guards::threat_intel::SpiderSensePolicyConfig {
            enabled: ti.enabled,
            pattern_db_path: ti.pattern_db.clone().unwrap_or_default(),
            similarity_threshold: ti.similarity_threshold,
            top_k: ti.top_k,
            ..Default::default()
        };
        // Re-enable since Default sets enabled=false
        cfg.enabled = ti.enabled;
        guards.spider_sense = Some(cfg);
    }

    #[cfg(all(feature = "policy-event", not(feature = "full")))]
    if let Some(ti) = &ext.threat_intel {
        guards.spider_sense = Some(compile_policy_event_threat_intel_passthrough(ti));
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Internal helpers: decompile direction (Clawdstrike -> HushSpec)
// ---------------------------------------------------------------------------

fn decompile_origins(origins_cfg: &OriginsConfig) -> hushspec::extensions::OriginsExtension {
    let default_behavior = match origins_cfg.default_behavior {
        Some(OriginDefaultBehavior::Deny) | None => {
            hushspec::extensions::OriginDefaultBehavior::Deny
        }
        Some(OriginDefaultBehavior::MinimalProfile) => {
            hushspec::extensions::OriginDefaultBehavior::MinimalProfile
        }
    };

    let profiles = origins_cfg
        .profiles
        .iter()
        .map(|p| {
            let match_rules = if p.match_rules == OriginMatch::default() {
                None
            } else {
                Some(hushspec::extensions::OriginMatch {
                    provider: p.match_rules.provider.as_ref().map(|pr| pr.to_string()),
                    tenant_id: p.match_rules.tenant_id.clone(),
                    space_id: p.match_rules.space_id.clone(),
                    space_type: p.match_rules.space_type.as_ref().map(|st| st.to_string()),
                    visibility: p.match_rules.visibility.as_ref().map(|v| v.to_string()),
                    external_participants: p.match_rules.external_participants,
                    tags: p.match_rules.tags.clone(),
                    sensitivity: p.match_rules.sensitivity.clone(),
                    actor_role: p.match_rules.actor_role.clone(),
                })
            };

            let tool_access = p.mcp.as_ref().map(|mt| hushspec::ToolAccessRule {
                enabled: mt.enabled,
                allow: mt.allow.clone(),
                block: mt.block.clone(),
                require_confirmation: mt.require_confirmation.clone(),
                default: mt
                    .default_action
                    .as_ref()
                    .map(|a| match a {
                        McpDefaultAction::Allow => hushspec::DefaultAction::Allow,
                        McpDefaultAction::Block => hushspec::DefaultAction::Block,
                    })
                    .unwrap_or(hushspec::DefaultAction::Allow),
                max_args_size: mt.max_args_size,
            });

            let egress = p.egress.as_ref().map(|eg| hushspec::EgressRule {
                enabled: eg.enabled,
                allow: eg.allow.clone(),
                block: eg.block.clone(),
                default: match eg.default_action {
                    Some(PolicyAction::Allow) | Some(PolicyAction::Log) => {
                        hushspec::DefaultAction::Allow
                    }
                    Some(PolicyAction::Block) | None => hushspec::DefaultAction::Block,
                },
            });

            let data = p
                .data
                .as_ref()
                .map(|d| hushspec::extensions::OriginDataPolicy {
                    allow_external_sharing: d.allow_external_sharing,
                    redact_before_send: d.redact_before_send,
                    block_sensitive_outputs: d.block_sensitive_outputs,
                });

            let budgets = p
                .budgets
                .as_ref()
                .map(|b| hushspec::extensions::OriginBudgets {
                    tool_calls: b.mcp_tool_calls,
                    egress_calls: b.egress_calls,
                    shell_commands: b.shell_commands,
                });

            let bridge = p
                .bridge_policy
                .as_ref()
                .map(|b| hushspec::extensions::BridgePolicy {
                    allow_cross_origin: b.allow_cross_origin,
                    allowed_targets: b
                        .allowed_targets
                        .iter()
                        .map(|t| hushspec::extensions::BridgeTarget {
                            provider: t.provider.as_ref().map(|pr| pr.to_string()),
                            space_type: t.space_type.as_ref().map(|st| st.to_string()),
                            tags: t.tags.clone(),
                            visibility: t.visibility.as_ref().map(|v| v.to_string()),
                        })
                        .collect(),
                    require_approval: b.require_approval,
                });

            hushspec::extensions::OriginProfile {
                id: p.id.clone(),
                match_rules,
                posture: p.posture.clone(),
                tool_access,
                egress,
                data,
                budgets,
                bridge,
                explanation: p.explanation.clone(),
            }
        })
        .collect();

    hushspec::extensions::OriginsExtension {
        default_behavior,
        profiles,
    }
}

// ---------------------------------------------------------------------------
// Type conversion helpers
// ---------------------------------------------------------------------------

fn convert_severity(s: &hushspec::Severity) -> Severity {
    match s {
        hushspec::Severity::Critical => Severity::Critical,
        hushspec::Severity::Error => Severity::Error,
        hushspec::Severity::Warn => Severity::Warning,
    }
}

fn deconvert_severity(s: &Severity) -> hushspec::Severity {
    match s {
        Severity::Critical => hushspec::Severity::Critical,
        Severity::Error => hushspec::Severity::Error,
        // Info and Warning both map to Warn (HushSpec has no Info variant)
        Severity::Warning | Severity::Info => hushspec::Severity::Warn,
    }
}

fn detection_level_to_prompt_level(
    level: hushspec::extensions::DetectionLevel,
) -> PromptInjectionLevel {
    match level {
        hushspec::extensions::DetectionLevel::Safe => PromptInjectionLevel::Safe,
        hushspec::extensions::DetectionLevel::Suspicious => PromptInjectionLevel::Suspicious,
        hushspec::extensions::DetectionLevel::High => PromptInjectionLevel::High,
        hushspec::extensions::DetectionLevel::Critical => PromptInjectionLevel::Critical,
    }
}

fn prompt_level_to_detection_level(
    level: PromptInjectionLevel,
) -> hushspec::extensions::DetectionLevel {
    match level {
        PromptInjectionLevel::Safe => hushspec::extensions::DetectionLevel::Safe,
        PromptInjectionLevel::Suspicious => hushspec::extensions::DetectionLevel::Suspicious,
        PromptInjectionLevel::High => hushspec::extensions::DetectionLevel::High,
        PromptInjectionLevel::Critical => hushspec::extensions::DetectionLevel::Critical,
    }
}

fn hushspec_trigger_to_posture(
    trigger: &hushspec::extensions::TransitionTrigger,
) -> posture::TransitionTrigger {
    match trigger {
        hushspec::extensions::TransitionTrigger::UserApproval => {
            posture::TransitionTrigger::UserApproval
        }
        hushspec::extensions::TransitionTrigger::UserDenial => {
            posture::TransitionTrigger::UserDenial
        }
        hushspec::extensions::TransitionTrigger::CriticalViolation => {
            posture::TransitionTrigger::CriticalViolation
        }
        hushspec::extensions::TransitionTrigger::AnyViolation => {
            posture::TransitionTrigger::AnyViolation
        }
        hushspec::extensions::TransitionTrigger::Timeout => posture::TransitionTrigger::Timeout,
        hushspec::extensions::TransitionTrigger::BudgetExhausted => {
            posture::TransitionTrigger::BudgetExhausted
        }
        hushspec::extensions::TransitionTrigger::PatternMatch => {
            posture::TransitionTrigger::PatternMatch
        }
    }
}

fn transition_trigger_to_hushspec(
    trigger: &posture::TransitionTrigger,
) -> hushspec::extensions::TransitionTrigger {
    match trigger {
        posture::TransitionTrigger::UserApproval => {
            hushspec::extensions::TransitionTrigger::UserApproval
        }
        posture::TransitionTrigger::UserDenial => {
            hushspec::extensions::TransitionTrigger::UserDenial
        }
        posture::TransitionTrigger::CriticalViolation => {
            hushspec::extensions::TransitionTrigger::CriticalViolation
        }
        posture::TransitionTrigger::AnyViolation => {
            hushspec::extensions::TransitionTrigger::AnyViolation
        }
        posture::TransitionTrigger::Timeout => hushspec::extensions::TransitionTrigger::Timeout,
        posture::TransitionTrigger::BudgetExhausted => {
            hushspec::extensions::TransitionTrigger::BudgetExhausted
        }
        posture::TransitionTrigger::PatternMatch => {
            hushspec::extensions::TransitionTrigger::PatternMatch
        }
    }
}

fn parse_origin_provider(s: &str) -> OriginProvider {
    match s {
        "slack" => OriginProvider::Slack,
        "teams" => OriginProvider::Teams,
        "github" => OriginProvider::GitHub,
        "jira" => OriginProvider::Jira,
        "email" => OriginProvider::Email,
        "discord" => OriginProvider::Discord,
        "webhook" => OriginProvider::Webhook,
        other => OriginProvider::Custom(other.to_string()),
    }
}

fn parse_space_type(s: &str) -> SpaceType {
    match s {
        "channel" => SpaceType::Channel,
        "group" => SpaceType::Group,
        "dm" => SpaceType::Dm,
        "thread" => SpaceType::Thread,
        "issue" => SpaceType::Issue,
        "ticket" => SpaceType::Ticket,
        "pull_request" => SpaceType::PullRequest,
        "email_thread" => SpaceType::EmailThread,
        other => SpaceType::Custom(other.to_string()),
    }
}

fn parse_visibility(s: &str) -> Visibility {
    match s {
        "private" => Visibility::Private,
        "internal" => Visibility::Internal,
        "public" => Visibility::Public,
        "external_shared" => Visibility::ExternalShared,
        _ => Visibility::Unknown,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_hushspec_true() {
        assert!(is_hushspec("hushspec: \"0.1.0\"\nname: test\n"));
    }

    #[test]
    fn test_is_hushspec_with_comments() {
        assert!(is_hushspec("# comment\nhushspec: \"0.1.0\"\n"));
    }

    #[test]
    fn test_is_hushspec_false() {
        assert!(!is_hushspec("version: \"1.5.0\"\nname: test\n"));
    }

    #[test]
    fn test_roundtrip_minimal() {
        let spec = hushspec::HushSpec {
            hushspec: "0.1.0".to_string(),
            name: Some("test".to_string()),
            description: None,
            extends: None,
            merge_strategy: None,
            rules: None,
            extensions: None,
        };

        let policy = compile(&spec).expect("compile should succeed");
        assert_eq!(policy.version, POLICY_SCHEMA_VERSION);
        assert_eq!(policy.name, "test");

        let roundtrip = decompile(&policy);
        assert_eq!(roundtrip.name, Some("test".to_string()));
    }

    #[test]
    fn test_compile_forbidden_paths() {
        let spec = hushspec::HushSpec {
            hushspec: "0.1.0".to_string(),
            name: None,
            description: None,
            extends: None,
            merge_strategy: None,
            rules: Some(hushspec::Rules {
                forbidden_paths: Some(hushspec::ForbiddenPathsRule {
                    enabled: true,
                    patterns: vec!["**/.ssh/**".to_string()],
                    exceptions: vec![],
                }),
                ..Default::default()
            }),
            extensions: None,
        };

        let policy = compile(&spec).expect("compile should succeed");
        let fp = policy
            .guards
            .forbidden_path
            .expect("forbidden_path should be set");
        assert!(fp.enabled);
        assert_eq!(fp.patterns, Some(vec!["**/.ssh/**".to_string()]));
    }

    #[test]
    fn test_compile_egress() {
        let spec = hushspec::HushSpec {
            hushspec: "0.1.0".to_string(),
            name: None,
            description: None,
            extends: None,
            merge_strategy: None,
            rules: Some(hushspec::Rules {
                egress: Some(hushspec::EgressRule {
                    enabled: true,
                    allow: vec!["*.example.com".to_string()],
                    block: vec![],
                    default: hushspec::DefaultAction::Block,
                }),
                ..Default::default()
            }),
            extensions: None,
        };

        let policy = compile(&spec).expect("compile should succeed");
        let eg = policy
            .guards
            .egress_allowlist
            .expect("egress should be set");
        assert!(eg.enabled);
        assert_eq!(eg.allow, vec!["*.example.com".to_string()]);
        assert_eq!(eg.default_action, Some(PolicyAction::Block));
    }

    #[test]
    fn test_severity_mapping() {
        assert_eq!(
            convert_severity(&hushspec::Severity::Critical),
            Severity::Critical
        );
        assert_eq!(
            convert_severity(&hushspec::Severity::Warn),
            Severity::Warning
        );
        assert_eq!(
            deconvert_severity(&Severity::Warning),
            hushspec::Severity::Warn
        );
        assert_eq!(
            deconvert_severity(&Severity::Info),
            hushspec::Severity::Warn
        );
    }

    #[test]
    fn test_compile_detection_jailbreak() {
        let spec = hushspec::HushSpec {
            hushspec: "0.1.0".to_string(),
            name: None,
            description: None,
            extends: None,
            merge_strategy: None,
            rules: None,
            extensions: Some(hushspec::Extensions {
                detection: Some(hushspec::extensions::DetectionExtension {
                    prompt_injection: None,
                    jailbreak: Some(hushspec::extensions::JailbreakDetection {
                        enabled: true,
                        block_threshold: 70,
                        warn_threshold: 30,
                        max_input_bytes: 200_000,
                    }),
                    threat_intel: None,
                }),
                ..Default::default()
            }),
        };

        let policy = compile(&spec).expect("compile should succeed");
        let jb = policy.guards.jailbreak.expect("jailbreak should be set");
        assert_eq!(jb.detector.block_threshold, 70u8);
        assert_eq!(jb.detector.warn_threshold, 30u8);
    }

    #[test]
    fn test_compile_detection_prompt_injection() {
        let spec = hushspec::HushSpec {
            hushspec: "0.1.0".to_string(),
            name: None,
            description: None,
            extends: None,
            merge_strategy: None,
            rules: None,
            extensions: Some(hushspec::Extensions {
                detection: Some(hushspec::extensions::DetectionExtension {
                    prompt_injection: Some(hushspec::extensions::PromptInjectionDetection {
                        enabled: true,
                        warn_at_or_above: hushspec::extensions::DetectionLevel::Suspicious,
                        block_at_or_above: hushspec::extensions::DetectionLevel::High,
                        max_scan_bytes: 100_000,
                    }),
                    jailbreak: None,
                    threat_intel: None,
                }),
                ..Default::default()
            }),
        };

        let policy = compile(&spec).expect("compile should succeed");
        let pi = policy
            .guards
            .prompt_injection
            .as_ref()
            .expect("prompt_injection should be set");
        assert!(pi.enabled);
        assert_eq!(pi.warn_at_or_above, PromptInjectionLevel::Suspicious);
        assert_eq!(pi.block_at_or_above, PromptInjectionLevel::High);
        assert_eq!(pi.max_scan_bytes, 100_000);

        // Roundtrip through decompile
        let roundtrip = decompile(&policy);
        let ext = roundtrip.extensions.expect("extensions should be set");
        let det = ext.detection.expect("detection should be set");
        let pi_rt = det
            .prompt_injection
            .expect("prompt_injection should be set");
        assert_eq!(
            pi_rt.warn_at_or_above,
            hushspec::extensions::DetectionLevel::Suspicious
        );
        assert_eq!(
            pi_rt.block_at_or_above,
            hushspec::extensions::DetectionLevel::High
        );
    }

    #[test]
    fn test_compile_posture() {
        let mut states = std::collections::BTreeMap::new();
        states.insert(
            "initial".to_string(),
            hushspec::extensions::PostureState {
                description: Some("Starting state".to_string()),
                capabilities: vec!["file_access".to_string()],
                budgets: std::collections::BTreeMap::new(),
            },
        );

        let spec = hushspec::HushSpec {
            hushspec: "0.1.0".to_string(),
            name: None,
            description: None,
            extends: None,
            merge_strategy: None,
            rules: None,
            extensions: Some(hushspec::Extensions {
                posture: Some(hushspec::extensions::PostureExtension {
                    initial: "initial".to_string(),
                    states,
                    transitions: vec![],
                }),
                ..Default::default()
            }),
        };

        let policy = compile(&spec).expect("compile should succeed");
        let posture_cfg = policy.posture.as_ref().expect("posture should be set");
        assert_eq!(posture_cfg.initial, "initial");
        assert!(posture_cfg.states.contains_key("initial"));

        // Roundtrip
        let roundtrip = decompile(&policy);
        let ext = roundtrip.extensions.expect("extensions should be set");
        let posture_rt = ext.posture.expect("posture should be set");
        assert_eq!(posture_rt.initial, "initial");
    }

    #[test]
    fn test_compile_origins() {
        let spec = hushspec::HushSpec {
            hushspec: "0.1.0".to_string(),
            name: None,
            description: None,
            extends: None,
            merge_strategy: None,
            rules: None,
            extensions: Some(hushspec::Extensions {
                origins: Some(hushspec::extensions::OriginsExtension {
                    default_behavior: hushspec::extensions::OriginDefaultBehavior::Deny,
                    profiles: vec![hushspec::extensions::OriginProfile {
                        id: "slack-internal".to_string(),
                        match_rules: Some(hushspec::extensions::OriginMatch {
                            provider: Some("slack".to_string()),
                            visibility: Some("internal".to_string()),
                            ..Default::default()
                        }),
                        posture: Some("elevated".to_string()),
                        tool_access: None,
                        egress: None,
                        data: None,
                        budgets: None,
                        bridge: None,
                        explanation: Some("Internal Slack channels".to_string()),
                    }],
                }),
                ..Default::default()
            }),
        };

        let policy = compile(&spec).expect("compile should succeed");
        let origins = policy.origins.as_ref().expect("origins should be set");
        assert_eq!(origins.default_behavior, Some(OriginDefaultBehavior::Deny));
        assert_eq!(origins.profiles.len(), 1);
        assert_eq!(origins.profiles[0].id, "slack-internal");
        assert_eq!(
            origins.profiles[0].match_rules.provider,
            Some(OriginProvider::Slack)
        );
        assert_eq!(
            origins.profiles[0].match_rules.visibility,
            Some(Visibility::Internal)
        );

        // Roundtrip
        let roundtrip = decompile(&policy);
        let ext = roundtrip.extensions.expect("extensions should be set");
        let origins_rt = ext.origins.expect("origins should be set");
        assert_eq!(origins_rt.profiles[0].id, "slack-internal");
    }

    #[cfg(feature = "full")]
    #[test]
    fn test_compile_detection_threat_intel() {
        let spec = hushspec::HushSpec {
            hushspec: "0.1.0".to_string(),
            name: None,
            description: None,
            extends: None,
            merge_strategy: None,
            rules: None,
            extensions: Some(hushspec::Extensions {
                detection: Some(hushspec::extensions::DetectionExtension {
                    prompt_injection: None,
                    jailbreak: None,
                    threat_intel: Some(hushspec::extensions::ThreatIntelDetection {
                        enabled: true,
                        pattern_db: Some("builtin:s2bench-v1".to_string()),
                        similarity_threshold: 0.90,
                        top_k: 3,
                    }),
                }),
                ..Default::default()
            }),
        };

        let policy = compile(&spec).expect("compile should succeed");
        let ss = policy
            .guards
            .spider_sense
            .as_ref()
            .expect("spider_sense should be set");
        assert!(ss.enabled);
        assert_eq!(ss.pattern_db_path, "builtin:s2bench-v1");
        assert!((ss.similarity_threshold - 0.90).abs() < f64::EPSILON);
        assert_eq!(ss.top_k, 3);

        // Roundtrip through decompile
        let roundtrip = decompile(&policy);
        let ext = roundtrip.extensions.expect("extensions should be set");
        let det = ext.detection.expect("detection should be set");
        let ti = det.threat_intel.expect("threat_intel should be set");
        assert!(ti.enabled);
        assert_eq!(ti.pattern_db.as_deref(), Some("builtin:s2bench-v1"));
        assert!((ti.similarity_threshold - 0.90).abs() < f64::EPSILON);
        assert_eq!(ti.top_k, 3);
    }

    #[test]
    fn test_compile_rejects_oversized_jailbreak_thresholds() {
        let spec = hushspec::HushSpec {
            hushspec: "0.1.0".to_string(),
            name: None,
            description: None,
            extends: None,
            merge_strategy: None,
            rules: None,
            extensions: Some(hushspec::Extensions {
                detection: Some(hushspec::extensions::DetectionExtension {
                    prompt_injection: None,
                    jailbreak: Some(hushspec::extensions::JailbreakDetection {
                        enabled: true,
                        block_threshold: 256,
                        warn_threshold: 30,
                        max_input_bytes: 200_000,
                    }),
                    threat_intel: None,
                }),
                ..Default::default()
            }),
        };

        let err = compile(&spec).expect_err("should reject block_threshold > 255");
        let msg = format!("{err}");
        assert!(msg.contains("block_threshold"));
    }
}
