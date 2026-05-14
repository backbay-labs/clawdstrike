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
use std::collections::BTreeSet;

use hush_proxy::policy::PolicyAction;

/// Returns true if the YAML string appears to be a HushSpec document.
///
/// Detection is based on the presence of a top-level `hushspec` key, regardless
/// of key order. A lightweight line scan is retained as a fallback when the
/// document does not parse cleanly as generic YAML.
pub fn is_hushspec(yaml: &str) -> bool {
    if let Ok(serde_yaml::Value::Mapping(map)) = serde_yaml::from_str::<serde_yaml::Value>(yaml) {
        return map
            .keys()
            .any(|key| matches!(key, serde_yaml::Value::String(s) if s == "hushspec"));
    }

    for line in yaml.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty()
            || trimmed.starts_with('#')
            || trimmed == "---"
            || trimmed == "..."
            || line.starts_with([' ', '\t'])
        {
            continue;
        }
        if trimmed.starts_with("hushspec:") {
            return true;
        }
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
///
/// Returns an error when the policy contains semantics that HushSpec cannot
/// represent losslessly, such as egress `default_action: log`.
pub fn decompile(policy: &Policy) -> Result<hushspec::HushSpec> {
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
            default: decompile_egress_default_action(
                eg.default_action.as_ref(),
                "guards.egress_allowlist.default_action",
            )?,
        });
    }

    if let Some(sl) = &policy.guards.secret_leak {
        has_rules = true;
        rules.secret_patterns = Some(hushspec::SecretPatternsRule {
            enabled: sl.enabled,
            patterns: sl
                .effective_patterns()
                .iter()
                .map(|p| -> Result<hushspec::rules::SecretPattern> {
                    let field_path = format!("guards.secret_leak.patterns[{}].severity", p.name);
                    Ok(hushspec::rules::SecretPattern {
                        name: p.name.clone(),
                        pattern: p.pattern.clone(),
                        severity: deconvert_severity(&p.severity, &field_path)?,
                        description: p.description.clone(),
                    })
                })
                .collect::<Result<Vec<_>>>()?,
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
        extensions.origins = Some(decompile_origins(origins_cfg)?);
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
            enabled: Some(pi.enabled),
            warn_at_or_above: Some(prompt_level_to_detection_level(pi.warn_at_or_above)),
            block_at_or_above: Some(prompt_level_to_detection_level(pi.block_at_or_above)),
            max_scan_bytes: Some(pi.max_scan_bytes),
        });
    }

    if let Some(jb) = &policy.guards.jailbreak {
        has_detection = true;
        detection.jailbreak = Some(hushspec::extensions::JailbreakDetection {
            enabled: Some(jb.enabled),
            block_threshold: Some(usize::from(jb.detector.block_threshold)),
            warn_threshold: Some(usize::from(jb.detector.warn_threshold)),
            max_input_bytes: Some(jb.detector.max_input_bytes),
        });
    }

    #[cfg(feature = "full")]
    {
        if let Some(ref ss) = policy.guards.spider_sense {
            has_detection = true;
            detection.threat_intel = Some(hushspec::extensions::ThreatIntelDetection {
                enabled: Some(ss.enabled),
                pattern_db: if ss.pattern_db_path.is_empty() {
                    None
                } else {
                    Some(ss.pattern_db_path.clone())
                },
                similarity_threshold: Some(ss.similarity_threshold),
                top_k: Some(ss.top_k),
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

    Ok(hushspec::HushSpec {
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
        metadata: None,
    })
}

// ---------------------------------------------------------------------------
// Internal helpers: compile direction (HushSpec -> Clawdstrike)
// ---------------------------------------------------------------------------

fn decompile_forbidden_path_patterns(fp: &ForbiddenPathConfig) -> Vec<String> {
    // HushSpec has no sentinel for "use engine defaults", so decompile the
    // concrete effective pattern set instead of collapsing to an empty list.
    fp.effective_patterns()
}

fn decompile_egress_default_action(
    action: Option<&PolicyAction>,
    field_path: &str,
) -> Result<hushspec::DefaultAction> {
    match action {
        Some(PolicyAction::Allow) => Ok(hushspec::DefaultAction::Allow),
        Some(PolicyAction::Block) | None => Ok(hushspec::DefaultAction::Block),
        Some(PolicyAction::Log) => Err(Error::ConfigError(format!(
            "Cannot decompile {field_path}=log to HushSpec: egress defaults only support allow or block"
        ))),
    }
}

#[cfg(all(feature = "policy-event", not(feature = "full")))]
fn compile_policy_event_threat_intel_passthrough(
    ti: &hushspec::extensions::ThreatIntelDetection,
) -> serde_json::Value {
    let mut map = serde_json::Map::new();
    if let Some(enabled) = ti.enabled {
        map.insert("enabled".to_string(), serde_json::Value::Bool(enabled));
    }
    if let Some(pattern_db) = &ti.pattern_db {
        map.insert(
            "pattern_db_path".to_string(),
            serde_json::Value::String(pattern_db.clone()),
        );
    }
    if let Some(similarity_threshold) = ti.similarity_threshold {
        map.insert(
            "similarity_threshold".to_string(),
            serde_json::json!(similarity_threshold),
        );
    }
    if let Some(top_k) = ti.top_k {
        map.insert("top_k".to_string(), serde_json::json!(top_k));
    }
    serde_json::Value::Object(map)
}

#[cfg(all(feature = "policy-event", not(feature = "full")))]
fn decompile_policy_event_threat_intel_passthrough(
    spider_sense: &serde_json::Value,
) -> Option<hushspec::extensions::ThreatIntelDetection> {
    let obj = spider_sense.as_object()?;

    let enabled = obj.get("enabled").and_then(|v| v.as_bool());
    let pattern_db = obj
        .get("pattern_db_path")
        .and_then(|v| v.as_str())
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned);
    let similarity_threshold = obj.get("similarity_threshold").and_then(|v| v.as_f64());
    let top_k = obj
        .get("top_k")
        .and_then(|v| v.as_u64())
        .and_then(|v| usize::try_from(v).ok());

    Some(hushspec::extensions::ThreatIntelDetection {
        enabled,
        pattern_db,
        similarity_threshold,
        top_k,
    })
}

fn prompt_injection_present_fields(
    prompt_injection: &hushspec::extensions::PromptInjectionDetection,
) -> BTreeSet<String> {
    let mut fields = BTreeSet::new();
    if prompt_injection.enabled.is_some() {
        fields.insert("enabled".to_string());
    }
    if prompt_injection.warn_at_or_above.is_some() {
        fields.insert("warn_at_or_above".to_string());
    }
    if prompt_injection.block_at_or_above.is_some() {
        fields.insert("block_at_or_above".to_string());
    }
    if prompt_injection.max_scan_bytes.is_some() {
        fields.insert("max_scan_bytes".to_string());
    }
    fields
}

fn jailbreak_present_fields(
    jailbreak: &hushspec::extensions::JailbreakDetection,
) -> BTreeSet<String> {
    let mut fields = BTreeSet::new();
    if jailbreak.enabled.is_some() {
        fields.insert("enabled".to_string());
    }
    if jailbreak.block_threshold.is_some() {
        fields.insert("block_threshold".to_string());
    }
    if jailbreak.warn_threshold.is_some() {
        fields.insert("warn_threshold".to_string());
    }
    if jailbreak.max_input_bytes.is_some() {
        fields.insert("max_input_bytes".to_string());
    }
    fields
}

fn compile_rules(rules: &hushspec::rules::Rules, guards: &mut GuardConfigs) {
    if let Some(fp) = &rules.forbidden_paths {
        guards.forbidden_path = Some(ForbiddenPathConfig {
            enabled: fp.enabled,
            // In HushSpec, an empty list is still an explicit override that clears
            // inherited/base patterns rather than "use Clawdstrike defaults".
            patterns: Some(fp.patterns.clone()),
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
    let default_behavior = ext
        .default_behavior
        .as_ref()
        .map(|behavior| match behavior {
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
                mcp_tool_calls: b.tool_calls.and_then(|v| u64::try_from(v).ok()),
                egress_calls: b.egress_calls.and_then(|v| u64::try_from(v).ok()),
                shell_commands: b.shell_commands.and_then(|v| u64::try_from(v).ok()),
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
        guards.prompt_injection_present_fields = prompt_injection_present_fields(pi);
        guards.prompt_injection = Some(PromptInjectionConfig {
            enabled: pi.enabled.unwrap_or(true),
            warn_at_or_above: detection_level_to_prompt_level(
                pi.warn_at_or_above
                    .unwrap_or(hushspec::extensions::DetectionLevel::Suspicious),
            ),
            block_at_or_above: detection_level_to_prompt_level(
                pi.block_at_or_above
                    .unwrap_or(hushspec::extensions::DetectionLevel::High),
            ),
            max_scan_bytes: pi.max_scan_bytes.unwrap_or(200_000),
        });
    }

    if let Some(jb) = &ext.jailbreak {
        guards.jailbreak_present_fields = jailbreak_present_fields(jb);
        let block_threshold = jb.block_threshold.unwrap_or(70);
        if block_threshold > 255 {
            return Err(Error::ConfigError(format!(
                "jailbreak block_threshold {} exceeds maximum value 255",
                block_threshold
            )));
        }
        let warn_threshold = jb.warn_threshold.unwrap_or(30);
        if warn_threshold > 255 {
            return Err(Error::ConfigError(format!(
                "jailbreak warn_threshold {} exceeds maximum value 255",
                warn_threshold
            )));
        }
        guards.jailbreak = Some(JailbreakConfig {
            enabled: jb.enabled.unwrap_or(true),
            detector: JailbreakGuardConfig {
                block_threshold: block_threshold as u8,
                warn_threshold: warn_threshold as u8,
                max_input_bytes: jb.max_input_bytes.unwrap_or(200_000),
                ..Default::default()
            },
        });
    }

    // Spider Sense mapping is feature-gated.
    #[cfg(feature = "full")]
    if let Some(ti) = &ext.threat_intel {
        let cfg = crate::async_guards::threat_intel::SpiderSensePolicyConfig {
            enabled: ti.enabled.unwrap_or(true),
            pattern_db_path: ti.pattern_db.clone().unwrap_or_default(),
            similarity_threshold: ti.similarity_threshold.unwrap_or(0.85),
            top_k: ti.top_k.unwrap_or(5),
            ..Default::default()
        };
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

fn decompile_origins(
    origins_cfg: &OriginsConfig,
) -> Result<hushspec::extensions::OriginsExtension> {
    let default_behavior = match origins_cfg.default_behavior {
        Some(OriginDefaultBehavior::Deny) => {
            Some(hushspec::extensions::OriginDefaultBehavior::Deny)
        }
        Some(OriginDefaultBehavior::MinimalProfile) => {
            Some(hushspec::extensions::OriginDefaultBehavior::MinimalProfile)
        }
        None => None,
    };

    let profiles = origins_cfg
        .profiles
        .iter()
        .map(|p| -> Result<hushspec::extensions::OriginProfile> {
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

            let egress = p
                .egress
                .as_ref()
                .map(|eg| {
                    let field_path = format!("origins.profiles[{}].egress.default_action", p.id);
                    Ok::<_, Error>(hushspec::EgressRule {
                        enabled: eg.enabled,
                        allow: eg.allow.clone(),
                        block: eg.block.clone(),
                        default: decompile_egress_default_action(
                            eg.default_action.as_ref(),
                            &field_path,
                        )?,
                    })
                })
                .transpose()?;

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
                    tool_calls: b.mcp_tool_calls.and_then(|v| usize::try_from(v).ok()),
                    egress_calls: b.egress_calls.and_then(|v| usize::try_from(v).ok()),
                    shell_commands: b.shell_commands.and_then(|v| usize::try_from(v).ok()),
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

            Ok(hushspec::extensions::OriginProfile {
                id: p.id.clone(),
                match_rules,
                posture: p.posture.clone(),
                tool_access,
                egress,
                data,
                budgets,
                bridge,
                explanation: p.explanation.clone(),
            })
        })
        .collect::<Result<Vec<_>>>()?;

    Ok(hushspec::extensions::OriginsExtension {
        default_behavior,
        profiles,
    })
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

fn deconvert_severity(s: &Severity, field_path: &str) -> Result<hushspec::Severity> {
    match s {
        Severity::Critical => Ok(hushspec::Severity::Critical),
        Severity::Error => Ok(hushspec::Severity::Error),
        Severity::Warning => Ok(hushspec::Severity::Warn),
        Severity::Info => Err(Error::ConfigError(format!(
            "Cannot decompile {field_path}=info to HushSpec: secret pattern severity only supports warn, error, or critical"
        ))),
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
    fn test_is_hushspec_with_reordered_top_level_key() {
        assert!(is_hushspec("name: test\nhushspec: \"0.1.0\"\n"));
        assert!(!is_hushspec("metadata:\n  hushspec: \"0.1.0\"\n"));
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
            metadata: None,
        };

        let policy = compile(&spec).expect("compile should succeed");
        assert_eq!(policy.version, POLICY_SCHEMA_VERSION);
        assert_eq!(policy.name, "test");

        let roundtrip = decompile(&policy).expect("decompile should succeed");
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
            metadata: None,
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
            metadata: None,
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
            deconvert_severity(
                &Severity::Warning,
                "guards.secret_leak.patterns[test].severity"
            )
            .expect("warning should decompile"),
            hushspec::Severity::Warn
        );
        let err = deconvert_severity(
            &Severity::Info,
            "guards.secret_leak.patterns[test].severity",
        )
        .expect_err("info should be rejected");
        assert!(
            err.to_string()
                .contains("guards.secret_leak.patterns[test].severity"),
            "error should point at the unsupported field"
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
                        enabled: Some(true),
                        block_threshold: Some(70),
                        warn_threshold: Some(30),
                        max_input_bytes: Some(200_000),
                    }),
                    threat_intel: None,
                }),
                ..Default::default()
            }),
            metadata: None,
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
                        enabled: Some(true),
                        warn_at_or_above: Some(hushspec::extensions::DetectionLevel::Suspicious),
                        block_at_or_above: Some(hushspec::extensions::DetectionLevel::High),
                        max_scan_bytes: Some(100_000),
                    }),
                    jailbreak: None,
                    threat_intel: None,
                }),
                ..Default::default()
            }),
            metadata: None,
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
        let roundtrip = decompile(&policy).expect("decompile should succeed");
        let ext = roundtrip.extensions.expect("extensions should be set");
        let det = ext.detection.expect("detection should be set");
        let pi_rt = det
            .prompt_injection
            .expect("prompt_injection should be set");
        assert_eq!(
            pi_rt.warn_at_or_above,
            Some(hushspec::extensions::DetectionLevel::Suspicious)
        );
        assert_eq!(
            pi_rt.block_at_or_above,
            Some(hushspec::extensions::DetectionLevel::High)
        );
    }

    #[test]
    fn test_compile_detection_prompt_injection_preserves_partial_overrides_on_merge() {
        let base = Policy {
            guards: GuardConfigs {
                prompt_injection: Some(PromptInjectionConfig {
                    enabled: false,
                    warn_at_or_above: PromptInjectionLevel::High,
                    block_at_or_above: PromptInjectionLevel::Critical,
                    max_scan_bytes: 80_000,
                }),
                ..Default::default()
            },
            ..Default::default()
        };

        let child = compile(&hushspec::HushSpec {
            hushspec: "0.1.0".to_string(),
            name: None,
            description: None,
            extends: None,
            merge_strategy: None,
            rules: None,
            extensions: Some(hushspec::Extensions {
                detection: Some(hushspec::extensions::DetectionExtension {
                    prompt_injection: Some(hushspec::extensions::PromptInjectionDetection {
                        enabled: None,
                        warn_at_or_above: None,
                        block_at_or_above: None,
                        max_scan_bytes: Some(120_000),
                    }),
                    jailbreak: None,
                    threat_intel: None,
                }),
                ..Default::default()
            }),
            metadata: None,
        })
        .expect("compile should succeed");

        let merged = base.merge(&child);
        let prompt = merged
            .guards
            .prompt_injection
            .expect("prompt injection should be merged");
        assert!(!prompt.enabled);
        assert_eq!(prompt.warn_at_or_above, PromptInjectionLevel::High);
        assert_eq!(prompt.block_at_or_above, PromptInjectionLevel::Critical);
        assert_eq!(prompt.max_scan_bytes, 120_000);
    }

    #[test]
    fn test_compile_detection_jailbreak_preserves_partial_overrides_on_merge() {
        let base = Policy {
            guards: GuardConfigs {
                jailbreak: Some(JailbreakConfig {
                    enabled: false,
                    detector: JailbreakGuardConfig {
                        block_threshold: 90,
                        warn_threshold: 45,
                        max_input_bytes: 50_000,
                        ..Default::default()
                    },
                }),
                ..Default::default()
            },
            ..Default::default()
        };

        let child = compile(&hushspec::HushSpec {
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
                        enabled: None,
                        block_threshold: None,
                        warn_threshold: None,
                        max_input_bytes: Some(125_000),
                    }),
                    threat_intel: None,
                }),
                ..Default::default()
            }),
            metadata: None,
        })
        .expect("compile should succeed");

        let merged = base.merge(&child);
        let jailbreak = merged.guards.jailbreak.expect("jailbreak should be merged");
        assert!(!jailbreak.enabled);
        assert_eq!(jailbreak.detector.block_threshold, 90);
        assert_eq!(jailbreak.detector.warn_threshold, 45);
        assert_eq!(jailbreak.detector.max_input_bytes, 125_000);
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
            metadata: None,
        };

        let policy = compile(&spec).expect("compile should succeed");
        let posture_cfg = policy.posture.as_ref().expect("posture should be set");
        assert_eq!(posture_cfg.initial, "initial");
        assert!(posture_cfg.states.contains_key("initial"));

        // Roundtrip
        let roundtrip = decompile(&policy).expect("decompile should succeed");
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
                    default_behavior: Some(hushspec::extensions::OriginDefaultBehavior::Deny),
                    profiles: vec![hushspec::extensions::OriginProfile {
                        id: "slack-internal".to_string(),
                        match_rules: Some(hushspec::extensions::OriginMatch {
                            provider: Some("slack".to_string()),
                            tenant_id: None,
                            space_id: None,
                            space_type: None,
                            visibility: Some("internal".to_string()),
                            external_participants: None,
                            tags: vec![],
                            sensitivity: None,
                            actor_role: None,
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
            metadata: None,
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
        let roundtrip = decompile(&policy).expect("decompile should succeed");
        let ext = roundtrip.extensions.expect("extensions should be set");
        let origins_rt = ext.origins.expect("origins should be set");
        assert_eq!(origins_rt.profiles[0].id, "slack-internal");
    }

    #[test]
    fn test_compile_origins_preserves_base_default_behavior_when_omitted() {
        let base = Policy {
            origins: Some(OriginsConfig {
                default_behavior: Some(OriginDefaultBehavior::MinimalProfile),
                profiles: vec![],
            }),
            ..Default::default()
        };

        let child = compile(&hushspec::HushSpec {
            hushspec: "0.1.0".to_string(),
            name: None,
            description: None,
            extends: None,
            merge_strategy: None,
            rules: None,
            extensions: Some(hushspec::Extensions {
                origins: Some(hushspec::extensions::OriginsExtension {
                    default_behavior: None,
                    profiles: vec![hushspec::extensions::OriginProfile {
                        id: "chat".to_string(),
                        match_rules: None,
                        posture: None,
                        tool_access: None,
                        egress: None,
                        data: None,
                        budgets: None,
                        bridge: None,
                        explanation: None,
                    }],
                }),
                ..Default::default()
            }),
            metadata: None,
        })
        .expect("compile should succeed");

        let merged = base.merge(&child);
        let origins = merged.origins.expect("origins should be merged");
        assert_eq!(
            origins.default_behavior,
            Some(OriginDefaultBehavior::MinimalProfile)
        );
        assert_eq!(origins.profiles.len(), 1);
        assert_eq!(origins.profiles[0].id, "chat");
    }

    #[test]
    fn test_decompile_origins_preserves_unset_default_behavior() {
        let policy = Policy {
            origins: Some(OriginsConfig {
                default_behavior: None,
                profiles: vec![OriginProfile {
                    id: "chat".to_string(),
                    match_rules: OriginMatch::default(),
                    posture: None,
                    mcp: None,
                    egress: None,
                    data: None,
                    budgets: None,
                    bridge_policy: None,
                    explanation: None,
                }],
            }),
            ..Default::default()
        };

        let roundtrip = decompile(&policy).expect("decompile should succeed");
        let ext = roundtrip.extensions.expect("extensions should be set");
        let origins = ext.origins.expect("origins should be set");
        assert_eq!(origins.default_behavior, None);
        assert_eq!(origins.profiles.len(), 1);
        assert_eq!(origins.profiles[0].id, "chat");
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
                        enabled: Some(true),
                        pattern_db: Some("builtin:s2bench-v1".to_string()),
                        similarity_threshold: Some(0.90),
                        top_k: Some(3),
                    }),
                }),
                ..Default::default()
            }),
            metadata: None,
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
        let roundtrip = decompile(&policy).expect("decompile should succeed");
        let ext = roundtrip.extensions.expect("extensions should be set");
        let det = ext.detection.expect("detection should be set");
        let ti = det.threat_intel.expect("threat_intel should be set");
        assert_eq!(ti.enabled, Some(true));
        assert_eq!(ti.pattern_db.as_deref(), Some("builtin:s2bench-v1"));
        assert_eq!(ti.similarity_threshold, Some(0.90));
        assert_eq!(ti.top_k, Some(3));
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
                        enabled: Some(true),
                        block_threshold: Some(256),
                        warn_threshold: Some(30),
                        max_input_bytes: Some(200_000),
                    }),
                    threat_intel: None,
                }),
                ..Default::default()
            }),
            metadata: None,
        };

        let err = compile(&spec).expect_err("should reject block_threshold > 255");
        let msg = format!("{err}");
        assert!(msg.contains("block_threshold"));
    }
}
