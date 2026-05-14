use crate::HushSpec;
use crate::conditions::{Condition, RuntimeContext, evaluate_condition};
use crate::extensions::{OriginProfile, PostureExtension, TransitionTrigger};
use crate::rules::{
    ComputerUseMode, ComputerUseRule, DefaultAction, ForbiddenPathsRule, InputInjectionRule,
    PatchIntegrityRule, PathAllowlistRule, RemoteDesktopChannelsRule, SecretPatternsRule,
    ShellCommandsRule,
};
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Decision {
    Allow,
    Warn,
    Deny,
}

#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EvaluationAction {
    #[serde(rename = "type")]
    pub action_type: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub content: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub origin: Option<OriginContext>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub posture: Option<PostureContext>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub args_size: Option<usize>,
}

#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OriginContext {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub provider: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tenant_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub space_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub space_type: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub visibility: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub external_participants: Option<bool>,
    #[serde(default)]
    pub tags: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sensitivity: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub actor_role: Option<String>,
}

#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PostureContext {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub current: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signal: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EvaluationResult {
    pub decision: Decision,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub matched_rule: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub origin_profile: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub posture: Option<PostureResult>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PostureResult {
    pub current: String,
    pub next: String,
}

pub fn evaluate(spec: &HushSpec, action: &EvaluationAction) -> EvaluationResult {
    if crate::panic::is_panic_active() {
        return EvaluationResult {
            decision: Decision::Deny,
            matched_rule: Some("__hushspec_panic__".to_string()),
            reason: Some("emergency panic mode is active".to_string()),
            origin_profile: None,
            posture: None,
        };
    }

    let matched_profile = select_origin_profile(spec, action.origin.as_ref());
    let origin_profile_id = matched_profile.map(|profile| profile.id.clone());
    let posture = resolve_posture(spec, matched_profile, action.posture.as_ref());

    if let Some(denied) = posture_capability_guard(action, &posture, spec, &origin_profile_id) {
        return denied;
    }

    match action.action_type.as_str() {
        "tool_call" => {
            evaluate_tool_call(spec, action, matched_profile, posture, origin_profile_id)
        }
        "egress" => evaluate_egress(spec, action, matched_profile, posture, origin_profile_id),
        "file_read" => {
            evaluate_file_read(spec, action, matched_profile, posture, origin_profile_id)
        }
        "file_write" => {
            evaluate_file_write(spec, action, matched_profile, posture, origin_profile_id)
        }
        "patch_apply" => evaluate_patch(spec, action, matched_profile, posture, origin_profile_id),
        "shell_command" => {
            evaluate_shell_command(spec, action, matched_profile, posture, origin_profile_id)
        }
        "computer_use" => evaluate_computer_use(spec, action, posture, origin_profile_id),
        "input_inject" => evaluate_input_injection(spec, action, posture, origin_profile_id),
        _ => EvaluationResult {
            decision: Decision::Allow,
            matched_rule: None,
            reason: Some("no reference evaluator rule for this action type".to_string()),
            origin_profile: origin_profile_id,
            posture,
        },
    }
}

/// Like [`evaluate`] but filters rule blocks through `when` conditions first.
///
/// Rule blocks whose conditions evaluate to false are treated as inert.
/// Rule blocks not present in the conditions map are unconditionally active.
pub fn evaluate_with_context(
    spec: &HushSpec,
    action: &EvaluationAction,
    context: &RuntimeContext,
    conditions: &HashMap<String, Condition>,
) -> EvaluationResult {
    if crate::panic::is_panic_active() {
        return EvaluationResult {
            decision: Decision::Deny,
            matched_rule: Some("__hushspec_panic__".to_string()),
            reason: Some("emergency panic mode is active".to_string()),
            origin_profile: None,
            posture: None,
        };
    }

    let matched_profile = select_origin_profile(spec, action.origin.as_ref());
    let origin_profile_id = matched_profile.map(|profile| profile.id.clone());
    let posture = resolve_posture(spec, matched_profile, action.posture.as_ref());

    if let Some(denied) = posture_capability_guard(action, &posture, spec, &origin_profile_id) {
        return denied;
    }

    let effective_spec = apply_conditions(spec, context, conditions);

    match action.action_type.as_str() {
        "tool_call" => evaluate_tool_call(
            &effective_spec,
            action,
            matched_profile,
            posture,
            origin_profile_id,
        ),
        "egress" => evaluate_egress(
            &effective_spec,
            action,
            matched_profile,
            posture,
            origin_profile_id,
        ),
        "file_read" => evaluate_file_read(
            &effective_spec,
            action,
            matched_profile,
            posture,
            origin_profile_id,
        ),
        "file_write" => evaluate_file_write(
            &effective_spec,
            action,
            matched_profile,
            posture,
            origin_profile_id,
        ),
        "patch_apply" => evaluate_patch(
            &effective_spec,
            action,
            matched_profile,
            posture,
            origin_profile_id,
        ),
        "shell_command" => evaluate_shell_command(
            &effective_spec,
            action,
            matched_profile,
            posture,
            origin_profile_id,
        ),
        "computer_use" => {
            evaluate_computer_use(&effective_spec, action, posture, origin_profile_id)
        }
        "input_inject" => {
            evaluate_input_injection(&effective_spec, action, posture, origin_profile_id)
        }
        _ => EvaluationResult {
            decision: Decision::Allow,
            matched_rule: None,
            reason: Some("no reference evaluator rule for this action type".to_string()),
            origin_profile: origin_profile_id,
            posture,
        },
    }
}

fn apply_conditions(
    spec: &HushSpec,
    context: &RuntimeContext,
    conditions: &HashMap<String, Condition>,
) -> HushSpec {
    let mut effective = spec.clone();

    if let Some(rules) = &mut effective.rules {
        for (block_name, condition) in conditions {
            if !evaluate_condition(condition, context) {
                match block_name.as_str() {
                    "forbidden_paths" => rules.forbidden_paths = None,
                    "path_allowlist" => rules.path_allowlist = None,
                    "egress" => rules.egress = None,
                    "secret_patterns" => rules.secret_patterns = None,
                    "patch_integrity" => rules.patch_integrity = None,
                    "shell_commands" => rules.shell_commands = None,
                    "tool_access" => rules.tool_access = None,
                    "computer_use" => rules.computer_use = None,
                    "remote_desktop_channels" => rules.remote_desktop_channels = None,
                    "input_injection" => rules.input_injection = None,
                    _ => {} // Unknown block name -- ignore silently.
                }
            }
        }
    }

    effective
}

fn evaluate_tool_call(
    spec: &HushSpec,
    action: &EvaluationAction,
    matched_profile: Option<&OriginProfile>,
    posture: Option<PostureResult>,
    origin_profile_id: Option<String>,
) -> EvaluationResult {
    let base_rule = spec
        .rules
        .as_ref()
        .and_then(|rules| rules.tool_access.as_ref())
        .filter(|rule| rule.enabled);
    let profile_rule = matched_profile
        .and_then(|profile| profile.tool_access.as_ref())
        .filter(|rule| rule.enabled);

    if base_rule.is_none() && profile_rule.is_none() {
        return allow_result(None, None, origin_profile_id, posture);
    }

    let target = action.target.as_deref().unwrap_or_default();
    let profile_prefix =
        matched_profile.map(|profile| profile_rule_prefix(profile.id.as_str(), "tool_access"));

    let smallest_arg_limit = [
        base_rule.and_then(|rule| {
            rule.max_args_size
                .map(|max_args_size| (max_args_size, "rules.tool_access.max_args_size".to_string()))
        }),
        profile_rule.and_then(|rule| {
            profile_prefix.as_ref().and_then(|prefix| {
                rule.max_args_size
                    .map(|max_args_size| (max_args_size, format!("{prefix}.max_args_size")))
            })
        }),
    ]
    .into_iter()
    .flatten()
    .min_by_key(|(max_args_size, _)| *max_args_size);

    if let Some((max_args_size, matched_rule)) = smallest_arg_limit
        && action.args_size.unwrap_or_default() > max_args_size
    {
        return deny_result(
            Some(matched_rule),
            Some("tool arguments exceeded max_args_size".to_string()),
            origin_profile_id,
            posture,
        );
    }

    if base_rule
        .and_then(|rule| find_first_match(target, &rule.block))
        .is_some()
    {
        return deny_result(
            Some("rules.tool_access.block".to_string()),
            Some("tool is explicitly blocked".to_string()),
            origin_profile_id,
            posture,
        );
    }
    if let Some(prefix) = profile_prefix.as_ref()
        && profile_rule
            .and_then(|rule| find_first_match(target, &rule.block))
            .is_some()
    {
        return deny_result(
            Some(format!("{prefix}.block")),
            Some("tool is explicitly blocked".to_string()),
            origin_profile_id,
            posture,
        );
    }

    if base_rule
        .and_then(|rule| find_first_match(target, &rule.require_confirmation))
        .is_some()
    {
        return warn_result(
            Some("rules.tool_access.require_confirmation".to_string()),
            Some("tool requires confirmation".to_string()),
            origin_profile_id,
            posture,
        );
    }
    if let Some(prefix) = profile_prefix.as_ref()
        && profile_rule
            .and_then(|rule| find_first_match(target, &rule.require_confirmation))
            .is_some()
    {
        return warn_result(
            Some(format!("{prefix}.require_confirmation")),
            Some("tool requires confirmation".to_string()),
            origin_profile_id,
            posture,
        );
    }

    let base_has_allow = base_rule.is_some_and(|rule| !rule.allow.is_empty());
    let profile_has_allow = profile_rule.is_some_and(|rule| !rule.allow.is_empty());
    let base_allow_match = !base_has_allow
        || base_rule
            .and_then(|rule| find_first_match(target, &rule.allow))
            .is_some();
    let profile_allow_match = !profile_has_allow
        || profile_rule
            .and_then(|rule| find_first_match(target, &rule.allow))
            .is_some();
    if (base_has_allow || profile_has_allow) && base_allow_match && profile_allow_match {
        let matched_rule = if profile_has_allow {
            profile_prefix
                .as_ref()
                .map(|prefix| format!("{prefix}.allow"))
        } else if base_has_allow {
            Some("rules.tool_access.allow".to_string())
        } else {
            None
        };
        return allow_result(
            matched_rule,
            Some("tool is explicitly allowed".to_string()),
            origin_profile_id,
            posture,
        );
    }

    let default_action = if base_rule.is_some_and(|rule| rule.default == DefaultAction::Block)
        || profile_rule.is_some_and(|rule| rule.default == DefaultAction::Block)
    {
        DefaultAction::Block
    } else {
        DefaultAction::Allow
    };
    let default_rule = if profile_rule.is_some() {
        profile_prefix.map(|prefix| format!("{prefix}.default"))
    } else if base_rule.is_some() {
        Some("rules.tool_access.default".to_string())
    } else {
        None
    };

    match default_action {
        DefaultAction::Allow => allow_result(
            default_rule,
            Some("tool matched default allow".to_string()),
            origin_profile_id,
            posture,
        ),
        DefaultAction::Block => deny_result(
            default_rule,
            Some("tool matched default block".to_string()),
            origin_profile_id,
            posture,
        ),
    }
}

fn evaluate_egress(
    spec: &HushSpec,
    action: &EvaluationAction,
    matched_profile: Option<&OriginProfile>,
    posture: Option<PostureResult>,
    origin_profile_id: Option<String>,
) -> EvaluationResult {
    let base_rule = spec
        .rules
        .as_ref()
        .and_then(|rules| rules.egress.as_ref())
        .filter(|rule| rule.enabled);
    let profile_rule = matched_profile
        .and_then(|profile| profile.egress.as_ref())
        .filter(|rule| rule.enabled);

    if base_rule.is_none() && profile_rule.is_none() {
        return allow_result(None, None, origin_profile_id, posture);
    }

    let target = action.target.as_deref().unwrap_or_default();
    let profile_prefix =
        matched_profile.map(|profile| profile_rule_prefix(profile.id.as_str(), "egress"));

    if base_rule
        .and_then(|rule| find_first_match(target, &rule.block))
        .is_some()
    {
        return deny_result(
            Some("rules.egress.block".to_string()),
            Some("domain is explicitly blocked".to_string()),
            origin_profile_id,
            posture,
        );
    }
    if let Some(prefix) = profile_prefix.as_ref()
        && profile_rule
            .and_then(|rule| find_first_match(target, &rule.block))
            .is_some()
    {
        return deny_result(
            Some(format!("{prefix}.block")),
            Some("domain is explicitly blocked".to_string()),
            origin_profile_id,
            posture,
        );
    }

    let base_has_allow = base_rule.is_some_and(|rule| !rule.allow.is_empty());
    let profile_has_allow = profile_rule.is_some_and(|rule| !rule.allow.is_empty());
    let base_allow_match = !base_has_allow
        || base_rule
            .and_then(|rule| find_first_match(target, &rule.allow))
            .is_some();
    let profile_allow_match = !profile_has_allow
        || profile_rule
            .and_then(|rule| find_first_match(target, &rule.allow))
            .is_some();
    if (base_has_allow || profile_has_allow) && base_allow_match && profile_allow_match {
        let matched_rule = if profile_has_allow {
            profile_prefix
                .as_ref()
                .map(|prefix| format!("{prefix}.allow"))
        } else if base_has_allow {
            Some("rules.egress.allow".to_string())
        } else {
            None
        };
        return allow_result(
            matched_rule,
            Some("domain is explicitly allowed".to_string()),
            origin_profile_id,
            posture,
        );
    }

    let default_action = if base_rule.is_some_and(|rule| rule.default == DefaultAction::Block)
        || profile_rule.is_some_and(|rule| rule.default == DefaultAction::Block)
    {
        DefaultAction::Block
    } else {
        DefaultAction::Allow
    };
    let default_rule = if profile_rule.is_some() {
        profile_prefix.map(|prefix| format!("{prefix}.default"))
    } else if base_rule.is_some() {
        Some("rules.egress.default".to_string())
    } else {
        None
    };

    match default_action {
        DefaultAction::Allow => allow_result(
            default_rule,
            Some("domain matched default allow".to_string()),
            origin_profile_id,
            posture,
        ),
        DefaultAction::Block => deny_result(
            default_rule,
            Some("domain matched default block".to_string()),
            origin_profile_id,
            posture,
        ),
    }
}

fn evaluate_file_read(
    spec: &HushSpec,
    action: &EvaluationAction,
    _matched_profile: Option<&OriginProfile>,
    posture: Option<PostureResult>,
    origin_profile_id: Option<String>,
) -> EvaluationResult {
    if let Some(result) = evaluate_path_guards(
        spec,
        action.target.as_deref().unwrap_or_default(),
        PathOperation::Read,
        posture.clone(),
        origin_profile_id.clone(),
    ) {
        return result;
    }

    allow_result(None, None, origin_profile_id, posture)
}

fn evaluate_file_write(
    spec: &HushSpec,
    action: &EvaluationAction,
    _matched_profile: Option<&OriginProfile>,
    posture: Option<PostureResult>,
    origin_profile_id: Option<String>,
) -> EvaluationResult {
    if let Some(result) = evaluate_path_guards(
        spec,
        action.target.as_deref().unwrap_or_default(),
        PathOperation::Write,
        posture.clone(),
        origin_profile_id.clone(),
    ) {
        return result;
    }

    if let Some(rule) = spec
        .rules
        .as_ref()
        .and_then(|rules| rules.secret_patterns.as_ref())
    {
        return evaluate_secret_patterns(
            rule,
            action.target.as_deref().unwrap_or_default(),
            action.content.as_deref().unwrap_or_default(),
            posture,
            origin_profile_id,
        );
    }

    allow_result(None, None, origin_profile_id, posture)
}

fn evaluate_patch(
    spec: &HushSpec,
    action: &EvaluationAction,
    _matched_profile: Option<&OriginProfile>,
    posture: Option<PostureResult>,
    origin_profile_id: Option<String>,
) -> EvaluationResult {
    if let Some(result) = evaluate_path_guards(
        spec,
        action.target.as_deref().unwrap_or_default(),
        PathOperation::Patch,
        posture.clone(),
        origin_profile_id.clone(),
    ) {
        return result;
    }

    if let Some(rule) = spec
        .rules
        .as_ref()
        .and_then(|rules| rules.patch_integrity.as_ref())
    {
        return evaluate_patch_integrity(
            rule,
            action.content.as_deref().unwrap_or_default(),
            posture,
            origin_profile_id,
        );
    }

    allow_result(None, None, origin_profile_id, posture)
}

fn evaluate_shell_command(
    spec: &HushSpec,
    action: &EvaluationAction,
    _matched_profile: Option<&OriginProfile>,
    posture: Option<PostureResult>,
    origin_profile_id: Option<String>,
) -> EvaluationResult {
    if let Some(rule) = spec
        .rules
        .as_ref()
        .and_then(|rules| rules.shell_commands.as_ref())
    {
        return evaluate_shell_rule(
            rule,
            action.target.as_deref().unwrap_or_default(),
            posture,
            origin_profile_id,
        );
    }

    allow_result(None, None, origin_profile_id, posture)
}

fn evaluate_computer_use(
    spec: &HushSpec,
    action: &EvaluationAction,
    posture: Option<PostureResult>,
    origin_profile_id: Option<String>,
) -> EvaluationResult {
    let target = action.target.as_deref().unwrap_or_default();
    let computer_use_result = spec
        .rules
        .as_ref()
        .and_then(|rules| rules.computer_use.as_ref())
        .map(|rule| {
            evaluate_computer_use_rule(rule, target, posture.clone(), origin_profile_id.clone())
        });
    let remote_desktop_result = spec
        .rules
        .as_ref()
        .and_then(|rules| rules.remote_desktop_channels.as_ref())
        .and_then(|rule| {
            evaluate_remote_desktop_channels_rule(
                rule,
                target,
                posture.clone(),
                origin_profile_id.clone(),
            )
        });

    match (computer_use_result, remote_desktop_result) {
        (Some(left), Some(right)) => more_restrictive_result(left, right),
        (Some(result), None) | (None, Some(result)) => result,
        (None, None) => allow_result(None, None, origin_profile_id, posture),
    }
}

fn evaluate_input_injection(
    spec: &HushSpec,
    action: &EvaluationAction,
    posture: Option<PostureResult>,
    origin_profile_id: Option<String>,
) -> EvaluationResult {
    if let Some(rule) = spec
        .rules
        .as_ref()
        .and_then(|rules| rules.input_injection.as_ref())
    {
        return evaluate_input_injection_rule(
            rule,
            action.target.as_deref().unwrap_or_default(),
            posture,
            origin_profile_id,
        );
    }

    allow_result(None, None, origin_profile_id, posture)
}

fn evaluate_secret_patterns(
    rule: &SecretPatternsRule,
    target: &str,
    content: &str,
    posture: Option<PostureResult>,
    origin_profile_id: Option<String>,
) -> EvaluationResult {
    if !rule.enabled {
        return allow_result(None, None, origin_profile_id, posture);
    }

    if find_first_match(target, &rule.skip_paths).is_some() {
        return allow_result(
            Some("rules.secret_patterns.skip_paths".to_string()),
            Some("path is excluded from secret scanning".to_string()),
            origin_profile_id,
            posture,
        );
    }

    for pattern in &rule.patterns {
        if Regex::new(&pattern.pattern)
            .map(|regex| regex.is_match(content))
            .unwrap_or(false)
        {
            return deny_result(
                Some(format!("rules.secret_patterns.patterns.{}", pattern.name)),
                Some(format!("content matched secret pattern '{}'", pattern.name)),
                origin_profile_id,
                posture,
            );
        }
    }

    allow_result(None, None, origin_profile_id, posture)
}

fn evaluate_patch_integrity(
    rule: &PatchIntegrityRule,
    content: &str,
    posture: Option<PostureResult>,
    origin_profile_id: Option<String>,
) -> EvaluationResult {
    if !rule.enabled {
        return allow_result(None, None, origin_profile_id, posture);
    }

    for (index, pattern) in rule.forbidden_patterns.iter().enumerate() {
        if Regex::new(pattern)
            .map(|regex| regex.is_match(content))
            .unwrap_or(false)
        {
            return deny_result(
                Some(format!("rules.patch_integrity.forbidden_patterns[{index}]")),
                Some("patch content matched a forbidden pattern".to_string()),
                origin_profile_id,
                posture,
            );
        }
    }

    let stats = patch_stats(content);
    if stats.additions > rule.max_additions {
        return deny_result(
            Some("rules.patch_integrity.max_additions".to_string()),
            Some("patch additions exceeded max_additions".to_string()),
            origin_profile_id,
            posture,
        );
    }
    if stats.deletions > rule.max_deletions {
        return deny_result(
            Some("rules.patch_integrity.max_deletions".to_string()),
            Some("patch deletions exceeded max_deletions".to_string()),
            origin_profile_id,
            posture,
        );
    }
    if rule.require_balance {
        let ratio = imbalance_ratio(stats.additions, stats.deletions);
        if ratio > rule.max_imbalance_ratio {
            return deny_result(
                Some("rules.patch_integrity.max_imbalance_ratio".to_string()),
                Some("patch exceeded max imbalance ratio".to_string()),
                origin_profile_id,
                posture,
            );
        }
    }

    allow_result(None, None, origin_profile_id, posture)
}

fn evaluate_shell_rule(
    rule: &ShellCommandsRule,
    target: &str,
    posture: Option<PostureResult>,
    origin_profile_id: Option<String>,
) -> EvaluationResult {
    if !rule.enabled {
        return allow_result(None, None, origin_profile_id, posture);
    }

    for (index, pattern) in rule.forbidden_patterns.iter().enumerate() {
        if Regex::new(pattern)
            .map(|regex| regex.is_match(target))
            .unwrap_or(false)
        {
            return deny_result(
                Some(format!("rules.shell_commands.forbidden_patterns[{index}]")),
                Some("shell command matched a forbidden pattern".to_string()),
                origin_profile_id,
                posture,
            );
        }
    }

    allow_result(None, None, origin_profile_id, posture)
}

fn evaluate_computer_use_rule(
    rule: &ComputerUseRule,
    target: &str,
    posture: Option<PostureResult>,
    origin_profile_id: Option<String>,
) -> EvaluationResult {
    if !rule.enabled {
        return allow_result(None, None, origin_profile_id, posture);
    }

    if rule.allowed_actions.iter().any(|action| action == target) {
        return allow_result(
            Some("rules.computer_use.allowed_actions".to_string()),
            Some("computer-use action is explicitly allowed".to_string()),
            origin_profile_id,
            posture,
        );
    }

    match rule.mode {
        ComputerUseMode::Observe => allow_result(
            Some("rules.computer_use.mode".to_string()),
            Some("observe mode does not block unlisted actions".to_string()),
            origin_profile_id,
            posture,
        ),
        ComputerUseMode::Guardrail => warn_result(
            Some("rules.computer_use.mode".to_string()),
            Some("guardrail mode warns on unlisted actions".to_string()),
            origin_profile_id,
            posture,
        ),
        ComputerUseMode::FailClosed => deny_result(
            Some("rules.computer_use.mode".to_string()),
            Some("fail_closed mode denies unlisted actions".to_string()),
            origin_profile_id,
            posture,
        ),
    }
}

fn evaluate_remote_desktop_channels_rule(
    rule: &RemoteDesktopChannelsRule,
    target: &str,
    posture: Option<PostureResult>,
    origin_profile_id: Option<String>,
) -> Option<EvaluationResult> {
    if !rule.enabled {
        return None;
    }

    let (field, allowed) = match target {
        "remote.clipboard" => ("clipboard", rule.clipboard),
        "remote.file_transfer" => ("file_transfer", rule.file_transfer),
        "remote.audio" => ("audio", rule.audio),
        "remote.drive_mapping" => ("drive_mapping", rule.drive_mapping),
        _ => return None,
    };

    if allowed {
        return Some(allow_result(
            Some(format!("rules.remote_desktop_channels.{field}")),
            Some(format!("remote desktop channel '{field}' is enabled")),
            origin_profile_id,
            posture,
        ));
    }

    Some(deny_result(
        Some(format!("rules.remote_desktop_channels.{field}")),
        Some(format!("remote desktop channel '{field}' is disabled")),
        origin_profile_id,
        posture,
    ))
}

fn evaluate_input_injection_rule(
    rule: &InputInjectionRule,
    target: &str,
    posture: Option<PostureResult>,
    origin_profile_id: Option<String>,
) -> EvaluationResult {
    if !rule.enabled {
        return allow_result(None, None, origin_profile_id, posture);
    }

    if rule.allowed_types.is_empty() {
        return deny_result(
            Some("rules.input_injection.allowed_types".to_string()),
            Some("input injection is not allowed when allowed_types is empty".to_string()),
            origin_profile_id,
            posture,
        );
    }

    if rule.allowed_types.iter().any(|allowed| allowed == target) {
        return allow_result(
            Some("rules.input_injection.allowed_types".to_string()),
            Some("input injection type is explicitly allowed".to_string()),
            origin_profile_id,
            posture,
        );
    }

    deny_result(
        Some("rules.input_injection.allowed_types".to_string()),
        Some("input injection type is not allowed".to_string()),
        origin_profile_id,
        posture,
    )
}

fn decision_rank(decision: &Decision) -> u8 {
    match decision {
        Decision::Allow => 1,
        Decision::Warn => 2,
        Decision::Deny => 3,
    }
}

fn more_restrictive_result(left: EvaluationResult, right: EvaluationResult) -> EvaluationResult {
    let left_rank = decision_rank(&left.decision);
    let right_rank = decision_rank(&right.decision);
    if right_rank > left_rank {
        return right;
    }
    if left_rank > right_rank {
        return left;
    }

    if right.matched_rule.is_some() {
        right
    } else {
        left
    }
}

struct ForbiddenPathOutcome {
    denied: Option<EvaluationResult>,
    exception_matched: bool,
}

fn evaluate_path_guards(
    spec: &HushSpec,
    target: &str,
    operation: PathOperation,
    posture: Option<PostureResult>,
    origin_profile_id: Option<String>,
) -> Option<EvaluationResult> {
    let rules = spec.rules.as_ref()?;
    let mut forbidden_exception_matched = false;

    if let Some(rule) = rules.forbidden_paths.as_ref() {
        let result =
            evaluate_forbidden_paths(rule, target, posture.clone(), origin_profile_id.clone());
        if let Some(denied) = result.denied {
            return Some(denied);
        }
        forbidden_exception_matched = result.exception_matched;
    }

    if let Some(rule) = rules.path_allowlist.as_ref()
        && let Some(result) = evaluate_path_allowlist(
            rule,
            target,
            operation,
            posture.clone(),
            origin_profile_id.clone(),
        )
    {
        return Some(result);
    }

    if forbidden_exception_matched {
        return Some(allow_result(
            Some("rules.forbidden_paths.exceptions".to_string()),
            Some("path matched an explicit exception".to_string()),
            origin_profile_id,
            posture,
        ));
    }

    None
}

fn evaluate_forbidden_paths(
    rule: &ForbiddenPathsRule,
    target: &str,
    posture: Option<PostureResult>,
    origin_profile_id: Option<String>,
) -> ForbiddenPathOutcome {
    if !rule.enabled {
        return ForbiddenPathOutcome {
            denied: None,
            exception_matched: false,
        };
    }

    if find_first_match(target, &rule.exceptions).is_some() {
        return ForbiddenPathOutcome {
            denied: None,
            exception_matched: true,
        };
    }

    if find_first_match(target, &rule.patterns).is_some() {
        return ForbiddenPathOutcome {
            denied: Some(deny_result(
                Some("rules.forbidden_paths.patterns".to_string()),
                Some("path matched a forbidden pattern".to_string()),
                origin_profile_id,
                posture,
            )),
            exception_matched: false,
        };
    }

    ForbiddenPathOutcome {
        denied: None,
        exception_matched: false,
    }
}

fn evaluate_path_allowlist(
    rule: &PathAllowlistRule,
    target: &str,
    operation: PathOperation,
    posture: Option<PostureResult>,
    origin_profile_id: Option<String>,
) -> Option<EvaluationResult> {
    if !rule.enabled {
        return None;
    }

    let patterns = match operation {
        PathOperation::Read => &rule.read,
        PathOperation::Write => &rule.write,
        PathOperation::Patch => {
            if rule.patch.is_empty() {
                &rule.write
            } else {
                &rule.patch
            }
        }
    };

    if find_first_match(target, patterns).is_some() {
        return Some(allow_result(
            Some("rules.path_allowlist".to_string()),
            Some("path matched allowlist".to_string()),
            origin_profile_id,
            posture,
        ));
    }

    Some(deny_result(
        Some("rules.path_allowlist".to_string()),
        Some("path did not match allowlist".to_string()),
        origin_profile_id,
        posture,
    ))
}

fn posture_capability_guard(
    action: &EvaluationAction,
    posture: &Option<PostureResult>,
    spec: &HushSpec,
    origin_profile_id: &Option<String>,
) -> Option<EvaluationResult> {
    let Some(posture_result) = posture else {
        return None;
    };
    let posture_extension = spec
        .extensions
        .as_ref()
        .and_then(|extensions| extensions.posture.as_ref())?;
    let capability = required_capability(action.action_type.as_str())?;
    let Some(current_state) = posture_extension.states.get(&posture_result.current) else {
        return Some(deny_result(
            Some(format!(
                "extensions.posture.states.{}",
                posture_result.current
            )),
            Some(format!(
                "unknown posture state '{}'",
                posture_result.current
            )),
            origin_profile_id.clone(),
            Some(posture_result.clone()),
        ));
    };

    if current_state
        .capabilities
        .iter()
        .any(|entry| entry == capability)
    {
        return None;
    }

    Some(deny_result(
        Some(format!(
            "extensions.posture.states.{}.capabilities",
            posture_result.current
        )),
        Some(format!(
            "posture '{}' does not allow capability '{capability}'",
            posture_result.current
        )),
        origin_profile_id.clone(),
        Some(posture_result.clone()),
    ))
}

fn resolve_posture(
    spec: &HushSpec,
    matched_profile: Option<&OriginProfile>,
    posture: Option<&PostureContext>,
) -> Option<PostureResult> {
    let posture_extension = spec
        .extensions
        .as_ref()
        .and_then(|extensions| extensions.posture.as_ref())?;

    let current = matched_profile
        .and_then(|profile| profile.posture.clone())
        .or_else(|| posture.and_then(|context| context.current.clone()))
        .unwrap_or_else(|| posture_extension.initial.clone());

    let signal = posture
        .and_then(|context| context.signal.as_deref())
        .filter(|signal| *signal != "none");
    let next = signal
        .and_then(|signal| next_posture_state(posture_extension, &current, signal))
        .unwrap_or_else(|| current.clone());

    Some(PostureResult { current, next })
}

fn next_posture_state(posture: &PostureExtension, current: &str, signal: &str) -> Option<String> {
    posture.transitions.iter().find_map(|transition| {
        if transition.from != "*" && transition.from != current {
            return None;
        }
        if trigger_name(&transition.on) != signal {
            return None;
        }
        Some(transition.to.clone())
    })
}

fn select_origin_profile<'a>(
    spec: &'a HushSpec,
    origin: Option<&OriginContext>,
) -> Option<&'a OriginProfile> {
    let origin = origin?;
    let profiles = spec
        .extensions
        .as_ref()
        .and_then(|extensions| extensions.origins.as_ref())
        .map(|origins| origins.profiles.as_slice())?;

    profiles
        .iter()
        .filter_map(|profile| {
            profile
                .match_rules
                .as_ref()
                .and_then(|rules| match_origin(rules, origin).map(|score| (score, profile)))
        })
        .max_by_key(|(score, _)| *score)
        .map(|(_, profile)| profile)
}

fn match_origin(rules: &crate::extensions::OriginMatch, origin: &OriginContext) -> Option<u32> {
    let mut score = 0;

    if let Some(provider) = &rules.provider {
        if origin.provider.as_ref() != Some(provider) {
            return None;
        }
        score += 4;
    }
    if let Some(tenant_id) = &rules.tenant_id {
        if origin.tenant_id.as_ref() != Some(tenant_id) {
            return None;
        }
        score += 6;
    }
    if let Some(space_id) = &rules.space_id {
        if origin.space_id.as_ref() != Some(space_id) {
            return None;
        }
        score += 8;
    }
    if let Some(space_type) = &rules.space_type {
        if origin.space_type.as_ref() != Some(space_type) {
            return None;
        }
        score += 4;
    }
    if let Some(visibility) = &rules.visibility {
        if origin.visibility.as_ref() != Some(visibility) {
            return None;
        }
        score += 4;
    }
    if let Some(external_participants) = rules.external_participants {
        if origin.external_participants != Some(external_participants) {
            return None;
        }
        score += 2;
    }
    if !rules.tags.is_empty() {
        if !rules
            .tags
            .iter()
            .all(|tag| origin.tags.iter().any(|candidate| candidate == tag))
        {
            return None;
        }
        score += rules.tags.len() as u32;
    }
    if let Some(sensitivity) = &rules.sensitivity {
        if origin.sensitivity.as_ref() != Some(sensitivity) {
            return None;
        }
        score += 4;
    }
    if let Some(actor_role) = &rules.actor_role {
        if origin.actor_role.as_ref() != Some(actor_role) {
            return None;
        }
        score += 4;
    }

    Some(score)
}

fn required_capability(action_type: &str) -> Option<&'static str> {
    match action_type {
        "file_read" => Some("file_access"),
        "file_write" => Some("file_write"),
        "patch_apply" => Some("patch"),
        "shell_command" => Some("shell"),
        "tool_call" => Some("tool_call"),
        "egress" => Some("egress"),
        _ => None,
    }
}

fn trigger_name(trigger: &TransitionTrigger) -> &'static str {
    match trigger {
        TransitionTrigger::UserApproval => "user_approval",
        TransitionTrigger::UserDenial => "user_denial",
        TransitionTrigger::CriticalViolation => "critical_violation",
        TransitionTrigger::AnyViolation => "any_violation",
        TransitionTrigger::Timeout => "timeout",
        TransitionTrigger::BudgetExhausted => "budget_exhausted",
        TransitionTrigger::PatternMatch => "pattern_match",
    }
}

fn profile_rule_prefix(profile_id: &str, field: &str) -> String {
    format!("extensions.origins.profiles.{profile_id}.{field}")
}

fn allow_result(
    matched_rule: Option<String>,
    reason: Option<String>,
    origin_profile: Option<String>,
    posture: Option<PostureResult>,
) -> EvaluationResult {
    EvaluationResult {
        decision: Decision::Allow,
        matched_rule,
        reason,
        origin_profile,
        posture,
    }
}

fn warn_result(
    matched_rule: Option<String>,
    reason: Option<String>,
    origin_profile: Option<String>,
    posture: Option<PostureResult>,
) -> EvaluationResult {
    EvaluationResult {
        decision: Decision::Warn,
        matched_rule,
        reason,
        origin_profile,
        posture,
    }
}

fn deny_result(
    matched_rule: Option<String>,
    reason: Option<String>,
    origin_profile: Option<String>,
    posture: Option<PostureResult>,
) -> EvaluationResult {
    EvaluationResult {
        decision: Decision::Deny,
        matched_rule,
        reason,
        origin_profile,
        posture,
    }
}

fn find_first_match(target: &str, patterns: &[String]) -> Option<usize> {
    patterns
        .iter()
        .enumerate()
        .find_map(|(index, pattern)| glob_matches(pattern, target).then_some(index))
}

pub fn glob_matches(pattern: &str, target: &str) -> bool {
    let mut regex = String::from("^");
    let mut chars = pattern.chars().peekable();
    while let Some(ch) = chars.next() {
        match ch {
            '*' => {
                if matches!(chars.peek(), Some('*')) {
                    chars.next();
                    regex.push_str(".*");
                } else {
                    regex.push_str("[^/]*");
                }
            }
            '?' => regex.push('.'),
            '.' | '+' | '(' | ')' | '{' | '}' | '[' | ']' | '^' | '$' | '|' | '\\' => {
                regex.push('\\');
                regex.push(ch);
            }
            _ => regex.push(ch),
        }
    }
    regex.push('$');
    Regex::new(&regex)
        .map(|compiled| compiled.is_match(target))
        .unwrap_or(false)
}

fn patch_stats(content: &str) -> PatchStats {
    let mut additions = 0usize;
    let mut deletions = 0usize;

    for line in content.lines() {
        if line.starts_with("+++") || line.starts_with("---") {
            continue;
        }
        if line.starts_with('+') {
            additions += 1;
        } else if line.starts_with('-') {
            deletions += 1;
        }
    }

    PatchStats {
        additions,
        deletions,
    }
}

fn imbalance_ratio(additions: usize, deletions: usize) -> f64 {
    match (additions, deletions) {
        (0, 0) => 0.0,
        (0, _) => deletions as f64,
        (_, 0) => additions as f64,
        _ => {
            let larger = additions.max(deletions) as f64;
            let smaller = additions.min(deletions) as f64;
            larger / smaller
        }
    }
}

#[derive(Clone, Copy)]
enum PathOperation {
    Read,
    Write,
    Patch,
}

struct PatchStats {
    additions: usize,
    deletions: usize,
}
