//! Semantic inheritance soundness checks (child-vs-parent policy).
//!
//! Extracted from `verifier.rs`. Dispatches per-guard inheritance checks that
//! detect when a child policy weakens a parent prohibition, synthesizing
//! witnesses via the `witness` module and the disabled-config builders here.

use super::*;

pub(crate) fn inspect_policy_inheritance_against_parent(
    child_policy: &Policy,
    parent_policy: &Policy,
) -> InheritanceResult {
    let mut weakened = Vec::new();
    weakened.extend(check_forbidden_path_inheritance(
        parent_policy.guards.forbidden_path.as_ref(),
        child_policy.guards.forbidden_path.as_ref(),
    ));
    weakened.extend(check_path_allowlist_inheritance(
        parent_policy.guards.path_allowlist.as_ref(),
        child_policy.guards.path_allowlist.as_ref(),
    ));
    weakened.extend(check_egress_inheritance(
        parent_policy.guards.egress_allowlist.as_ref(),
        child_policy.guards.egress_allowlist.as_ref(),
    ));
    weakened.extend(check_mcp_inheritance(
        parent_policy.guards.mcp_tool.as_ref(),
        child_policy.guards.mcp_tool.as_ref(),
    ));
    weakened.extend(check_shell_command_inheritance(
        parent_policy.guards.shell_command.as_ref(),
        child_policy.guards.shell_command.as_ref(),
        parent_policy.guards.forbidden_path.as_ref(),
        child_policy.guards.forbidden_path.as_ref(),
    ));

    weakened.sort_by(|a, b| a.atom.cmp(&b.atom));
    weakened.dedup_by(|a, b| a.atom == b.atom);

    InheritanceResult {
        outcome: if weakened.is_empty() {
            CheckOutcome::Pass
        } else {
            CheckOutcome::Fail
        },
        weakened,
    }
}

pub(crate) fn check_forbidden_path_inheritance(
    base_cfg: Option<&ForbiddenPathConfig>,
    child_cfg: Option<&ForbiddenPathConfig>,
) -> Vec<WeakenedProhibition> {
    let Some(base_cfg) = base_cfg.filter(|cfg| cfg.enabled) else {
        return Vec::new();
    };

    let base_guard = ForbiddenPathGuard::with_config(base_cfg.clone());
    let child_guard = ForbiddenPathGuard::with_config(
        child_cfg
            .filter(|cfg| cfg.enabled)
            .cloned()
            .unwrap_or_else(disabled_forbidden_path_config),
    );

    let mut candidates = BTreeSet::new();
    let child_exceptions = child_cfg
        .filter(|cfg| cfg.enabled)
        .map(|cfg| cfg.exceptions.as_slice())
        .unwrap_or(&[]);
    let mut weakened = Vec::new();

    for exception in child_exceptions {
        if base_guard.is_forbidden(exception) && !child_guard.is_forbidden(exception) {
            weakened.push(WeakenedProhibition {
                atom: format!("access({exception})"),
            });
        }
    }

    for pattern in base_cfg.effective_patterns() {
        candidates.insert(representative_path(&pattern));
        for exception in child_exceptions {
            if let Some(witness) = path_intersection_witness(&pattern, exception) {
                candidates.insert(witness);
            }
        }
    }

    for exception in child_exceptions {
        candidates.insert(representative_path(exception));
    }

    weakened.extend(candidates.into_iter().filter_map(|candidate| {
        (base_guard.is_forbidden(&candidate) && !child_guard.is_forbidden(&candidate)).then(|| {
            WeakenedProhibition {
                atom: format!("access({candidate})"),
            }
        })
    }));

    weakened
}

pub(crate) fn check_path_allowlist_inheritance(
    base_cfg: Option<&PathAllowlistConfig>,
    child_cfg: Option<&PathAllowlistConfig>,
) -> Vec<WeakenedProhibition> {
    let Some(base_cfg) = base_cfg.filter(|cfg| cfg.enabled) else {
        return Vec::new();
    };

    let base_guard = PathAllowlistGuard::with_config(base_cfg.clone());
    let child_guard = PathAllowlistGuard::with_config(
        child_cfg
            .filter(|cfg| cfg.enabled)
            .cloned()
            .unwrap_or_else(disabled_path_allowlist_config),
    );

    let child_cfg = child_cfg.filter(|cfg| cfg.enabled);
    let mut weakened = Vec::new();
    weakened.extend(check_path_allowlist_mode_inheritance(
        &base_guard,
        &child_guard,
        child_cfg.map_or(&[][..], |cfg| cfg.file_access_allow.as_slice()),
        "access",
        PathAllowlistGuard::is_file_access_allowed,
    ));
    weakened.extend(check_path_allowlist_mode_inheritance(
        &base_guard,
        &child_guard,
        child_cfg.map_or(&[][..], |cfg| cfg.file_write_allow.as_slice()),
        "write",
        PathAllowlistGuard::is_file_write_allowed,
    ));
    weakened.extend(check_path_allowlist_mode_inheritance(
        &base_guard,
        &child_guard,
        child_cfg.map_or(&[][..], |cfg| cfg.patch_allow.as_slice()),
        "patch",
        PathAllowlistGuard::is_patch_allowed,
    ));
    weakened
}

pub(crate) fn check_path_allowlist_mode_inheritance<F>(
    base_guard: &PathAllowlistGuard,
    child_guard: &PathAllowlistGuard,
    child_patterns: &[String],
    atom_prefix: &str,
    is_allowed: F,
) -> Vec<WeakenedProhibition>
where
    F: Fn(&PathAllowlistGuard, &str) -> bool,
{
    let mut candidates = BTreeSet::new();
    for pattern in child_patterns {
        candidates.extend(representative_path_samples(pattern));
    }
    candidates.insert(default_path_probe(base_guard, &is_allowed));

    candidates
        .into_iter()
        .filter(|candidate| {
            !is_allowed(base_guard, candidate) && is_allowed(child_guard, candidate)
        })
        .map(|candidate| WeakenedProhibition {
            atom: format!("{atom_prefix}({candidate})"),
        })
        .collect()
}

pub(crate) fn check_egress_inheritance(
    base_cfg: Option<&EgressAllowlistConfig>,
    child_cfg: Option<&EgressAllowlistConfig>,
) -> Vec<WeakenedProhibition> {
    let Some(base_cfg) = base_cfg.filter(|cfg| cfg.enabled) else {
        return Vec::new();
    };

    let child_cfg = child_cfg.filter(|cfg| cfg.enabled);
    let base_policy = domain_policy_from_config(base_cfg);
    let child_policy =
        domain_policy_from_config(&child_cfg.cloned().unwrap_or_else(disabled_egress_config));
    let base_block_patterns = base_cfg.effective_block_patterns();

    let mut candidates = BTreeSet::new();
    for blocked in &base_block_patterns {
        candidates.insert(representative_domain(blocked));
    }

    if child_cfg.is_none_or(|cfg| {
        matches!(
            cfg.default_action,
            None | Some(PolicyAction::Allow) | Some(PolicyAction::Log)
        )
    }) {
        candidates.insert(default_domain_probe(&base_policy));
    }

    if let Some(child_cfg) = child_cfg {
        let child_allow_patterns = child_cfg.effective_allow_patterns();
        for allowed in &child_allow_patterns {
            candidates.insert(representative_domain(allowed));
            for blocked in &base_block_patterns {
                if let Some(witness) = domain_intersection_witness(blocked, allowed) {
                    candidates.insert(witness);
                }
            }
        }
    }

    candidates
        .into_iter()
        .filter(|candidate| {
            domain_action(&base_policy, candidate) == PolicyAction::Block
                && domain_action(&child_policy, candidate) != PolicyAction::Block
        })
        .map(|candidate| WeakenedProhibition {
            atom: format!("egress({candidate})"),
        })
        .collect()
}

pub(crate) fn check_mcp_inheritance(
    base_cfg: Option<&McpToolConfig>,
    child_cfg: Option<&McpToolConfig>,
) -> Vec<WeakenedProhibition> {
    let Some(base_cfg) = base_cfg.filter(|cfg| cfg.enabled) else {
        return Vec::new();
    };

    let base_guard = McpToolGuard::with_config(base_cfg.clone());
    let child_guard = McpToolGuard::with_config(
        child_cfg
            .filter(|cfg| cfg.enabled)
            .cloned()
            .unwrap_or_else(disabled_mcp_config),
    );
    let base_block_tools = base_cfg.effective_block_tools();

    let mut candidates = BTreeSet::new();
    for blocked in &base_block_tools {
        candidates.insert(blocked.clone());
    }

    if let Some(child_cfg) = child_cfg.filter(|cfg| cfg.enabled) {
        candidates.extend(child_cfg.effective_allow_tools());
        candidates.extend(child_cfg.require_confirmation.iter().cloned());
    }

    let base_allow_tools = base_cfg.effective_allow_tools();

    if !base_allow_tools.is_empty()
        || matches!(base_cfg.default_action, Some(McpDefaultAction::Block))
    {
        candidates.insert(default_mcp_probe(base_cfg, child_cfg));
    }

    let Some(block_probe) = base_block_tools.first().cloned().or_else(|| {
        (!base_allow_tools.is_empty()
            || matches!(base_cfg.default_action, Some(McpDefaultAction::Block)))
        .then(|| default_mcp_probe(base_cfg, child_cfg))
    }) else {
        return Vec::new();
    };
    let blocked_decision = std::mem::discriminant(&base_guard.is_allowed(&block_probe));
    let mut weakened: Vec<_> = candidates
        .iter()
        .filter(|candidate| {
            std::mem::discriminant(&base_guard.is_allowed(candidate)) == blocked_decision
                && std::mem::discriminant(&child_guard.is_allowed(candidate)) != blocked_decision
        })
        .map(|candidate| WeakenedProhibition {
            atom: format!("mcp({candidate})"),
        })
        .collect();

    weakened.extend(check_mcp_max_args_size_inheritance(
        base_cfg,
        child_cfg,
        &base_guard,
        &child_guard,
        &candidates,
        &block_probe,
    ));

    weakened
}

pub(crate) fn check_shell_command_inheritance(
    base_cfg: Option<&ShellCommandConfig>,
    child_cfg: Option<&ShellCommandConfig>,
    base_forbidden_path: Option<&ForbiddenPathConfig>,
    child_forbidden_path: Option<&ForbiddenPathConfig>,
) -> Vec<WeakenedProhibition> {
    let Some(base_cfg) = base_cfg.filter(|cfg| cfg.enabled) else {
        return Vec::new();
    };

    let child_cfg = child_cfg.filter(|cfg| cfg.enabled);
    let mut weakened = check_shell_regex_inheritance(base_cfg, child_cfg);

    if base_cfg.enforce_forbidden_paths {
        let base_forbidden_path = Some(
            base_forbidden_path
                .cloned()
                .unwrap_or_else(ForbiddenPathConfig::default),
        );
        let child_forbidden_path = if child_cfg.is_some_and(|cfg| cfg.enforce_forbidden_paths) {
            Some(
                child_forbidden_path
                    .cloned()
                    .unwrap_or_else(ForbiddenPathConfig::default),
            )
        } else {
            None
        };

        weakened.extend(check_shell_forbidden_path_inheritance(
            base_forbidden_path.as_ref(),
            child_forbidden_path.as_ref(),
        ));
    }

    weakened.sort_by(|a, b| a.atom.cmp(&b.atom));
    weakened.dedup_by(|a, b| a.atom == b.atom);
    weakened
}

pub(crate) fn check_shell_regex_inheritance(
    base_cfg: &ShellCommandConfig,
    child_cfg: Option<&ShellCommandConfig>,
) -> Vec<WeakenedProhibition> {
    let child_cfg = child_cfg.cloned().unwrap_or_else(disabled_shell_config);

    let mut candidates = default_shell_command_probes();
    for pattern in &base_cfg.forbidden_patterns {
        candidates.extend(representative_shell_command_samples(pattern));
    }
    for pattern in &child_cfg.forbidden_patterns {
        candidates.extend(representative_shell_command_samples(pattern));
    }

    candidates
        .into_iter()
        .filter(|candidate| {
            shell_regex_blocks_command(base_cfg, candidate)
                && !shell_regex_blocks_command(&child_cfg, candidate)
        })
        .map(|candidate| WeakenedProhibition {
            atom: format!("exec({candidate})"),
        })
        .collect()
}

pub(crate) fn check_shell_forbidden_path_inheritance(
    base_cfg: Option<&ForbiddenPathConfig>,
    child_cfg: Option<&ForbiddenPathConfig>,
) -> Vec<WeakenedProhibition> {
    let Some(base_cfg) = base_cfg.filter(|cfg| cfg.enabled) else {
        return Vec::new();
    };

    let base_guard = ForbiddenPathGuard::with_config(base_cfg.clone());
    let child_guard = ForbiddenPathGuard::with_config(
        child_cfg
            .filter(|cfg| cfg.enabled)
            .cloned()
            .unwrap_or_else(disabled_forbidden_path_config),
    );

    let mut candidates = BTreeSet::new();
    let child_exceptions = child_cfg
        .filter(|cfg| cfg.enabled)
        .map(|cfg| cfg.exceptions.as_slice())
        .unwrap_or(&[]);
    let mut weakened = Vec::new();

    for exception in child_exceptions {
        if base_guard.is_forbidden(exception) && !child_guard.is_forbidden(exception) {
            weakened.push(WeakenedProhibition {
                atom: format!("exec(touches {exception})"),
            });
        }
    }

    for pattern in base_cfg.effective_patterns() {
        candidates.insert(representative_path(&pattern));
        for exception in child_exceptions {
            if let Some(witness) = path_intersection_witness(&pattern, exception) {
                candidates.insert(witness);
            }
        }
    }

    weakened.extend(candidates.into_iter().filter_map(|candidate| {
        (base_guard.is_forbidden(&candidate) && !child_guard.is_forbidden(&candidate)).then(|| {
            WeakenedProhibition {
                atom: format!("exec(touches {candidate})"),
            }
        })
    }));

    weakened
}

pub(crate) fn disabled_forbidden_path_config() -> ForbiddenPathConfig {
    ForbiddenPathConfig {
        enabled: false,
        patterns: Some(Vec::new()),
        exceptions: Vec::new(),
        additional_patterns: Vec::new(),
        remove_patterns: Vec::new(),
    }
}

pub(crate) fn disabled_path_allowlist_config() -> PathAllowlistConfig {
    PathAllowlistConfig {
        enabled: false,
        file_access_allow: Vec::new(),
        file_write_allow: Vec::new(),
        patch_allow: Vec::new(),
    }
}

pub(crate) fn disabled_egress_config() -> EgressAllowlistConfig {
    EgressAllowlistConfig {
        enabled: false,
        allow: Vec::new(),
        block: Vec::new(),
        default_action: Some(PolicyAction::Allow),
        additional_allow: Vec::new(),
        remove_allow: Vec::new(),
        additional_block: Vec::new(),
        remove_block: Vec::new(),
    }
}

pub(crate) fn disabled_mcp_config() -> McpToolConfig {
    McpToolConfig {
        enabled: false,
        allow: Vec::new(),
        block: Vec::new(),
        require_confirmation: Vec::new(),
        default_action: Some(McpDefaultAction::Allow),
        max_args_size: None,
        additional_allow: Vec::new(),
        remove_allow: Vec::new(),
        additional_block: Vec::new(),
        remove_block: Vec::new(),
    }
}

const DEFAULT_MCP_MAX_ARGS_SIZE: usize = 1024 * 1024;

pub(crate) fn effective_mcp_max_args_size(cfg: Option<&McpToolConfig>) -> usize {
    match cfg.filter(|cfg| cfg.enabled) {
        Some(cfg) => cfg.max_args_size.unwrap_or(DEFAULT_MCP_MAX_ARGS_SIZE),
        None => usize::MAX,
    }
}

pub(crate) fn disabled_shell_config() -> ShellCommandConfig {
    ShellCommandConfig {
        enabled: false,
        forbidden_patterns: Vec::new(),
        enforce_forbidden_paths: false,
    }
}

pub(crate) fn domain_policy_from_config(config: &EgressAllowlistConfig) -> DomainPolicy {
    let mut policy = DomainPolicy::new();
    policy.set_default_action(config.default_action.clone().unwrap_or_default());
    policy.extend_allow(config.effective_allow_patterns());
    policy.extend_block(config.effective_block_patterns());
    policy
}

pub(crate) fn check_mcp_max_args_size_inheritance(
    base_cfg: &McpToolConfig,
    child_cfg: Option<&McpToolConfig>,
    base_guard: &McpToolGuard,
    child_guard: &McpToolGuard,
    candidates: &BTreeSet<String>,
    block_probe: &str,
) -> Vec<WeakenedProhibition> {
    let base_limit = effective_mcp_max_args_size(Some(base_cfg));
    let child_limit = effective_mcp_max_args_size(child_cfg);

    if child_limit <= base_limit {
        return Vec::new();
    }

    let blocked_decision = std::mem::discriminant(&base_guard.is_allowed(block_probe));

    candidates
        .iter()
        .find(|candidate| {
            std::mem::discriminant(&base_guard.is_allowed(candidate)) != blocked_decision
                && std::mem::discriminant(&child_guard.is_allowed(candidate)) != blocked_decision
        })
        .map(|candidate| {
            vec![WeakenedProhibition {
                atom: format!(
                    "mcp({candidate},args_size={})",
                    base_limit.saturating_add(1)
                ),
            }]
        })
        .unwrap_or_default()
}

pub(crate) fn domain_action(policy: &DomainPolicy, domain: &str) -> PolicyAction {
    policy.evaluate_detailed(domain).action
}
