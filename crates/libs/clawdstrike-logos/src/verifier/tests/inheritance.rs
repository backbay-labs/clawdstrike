// Semantic inheritance weakening-detection tests.
//
// Included into `verifier::tests` via `include!` from tests/mod.rs, so these
// bodies share that module's imports and fixtures unchanged.
#[test]
fn sound_inheritance_passes_for_stricter_child_policy() {
    let mut parent = Policy::default();
    parent.guards.forbidden_path = Some(simple_forbidden_path("/etc/shadow"));

    let mut merged = parent.clone();
    merged.guards.forbidden_path = Some(ForbiddenPathConfig {
        enabled: true,
        patterns: Some(vec!["/etc/shadow".to_string(), "/etc/passwd".to_string()]),
        exceptions: vec![],
        additional_patterns: vec![],
        remove_patterns: vec![],
    });

    let report = formula_verifier().verify_policy_with_parent(&parent, &merged, agent());
    assert!(report.inheritance.outcome.is_pass(), "{report:?}");
    assert!(report.all_pass());
}

#[test]
fn inheritance_uses_source_child_without_false_failure() {
    let mut parent = Policy::default();
    parent.guards.forbidden_path = Some(simple_forbidden_path("/etc/shadow"));

    let mut child = Policy::default();
    child.extends = Some("parent.yaml".to_string());

    let effective = parent.merge(&child);
    let report = formula_verifier().verify_policy_with_parent_and_source(
        &parent,
        &child,
        &effective,
        agent(),
    );
    assert!(report.inheritance.outcome.is_pass(), "{report:?}");
}

#[test]
fn origin_enclaves_ruleset_reports_expected_egress_widening() {
    let (parent_yaml, _) = RuleSet::yaml_by_name("default").unwrap();
    let parent = Policy::from_yaml(parent_yaml).unwrap();

    let (child_yaml, _) = RuleSet::yaml_by_name("origin-enclaves-example").unwrap();
    let child = Policy::from_yaml(child_yaml).unwrap();
    let effective = parent.merge(&child);

    let report = formula_verifier().verify_policy_with_parent_and_source(
        &parent,
        &child,
        &effective,
        agent(),
    );

    assert_eq!(report.inheritance.outcome, CheckOutcome::Fail);
    assert!(report
        .inheritance
        .weakened
        .iter()
        .any(|item| item.atom == "egress(x.internal.corp)"));
}

#[test]
fn forbidden_path_exception_weakening_is_detected_semantically() {
    let mut parent = Policy::default();
    parent.guards.forbidden_path = Some(ForbiddenPathConfig {
        enabled: true,
        patterns: Some(vec!["**/.env".to_string()]),
        exceptions: vec![],
        additional_patterns: vec![],
        remove_patterns: vec![],
    });

    let mut merged = parent.clone();
    merged.guards.forbidden_path = Some(ForbiddenPathConfig {
        enabled: true,
        patterns: Some(vec!["**/.env".to_string()]),
        exceptions: vec!["/tmp/project/.env".to_string()],
        additional_patterns: vec![],
        remove_patterns: vec![],
    });

    let report = formula_verifier().verify_policy_with_parent(&parent, &merged, agent());
    assert_eq!(report.inheritance.outcome, CheckOutcome::Fail);
    assert!(report
        .inheritance
        .weakened
        .iter()
        .any(|item| item.atom == "access(/tmp/project/.env)"));
}

#[test]
fn path_allowlist_widening_is_detected_semantically() {
    let mut parent = Policy::default();
    parent.guards.path_allowlist = Some(PathAllowlistConfig {
        enabled: true,
        file_access_allow: vec!["/workspace/project/**".to_string()],
        file_write_allow: vec![],
        patch_allow: vec![],
    });

    let mut merged = parent.clone();
    merged.guards.path_allowlist = Some(PathAllowlistConfig {
        enabled: true,
        file_access_allow: vec!["/workspace/**".to_string()],
        file_write_allow: vec![],
        patch_allow: vec![],
    });

    let report = formula_verifier().verify_policy_with_parent(&parent, &merged, agent());
    assert_eq!(report.inheritance.outcome, CheckOutcome::Fail);
    assert!(report
        .inheritance
        .weakened
        .iter()
        .any(|item| item.atom == "access(/workspace/x)"));
}

#[test]
fn path_allowlist_widening_uses_multiple_representatives() {
    let mut parent = Policy::default();
    parent.guards.path_allowlist = Some(PathAllowlistConfig {
        enabled: true,
        file_access_allow: vec!["/workspace/*x*".to_string()],
        file_write_allow: vec![],
        patch_allow: vec![],
    });

    let mut merged = parent.clone();
    merged.guards.path_allowlist = Some(PathAllowlistConfig {
        enabled: true,
        file_access_allow: vec!["/workspace/*".to_string()],
        file_write_allow: vec![],
        patch_allow: vec![],
    });

    let report = formula_verifier().verify_policy_with_parent(&parent, &merged, agent());
    assert_eq!(report.inheritance.outcome, CheckOutcome::Fail);
    assert!(report
        .inheritance
        .weakened
        .iter()
        .any(|item| item.atom == "access(/workspace/a)"));
}

#[test]
fn egress_allow_override_is_detected_semantically() {
    let mut parent = Policy::default();
    parent.guards.egress_allowlist = Some(EgressAllowlistConfig {
        enabled: true,
        allow: vec![],
        block: vec!["*.internal".to_string()],
        default_action: Some(PolicyAction::Allow),
        additional_allow: vec![],
        remove_allow: vec![],
        additional_block: vec![],
        remove_block: vec![],
    });

    let mut merged = parent.clone();
    merged.guards.egress_allowlist = Some(EgressAllowlistConfig {
        enabled: true,
        allow: vec!["db.internal".to_string()],
        block: vec![],
        default_action: Some(PolicyAction::Allow),
        additional_allow: vec![],
        remove_allow: vec![],
        additional_block: vec![],
        remove_block: vec![],
    });

    let report = formula_verifier().verify_policy_with_parent(&parent, &merged, agent());
    assert_eq!(report.inheritance.outcome, CheckOutcome::Fail);
    assert!(report
        .inheritance
        .weakened
        .iter()
        .any(|item| item.atom == "egress(db.internal)"));
}

#[test]
fn egress_default_block_without_child_guard_is_detected() {
    let mut parent = Policy::default();
    parent.guards.egress_allowlist = Some(EgressAllowlistConfig {
        enabled: true,
        allow: vec![],
        block: vec![],
        default_action: Some(PolicyAction::Block),
        additional_allow: vec![],
        remove_allow: vec![],
        additional_block: vec![],
        remove_block: vec![],
    });

    let child = Policy::default();
    let report = formula_verifier().verify_policy_with_parent(&parent, &child, agent());
    assert_eq!(report.inheritance.outcome, CheckOutcome::Fail);
    assert!(report
        .inheritance
        .weakened
        .iter()
        .any(|item| item.atom == "egress(clawdstrike-inheritance-check.invalid)"));
}

#[test]
fn egress_modifier_weakening_uses_effective_patterns() {
    let mut parent = Policy::default();
    parent.guards.egress_allowlist = Some(EgressAllowlistConfig {
        enabled: true,
        allow: vec![],
        block: vec![],
        default_action: Some(PolicyAction::Allow),
        additional_allow: vec![],
        remove_allow: vec![],
        additional_block: vec!["*.internal".to_string()],
        remove_block: vec![],
    });

    let mut merged = Policy::default();
    merged.guards.egress_allowlist = Some(EgressAllowlistConfig {
        enabled: true,
        allow: vec![],
        block: vec![],
        default_action: Some(PolicyAction::Allow),
        additional_allow: vec!["db.internal".to_string()],
        remove_allow: vec![],
        additional_block: vec![],
        remove_block: vec!["*.internal".to_string()],
    });

    let report = formula_verifier().verify_policy_with_parent(&parent, &merged, agent());
    assert_eq!(report.inheritance.outcome, CheckOutcome::Fail);
    assert!(report
        .inheritance
        .weakened
        .iter()
        .any(|item| item.atom == "egress(db.internal)"));
}

#[test]
fn mcp_allow_override_is_detected_semantically() {
    let mut parent = Policy::default();
    parent.guards.mcp_tool = Some(McpToolConfig {
        enabled: true,
        allow: vec![],
        block: vec!["shell_exec".to_string()],
        require_confirmation: vec![],
        default_action: Some(clawdstrike::guards::McpDefaultAction::Allow),
        max_args_size: None,
        additional_allow: vec![],
        remove_allow: vec![],
        additional_block: vec![],
        remove_block: vec![],
    });

    let mut merged = parent.clone();
    merged.guards.mcp_tool = Some(McpToolConfig {
        enabled: true,
        allow: vec!["shell_exec".to_string()],
        block: vec![],
        require_confirmation: vec![],
        default_action: Some(clawdstrike::guards::McpDefaultAction::Allow),
        max_args_size: None,
        additional_allow: vec![],
        remove_allow: vec![],
        additional_block: vec![],
        remove_block: vec![],
    });

    let report = formula_verifier().verify_policy_with_parent(&parent, &merged, agent());
    assert_eq!(report.inheritance.outcome, CheckOutcome::Fail);
    assert!(report
        .inheritance
        .weakened
        .iter()
        .any(|item| item.atom == "mcp(shell_exec)"));
}

#[test]
fn mcp_max_args_size_weakening_is_detected() {
    let mut parent = Policy::default();
    parent.guards.mcp_tool = Some(McpToolConfig {
        enabled: true,
        allow: vec!["safe_tool".to_string()],
        block: vec![],
        require_confirmation: vec![],
        default_action: Some(clawdstrike::guards::McpDefaultAction::Allow),
        max_args_size: Some(32),
        additional_allow: vec![],
        remove_allow: vec![],
        additional_block: vec![],
        remove_block: vec![],
    });

    let mut merged = parent.clone();
    merged.guards.mcp_tool = Some(McpToolConfig {
        enabled: true,
        allow: vec!["safe_tool".to_string()],
        block: vec![],
        require_confirmation: vec![],
        default_action: Some(clawdstrike::guards::McpDefaultAction::Allow),
        max_args_size: Some(128),
        additional_allow: vec![],
        remove_allow: vec![],
        additional_block: vec![],
        remove_block: vec![],
    });

    let report = formula_verifier().verify_policy_with_parent(&parent, &merged, agent());
    assert_eq!(report.inheritance.outcome, CheckOutcome::Fail);
    assert!(report
        .inheritance
        .weakened
        .iter()
        .any(|item| item.atom == "mcp(safe_tool,args_size=33)"));
}

#[test]
fn dropped_shell_command_guard_is_detected_semantically() {
    let mut parent = Policy::default();
    parent.guards.shell_command = Some(ShellCommandConfig {
        enabled: true,
        forbidden_patterns: vec!["rm -rf /".to_string()],
        enforce_forbidden_paths: true,
    });

    let merged = Policy::default();
    let report = formula_verifier().verify_policy_with_parent(&parent, &merged, agent());
    assert_eq!(report.inheritance.outcome, CheckOutcome::Fail);
    assert!(report
        .inheritance
        .weakened
        .iter()
        .any(|item| item.atom == "exec(rm -rf /)"));
}

#[test]
fn shell_command_path_enforcement_drop_is_detected() {
    let mut parent = Policy::default();
    parent.guards.forbidden_path = Some(simple_forbidden_path("/etc/shadow"));
    parent.guards.shell_command = Some(ShellCommandConfig {
        enabled: true,
        forbidden_patterns: vec!["rm -rf /".to_string()],
        enforce_forbidden_paths: true,
    });

    let mut merged = parent.clone();
    merged.guards.shell_command = Some(ShellCommandConfig {
        enabled: true,
        forbidden_patterns: vec!["rm -rf /".to_string()],
        enforce_forbidden_paths: false,
    });

    let report = formula_verifier().verify_policy_with_parent(&parent, &merged, agent());
    assert_eq!(report.inheritance.outcome, CheckOutcome::Fail);
    assert!(report
        .inheritance
        .weakened
        .iter()
        .any(|item| item.atom == "exec(touches /etc/shadow)"));
}

#[test]
fn shell_command_regex_semantics_allow_stricter_replacement() {
    let mut parent = Policy::default();
    parent.guards.shell_command = Some(ShellCommandConfig {
        enabled: true,
        forbidden_patterns: vec![
            r"(?i)\bcurl\s+https://example\.invalid/install\.sh\s+\|\s+bash\b".to_string(),
        ],
        enforce_forbidden_paths: false,
    });

    let mut merged = parent.clone();
    merged.guards.shell_command = Some(ShellCommandConfig {
        enabled: true,
        forbidden_patterns: vec![r"(?i)\bcurl\s+\S+\s+\|\s+bash\b".to_string()],
        enforce_forbidden_paths: false,
    });

    let report = formula_verifier().verify_policy_with_parent(&parent, &merged, agent());
    assert!(report.inheritance.outcome.is_pass(), "{report:?}");
}

#[test]
fn shell_command_default_forbidden_paths_are_checked_in_inheritance() {
    let mut parent = Policy::default();
    parent.guards.shell_command = Some(ShellCommandConfig {
        enabled: true,
        forbidden_patterns: vec!["rm -rf /".to_string()],
        enforce_forbidden_paths: true,
    });

    let mut merged = parent.clone();
    merged.guards.shell_command = Some(ShellCommandConfig {
        enabled: true,
        forbidden_patterns: vec!["rm -rf /".to_string()],
        enforce_forbidden_paths: false,
    });

    let report = formula_verifier().verify_policy_with_parent(&parent, &merged, agent());
    assert_eq!(report.inheritance.outcome, CheckOutcome::Fail);
    assert!(report
        .inheritance
        .weakened
        .iter()
        .any(|item| item.atom == "exec(touches /etc/shadow)"));
}

