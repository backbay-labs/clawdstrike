#![cfg(feature = "full")]
#![allow(clippy::expect_used, clippy::unwrap_used)]

//! Tests for the CUA-specific built-in policy rulesets:
//! remote-desktop, remote-desktop-strict, remote-desktop-permissive.

use clawdstrike::policy::RuleSet;

#[test]
fn remote_desktop_ruleset_parses_without_errors() {
    let rs = RuleSet::by_name("remote-desktop")
        .expect("should not error")
        .expect("remote-desktop ruleset must exist");

    assert_eq!(rs.id, "remote-desktop");
    assert_eq!(rs.policy.name, "Remote Desktop Agent");
    rs.policy.validate().expect("policy must validate");
}

#[test]
fn remote_desktop_strict_ruleset_parses_without_errors() {
    let rs = RuleSet::by_name("remote-desktop-strict")
        .expect("should not error")
        .expect("remote-desktop-strict ruleset must exist");

    assert_eq!(rs.id, "remote-desktop-strict");
    assert_eq!(rs.policy.name, "Remote Desktop Strict");
    rs.policy.validate().expect("policy must validate");
}

#[test]
fn remote_desktop_permissive_ruleset_parses_without_errors() {
    let rs = RuleSet::by_name("remote-desktop-permissive")
        .expect("should not error")
        .expect("remote-desktop-permissive ruleset must exist");

    assert_eq!(rs.id, "remote-desktop-permissive");
    assert_eq!(rs.policy.name, "Remote Desktop Permissive");
    rs.policy.validate().expect("policy must validate");
}

#[test]
fn remote_desktop_strict_inherits_from_remote_desktop() {
    // Load the raw YAML for remote-desktop-strict and verify it declares extends: remote-desktop
    let yaml = include_str!("../rulesets/remote-desktop-strict.yaml");
    let raw: serde_yaml::Value = serde_yaml::from_str(yaml).expect("valid YAML");
    let extends = raw
        .get("extends")
        .and_then(|v| v.as_str())
        .expect("remote-desktop-strict must have extends field");
    assert_eq!(
        extends, "remote-desktop",
        "remote-desktop-strict must extend remote-desktop"
    );
}

#[test]
fn remote_desktop_permissive_inherits_from_remote_desktop() {
    let yaml = include_str!("../rulesets/remote-desktop-permissive.yaml");
    let raw: serde_yaml::Value = serde_yaml::from_str(yaml).expect("valid YAML");
    let extends = raw
        .get("extends")
        .and_then(|v| v.as_str())
        .expect("remote-desktop-permissive must have extends field");
    assert_eq!(
        extends, "remote-desktop",
        "remote-desktop-permissive must extend remote-desktop"
    );
}

#[test]
fn all_cua_rulesets_have_computer_use_guard_configured() {
    for name in &[
        "remote-desktop",
        "remote-desktop-strict",
        "remote-desktop-permissive",
    ] {
        let rs = RuleSet::by_name(name)
            .unwrap_or_else(|e| panic!("error loading {}: {}", name, e))
            .unwrap_or_else(|| panic!("missing ruleset: {}", name));

        assert!(
            rs.policy.guards.computer_use.is_some(),
            "ruleset '{}' must have computer_use guard configured",
            name
        );
    }
}

#[test]
fn remote_desktop_has_all_ten_cua_actions() {
    let rs = RuleSet::by_name("remote-desktop")
        .unwrap()
        .expect("remote-desktop must exist");

    let cu = rs
        .policy
        .guards
        .computer_use
        .as_ref()
        .expect("computer_use config must be present");

    let expected_actions = vec![
        "remote.session.connect",
        "remote.session.disconnect",
        "remote.session.reconnect",
        "input.inject",
        "remote.clipboard",
        "remote.file_transfer",
        "remote.audio",
        "remote.drive_mapping",
        "remote.printing",
        "remote.session_share",
    ];
    let expected_set: std::collections::BTreeSet<String> = expected_actions
        .into_iter()
        .map(|s| s.to_string())
        .collect();
    let actual_set: std::collections::BTreeSet<String> =
        cu.allowed_actions.iter().cloned().collect();

    assert_eq!(
        actual_set, expected_set,
        "remote-desktop computer_use actions should match the canonical 10-action set"
    );
}

#[test]
fn remote_desktop_strict_has_minimal_actions() {
    let rs = RuleSet::by_name("remote-desktop-strict")
        .unwrap()
        .expect("remote-desktop-strict must exist");

    let cu = rs
        .policy
        .guards
        .computer_use
        .as_ref()
        .expect("computer_use config must be present");

    // strict only allows connect, disconnect, input.inject
    assert!(cu
        .allowed_actions
        .contains(&"remote.session.connect".to_string()));
    assert!(cu
        .allowed_actions
        .contains(&"remote.session.disconnect".to_string()));
    assert!(cu.allowed_actions.contains(&"input.inject".to_string()));

    // must NOT contain session_share, clipboard, file_transfer, reconnect
    assert!(
        !cu.allowed_actions
            .contains(&"remote.session_share".to_string()),
        "strict must not allow session_share"
    );
    assert!(
        !cu.allowed_actions.contains(&"remote.clipboard".to_string()),
        "strict must not allow clipboard"
    );
    assert!(
        !cu.allowed_actions
            .contains(&"remote.file_transfer".to_string()),
        "strict must not allow file_transfer"
    );
}

#[test]
fn remote_desktop_strict_disables_all_side_channels() {
    let rs = RuleSet::by_name("remote-desktop-strict")
        .unwrap()
        .expect("remote-desktop-strict must exist");

    let sc = rs
        .policy
        .guards
        .remote_desktop_side_channel
        .as_ref()
        .expect("remote_desktop_side_channel config must be present");

    assert!(!sc.clipboard_enabled, "strict: clipboard must be disabled");
    assert!(
        !sc.file_transfer_enabled,
        "strict: file_transfer must be disabled"
    );
    assert!(
        !sc.session_share_enabled,
        "strict: session_share must be disabled"
    );
    assert!(!sc.audio_enabled, "strict: audio must be disabled");
    assert!(
        !sc.drive_mapping_enabled,
        "strict: drive mapping must be disabled"
    );
    assert!(!sc.printing_enabled, "strict: printing must be disabled");
}

#[test]
fn remote_desktop_strict_requires_postcondition_probe() {
    let rs = RuleSet::by_name("remote-desktop-strict")
        .unwrap()
        .expect("remote-desktop-strict must exist");

    let iic = rs
        .policy
        .guards
        .input_injection_capability
        .as_ref()
        .expect("input_injection_capability config must be present");

    assert!(
        iic.require_postcondition_probe,
        "strict: postcondition probe must be required"
    );
    assert_eq!(
        iic.allowed_input_types,
        vec!["keyboard".to_string()],
        "strict: only keyboard input should be allowed"
    );
}

#[test]
fn remote_desktop_permissive_enables_all_channels() {
    let rs = RuleSet::by_name("remote-desktop-permissive")
        .unwrap()
        .expect("remote-desktop-permissive must exist");

    let sc = rs
        .policy
        .guards
        .remote_desktop_side_channel
        .as_ref()
        .expect("remote_desktop_side_channel config must be present");

    assert!(
        sc.clipboard_enabled,
        "permissive: clipboard must be enabled"
    );
    assert!(
        sc.file_transfer_enabled,
        "permissive: file_transfer must be enabled"
    );
    assert!(
        sc.session_share_enabled,
        "permissive: session_share must be enabled"
    );
    assert!(sc.audio_enabled, "permissive: audio must be enabled");
    assert!(
        sc.drive_mapping_enabled,
        "permissive: drive mapping must be enabled"
    );
    assert!(sc.printing_enabled, "permissive: printing must be enabled");
}

#[test]
fn remote_desktop_permissive_allows_all_input_types() {
    let rs = RuleSet::by_name("remote-desktop-permissive")
        .unwrap()
        .expect("remote-desktop-permissive must exist");

    let iic = rs
        .policy
        .guards
        .input_injection_capability
        .as_ref()
        .expect("input_injection_capability config must be present");

    assert!(iic.allowed_input_types.contains(&"keyboard".to_string()));
    assert!(iic.allowed_input_types.contains(&"mouse".to_string()));
    assert!(iic.allowed_input_types.contains(&"touch".to_string()));
    assert!(
        !iic.require_postcondition_probe,
        "permissive: postcondition probe must not be required"
    );
}

#[test]
fn cua_rulesets_are_in_builtin_list() {
    let list = RuleSet::list();
    assert!(
        list.contains(&"remote-desktop"),
        "remote-desktop must be in RuleSet::list()"
    );
    assert!(
        list.contains(&"remote-desktop-strict"),
        "remote-desktop-strict must be in RuleSet::list()"
    );
    assert!(
        list.contains(&"remote-desktop-permissive"),
        "remote-desktop-permissive must be in RuleSet::list()"
    );
}

#[test]
fn cua_rulesets_resolve_with_clawdstrike_prefix() {
    for name in &[
        "remote-desktop",
        "remote-desktop-strict",
        "remote-desktop-permissive",
    ] {
        let prefixed = format!("clawdstrike:{}", name);
        let rs = RuleSet::by_name(&prefixed)
            .unwrap_or_else(|e| panic!("error loading {}: {}", prefixed, e))
            .unwrap_or_else(|| panic!("missing ruleset: {}", prefixed));
        assert_eq!(rs.id, *name);
    }
}

#[test]
fn remote_desktop_extends_chain_resolves_correctly() {
    // remote-desktop-strict -> remote-desktop -> ai-agent
    // After full resolution, the policy should have inherited guards from ai-agent
    let rs = RuleSet::by_name("remote-desktop-strict")
        .unwrap()
        .expect("remote-desktop-strict must exist");

    // ai-agent defines prompt_injection and jailbreak guards; they should be inherited
    assert!(
        rs.policy.guards.prompt_injection.is_some(),
        "strict should inherit prompt_injection from ai-agent via remote-desktop"
    );
    assert!(
        rs.policy.guards.jailbreak.is_some(),
        "strict should inherit jailbreak from ai-agent via remote-desktop"
    );
}
