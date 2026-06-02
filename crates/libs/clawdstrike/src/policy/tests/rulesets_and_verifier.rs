//! Built-in ruleset loading and load-time verifier tests.

use super::*;

#[test]
fn test_rulesets() {
    let default = match RuleSet::by_name("default") {
        Ok(Some(rs)) => rs,
        Ok(None) => panic!("missing built-in ruleset: default"),
        Err(e) => panic!("failed to load built-in ruleset: {}", e),
    };
    assert_eq!(default.id, "default");

    let strict = match RuleSet::by_name("strict") {
        Ok(Some(rs)) => rs,
        Ok(None) => panic!("missing built-in ruleset: strict"),
        Err(e) => panic!("failed to load built-in ruleset: {}", e),
    };
    assert!(strict.policy.settings.effective_fail_fast());

    let permissive = match RuleSet::by_name("permissive") {
        Ok(Some(rs)) => rs,
        Ok(None) => panic!("missing built-in ruleset: permissive"),
        Err(e) => panic!("failed to load built-in ruleset: {}", e),
    };
    assert!(permissive.policy.settings.effective_verbose_logging());
}

#[test]
fn test_ruleset_by_name() {
    assert!(matches!(RuleSet::by_name("default"), Ok(Some(_))));
    assert!(matches!(RuleSet::by_name("strict"), Ok(Some(_))));
    assert!(matches!(RuleSet::by_name("ai-agent"), Ok(Some(_))));
    assert!(matches!(RuleSet::by_name("cicd"), Ok(Some(_))));
    assert!(matches!(RuleSet::by_name("permissive"), Ok(Some(_))));
    assert!(matches!(RuleSet::by_name("unknown"), Ok(None)));
}

#[test]
fn test_origin_enclaves_example_ruleset_loads() {
    let (yaml, _) = RuleSet::yaml_by_name("origin-enclaves-example").unwrap();
    let policy = Policy::from_yaml(yaml).unwrap();
    assert_eq!(policy.version, "1.4.0");
    assert!(policy.origins.is_some());
    let origins = policy.origins.unwrap();
    assert_eq!(origins.profiles.len(), 4);
    assert_eq!(origins.profiles[0].id, "incident-room");
    assert_eq!(origins.profiles[1].id, "external-chat");
    assert_eq!(origins.profiles[2].id, "code-review");
    assert_eq!(origins.profiles[3].id, "internal-default");
    assert_eq!(origins.default_behavior, Some(OriginDefaultBehavior::Deny));
}

#[test]
fn test_rulesets_parse_validate_and_match_disk_registry() {
    use std::collections::HashSet;
    use std::path::PathBuf;

    let expected: HashSet<&str> = RuleSet::list().iter().copied().collect();
    assert!(!expected.is_empty());

    for id in RuleSet::list() {
        let rs = RuleSet::by_name(id)
            .unwrap()
            .unwrap_or_else(|| panic!("missing built-in ruleset: {}", id));
        rs.policy.validate().unwrap();

        let prefixed = format!("clawdstrike:{}", id);
        let rs2 = RuleSet::by_name(&prefixed)
            .unwrap()
            .unwrap_or_else(|| panic!("missing built-in ruleset: {}", prefixed));
        assert_eq!(rs2.id, *id);
    }

    let rulesets_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../../rulesets");
    let mut disk_ids: HashSet<String> = HashSet::new();
    for entry in std::fs::read_dir(&rulesets_dir)
        .unwrap_or_else(|e| panic!("failed to read {:?}: {}", rulesets_dir, e))
    {
        let entry = entry.unwrap();
        let path = entry.path();
        if path.extension().is_some_and(|e| e == "yaml") {
            if let Some(stem) = path.file_stem().and_then(|s| s.to_str()) {
                disk_ids.insert(stem.to_string());
            }
        }
    }

    let disk: HashSet<&str> = disk_ids.iter().map(|s| s.as_str()).collect();
    assert_eq!(
        disk, expected,
        "rulesets/ directory and RuleSet::list() drifted"
    );
}

#[test]
fn strict_verification_without_registered_verifier_fails_closed() {
    let yaml = r#"
version: "1.5.0"
name: strict-verified
settings:
  verification:
    enabled: true
    strict: true
"#;

    let err = Policy::from_yaml(yaml)
        .expect_err("strict verification should fail without a registered verifier");
    assert!(err
        .to_string()
        .contains("no load-time policy verifier is registered"));
}

#[test]
fn non_strict_verification_without_registered_verifier_warns_but_loads() {
    let yaml = r#"
version: "1.5.0"
name: non-strict-verified
settings:
  verification:
    enabled: true
    strict: false
"#;

    let policy = Policy::from_yaml(yaml).expect("non-strict verification should not block");
    assert_eq!(policy.name, "non-strict-verified");
}

#[test]
fn child_inherits_parent_verification_during_extends_load() {
    let parent = Policy::from_yaml_unvalidated(
        r#"
version: "1.5.0"
name: parent
settings:
  verification:
    enabled: true
    strict: true
"#,
    )
    .expect("parse parent");

    let child = Policy::from_yaml_unvalidated(
        r#"
version: "1.5.0"
name: child
extends: "parent.yaml"
settings:
  verification:
    enabled: false
    strict: false
"#,
    )
    .expect("parse child");

    let merged = parent.merge(&child);
    merged.validate().expect("merged policy should validate");
    assert_eq!(merged.name, "child");
    let verification = merged.settings.effective_verification();
    assert!(verification.enabled);
    assert!(verification.strict);
}

#[test]
fn replace_merge_cannot_disable_parent_verification() {
    let parent = Policy::from_yaml_unvalidated(
        r#"
version: "1.5.0"
name: parent
settings:
  verification:
    enabled: true
    strict: true
"#,
    )
    .expect("parse parent");

    let child = Policy::from_yaml_unvalidated(
        r#"
version: "1.5.0"
name: child
merge_strategy: replace
settings:
  verification:
    enabled: false
    strict: false
"#,
    )
    .expect("parse child");

    let merged = parent.merge(&child);
    let verification = merged.settings.effective_verification();
    assert!(verification.enabled);
    assert!(verification.strict);
}

#[test]
fn merge_strategy_merge_keeps_settings_shallow_except_verification_gate() {
    let parent = Policy::from_yaml_unvalidated(
        r#"
version: "1.5.0"
name: parent
settings:
  fail_fast: true
  session_timeout_secs: 42
  verification:
    enabled: true
    strict: true
"#,
    )
    .expect("parse parent");

    let child = Policy::from_yaml_unvalidated(
        r#"
version: "1.5.0"
name: child
merge_strategy: merge
settings:
  verbose_logging: true
"#,
    )
    .expect("parse child");

    let merged = parent.merge(&child);

    assert_eq!(merged.settings.fail_fast, None);
    assert_eq!(merged.settings.session_timeout_secs, None);
    assert_eq!(merged.settings.verbose_logging, Some(true));

    let verification = merged.settings.effective_verification();
    assert!(verification.enabled);
    assert!(verification.strict);
}

#[test]
fn strict_verification_with_extends_defers_until_resolution() {
    let yaml = r#"
version: "1.5.0"
name: child
extends: "parent.yaml"
settings:
  verification:
    enabled: true
    strict: true
"#;

    let policy =
        Policy::from_yaml(yaml).expect("unresolved strict policies should defer verification");
    assert_eq!(policy.extends.as_deref(), Some("parent.yaml"));
}
