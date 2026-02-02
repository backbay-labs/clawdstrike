//! Integration tests for policy extends feature

#![allow(clippy::expect_used, clippy::unwrap_used)]

use clawdstrike::Policy;
use std::fs;
use tempfile::TempDir;

#[test]
fn test_policy_extends_builtin_strict() {
    let yaml = r#"
version: "1.0.0"
name: CustomPolicy
extends: strict
guards:
  forbidden_path:
    additional_patterns:
      - "**/custom-secret/**"
"#;

    let policy = Policy::from_yaml_with_extends(yaml, None).unwrap();

    // Should have strict's settings
    assert!(policy.settings.fail_fast);

    // Should have custom pattern added
    let fp = policy.guards.forbidden_path.as_ref().unwrap();
    assert!(fp.patterns.iter().any(|p| p.contains("custom-secret")));
}

#[test]
fn test_policy_extends_file() {
    let temp_dir = TempDir::new().unwrap();

    // Create base policy
    let base_yaml = r#"
version: "1.0.0"
name: Base
guards:
  forbidden_path:
    patterns:
      - "**/.ssh/**"
settings:
  fail_fast: true
"#;
    let base_path = temp_dir.path().join("base.yaml");
    fs::write(&base_path, base_yaml).unwrap();

    // Create child policy
    let child_yaml = format!(
        r#"
version: "1.0.0"
name: Child
extends: {}
guards:
  forbidden_path:
    additional_patterns:
      - "**/secrets/**"
"#,
        base_path.display()
    );

    let policy = Policy::from_yaml_with_extends(&child_yaml, None).unwrap();

    assert_eq!(policy.name, "Child");
    assert!(policy.settings.fail_fast); // from base
    let fp = policy.guards.forbidden_path.as_ref().unwrap();
    assert!(fp.patterns.iter().any(|p| p.contains(".ssh")));
    assert!(fp.patterns.iter().any(|p| p.contains("secrets")));
}

#[test]
fn test_policy_merge_strategy_replace() {
    let yaml = r#"
version: "1.0.0"
name: CustomPolicy
extends: strict
merge_strategy: replace
settings:
  fail_fast: false
"#;

    let policy = Policy::from_yaml_with_extends(yaml, None).unwrap();

    // Replace strategy means child settings replace base entirely
    assert!(!policy.settings.fail_fast);
}

#[test]
fn test_policy_merge_strategy_deep_merge() {
    let yaml = r#"
version: "1.0.0"
name: CustomPolicy
extends: strict
merge_strategy: deep_merge
settings:
  verbose_logging: true
"#;

    let policy = Policy::from_yaml_with_extends(yaml, None).unwrap();

    // Deep merge keeps base values not overridden
    assert!(policy.settings.fail_fast); // from strict
    assert!(policy.settings.verbose_logging); // from child
}

#[test]
fn test_policy_remove_patterns() {
    let temp_dir = TempDir::new().unwrap();

    // Create base policy with patterns
    let base_yaml = r#"
version: "1.0.0"
name: Base
guards:
  forbidden_path:
    patterns:
      - "**/.ssh/**"
      - "**/.env"
      - "**/.aws/**"
"#;
    let base_path = temp_dir.path().join("base.yaml");
    fs::write(&base_path, base_yaml).unwrap();

    // Create child policy that removes .env
    let child_yaml = format!(
        r#"
version: "1.0.0"
name: DevPolicy
extends: {}
guards:
  forbidden_path:
    remove_patterns:
      - "**/.env"
"#,
        base_path.display()
    );

    let policy = Policy::from_yaml_with_extends(&child_yaml, None).unwrap();
    let fp = policy.guards.forbidden_path.as_ref().unwrap();

    // .env patterns should be removed
    assert!(!fp.patterns.iter().any(|p| p == "**/.env"));
    // But other patterns should remain
    assert!(fp.patterns.iter().any(|p| p.contains(".ssh")));
    assert!(fp.patterns.iter().any(|p| p.contains(".aws")));
}

#[test]
fn test_policy_circular_extends_detected() {
    let temp_dir = TempDir::new().unwrap();

    // Create policy A that extends B
    let policy_a = temp_dir.path().join("policy-a.yaml");
    let policy_b = temp_dir.path().join("policy-b.yaml");

    fs::write(
        &policy_a,
        format!(
            r#"
version: "1.0.0"
name: A
extends: {}
"#,
            policy_b.display()
        ),
    )
    .unwrap();

    fs::write(
        &policy_b,
        format!(
            r#"
version: "1.0.0"
name: B
extends: {}
"#,
            policy_a.display()
        ),
    )
    .unwrap();

    let result = Policy::from_yaml_file_with_extends(&policy_a);
    assert!(result.is_err());
    let err = result.unwrap_err().to_string();
    assert!(err.contains("Circular"));
}

#[test]
fn test_policy_multi_level_extends() {
    let temp_dir = TempDir::new().unwrap();

    // Create grandparent policy
    let grandparent_yaml = r#"
version: "1.0.0"
name: Grandparent
settings:
  session_timeout_secs: 1800
"#;
    let grandparent_path = temp_dir.path().join("grandparent.yaml");
    fs::write(&grandparent_path, grandparent_yaml).unwrap();

    // Create parent policy
    let parent_yaml = format!(
        r#"
version: "1.0.0"
name: Parent
extends: {}
settings:
  fail_fast: true
"#,
        grandparent_path.display()
    );
    let parent_path = temp_dir.path().join("parent.yaml");
    fs::write(&parent_path, &parent_yaml).unwrap();

    // Create child policy
    let child_yaml = format!(
        r#"
version: "1.0.0"
name: Child
extends: {}
settings:
  verbose_logging: true
"#,
        parent_path.display()
    );

    let policy = Policy::from_yaml_with_extends(&child_yaml, None).unwrap();

    assert_eq!(policy.name, "Child");
    assert_eq!(policy.settings.session_timeout_secs, 1800); // from grandparent
    assert!(policy.settings.fail_fast); // from parent
    assert!(policy.settings.verbose_logging); // from child
}
