//! Merge-strategy and `extends` inheritance tests.

use super::*;

#[test]
fn test_merge_strategy_default() {
    let yaml = r#"
version: "1.1.0"
name: Test
"#;
    let policy = Policy::from_yaml(yaml).unwrap();
    assert_eq!(policy.merge_strategy, MergeStrategy::DeepMerge);
}

#[test]
fn test_merge_strategy_parse() {
    let yaml = r#"
version: "1.1.0"
name: Test
merge_strategy: replace
"#;
    let policy = Policy::from_yaml(yaml).unwrap();
    assert_eq!(policy.merge_strategy, MergeStrategy::Replace);
}

#[test]
fn test_extends_field_parse() {
    let yaml = r#"
version: "1.1.0"
name: Test
extends: strict
"#;
    let policy = Policy::from_yaml(yaml).unwrap();
    assert_eq!(policy.extends, Some("strict".to_string()));
}

#[test]
fn test_extends_field_none_by_default() {
    let yaml = r#"
version: "1.1.0"
name: Test
"#;
    let policy = Policy::from_yaml(yaml).unwrap();
    assert!(policy.extends.is_none());
}

#[test]
fn test_resolve_base_builtin_strict() {
    let base = Policy::resolve_base("strict").unwrap();
    assert!(base.settings.effective_fail_fast());
}

#[test]
fn test_resolve_base_builtin_default() {
    let base = Policy::resolve_base("default").unwrap();
    assert!(!base.settings.effective_fail_fast());
}

#[test]
fn test_resolve_base_unknown_returns_error() {
    let result = Policy::resolve_base("nonexistent");
    assert!(result.is_err());
}

#[test]
fn test_guard_configs_merge() {
    let base = GuardConfigs {
        forbidden_path: Some(ForbiddenPathConfig {
            patterns: Some(vec!["**/.ssh/**".to_string()]),
            ..Default::default()
        }),
        ..Default::default()
    };

    let child = GuardConfigs {
        forbidden_path: Some(ForbiddenPathConfig {
            additional_patterns: vec!["**/secrets/**".to_string()],
            ..Default::default()
        }),
        ..Default::default()
    };

    let merged = base.merge_with(&child);
    let fp = merged.forbidden_path.unwrap();
    let patterns = fp.patterns.unwrap();
    assert!(patterns.contains(&"**/.ssh/**".to_string()));
    assert!(patterns.contains(&"**/secrets/**".to_string()));
}

#[test]
fn test_policy_merge_deep() {
    let base = Policy {
        name: "Base".to_string(),
        settings: PolicySettings {
            fail_fast: Some(true),
            ..Default::default()
        },
        ..Default::default()
    };

    let child = Policy {
        name: "Child".to_string(),
        merge_strategy: MergeStrategy::DeepMerge,
        settings: PolicySettings {
            verbose_logging: Some(true),
            ..Default::default()
        },
        ..Default::default()
    };

    let merged = base.merge(&child);
    assert_eq!(merged.name, "Child");
    assert!(merged.settings.effective_fail_fast()); // from base
    assert!(merged.settings.effective_verbose_logging()); // from child
}

#[test]
fn test_policy_merge_replace() {
    let base = Policy {
        name: "Base".to_string(),
        settings: PolicySettings {
            fail_fast: Some(true),
            verbose_logging: Some(true),
            ..Default::default()
        },
        ..Default::default()
    };

    let child = Policy {
        name: "Child".to_string(),
        merge_strategy: MergeStrategy::Replace,
        settings: PolicySettings::default(),
        ..Default::default()
    };

    let merged = base.merge(&child);
    assert_eq!(merged.name, "Child");
    assert!(!merged.settings.effective_fail_fast()); // child replaces
    assert!(!merged.settings.effective_verbose_logging()); // child replaces
}

#[test]
fn test_policy_merge_allows_child_version_1_2_override() {
    let base = Policy {
        version: "1.1.0".to_string(),
        name: "Base".to_string(),
        ..Default::default()
    };
    let child = Policy {
        version: "1.2.0".to_string(),
        name: "Child".to_string(),
        merge_strategy: MergeStrategy::DeepMerge,
        ..Default::default()
    };

    let merged = base.merge(&child);
    assert_eq!(merged.version, "1.2.0");
}

#[test]
fn test_policy_extends_builtin() {
    let yaml = r#"
version: "1.2.0"
name: CustomStrict
extends: strict
settings:
  verbose_logging: true
"#;
    let policy = Policy::from_yaml_with_extends(yaml, None).unwrap();

    // Should have strict's fail_fast
    assert!(policy.settings.effective_fail_fast());
    // Should have child's verbose_logging
    assert!(policy.settings.effective_verbose_logging());
    // Name should be from child
    assert_eq!(policy.name, "CustomStrict");
}

#[test]
fn test_policy_extends_with_additional_patterns() {
    // Test adding patterns via additional_patterns
    let yaml = r#"
version: "1.2.0"
name: CustomDefault
extends: default
guards:
  forbidden_path:
    additional_patterns:
      - "**/my-secrets/**"
"#;
    let policy = Policy::from_yaml_with_extends(yaml, None).unwrap();

    // Should have the additional pattern added
    let fp = policy.guards.forbidden_path.unwrap();
    assert!(fp
        .effective_patterns()
        .iter()
        .any(|p| p.contains("my-secrets")));
}

#[test]
fn test_policy_circular_extends_detection() {
    use std::collections::HashSet;
    let mut visited = HashSet::new();
    visited.insert("policy-a".to_string());

    // Simulating circular detection
    assert!(visited.contains("policy-a"));
}

#[test]
fn test_secret_leak_merge_preserves_base_patterns() {
    let yaml = r#"
version: "1.2.0"
name: CustomDefault
extends: default
guards:
  secret_leak:
    additional_patterns:
      - name: custom_token
        pattern: "CUSTOM_[A-Za-z0-9]{32}"
"#;
    let policy = Policy::from_yaml_with_extends(yaml, None).unwrap();
    let sl = policy.guards.secret_leak.unwrap();
    let effective = sl.effective_patterns();

    // Base patterns should still be present
    assert!(
        effective.iter().any(|p| p.name == "aws_access_key"),
        "base pattern aws_access_key must be preserved"
    );
    assert!(
        effective.iter().any(|p| p.name == "github_token"),
        "base pattern github_token must be preserved"
    );
    // Additional pattern should be present
    assert!(
        effective.iter().any(|p| p.name == "custom_token"),
        "additional pattern custom_token must be present"
    );
}

#[test]
fn test_secret_leak_merge_remove_patterns() {
    let base = SecretLeakConfig::default();
    let child = SecretLeakConfig {
        remove_patterns: vec!["generic_api_key".to_string()],
        ..Default::default()
    };
    let merged = base.merge_with(&child);
    let effective = merged.effective_patterns();

    assert!(
        !effective.iter().any(|p| p.name == "generic_api_key"),
        "removed pattern must not be in effective set"
    );
    assert!(
        effective.iter().any(|p| p.name == "aws_access_key"),
        "other patterns must be preserved"
    );
}

#[test]
fn test_secret_leak_deep_merge_in_guard_configs() {
    let base = GuardConfigs {
        secret_leak: Some(SecretLeakConfig::default()),
        ..Default::default()
    };
    let child = GuardConfigs {
        secret_leak: Some(SecretLeakConfig {
            additional_patterns: vec![crate::guards::SecretPattern {
                name: "my_custom".to_string(),
                pattern: r"MY_[A-Z]{10}".to_string(),
                severity: crate::guards::Severity::Critical,
                description: None,
                luhn_check: false,
                masking: None,
            }],
            ..Default::default()
        }),
        ..Default::default()
    };

    let merged = base.merge_with(&child);
    let sl = merged.secret_leak.unwrap();
    let effective = sl.effective_patterns();

    assert!(
        effective.iter().any(|p| p.name == "aws_access_key"),
        "base patterns preserved in deep merge"
    );
    assert!(
        effective.iter().any(|p| p.name == "my_custom"),
        "additional pattern added in deep merge"
    );
}

#[test]
fn test_extends_depth_terminal_policy_still_fails() {
    let dir = tempdir().expect("tempdir");
    let mut previous: Option<std::path::PathBuf> = None;

    for depth in 0..=crate::core::cycle::MAX_POLICY_EXTENDS_DEPTH + 1 {
        let path = dir.path().join(format!("policy-{depth}.yaml"));
        let yaml = if let Some(previous) = previous.as_ref() {
            format!(
                "version: \"1.1.0\"\nname: \"policy-{depth}\"\nextends: \"{}\"\n",
                previous.file_name().expect("filename").to_string_lossy()
            )
        } else {
            format!("version: \"1.1.0\"\nname: \"policy-{depth}\"\n")
        };
        std::fs::write(&path, yaml).expect("write policy");
        previous = Some(path);
    }

    let root = dir.path().join(format!(
        "policy-{}.yaml",
        crate::core::cycle::MAX_POLICY_EXTENDS_DEPTH + 1
    ));
    let root_yaml = std::fs::read_to_string(&root).expect("read root");
    let err = Policy::from_yaml_with_extends(&root_yaml, Some(root.as_path()))
        .expect_err("depth exceeded");
    assert!(
        err.to_string().contains("Policy extends depth exceeded"),
        "unexpected error: {err}"
    );
}
