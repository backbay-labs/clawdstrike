//! Origins schema parse, version-gating, and merge tests.

use super::*;

#[test]
fn test_origins_yaml_parse_roundtrip() {
    let yaml = r#"
version: "1.4.0"
name: OriginTest
posture:
  initial: standard
  states:
    standard:
      description: Standard posture
    restricted:
      description: Restricted posture
origins:
  default_behavior: deny
  profiles:
    - id: slack-internal
      match_rules:
        provider: slack
        space_type: channel
        visibility: internal
        tags:
          - hipaa
        provenance_confidence: strong
      posture: restricted
      mcp:
        enabled: true
        allow:
          - "read_*"
      egress:
        enabled: true
        allow:
          - "*.internal.corp"
      data:
        allow_external_sharing: false
        redact_before_send: true
        block_sensitive_outputs: true
      budgets:
        mcp_tool_calls: 100
        egress_calls: 50
        shell_commands: 10
      bridge_policy:
        allow_cross_origin: true
        require_approval: true
        allowed_targets:
          - provider: github
            space_type: issue
            tags:
              - engineering
            visibility: internal
      explanation: "Internal Slack channels with HIPAA data"
"#;

    let policy = Policy::from_yaml(yaml).expect("v1.4.0 origins policy should parse");
    assert_eq!(policy.version, "1.4.0");

    let origins = policy.origins.as_ref().expect("origins must be present");
    assert_eq!(origins.default_behavior, Some(OriginDefaultBehavior::Deny));
    assert_eq!(origins.profiles.len(), 1);

    let profile = &origins.profiles[0];
    assert_eq!(profile.id, "slack-internal");
    assert_eq!(profile.match_rules.provider, Some(OriginProvider::Slack));
    assert_eq!(profile.match_rules.space_type, Some(SpaceType::Channel));
    assert_eq!(profile.match_rules.visibility, Some(Visibility::Internal));
    assert_eq!(profile.match_rules.tags, vec!["hipaa"]);
    assert_eq!(
        profile.match_rules.provenance_confidence,
        Some(ProvenanceConfidence::Strong)
    );
    assert_eq!(profile.posture.as_deref(), Some("restricted"));
    assert!(profile.mcp.is_some());
    assert!(profile.egress.is_some());

    let data = profile.data.as_ref().expect("data policy");
    assert!(!data.allow_external_sharing);
    assert!(data.redact_before_send);
    assert!(data.block_sensitive_outputs);

    let budgets = profile.budgets.as_ref().expect("budgets");
    assert_eq!(budgets.mcp_tool_calls, Some(100));
    assert_eq!(budgets.egress_calls, Some(50));
    assert_eq!(budgets.shell_commands, Some(10));

    let bridge = profile.bridge_policy.as_ref().expect("bridge_policy");
    assert!(bridge.allow_cross_origin);
    assert!(bridge.require_approval);
    assert_eq!(bridge.allowed_targets.len(), 1);
    assert_eq!(
        bridge.allowed_targets[0].provider,
        Some(OriginProvider::GitHub)
    );
    assert_eq!(bridge.allowed_targets[0].space_type, Some(SpaceType::Issue));

    assert_eq!(
        profile.explanation.as_deref(),
        Some("Internal Slack channels with HIPAA data")
    );

    // Roundtrip through YAML serialization
    let yaml_out = policy.to_yaml().expect("to_yaml");
    let restored = Policy::from_yaml(&yaml_out).expect("roundtrip parse");
    let restored_origins = restored.origins.expect("restored origins");
    assert_eq!(restored_origins.profiles.len(), 1);
    assert_eq!(restored_origins.profiles[0].id, "slack-internal");
}

#[test]
fn test_origins_version_gating_rejects_1_3() {
    let yaml = r#"
version: "1.3.0"
name: OriginVersionGated
origins:
  default_behavior: deny
  profiles:
    - id: test
      match_rules:
        provider: slack
"#;

    let err = Policy::from_yaml(yaml).unwrap_err();
    match err {
        Error::PolicyValidation(e) => {
            assert!(
                e.errors.iter().any(|fe| fe.path == "origins"
                    && fe
                        .message
                        .contains("origins block requires schema version >= 1.4.0")),
                "expected origins version gating error, got: {:?}",
                e.errors
            );
        }
        other => panic!("expected policy validation error, got: {}", other),
    }
}

#[test]
fn test_origins_backward_compat_v1_3_without_origins() {
    let yaml = r#"
version: "1.3.0"
name: NoOrigins
"#;
    let policy = Policy::from_yaml(yaml).unwrap();
    assert!(
        policy.origins.is_none(),
        "v1.3.0 policy without origins should load fine"
    );
}

#[test]
fn test_origins_backward_compat_v1_1_without_origins() {
    let yaml = r#"
version: "1.1.0"
name: LegacyPolicy
"#;
    let policy = Policy::from_yaml(yaml).unwrap();
    assert!(policy.origins.is_none());
}

#[test]
fn test_origins_merge_deep_child_overrides_profile_by_id() {
    let base = Policy {
        version: "1.4.0".to_string(),
        name: "Base".to_string(),
        origins: Some(OriginsConfig {
            default_behavior: Some(OriginDefaultBehavior::Deny),
            profiles: vec![
                OriginProfile {
                    id: "slack-internal".to_string(),
                    match_rules: OriginMatch {
                        provider: Some(OriginProvider::Slack),
                        ..Default::default()
                    },
                    posture: Some("base-posture".to_string()),
                    mcp: None,
                    egress: None,
                    data: None,
                    budgets: None,
                    bridge_policy: None,
                    explanation: Some("base explanation".to_string()),
                },
                OriginProfile {
                    id: "github-ci".to_string(),
                    match_rules: OriginMatch {
                        provider: Some(OriginProvider::GitHub),
                        ..Default::default()
                    },
                    posture: None,
                    mcp: None,
                    egress: None,
                    data: None,
                    budgets: None,
                    bridge_policy: None,
                    explanation: Some("base github ci".to_string()),
                },
            ],
        }),
        ..Default::default()
    };

    let child = Policy {
        version: "1.4.0".to_string(),
        name: "Child".to_string(),
        merge_strategy: MergeStrategy::DeepMerge,
        origins: Some(OriginsConfig {
            default_behavior: Some(OriginDefaultBehavior::MinimalProfile),
            profiles: vec![OriginProfile {
                id: "slack-internal".to_string(),
                match_rules: OriginMatch {
                    provider: Some(OriginProvider::Slack),
                    visibility: Some(Visibility::Private),
                    ..Default::default()
                },
                posture: Some("child-posture".to_string()),
                mcp: None,
                egress: None,
                data: None,
                budgets: None,
                bridge_policy: None,
                explanation: Some("child explanation".to_string()),
            }],
        }),
        ..Default::default()
    };

    let merged = base.merge(&child);
    let origins = merged.origins.expect("merged origins");

    // Child's default_behavior wins
    assert_eq!(
        origins.default_behavior,
        Some(OriginDefaultBehavior::MinimalProfile)
    );

    // Should have 2 profiles: slack-internal overridden, github-ci preserved
    assert_eq!(origins.profiles.len(), 2);

    let slack = origins
        .profiles
        .iter()
        .find(|p| p.id == "slack-internal")
        .expect("slack-internal profile");
    assert_eq!(
        slack.posture.as_deref(),
        Some("child-posture"),
        "child profile should override base"
    );
    assert_eq!(slack.explanation.as_deref(), Some("child explanation"),);
    assert_eq!(
        slack.match_rules.visibility,
        Some(Visibility::Private),
        "child match_rules should be used"
    );

    let github = origins
        .profiles
        .iter()
        .find(|p| p.id == "github-ci")
        .expect("github-ci profile");
    assert_eq!(
        github.explanation.as_deref(),
        Some("base github ci"),
        "unmatched base profile should be preserved"
    );
}

#[test]
fn test_origins_reject_unknown_fields_in_origin_profile() {
    let yaml = r#"
version: "1.4.0"
name: BadProfile
origins:
  default_behavior: deny
  profiles:
    - id: test
      match_rules:
        provider: slack
      unknown_field: "boom"
"#;

    let err = Policy::from_yaml(yaml).unwrap_err();
    let err_msg = err.to_string();
    assert!(
        err_msg.contains("unknown field"),
        "expected 'unknown field' in error, got: {err_msg}"
    );
}

#[test]
fn test_origins_reject_duplicate_profile_ids() {
    let yaml = r#"
version: "1.4.0"
name: DuplicateIds
origins:
  default_behavior: deny
  profiles:
    - id: same-id
      match_rules:
        provider: slack
    - id: same-id
      match_rules:
        provider: github
"#;

    let err = Policy::from_yaml(yaml).unwrap_err();
    match err {
        Error::PolicyValidation(e) => {
            assert!(
                e.errors.iter().any(|fe| fe.path == "origins.profiles"
                    && fe.message.contains("duplicate origin profile id: same-id")),
                "expected duplicate profile id error, got: {:?}",
                e.errors
            );
        }
        other => panic!("expected policy validation error, got: {}", other),
    }
}

#[test]
fn test_origins_default_behavior_minimal_profile() {
    let yaml = r#"
version: "1.4.0"
name: MinimalProfileDefault
origins:
  default_behavior: minimal_profile
  profiles: []
"#;
    let policy = Policy::from_yaml(yaml).unwrap();
    let origins = policy.origins.expect("origins");
    assert_eq!(
        origins.default_behavior,
        Some(OriginDefaultBehavior::MinimalProfile)
    );
}

#[test]
fn test_origins_merge_child_appends_new_profile() {
    let base = Policy {
        version: "1.4.0".to_string(),
        origins: Some(OriginsConfig {
            default_behavior: Some(OriginDefaultBehavior::Deny),
            profiles: vec![OriginProfile {
                id: "existing".to_string(),
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

    let child = Policy {
        version: "1.4.0".to_string(),
        merge_strategy: MergeStrategy::DeepMerge,
        origins: Some(OriginsConfig {
            default_behavior: Some(OriginDefaultBehavior::Deny),
            profiles: vec![OriginProfile {
                id: "new-profile".to_string(),
                match_rules: OriginMatch {
                    provider: Some(OriginProvider::Teams),
                    ..Default::default()
                },
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

    let merged = base.merge(&child);
    let origins = merged.origins.expect("merged origins");
    assert_eq!(origins.profiles.len(), 2);
    assert!(origins.profiles.iter().any(|p| p.id == "existing"));
    assert!(origins.profiles.iter().any(|p| p.id == "new-profile"));
}
