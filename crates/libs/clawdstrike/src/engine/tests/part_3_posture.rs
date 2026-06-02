//! Origin enclave + posture integration tests (part 3).
#![allow(clippy::expect_used, clippy::unwrap_used)]

use super::*;

// -----------------------------------------------------------------------
// Origin Enclave + Posture Integration Tests (Phase 1.3)
// -----------------------------------------------------------------------

#[tokio::test]
async fn test_enclave_sets_initial_posture() {
    // Policy has initial="standard", enclave specifies posture="elevated".
    // First check should run with elevated posture and elevated budgets.
    let posture_yaml = r#"
version: "1.2.0"
name: "enclave-posture"
posture:
  initial: standard
  states:
    standard:
      capabilities: [file_access]
      budgets:
        file_writes: 5
    elevated:
      capabilities: [file_access, file_write, egress]
      budgets:
        file_writes: 100
        egress_calls: 50
"#;

    let origins = OriginsConfig {
        default_behavior: Some(OriginDefaultBehavior::MinimalProfile),
        profiles: vec![slack_profile_with_posture("slack-elevated", "elevated")],
    };
    let policy = policy_with_posture_and_origins(posture_yaml, origins);
    let engine = HushEngine::with_policy(policy);

    let context = GuardContext::new().with_origin(test_slack_origin());
    let mut posture = None;

    let report = engine
        .check_action_report_with_posture(
            &GuardAction::FileAccess("/app/src/main.rs"),
            &context,
            &mut posture,
        )
        .await
        .unwrap();

    // Enclave should have overridden the initial posture to "elevated".
    assert!(report.guard_report.overall.allowed);
    assert_eq!(report.posture_before, "elevated");
    assert_eq!(report.posture_after, "elevated");

    // Budgets should reflect the elevated state.
    let state = posture.as_ref().unwrap();
    assert_eq!(state.current_state, "elevated");
    assert_eq!(state.budgets.get("file_writes").map(|b| b.limit), Some(100));
    assert_eq!(state.budgets.get("egress_calls").map(|b| b.limit), Some(50));
}

#[tokio::test]
async fn test_enclave_posture_does_not_override_mid_session() {
    // After a transition has occurred (transition_history not empty),
    // enclave posture is ignored.
    let posture_yaml = r#"
version: "1.2.0"
name: "enclave-posture-mid-session"
posture:
  initial: standard
  states:
    standard:
      capabilities: [file_access, egress]
      budgets: {}
    elevated:
      capabilities: [file_access, file_write, egress]
      budgets: {}
    quarantine:
      capabilities: []
      budgets: {}
  transitions:
    - { from: "*", to: quarantine, on: any_violation }
"#;

    let origins = OriginsConfig {
        default_behavior: Some(OriginDefaultBehavior::MinimalProfile),
        profiles: vec![slack_profile_with_posture("slack-elevated", "elevated")],
    };
    let policy = policy_with_posture_and_origins(posture_yaml, origins);
    let engine = HushEngine::with_policy(policy);

    let context = GuardContext::new().with_origin(test_slack_origin());

    // Pre-populate posture state with a non-empty transition history,
    // simulating a session that has already transitioned.
    let mut posture = Some(PostureRuntimeState {
        current_state: "quarantine".to_string(),
        entered_at: chrono::Utc::now().to_rfc3339(),
        transition_history: vec![PostureTransitionRecord {
            from: "standard".to_string(),
            to: "quarantine".to_string(),
            trigger: "any_violation".to_string(),
            at: chrono::Utc::now().to_rfc3339(),
        }],
        budgets: HashMap::new(),
        origin_runtime: None,
    });

    let report = engine
        .check_action_report_with_posture(
            &GuardAction::FileAccess("/app/src/main.rs"),
            &context,
            &mut posture,
        )
        .await
        .unwrap();

    // Posture should remain quarantine — enclave must not override mid-session.
    assert_eq!(report.posture_before, "quarantine");
    let state = posture.as_ref().unwrap();
    assert_eq!(state.current_state, "quarantine");
}

#[tokio::test]
async fn test_posture_path_uses_pre_resolved_enclave() {
    let posture_yaml = r#"
version: "1.2.0"
name: "enclave-pre-resolved"
posture:
  initial: standard
  states:
    standard:
      capabilities: [file_access]
      budgets: {}
    elevated:
      capabilities: [file_access, file_write]
      budgets: {}
"#;

    let origins = OriginsConfig {
        default_behavior: Some(OriginDefaultBehavior::Deny),
        profiles: vec![slack_profile_with_posture("slack-elevated", "elevated")],
    };
    let policy = policy_with_posture_and_origins(posture_yaml, origins);
    let engine = HushEngine::with_policy(policy);

    let context = GuardContext::new()
        .with_origin(test_github_origin())
        .with_enclave(manual_enclave("manual-pre-resolved", Some("elevated")));
    let mut posture = None;

    let report = engine
        .check_action_report_with_posture(
            &GuardAction::FileAccess("/app/src/main.rs"),
            &context,
            &mut posture,
        )
        .await
        .unwrap();

    assert!(report.guard_report.overall.allowed);
    assert_eq!(report.posture_before, "elevated");
    assert_eq!(report.posture_after, "elevated");
    assert_eq!(
        posture.as_ref().map(|state| state.current_state.as_str()),
        Some("elevated")
    );
}

#[tokio::test]
async fn test_enclave_references_nonexistent_posture_state() {
    // Enclave specifies posture="nonexistent" which doesn't exist in the program.
    // Should return an error (fail-closed).
    let posture_yaml = r#"
version: "1.2.0"
name: "enclave-posture-bad-state"
posture:
  initial: standard
  states:
    standard:
      capabilities: [file_access]
      budgets: {}
"#;

    let origins = OriginsConfig {
        default_behavior: Some(OriginDefaultBehavior::MinimalProfile),
        profiles: vec![slack_profile_with_posture("slack-bad", "nonexistent")],
    };
    let policy = policy_with_posture_and_origins(posture_yaml, origins);
    let engine = HushEngine::with_policy(policy);

    let context = GuardContext::new().with_origin(test_slack_origin());
    let mut posture = None;

    let err = engine
        .check_action_report_with_posture(
            &GuardAction::FileAccess("/app/src/main.rs"),
            &context,
            &mut posture,
        )
        .await
        .unwrap_err();

    let msg = err.to_string();
    assert!(
        msg.contains("unknown posture state 'nonexistent'"),
        "unexpected error: {msg}"
    );
}

#[tokio::test]
async fn test_no_enclave_posture_normal_flow() {
    // Enclave resolved but has no posture field — posture uses policy default.
    let posture_yaml = r#"
version: "1.2.0"
name: "enclave-posture-no-override"
posture:
  initial: standard
  states:
    standard:
      capabilities: [file_access]
      budgets:
        file_writes: 10
"#;

    // Profile matches Slack but has NO posture field.
    let profile = OriginProfile {
        id: "slack-no-posture".to_string(),
        match_rules: OriginMatch {
            provider: Some(OriginProvider::Slack),
            ..Default::default()
        },
        posture: None,
        mcp: None,
        egress: None,
        data: None,
        budgets: None,
        bridge_policy: None,
        explanation: None,
    };

    let origins = OriginsConfig {
        default_behavior: Some(OriginDefaultBehavior::MinimalProfile),
        profiles: vec![profile],
    };
    let policy = policy_with_posture_and_origins(posture_yaml, origins);
    let engine = HushEngine::with_policy(policy);

    let context = GuardContext::new().with_origin(test_slack_origin());
    let mut posture = None;

    let report = engine
        .check_action_report_with_posture(
            &GuardAction::FileAccess("/app/src/main.rs"),
            &context,
            &mut posture,
        )
        .await
        .unwrap();

    // Should use the policy's default initial posture "standard".
    assert!(report.guard_report.overall.allowed);
    assert_eq!(report.posture_before, "standard");
    assert_eq!(report.posture_after, "standard");

    let state = posture.as_ref().unwrap();
    assert_eq!(state.current_state, "standard");
    assert_eq!(state.budgets.get("file_writes").map(|b| b.limit), Some(10));
}
