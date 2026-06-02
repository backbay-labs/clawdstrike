//! Cross-origin isolation tests (part 4).
#![allow(clippy::expect_used, clippy::unwrap_used)]

use super::*;

// -----------------------------------------------------------------------
// Cross-Origin Isolation Tests (Phase 1b)
// -----------------------------------------------------------------------

#[tokio::test]
async fn test_cross_origin_same_origin_passes() {
    // Two checks from the same origin (same provider + same space_id)
    // should both succeed without any cross-origin denial.
    let origins = OriginsConfig {
        default_behavior: Some(OriginDefaultBehavior::Deny),
        profiles: vec![slack_profile_with_bridge("slack-base", None)],
    };
    let policy = policy_with_origins(origins);
    let engine = HushEngine::with_policy(policy);

    let context = GuardContext::new().with_origin(test_slack_origin());
    let mut origin_state = None;

    // First check establishes session origin
    let report = check_with_origin_runtime(&engine, &context, &mut origin_state).await;
    assert!(report.overall.allowed);

    // Second check with same origin should pass
    let report = check_with_origin_runtime(&engine, &context, &mut origin_state).await;
    assert!(report.overall.allowed);
}

#[tokio::test]
async fn test_origin_runtime_is_ignored_without_origins_policy() {
    let mut policy = Policy::new();
    policy.version = "1.4.0".to_string();
    policy.name = "origin-runtime-opt-in".to_string();
    let engine = HushEngine::with_policy(policy);
    let mut origin_state = None;

    let slack_ctx = GuardContext::new()
        .with_origin(test_slack_origin())
        .with_enclave(manual_enclave("manual-slack", None));
    let slack_report = check_with_origin_runtime(&engine, &slack_ctx, &mut origin_state).await;
    assert!(slack_report.overall.allowed);
    assert!(origin_state.is_none());

    let github_ctx = GuardContext::new()
        .with_origin(test_github_origin())
        .with_enclave(manual_enclave("manual-github", None));
    let github_report = check_with_origin_runtime(&engine, &github_ctx, &mut origin_state).await;
    assert!(github_report.overall.allowed);
    assert!(origin_state.is_none());
}

#[tokio::test]
async fn test_cross_origin_different_origin_no_bridge_denied() {
    // First check from Slack, second from GitHub, no bridge policy -> denied
    let origins = OriginsConfig {
        default_behavior: Some(OriginDefaultBehavior::Deny),
        profiles: vec![
            slack_profile_with_bridge("slack-no-bridge", None),
            github_profile(),
        ],
    };
    let policy = policy_with_origins(origins);
    let engine = HushEngine::with_policy(policy);
    let mut origin_state = None;

    // First check from Slack establishes session origin
    let slack_ctx = GuardContext::new().with_origin(test_slack_origin());
    let report = check_with_origin_runtime(&engine, &slack_ctx, &mut origin_state).await;
    assert!(report.overall.allowed);

    // Second check from GitHub: cross-origin, no bridge policy -> denied
    let github_ctx = GuardContext::new().with_origin(test_github_origin());
    let report = check_with_origin_runtime(&engine, &github_ctx, &mut origin_state).await;
    assert!(!report.overall.allowed);
    assert_eq!(report.overall.guard, "cross_origin");
    assert_eq!(report.overall.severity, Severity::Error);
    assert!(report
        .overall
        .message
        .contains("no bridge policy configured"));
}

#[tokio::test]
async fn test_cross_origin_bridge_allowed() {
    // Bridge policy allows cross-origin to GitHub -> second check passes
    let bridge = BridgePolicy {
        allow_cross_origin: true,
        allowed_targets: vec![BridgeTarget {
            provider: Some(OriginProvider::GitHub),
            space_type: None,
            tags: vec![],
            visibility: None,
        }],
        require_approval: false,
    };
    let origins = OriginsConfig {
        default_behavior: Some(OriginDefaultBehavior::Deny),
        profiles: vec![
            slack_profile_with_bridge("slack-bridged", Some(bridge)),
            github_profile(),
        ],
    };
    let policy = policy_with_origins(origins);
    let engine = HushEngine::with_policy(policy);
    let mut origin_state = None;

    // First check from Slack establishes session origin
    let slack_ctx = GuardContext::new().with_origin(test_slack_origin());
    let report = check_with_origin_runtime(&engine, &slack_ctx, &mut origin_state).await;
    assert!(report.overall.allowed);

    // Second check from GitHub: bridge allows it
    let github_ctx = GuardContext::new().with_origin(test_github_origin());
    let report = check_with_origin_runtime(&engine, &github_ctx, &mut origin_state).await;
    assert!(report.overall.allowed);
}

#[tokio::test]
async fn test_cross_origin_bridge_reinitializes_budgets_from_target_enclave() {
    let bridge = BridgePolicy {
        allow_cross_origin: true,
        allowed_targets: vec![BridgeTarget {
            provider: Some(OriginProvider::GitHub),
            space_type: None,
            tags: vec![],
            visibility: None,
        }],
        require_approval: false,
    };
    let origins = OriginsConfig {
        default_behavior: Some(OriginDefaultBehavior::Deny),
        profiles: vec![
            OriginProfile {
                id: "slack-source".to_string(),
                match_rules: OriginMatch {
                    provider: Some(OriginProvider::Slack),
                    ..Default::default()
                },
                mcp: None,
                posture: None,
                egress: None,
                data: None,
                budgets: Some(crate::policy::OriginBudgets {
                    mcp_tool_calls: Some(5),
                    ..Default::default()
                }),
                bridge_policy: Some(bridge),
                explanation: None,
            },
            OriginProfile {
                id: "github-target".to_string(),
                match_rules: OriginMatch {
                    provider: Some(OriginProvider::GitHub),
                    ..Default::default()
                },
                mcp: None,
                posture: None,
                egress: None,
                data: None,
                budgets: Some(crate::policy::OriginBudgets {
                    mcp_tool_calls: Some(1),
                    ..Default::default()
                }),
                bridge_policy: None,
                explanation: None,
            },
        ],
    };
    let engine = HushEngine::with_policy(policy_with_origins(origins));
    let args = serde_json::json!({});
    let mut posture_state = None;
    let mut origin_state = None;

    let slack_ctx = GuardContext::new().with_origin(test_slack_origin());
    let slack = engine
        .check_action_report_with_runtime(
            &GuardAction::McpTool("safe_tool", &args),
            &slack_ctx,
            &mut posture_state,
            &mut origin_state,
        )
        .await
        .unwrap();
    assert!(slack.guard_report.overall.allowed);
    assert_eq!(
        origin_state
            .as_ref()
            .and_then(|state| state.budgets.get("mcp_tool_calls"))
            .map(|counter| counter.limit),
        Some(5)
    );

    let github_ctx = GuardContext::new().with_origin(test_github_origin());
    let github = engine
        .check_action_report_with_runtime(
            &GuardAction::McpTool("safe_tool", &args),
            &github_ctx,
            &mut posture_state,
            &mut origin_state,
        )
        .await
        .unwrap();
    assert!(github.guard_report.overall.allowed);
    assert_eq!(
        origin_state
            .as_ref()
            .and_then(|state| state.current_enclave.profile_id.as_deref()),
        Some("github-target")
    );
    assert_eq!(
        origin_state
            .as_ref()
            .and_then(|state| state.budgets.get("mcp_tool_calls"))
            .map(|counter| counter.limit),
        Some(1)
    );
}

#[tokio::test]
async fn test_posture_wrapper_persists_origin_runtime_between_calls() {
    let posture_yaml = r#"
version: "1.2.0"
name: "posture-origin-wrapper"
guards:
  mcp_tool:
    allow: [safe_tool]
    block: []
    require_confirmation: []
    default_action: block
posture:
  initial: standard
  states:
    standard:
      capabilities: [mcp_tool]
"#;
    let origins = OriginsConfig {
        default_behavior: Some(OriginDefaultBehavior::Deny),
        profiles: vec![OriginProfile {
            id: "slack-budgeted".to_string(),
            match_rules: OriginMatch {
                provider: Some(OriginProvider::Slack),
                ..Default::default()
            },
            mcp: None,
            posture: None,
            egress: None,
            data: None,
            budgets: Some(crate::policy::OriginBudgets {
                mcp_tool_calls: Some(1),
                ..Default::default()
            }),
            bridge_policy: None,
            explanation: None,
        }],
    };
    let engine = HushEngine::with_policy(policy_with_posture_and_origins(posture_yaml, origins));
    let args = serde_json::json!({});
    let context = GuardContext::new().with_origin(test_slack_origin());
    let mut posture = None;

    let first = engine
        .check_action_report_with_posture(
            &GuardAction::McpTool("safe_tool", &args),
            &context,
            &mut posture,
        )
        .await
        .unwrap();
    assert!(first.guard_report.overall.allowed);
    assert!(posture
        .as_ref()
        .and_then(|state| state.origin_runtime.as_ref())
        .is_some());

    let second = engine
        .check_action_report_with_posture(
            &GuardAction::McpTool("safe_tool", &args),
            &context,
            &mut posture,
        )
        .await
        .unwrap();
    assert!(!second.guard_report.overall.allowed);
    assert_eq!(second.guard_report.overall.guard, "origin_budget");
    assert!(second.guard_report.overall.message.contains("exhausted"));
}

#[tokio::test]
async fn test_posture_wrapper_persists_origin_runtime_without_posture_program() {
    let engine = HushEngine::with_policy(policy_with_origins(OriginsConfig {
        default_behavior: Some(OriginDefaultBehavior::Deny),
        profiles: vec![OriginProfile {
            id: "slack-budgeted".to_string(),
            match_rules: OriginMatch {
                provider: Some(OriginProvider::Slack),
                ..Default::default()
            },
            mcp: None,
            posture: None,
            egress: None,
            data: None,
            budgets: Some(crate::policy::OriginBudgets {
                mcp_tool_calls: Some(1),
                ..Default::default()
            }),
            bridge_policy: None,
            explanation: None,
        }],
    }));
    let args = serde_json::json!({});
    let context = GuardContext::new().with_origin(test_slack_origin());
    let mut posture = None;

    let first = engine
        .check_action_report_with_posture(
            &GuardAction::McpTool("safe_tool", &args),
            &context,
            &mut posture,
        )
        .await
        .unwrap();
    assert!(first.guard_report.overall.allowed);
    assert_eq!(
        posture.as_ref().map(|state| state.current_state.as_str()),
        Some("default")
    );
    assert!(posture
        .as_ref()
        .and_then(|state| state.origin_runtime.as_ref())
        .is_some());

    let second = engine
        .check_action_report_with_posture(
            &GuardAction::McpTool("safe_tool", &args),
            &context,
            &mut posture,
        )
        .await
        .unwrap();
    assert!(!second.guard_report.overall.allowed);
    assert_eq!(second.guard_report.overall.guard, "origin_budget");
    assert!(second.guard_report.overall.message.contains("exhausted"));
}

#[tokio::test]
async fn test_cross_origin_bridge_require_approval() {
    // Bridge policy requires approval -> denied with Warning severity
    let bridge = BridgePolicy {
        allow_cross_origin: true,
        allowed_targets: vec![], // empty = all targets allowed
        require_approval: true,
    };
    let origins = OriginsConfig {
        default_behavior: Some(OriginDefaultBehavior::Deny),
        profiles: vec![
            slack_profile_with_bridge("slack-approval", Some(bridge)),
            github_profile(),
        ],
    };
    let policy = policy_with_origins(origins);
    let engine = HushEngine::with_policy(policy);
    let mut origin_state = None;

    // First check from Slack establishes session origin
    let slack_ctx = GuardContext::new().with_origin(test_slack_origin());
    let report = check_with_origin_runtime(&engine, &slack_ctx, &mut origin_state).await;
    assert!(report.overall.allowed);

    // Second check from GitHub: requires approval -> denied with Warning
    let github_ctx = GuardContext::new().with_origin(test_github_origin());
    let report = check_with_origin_runtime(&engine, &github_ctx, &mut origin_state).await;
    assert!(!report.overall.allowed);
    assert_eq!(report.overall.guard, "cross_origin");
    assert_eq!(report.overall.severity, Severity::Warning);
    assert!(report.overall.message.contains("requires approval"));
}

#[tokio::test]
async fn test_cross_origin_target_not_in_allowed_targets() {
    // Bridge allows cross-origin but only to GitHub; target is Teams -> denied
    let bridge = BridgePolicy {
        allow_cross_origin: true,
        allowed_targets: vec![BridgeTarget {
            provider: Some(OriginProvider::GitHub),
            space_type: None,
            tags: vec![],
            visibility: None,
        }],
        require_approval: false,
    };
    let origins = OriginsConfig {
        default_behavior: Some(OriginDefaultBehavior::Deny),
        profiles: vec![
            slack_profile_with_bridge("slack-github-only", Some(bridge)),
            github_profile(),
            teams_profile(),
        ],
    };
    let policy = policy_with_origins(origins);
    let engine = HushEngine::with_policy(policy);
    let mut origin_state = None;

    // First check from Slack establishes session origin
    let slack_ctx = GuardContext::new().with_origin(test_slack_origin());
    let report = check_with_origin_runtime(&engine, &slack_ctx, &mut origin_state).await;
    assert!(report.overall.allowed);

    // Second check from Teams: not in allowed targets -> denied
    let teams_ctx = GuardContext::new().with_origin(test_teams_origin());
    let report = check_with_origin_runtime(&engine, &teams_ctx, &mut origin_state).await;
    assert!(!report.overall.allowed);
    assert_eq!(report.overall.guard, "cross_origin");
    assert_eq!(report.overall.severity, Severity::Error);
    assert!(report
        .overall
        .message
        .contains("does not match any allowed bridge target"));
}

#[tokio::test]
async fn test_cross_origin_first_origin_establishes_session() {
    // First check sets session_origin; verify by checking that a different
    // origin is detected as cross-origin on the second check.
    let origins = OriginsConfig {
        default_behavior: Some(OriginDefaultBehavior::Deny),
        profiles: vec![
            slack_profile_with_bridge("slack-no-bridge", None),
            github_profile(),
        ],
    };
    let policy = policy_with_origins(origins);
    let engine = HushEngine::with_policy(policy);
    let mut origin_state = None;

    // First check from Slack establishes session origin
    let slack_ctx = GuardContext::new().with_origin(test_slack_origin());
    let report = check_with_origin_runtime(&engine, &slack_ctx, &mut origin_state).await;
    assert!(report.overall.allowed);

    // Verify session_origin was set: different origin triggers cross-origin detection
    let github_ctx = GuardContext::new().with_origin(test_github_origin());
    let report = check_with_origin_runtime(&engine, &github_ctx, &mut origin_state).await;
    assert!(!report.overall.allowed);
    assert_eq!(report.overall.guard, "cross_origin");
    // No bridge policy configured, so it should say so
    assert!(report
        .overall
        .message
        .contains("no bridge policy configured"));
}

#[tokio::test]
async fn test_cross_origin_disabled_bridge() {
    // Bridge policy exists but allow_cross_origin=false -> denied
    let bridge = BridgePolicy {
        allow_cross_origin: false,
        allowed_targets: vec![],
        require_approval: false,
    };
    let origins = OriginsConfig {
        default_behavior: Some(OriginDefaultBehavior::Deny),
        profiles: vec![
            slack_profile_with_bridge("slack-disabled-bridge", Some(bridge)),
            github_profile(),
        ],
    };
    let policy = policy_with_origins(origins);
    let engine = HushEngine::with_policy(policy);
    let mut origin_state = None;

    let slack_ctx = GuardContext::new().with_origin(test_slack_origin());
    let report = check_with_origin_runtime(&engine, &slack_ctx, &mut origin_state).await;
    assert!(report.overall.allowed);

    let github_ctx = GuardContext::new().with_origin(test_github_origin());
    let report = check_with_origin_runtime(&engine, &github_ctx, &mut origin_state).await;
    assert!(!report.overall.allowed);
    assert_eq!(report.overall.guard, "cross_origin");
    assert!(report
        .overall
        .message
        .contains("cross-origin transitions disabled"));
}

#[tokio::test]
async fn test_cross_origin_bridge_target_with_space_type_filter() {
    // Bridge allows cross-origin to GitHub issues only; target is PR -> denied
    let bridge = BridgePolicy {
        allow_cross_origin: true,
        allowed_targets: vec![BridgeTarget {
            provider: Some(OriginProvider::GitHub),
            space_type: Some(SpaceType::Issue),
            tags: vec![],
            visibility: None,
        }],
        require_approval: false,
    };
    let origins = OriginsConfig {
        default_behavior: Some(OriginDefaultBehavior::Deny),
        profiles: vec![
            slack_profile_with_bridge("slack-github-issues", Some(bridge)),
            github_profile(),
        ],
    };
    let policy = policy_with_origins(origins);
    let engine = HushEngine::with_policy(policy);
    let mut origin_state = None;

    let slack_ctx = GuardContext::new().with_origin(test_slack_origin());
    let report = check_with_origin_runtime(&engine, &slack_ctx, &mut origin_state).await;
    assert!(report.overall.allowed);

    // GitHub origin with space_type=PullRequest but bridge only allows Issue -> denied
    let github_ctx = GuardContext::new().with_origin(test_github_origin());
    let report = check_with_origin_runtime(&engine, &github_ctx, &mut origin_state).await;
    assert!(!report.overall.allowed);
    assert_eq!(report.overall.guard, "cross_origin");
    assert!(report
        .overall
        .message
        .contains("does not match any allowed bridge target"));
}

#[tokio::test]
async fn test_cross_origin_bridge_target_with_visibility_filter() {
    // Bridge allows cross-origin only to public GitHub spaces
    let bridge = BridgePolicy {
        allow_cross_origin: true,
        allowed_targets: vec![BridgeTarget {
            provider: Some(OriginProvider::GitHub),
            space_type: None,
            tags: vec![],
            visibility: Some(Visibility::Public),
        }],
        require_approval: false,
    };
    let origins = OriginsConfig {
        default_behavior: Some(OriginDefaultBehavior::Deny),
        profiles: vec![
            slack_profile_with_bridge("slack-public-github", Some(bridge)),
            github_profile(),
        ],
    };
    let policy = policy_with_origins(origins);
    let engine = HushEngine::with_policy(policy);
    let mut origin_state = None;

    let slack_ctx = GuardContext::new().with_origin(test_slack_origin());
    let report = check_with_origin_runtime(&engine, &slack_ctx, &mut origin_state).await;
    assert!(report.overall.allowed);

    // GitHub origin without visibility does not match Public filter -> denied
    let github_ctx = GuardContext::new().with_origin(test_github_origin());
    let report = check_with_origin_runtime(&engine, &github_ctx, &mut origin_state).await;
    assert!(!report.overall.allowed);
    assert_eq!(report.overall.guard, "cross_origin");

    // Now test with a public GitHub origin (new engine instance)
    let bridge2 = BridgePolicy {
        allow_cross_origin: true,
        allowed_targets: vec![BridgeTarget {
            provider: Some(OriginProvider::GitHub),
            space_type: None,
            tags: vec![],
            visibility: Some(Visibility::Public),
        }],
        require_approval: false,
    };
    let origins2 = OriginsConfig {
        default_behavior: Some(OriginDefaultBehavior::Deny),
        profiles: vec![
            slack_profile_with_bridge("slack-public-github", Some(bridge2)),
            github_profile(),
        ],
    };
    let engine2 = HushEngine::with_policy(policy_with_origins(origins2));
    let mut origin_state2 = None;

    let slack_ctx2 = GuardContext::new().with_origin(test_slack_origin());
    let _ = check_with_origin_runtime(&engine2, &slack_ctx2, &mut origin_state2).await;

    let public_github = OriginContext {
        provider: OriginProvider::GitHub,
        space_id: Some("repo-1".into()),
        visibility: Some(Visibility::Public),
        ..OriginContext::default()
    };
    let github_ctx2 = GuardContext::new().with_origin(public_github);
    let report = check_with_origin_runtime(&engine2, &github_ctx2, &mut origin_state2).await;
    assert!(report.overall.allowed);
}

#[tokio::test]
async fn test_cross_origin_same_space_trust_downgrade_denied_without_bridge() {
    let origins = OriginsConfig {
        default_behavior: Some(OriginDefaultBehavior::Deny),
        profiles: vec![
            OriginProfile {
                id: "slack-internal".to_string(),
                match_rules: OriginMatch {
                    provider: Some(OriginProvider::Slack),
                    external_participants: Some(false),
                    ..Default::default()
                },
                mcp: None,
                posture: None,
                egress: None,
                data: None,
                budgets: None,
                bridge_policy: None,
                explanation: None,
            },
            OriginProfile {
                id: "slack-external".to_string(),
                match_rules: OriginMatch {
                    provider: Some(OriginProvider::Slack),
                    external_participants: Some(true),
                    ..Default::default()
                },
                mcp: None,
                posture: None,
                egress: None,
                data: None,
                budgets: None,
                bridge_policy: None,
                explanation: None,
            },
        ],
    };
    let engine = HushEngine::with_policy(policy_with_origins(origins));
    let mut origin_state = None;

    let internal_origin = OriginContext {
        provider: OriginProvider::Slack,
        space_id: Some("C-test-123".into()),
        external_participants: Some(false),
        ..OriginContext::default()
    };
    let external_origin = OriginContext {
        provider: OriginProvider::Slack,
        space_id: Some("C-test-123".into()),
        external_participants: Some(true),
        ..OriginContext::default()
    };

    let internal_report = check_with_origin_runtime(
        &engine,
        &GuardContext::new().with_origin(internal_origin),
        &mut origin_state,
    )
    .await;
    assert!(internal_report.overall.allowed);

    let external_report = check_with_origin_runtime(
        &engine,
        &GuardContext::new().with_origin(external_origin),
        &mut origin_state,
    )
    .await;
    assert!(!external_report.overall.allowed);
    assert_eq!(external_report.overall.guard, "cross_origin");
    assert!(external_report
        .overall
        .message
        .contains("no bridge policy configured"));
}
