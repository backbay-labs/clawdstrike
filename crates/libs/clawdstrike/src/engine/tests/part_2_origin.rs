//! Origin enclave tests (part 2).
#![allow(clippy::expect_used, clippy::unwrap_used)]

use super::*;

// -----------------------------------------------------------------------
// Origin Enclave Tests (Phase 1.1)
// -----------------------------------------------------------------------

#[tokio::test]
async fn test_enclave_blocks_mcp_tool() {
    let mcp = crate::guards::McpToolConfig {
        enabled: true,
        block: vec!["dangerous_tool".to_string()],
        allow: vec![],
        require_confirmation: vec![],
        default_action: Some(McpDefaultAction::Allow),
        ..Default::default()
    };

    let origins = OriginsConfig {
        default_behavior: Some(OriginDefaultBehavior::Deny),
        profiles: vec![slack_profile_with_mcp("slack-restricted", mcp)],
    };
    let policy = policy_with_origins(origins);
    let engine = HushEngine::with_policy(policy);

    let context = GuardContext::new().with_origin(test_slack_origin());
    let args = serde_json::json!({});

    let report = engine
        .check_action_report(&GuardAction::McpTool("dangerous_tool", &args), &context)
        .await
        .unwrap();

    assert!(!report.overall.allowed);
    assert_eq!(report.overall.guard, "enclave");
    assert!(report
        .overall
        .message
        .contains("blocked by enclave profile"));
    assert!(report.overall.message.contains("slack-restricted"));
}

#[tokio::test]
async fn test_enclave_allows_mcp_tool_passes_to_guard_pipeline() {
    let mcp = crate::guards::McpToolConfig {
        enabled: true,
        block: vec!["other_tool".to_string()],
        allow: vec![],
        require_confirmation: vec![],
        default_action: Some(McpDefaultAction::Allow),
        ..Default::default()
    };

    let origins = OriginsConfig {
        default_behavior: Some(OriginDefaultBehavior::Deny),
        profiles: vec![slack_profile_with_mcp("slack-open", mcp)],
    };
    let policy = policy_with_origins(origins);
    let engine = HushEngine::with_policy(policy);

    let context = GuardContext::new().with_origin(test_slack_origin());
    let args = serde_json::json!({});

    // "safe_tool" is NOT in the enclave block list, and default_action=Allow
    // It should pass through the enclave check to the guard pipeline.
    let report = engine
        .check_action_report(&GuardAction::McpTool("safe_tool", &args), &context)
        .await
        .unwrap();

    // The guard pipeline (McpToolGuard) runs after the enclave allows the tool.
    assert!(report.overall.allowed);
    // Verify enclave is NOT the denying guard
    assert_ne!(report.overall.guard, "enclave");
}

#[tokio::test]
async fn test_policy_blocks_tool_even_if_enclave_allows() {
    // Enclave allows all tools
    let enclave_mcp = crate::guards::McpToolConfig {
        enabled: true,
        block: vec![],
        allow: vec![],
        require_confirmation: vec![],
        default_action: Some(McpDefaultAction::Allow),
        ..Default::default()
    };

    let origins = OriginsConfig {
        default_behavior: Some(OriginDefaultBehavior::Deny),
        profiles: vec![slack_profile_with_mcp("slack-permissive", enclave_mcp)],
    };

    // But the main policy blocks "shell_exec" by default
    let policy = policy_with_origins(origins);
    let engine = HushEngine::with_policy(policy);

    let context = GuardContext::new().with_origin(test_slack_origin());
    let args = serde_json::json!({});

    // "shell_exec" is in the default MCP block list for the policy
    let report = engine
        .check_action_report(&GuardAction::McpTool("shell_exec", &args), &context)
        .await
        .unwrap();

    // Policy guards should still block it even though enclave allows
    assert!(!report.overall.allowed);
    assert_eq!(report.overall.guard, "mcp_tool");
}

#[tokio::test]
async fn test_no_origin_normal_flow() {
    let engine = HushEngine::new();
    let context = GuardContext::new(); // No origin set

    let args = serde_json::json!({});
    let report = engine
        .check_action_report(&GuardAction::McpTool("safe_tool", &args), &context)
        .await
        .unwrap();

    // Normal flow: no enclave resolution, just the fail-closed guard pipeline.
    assert!(!report.overall.allowed);
    assert_eq!(report.overall.guard, "mcp_tool");
}

#[tokio::test]
async fn test_posture_origin_resolution_failure_returns_deny_report() {
    let policy = Policy::from_yaml(
        r#"
version: "1.4.0"
name: "posture-origin-resolution-failure"
posture:
  initial: work
  states:
    work:
      capabilities: [mcp_tool]
      budgets: {}
origins:
  default_behavior: deny
  profiles:
    - id: github-only
      match_rules:
        provider: github
"#,
    )
    .unwrap();

    let engine = HushEngine::with_policy(policy);
    let context = GuardContext::new().with_origin(test_slack_origin());
    let mut posture = None;
    let args = serde_json::json!({});

    let report = engine
        .check_action_report_with_posture(
            &GuardAction::McpTool("safe_tool", &args),
            &context,
            &mut posture,
        )
        .await
        .expect("resolution failure should return a deny report, not an error");

    assert!(!report.guard_report.overall.allowed);
    assert_eq!(report.guard_report.overall.guard, "enclave");
    assert!(report
        .guard_report
        .overall
        .message
        .contains("enclave resolution failed"));
}

#[tokio::test]
async fn test_origin_egress_profile_intersects_with_base_policy() {
    use hush_proxy::policy::PolicyAction;

    let mut policy = policy_with_origins(OriginsConfig {
        default_behavior: Some(OriginDefaultBehavior::Deny),
        profiles: vec![OriginProfile {
            id: "slack-egress".to_string(),
            match_rules: OriginMatch {
                provider: Some(OriginProvider::Slack),
                ..Default::default()
            },
            mcp: None,
            posture: None,
            egress: Some(crate::guards::EgressAllowlistConfig {
                enabled: true,
                allow: vec!["api.github.com".to_string()],
                block: vec![],
                default_action: Some(PolicyAction::Block),
                additional_allow: vec![],
                remove_allow: vec![],
                additional_block: vec![],
                remove_block: vec![],
            }),
            data: None,
            budgets: None,
            bridge_policy: None,
            explanation: None,
        }],
    });
    policy.guards.egress_allowlist = Some(crate::guards::EgressAllowlistConfig {
        enabled: true,
        allow: vec!["api.openai.com".to_string(), "api.github.com".to_string()],
        block: vec![],
        default_action: Some(PolicyAction::Block),
        additional_allow: vec![],
        remove_allow: vec![],
        additional_block: vec![],
        remove_block: vec![],
    });

    let engine = HushEngine::with_policy(policy);
    let context = GuardContext::new().with_origin(test_slack_origin());

    let allowed = engine
        .check_egress("api.github.com", 443, &context)
        .await
        .unwrap();
    assert!(allowed.allowed);

    let blocked = engine
        .check_egress("api.openai.com", 443, &context)
        .await
        .unwrap();
    assert!(!blocked.allowed);
    assert_eq!(blocked.guard, "egress_allowlist");
}

#[tokio::test]
async fn test_origin_output_send_blocks_external_sharing() {
    let policy = policy_with_origins(OriginsConfig {
        default_behavior: Some(OriginDefaultBehavior::Deny),
        profiles: vec![OriginProfile {
            id: "slack-data".to_string(),
            match_rules: OriginMatch {
                provider: Some(OriginProvider::Slack),
                ..Default::default()
            },
            mcp: None,
            posture: None,
            egress: None,
            data: Some(crate::policy::OriginDataPolicy {
                allow_external_sharing: false,
                redact_before_send: false,
                block_sensitive_outputs: false,
            }),
            budgets: None,
            bridge_policy: None,
            explanation: None,
        }],
    });
    let engine = HushEngine::with_policy(policy);
    let context = GuardContext::new().with_origin(OriginContext {
        provider: OriginProvider::Slack,
        space_id: Some("C-external".into()),
        visibility: Some(Visibility::ExternalShared),
        tags: vec!["provider:slack".to_string()],
        ..OriginContext::default()
    });
    let payload = serde_json::json!({
        "text": "share this status update",
        "target": "external-room"
    });

    let report = engine
        .check_action_report(
            &GuardAction::Custom("origin.output_send", &payload),
            &context,
        )
        .await
        .unwrap();

    assert!(!report.overall.allowed);
    assert_eq!(report.overall.guard, "origin_data");
    assert!(report.overall.message.contains("external origin"));
}

#[tokio::test]
async fn test_origin_output_send_invalid_payload_is_ignored_without_data_policy() {
    let engine = HushEngine::new();
    let payload = serde_json::json!({
        "target": "external-room"
    });

    let report = engine
        .check_action_report(
            &GuardAction::Custom("origin.output_send", &payload),
            &GuardContext::new(),
        )
        .await
        .unwrap();

    assert!(report.overall.allowed);
    assert!(!report
        .per_guard
        .iter()
        .any(|result| result.guard == "origin_data"));
}

#[tokio::test]
async fn test_origin_output_send_sanitizes_without_leaking_raw_content() {
    let policy = policy_with_origins(OriginsConfig {
        default_behavior: Some(OriginDefaultBehavior::Deny),
        profiles: vec![OriginProfile {
            id: "slack-redact".to_string(),
            match_rules: OriginMatch {
                provider: Some(OriginProvider::Slack),
                ..Default::default()
            },
            mcp: None,
            posture: None,
            egress: None,
            data: Some(crate::policy::OriginDataPolicy {
                allow_external_sharing: true,
                redact_before_send: true,
                block_sensitive_outputs: false,
            }),
            budgets: None,
            bridge_policy: None,
            explanation: None,
        }],
    });
    let engine = HushEngine::with_policy(policy);
    let context = GuardContext::new().with_origin(test_slack_origin());
    let raw_email = "alice@example.com";
    let payload = serde_json::json!({
        "text": format!("Contact {raw_email} for incident updates."),
        "target": "slack-channel"
    });

    let report = engine
        .check_action_report(
            &GuardAction::Custom("origin.output_send", &payload),
            &context,
        )
        .await
        .unwrap();

    assert!(report.overall.allowed);
    assert_eq!(report.overall.guard, "origin_data");
    let details = report.overall.details.as_ref().expect("details");
    let sanitized = details
        .get("sanitized")
        .and_then(|value| value.as_str())
        .expect("sanitized text");
    assert!(!sanitized.contains(raw_email));
    assert!(sanitized.contains("***"));
    let serialized_report = serde_json::to_string(&report).unwrap();
    assert!(!serialized_report.contains(raw_email));
}

#[tokio::test]
async fn test_origin_budget_exhaustion_blocks_followup_action() {
    let policy = policy_with_origins(OriginsConfig {
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
    });
    let engine = HushEngine::with_policy(policy);
    let context = GuardContext::new().with_origin(test_slack_origin());
    let mut posture_state = None;
    let mut origin_state = None;
    let args = serde_json::json!({});

    let allowed = engine
        .check_action_report_with_runtime(
            &GuardAction::McpTool("safe_tool", &args),
            &context,
            &mut posture_state,
            &mut origin_state,
        )
        .await
        .unwrap();
    assert!(allowed.guard_report.overall.allowed);

    let denied = engine
        .check_action_report_with_runtime(
            &GuardAction::McpTool("safe_tool", &args),
            &context,
            &mut posture_state,
            &mut origin_state,
        )
        .await
        .unwrap();
    assert!(!denied.guard_report.overall.allowed);
    assert_eq!(denied.guard_report.overall.guard, "origin_budget");
    assert!(denied.guard_report.overall.message.contains("exhausted"));
}

#[tokio::test]
async fn test_origin_budget_blocks_on_stateless_api_path() {
    let policy = policy_with_origins(OriginsConfig {
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
    });
    let engine = HushEngine::with_policy(policy);
    let context = GuardContext::new().with_origin(test_slack_origin());
    let args = serde_json::json!({});

    let report = engine
        .check_action_report(&GuardAction::McpTool("safe_tool", &args), &context)
        .await
        .unwrap();
    assert!(!report.overall.allowed);
    assert_eq!(report.overall.guard, "origin_budget");
    assert!(report
        .overall
        .message
        .contains("requires session runtime state"));
}

#[tokio::test]
async fn test_pre_resolved_enclave_is_preserved_without_origin_for_minimal_profile() {
    let policy = policy_with_origins(OriginsConfig {
        default_behavior: Some(OriginDefaultBehavior::MinimalProfile),
        profiles: vec![],
    });
    let engine = HushEngine::with_policy(policy);
    let context = GuardContext::new().with_enclave(manual_enclave("manual-pre-set", None));

    let report = engine
        .check_action_report(&GuardAction::FileAccess("/app/src/main.rs"), &context)
        .await
        .unwrap();

    assert!(report.overall.allowed);
    let metadata = report.metadata.as_ref().expect("metadata");
    let enclave = metadata.enclave.as_ref().expect("enclave metadata");
    assert_eq!(enclave.profile_id.as_deref(), Some("manual-pre-set"));
}

#[tokio::test]
async fn test_origin_required_still_denies_without_origin_even_with_pre_resolved_enclave() {
    let policy = policy_with_origins(OriginsConfig {
        default_behavior: Some(OriginDefaultBehavior::Deny),
        profiles: vec![],
    });
    let engine = HushEngine::with_policy(policy);
    let context = GuardContext::new().with_enclave(manual_enclave("manual-pre-set", None));

    let report = engine
        .check_action_report(&GuardAction::FileAccess("/app/src/main.rs"), &context)
        .await
        .unwrap();

    assert!(!report.overall.allowed);
    assert_eq!(report.overall.guard, "origin_required");
}

#[tokio::test]
async fn test_receipt_contains_origin_metadata() {
    let mcp = crate::guards::McpToolConfig {
        enabled: true,
        block: vec![],
        allow: vec![],
        require_confirmation: vec![],
        default_action: Some(McpDefaultAction::Allow),
        ..Default::default()
    };

    let origins = OriginsConfig {
        default_behavior: Some(OriginDefaultBehavior::Deny),
        profiles: vec![slack_profile_with_mcp("slack-meta", mcp)],
    };
    let policy = policy_with_origins(origins);
    let engine = HushEngine::with_policy(policy);

    let context = GuardContext::new().with_origin(test_slack_origin());
    let args = serde_json::json!({});

    let report = engine
        .check_action_report(&GuardAction::McpTool("safe_tool", &args), &context)
        .await
        .unwrap();

    let receipt = engine
        .create_receipt_for_report(sha256(b"origin-test"), &report)
        .await
        .unwrap();
    let metadata = receipt.metadata.expect("expected receipt metadata");

    // Verify origin metadata is present
    let origin_val = metadata
        .pointer("/clawdstrike/origin")
        .expect("origin metadata missing");
    assert_eq!(
        origin_val.get("provider").and_then(|v| v.as_str()),
        Some("slack")
    );
    assert_eq!(
        origin_val.get("space_id").and_then(|v| v.as_str()),
        Some("C-test-123")
    );

    // Verify enclave metadata is present
    let enclave_val = metadata
        .pointer("/clawdstrike/enclave")
        .expect("enclave metadata missing");
    assert_eq!(
        enclave_val.get("profile_id").and_then(|v| v.as_str()),
        Some("slack-meta")
    );
    assert!(enclave_val.get("resolution_path").is_some());
}

#[tokio::test]
async fn test_enclave_resolution_failure_deny() {
    // Origins config has deny default and no matching profile for Slack
    let origins = OriginsConfig {
        default_behavior: Some(OriginDefaultBehavior::Deny),
        profiles: vec![OriginProfile {
            id: "github-only".to_string(),
            match_rules: OriginMatch {
                provider: Some(OriginProvider::GitHub),
                ..Default::default()
            },
            mcp: None,
            posture: None,
            egress: None,
            data: None,
            budgets: None,
            bridge_policy: None,
            explanation: None,
        }],
    };
    let policy = policy_with_origins(origins);
    let engine = HushEngine::with_policy(policy);

    let context = GuardContext::new().with_origin(test_slack_origin());
    let args = serde_json::json!({});

    // Slack origin + deny default + no Slack profile → resolution fails → deny report
    let report = engine
        .check_action_report(&GuardAction::McpTool("any_tool", &args), &context)
        .await
        .unwrap();

    assert!(!report.overall.allowed);
    assert!(report.overall.message.contains("enclave resolution failed"));
}

#[tokio::test]
async fn test_enclave_default_action_block_without_allow_list() {
    // Enclave has default_action=Block and empty allow list → blocks all tools
    let mcp = crate::guards::McpToolConfig {
        enabled: true,
        block: vec![],
        allow: vec![],
        require_confirmation: vec![],
        default_action: Some(McpDefaultAction::Block),
        ..Default::default()
    };

    let origins = OriginsConfig {
        default_behavior: Some(OriginDefaultBehavior::Deny),
        profiles: vec![slack_profile_with_mcp("slack-locked", mcp)],
    };
    let policy = policy_with_origins(origins);
    let engine = HushEngine::with_policy(policy);

    let context = GuardContext::new().with_origin(test_slack_origin());
    let args = serde_json::json!({});

    let report = engine
        .check_action_report(&GuardAction::McpTool("any_tool", &args), &context)
        .await
        .unwrap();

    assert!(!report.overall.allowed);
    assert_eq!(report.overall.guard, "enclave");
    assert!(report.overall.message.contains("blocked by default_action"));
}

#[tokio::test]
async fn test_enclave_default_action_block_beats_confirmation_without_allow_list() {
    let mcp = crate::guards::McpToolConfig {
        enabled: true,
        block: vec![],
        allow: vec![],
        require_confirmation: vec!["any_tool".to_string()],
        default_action: Some(McpDefaultAction::Block),
        ..Default::default()
    };

    let origins = OriginsConfig {
        default_behavior: Some(OriginDefaultBehavior::Deny),
        profiles: vec![slack_profile_with_mcp("slack-locked", mcp)],
    };
    let policy = policy_with_origins(origins);
    let engine = HushEngine::with_policy(policy);

    let context = GuardContext::new().with_origin(test_slack_origin());
    let args = serde_json::json!({});

    let report = engine
        .check_action_report(&GuardAction::McpTool("any_tool", &args), &context)
        .await
        .unwrap();

    assert!(!report.overall.allowed);
    assert_eq!(report.overall.guard, "enclave");
    assert_eq!(report.overall.severity, Severity::Error);
    assert!(report.overall.message.contains("blocked by default_action"));
}

#[tokio::test]
async fn test_enclave_default_action_block_with_allow_list() {
    // Enclave has default_action=Block but "read_file" is in allow list
    let mcp = crate::guards::McpToolConfig {
        enabled: true,
        block: vec![],
        allow: vec!["read_file".to_string()],
        require_confirmation: vec![],
        default_action: Some(McpDefaultAction::Block),
        ..Default::default()
    };

    let origins = OriginsConfig {
        default_behavior: Some(OriginDefaultBehavior::Deny),
        profiles: vec![slack_profile_with_mcp("slack-allowlist", mcp)],
    };
    let policy = policy_with_origins(origins);
    let engine = HushEngine::with_policy(policy);

    let context = GuardContext::new().with_origin(test_slack_origin());
    let args = serde_json::json!({});

    // "read_file" is in allow list → passes enclave check
    let report = engine
        .check_action_report(&GuardAction::McpTool("read_file", &args), &context)
        .await
        .unwrap();
    assert!(report.overall.allowed);

    // "write_file" is NOT in allow list → blocked by enclave
    let report = engine
        .check_action_report(&GuardAction::McpTool("write_file", &args), &context)
        .await
        .unwrap();
    assert!(!report.overall.allowed);
    assert_eq!(report.overall.guard, "enclave");
}

#[tokio::test]
async fn test_enclave_allow_list_can_still_require_confirmation() {
    let mcp = crate::guards::McpToolConfig {
        enabled: true,
        block: vec![],
        allow: vec!["read_file".to_string()],
        require_confirmation: vec!["read_file".to_string()],
        default_action: Some(McpDefaultAction::Block),
        ..Default::default()
    };

    let origins = OriginsConfig {
        default_behavior: Some(OriginDefaultBehavior::Deny),
        profiles: vec![slack_profile_with_mcp("slack-confirm", mcp)],
    };
    let policy = policy_with_origins(origins);
    let engine = HushEngine::with_policy(policy);

    let context = GuardContext::new().with_origin(test_slack_origin());
    let args = serde_json::json!({});

    let report = engine
        .check_action_report(&GuardAction::McpTool("read_file", &args), &context)
        .await
        .unwrap();

    assert!(!report.overall.allowed);
    assert_eq!(report.overall.guard, "enclave");
    assert_eq!(report.overall.severity, Severity::Warning);
    assert!(report.overall.message.contains("requires confirmation"));
}

#[tokio::test]
async fn test_enclave_wildcard_block() {
    // Enclave blocks "dangerous_*" pattern
    let mcp = crate::guards::McpToolConfig {
        enabled: true,
        block: vec!["dangerous_*".to_string()],
        allow: vec![],
        require_confirmation: vec![],
        default_action: Some(McpDefaultAction::Allow),
        ..Default::default()
    };

    let origins = OriginsConfig {
        default_behavior: Some(OriginDefaultBehavior::Deny),
        profiles: vec![slack_profile_with_mcp("slack-wildcard", mcp)],
    };
    let policy = policy_with_origins(origins);
    let engine = HushEngine::with_policy(policy);

    let context = GuardContext::new().with_origin(test_slack_origin());
    let args = serde_json::json!({});

    // "dangerous_exec" matches "dangerous_*" → blocked
    let report = engine
        .check_action_report(&GuardAction::McpTool("dangerous_exec", &args), &context)
        .await
        .unwrap();
    assert!(!report.overall.allowed);
    assert_eq!(report.overall.guard, "enclave");

    // "safe_tool" does NOT match "dangerous_*" → passes enclave
    let report = engine
        .check_action_report(&GuardAction::McpTool("safe_tool", &args), &context)
        .await
        .unwrap();
    assert!(report.overall.allowed);
}

#[test]
fn test_tool_matches_helper() {
    // Exact match
    assert!(tool_matches("read_file", "read_file"));
    assert!(!tool_matches("read_file", "write_file"));

    // Wildcard
    assert!(tool_matches("read_file", "*"));
    assert!(tool_matches("dangerous_exec", "dangerous_*"));
    assert!(tool_matches("dangerous_", "dangerous_*"));
    assert!(!tool_matches("safe_tool", "dangerous_*"));

    // Prefix only (no wildcard)
    assert!(!tool_matches("read_file_extra", "read_file"));
}

#[tokio::test]
async fn test_enclave_non_mcp_action_not_affected() {
    // Enclave with MCP restrictions should not affect file access checks
    let mcp = crate::guards::McpToolConfig {
        enabled: true,
        block: vec!["*".to_string()],
        allow: vec![],
        require_confirmation: vec![],
        default_action: Some(McpDefaultAction::Block),
        ..Default::default()
    };

    let origins = OriginsConfig {
        default_behavior: Some(OriginDefaultBehavior::Deny),
        profiles: vec![slack_profile_with_mcp("slack-lockdown", mcp)],
    };
    let policy = policy_with_origins(origins);
    let engine = HushEngine::with_policy(policy);

    let context = GuardContext::new().with_origin(test_slack_origin());

    // File access should not be affected by enclave MCP restrictions
    let report = engine
        .check_action_report(&GuardAction::FileAccess("/app/src/main.rs"), &context)
        .await
        .unwrap();
    assert!(report.overall.allowed);
}
