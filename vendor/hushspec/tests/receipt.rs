use hushspec::receipt::{RuleOutcome, compute_policy_hash};
use hushspec::{
    AuditConfig, Decision, DecisionReceipt, EvaluationAction, HushSpec, evaluate, evaluate_audited,
};

fn simple_spec() -> HushSpec {
    let yaml = r#"
hushspec: "0.1.0"
name: "test-policy"
rules:
  tool_access:
    enabled: true
    default: block
    allow:
      - "safe_tool"
    block:
      - "dangerous_tool"
    require_confirmation:
      - "risky_tool"
  forbidden_paths:
    enabled: true
    patterns:
      - "/etc/shadow"
      - "/root/**"
    exceptions: []
  egress:
    enabled: true
    default: block
    allow:
      - "*.example.com"
    block:
      - "*.evil.com"
"#;
    HushSpec::parse(yaml).unwrap()
}

fn default_audit_config() -> AuditConfig {
    AuditConfig {
        enabled: true,
        include_rule_trace: true,
        redact_content: true,
    }
}

// --- Decision correctness ---

#[test]
fn audited_returns_same_decision_as_evaluate_allow() {
    let spec = simple_spec();
    let action = EvaluationAction {
        action_type: "tool_call".to_string(),
        target: Some("safe_tool".to_string()),
        ..Default::default()
    };

    let standard = evaluate(&spec, &action);
    let receipt = evaluate_audited(&spec, &action, &default_audit_config());

    assert_eq!(receipt.decision, standard.decision);
    assert_eq!(receipt.decision, Decision::Allow);
    assert_eq!(receipt.matched_rule, standard.matched_rule);
    assert_eq!(receipt.reason, standard.reason);
}

#[test]
fn audited_returns_same_decision_as_evaluate_deny() {
    let spec = simple_spec();
    let action = EvaluationAction {
        action_type: "tool_call".to_string(),
        target: Some("dangerous_tool".to_string()),
        ..Default::default()
    };

    let standard = evaluate(&spec, &action);
    let receipt = evaluate_audited(&spec, &action, &default_audit_config());

    assert_eq!(receipt.decision, standard.decision);
    assert_eq!(receipt.decision, Decision::Deny);
    assert_eq!(receipt.matched_rule, standard.matched_rule);
}

#[test]
fn audited_returns_same_decision_as_evaluate_warn() {
    let spec = simple_spec();
    let action = EvaluationAction {
        action_type: "tool_call".to_string(),
        target: Some("risky_tool".to_string()),
        ..Default::default()
    };

    let standard = evaluate(&spec, &action);
    let receipt = evaluate_audited(&spec, &action, &default_audit_config());

    assert_eq!(receipt.decision, standard.decision);
    assert_eq!(receipt.decision, Decision::Warn);
}

#[test]
fn audited_returns_same_decision_for_egress() {
    let spec = simple_spec();
    let action = EvaluationAction {
        action_type: "egress".to_string(),
        target: Some("api.example.com".to_string()),
        ..Default::default()
    };

    let standard = evaluate(&spec, &action);
    let receipt = evaluate_audited(&spec, &action, &default_audit_config());

    assert_eq!(receipt.decision, standard.decision);
    assert_eq!(receipt.decision, Decision::Allow);
}

#[test]
fn audited_returns_same_decision_for_forbidden_path() {
    let spec = simple_spec();
    let action = EvaluationAction {
        action_type: "file_read".to_string(),
        target: Some("/etc/shadow".to_string()),
        ..Default::default()
    };

    let standard = evaluate(&spec, &action);
    let receipt = evaluate_audited(&spec, &action, &default_audit_config());

    assert_eq!(receipt.decision, standard.decision);
    assert_eq!(receipt.decision, Decision::Deny);
}

#[test]
fn audited_returns_same_decision_for_default_block() {
    let spec = simple_spec();
    let action = EvaluationAction {
        action_type: "tool_call".to_string(),
        target: Some("unknown_tool".to_string()),
        ..Default::default()
    };

    let standard = evaluate(&spec, &action);
    let receipt = evaluate_audited(&spec, &action, &default_audit_config());

    assert_eq!(receipt.decision, standard.decision);
    assert_eq!(receipt.decision, Decision::Deny);
}

// --- Rule trace ---

#[test]
fn rule_trace_populated_for_tool_call() {
    let spec = simple_spec();
    let action = EvaluationAction {
        action_type: "tool_call".to_string(),
        target: Some("safe_tool".to_string()),
        ..Default::default()
    };

    let receipt = evaluate_audited(&spec, &action, &default_audit_config());

    assert!(
        !receipt.rule_trace.is_empty(),
        "rule trace should not be empty"
    );
    let tool_trace = receipt
        .rule_trace
        .iter()
        .find(|t| t.rule_block == "tool_access");
    assert!(tool_trace.is_some(), "should have tool_access in trace");
    let tool_trace = tool_trace.unwrap();
    assert!(tool_trace.evaluated);
    assert_eq!(tool_trace.outcome, RuleOutcome::Allow);
}

#[test]
fn rule_trace_populated_for_file_read_deny() {
    let spec = simple_spec();
    let action = EvaluationAction {
        action_type: "file_read".to_string(),
        target: Some("/etc/shadow".to_string()),
        ..Default::default()
    };

    let receipt = evaluate_audited(&spec, &action, &default_audit_config());

    let forbidden_trace = receipt
        .rule_trace
        .iter()
        .find(|t| t.rule_block == "forbidden_paths");
    assert!(
        forbidden_trace.is_some(),
        "should have forbidden_paths in trace"
    );
    let forbidden_trace = forbidden_trace.unwrap();
    assert!(forbidden_trace.evaluated);
    assert_eq!(forbidden_trace.outcome, RuleOutcome::Deny);
}

#[test]
fn rule_trace_empty_when_disabled() {
    let spec = simple_spec();
    let action = EvaluationAction {
        action_type: "tool_call".to_string(),
        target: Some("safe_tool".to_string()),
        ..Default::default()
    };

    let config = AuditConfig {
        enabled: true,
        include_rule_trace: false,
        redact_content: true,
    };
    let receipt = evaluate_audited(&spec, &action, &config);

    assert!(
        receipt.rule_trace.is_empty(),
        "rule trace should be empty when include_rule_trace is false"
    );
    // Decision should still be correct.
    assert_eq!(receipt.decision, Decision::Allow);
}

// --- AuditConfig { enabled: false } ---

#[test]
fn disabled_audit_still_returns_correct_decision() {
    let spec = simple_spec();
    let action = EvaluationAction {
        action_type: "tool_call".to_string(),
        target: Some("dangerous_tool".to_string()),
        ..Default::default()
    };

    let config = AuditConfig {
        enabled: false,
        include_rule_trace: true,
        redact_content: true,
    };
    let receipt = evaluate_audited(&spec, &action, &config);

    assert_eq!(receipt.decision, Decision::Deny);
    assert!(
        receipt.rule_trace.is_empty(),
        "rule trace should be empty when audit disabled"
    );
    assert_eq!(
        receipt.evaluation_duration_us, 0,
        "duration should be 0 when audit disabled"
    );
    assert!(
        receipt.policy.content_hash.is_empty(),
        "content hash should be empty when audit disabled"
    );
}

// --- Policy content hash ---

#[test]
fn policy_content_hash_is_deterministic() {
    let spec = simple_spec();

    let hash1 = compute_policy_hash(&spec);
    let hash2 = compute_policy_hash(&spec);

    assert_eq!(hash1, hash2, "same spec should produce same hash");
    assert_eq!(hash1.len(), 64, "SHA-256 hex digest should be 64 chars");
    assert!(
        hash1.chars().all(|c| c.is_ascii_hexdigit()),
        "hash should be hex"
    );
}

#[test]
fn policy_content_hash_changes_with_spec() {
    let spec1 = simple_spec();

    let yaml2 = r#"
hushspec: "0.1.0"
name: "different-policy"
rules:
  tool_access:
    enabled: true
    default: allow
    allow: []
    block: []
    require_confirmation: []
"#;
    let spec2 = HushSpec::parse(yaml2).unwrap();

    let hash1 = compute_policy_hash(&spec1);
    let hash2 = compute_policy_hash(&spec2);

    assert_ne!(
        hash1, hash2,
        "different specs should produce different hashes"
    );
}

#[test]
fn receipt_policy_summary_has_correct_fields() {
    let spec = simple_spec();
    let action = EvaluationAction {
        action_type: "tool_call".to_string(),
        target: Some("safe_tool".to_string()),
        ..Default::default()
    };

    let receipt = evaluate_audited(&spec, &action, &default_audit_config());

    assert_eq!(receipt.policy.name.as_deref(), Some("test-policy"));
    assert_eq!(receipt.policy.version, "0.1.0");
    assert!(!receipt.policy.content_hash.is_empty());
}

// --- Timestamps ---

#[test]
fn timestamp_is_valid_iso8601() {
    let spec = simple_spec();
    let action = EvaluationAction {
        action_type: "tool_call".to_string(),
        target: Some("safe_tool".to_string()),
        ..Default::default()
    };

    let receipt = evaluate_audited(&spec, &action, &default_audit_config());

    // Should parse as a valid DateTime.
    let parsed = chrono::DateTime::parse_from_rfc3339(&receipt.timestamp);
    assert!(
        parsed.is_ok(),
        "timestamp should be valid RFC 3339: {}",
        receipt.timestamp
    );

    // Should end with Z (UTC).
    assert!(
        receipt.timestamp.ends_with('Z'),
        "timestamp should use UTC (Z suffix): {}",
        receipt.timestamp
    );
}

// --- Receipt ID ---

#[test]
fn receipt_id_is_valid_uuid() {
    let spec = simple_spec();
    let action = EvaluationAction {
        action_type: "tool_call".to_string(),
        target: Some("safe_tool".to_string()),
        ..Default::default()
    };

    let receipt = evaluate_audited(&spec, &action, &default_audit_config());

    let parsed = uuid::Uuid::parse_str(&receipt.receipt_id);
    assert!(
        parsed.is_ok(),
        "receipt_id should be a valid UUID: {}",
        receipt.receipt_id
    );
}

#[test]
fn receipt_ids_are_unique() {
    let spec = simple_spec();
    let action = EvaluationAction {
        action_type: "tool_call".to_string(),
        target: Some("safe_tool".to_string()),
        ..Default::default()
    };

    let r1 = evaluate_audited(&spec, &action, &default_audit_config());
    let r2 = evaluate_audited(&spec, &action, &default_audit_config());

    assert_ne!(
        r1.receipt_id, r2.receipt_id,
        "each receipt should have a unique ID"
    );
}

// --- JSON serialization ---

#[test]
fn receipt_serializes_to_valid_json() {
    let spec = simple_spec();
    let action = EvaluationAction {
        action_type: "tool_call".to_string(),
        target: Some("safe_tool".to_string()),
        ..Default::default()
    };

    let receipt = evaluate_audited(&spec, &action, &default_audit_config());
    let json = serde_json::to_string_pretty(&receipt);
    assert!(json.is_ok(), "receipt should serialize to JSON");

    let json_str = json.unwrap();
    // Verify it round-trips.
    let deserialized: Result<DecisionReceipt, _> = serde_json::from_str(&json_str);
    assert!(deserialized.is_ok(), "receipt should deserialize from JSON");

    let roundtripped = deserialized.unwrap();
    assert_eq!(roundtripped.decision, receipt.decision);
    assert_eq!(roundtripped.receipt_id, receipt.receipt_id);
    assert_eq!(
        roundtripped.policy.content_hash,
        receipt.policy.content_hash
    );
}

#[test]
fn receipt_json_contains_expected_fields() {
    let spec = simple_spec();
    let action = EvaluationAction {
        action_type: "tool_call".to_string(),
        target: Some("safe_tool".to_string()),
        ..Default::default()
    };

    let receipt = evaluate_audited(&spec, &action, &default_audit_config());
    let json_value: serde_json::Value = serde_json::to_value(&receipt).unwrap();
    let obj = json_value.as_object().unwrap();

    assert!(obj.contains_key("receipt_id"), "missing receipt_id");
    assert!(obj.contains_key("timestamp"), "missing timestamp");
    assert!(
        obj.contains_key("hushspec_version"),
        "missing hushspec_version"
    );
    assert!(obj.contains_key("action"), "missing action");
    assert!(obj.contains_key("decision"), "missing decision");
    assert!(obj.contains_key("rule_trace"), "missing rule_trace");
    assert!(obj.contains_key("policy"), "missing policy");
    assert!(
        obj.contains_key("evaluation_duration_us"),
        "missing evaluation_duration_us"
    );
}

// --- HushSpec version ---

#[test]
fn receipt_contains_hushspec_version() {
    let spec = simple_spec();
    let action = EvaluationAction {
        action_type: "tool_call".to_string(),
        target: Some("safe_tool".to_string()),
        ..Default::default()
    };

    let receipt = evaluate_audited(&spec, &action, &default_audit_config());
    assert_eq!(receipt.hushspec_version, "0.1.0");
}

// --- Content redaction ---

#[test]
fn content_redacted_flag_set_when_content_present() {
    let spec = simple_spec();
    let action = EvaluationAction {
        action_type: "file_write".to_string(),
        target: Some("/tmp/test.txt".to_string()),
        content: Some("sensitive data".to_string()),
        ..Default::default()
    };

    let config = AuditConfig {
        enabled: true,
        include_rule_trace: true,
        redact_content: true,
    };
    let receipt = evaluate_audited(&spec, &action, &config);

    assert!(
        receipt.action.content_redacted,
        "content_redacted should be true when content was present and redaction enabled"
    );
}

#[test]
fn content_redacted_flag_false_when_no_content() {
    let spec = simple_spec();
    let action = EvaluationAction {
        action_type: "tool_call".to_string(),
        target: Some("safe_tool".to_string()),
        content: None,
        ..Default::default()
    };

    let receipt = evaluate_audited(&spec, &action, &default_audit_config());

    assert!(
        !receipt.action.content_redacted,
        "content_redacted should be false when no content"
    );
}

#[test]
fn content_redacted_flag_false_when_redaction_disabled() {
    let spec = simple_spec();
    let action = EvaluationAction {
        action_type: "file_write".to_string(),
        target: Some("/tmp/test.txt".to_string()),
        content: Some("sensitive data".to_string()),
        ..Default::default()
    };

    let config = AuditConfig {
        enabled: true,
        include_rule_trace: true,
        redact_content: false,
    };
    let receipt = evaluate_audited(&spec, &action, &config);

    assert!(
        !receipt.action.content_redacted,
        "content_redacted should be false when redaction is disabled"
    );
}

// --- Action summary ---

#[test]
fn action_summary_captures_action_type_and_target() {
    let spec = simple_spec();
    let action = EvaluationAction {
        action_type: "egress".to_string(),
        target: Some("api.example.com".to_string()),
        ..Default::default()
    };

    let receipt = evaluate_audited(&spec, &action, &default_audit_config());

    assert_eq!(receipt.action.action_type, "egress");
    assert_eq!(receipt.action.target.as_deref(), Some("api.example.com"));
}

// --- Egress deny trace ---

#[test]
fn egress_deny_produces_correct_trace() {
    let spec = simple_spec();
    let action = EvaluationAction {
        action_type: "egress".to_string(),
        target: Some("malware.evil.com".to_string()),
        ..Default::default()
    };

    let receipt = evaluate_audited(&spec, &action, &default_audit_config());

    assert_eq!(receipt.decision, Decision::Deny);
    let egress_trace = receipt.rule_trace.iter().find(|t| t.rule_block == "egress");
    assert!(egress_trace.is_some());
    assert_eq!(egress_trace.unwrap().outcome, RuleOutcome::Deny);
}

// --- Shell command ---

#[test]
fn shell_command_with_no_rules_allows() {
    let yaml = r#"
hushspec: "0.1.0"
"#;
    let spec = HushSpec::parse(yaml).unwrap();
    let action = EvaluationAction {
        action_type: "shell_command".to_string(),
        target: Some("ls -la".to_string()),
        ..Default::default()
    };

    let standard = evaluate(&spec, &action);
    let receipt = evaluate_audited(&spec, &action, &default_audit_config());

    assert_eq!(receipt.decision, standard.decision);
    assert_eq!(receipt.decision, Decision::Allow);
}

// --- Origin profile ---

#[test]
fn origin_profile_propagated_from_evaluation() {
    let spec = simple_spec();
    let action = EvaluationAction {
        action_type: "tool_call".to_string(),
        target: Some("safe_tool".to_string()),
        ..Default::default()
    };

    let standard = evaluate(&spec, &action);
    let receipt = evaluate_audited(&spec, &action, &default_audit_config());

    assert_eq!(receipt.origin_profile, standard.origin_profile);
}

// --- Posture ---

#[test]
fn posture_propagated_from_evaluation() {
    let spec = simple_spec();
    let action = EvaluationAction {
        action_type: "tool_call".to_string(),
        target: Some("safe_tool".to_string()),
        ..Default::default()
    };

    let standard = evaluate(&spec, &action);
    let receipt = evaluate_audited(&spec, &action, &default_audit_config());

    assert_eq!(receipt.posture, standard.posture);
}
