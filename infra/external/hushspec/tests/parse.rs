use hushspec::{HushSpec, validate};

#[test]
fn parse_minimal_valid() {
    let yaml = r#"
hushspec: "0.1.0"
name: test
"#;
    let spec = HushSpec::parse(yaml).unwrap();
    assert_eq!(spec.hushspec, "0.1.0");
    assert_eq!(spec.name.as_deref(), Some("test"));
    let result = validate(&spec);
    assert!(result.is_valid());
}

#[test]
fn parse_with_rules() {
    let yaml = r#"
hushspec: "0.1.0"
name: test-rules
rules:
  forbidden_paths:
    patterns:
      - "**/.ssh/**"
      - "**/.aws/**"
    exceptions:
      - "**/.ssh/config"
  egress:
    allow:
      - "api.openai.com"
    default: block
  tool_access:
    block:
      - shell_exec
    default: allow
"#;
    let spec = HushSpec::parse(yaml).unwrap();
    let rules = spec.rules.as_ref().unwrap();
    let fp = rules.forbidden_paths.as_ref().unwrap();
    assert_eq!(fp.patterns.len(), 2);
    assert_eq!(fp.exceptions.len(), 1);
    let eg = rules.egress.as_ref().unwrap();
    assert_eq!(eg.allow.len(), 1);
    assert_eq!(eg.default, hushspec::DefaultAction::Block);
}

#[test]
fn reject_unknown_fields() {
    let yaml = r#"
hushspec: "0.1.0"
name: test
unknown_field: true
"#;
    let result = HushSpec::parse(yaml);
    assert!(result.is_err());
}

#[test]
fn reject_unknown_rule() {
    let yaml = r#"
hushspec: "0.1.0"
rules:
  nonexistent_rule:
    enabled: true
"#;
    let result = HushSpec::parse(yaml);
    assert!(result.is_err());
}

#[test]
fn validate_unsupported_version() {
    let yaml = r#"
hushspec: "99.0.0"
"#;
    let spec = HushSpec::parse(yaml).unwrap();
    let result = validate(&spec);
    assert!(!result.is_valid());
}

#[test]
fn validate_duplicate_secret_pattern_names() {
    let yaml = r#"
hushspec: "0.1.0"
rules:
  secret_patterns:
    patterns:
      - name: aws_key
        pattern: "AKIA[0-9A-Z]{16}"
        severity: critical
      - name: aws_key
        pattern: "ASIA[0-9A-Z]{16}"
        severity: critical
"#;
    let spec = HushSpec::parse(yaml).unwrap();
    let result = validate(&spec);
    assert!(!result.is_valid());
}

#[test]
fn validate_invalid_regex_pattern() {
    let yaml = r#"
hushspec: "0.1.0"
rules:
  secret_patterns:
    patterns:
      - name: bad
        pattern: "["
        severity: critical
"#;
    let spec = HushSpec::parse(yaml).unwrap();
    let result = validate(&spec);
    assert!(!result.is_valid());
}

#[test]
fn validate_invalid_detection_top_k() {
    let yaml = r#"
hushspec: "0.1.0"
extensions:
  detection:
    threat_intel:
      top_k: 0
"#;
    let spec = HushSpec::parse(yaml).unwrap();
    let result = validate(&spec);
    assert!(!result.is_valid());
}

#[test]
fn validate_valid_regex_patterns_pass() {
    let yaml = r#"
hushspec: "0.1.0"
rules:
  secret_patterns:
    patterns:
      - name: aws_key
        pattern: "AKIA[0-9A-Z]{16}"
        severity: critical
      - name: private_key
        pattern: "-----BEGIN\\s+(RSA\\s+)?PRIVATE\\s+KEY-----"
        severity: critical
  shell_commands:
    forbidden_patterns:
      - "(?i)rm\\s+-rf\\s+/"
      - "curl.*\\|.*bash"
  patch_integrity:
    max_imbalance_ratio: 10.0
    forbidden_patterns:
      - "(?i)disable[\\s_\\-]?(security|auth|ssl|tls)"
      - "(?i)chmod\\s+777"
"#;
    let spec = HushSpec::parse(yaml).unwrap();
    let result = validate(&spec);
    assert!(
        result.is_valid(),
        "valid RE2 patterns should pass: {:?}",
        result.errors
    );
}

#[test]
fn validate_invalid_regex_syntax_in_shell_commands() {
    let yaml = r#"
hushspec: "0.1.0"
rules:
  shell_commands:
    forbidden_patterns:
      - "[invalid"
"#;
    let spec = HushSpec::parse(yaml).unwrap();
    let result = validate(&spec);
    assert!(!result.is_valid());
    let has_regex_error = result.errors.iter().any(|e| {
        matches!(e, hushspec::ValidationError::InvalidRegex { field, .. }
            if field.contains("shell_commands.forbidden_patterns"))
    });
    assert!(
        has_regex_error,
        "expected InvalidRegex error for shell_commands"
    );
}

#[test]
fn validate_invalid_regex_syntax_in_patch_integrity() {
    let yaml = r#"
hushspec: "0.1.0"
rules:
  patch_integrity:
    max_imbalance_ratio: 10.0
    forbidden_patterns:
      - "valid_pattern"
      - "(unclosed"
"#;
    let spec = HushSpec::parse(yaml).unwrap();
    let result = validate(&spec);
    assert!(!result.is_valid());
    let has_regex_error = result.errors.iter().any(|e| {
        matches!(e, hushspec::ValidationError::InvalidRegex { field, .. }
            if field.contains("patch_integrity.forbidden_patterns"))
    });
    assert!(
        has_regex_error,
        "expected InvalidRegex error for patch_integrity"
    );
}

#[test]
fn validate_regex_error_variant_contains_pattern() {
    let yaml = r#"
hushspec: "0.1.0"
rules:
  secret_patterns:
    patterns:
      - name: bad_pattern
        pattern: "[unterminated"
        severity: critical
"#;
    let spec = HushSpec::parse(yaml).unwrap();
    let result = validate(&spec);
    assert!(!result.is_valid());
    let regex_error = result
        .errors
        .iter()
        .find(|e| matches!(e, hushspec::ValidationError::InvalidRegex { .. }));
    assert!(regex_error.is_some(), "expected InvalidRegex variant");
    if let Some(hushspec::ValidationError::InvalidRegex {
        field,
        pattern,
        message,
    }) = regex_error
    {
        assert!(
            field.contains("bad_pattern"),
            "field should reference the pattern name"
        );
        assert_eq!(pattern, "[unterminated");
        assert!(!message.is_empty(), "message should describe the error");
    }
}

#[test]
fn validate_rust_regex_rejects_backreference() {
    // The Rust regex crate rejects backreferences (non-RE2 feature).
    // This verifies our ReDoS protection catches patterns that would be
    // dangerous in TypeScript/Python backtracking engines.
    let yaml = r#"
hushspec: "0.1.0"
rules:
  secret_patterns:
    patterns:
      - name: backref
        pattern: "(a)\\1"
        severity: critical
"#;
    let spec = HushSpec::parse(yaml).unwrap();
    let result = validate(&spec);
    // Rust's regex crate treats \1 as an error (no backreferences in RE2).
    assert!(
        !result.is_valid(),
        "backreference pattern should be rejected"
    );
}

#[test]
fn validate_rust_regex_rejects_lookahead() {
    // Lookahead is not supported in RE2/Rust regex.
    let yaml = r#"
hushspec: "0.1.0"
rules:
  shell_commands:
    forbidden_patterns:
      - "(?=foo)bar"
"#;
    let spec = HushSpec::parse(yaml).unwrap();
    let result = validate(&spec);
    assert!(!result.is_valid(), "lookahead pattern should be rejected");
}

#[test]
fn validate_rust_regex_rejects_lookbehind() {
    // Lookbehind is not supported in RE2/Rust regex.
    let yaml = r#"
hushspec: "0.1.0"
rules:
  patch_integrity:
    max_imbalance_ratio: 10.0
    forbidden_patterns:
      - "(?<=password:)\\s*\\S+"
"#;
    let spec = HushSpec::parse(yaml).unwrap();
    let result = validate(&spec);
    assert!(!result.is_valid(), "lookbehind pattern should be rejected");
}

#[test]
fn validate_builtin_rulesets_pass() {
    // Validate the crate's own built-in HushSpec rulesets, not ClawdStrike's
    // higher-level policy files, which have a different top-level schema.
    let rulesets = [
        include_str!("../rulesets/default.yaml"),
        include_str!("../rulesets/strict.yaml"),
        include_str!("../rulesets/permissive.yaml"),
        include_str!("../rulesets/ai-agent.yaml"),
        include_str!("../rulesets/cicd.yaml"),
        include_str!("../rulesets/remote-desktop.yaml"),
    ];
    for (i, yaml) in rulesets.iter().enumerate() {
        let spec =
            HushSpec::parse(yaml).unwrap_or_else(|e| panic!("ruleset {i} failed to parse: {e}"));
        let result = validate(&spec);
        assert!(
            result.is_valid(),
            "ruleset {i} failed validation: {:?}",
            result.errors
        );
    }
}

#[test]
fn roundtrip_yaml() {
    let yaml = r#"
hushspec: "0.1.0"
name: roundtrip
rules:
  egress:
    allow:
      - "*.openai.com"
    default: block
"#;
    let spec = HushSpec::parse(yaml).unwrap();
    let out = spec.to_yaml().unwrap();
    let spec2 = HushSpec::parse(&out).unwrap();
    assert_eq!(spec, spec2);
}
