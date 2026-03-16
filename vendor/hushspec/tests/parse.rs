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
