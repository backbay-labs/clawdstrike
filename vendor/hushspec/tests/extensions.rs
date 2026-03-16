use hushspec::{HushSpec, merge, validate};

#[test]
fn parse_posture_extension() {
    let yaml = r#"
hushspec: "0.1.0"
extensions:
  posture:
    initial: standard
    states:
      restricted:
        description: Minimal access
        capabilities: [file_access]
        budgets: {}
      standard:
        capabilities: [file_access, file_write, egress]
        budgets:
          file_writes: 50
          egress_calls: 20
      elevated:
        capabilities: [file_access, file_write, egress, shell, tool_call, patch]
        budgets:
          file_writes: 200
    transitions:
      - from: restricted
        to: standard
        on: user_approval
      - from: standard
        to: elevated
        on: user_approval
      - from: "*"
        to: restricted
        on: critical_violation
      - from: elevated
        to: standard
        on: timeout
        after: "1h"
      - from: standard
        to: restricted
        on: budget_exhausted
"#;
    let spec = HushSpec::parse(yaml).unwrap();
    let result = validate(&spec);
    assert!(result.is_valid(), "errors: {:?}", result.errors);

    let ext = spec.extensions.as_ref().unwrap();
    let posture = ext.posture.as_ref().unwrap();
    assert_eq!(posture.initial, "standard");
    assert_eq!(posture.states.len(), 3);
    assert_eq!(posture.transitions.len(), 5);
}

#[test]
fn validate_posture_invalid_initial() {
    let yaml = r#"
hushspec: "0.1.0"
extensions:
  posture:
    initial: nonexistent
    states:
      valid:
        capabilities: []
    transitions: []
"#;
    let spec = HushSpec::parse(yaml).unwrap();
    let result = validate(&spec);
    assert!(!result.is_valid());
}

#[test]
fn validate_posture_timeout_requires_after() {
    let yaml = r#"
hushspec: "0.1.0"
extensions:
  posture:
    initial: a
    states:
      a:
        capabilities: []
      b:
        capabilities: []
    transitions:
      - from: a
        to: b
        on: timeout
"#;
    let spec = HushSpec::parse(yaml).unwrap();
    let result = validate(&spec);
    assert!(!result.is_valid());
}

#[test]
fn parse_origins_extension() {
    let yaml = r#"
hushspec: "0.1.0"
extensions:
  origins:
    default_behavior: deny
    profiles:
      - id: incident-room
        match:
          provider: slack
          tags: [incident]
        posture: elevated
        tool_access:
          allow: ["*"]
          default: allow
        budgets:
          tool_calls: 200
        explanation: Incident response channel
      - id: external-chat
        match:
          visibility: external_shared
        data:
          redact_before_send: true
          block_sensitive_outputs: true
"#;
    let spec = HushSpec::parse(yaml).unwrap();
    let result = validate(&spec);
    assert!(result.is_valid(), "errors: {:?}", result.errors);

    let ext = spec.extensions.as_ref().unwrap();
    let origins = ext.origins.as_ref().unwrap();
    assert_eq!(origins.profiles.len(), 2);
    assert_eq!(origins.profiles[0].id, "incident-room");
}

#[test]
fn validate_origins_duplicate_ids() {
    let yaml = r#"
hushspec: "0.1.0"
extensions:
  origins:
    profiles:
      - id: dup
        match:
          provider: slack
      - id: dup
        match:
          provider: teams
"#;
    let spec = HushSpec::parse(yaml).unwrap();
    let result = validate(&spec);
    assert!(!result.is_valid());
}

#[test]
fn parse_detection_extension() {
    let yaml = r#"
hushspec: "0.1.0"
extensions:
  detection:
    prompt_injection:
      enabled: true
      warn_at_or_above: suspicious
      block_at_or_above: high
    jailbreak:
      enabled: true
      block_threshold: 40
      warn_threshold: 15
    threat_intel:
      enabled: true
      pattern_db: "builtin:s2bench-v1"
      similarity_threshold: 0.85
      top_k: 5
"#;
    let spec = HushSpec::parse(yaml).unwrap();
    let result = validate(&spec);
    assert!(result.is_valid(), "errors: {:?}", result.errors);
}

#[test]
fn validate_detection_threshold_warning() {
    let yaml = r#"
hushspec: "0.1.0"
extensions:
  detection:
    jailbreak:
      block_threshold: 10
      warn_threshold: 50
"#;
    let spec = HushSpec::parse(yaml).unwrap();
    let result = validate(&spec);
    assert!(result.is_valid()); // warning, not error
    assert!(!result.warnings.is_empty());
}

#[test]
fn validate_detection_similarity_out_of_range() {
    let yaml = r#"
hushspec: "0.1.0"
extensions:
  detection:
    threat_intel:
      similarity_threshold: 1.5
"#;
    let spec = HushSpec::parse(yaml).unwrap();
    let result = validate(&spec);
    assert!(!result.is_valid());
}

#[test]
fn merge_extensions_posture() {
    let base = HushSpec::parse(
        r#"
hushspec: "0.1.0"
extensions:
  posture:
    initial: a
    states:
      a:
        capabilities: [file_access]
    transitions: []
"#,
    )
    .unwrap();
    let child = HushSpec::parse(
        r#"
hushspec: "0.1.0"
extensions:
  posture:
    initial: b
    states:
      b:
        capabilities: [egress]
    transitions: []
"#,
    )
    .unwrap();
    let merged = merge(&base, &child);
    let posture = merged
        .extensions
        .as_ref()
        .unwrap()
        .posture
        .as_ref()
        .unwrap();
    assert_eq!(posture.initial, "b"); // child overrides
}

#[test]
fn merge_extensions_origins_by_id() {
    let base = HushSpec::parse(
        r#"
hushspec: "0.1.0"
extensions:
  origins:
    default_behavior: deny
    profiles:
      - id: existing
        match:
          provider: slack
        explanation: base profile
"#,
    )
    .unwrap();
    let child = HushSpec::parse(
        r#"
hushspec: "0.1.0"
extensions:
  origins:
    profiles:
      - id: existing
        match:
          provider: teams
        explanation: overridden
      - id: new-profile
        match:
          provider: github
"#,
    )
    .unwrap();
    let merged = merge(&base, &child);
    let origins = merged
        .extensions
        .as_ref()
        .unwrap()
        .origins
        .as_ref()
        .unwrap();
    assert_eq!(origins.profiles.len(), 2);
    // existing overridden
    let existing = origins
        .profiles
        .iter()
        .find(|p| p.id == "existing")
        .unwrap();
    assert_eq!(existing.explanation.as_deref(), Some("overridden"));
    // new appended
    assert!(origins.profiles.iter().any(|p| p.id == "new-profile"));
}

#[test]
fn parse_full_document_with_rules_and_extensions() {
    let yaml = r#"
hushspec: "0.1.0"
name: full-featured
rules:
  egress:
    allow: ["api.openai.com"]
    default: block
  tool_access:
    block: ["shell_exec"]
    default: allow
extensions:
  posture:
    initial: standard
    states:
      standard:
        capabilities: [file_access, egress]
      restricted:
        capabilities: [file_access]
    transitions:
      - from: "*"
        to: restricted
        on: critical_violation
  detection:
    prompt_injection:
      enabled: true
      block_at_or_above: high
"#;
    let spec = HushSpec::parse(yaml).unwrap();
    let result = validate(&spec);
    assert!(result.is_valid(), "errors: {:?}", result.errors);
    assert!(spec.rules.is_some());
    assert!(spec.extensions.is_some());
}
