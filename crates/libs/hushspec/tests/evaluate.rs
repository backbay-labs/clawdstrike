use hushspec::{Decision, EvaluationAction, HushSpec, evaluate};

#[test]
fn input_inject_denies_unlisted_type() {
    let spec = HushSpec::parse(
        r#"
hushspec: "0.1.0"
name: input-injection
rules:
  input_injection:
    enabled: true
    allowed_types:
      - keyboard
"#,
    )
    .expect("valid spec");

    let result = evaluate(
        &spec,
        &EvaluationAction {
            action_type: "input_inject".into(),
            target: Some("mouse".into()),
            ..Default::default()
        },
    );

    assert_eq!(result.decision, Decision::Deny);
    assert_eq!(
        result.matched_rule.as_deref(),
        Some("rules.input_injection.allowed_types")
    );
}

#[test]
fn computer_use_respects_remote_desktop_channel_blocks() {
    let spec = HushSpec::parse(
        r#"
hushspec: "0.1.0"
name: remote-desktop
rules:
  computer_use:
    enabled: true
    mode: observe
    allowed_actions:
      - remote.clipboard
  remote_desktop_channels:
    enabled: true
    clipboard: false
    file_transfer: false
    audio: true
    drive_mapping: false
"#,
    )
    .expect("valid spec");

    let result = evaluate(
        &spec,
        &EvaluationAction {
            action_type: "computer_use".into(),
            target: Some("remote.clipboard".into()),
            ..Default::default()
        },
    );

    assert_eq!(result.decision, Decision::Deny);
    assert_eq!(
        result.matched_rule.as_deref(),
        Some("rules.remote_desktop_channels.clipboard")
    );
}

#[test]
fn origin_profile_tool_access_still_respects_base_blocklist() {
    let spec = HushSpec::parse(
        r#"
hushspec: "0.1.0"
name: origin-tool-access
rules:
  tool_access:
    enabled: true
    allow:
      - "*"
    block:
      - dangerous_tool
    require_confirmation: []
    default: allow
extensions:
  origins:
    default_behavior: deny
    profiles:
      - id: slack
        match:
          provider: slack
        tool_access:
          enabled: true
          allow:
            - "*"
          block: []
          require_confirmation: []
          default: allow
"#,
    )
    .expect("valid spec");

    let result = evaluate(
        &spec,
        &EvaluationAction {
            action_type: "tool_call".into(),
            target: Some("dangerous_tool".into()),
            origin: Some(hushspec::OriginContext {
                provider: Some("slack".into()),
                ..Default::default()
            }),
            ..Default::default()
        },
    );

    assert_eq!(result.decision, Decision::Deny);
    assert_eq!(
        result.matched_rule.as_deref(),
        Some("rules.tool_access.block")
    );
    assert_eq!(result.origin_profile.as_deref(), Some("slack"));
}

#[test]
fn origin_profile_egress_cannot_bypass_base_default_block() {
    let spec = HushSpec::parse(
        r#"
hushspec: "0.1.0"
name: origin-egress
rules:
  egress:
    enabled: true
    allow:
      - api.safe.example.com
    block: []
    default: block
extensions:
  origins:
    default_behavior: deny
    profiles:
      - id: slack
        match:
          provider: slack
        egress:
          enabled: true
          allow: []
          block: []
          default: allow
"#,
    )
    .expect("valid spec");

    let result = evaluate(
        &spec,
        &EvaluationAction {
            action_type: "egress".into(),
            target: Some("evil.example.com".into()),
            origin: Some(hushspec::OriginContext {
                provider: Some("slack".into()),
                ..Default::default()
            }),
            ..Default::default()
        },
    );

    assert_eq!(result.decision, Decision::Deny);
    assert_eq!(
        result.matched_rule.as_deref(),
        Some("extensions.origins.profiles.slack.egress.default")
    );
    assert_eq!(result.origin_profile.as_deref(), Some("slack"));
}

#[test]
fn forbidden_path_exception_still_respects_path_allowlist() {
    let spec = HushSpec::parse(
        r#"
hushspec: "0.1.0"
name: path-guards
rules:
  forbidden_paths:
    enabled: true
    patterns:
      - "**/*.key"
    exceptions:
      - "/workspace/allowed.key"
  path_allowlist:
    enabled: true
    write:
      - "/workspace/reports/**"
"#,
    )
    .expect("valid spec");

    let result = evaluate(
        &spec,
        &EvaluationAction {
            action_type: "file_write".into(),
            target: Some("/workspace/allowed.key".into()),
            ..Default::default()
        },
    );

    assert_eq!(result.decision, Decision::Deny);
    assert_eq!(result.matched_rule.as_deref(), Some("rules.path_allowlist"));
}

#[test]
fn unknown_posture_state_fails_closed() {
    let spec = HushSpec::parse(
        r#"
hushspec: "0.1.0"
name: posture-unknown-state
extensions:
  posture:
    initial: standard
    states:
      standard:
        capabilities: [file_access]
    transitions: []
"#,
    )
    .expect("valid spec");

    let result = evaluate(
        &spec,
        &EvaluationAction {
            action_type: "file_read".into(),
            target: Some("/workspace/readme.md".into()),
            posture: Some(hushspec::PostureContext {
                current: Some("typo".into()),
                signal: None,
            }),
            ..Default::default()
        },
    );

    assert_eq!(result.decision, Decision::Deny);
    assert_eq!(
        result.matched_rule.as_deref(),
        Some("extensions.posture.states.typo")
    );
    assert_eq!(
        result.reason.as_deref(),
        Some("unknown posture state 'typo'")
    );
}
