//! Schema validation tests: globs, regex, placeholder env-vars, version gating.

use super::*;
use std::sync::Mutex;

static ENV_MUTEX: Mutex<()> = Mutex::new(());

#[test]
fn test_default_policy() {
    let policy = Policy::new();
    assert_eq!(policy.version, "1.5.0");
}

#[test]
fn test_policy_yaml_roundtrip() {
    let policy = Policy::new();
    let yaml = policy.to_yaml().unwrap();
    let restored = Policy::from_yaml(&yaml).unwrap();
    assert_eq!(policy.version, restored.version);
}

#[test]
fn test_policy_validation_rejects_invalid_glob() {
    let yaml = r#"
version: "1.1.0"
name: Test
guards:
  forbidden_path:
    patterns:
      - "foo[bar"
"#;

    let err = Policy::from_yaml(yaml).unwrap_err();
    match err {
        Error::PolicyValidation(e) => {
            assert!(!e.is_empty());
            assert!(e
                .errors
                .iter()
                .any(|fe| fe.path == "guards.forbidden_path.patterns[0]"));
        }
        other => panic!("expected policy validation error, got: {}", other),
    }
}

#[test]
fn test_policy_validation_rejects_invalid_domain_glob() {
    let yaml = r#"
version: "1.1.0"
name: Test
guards:
  egress_allowlist:
    allow:
      - "foo[bar"
"#;

    let err = Policy::from_yaml(yaml).unwrap_err();
    match err {
        Error::PolicyValidation(e) => {
            assert!(!e.is_empty());
            assert!(e
                .errors
                .iter()
                .any(|fe| fe.path == "guards.egress_allowlist.allow[0]"));
        }
        other => panic!("expected policy validation error, got: {}", other),
    }
}

#[test]
fn test_policy_validation_rejects_invalid_regex() {
    let yaml = r#"
version: "1.1.0"
name: Test
guards:
  secret_leak:
    patterns:
      - name: bad
        pattern: "("
"#;

    let err = Policy::from_yaml(yaml).unwrap_err();
    match err {
        Error::PolicyValidation(e) => {
            assert!(!e.is_empty());
            assert!(e
                .errors
                .iter()
                .any(|fe| fe.path == "guards.secret_leak.patterns[0].pattern"));
        }
        other => panic!("expected policy validation error, got: {}", other),
    }
}

#[test]
fn test_policy_validation_custom_guards_skips_missing_env_when_disabled() {
    let _lock = ENV_MUTEX.lock().unwrap();

    let missing = "CLAWDSTRIKE_TEST_CUSTOM_GUARD_MISSING_ENV";
    std::env::remove_var(missing);

    let yaml = format!(
        r#"
version: "1.1.0"
name: Test
custom_guards:
  - id: "acme.deny"
    enabled: false
    config:
      api_key: "${{{}}}"
"#,
        missing
    );

    Policy::from_yaml(&yaml).unwrap();
}

#[test]
fn test_policy_validation_custom_guards_requires_env_when_enabled() {
    let _lock = ENV_MUTEX.lock().unwrap();

    let missing = "CLAWDSTRIKE_TEST_CUSTOM_GUARD_MISSING_ENV";
    std::env::remove_var(missing);

    let yaml = format!(
        r#"
version: "1.1.0"
name: Test
custom_guards:
  - id: "acme.deny"
    enabled: true
    config:
      api_key: "${{{}}}"
"#,
        missing
    );

    let err = Policy::from_yaml(&yaml).unwrap_err();
    match err {
        Error::PolicyValidation(e) => {
            assert!(e
                .errors
                .iter()
                .any(|fe| fe.path == "custom_guards[0].config.api_key"));
        }
        other => panic!("expected policy validation error, got: {}", other),
    }
}

#[test]
fn test_policy_validation_plugin_custom_guards_skips_missing_env_when_disabled() {
    let _lock = ENV_MUTEX.lock().unwrap();

    let missing = "CLAWDSTRIKE_TEST_ASYNC_CUSTOM_GUARD_MISSING_ENV";
    std::env::remove_var(missing);

    let yaml = format!(
        r#"
version: "1.1.0"
name: Test
guards:
  custom:
    - package: "clawdstrike-virustotal"
      enabled: false
      config:
        api_key: "${{{}}}"
"#,
        missing
    );

    Policy::from_yaml(&yaml).unwrap();
}

#[test]
fn test_policy_validation_plugin_custom_guards_requires_env_when_enabled() {
    let _lock = ENV_MUTEX.lock().unwrap();

    let missing = "CLAWDSTRIKE_TEST_ASYNC_CUSTOM_GUARD_MISSING_ENV";
    std::env::remove_var(missing);

    let yaml = format!(
        r#"
version: "1.1.0"
name: Test
guards:
  custom:
    - package: "clawdstrike-virustotal"
      enabled: true
      config:
        api_key: "${{{}}}"
"#,
        missing
    );

    let err = Policy::from_yaml(&yaml).unwrap_err();
    match err {
        Error::PolicyValidation(e) => {
            assert!(e
                .errors
                .iter()
                .any(|fe| fe.path == "guards.custom[0].config.api_key"));
        }
        other => panic!("expected policy validation error, got: {}", other),
    }
}

#[test]
fn test_policy_validation_lax_allows_missing_env_vars_but_still_validates_placeholder_syntax() {
    let _lock = ENV_MUTEX.lock().unwrap();

    let missing = "CLAWDSTRIKE_TEST_LAX_PLACEHOLDER_MISSING_ENV";
    std::env::remove_var(missing);

    let yaml = format!(
        r#"
version: "1.1.0"
name: Test
custom_guards:
  - id: "acme.deny"
    enabled: true
    config:
      api_key: "${{{}}}"
"#,
        missing
    );

    let policy = Policy::from_yaml_unvalidated(&yaml).unwrap();
    policy
        .validate_with_options(PolicyValidationOptions::LAX)
        .unwrap();

    let bad_yaml = r#"
version: "1.1.0"
name: Test
custom_guards:
  - id: "acme.deny"
    enabled: true
    config:
      api_key: "${}"
"#;

    let policy = Policy::from_yaml_unvalidated(bad_yaml).unwrap();
    let err = policy
        .validate_with_options(PolicyValidationOptions::LAX)
        .unwrap_err();
    match err {
        Error::PolicyValidation(e) => {
            assert!(e
                .errors
                .iter()
                .any(|fe| fe.message.contains("placeholder ${} is invalid")));
        }
        other => panic!("expected policy validation error, got: {}", other),
    }
}

#[test]
fn test_policy_version_rejects_invalid_semver() {
    let yaml = r#"
version: "1.0"
name: Test
"#;

    let err = Policy::from_yaml(yaml).unwrap_err();
    match err {
        Error::InvalidPolicyVersion { .. } => {}
        other => panic!("expected invalid policy version error, got: {}", other),
    }
}

#[test]
fn test_policy_version_rejects_unsupported_version() {
    let yaml = r#"
version: "2.0.0"
name: Test
"#;

    let err = Policy::from_yaml(yaml).unwrap_err();
    match err {
        Error::UnsupportedPolicyVersion { .. } => {}
        other => panic!("expected unsupported policy version error, got: {}", other),
    }
}

#[test]
fn test_policy_version_accepts_1_2_0() {
    let yaml = r#"
version: "1.2.0"
name: Test
"#;

    let policy = Policy::from_yaml(yaml).unwrap();
    assert_eq!(policy.version, "1.2.0");
}

#[test]
fn test_policy_version_accepts_1_3_0() {
    let yaml = r#"
version: "1.3.0"
name: Test
"#;

    let policy = Policy::from_yaml(yaml).unwrap();
    assert_eq!(policy.version, "1.3.0");
}

#[test]
fn test_policy_version_accepts_1_5_0() {
    let yaml = r#"
version: "1.5.0"
name: Test
"#;

    let policy = Policy::from_yaml(yaml).unwrap();
    assert_eq!(policy.version, "1.5.0");
}

#[test]
fn test_broker_version_gating_rejects_1_4_policy() {
    let yaml = r#"
version: "1.4.0"
name: broker-old
broker:
  enabled: true
  providers:
    - name: "openai"
      host: "api.openai.com"
      exact_paths: ["/v1/responses"]
      methods: ["POST"]
      secret_ref: "openai/dev"
"#;

    let err = Policy::from_yaml(yaml).unwrap_err();
    match err {
        Error::PolicyValidation(e) => {
            assert!(e.errors.iter().any(|fe| fe.path == "broker"
                && fe
                    .message
                    .contains("broker block requires schema version >= 1.5.0")));
        }
        other => panic!("expected policy validation error, got: {}", other),
    }
}

#[test]
fn test_broker_policy_parses_on_1_5() {
    let yaml = r#"
version: "1.5.0"
name: broker-new
broker:
  enabled: true
  providers:
    - name: "openai"
      host: "api.openai.com"
      port: 443
      exact_paths: ["/v1/responses"]
      methods: ["POST"]
      secret_ref: "openai/dev"
      allowed_headers: ["content-type"]
      require_body_sha256: true
"#;

    let policy = Policy::from_yaml(yaml).unwrap();
    let broker = policy.broker.expect("broker config");
    assert!(broker.enabled);
    assert_eq!(broker.providers.len(), 1);
    assert_eq!(broker.providers[0].name, "openai");
    assert_eq!(broker.providers[0].port, Some(443));
    assert_eq!(broker.providers[0].methods, vec![BrokerMethod::POST]);
}

#[test]
fn test_posture_parses_for_1_2_0() {
    let yaml = r#"
version: "1.2.0"
name: Test
posture:
  initial: work
  states:
    work:
      capabilities:
        - file_access
"#;

    let policy = Policy::from_yaml(yaml).unwrap();
    let posture = policy.posture.expect("posture must exist");
    assert_eq!(posture.initial, "work");
    assert!(posture.states.contains_key("work"));
}

#[test]
fn test_posture_rejected_for_1_1_0() {
    let yaml = r#"
version: "1.1.0"
name: Test
posture:
  initial: work
  states:
    work:
      capabilities:
        - file_access
"#;

    let err = Policy::from_yaml(yaml).unwrap_err();
    match err {
        Error::PolicyValidation(e) => {
            assert!(e
                .errors
                .iter()
                .any(|fe| fe.path == "posture"
                    && fe.message == "posture requires policy version 1.2.0"));
        }
        other => panic!("expected policy validation error, got: {}", other),
    }
}

#[test]
fn test_path_allowlist_rejected_for_1_1_0() {
    let yaml = r#"
version: "1.1.0"
name: Test
guards:
  path_allowlist:
    enabled: true
    file_access_allow:
      - "**/repo/**"
"#;

    let err = Policy::from_yaml(yaml).unwrap_err();
    match err {
        Error::PolicyValidation(e) => {
            assert!(e.errors.iter().any(|fe| fe.path == "guards.path_allowlist"
                && fe.message == "path_allowlist requires policy version 1.2.0"));
        }
        other => panic!("expected policy validation error, got: {}", other),
    }
}

#[test]
fn test_path_allowlist_parses_for_1_2_0() {
    let yaml = r#"
version: "1.2.0"
name: Test
guards:
  path_allowlist:
    enabled: true
    file_access_allow:
      - "**/repo/**"
"#;

    let policy = Policy::from_yaml(yaml).unwrap();
    assert!(policy.guards.path_allowlist.is_some());
}

#[test]
fn test_create_guards() {
    let policy = Policy::new();
    let guards = policy.create_guards();

    // Verify guards were created
    assert!(!guards.forbidden_path.is_forbidden("/normal/path"));
    assert!(guards.forbidden_path.is_forbidden("/home/user/.ssh/id_rsa"));
}

#[test]
fn test_policy_version_accepts_1_4_0() {
    let yaml = r#"
version: "1.4.0"
name: Test
"#;

    let policy = Policy::from_yaml(yaml).unwrap();
    assert_eq!(policy.version, "1.4.0");
    assert!(policy.origins.is_none());
}

#[test]
fn test_policy_version_supports_origins_function() {
    assert!(!policy_version_supports_origins("1.1.0"));
    assert!(!policy_version_supports_origins("1.2.0"));
    assert!(!policy_version_supports_origins("1.3.0"));
    assert!(policy_version_supports_origins("1.4.0"));
}

#[test]
fn test_policy_version_supports_broker_function() {
    assert!(!policy_version_supports_broker("1.1.0"));
    assert!(!policy_version_supports_broker("1.4.0"));
    assert!(policy_version_supports_broker("1.5.0"));
}
