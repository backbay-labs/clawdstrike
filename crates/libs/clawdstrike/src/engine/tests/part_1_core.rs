//! Engine core tests (part 1).
#![allow(clippy::expect_used, clippy::unwrap_used)]

use super::*;

#[tokio::test]
async fn test_engine_new() {
    let engine = HushEngine::new();
    let stats = engine.stats().await;
    assert_eq!(stats.action_count, 0);
    assert_eq!(stats.violation_count, 0);
}

#[tokio::test]
async fn test_check_file_access() {
    let engine = HushEngine::new();
    let context = GuardContext::new();

    // Normal file should be allowed
    let result = engine
        .check_file_access("/app/src/main.rs", &context)
        .await
        .unwrap();
    assert!(result.allowed);

    // SSH key should be blocked
    let result = engine
        .check_file_access("/home/user/.ssh/id_rsa", &context)
        .await
        .unwrap();
    assert!(!result.allowed);
}

#[tokio::test]
async fn test_extra_guard_executes_for_custom_action() {
    let calls = Arc::new(AtomicUsize::new(0));

    let engine = HushEngine::new().with_extra_guard(TestExtraGuard {
        name: "extra_guard_test",
        calls: calls.clone(),
    });
    let context = GuardContext::new();
    let payload = serde_json::json!({ "test": true });

    let report = engine
        .check_action_report(&GuardAction::Custom("extra_guard_test", &payload), &context)
        .await
        .unwrap();

    assert_eq!(calls.load(Ordering::Relaxed), 1);
    assert_eq!(report.per_guard.len(), 1);
    assert_eq!(report.per_guard[0].guard, "extra_guard_test");
}

#[tokio::test]
async fn test_extra_guard_runs_after_builtins() {
    let calls = Arc::new(AtomicUsize::new(0));

    let engine = HushEngine::new().with_extra_guard(TestExtraGuard {
        name: "extra_guard_order",
        calls: calls.clone(),
    });
    let context = GuardContext::new();

    let report = engine
        .check_action_report(&GuardAction::FileAccess("/app/src/main.rs"), &context)
        .await
        .unwrap();

    assert_eq!(calls.load(Ordering::Relaxed), 1);
    assert!(report.overall.allowed);
    assert!(report
        .per_guard
        .iter()
        .any(|r| r.guard != "extra_guard_order"));
    assert_eq!(
        report.per_guard.last().map(|r| r.guard.as_str()),
        Some("extra_guard_order")
    );
    assert_eq!(
        report
            .per_guard
            .iter()
            .filter(|r| r.guard == "extra_guard_order")
            .count(),
        1
    );
}

#[tokio::test]
async fn test_fail_fast_skips_extra_guards_after_deny() {
    let calls = Arc::new(AtomicUsize::new(0));

    let mut policy = Policy::new();
    policy.settings.fail_fast = Some(true);

    let engine = HushEngine::with_policy(policy).with_extra_guard(TestExtraGuard {
        name: "extra_guard_order",
        calls: calls.clone(),
    });
    let context = GuardContext::new();

    let report = engine
        .check_action_report(&GuardAction::FileAccess("/home/user/.ssh/id_rsa"), &context)
        .await
        .unwrap();

    assert!(!report.overall.allowed);
    assert_eq!(calls.load(Ordering::Relaxed), 0);
}

#[tokio::test]
async fn test_check_egress() {
    let engine = HushEngine::new();
    let context = GuardContext::new();

    // Allowed API
    let result = engine
        .check_egress("api.openai.com", 443, &context)
        .await
        .unwrap();
    assert!(result.allowed);

    // Unknown domain blocked
    let result = engine
        .check_egress("evil.com", 443, &context)
        .await
        .unwrap();
    assert!(!result.allowed);
}

#[tokio::test]
async fn test_warn_aggregation_across_guards() {
    let engine = HushEngine::new();
    let context = GuardContext::new();

    let diff = r#"
--- a/src/lib.rs
+++ b/src/lib.rs
@@ -1 +1 @@
+api_key = "0123456789abcdef0123456789abcdef"
"#;

    let report = engine
        .check_action_report(&GuardAction::Patch("src/lib.rs", diff), &context)
        .await
        .unwrap();

    assert!(report.overall.allowed);
    assert_eq!(report.overall.severity, Severity::Warning);
    assert!(report.per_guard.iter().any(|r| r.guard == "secret_leak"));
}

#[test]
fn aggregate_overall_prefers_sanitize_over_plain_warning_on_tie() {
    let plain_warning = GuardResult::warn("warn_guard", "warning only");
    let sanitize_warning = GuardResult::sanitize(
        "sanitize_guard",
        "sanitized content",
        "dangerous input",
        "safe input",
    );

    let overall = aggregate_overall(&[plain_warning, sanitize_warning.clone()]);

    assert!(overall.allowed);
    assert_eq!(overall.severity, Severity::Warning);
    assert_eq!(overall.guard, "sanitize_guard");
    assert!(overall.is_sanitized());
    assert_eq!(
        overall.details.as_ref().and_then(|d| d.get("sanitized")),
        sanitize_warning
            .details
            .as_ref()
            .and_then(|d| d.get("sanitized"))
    );
}

#[tokio::test]
async fn test_evaluation_path_records_fast_and_std_paths() {
    let engine = HushEngine::new();
    let context = GuardContext::new();

    let report = engine
        .check_action_report(
            &GuardAction::FileWrite("/app/src/main.rs", b"hello"),
            &context,
        )
        .await
        .unwrap();

    let path = report
        .evaluation_path
        .expect("evaluation path should be present");
    assert_eq!(
        path.stages,
        vec!["fast_path".to_string(), "std_path".to_string()]
    );
    assert!(path.stage_timings_us.contains_key("fast_path"));
    assert!(path.stage_timings_us.contains_key("std_path"));
    assert!(path.guard_sequence.iter().any(|g| g == "forbidden_path"));
    assert!(path.guard_sequence.iter().any(|g| g == "secret_leak"));
}

#[tokio::test]
async fn test_evaluation_path_records_deep_path_with_async_guards() {
    let mut engine = HushEngine::new();
    engine.async_guards = vec![Arc::new(TestAsyncAllowGuard::new())];

    let context = GuardContext::new();
    let report = engine
        .check_action_report(&GuardAction::FileAccess("/app/src/main.rs"), &context)
        .await
        .unwrap();

    let path = report
        .evaluation_path
        .expect("evaluation path should be present");
    assert_eq!(
        path.stages,
        vec!["fast_path".to_string(), "deep_path".to_string()]
    );
    assert!(path.stage_timings_us.contains_key("fast_path"));
    assert!(path.stage_timings_us.contains_key("deep_path"));
    assert!(path.guard_sequence.iter().any(|g| g == "test_async_allow"));
}

#[tokio::test]
async fn test_violation_tracking() {
    let engine = HushEngine::new();
    let context = GuardContext::new();

    // Cause a violation
    let _ = engine
        .check_file_access("/home/user/.ssh/id_rsa", &context)
        .await
        .unwrap();

    let stats = engine.stats().await;
    assert_eq!(stats.action_count, 1);
    assert_eq!(stats.violation_count, 1);
}

#[tokio::test]
async fn test_create_receipt() {
    let engine = HushEngine::new().with_generated_keypair();
    let context = GuardContext::new();

    // Normal action
    let _ = engine
        .check_file_access("/app/main.rs", &context)
        .await
        .unwrap();

    let content_hash = sha256(b"test content");
    let receipt = engine.create_receipt(content_hash).await.unwrap();

    assert!(receipt.verdict.passed);
    assert!(receipt.provenance.is_some());
}

#[tokio::test]
async fn test_receipt_metadata_omitted_without_extra_guards() {
    let engine = HushEngine::new();
    let receipt = engine
        .create_receipt(sha256(b"test content"))
        .await
        .unwrap();
    assert!(receipt.metadata.is_none());
}

#[tokio::test]
async fn test_receipt_metadata_includes_extra_guards() {
    let calls = Arc::new(AtomicUsize::new(0));

    let engine = HushEngine::new().with_extra_guard(TestExtraGuard {
        name: "extra_guard_metadata",
        calls: calls.clone(),
    });
    let receipt = engine
        .create_receipt(sha256(b"test content"))
        .await
        .unwrap();

    let metadata = receipt.metadata.expect("expected receipt metadata");
    assert_eq!(
        metadata["clawdstrike"]["extra_guards"],
        serde_json::json!(["extra_guard_metadata"])
    );
}

#[tokio::test]
async fn test_receipt_metadata_includes_evaluation_path() {
    let engine = HushEngine::new();
    let context = GuardContext::new();

    let _ = engine
        .check_action_report(
            &GuardAction::FileWrite("/app/src/main.rs", b"hello"),
            &context,
        )
        .await
        .unwrap();

    let receipt = engine
        .create_receipt(sha256(b"test content"))
        .await
        .unwrap();
    let metadata = receipt.metadata.expect("expected receipt metadata");
    assert_eq!(
        metadata.pointer("/clawdstrike/evaluation/last_path"),
        Some(&serde_json::json!("fast_path -> std_path"))
    );
    assert!(metadata
        .pointer("/clawdstrike/evaluation/last/stage_timings_us/fast_path")
        .is_some());
    let observed = metadata
        .pointer("/clawdstrike/evaluation/observed_paths")
        .and_then(|v| v.as_object())
        .expect("observed path map");
    assert_eq!(
        observed.get("fast_path -> std_path"),
        Some(&serde_json::json!(1))
    );
}

#[tokio::test]
async fn test_pipeline_perf_measurement_metadata_present() {
    let engine = HushEngine::new();
    let context = GuardContext::new();

    for _ in 0..32 {
        let _ = engine
            .check_action_report(&GuardAction::FileAccess("/app/src/main.rs"), &context)
            .await
            .unwrap();
    }

    let receipt = engine
        .create_receipt(sha256(b"pipeline-perf"))
        .await
        .unwrap();
    let metadata = receipt.metadata.expect("expected receipt metadata");
    let timings = metadata
        .pointer("/clawdstrike/evaluation/last/stage_timings_us")
        .and_then(|v| v.as_object())
        .expect("expected stage timings");
    assert!(!timings.is_empty());
}

#[tokio::test]
async fn test_create_signed_receipt() {
    let engine = HushEngine::new().with_generated_keypair();
    let context = GuardContext::new();

    let _ = engine
        .check_file_access("/app/main.rs", &context)
        .await
        .unwrap();

    let content_hash = sha256(b"test content");
    let signed = engine.create_signed_receipt(content_hash).await.unwrap();

    assert!(signed.receipt.verdict.passed);
}

#[tokio::test]
async fn test_from_ruleset() {
    let engine = HushEngine::from_ruleset("strict").unwrap();
    let context = GuardContext::new();

    // Strict ruleset blocks unknown egress
    let result = engine
        .check_egress("random.com", 443, &context)
        .await
        .unwrap();
    assert!(!result.allowed);
}

#[tokio::test]
async fn test_reset() {
    let engine = HushEngine::new();
    let context = GuardContext::new();

    let _ = engine
        .check_file_access("/home/user/.ssh/id_rsa", &context)
        .await
        .unwrap();
    assert_eq!(engine.stats().await.violation_count, 1);

    engine.reset().await;
    assert_eq!(engine.stats().await.violation_count, 0);
}

struct AlwaysWarnGuard;

#[async_trait]
impl Guard for AlwaysWarnGuard {
    fn name(&self) -> &str {
        "acme.always_warn"
    }

    fn handles(&self, _action: &GuardAction<'_>) -> bool {
        true
    }

    async fn check(&self, _action: &GuardAction<'_>, _context: &GuardContext) -> GuardResult {
        GuardResult::warn(self.name(), "Policy-driven custom guard warning")
    }
}

struct AlwaysWarnFactory;

impl crate::guards::CustomGuardFactory for AlwaysWarnFactory {
    fn id(&self) -> &str {
        "acme.always_warn"
    }

    fn build(&self, _config: serde_json::Value) -> Result<Box<dyn Guard>> {
        Ok(Box::new(AlwaysWarnGuard))
    }
}

struct ExpectTokenFactory;

impl crate::guards::CustomGuardFactory for ExpectTokenFactory {
    fn id(&self) -> &str {
        "acme.expect_token"
    }

    fn build(&self, config: serde_json::Value) -> Result<Box<dyn Guard>> {
        let token = config
            .get("token")
            .and_then(|v| v.as_str())
            .unwrap_or_default();
        if token != "sekret" {
            return Err(Error::ConfigError(format!(
                "expected token 'sekret' but got {:?}",
                token
            )));
        }
        Ok(Box::new(AlwaysWarnGuard))
    }
}

#[tokio::test]
async fn test_policy_custom_guards_run_after_builtins_when_registry_provided() {
    let yaml = r#"
version: "1.1.0"
name: Custom
custom_guards:
  - id: "acme.always_warn"
    enabled: true
    config: {}
"#;
    let policy = Policy::from_yaml(yaml).unwrap();

    let mut registry = CustomGuardRegistry::new();
    registry.register(AlwaysWarnFactory);

    let engine = HushEngine::builder(policy)
        .with_custom_guard_registry(registry)
        .build()
        .unwrap();

    let context = GuardContext::new();
    let report = engine
        .check_action_report(&GuardAction::FileAccess("/app/src/main.rs"), &context)
        .await
        .unwrap();

    assert!(report.overall.allowed);
    assert_eq!(report.overall.severity, Severity::Warning);
    assert_eq!(
        report.per_guard.last().map(|r| r.guard.as_str()),
        Some("acme.always_warn")
    );
}

#[tokio::test]
async fn test_policy_custom_guards_resolve_placeholders_in_config_before_build() {
    let key = "HC_TEST_CUSTOM_GUARD_TOKEN";
    let prev = std::env::var(key).ok();
    std::env::set_var(key, "sekret");

    let yaml = format!(
        r#"
version: "1.1.0"
name: Custom
custom_guards:
  - id: "acme.expect_token"
    enabled: true
    config:
      token: "${{{}}}"
"#,
        key
    );
    let policy = Policy::from_yaml(&yaml).unwrap();

    let mut registry = CustomGuardRegistry::new();
    registry.register(ExpectTokenFactory);

    let engine = HushEngine::builder(policy)
        .with_custom_guard_registry(registry)
        .build()
        .unwrap();

    let context = GuardContext::new();
    let report = engine
        .check_action_report(&GuardAction::FileAccess("/app/src/main.rs"), &context)
        .await
        .unwrap();
    assert!(report.overall.allowed);

    match prev {
        Some(v) => std::env::set_var(key, v),
        None => std::env::remove_var(key),
    }
}

#[test]
fn test_policy_custom_guards_missing_env_placeholder_fails_closed() {
    let key = "HC_TEST_MISSING_CUSTOM_GUARD_ENV";
    let prev = std::env::var(key).ok();
    std::env::remove_var(key);

    let yaml = format!(
        r#"
version: "1.1.0"
name: Custom
custom_guards:
  - id: "acme.expect_token"
    enabled: true
    config:
      token: "${{{}}}"
"#,
        key
    );

    let err = Policy::from_yaml(&yaml).unwrap_err();
    assert!(err.to_string().contains(key));

    match prev {
        Some(v) => std::env::set_var(key, v),
        None => std::env::remove_var(key),
    }
}

#[tokio::test]
async fn test_policy_custom_guards_fail_closed_when_registry_missing() {
    let yaml = r#"
version: "1.1.0"
name: Custom
custom_guards:
  - id: "acme.always_warn"
    enabled: true
    config: {}
"#;
    let policy = Policy::from_yaml(yaml).unwrap();

    // Builder should fail closed.
    let err = match HushEngine::builder(policy.clone()).build() {
        Ok(_) => panic!("Expected builder to fail without CustomGuardRegistry"),
        Err(e) => e,
    };
    assert!(err.to_string().contains("CustomGuardRegistry"));

    // Legacy constructor should also fail closed at evaluation time.
    let engine = HushEngine::with_policy(policy);
    let context = GuardContext::new();
    let err = engine
        .check_action_report(&GuardAction::FileAccess("/app/src/main.rs"), &context)
        .await
        .unwrap_err();
    assert!(err.to_string().contains("CustomGuardRegistry"));
}

#[tokio::test]
async fn test_posture_precheck_denies_missing_capability() {
    let policy = Policy::from_yaml(
        r#"
version: "1.2.0"
name: "posture-precheck"
posture:
  initial: work
  states:
    work:
      capabilities: [file_access]
      budgets: {}
"#,
    )
    .unwrap();

    let engine = HushEngine::with_policy(policy);
    let context = GuardContext::new();
    let mut posture = None;

    let report = engine
        .check_action_report_with_posture(
            &GuardAction::FileWrite("/tmp/out.txt", b"ok"),
            &context,
            &mut posture,
        )
        .await
        .unwrap();

    assert!(!report.guard_report.overall.allowed);
    assert_eq!(report.guard_report.overall.guard, "posture");
    assert_eq!(report.posture_after, "work");
}

#[tokio::test]
async fn test_posture_precheck_denial_counts_as_violation_and_fails_receipt() {
    let policy = Policy::from_yaml(
        r#"
version: "1.2.0"
name: "posture-precheck-receipt"
posture:
  initial: work
  states:
    work:
      capabilities: [file_access]
      budgets: {}
"#,
    )
    .unwrap();

    let engine = HushEngine::with_policy(policy);
    let context = GuardContext::new();
    let mut posture = None;

    let report = engine
        .check_action_report_with_posture(
            &GuardAction::ShellCommand("echo hi"),
            &context,
            &mut posture,
        )
        .await
        .unwrap();
    assert!(!report.guard_report.overall.allowed);

    let stats = engine.stats().await;
    assert_eq!(stats.action_count, 1);
    assert_eq!(stats.violation_count, 1);

    let receipt = engine
        .create_receipt(sha256(b"posture-precheck-denial"))
        .await
        .unwrap();
    assert!(!receipt.verdict.passed);
    let provenance = receipt
        .provenance
        .expect("receipt should include provenance");
    assert_eq!(provenance.violations.len(), 1);
    assert_eq!(provenance.violations[0].guard, "posture");
}

#[tokio::test]
async fn test_posture_budget_exhaustion_triggers_transition() {
    let policy = Policy::from_yaml(
        r#"
version: "1.2.0"
name: "posture-budget"
posture:
  initial: work
  states:
    work:
      capabilities: [file_write]
      budgets:
        file_writes: 1
    quarantine:
      capabilities: []
      budgets: {}
  transitions:
    - { from: "*", to: quarantine, on: budget_exhausted }
"#,
    )
    .unwrap();

    let engine = HushEngine::with_policy(policy);
    let context = GuardContext::new();
    let mut posture = None;

    let report = engine
        .check_action_report_with_posture(
            &GuardAction::FileWrite("/tmp/out.txt", b"ok"),
            &context,
            &mut posture,
        )
        .await
        .unwrap();

    assert!(report.guard_report.overall.allowed);
    assert_eq!(report.posture_after, "quarantine");
    assert_eq!(
        report.transition.as_ref().map(|t| t.trigger.as_str()),
        Some("budget_exhausted")
    );
}

#[tokio::test]
async fn test_posture_any_violation_transition() {
    let policy = Policy::from_yaml(
        r#"
version: "1.2.0"
name: "posture-any-violation"
posture:
  initial: work
  states:
    work:
      capabilities: [egress]
      budgets: {}
    quarantine:
      capabilities: []
      budgets: {}
  transitions:
    - { from: "*", to: quarantine, on: any_violation }
"#,
    )
    .unwrap();

    let engine = HushEngine::with_policy(policy);
    let context = GuardContext::new();
    let mut posture = None;

    let report = engine
        .check_action_report_with_posture(
            &GuardAction::NetworkEgress("evil.example", 443),
            &context,
            &mut posture,
        )
        .await
        .unwrap();

    assert!(!report.guard_report.overall.allowed);
    assert_eq!(report.posture_after, "quarantine");
    assert_eq!(
        report.transition.as_ref().map(|t| t.trigger.as_str()),
        Some("any_violation")
    );
}

#[tokio::test]
async fn test_posture_critical_violation_transition() {
    let policy = Policy::from_yaml(
        r#"
version: "1.2.0"
name: "posture-critical-violation"
posture:
  initial: work
  states:
    work:
      capabilities: [file_write]
      budgets: {}
    quarantine:
      capabilities: []
      budgets: {}
  transitions:
    - { from: "*", to: quarantine, on: critical_violation }
"#,
    )
    .unwrap();

    let engine = HushEngine::with_policy(policy);
    let context = GuardContext::new();
    let mut posture = None;

    let report = engine
        .check_action_report_with_posture(
            &GuardAction::FileWrite("/tmp/output.txt", b"AKIAABCDEFGHIJKLMNOP"),
            &context,
            &mut posture,
        )
        .await
        .unwrap();

    assert!(!report.guard_report.overall.allowed);
    assert_eq!(report.guard_report.overall.severity, Severity::Critical);
    assert_eq!(report.posture_after, "quarantine");
    assert_eq!(
        report.transition.as_ref().map(|t| t.trigger.as_str()),
        Some("critical_violation")
    );
}

#[tokio::test]
async fn test_posture_timeout_transition_applied_on_request() {
    let policy = Policy::from_yaml(
        r#"
version: "1.2.0"
name: "posture-timeout"
posture:
  initial: elevated
  states:
    elevated:
      capabilities: [file_access]
      budgets: {}
    work:
      capabilities: [file_access]
      budgets: {}
  transitions:
    - { from: elevated, to: work, on: timeout, after: 1s }
"#,
    )
    .unwrap();

    let engine = HushEngine::with_policy(policy);
    let context = GuardContext::new();
    let mut posture = Some(PostureRuntimeState {
        current_state: "elevated".to_string(),
        entered_at: "2026-01-01T00:00:00Z".to_string(),
        transition_history: Vec::new(),
        budgets: HashMap::new(),
        origin_runtime: None,
    });

    let report = engine
        .check_action_report_with_posture(
            &GuardAction::FileAccess("/tmp/readme.md"),
            &context,
            &mut posture,
        )
        .await
        .unwrap();

    assert!(report.guard_report.overall.allowed);
    assert_eq!(report.posture_after, "work");
    assert_eq!(
        report.transition.as_ref().map(|t| t.trigger.as_str()),
        Some("timeout")
    );
}
