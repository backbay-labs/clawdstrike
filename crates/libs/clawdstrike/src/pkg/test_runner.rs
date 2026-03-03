//! Guard test runner for WASM guard plugins.
//!
//! Provides a YAML-based test fixture format and a runner that executes
//! WASM guards against fixtures, comparing actual results to expectations.

use std::path::Path;
use std::time::Instant;

use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};
use crate::guards::Severity;
use crate::plugins::{execute_wasm_guard_bytes, WasmGuardInputEnvelope, WasmGuardRuntimeOptions};

// ---------------------------------------------------------------------------
// Test fixture types (parsed from YAML)
// ---------------------------------------------------------------------------

/// A complete test suite loaded from a YAML fixture file.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GuardTestSuite {
    /// Display name for the test suite.
    pub suite: String,
    /// Guard name to invoke in the WASM module.
    pub guard: String,
    /// Individual test fixtures.
    pub fixtures: Vec<GuardTestFixture>,
}

/// A single test fixture within a suite.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GuardTestFixture {
    /// Human-readable name for this test case.
    pub name: String,
    /// The action to evaluate.
    pub action: FixtureAction,
    /// Optional per-fixture config passed to the guard.
    #[serde(default)]
    pub config: serde_json::Value,
    /// Expected outcome.
    pub expect: FixtureExpectation,
}

/// Describes the action being tested.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FixtureAction {
    /// Action type string (e.g. "file_access", "tool_call", "shell_command").
    #[serde(rename = "type")]
    pub action_type: String,
    /// Remaining fields become the payload.
    #[serde(flatten)]
    pub payload: serde_json::Map<String, serde_json::Value>,
}

/// Expected result of a guard check.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct FixtureExpectation {
    /// Whether the action should be allowed.
    #[serde(default)]
    pub allowed: Option<bool>,
    /// Expected severity (case-insensitive: "info", "warning", "error", "critical").
    #[serde(default)]
    pub severity: Option<String>,
    /// The message must contain this substring.
    #[serde(default)]
    pub message_contains: Option<String>,
    /// The message must equal this exact string.
    #[serde(default)]
    pub message_equals: Option<String>,
}

// ---------------------------------------------------------------------------
// Test result types
// ---------------------------------------------------------------------------

/// Result of running a single test fixture.
#[derive(Clone, Debug)]
pub struct GuardTestResult {
    /// Name of the fixture.
    pub name: String,
    /// Whether the test passed.
    pub passed: bool,
    /// Mismatch details (empty if passed).
    pub mismatches: Vec<TestMismatch>,
    /// How long the test took.
    pub duration: std::time::Duration,
    /// If the guard returned an error instead of a result.
    pub error: Option<String>,
}

/// A single field mismatch between expected and actual.
#[derive(Clone, Debug)]
pub struct TestMismatch {
    pub field: String,
    pub expected: String,
    pub actual: String,
}

// ---------------------------------------------------------------------------
// Parsing
// ---------------------------------------------------------------------------

/// Parse a YAML string into a `GuardTestSuite`.
pub fn parse_guard_test_suite(yaml: &str) -> Result<GuardTestSuite> {
    let suite: GuardTestSuite = serde_yaml::from_str(yaml)?;
    if suite.fixtures.is_empty() {
        return Err(Error::ConfigError(
            "guard test suite must have at least one fixture".to_string(),
        ));
    }
    if suite.guard.trim().is_empty() {
        return Err(Error::ConfigError(
            "guard test suite must specify a non-empty guard name".to_string(),
        ));
    }
    Ok(suite)
}

/// Parse a YAML file into a `GuardTestSuite`.
pub fn parse_guard_test_file(path: &Path) -> Result<GuardTestSuite> {
    let content = std::fs::read_to_string(path).map_err(|e| {
        Error::ConfigError(format!(
            "failed to read guard test file {}: {}",
            path.display(),
            e
        ))
    })?;
    parse_guard_test_suite(&content)
}

// ---------------------------------------------------------------------------
// Runner
// ---------------------------------------------------------------------------

/// Run all fixtures in a test suite against the provided WASM guard bytes.
///
/// If `filter` is `Some`, only fixtures whose name contains the filter string
/// (case-insensitive) will be executed.
pub fn run_guard_tests(
    wasm_bytes: &[u8],
    suite: &GuardTestSuite,
    options: &WasmGuardRuntimeOptions,
    filter: Option<&str>,
) -> Vec<GuardTestResult> {
    let mut results = Vec::new();

    for fixture in &suite.fixtures {
        // Apply filter
        if let Some(f) = filter {
            if !fixture.name.to_lowercase().contains(&f.to_lowercase()) {
                continue;
            }
        }

        let start = Instant::now();
        let result = run_single_fixture(wasm_bytes, &suite.guard, fixture, options);
        let duration = start.elapsed();

        match result {
            Ok((passed, mismatches)) => {
                results.push(GuardTestResult {
                    name: fixture.name.clone(),
                    passed,
                    mismatches,
                    duration,
                    error: None,
                });
            }
            Err(e) => {
                results.push(GuardTestResult {
                    name: fixture.name.clone(),
                    passed: false,
                    mismatches: Vec::new(),
                    duration,
                    error: Some(e.to_string()),
                });
            }
        }
    }

    results
}

fn run_single_fixture(
    wasm_bytes: &[u8],
    guard_name: &str,
    fixture: &GuardTestFixture,
    options: &WasmGuardRuntimeOptions,
) -> Result<(bool, Vec<TestMismatch>)> {
    // Build the payload from the fixture action
    let mut payload = serde_json::Value::Object(fixture.action.payload.clone());
    // Ensure the action_type is in the payload for guards that inspect it
    if let serde_json::Value::Object(ref mut map) = payload {
        map.entry("type".to_string())
            .or_insert_with(|| serde_json::Value::String(fixture.action.action_type.clone()));
    }

    let envelope = WasmGuardInputEnvelope {
        guard: guard_name.to_string(),
        action_type: Some(fixture.action.action_type.clone()),
        payload,
        config: fixture.config.clone(),
    };

    let execution = execute_wasm_guard_bytes(wasm_bytes, &envelope, options)?;
    let result = &execution.result;
    let mut mismatches = Vec::new();

    // Check allowed
    if let Some(expected_allowed) = fixture.expect.allowed {
        if result.allowed != expected_allowed {
            mismatches.push(TestMismatch {
                field: "allowed".to_string(),
                expected: expected_allowed.to_string(),
                actual: result.allowed.to_string(),
            });
        }
    }

    // Check severity
    if let Some(ref expected_sev) = fixture.expect.severity {
        let actual_sev = severity_to_string(&result.severity);
        if !expected_sev.eq_ignore_ascii_case(&actual_sev) {
            mismatches.push(TestMismatch {
                field: "severity".to_string(),
                expected: expected_sev.clone(),
                actual: actual_sev,
            });
        }
    }

    // Check message_contains
    if let Some(ref expected_substr) = fixture.expect.message_contains {
        if !result
            .message
            .to_lowercase()
            .contains(&expected_substr.to_lowercase())
        {
            mismatches.push(TestMismatch {
                field: "message_contains".to_string(),
                expected: expected_substr.clone(),
                actual: result.message.clone(),
            });
        }
    }

    // Check message_equals
    if let Some(ref expected_msg) = fixture.expect.message_equals {
        if result.message != *expected_msg {
            mismatches.push(TestMismatch {
                field: "message_equals".to_string(),
                expected: expected_msg.clone(),
                actual: result.message.clone(),
            });
        }
    }

    let passed = mismatches.is_empty();
    Ok((passed, mismatches))
}

fn severity_to_string(severity: &Severity) -> String {
    match severity {
        Severity::Info => "info".to_string(),
        Severity::Warning => "warning".to_string(),
        Severity::Error => "error".to_string(),
        Severity::Critical => "critical".to_string(),
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_basic_test_suite() {
        let yaml = r#"
suite: "Basic Tests"
guard: "my-guard"
fixtures:
  - name: "blocks sensitive path"
    action:
      type: "file_access"
      path: "/etc/shadow"
    expect:
      allowed: false
      severity: "error"
      message_contains: "blocked"
"#;
        let suite = parse_guard_test_suite(yaml).unwrap();
        assert_eq!(suite.suite, "Basic Tests");
        assert_eq!(suite.guard, "my-guard");
        assert_eq!(suite.fixtures.len(), 1);
        assert_eq!(suite.fixtures[0].name, "blocks sensitive path");
        assert_eq!(suite.fixtures[0].action.action_type, "file_access");
        assert_eq!(suite.fixtures[0].expect.allowed, Some(false));
        assert_eq!(suite.fixtures[0].expect.severity.as_deref(), Some("error"));
        assert_eq!(
            suite.fixtures[0].expect.message_contains.as_deref(),
            Some("blocked")
        );
    }

    #[test]
    fn parses_suite_with_config_and_multiple_fixtures() {
        let yaml = r#"
suite: "Multi Fixture"
guard: "phi-access"
fixtures:
  - name: "blocks patient records"
    action:
      type: "file_access"
      path: "/data/patients/record-001.json"
    config:
      strict: true
    expect:
      allowed: false
  - name: "allows public docs"
    action:
      type: "file_access"
      path: "/docs/public/readme.md"
    expect:
      allowed: true
"#;
        let suite = parse_guard_test_suite(yaml).unwrap();
        assert_eq!(suite.fixtures.len(), 2);
        assert_eq!(suite.fixtures[0].config["strict"], true);
        assert_eq!(suite.fixtures[1].expect.allowed, Some(true));
    }

    #[test]
    fn rejects_empty_fixtures() {
        let yaml = r#"
suite: "Empty"
guard: "my-guard"
fixtures: []
"#;
        let err = parse_guard_test_suite(yaml).unwrap_err();
        assert!(err.to_string().contains("at least one fixture"));
    }

    #[test]
    fn rejects_empty_guard_name() {
        let yaml = r#"
suite: "No Guard"
guard: "  "
fixtures:
  - name: "test"
    action:
      type: "file_access"
      path: "/tmp"
    expect:
      allowed: true
"#;
        let err = parse_guard_test_suite(yaml).unwrap_err();
        assert!(err.to_string().contains("non-empty guard name"));
    }

    #[test]
    fn parses_message_equals_expectation() {
        let yaml = r#"
suite: "Exact Msg"
guard: "my-guard"
fixtures:
  - name: "exact message check"
    action:
      type: "tool_call"
      tool: "dangerous_tool"
    expect:
      allowed: false
      message_equals: "Denied by policy"
"#;
        let suite = parse_guard_test_suite(yaml).unwrap();
        assert_eq!(
            suite.fixtures[0].expect.message_equals.as_deref(),
            Some("Denied by policy")
        );
    }

    // -- Matching logic tests (no WASM needed) --

    #[test]
    fn severity_to_string_all_variants() {
        assert_eq!(severity_to_string(&Severity::Info), "info");
        assert_eq!(severity_to_string(&Severity::Warning), "warning");
        assert_eq!(severity_to_string(&Severity::Error), "error");
        assert_eq!(severity_to_string(&Severity::Critical), "critical");
    }

    #[test]
    fn fixture_action_captures_extra_fields() {
        let yaml = r#"
suite: "Payload"
guard: "my-guard"
fixtures:
  - name: "extra fields"
    action:
      type: "shell_command"
      command: "rm -rf /"
      working_dir: "/tmp"
    expect:
      allowed: false
"#;
        let suite = parse_guard_test_suite(yaml).unwrap();
        let action = &suite.fixtures[0].action;
        assert_eq!(action.action_type, "shell_command");
        assert_eq!(action.payload.get("command").unwrap(), "rm -rf /");
        assert_eq!(action.payload.get("working_dir").unwrap(), "/tmp");
    }

    // -- Integration test with a real WASM guard --

    #[test]
    fn runs_test_against_wasm_guard_deny() {
        // A WASM guard that always denies with message "Blocked by test guard"
        // JSON is 70 bytes
        let wasm = wat::parse_str(
            r#"(module
                (import "clawdstrike_host" "set_output" (func $set_output (param i32 i32) (result i32)))
                (import "clawdstrike_host" "request_capability" (func $cap (param i32) (result i32)))
                (memory (export "memory") 1)
                (data (i32.const 64) "{\"allowed\":false,\"severity\":\"error\",\"message\":\"Blocked by test guard\"}")
                (func (export "clawdstrike_guard_init") (result i32)
                  i32.const 1)
                (func (export "clawdstrike_guard_handles") (param i32 i32) (result i32)
                  i32.const 1)
                (func (export "clawdstrike_guard_check") (param i32 i32) (result i32)
                  i32.const 64
                  i32.const 70
                  call $set_output
                  drop
                  i32.const 0)
            )"#,
        )
        .expect("valid wat");

        let suite = parse_guard_test_suite(
            r#"
suite: "Deny Guard Tests"
guard: "test-deny"
fixtures:
  - name: "should be denied"
    action:
      type: "file_access"
      path: "/etc/shadow"
    expect:
      allowed: false
      severity: "error"
      message_contains: "Blocked"
  - name: "should fail if expecting allow"
    action:
      type: "file_access"
      path: "/tmp/safe"
    expect:
      allowed: true
"#,
        )
        .unwrap();

        let results = run_guard_tests(&wasm, &suite, &WasmGuardRuntimeOptions::default(), None);
        assert_eq!(results.len(), 2);

        // First fixture should pass (expecting deny, got deny)
        assert!(results[0].passed, "first fixture should pass");
        assert!(results[0].mismatches.is_empty());

        // Second fixture should fail (expecting allow, got deny)
        assert!(!results[1].passed, "second fixture should fail");
        assert_eq!(results[1].mismatches.len(), 1);
        assert_eq!(results[1].mismatches[0].field, "allowed");
    }

    #[test]
    fn runs_test_against_wasm_guard_allow() {
        // A WASM guard that always allows
        // JSON is 68 bytes
        let wasm = wat::parse_str(
            r#"(module
                (import "clawdstrike_host" "set_output" (func $set_output (param i32 i32) (result i32)))
                (import "clawdstrike_host" "request_capability" (func $cap (param i32) (result i32)))
                (memory (export "memory") 1)
                (data (i32.const 64) "{\"allowed\":true,\"severity\":\"info\",\"message\":\"Allowed by test guard\"}")
                (func (export "clawdstrike_guard_init") (result i32)
                  i32.const 1)
                (func (export "clawdstrike_guard_handles") (param i32 i32) (result i32)
                  i32.const 1)
                (func (export "clawdstrike_guard_check") (param i32 i32) (result i32)
                  i32.const 64
                  i32.const 68
                  call $set_output
                  drop
                  i32.const 0)
            )"#,
        )
        .expect("valid wat");

        let suite = parse_guard_test_suite(
            r#"
suite: "Allow Guard Tests"
guard: "test-allow"
fixtures:
  - name: "should be allowed"
    action:
      type: "file_access"
      path: "/tmp/safe"
    expect:
      allowed: true
      severity: "info"
      message_equals: "Allowed by test guard"
"#,
        )
        .unwrap();

        let results = run_guard_tests(&wasm, &suite, &WasmGuardRuntimeOptions::default(), None);
        assert_eq!(results.len(), 1);
        assert!(results[0].passed, "fixture should pass");
    }

    #[test]
    fn filter_selects_matching_fixtures() {
        let wasm = wat::parse_str(
            r#"(module
                (import "clawdstrike_host" "set_output" (func $set_output (param i32 i32) (result i32)))
                (import "clawdstrike_host" "request_capability" (func $cap (param i32) (result i32)))
                (memory (export "memory") 1)
                (data (i32.const 64) "{\"allowed\":false,\"severity\":\"error\",\"message\":\"denied\"}")
                (func (export "clawdstrike_guard_init") (result i32)
                  i32.const 1)
                (func (export "clawdstrike_guard_handles") (param i32 i32) (result i32)
                  i32.const 1)
                (func (export "clawdstrike_guard_check") (param i32 i32) (result i32)
                  i32.const 64
                  i32.const 55
                  call $set_output
                  drop
                  i32.const 0)
            )"#,
        )
        .expect("valid wat");

        let suite = parse_guard_test_suite(
            r#"
suite: "Filter Tests"
guard: "test-guard"
fixtures:
  - name: "alpha test"
    action:
      type: "file_access"
      path: "/etc/shadow"
    expect:
      allowed: false
  - name: "beta test"
    action:
      type: "file_access"
      path: "/tmp/foo"
    expect:
      allowed: false
  - name: "alpha check"
    action:
      type: "file_access"
      path: "/etc/passwd"
    expect:
      allowed: false
"#,
        )
        .unwrap();

        let results = run_guard_tests(
            &wasm,
            &suite,
            &WasmGuardRuntimeOptions::default(),
            Some("alpha"),
        );
        assert_eq!(results.len(), 2);
        assert!(results.iter().all(|r| r.name.contains("alpha")));
    }

    #[test]
    fn message_contains_is_case_insensitive() {
        // JSON is 65 bytes
        let wasm = wat::parse_str(
            r#"(module
                (import "clawdstrike_host" "set_output" (func $set_output (param i32 i32) (result i32)))
                (import "clawdstrike_host" "request_capability" (func $cap (param i32) (result i32)))
                (memory (export "memory") 1)
                (data (i32.const 64) "{\"allowed\":false,\"severity\":\"error\",\"message\":\"BLOCKED by Guard\"}")
                (func (export "clawdstrike_guard_init") (result i32)
                  i32.const 1)
                (func (export "clawdstrike_guard_handles") (param i32 i32) (result i32)
                  i32.const 1)
                (func (export "clawdstrike_guard_check") (param i32 i32) (result i32)
                  i32.const 64
                  i32.const 65
                  call $set_output
                  drop
                  i32.const 0)
            )"#,
        )
        .expect("valid wat");

        let suite = parse_guard_test_suite(
            r#"
suite: "Case Insensitive"
guard: "test-guard"
fixtures:
  - name: "case test"
    action:
      type: "file_access"
      path: "/etc/shadow"
    expect:
      allowed: false
      message_contains: "blocked"
"#,
        )
        .unwrap();

        let results = run_guard_tests(&wasm, &suite, &WasmGuardRuntimeOptions::default(), None);
        assert!(results[0].passed, "case-insensitive match should pass");
    }
}
