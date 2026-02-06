use std::collections::BTreeMap;
use std::io::Write;
use std::path::{Path, PathBuf};

use anyhow::Context as _;
use clawdstrike::{
    GuardReport, HushEngine, PostureRuntimeState, PostureTransitionRecord, Severity,
};
use serde::Deserialize;

use crate::policy_event::{map_policy_event, PolicyEvent};
use crate::remote_extends::RemoteExtendsConfig;
use crate::{CliJsonError, ExitCode, CLI_JSON_VERSION};

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct PolicyTestFile {
    name: String,
    #[serde(default)]
    #[allow(dead_code)]
    description: Option<String>,
    policy: String,
    #[serde(default)]
    suites: Vec<PolicyTestSuite>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct PolicyTestSuite {
    name: String,
    #[serde(default)]
    parameters: BTreeMap<String, Vec<serde_yaml::Value>>,
    #[serde(default)]
    tests: Vec<PolicyTestCase>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct PolicyTestCase {
    name: String,
    input: serde_yaml::Value,
    expect: PolicyTestExpect,
    #[serde(default)]
    context: Option<serde_yaml::Value>,
    #[serde(default)]
    mock: Option<PolicyTestMock>,
    #[serde(default)]
    foreach: Option<String>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct PolicyTestMock {
    #[serde(default)]
    time: Option<String>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct PolicyTestExpect {
    #[serde(default)]
    allowed: Option<bool>,
    #[serde(default)]
    denied: Option<bool>,
    #[serde(default)]
    warn: Option<bool>,
    #[serde(default)]
    guard: Option<String>,
    #[serde(default)]
    severity: Option<String>,
    #[serde(default)]
    reason_contains: Option<String>,
    #[serde(default)]
    message_contains: Option<String>,
    #[serde(default)]
    posture_state: Option<String>,
    #[serde(default)]
    posture_transition: Option<PolicyTestExpectedTransition>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct PolicyTestExpectedTransition {
    #[serde(default)]
    from: Option<String>,
    #[serde(default)]
    to: Option<String>,
    #[serde(default)]
    trigger: Option<String>,
}

#[derive(Clone, Debug, serde::Serialize)]
pub struct PolicyTestFailure {
    pub suite: String,
    pub test: String,
    pub message: String,
}

#[derive(Clone, Debug, serde::Serialize)]
pub struct PolicyTestJsonOutput {
    pub version: u8,
    pub command: &'static str,
    pub name: String,
    pub policy: String,
    pub total: u64,
    pub passed: u64,
    pub failed: u64,
    pub coverage: Option<BTreeMap<String, u64>>,
    pub exit_code: i32,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub failures: Vec<PolicyTestFailure>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<CliJsonError>,
}

pub async fn cmd_policy_test(
    test_file: String,
    resolve: bool,
    remote_extends: &RemoteExtendsConfig,
    json: bool,
    coverage: bool,
    stdout: &mut dyn Write,
    stderr: &mut dyn Write,
) -> ExitCode {
    let path = PathBuf::from(&test_file);
    let raw = match std::fs::read_to_string(&path) {
        Ok(v) => v,
        Err(e) => {
            return emit_error(
                json,
                &test_file,
                ExitCode::RuntimeError,
                "runtime_error",
                &format!("Failed to read test file: {}", e),
                stdout,
                stderr,
            );
        }
    };

    let spec: PolicyTestFile = match serde_yaml::from_str(&raw) {
        Ok(v) => v,
        Err(e) => {
            return emit_error(
                json,
                &test_file,
                ExitCode::ConfigError,
                "config_error",
                &format!("Invalid policy test YAML: {}", e),
                stdout,
                stderr,
            );
        }
    };

    let policy_ref = resolve_policy_ref(&path, &spec.policy);
    let loaded =
        match crate::policy_diff::load_policy_from_arg(&policy_ref, resolve, remote_extends) {
            Ok(v) => v,
            Err(e) => {
                let code = crate::policy_error_exit_code(&e.source);
                let error_kind = if code == ExitCode::RuntimeError {
                    "runtime_error"
                } else {
                    "config_error"
                };
                return emit_error(
                    json, &test_file, code, error_kind, &e.message, stdout, stderr,
                );
            }
        };

    let engine = match HushEngine::builder(loaded.policy).build() {
        Ok(engine) => engine,
        Err(e) => {
            return emit_error(
                json,
                &test_file,
                ExitCode::ConfigError,
                "config_error",
                &format!("Failed to initialize engine: {}", e),
                stdout,
                stderr,
            );
        }
    };

    let mut failures = Vec::new();
    let mut total = 0u64;
    let mut passed = 0u64;
    let mut guard_coverage: BTreeMap<String, u64> = BTreeMap::new();

    for suite in &spec.suites {
        for case in expand_foreach(suite, &suite.tests) {
            total += 1;
            match run_case(&engine, suite, &case, &mut guard_coverage).await {
                Ok(()) => passed += 1,
                Err(msg) => failures.push(PolicyTestFailure {
                    suite: suite.name.clone(),
                    test: case.name.clone(),
                    message: msg.to_string(),
                }),
            }
        }
    }

    let failed = total.saturating_sub(passed);
    let code = if failed == 0 {
        ExitCode::Ok
    } else {
        ExitCode::Fail
    };

    if json {
        let output = PolicyTestJsonOutput {
            version: CLI_JSON_VERSION,
            command: "policy_test",
            name: spec.name,
            policy: policy_ref,
            total,
            passed,
            failed,
            coverage: if coverage { Some(guard_coverage) } else { None },
            exit_code: code.as_i32(),
            failures,
            error: None,
        };

        let _ = writeln!(
            stdout,
            "{}",
            serde_json::to_string_pretty(&output).unwrap_or_else(|_| "{}".to_string())
        );
        return code;
    }

    let _ = writeln!(stdout, "Policy test: {}", spec.name);
    let _ = writeln!(stdout, "Policy: {}", policy_ref);
    let _ = writeln!(
        stdout,
        "Total: {}, Passed: {}, Failed: {}",
        total, passed, failed
    );

    if coverage {
        let _ = writeln!(stdout, "Coverage (by guard):");
        for (guard, count) in &guard_coverage {
            let _ = writeln!(stdout, "  {}: {}", guard, count);
        }
    }

    if !failures.is_empty() {
        let _ = writeln!(stderr, "\nFailures:");
        for f in &failures {
            let _ = writeln!(stderr, "- {} / {}: {}", f.suite, f.test, f.message);
        }
    }

    code
}

fn resolve_policy_ref(test_file_path: &Path, policy: &str) -> String {
    if policy.starts_with("clawdstrike:") {
        return policy.to_string();
    }

    let candidate = PathBuf::from(policy);
    if candidate.is_absolute() {
        return policy.to_string();
    }

    let base = test_file_path.parent().unwrap_or_else(|| Path::new("."));
    base.join(policy).to_string_lossy().to_string()
}

fn expand_foreach(suite: &PolicyTestSuite, cases: &[PolicyTestCase]) -> Vec<PolicyTestCase> {
    let mut expanded = Vec::new();

    for case in cases {
        let Some(ref foreach) = case.foreach else {
            expanded.push(case.clone());
            continue;
        };

        let Some(values) = suite.parameters.get(foreach) else {
            expanded.push(case.clone());
            continue;
        };

        for (idx, v) in values.iter().enumerate() {
            let value = yaml_scalar_to_string(v);

            let mut cloned = case.clone();
            cloned.name = cloned
                .name
                .replace("{item}", &value)
                .replace("{value}", &value)
                .replace("{path}", &value);
            cloned.input = substitute_yaml_strings(&cloned.input, &value);
            cloned.context = cloned
                .context
                .as_ref()
                .map(|c| substitute_yaml_strings(c, &value));
            cloned.foreach = None;

            // Ensure uniqueness if user didn't include a placeholder.
            if cloned.name == case.name {
                cloned.name = format!("{} [{}#{}]", cloned.name, foreach, idx + 1);
            }

            expanded.push(cloned);
        }
    }

    expanded
}

fn substitute_yaml_strings(value: &serde_yaml::Value, replacement: &str) -> serde_yaml::Value {
    match value {
        serde_yaml::Value::String(s) => serde_yaml::Value::String(
            s.replace("{item}", replacement)
                .replace("{value}", replacement)
                .replace("{path}", replacement),
        ),
        serde_yaml::Value::Sequence(seq) => serde_yaml::Value::Sequence(
            seq.iter()
                .map(|v| substitute_yaml_strings(v, replacement))
                .collect(),
        ),
        serde_yaml::Value::Mapping(map) => {
            let mut out = serde_yaml::Mapping::new();
            for (k, v) in map {
                out.insert(
                    substitute_yaml_strings(k, replacement),
                    substitute_yaml_strings(v, replacement),
                );
            }
            serde_yaml::Value::Mapping(out)
        }
        other => other.clone(),
    }
}

async fn run_case(
    engine: &HushEngine,
    suite: &PolicyTestSuite,
    case: &PolicyTestCase,
    coverage: &mut BTreeMap<String, u64>,
) -> anyhow::Result<()> {
    let mut json_value = yaml_to_json(&case.input);
    let serde_json::Value::Object(obj) = &mut json_value else {
        anyhow::bail!("input must be an object");
    };

    if !obj.contains_key("eventId") && !obj.contains_key("event_id") {
        obj.insert(
            "eventId".to_string(),
            serde_json::Value::String(format!(
                "test-{}-{}",
                sanitize_id(&suite.name),
                sanitize_id(&case.name)
            )),
        );
    }

    if !obj.contains_key("timestamp") {
        let timestamp = case
            .mock
            .as_ref()
            .and_then(|m| m.time.clone())
            .unwrap_or_else(|| "2026-02-03T00:00:00Z".to_string());
        obj.insert(
            "timestamp".to_string(),
            serde_json::Value::String(timestamp),
        );
    }

    let mut event: PolicyEvent =
        serde_json::from_value(json_value).context("failed to build PolicyEvent from input")?;

    if let Some(ref context) = case.context {
        event.context = Some(yaml_to_json(context));
    }

    let mapped = map_policy_event(&event)?;
    let mut posture_state = extract_case_posture_state(case.context.as_ref())?;
    let posture_report = engine
        .check_action_report_with_posture(
            &mapped.action.as_guard_action(),
            &mapped.context,
            &mut posture_state,
        )
        .await?;
    let report = posture_report.guard_report;
    engine.reset().await;

    for r in &report.per_guard {
        *coverage.entry(r.guard.clone()).or_insert(0) += 1;
    }

    assert_expectations(
        case,
        &report,
        posture_state.as_ref(),
        posture_report.transition.as_ref(),
    )
}

fn assert_expectations(
    case: &PolicyTestCase,
    report: &GuardReport,
    posture_state: Option<&PostureRuntimeState>,
    posture_transition: Option<&PostureTransitionRecord>,
) -> anyhow::Result<()> {
    let expect = &case.expect;
    let outcome = outcome_for_report(report);

    if expect.allowed == Some(true) && outcome == "blocked" {
        anyhow::bail!("expected allowed, got blocked");
    }
    if expect.denied == Some(true) && outcome != "blocked" {
        anyhow::bail!("expected denied, got {}", outcome);
    }
    if expect.warn == Some(true) && outcome != "warn" {
        anyhow::bail!("expected warn, got {}", outcome);
    }

    if let Some(ref guard) = expect.guard {
        if report.overall.guard != *guard {
            anyhow::bail!("expected guard {:?}, got {:?}", guard, report.overall.guard);
        }
    }

    if let Some(ref severity) = expect.severity {
        let actual = canonical_severity(report);
        if actual.as_deref() != Some(severity.as_str()) {
            anyhow::bail!("expected severity {:?}, got {:?}", severity, actual);
        }
    }

    if let Some(ref needle) = expect.message_contains {
        if !report.overall.message.contains(needle) {
            anyhow::bail!(
                "expected message to contain {:?}, got {:?}",
                needle,
                report.overall.message
            );
        }
    }

    if let Some(ref needle) = expect.reason_contains {
        let hay = format!(
            "{} {}",
            report.overall.message,
            report
                .overall
                .details
                .as_ref()
                .map(|d| d.to_string())
                .unwrap_or_default()
        );
        if !hay.contains(needle) {
            anyhow::bail!("expected reason to contain {:?}, got {:?}", needle, hay);
        }
    }

    if let Some(expected_state) = expect.posture_state.as_ref() {
        let Some(actual_state) = posture_state.as_ref().map(|s| s.current_state.as_str()) else {
            anyhow::bail!(
                "expected posture_state {:?}, but no posture state was available",
                expected_state
            );
        };
        if actual_state != expected_state {
            anyhow::bail!(
                "expected posture_state {:?}, got {:?}",
                expected_state,
                actual_state
            );
        }
    }

    if let Some(expected_transition) = expect.posture_transition.as_ref() {
        let Some(actual) = posture_transition else {
            anyhow::bail!(
                "expected posture_transition {:?}, but no transition occurred",
                expected_transition.trigger.as_deref().unwrap_or("<any>")
            );
        };

        if let Some(from) = expected_transition.from.as_ref() {
            if actual.from != *from {
                anyhow::bail!(
                    "expected posture_transition.from {:?}, got {:?}",
                    from,
                    actual.from
                );
            }
        }
        if let Some(to) = expected_transition.to.as_ref() {
            if actual.to != *to {
                anyhow::bail!(
                    "expected posture_transition.to {:?}, got {:?}",
                    to,
                    actual.to
                );
            }
        }
        if let Some(trigger) = expected_transition.trigger.as_ref() {
            if actual.trigger != *trigger {
                anyhow::bail!(
                    "expected posture_transition.trigger {:?}, got {:?}",
                    trigger,
                    actual.trigger
                );
            }
        }
    }

    Ok(())
}

fn extract_case_posture_state(
    context: Option<&serde_yaml::Value>,
) -> anyhow::Result<Option<PostureRuntimeState>> {
    let Some(context) = context else {
        return Ok(None);
    };

    let json = yaml_to_json(context);
    let serde_json::Value::Object(mut obj) = json else {
        return Ok(None);
    };

    let Some(mut posture_value) = obj.remove("session_posture") else {
        return Ok(None);
    };

    if posture_value.is_null() {
        return Ok(None);
    }

    let serde_json::Value::Object(ref mut posture_obj) = posture_value else {
        anyhow::bail!("context.session_posture must be an object or null");
    };

    if !posture_obj.contains_key("current_state") {
        if let Some(state) = posture_obj.remove("state") {
            posture_obj.insert("current_state".to_string(), state);
        }
    }
    posture_obj
        .entry("entered_at".to_string())
        .or_insert(serde_json::Value::String(
            "2026-02-03T00:00:00Z".to_string(),
        ));
    posture_obj
        .entry("budgets".to_string())
        .or_insert(serde_json::json!({}));
    posture_obj
        .entry("transition_history".to_string())
        .or_insert(serde_json::json!([]));

    let parsed = serde_json::from_value::<PostureRuntimeState>(posture_value)
        .context("failed to parse context.session_posture")?;
    Ok(Some(parsed))
}

fn outcome_for_report(report: &GuardReport) -> &'static str {
    if !report.overall.allowed {
        return "blocked";
    }
    if report.overall.severity == Severity::Warning {
        return "warn";
    }
    "allowed"
}

fn canonical_severity(report: &GuardReport) -> Option<String> {
    if report.overall.allowed && report.overall.severity == Severity::Info {
        return None;
    }

    Some(
        match report.overall.severity {
            Severity::Info => "low",
            Severity::Warning => "medium",
            Severity::Error => "high",
            Severity::Critical => "critical",
        }
        .to_string(),
    )
}

fn sanitize_id(s: &str) -> String {
    s.chars()
        .map(|c| if c.is_ascii_alphanumeric() { c } else { '-' })
        .collect::<String>()
        .trim_matches('-')
        .to_string()
}

fn yaml_to_json(value: &serde_yaml::Value) -> serde_json::Value {
    match value {
        serde_yaml::Value::Null => serde_json::Value::Null,
        serde_yaml::Value::Bool(b) => serde_json::Value::Bool(*b),
        serde_yaml::Value::Number(n) => {
            if let Some(i) = n.as_i64() {
                serde_json::Value::Number(i.into())
            } else if let Some(u) = n.as_u64() {
                serde_json::Value::Number(u.into())
            } else if let Some(f) = n.as_f64() {
                serde_json::Number::from_f64(f)
                    .map(serde_json::Value::Number)
                    .unwrap_or(serde_json::Value::Null)
            } else {
                serde_json::Value::Null
            }
        }
        serde_yaml::Value::String(s) => serde_json::Value::String(s.clone()),
        serde_yaml::Value::Sequence(seq) => {
            serde_json::Value::Array(seq.iter().map(yaml_to_json).collect())
        }
        serde_yaml::Value::Mapping(map) => {
            let mut out = serde_json::Map::new();
            for (k, v) in map {
                let key = match k {
                    serde_yaml::Value::String(s) => s.clone(),
                    other => serde_yaml::to_string(other)
                        .unwrap_or_else(|_| "<non-string-key>".to_string())
                        .trim()
                        .to_string(),
                };
                out.insert(key, yaml_to_json(v));
            }
            serde_json::Value::Object(out)
        }
        serde_yaml::Value::Tagged(tagged) => yaml_to_json(&tagged.value),
    }
}

fn yaml_scalar_to_string(value: &serde_yaml::Value) -> String {
    match value {
        serde_yaml::Value::Null => "null".to_string(),
        serde_yaml::Value::Bool(b) => b.to_string(),
        serde_yaml::Value::Number(n) => n.to_string(),
        serde_yaml::Value::String(s) => s.clone(),
        other => serde_yaml::to_string(other)
            .unwrap_or_else(|_| "<non-scalar>".to_string())
            .trim()
            .to_string(),
    }
}

fn emit_error(
    json: bool,
    test_file: &str,
    code: ExitCode,
    error_kind: &'static str,
    message: &str,
    stdout: &mut dyn Write,
    stderr: &mut dyn Write,
) -> ExitCode {
    if json {
        let output = PolicyTestJsonOutput {
            version: CLI_JSON_VERSION,
            command: "policy_test",
            name: test_file.to_string(),
            policy: "<unknown>".to_string(),
            total: 0,
            passed: 0,
            failed: 0,
            coverage: None,
            exit_code: code.as_i32(),
            failures: Vec::new(),
            error: Some(CliJsonError {
                kind: error_kind,
                message: message.to_string(),
            }),
        };

        let _ = writeln!(
            stdout,
            "{}",
            serde_json::to_string_pretty(&output).unwrap_or_else(|_| "{}".to_string())
        );
        return code;
    }

    let _ = writeln!(stderr, "Error: {}", message);
    code
}
