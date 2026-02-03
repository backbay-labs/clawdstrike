use std::io::{BufRead, Read as _, Write};

use clawdstrike::{GuardReport, GuardResult, HushEngine, Severity};

use crate::policy_event::{map_policy_event, PolicyEvent};
use crate::{CliJsonError, ExitCode, PolicySource, CLI_JSON_VERSION};

#[derive(Clone, Debug, serde::Serialize)]
pub struct DecisionJson {
    pub allowed: bool,
    pub denied: bool,
    pub warn: bool,
    pub guard: Option<String>,
    pub severity: Option<String>,
    pub message: Option<String>,
    pub reason: Option<String>,
}

#[derive(Clone, Debug, serde::Serialize)]
pub struct PolicyEvalJsonOutput {
    pub version: u8,
    pub command: &'static str,
    pub policy: PolicySource,
    pub event: serde_json::Value,
    pub outcome: &'static str,
    pub exit_code: i32,
    pub decision: DecisionJson,
    pub report: GuardReport,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<CliJsonError>,
}

#[derive(Clone, Debug, serde::Serialize)]
pub struct EventsRef {
    pub path: String,
    pub count: u64,
}

#[derive(Clone, Debug, serde::Serialize)]
pub struct SimulationSummary {
    pub total: u64,
    pub allowed: u64,
    pub warn: u64,
    pub blocked: u64,
}

#[derive(Clone, Debug, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SimulationResultEntry {
    pub event_id: String,
    pub outcome: &'static str,
    pub decision: DecisionJson,
    pub report: GuardReport,
}

#[derive(Clone, Debug, serde::Serialize)]
pub struct PolicySimulateJsonOutput {
    pub version: u8,
    pub command: &'static str,
    pub policy: PolicySource,
    pub events: EventsRef,
    pub summary: SimulationSummary,
    pub results: Vec<SimulationResultEntry>,
    pub exit_code: i32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<CliJsonError>,
}

fn policy_source_for_loaded(source: &crate::policy_diff::ResolvedPolicySource) -> PolicySource {
    match source {
        crate::policy_diff::ResolvedPolicySource::Ruleset { id } => PolicySource::Ruleset {
            name: id.clone(),
        },
        crate::policy_diff::ResolvedPolicySource::File { path } => PolicySource::PolicyFile {
            path: path.clone(),
        },
    }
}

fn policy_source_guess(policy_ref: &str) -> PolicySource {
    match clawdstrike::RuleSet::by_name(policy_ref) {
        Ok(Some(rs)) => PolicySource::Ruleset { name: rs.id },
        _ => PolicySource::PolicyFile {
            path: policy_ref.to_string(),
        },
    }
}

fn canonical_severity_for_decision(result: &GuardResult) -> Option<String> {
    if result.allowed && result.severity == Severity::Info {
        return None;
    }

    Some(
        match result.severity {
            Severity::Info => "low",
            Severity::Warning => "medium",
            Severity::Error => "high",
            Severity::Critical => "critical",
        }
        .to_string(),
    )
}

fn decision_from_report(report: &GuardReport, reason_override: Option<String>) -> DecisionJson {
    let overall = &report.overall;

    let warn = overall.allowed && overall.severity == Severity::Warning;
    let denied = !overall.allowed;

    DecisionJson {
        allowed: overall.allowed,
        denied,
        warn,
        guard: if overall.allowed && overall.severity == Severity::Info {
            None
        } else {
            Some(overall.guard.clone())
        },
        severity: canonical_severity_for_decision(overall),
        message: Some(overall.message.clone()),
        reason: reason_override,
    }
}

fn outcome_and_exit_code(report: &GuardReport) -> (&'static str, ExitCode) {
    if !report.overall.allowed {
        return ("blocked", ExitCode::Fail);
    }

    if report.overall.severity == Severity::Warning {
        return ("warn", ExitCode::Warn);
    }

    ("allowed", ExitCode::Ok)
}

fn synthetic_error_report(message: &str) -> GuardReport {
    GuardReport {
        overall: GuardResult::block("engine", Severity::Error, message),
        per_guard: Vec::new(),
    }
}

pub async fn cmd_policy_eval(
    policy_ref: String,
    event_path: String,
    resolve: bool,
    json: bool,
    stdout: &mut dyn Write,
    stderr: &mut dyn Write,
) -> ExitCode {
    let loaded = match crate::policy_diff::load_policy_from_arg(&policy_ref, resolve) {
        Ok(v) => v,
        Err(e) => {
            let code = crate::policy_error_exit_code(&e.source);
            let error_kind = if code == ExitCode::RuntimeError {
                "runtime_error"
            } else {
                "config_error"
            };
            return emit_policy_eval_error(
                json,
                policy_source_guess(&policy_ref),
                None,
                code,
                error_kind,
                &e.message,
                stdout,
                stderr,
            );
        }
    };

    let policy = policy_source_for_loaded(&loaded.source);
    let engine = HushEngine::with_policy(loaded.policy);

    let event_json = match read_input_to_string(&event_path) {
        Ok(v) => v,
        Err(e) => {
            return emit_policy_eval_error(
                json,
                policy,
                None,
                ExitCode::RuntimeError,
                "runtime_error",
                &format!("Failed to read event input: {}", e),
                stdout,
                stderr,
            );
        }
    };

    let raw_value: serde_json::Value = match serde_json::from_str(&event_json) {
        Ok(v) => v,
        Err(e) => {
            return emit_policy_eval_error(
                json,
                policy,
                Some(serde_json::Value::Null),
                ExitCode::ConfigError,
                "config_error",
                &format!("Invalid event JSON: {}", e),
                stdout,
                stderr,
            );
        }
    };

    let event: PolicyEvent = match serde_json::from_value(raw_value.clone()) {
        Ok(v) => v,
        Err(e) => {
            return emit_policy_eval_error(
                json,
                policy,
                Some(raw_value),
                ExitCode::ConfigError,
                "config_error",
                &format!("Invalid PolicyEvent: {}", e),
                stdout,
                stderr,
            );
        }
    };

    let normalized_event = serde_json::to_value(&event).unwrap_or(serde_json::Value::Null);

    let mapped = match map_policy_event(&event) {
        Ok(v) => v,
        Err(e) => {
            return emit_policy_eval_error(
                json,
                policy,
                Some(normalized_event),
                ExitCode::ConfigError,
                "config_error",
                &format!("Failed to map PolicyEvent: {}", e),
                stdout,
                stderr,
            );
        }
    };

    let report = match engine
        .check_action_report(&mapped.action.as_guard_action(), &mapped.context)
        .await
    {
        Ok(v) => v,
        Err(e) => {
            return emit_policy_eval_error(
                json,
                policy,
                Some(normalized_event),
                ExitCode::RuntimeError,
                "runtime_error",
                &format!("Policy evaluation failed: {}", e),
                stdout,
                stderr,
            );
        }
    };

    let decision = decision_from_report(&report, mapped.decision_reason);
    let (outcome, code) = outcome_and_exit_code(&report);

    if json {
        let output = PolicyEvalJsonOutput {
            version: CLI_JSON_VERSION,
            command: "policy_eval",
            policy,
            event: normalized_event,
            outcome,
            exit_code: code.as_i32(),
            decision,
            report,
            error: None,
        };
        let _ = writeln!(
            stdout,
            "{}",
            serde_json::to_string_pretty(&output).unwrap_or_else(|_| "{}".to_string())
        );
        return code;
    }

    match code {
        ExitCode::Ok => {
            let _ = writeln!(stdout, "ALLOWED: {}", report.overall.message);
        }
        ExitCode::Warn => {
            let _ = writeln!(
                stdout,
                "WARN [{}]: {}",
                report.overall.guard, report.overall.message
            );
        }
        ExitCode::Fail => {
            let _ = writeln!(
                stderr,
                "BLOCKED [{}] ({:?}): {}",
                report.overall.guard, report.overall.severity, report.overall.message
            );
        }
        _ => {}
    }

    code
}

pub async fn cmd_policy_simulate(
    policy_ref: String,
    events_path: String,
    resolve: bool,
    json: bool,
    stdout: &mut dyn Write,
    stderr: &mut dyn Write,
) -> ExitCode {
    let loaded = match crate::policy_diff::load_policy_from_arg(&policy_ref, resolve) {
        Ok(v) => v,
        Err(e) => {
            let code = crate::policy_error_exit_code(&e.source);
            let error_kind = if code == ExitCode::RuntimeError {
                "runtime_error"
            } else {
                "config_error"
            };
            return emit_policy_simulate_error(
                json,
                policy_source_guess(&policy_ref),
                &events_path,
                SimulationSummary {
                    total: 0,
                    allowed: 0,
                    warn: 0,
                    blocked: 0,
                },
                Vec::new(),
                code,
                error_kind,
                &e.message,
                stdout,
                stderr,
            );
        }
    };

    let policy = policy_source_for_loaded(&loaded.source);
    let engine = HushEngine::with_policy(loaded.policy);

    let input = match open_events_reader(&events_path) {
        Ok(v) => v,
        Err(e) => {
            return emit_policy_simulate_error(
                json,
                policy,
                &events_path,
                SimulationSummary {
                    total: 0,
                    allowed: 0,
                    warn: 0,
                    blocked: 0,
                },
                Vec::new(),
                ExitCode::RuntimeError,
                "runtime_error",
                &format!("Failed to read events input: {}", e),
                stdout,
                stderr,
            );
        }
    };

    let mut results = Vec::new();
    let mut summary = SimulationSummary {
        total: 0,
        allowed: 0,
        warn: 0,
        blocked: 0,
    };

    for (idx, line) in input.lines().enumerate() {
        let line = match line {
            Ok(v) => v,
            Err(e) => {
                return emit_policy_simulate_error(
                    json,
                    policy,
                    &events_path,
                    summary,
                    results,
                    ExitCode::RuntimeError,
                    "runtime_error",
                    &format!("Failed to read line {}: {}", idx + 1, e),
                    stdout,
                    stderr,
                );
            }
        };

        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }

        let event: PolicyEvent = match serde_json::from_str(trimmed) {
            Ok(v) => v,
            Err(e) => {
                return emit_policy_simulate_error(
                    json,
                    policy,
                    &events_path,
                    summary,
                    results,
                    ExitCode::ConfigError,
                    "config_error",
                    &format!("Invalid PolicyEvent JSON on line {}: {}", idx + 1, e),
                    stdout,
                    stderr,
                );
            }
        };

        let mapped = match map_policy_event(&event) {
            Ok(v) => v,
            Err(e) => {
                return emit_policy_simulate_error(
                    json,
                    policy,
                    &events_path,
                    summary,
                    results,
                    ExitCode::ConfigError,
                    "config_error",
                    &format!("Failed to map PolicyEvent on line {}: {}", idx + 1, e),
                    stdout,
                    stderr,
                );
            }
        };

        let report = match engine
            .check_action_report(&mapped.action.as_guard_action(), &mapped.context)
            .await
        {
            Ok(v) => v,
            Err(e) => {
                return emit_policy_simulate_error(
                    json,
                    policy,
                    &events_path,
                    summary,
                    results,
                    ExitCode::RuntimeError,
                    "runtime_error",
                    &format!("Policy evaluation failed on line {}: {}", idx + 1, e),
                    stdout,
                    stderr,
                );
            }
        };

        let decision = decision_from_report(&report, mapped.decision_reason);
        let (outcome, _code) = outcome_and_exit_code(&report);

        summary.total += 1;
        match outcome {
            "allowed" => summary.allowed += 1,
            "warn" => summary.warn += 1,
            "blocked" => summary.blocked += 1,
            _ => {}
        }

        results.push(SimulationResultEntry {
            event_id: event.event_id.clone(),
            outcome,
            decision,
            report,
        });
    }

    let code = if summary.blocked > 0 {
        ExitCode::Fail
    } else if summary.warn > 0 {
        ExitCode::Warn
    } else {
        ExitCode::Ok
    };

    if json {
        let output = PolicySimulateJsonOutput {
            version: CLI_JSON_VERSION,
            command: "policy_simulate",
            policy,
            events: EventsRef {
                path: events_path.clone(),
                count: summary.total,
            },
            summary,
            results,
            exit_code: code.as_i32(),
            error: None,
        };

        let _ = writeln!(
            stdout,
            "{}",
            serde_json::to_string_pretty(&output).unwrap_or_else(|_| "{}".to_string())
        );
        return code;
    }

    let _ = writeln!(
        stdout,
        "Simulation complete: total={}, allowed={}, warn={}, blocked={}",
        summary.total, summary.allowed, summary.warn, summary.blocked
    );
    code
}

fn emit_policy_eval_error(
    json: bool,
    policy: PolicySource,
    event: Option<serde_json::Value>,
    code: ExitCode,
    error_kind: &'static str,
    message: &str,
    stdout: &mut dyn Write,
    stderr: &mut dyn Write,
) -> ExitCode {
    if json {
        let report = synthetic_error_report(message);
        let decision = DecisionJson {
            allowed: false,
            denied: false,
            warn: false,
            guard: None,
            severity: None,
            message: None,
            reason: None,
        };

        let output = PolicyEvalJsonOutput {
            version: CLI_JSON_VERSION,
            command: "policy_eval",
            policy,
            event: event.unwrap_or(serde_json::Value::Null),
            outcome: "error",
            exit_code: code.as_i32(),
            decision,
            report,
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

fn emit_policy_simulate_error(
    json: bool,
    policy: PolicySource,
    events_path: &str,
    summary: SimulationSummary,
    results: Vec<SimulationResultEntry>,
    code: ExitCode,
    error_kind: &'static str,
    message: &str,
    stdout: &mut dyn Write,
    stderr: &mut dyn Write,
) -> ExitCode {
    if json {
        let output = PolicySimulateJsonOutput {
            version: CLI_JSON_VERSION,
            command: "policy_simulate",
            policy,
            events: EventsRef {
                path: events_path.to_string(),
                count: summary.total,
            },
            summary,
            results,
            exit_code: code.as_i32(),
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

fn read_input_to_string(path: &str) -> std::io::Result<String> {
    if path == "-" {
        let mut buf = String::new();
        std::io::stdin().read_to_string(&mut buf)?;
        return Ok(buf);
    }

    std::fs::read_to_string(path)
}

fn open_events_reader(path: &str) -> std::io::Result<Box<dyn BufRead>> {
    if path == "-" {
        return Ok(Box::new(std::io::BufReader::new(std::io::stdin())));
    }

    let file = std::fs::File::open(path)?;
    Ok(Box::new(std::io::BufReader::new(file)))
}
