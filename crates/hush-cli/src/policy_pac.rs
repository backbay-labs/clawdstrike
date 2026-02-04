use std::io::{BufRead, IsTerminal as _, Read as _, Write};
use std::time::Instant;

use anyhow::Context as _;
use clawdstrike::{GuardReport, GuardResult, HushEngine, Severity};

use crate::guard_report_json::GuardReportJson;
use crate::policy_event::{map_policy_event, PolicyEvent};
use crate::remote_extends::RemoteExtendsConfig;
use crate::{CliJsonError, ExitCode, PolicySource, CLI_JSON_VERSION};

#[derive(Clone, Debug)]
pub struct PolicySimulateOptions<'a> {
    pub resolve: bool,
    pub remote_extends: &'a RemoteExtendsConfig,
    pub json: bool,
    pub jsonl: bool,
    pub summary: bool,
    pub fail_on_deny: bool,
    pub benchmark: bool,
}

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
    pub report: GuardReportJson,
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
    pub report: GuardReportJson,
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
        crate::policy_diff::ResolvedPolicySource::Ruleset { id } => {
            PolicySource::Ruleset { name: id.clone() }
        }
        crate::policy_diff::ResolvedPolicySource::File { path } => {
            PolicySource::PolicyFile { path: path.clone() }
        }
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

fn synthetic_error_report_json(message: &str) -> GuardReportJson {
    GuardReportJson::synthetic_error(message)
}

pub async fn cmd_policy_eval(
    policy_ref: String,
    event_path: String,
    resolve: bool,
    remote_extends: &RemoteExtendsConfig,
    json: bool,
    stdout: &mut dyn Write,
    stderr: &mut dyn Write,
) -> ExitCode {
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
    let engine = match HushEngine::builder(loaded.policy).build() {
        Ok(engine) => engine,
        Err(e) => {
            return emit_policy_eval_error(
                json,
                policy.clone(),
                None,
                ExitCode::ConfigError,
                "config_error",
                &format!("Failed to initialize engine: {}", e),
                stdout,
                stderr,
            );
        }
    };

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
        let report = GuardReportJson::from_report(&report);
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
    events_path: Option<String>,
    opts: PolicySimulateOptions<'_>,
    stdout: &mut dyn Write,
    stderr: &mut dyn Write,
) -> ExitCode {
    let loaded = match crate::policy_diff::load_policy_from_arg(
        &policy_ref,
        opts.resolve,
        opts.remote_extends,
    ) {
        Ok(v) => v,
        Err(e) => {
            let code = crate::policy_error_exit_code(&e.source);
            let error_kind = if code == ExitCode::RuntimeError {
                "runtime_error"
            } else {
                "config_error"
            };
            return emit_policy_simulate_error(
                opts.json,
                policy_source_guess(&policy_ref),
                events_path.as_deref().unwrap_or("-"),
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
    let engine = match HushEngine::builder(loaded.policy).build() {
        Ok(engine) => engine,
        Err(e) => {
            return emit_policy_simulate_error(
                opts.json,
                policy.clone(),
                events_path.as_deref().unwrap_or("-"),
                SimulationSummary {
                    total: 0,
                    allowed: 0,
                    warn: 0,
                    blocked: 0,
                },
                Vec::new(),
                ExitCode::ConfigError,
                "config_error",
                &format!("Failed to initialize engine: {}", e),
                stdout,
                stderr,
            );
        }
    };

    let is_interactive =
        events_path.is_none() && std::io::stdin().is_terminal() && !opts.json && !opts.jsonl;

    if is_interactive {
        return cmd_policy_simulate_interactive(engine, stdout, stderr).await;
    }

    let events_path = events_path.unwrap_or_else(|| "-".to_string());
    let input = match open_events_reader(&events_path) {
        Ok(v) => v,
        Err(e) => {
            return emit_policy_simulate_error(
                opts.json,
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

    let started = Instant::now();
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
                    opts.json,
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
                    opts.json,
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
                    opts.json,
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
                    opts.json,
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

        engine.reset().await;

        let decision = decision_from_report(&report, mapped.decision_reason);
        let (outcome, _code) = outcome_and_exit_code(&report);

        summary.total += 1;
        match outcome {
            "allowed" => summary.allowed += 1,
            "warn" => summary.warn += 1,
            "blocked" => summary.blocked += 1,
            _ => {}
        }

        if opts.jsonl || (opts.json && !opts.summary) {
            let entry = SimulationResultEntry {
                event_id: event.event_id.clone(),
                outcome,
                decision,
                report: GuardReportJson::from_report(&report),
            };

            if opts.jsonl {
                let _ = writeln!(
                    stdout,
                    "{}",
                    serde_json::to_string(&entry).unwrap_or_else(|_| "{}".to_string())
                );
            } else {
                results.push(entry);
            }
        }
    }

    let elapsed = started.elapsed();

    let code = if summary.blocked > 0 && opts.fail_on_deny {
        ExitCode::Fail
    } else if summary.warn > 0 {
        ExitCode::Warn
    } else {
        ExitCode::Ok
    };

    if opts.benchmark {
        let per_sec = if elapsed.as_secs_f64() > 0.0 {
            summary.total as f64 / elapsed.as_secs_f64()
        } else {
            0.0
        };
        let _ = writeln!(
            stderr,
            "Benchmark: events={}, duration_ms={}, events_per_sec={:.2}",
            summary.total,
            elapsed.as_millis(),
            per_sec
        );
    }

    if opts.json {
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

    if opts.jsonl {
        let _ = writeln!(
            stderr,
            "Simulation complete: total={}, allowed={}, warn={}, blocked={}",
            summary.total, summary.allowed, summary.warn, summary.blocked
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

async fn cmd_policy_simulate_interactive(
    engine: HushEngine,
    stdout: &mut dyn Write,
    stderr: &mut dyn Write,
) -> ExitCode {
    use crate::policy_event::{
        FileEventData, NetworkEventData, PatchEventData, PolicyEventData, PolicyEventType,
        ToolEventData,
    };
    use chrono::Utc;

    let _ = writeln!(stdout, "Clawdstrike Policy Simulator");
    let _ = writeln!(stdout, "==========================");
    let _ = writeln!(stdout, "Type `help` for commands, `exit` to quit.");

    let mut history: Vec<(String, String, &'static str)> = Vec::new();
    let mut next_id = 1u64;

    let stdin = std::io::stdin();
    let mut line = String::new();
    loop {
        line.clear();
        let _ = write!(stdout, "> ");
        let _ = stdout.flush();

        let n = match stdin.read_line(&mut line) {
            Ok(n) => n,
            Err(e) => {
                let _ = writeln!(stderr, "Error reading input: {}", e);
                return ExitCode::RuntimeError;
            }
        };
        if n == 0 {
            break;
        }

        let input = line.trim();
        if input.is_empty() {
            continue;
        }

        match input {
            "exit" | "quit" => break,
            "help" => {
                let _ = writeln!(stdout, "Shortcuts:");
                let _ = writeln!(stdout, "  file:read <path>");
                let _ = writeln!(stdout, "  file:write <path> [content]");
                let _ = writeln!(stdout, "  egress <host> [port]");
                let _ = writeln!(stdout, "  tool <name> [jsonParams]");
                let _ = writeln!(stdout, "  patch <filePath> <patchContent>");
                let _ = writeln!(stdout, "  history");
                let _ = writeln!(stdout, "  exit");
                let _ = writeln!(stdout, "Or paste a full PolicyEvent JSON object.");
                continue;
            }
            "history" => {
                if history.is_empty() {
                    let _ = writeln!(stdout, "No events yet.");
                    continue;
                }

                let _ = writeln!(stdout, "Event History:");
                for (idx, (event_id, summary, outcome)) in history.iter().enumerate() {
                    let _ = writeln!(
                        stdout,
                        "  {}. {} {} -> {}",
                        idx + 1,
                        event_id,
                        summary,
                        outcome
                    );
                }
                continue;
            }
            _ => {}
        }

        let event_id = format!("interactive-{:04}", next_id);
        next_id += 1;

        let parsed: anyhow::Result<(PolicyEvent, String)> = (|| {
            if let Some(rest) = input.strip_prefix("file:read ") {
                let path = rest.trim();
                anyhow::ensure!(!path.is_empty(), "missing path");
                Ok((
                    PolicyEvent {
                        event_id: event_id.clone(),
                        event_type: PolicyEventType::FileRead,
                        timestamp: Utc::now(),
                        session_id: None,
                        data: PolicyEventData::File(FileEventData {
                            path: path.to_string(),
                            operation: Some("read".to_string()),
                            content_base64: None,
                            content: None,
                            content_hash: None,
                        }),
                        metadata: Some(serde_json::json!({ "source": "interactive" })),
                        context: None,
                    },
                    format!("file_read {}", path),
                ))
            } else if let Some(rest) = input.strip_prefix("file:write ") {
                let mut parts = rest.splitn(2, ' ');
                let path = parts.next().unwrap_or("").trim();
                anyhow::ensure!(!path.is_empty(), "missing path");
                let content = parts.next().map(|s| s.trim().to_string());
                Ok((
                    PolicyEvent {
                        event_id: event_id.clone(),
                        event_type: PolicyEventType::FileWrite,
                        timestamp: Utc::now(),
                        session_id: None,
                        data: PolicyEventData::File(FileEventData {
                            path: path.to_string(),
                            operation: Some("write".to_string()),
                            content_base64: None,
                            content,
                            content_hash: None,
                        }),
                        metadata: Some(serde_json::json!({ "source": "interactive" })),
                        context: None,
                    },
                    format!("file_write {}", path),
                ))
            } else if let Some(rest) = input.strip_prefix("egress ") {
                let mut parts = rest.split_whitespace();
                let host = parts.next().unwrap_or("");
                anyhow::ensure!(!host.is_empty(), "missing host");
                let port: u16 = match parts.next() {
                    Some(p) => p.parse().context("port must be a number")?,
                    None => 443,
                };
                Ok((
                    PolicyEvent {
                        event_id: event_id.clone(),
                        event_type: PolicyEventType::NetworkEgress,
                        timestamp: Utc::now(),
                        session_id: None,
                        data: PolicyEventData::Network(NetworkEventData {
                            host: host.to_string(),
                            port,
                            protocol: Some("tcp".to_string()),
                            url: None,
                        }),
                        metadata: Some(serde_json::json!({ "source": "interactive" })),
                        context: None,
                    },
                    format!("network_egress {}:{}", host, port),
                ))
            } else if let Some(rest) = input.strip_prefix("tool ") {
                let mut parts = rest.splitn(2, ' ');
                let name = parts.next().unwrap_or("").trim();
                anyhow::ensure!(!name.is_empty(), "missing tool name");
                let params = match parts.next() {
                    Some(json) if !json.trim().is_empty() => {
                        serde_json::from_str(json.trim()).context("invalid JSON parameters")?
                    }
                    _ => serde_json::json!({}),
                };
                Ok((
                    PolicyEvent {
                        event_id: event_id.clone(),
                        event_type: PolicyEventType::ToolCall,
                        timestamp: Utc::now(),
                        session_id: None,
                        data: PolicyEventData::Tool(ToolEventData {
                            tool_name: name.to_string(),
                            parameters: params,
                        }),
                        metadata: Some(serde_json::json!({ "source": "interactive" })),
                        context: None,
                    },
                    format!("tool_call {}", name),
                ))
            } else if let Some(rest) = input.strip_prefix("patch ") {
                let mut parts = rest.splitn(2, ' ');
                let file_path = parts.next().unwrap_or("").trim();
                let patch_content = parts.next().unwrap_or("").trim();
                anyhow::ensure!(!file_path.is_empty(), "missing filePath");
                anyhow::ensure!(!patch_content.is_empty(), "missing patchContent");
                Ok((
                    PolicyEvent {
                        event_id: event_id.clone(),
                        event_type: PolicyEventType::PatchApply,
                        timestamp: Utc::now(),
                        session_id: None,
                        data: PolicyEventData::Patch(PatchEventData {
                            file_path: file_path.to_string(),
                            patch_content: patch_content.to_string(),
                            patch_hash: None,
                        }),
                        metadata: Some(serde_json::json!({ "source": "interactive" })),
                        context: None,
                    },
                    format!("patch_apply {}", file_path),
                ))
            } else {
                let value: serde_json::Value =
                    serde_json::from_str(input).context("invalid JSON input")?;
                let event: PolicyEvent =
                    serde_json::from_value(value).context("invalid PolicyEvent")?;
                let summary = format!("{} {}", event.event_type, event.event_id);
                Ok((event, summary))
            }
        })();

        let (event, summary) = match parsed {
            Ok(v) => v,
            Err(e) => {
                let _ = writeln!(stderr, "Error: {}", e);
                continue;
            }
        };

        let mapped = match map_policy_event(&event) {
            Ok(v) => v,
            Err(e) => {
                let _ = writeln!(stderr, "Error: {}", e);
                continue;
            }
        };

        let report = match engine
            .check_action_report(&mapped.action.as_guard_action(), &mapped.context)
            .await
        {
            Ok(v) => v,
            Err(e) => {
                let _ = writeln!(stderr, "Error: {}", e);
                continue;
            }
        };

        engine.reset().await;

        let (outcome, _code) = outcome_and_exit_code(&report);
        history.push((event.event_id.clone(), summary, outcome));

        match outcome {
            "allowed" => {
                let _ = writeln!(stdout, "ALLOWED: {}", report.overall.message);
            }
            "warn" => {
                let _ = writeln!(
                    stdout,
                    "WARN [{}]: {}",
                    report.overall.guard, report.overall.message
                );
            }
            "blocked" => {
                let _ = writeln!(
                    stderr,
                    "DENIED [{}] ({:?}): {}",
                    report.overall.guard, report.overall.severity, report.overall.message
                );
            }
            _ => {}
        }
    }

    ExitCode::Ok
}

#[allow(clippy::too_many_arguments)]
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
        let report = synthetic_error_report_json(message);
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

#[allow(clippy::too_many_arguments)]
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

pub(crate) fn open_events_reader(path: &str) -> std::io::Result<Box<dyn BufRead>> {
    if path == "-" {
        return Ok(Box::new(std::io::BufReader::new(std::io::stdin())));
    }

    let file = std::fs::File::open(path)?;
    Ok(Box::new(std::io::BufReader::new(file)))
}
