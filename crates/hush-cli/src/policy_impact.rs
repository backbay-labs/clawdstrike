use std::io::{BufRead, Write};

use clawdstrike::HushEngine;

use crate::policy_diff::ResolvedPolicySource;
use crate::policy_event::map_policy_event;
use crate::{CliJsonError, ExitCode, PolicySource, CLI_JSON_VERSION};

#[derive(Clone, Debug, serde::Serialize)]
pub struct ImpactSummary {
    pub total: u64,
    pub changed: u64,
    pub allow_to_warn: u64,
    pub allow_to_block: u64,
    pub warn_to_allow: u64,
    pub warn_to_block: u64,
    pub block_to_allow: u64,
    pub block_to_warn: u64,
}

#[derive(Clone, Debug, serde::Serialize)]
pub struct EventsRef {
    pub path: String,
    pub count: u64,
}

#[derive(Clone, Debug, serde::Serialize)]
pub struct PolicyImpactJsonOutput {
    pub version: u8,
    pub command: &'static str,
    pub old_policy: PolicySource,
    pub new_policy: PolicySource,
    pub events: EventsRef,
    pub summary: ImpactSummary,
    pub exit_code: i32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<CliJsonError>,
}

pub async fn cmd_policy_impact(
    old_policy_ref: String,
    new_policy_ref: String,
    events_path: String,
    resolve: bool,
    json: bool,
    fail_on_breaking: bool,
    stdout: &mut dyn Write,
    stderr: &mut dyn Write,
) -> ExitCode {
    let old_loaded = match crate::policy_diff::load_policy_from_arg(&old_policy_ref, resolve) {
        Ok(v) => v,
        Err(e) => {
            let code = crate::policy_error_exit_code(&e.source);
            return emit_error(
                json,
                guess_policy_source(&old_policy_ref),
                guess_policy_source(&new_policy_ref),
                &events_path,
                ImpactSummary::default(),
                code,
                if code == ExitCode::RuntimeError {
                    "runtime_error"
                } else {
                    "config_error"
                },
                &e.message,
                stdout,
                stderr,
            );
        }
    };

    let new_loaded = match crate::policy_diff::load_policy_from_arg(&new_policy_ref, resolve) {
        Ok(v) => v,
        Err(e) => {
            let code = crate::policy_error_exit_code(&e.source);
            return emit_error(
                json,
                policy_source_for_loaded(&old_loaded.source),
                guess_policy_source(&new_policy_ref),
                &events_path,
                ImpactSummary::default(),
                code,
                if code == ExitCode::RuntimeError {
                    "runtime_error"
                } else {
                    "config_error"
                },
                &e.message,
                stdout,
                stderr,
            );
        }
    };

    let old_policy_source = policy_source_for_loaded(&old_loaded.source);
    let new_policy_source = policy_source_for_loaded(&new_loaded.source);
    let old_engine = HushEngine::with_policy(old_loaded.policy);
    let new_engine = HushEngine::with_policy(new_loaded.policy);

    let input = match crate::policy_pac::open_events_reader(&events_path) {
        Ok(v) => v,
        Err(e) => {
            return emit_error(
                json,
                old_policy_source,
                new_policy_source,
                &events_path,
                ImpactSummary::default(),
                ExitCode::RuntimeError,
                "runtime_error",
                &format!("Failed to read events input: {}", e),
                stdout,
                stderr,
            );
        }
    };

    let mut summary = ImpactSummary::default();

    for (idx, line) in input.lines().enumerate() {
        let line = match line {
            Ok(v) => v,
            Err(e) => {
                return emit_error(
                    json,
                    old_policy_source,
                    new_policy_source,
                    &events_path,
                    summary,
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

        let event: crate::policy_event::PolicyEvent = match serde_json::from_str(trimmed) {
            Ok(v) => v,
            Err(e) => {
                return emit_error(
                    json,
                    old_policy_source,
                    new_policy_source,
                    &events_path,
                    summary,
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
                return emit_error(
                    json,
                    old_policy_source,
                    new_policy_source,
                    &events_path,
                    summary,
                    ExitCode::ConfigError,
                    "config_error",
                    &format!("Failed to map PolicyEvent on line {}: {}", idx + 1, e),
                    stdout,
                    stderr,
                );
            }
        };

        let old_report = match old_engine
            .check_action_report(&mapped.action.as_guard_action(), &mapped.context)
            .await
        {
            Ok(v) => v,
            Err(e) => {
                return emit_error(
                    json,
                    old_policy_source,
                    new_policy_source,
                    &events_path,
                    summary,
                    ExitCode::RuntimeError,
                    "runtime_error",
                    &format!("Old policy evaluation failed on line {}: {}", idx + 1, e),
                    stdout,
                    stderr,
                );
            }
        };
        old_engine.reset().await;

        let new_report = match new_engine
            .check_action_report(&mapped.action.as_guard_action(), &mapped.context)
            .await
        {
            Ok(v) => v,
            Err(e) => {
                return emit_error(
                    json,
                    old_policy_source,
                    new_policy_source,
                    &events_path,
                    summary,
                    ExitCode::RuntimeError,
                    "runtime_error",
                    &format!("New policy evaluation failed on line {}: {}", idx + 1, e),
                    stdout,
                    stderr,
                );
            }
        };
        new_engine.reset().await;

        let old_outcome = outcome_for_report(&old_report);
        let new_outcome = outcome_for_report(&new_report);

        summary.total += 1;

        if old_outcome != new_outcome {
            summary.changed += 1;
        }

        match (old_outcome, new_outcome) {
            ("allowed", "warn") => summary.allow_to_warn += 1,
            ("allowed", "blocked") => summary.allow_to_block += 1,
            ("warn", "allowed") => summary.warn_to_allow += 1,
            ("warn", "blocked") => summary.warn_to_block += 1,
            ("blocked", "allowed") => summary.block_to_allow += 1,
            ("blocked", "warn") => summary.block_to_warn += 1,
            _ => {}
        }
    }

    let code = if fail_on_breaking && summary.allow_to_block > 0 {
        ExitCode::Fail
    } else {
        ExitCode::Ok
    };

    if json {
        let output = PolicyImpactJsonOutput {
            version: CLI_JSON_VERSION,
            command: "policy_impact",
            old_policy: old_policy_source,
            new_policy: new_policy_source,
            events: EventsRef {
                path: events_path.clone(),
                count: summary.total,
            },
            summary,
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

    let _ = writeln!(stdout, "Policy impact report");
    let _ = writeln!(stdout, "====================");
    let _ = writeln!(stdout, "Events: {}", summary.total);
    let _ = writeln!(stdout, "Changed: {}", summary.changed);
    let _ = writeln!(stdout, "Allow -> Warn: {}", summary.allow_to_warn);
    let _ = writeln!(stdout, "Allow -> Block: {}", summary.allow_to_block);
    let _ = writeln!(stdout, "Warn -> Allow: {}", summary.warn_to_allow);
    let _ = writeln!(stdout, "Warn -> Block: {}", summary.warn_to_block);
    let _ = writeln!(stdout, "Block -> Allow: {}", summary.block_to_allow);
    let _ = writeln!(stdout, "Block -> Warn: {}", summary.block_to_warn);

    if fail_on_breaking && summary.allow_to_block > 0 {
        let _ = writeln!(stderr, "Breaking changes detected (allow -> block).");
    }

    code
}

impl Default for ImpactSummary {
    fn default() -> Self {
        Self {
            total: 0,
            changed: 0,
            allow_to_warn: 0,
            allow_to_block: 0,
            warn_to_allow: 0,
            warn_to_block: 0,
            block_to_allow: 0,
            block_to_warn: 0,
        }
    }
}

fn outcome_for_report(report: &clawdstrike::GuardReport) -> &'static str {
    if !report.overall.allowed {
        return "blocked";
    }
    if report.overall.severity == clawdstrike::Severity::Warning {
        return "warn";
    }
    "allowed"
}

fn emit_error(
    json: bool,
    old_policy: PolicySource,
    new_policy: PolicySource,
    events_path: &str,
    summary: ImpactSummary,
    code: ExitCode,
    error_kind: &'static str,
    message: &str,
    stdout: &mut dyn Write,
    stderr: &mut dyn Write,
) -> ExitCode {
    if json {
        let output = PolicyImpactJsonOutput {
            version: CLI_JSON_VERSION,
            command: "policy_impact",
            old_policy,
            new_policy,
            events: EventsRef {
                path: events_path.to_string(),
                count: summary.total,
            },
            summary,
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

fn policy_source_for_loaded(source: &ResolvedPolicySource) -> PolicySource {
    match source {
        ResolvedPolicySource::Ruleset { id } => PolicySource::Ruleset { name: id.clone() },
        ResolvedPolicySource::File { path } => PolicySource::PolicyFile { path: path.clone() },
    }
}

fn guess_policy_source(policy_ref: &str) -> PolicySource {
    match clawdstrike::RuleSet::by_name(policy_ref) {
        Ok(Some(rs)) => PolicySource::Ruleset { name: rs.id },
        _ => PolicySource::PolicyFile {
            path: policy_ref.to_string(),
        },
    }
}

