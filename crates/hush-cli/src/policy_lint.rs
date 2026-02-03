use std::collections::BTreeSet;
use std::io::Write;

use clawdstrike::Policy;

use crate::policy_diff::{ResolvedPolicySource, ResolvedPolicySource as Rps};
use crate::{CliJsonError, ExitCode, PolicySource, CLI_JSON_VERSION};

#[derive(Clone, Debug, serde::Serialize)]
pub struct LintFinding {
    pub code: &'static str,
    pub message: String,
}

#[derive(Clone, Debug, serde::Serialize)]
pub struct PolicyLintJsonOutput {
    pub version: u8,
    pub command: &'static str,
    pub policy: PolicySource,
    pub valid: bool,
    pub warnings: Vec<LintFinding>,
    pub exit_code: i32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<CliJsonError>,
}

pub fn cmd_policy_lint(
    policy_ref: String,
    resolve: bool,
    json: bool,
    strict: bool,
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

            if json {
                let output = PolicyLintJsonOutput {
                    version: CLI_JSON_VERSION,
                    command: "policy_lint",
                    policy: guess_policy_source(&policy_ref),
                    valid: false,
                    warnings: Vec::new(),
                    exit_code: code.as_i32(),
                    error: Some(CliJsonError {
                        kind: error_kind,
                        message: e.message,
                    }),
                };
                let _ = writeln!(
                    stdout,
                    "{}",
                    serde_json::to_string_pretty(&output).unwrap_or_else(|_| "{}".to_string())
                );
                return code;
            }

            let _ = writeln!(stderr, "Error: {}", e.message);
            return code;
        }
    };

    let policy_source = policy_source_for_loaded(&loaded.source);
    let warnings = lint_policy(&loaded.policy);

    let code = if warnings.is_empty() {
        ExitCode::Ok
    } else if strict {
        ExitCode::ConfigError
    } else {
        ExitCode::Warn
    };

    if json {
        let output = PolicyLintJsonOutput {
            version: CLI_JSON_VERSION,
            command: "policy_lint",
            policy: policy_source,
            valid: true,
            warnings,
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

    if warnings.is_empty() {
        let _ = writeln!(stdout, "Policy lint: OK");
        return ExitCode::Ok;
    }

    let _ = writeln!(stdout, "Policy lint: {} warning(s)", warnings.len());
    for w in &warnings {
        let _ = writeln!(stdout, "- {}: {}", w.code, w.message);
    }
    if strict {
        let _ = writeln!(stderr, "Strict mode: warnings treated as errors.");
    }
    code
}

fn lint_policy(policy: &Policy) -> Vec<LintFinding> {
    let mut warnings = Vec::new();

    if let Some(ref egress) = policy.guards.egress_allowlist {
        let allow: BTreeSet<&str> = egress.allow.iter().map(|s| s.as_str()).collect();
        let block: BTreeSet<&str> = egress.block.iter().map(|s| s.as_str()).collect();

        if allow.contains("*") {
            warnings.push(LintFinding {
                code: "SEC001",
                message: "egress_allowlist.allow contains \"*\" (overly permissive)".to_string(),
            });
        }

        for pat in allow.intersection(&block) {
            warnings.push(LintFinding {
                code: "SEC002",
                message: format!(
                    "egress_allowlist has conflicting allow/block entry: {:?}",
                    pat
                ),
            });
        }
    }

    if let Some(ref forbidden) = policy.guards.forbidden_path {
        if forbidden.patterns.iter().any(|p| p == "**" || p == "**/*") {
            warnings.push(LintFinding {
                code: "SEC010",
                message: "forbidden_path.patterns contains a catch-all pattern (may block everything)".to_string(),
            });
        }
    }

    warnings
}

fn policy_source_for_loaded(source: &ResolvedPolicySource) -> PolicySource {
    match source {
        Rps::Ruleset { id } => PolicySource::Ruleset { name: id.clone() },
        Rps::File { path } => PolicySource::PolicyFile { path: path.clone() },
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

