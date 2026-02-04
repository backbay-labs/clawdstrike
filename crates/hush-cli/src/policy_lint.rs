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

    if policy.name.trim().is_empty() {
        warnings.push(LintFinding {
            code: "STY001",
            message: "policy.name is empty (add a human-readable name)".to_string(),
        });
    }
    if policy.description.trim().is_empty() {
        warnings.push(LintFinding {
            code: "STY002",
            message: "policy.description is empty (document intent + scope)".to_string(),
        });
    }

    if let Some(ref egress) = policy.guards.egress_allowlist {
        lint_sorted_unique(
            &mut warnings,
            "STY010",
            "guards.egress_allowlist.allow",
            &egress.allow,
        );
        lint_sorted_unique(
            &mut warnings,
            "STY011",
            "guards.egress_allowlist.block",
            &egress.block,
        );

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
        if let Some(patterns) = forbidden.patterns.as_ref() {
            lint_sorted_unique(
                &mut warnings,
                "STY020",
                "guards.forbidden_path.patterns",
                patterns,
            );
        }
        lint_sorted_unique(
            &mut warnings,
            "STY021",
            "guards.forbidden_path.exceptions",
            &forbidden.exceptions,
        );

        let patterns = forbidden.effective_patterns();
        if patterns.iter().any(|p| p == "**" || p == "**/*") {
            warnings.push(LintFinding {
                code: "SEC010",
                message:
                    "forbidden_path.patterns contains a catch-all pattern (may block everything)"
                        .to_string(),
            });
        }
    }

    if let Some(ref secret_leak) = policy.guards.secret_leak {
        lint_sorted_unique(
            &mut warnings,
            "STY030",
            "guards.secret_leak.skip_paths",
            &secret_leak.skip_paths,
        );

        for p in &secret_leak.patterns {
            if looks_like_backtracking_redos(&p.pattern) {
                warnings.push(LintFinding {
                    code: "SEC020",
                    message: format!(
                        "guards.secret_leak.patterns contains a potentially ReDoS-prone regex (for backtracking engines): {}",
                        p.name
                    ),
                });
            }
        }
    }

    if let Some(ref patch_integrity) = policy.guards.patch_integrity {
        lint_sorted_unique(
            &mut warnings,
            "STY040",
            "guards.patch_integrity.forbidden_patterns",
            &patch_integrity.forbidden_patterns,
        );

        for (idx, pattern) in patch_integrity.forbidden_patterns.iter().enumerate() {
            if looks_like_backtracking_redos(pattern) {
                warnings.push(LintFinding {
                    code: "SEC021",
                    message: format!(
                        "guards.patch_integrity.forbidden_patterns[{}] is potentially ReDoS-prone (for backtracking engines)",
                        idx
                    ),
                });
            }
        }
    }

    warnings
}

fn lint_sorted_unique(
    warnings: &mut Vec<LintFinding>,
    code: &'static str,
    field: &str,
    values: &[String],
) {
    if values.len() < 2 {
        return;
    }

    let mut sorted = values.to_vec();
    sorted.sort();

    if sorted != values {
        warnings.push(LintFinding {
            code,
            message: format!("{field} is not sorted (consider sorting for stable diffs)"),
        });
    }

    sorted.dedup();
    if sorted.len() != values.len() {
        warnings.push(LintFinding {
            code,
            message: format!("{field} contains duplicates"),
        });
    }
}

fn looks_like_backtracking_redos(pattern: &str) -> bool {
    // Heuristic-only: Rust's `regex` crate is linear-time, but other SDKs may run these patterns in
    // backtracking engines. Flag obvious nested-quantifier constructs like `(a+)+` / `(.*)+`.
    #[derive(Clone, Copy, Debug)]
    struct Group {
        has_quantifier: bool,
    }

    let mut stack: Vec<Group> = Vec::new();
    let mut in_char_class = false;
    let mut escaped = false;

    let bytes = pattern.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        let b = bytes[i];
        if escaped {
            escaped = false;
            i += 1;
            continue;
        }

        match b {
            b'\\' => escaped = true,
            b'[' => in_char_class = true,
            b']' => in_char_class = false,
            b'(' if !in_char_class => stack.push(Group {
                has_quantifier: false,
            }),
            b')' if !in_char_class => {
                let Some(group) = stack.pop() else {
                    i += 1;
                    continue;
                };

                let next = bytes.get(i + 1).copied();
                let outer_quant = matches!(next, Some(b'+') | Some(b'*') | Some(b'{'));
                if outer_quant && group.has_quantifier {
                    return true;
                }

                if group.has_quantifier {
                    if let Some(parent) = stack.last_mut() {
                        parent.has_quantifier = true;
                    }
                }
            }
            b'+' | b'*' | b'{' if !in_char_class => {
                if let Some(group) = stack.last_mut() {
                    group.has_quantifier = true;
                }
            }
            _ => {}
        }

        i += 1;
    }

    false
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
