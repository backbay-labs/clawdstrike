use std::collections::BTreeSet;
use std::io::Write;

use clawdstrike::Policy;
use serde_json::json;

use crate::policy_diff::{ResolvedPolicySource, ResolvedPolicySource as Rps};
use crate::remote_extends::RemoteExtendsConfig;
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

#[derive(Clone, Debug)]
pub struct PolicyLintCommand {
    pub policy_ref: String,
    pub resolve: bool,
    pub json: bool,
    pub sarif: bool,
    pub strict: bool,
}

pub fn cmd_policy_lint(
    command: PolicyLintCommand,
    remote_extends: &RemoteExtendsConfig,
    stdout: &mut dyn Write,
    stderr: &mut dyn Write,
) -> ExitCode {
    let PolicyLintCommand {
        policy_ref,
        resolve,
        json,
        sarif,
        strict,
    } = command;

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
                let message = e.message;
                let policy = guess_policy_source(&policy_ref);

                if json {
                    let output = PolicyLintJsonOutput {
                        version: CLI_JSON_VERSION,
                        command: "policy_lint",
                        policy,
                        valid: false,
                        warnings: Vec::new(),
                        exit_code: code.as_i32(),
                        error: Some(CliJsonError {
                            kind: error_kind,
                            message: message.clone(),
                        }),
                    };
                    let _ = writeln!(
                        stdout,
                        "{}",
                        serde_json::to_string_pretty(&output).unwrap_or_else(|_| "{}".to_string())
                    );
                    return code;
                }
                if sarif {
                    emit_sarif(
                        stdout,
                        &policy,
                        &[],
                        code.as_i32(),
                        Some(message.as_str()),
                        false,
                    );
                    return code;
                }

                let _ = writeln!(stderr, "Error: {}", message);
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
            policy: policy_source.clone(),
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
    if sarif {
        emit_sarif(stdout, &policy_source, &warnings, code.as_i32(), None, true);
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

    if let Some(ref posture) = policy.posture {
        lint_posture(&mut warnings, posture);
    }

    warnings
}

fn lint_posture(warnings: &mut Vec<LintFinding>, posture: &clawdstrike::PostureConfig) {
    let mut incoming: std::collections::HashMap<String, usize> = std::collections::HashMap::new();
    let mut outgoing: std::collections::HashMap<String, usize> = std::collections::HashMap::new();

    for state in posture.states.keys() {
        incoming.insert(state.clone(), 0);
        outgoing.insert(state.clone(), 0);
    }

    for transition in &posture.transitions {
        if let Some(in_count) = incoming.get_mut(&transition.to) {
            *in_count += 1;
        }

        if transition.from == "*" {
            for out_count in outgoing.values_mut() {
                *out_count += 1;
            }
        } else if let Some(out_count) = outgoing.get_mut(&transition.from) {
            *out_count += 1;
        }
    }

    for state in posture.states.keys() {
        let in_count = incoming.get(state).copied().unwrap_or(0);
        if state != &posture.initial && in_count == 0 {
            warnings.push(LintFinding {
                code: "POS001",
                message: format!(
                    "state '{}' has no incoming transitions (unreachable)",
                    state
                ),
            });
        }

        let out_count = outgoing.get(state).copied().unwrap_or(0);
        if out_count == 0 {
            warnings.push(LintFinding {
                code: "POS002",
                message: format!("state '{}' has no outgoing transitions", state),
            });
        }
    }
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

fn emit_sarif(
    stdout: &mut dyn Write,
    policy: &PolicySource,
    warnings: &[LintFinding],
    exit_code: i32,
    error_message: Option<&str>,
    valid: bool,
) {
    let mut rule_ids: BTreeSet<String> = warnings.iter().map(|w| w.code.to_string()).collect();
    if error_message.is_some() {
        rule_ids.insert("LINT_ERROR".to_string());
    }

    let rules = rule_ids
        .into_iter()
        .map(|id| {
            json!({
                "id": id,
                "name": "policy-lint",
                "shortDescription": { "text": sarif_rule_description(&id) },
            })
        })
        .collect::<Vec<_>>();

    let mut results = Vec::new();
    for warning in warnings {
        results.push(json!({
            "ruleId": warning.code,
            "level": sarif_level_for_code(warning.code),
            "message": { "text": warning.message },
        }));
    }
    if let Some(message) = error_message {
        results.push(json!({
            "ruleId": "LINT_ERROR",
            "level": "error",
            "message": { "text": message },
        }));
    }

    let sarif = json!({
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "hush policy lint",
                    "rules": rules,
                }
            },
            "invocations": [{
                "executionSuccessful": error_message.is_none(),
                "exitCode": exit_code,
            }],
            "results": results,
            "properties": {
                "policy": policy,
                "valid": valid,
            }
        }]
    });

    let _ = writeln!(
        stdout,
        "{}",
        serde_json::to_string_pretty(&sarif).unwrap_or_else(|_| "{}".to_string())
    );
}

fn sarif_level_for_code(code: &str) -> &'static str {
    if code.starts_with("SEC") {
        "warning"
    } else if code.starts_with("STY") {
        "note"
    } else {
        "warning"
    }
}

fn sarif_rule_description(code: &str) -> &'static str {
    if code.starts_with("SEC") {
        "Security lint finding"
    } else if code.starts_with("STY") {
        "Style lint finding"
    } else {
        "Policy lint finding"
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use clawdstrike::Policy;

    #[test]
    fn emits_sarif_with_warning_results() {
        let mut out = Vec::<u8>::new();
        let warnings = vec![LintFinding {
            code: "SEC001",
            message: "overly permissive".to_string(),
        }];

        emit_sarif(
            &mut out,
            &PolicySource::Ruleset {
                name: "default".to_string(),
            },
            &warnings,
            ExitCode::Warn.as_i32(),
            None,
            true,
        );

        let value: serde_json::Value = serde_json::from_slice(&out).expect("valid sarif json");
        assert_eq!(value["version"], "2.1.0");
        assert_eq!(value["runs"][0]["results"][0]["ruleId"], "SEC001");
        assert_eq!(value["runs"][0]["results"][0]["level"], "warning");
    }

    #[test]
    fn emits_sarif_error_result_for_load_failures() {
        let mut out = Vec::<u8>::new();
        emit_sarif(
            &mut out,
            &PolicySource::PolicyFile {
                path: "missing.yaml".to_string(),
            },
            &[],
            ExitCode::ConfigError.as_i32(),
            Some("missing policy"),
            false,
        );

        let value: serde_json::Value = serde_json::from_slice(&out).expect("valid sarif json");
        let results = value["runs"][0]["results"]
            .as_array()
            .expect("results array");
        assert_eq!(results.len(), 1);
        assert_eq!(results[0]["ruleId"], "LINT_ERROR");
        assert_eq!(results[0]["level"], "error");
    }

    #[test]
    fn lint_warns_on_unreachable_posture_state() {
        let policy = Policy::from_yaml(
            r#"
version: "1.2.0"
name: "posture lint"
description: "test"
posture:
  initial: work
  states:
    work: { capabilities: [file_access] }
    unreachable: { capabilities: [file_access] }
  transitions: []
"#,
        )
        .expect("policy");

        let warnings = lint_policy(&policy);
        assert!(warnings.iter().any(|w| w.code == "POS001"));
        assert!(warnings.iter().any(|w| w.message.contains("unreachable")));
    }

    #[test]
    fn lint_warns_on_terminal_posture_state() {
        let policy = Policy::from_yaml(
            r#"
version: "1.2.0"
name: "posture lint"
description: "test"
posture:
  initial: observe
  states:
    observe: { capabilities: [file_access] }
    quarantine: { capabilities: [] }
  transitions:
    - { from: observe, to: quarantine, on: user_approval }
"#,
        )
        .expect("policy");

        let warnings = lint_policy(&policy);
        assert!(warnings.iter().any(|w| w.code == "POS002"));
        assert!(warnings
            .iter()
            .any(|w| w.message.contains("no outgoing transitions")));
    }
}
