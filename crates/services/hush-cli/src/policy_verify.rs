//! `hush policy verify` -- policy verification via Logos formula inspection
//! and optional Z3 checks.

use std::io::Write;

use clawdstrike::policy::PolicyResolver;
use clawdstrike::Policy;
use colored::Colorize;

use clawdstrike_logos::compiler::{DefaultPolicyCompiler, PolicyCompiler};
use clawdstrike_logos::logos_ffi::AgentId;
use clawdstrike_logos::verifier::{
    AttestationLevel, CheckOutcome, PolicyVerifier, VerificationBackend, VerificationReport,
};

use crate::policy_diff::{
    LoadedPolicy, PolicyLoadError, ResolvedPolicySource, ResolvedPolicySource as Rps,
};
use crate::remote_extends::RemoteExtendsConfig;
use crate::ui;
use crate::{CliJsonError, ExitCode, PolicySource, CLI_JSON_VERSION};

#[derive(Clone, Debug)]
pub struct PolicyVerifyCommand {
    pub policy_ref: String,
    pub resolve: bool,
    pub json: bool,
    pub attestation_level: bool,
    pub verbose: bool,
}

#[derive(Clone, Debug, serde::Serialize)]
pub struct PolicyVerifyJsonOutput {
    pub version: u8,
    pub command: &'static str,
    pub policy: PolicySource,
    pub outcome: &'static str,
    pub exit_code: i32,
    pub attestation_level: u8,
    pub attestation_level_name: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub report: Option<VerificationReport>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<CliJsonError>,
}

pub fn cmd_policy_verify(
    command: PolicyVerifyCommand,
    remote_extends: &RemoteExtendsConfig,
    stdout: &mut dyn Write,
    stderr: &mut dyn Write,
) -> ExitCode {
    let PolicyVerifyCommand {
        policy_ref,
        resolve: _resolve,
        json,
        attestation_level: show_attestation_level,
        verbose,
    } = command;

    // Verification must inspect the effective policy graph, not the unresolved leaf,
    // otherwise inheritance checks can false-pass across extends chains.
    let resolve = true;

    let loaded =
        match crate::policy_diff::load_policy_from_arg(&policy_ref, resolve, remote_extends) {
            Ok(v) => v,
            Err(e) => {
                return emit_policy_verify_error(
                    guess_policy_source(&policy_ref),
                    e,
                    json,
                    stdout,
                    stderr,
                );
            }
        };

    let policy_source = policy_source_for_loaded(&loaded.source);
    let effective_policy = &loaded.policy;
    let source_policy = &loaded.source_policy;

    let base_policy = match load_parent_policy_for_inheritance(&loaded, remote_extends) {
        Ok(base) => base,
        Err(e) => {
            return emit_policy_verify_error(policy_source.clone(), e, json, stdout, stderr);
        }
    };

    let agent = AgentId::new("clawdstrike-agent");
    let compiler = DefaultPolicyCompiler::new(agent.clone());
    let formulas = compiler.compile_policy(effective_policy);

    let verifier = preferred_verifier();
    let report = match base_policy.as_ref() {
        Some(parent) => verifier.verify_policy_with_parent_and_source(
            parent,
            source_policy,
            effective_policy,
            agent,
        ),
        None => verifier.verify_policy(effective_policy, agent),
    };

    let all_pass = report.all_pass();
    let code = if all_pass {
        ExitCode::Ok
    } else {
        ExitCode::Fail
    };

    if json {
        let output = PolicyVerifyJsonOutput {
            version: CLI_JSON_VERSION,
            command: "policy_verify",
            policy: policy_source,
            outcome: if all_pass { "pass" } else { "fail" },
            exit_code: code.as_i32(),
            attestation_level: report.attestation_level.as_u8(),
            attestation_level_name: report.attestation_level.name(),
            report: Some(report),
            error: None,
        };
        let _ = writeln!(
            stdout,
            "{}",
            serde_json::to_string_pretty(&output).unwrap_or_else(|_| "{}".to_string())
        );
        return code;
    }

    let _ = writeln!(stdout);
    let _ = writeln!(stdout, "Policy Verification Report");
    let _ = writeln!(stdout, "==========================");
    let _ = writeln!(stdout, "Policy: {}", &policy_ref);
    let _ = writeln!(stdout, "Schema: v{}", effective_policy.version);

    if let Some(ref extends_name) = loaded.original_extends {
        let _ = writeln!(stdout, "Extends: {}", extends_name);
    }

    let _ = writeln!(stdout);
    let _ = writeln!(stdout, "Formulas compiled: {}", report.formula_count);
    let _ = writeln!(stdout, "Action atoms:      {}", report.atom_count);
    let _ = writeln!(
        stdout,
        "Backend:           {}",
        verification_backend_label(report.backend)
    );
    let _ = writeln!(stdout);

    let consistency_label = outcome_label(&report.consistency.outcome);
    let _ = writeln!(
        stdout,
        "Consistency:       {}  ({} conflicts in {} formulas)",
        consistency_label, report.consistency.conflict_count, report.formula_count,
    );
    for conflict in &report.consistency.conflicts {
        let _ = writeln!(
            stdout,
            "  ! Conflict: {} is both permitted and prohibited",
            conflict.atom
        );
    }

    let completeness_label = outcome_label(&report.completeness.outcome);
    let covered = report.completeness.covered.len();
    let total = covered + report.completeness.missing.len();
    let _ = writeln!(
        stdout,
        "Completeness:      {}  ({}/{} action types covered)",
        completeness_label, covered, total,
    );
    for missing in &report.completeness.missing {
        let _ = writeln!(stdout, "  ! Missing action type: {}", missing);
    }

    let inheritance_label = outcome_label(&report.inheritance.outcome);
    match report.inheritance.outcome {
        CheckOutcome::Skipped => {
            let _ = writeln!(
                stdout,
                "Inheritance:       {}  (no base policy)",
                inheritance_label,
            );
        }
        _ => {
            let _ = writeln!(
                stdout,
                "Inheritance:       {}  ({} weakened prohibitions from base {:?})",
                inheritance_label,
                report.inheritance.weakened.len(),
                loaded.original_extends.as_deref().unwrap_or("unknown"),
            );
            for w in &report.inheritance.weakened {
                let _ = writeln!(
                    stdout,
                    "  ! Weakened prohibition: {} (present in base, absent in child)",
                    w.atom
                );
            }
        }
    }

    let _ = writeln!(stdout);
    let _ = writeln!(
        stdout,
        "Verification time: {}ms",
        report.verification_time_ms
    );

    if show_attestation_level {
        let _ = writeln!(stdout);
        let _ = writeln!(
            stdout,
            "Attestation level: {}",
            attestation_level_label(&report.attestation_level),
        );
        let _ = writeln!(stdout, "  Level 0: Heuristic guards only");
        let _ = writeln!(
            stdout,
            "  Level 1: Formula-verified inspection     {}",
            if report.attestation_level >= AttestationLevel::FormulaVerified {
                "[achieved]".green().to_string()
            } else {
                "[not achieved]".dimmed().to_string()
            }
        );
        let _ = writeln!(
            stdout,
            "  Level 2: Z3-verified SMT checks          {}",
            if report.attestation_level >= AttestationLevel::Z3Verified {
                "[achieved]".green().to_string()
            } else if report.backend == VerificationBackend::FormulaInspection {
                "[formula backend]".dimmed().to_string()
            } else {
                "[not available]".dimmed().to_string()
            }
        );
        let _ = writeln!(
            stdout,
            "  Level 3: Lean-proved properties          {}",
            if report.attestation_level >= AttestationLevel::LeanProved {
                "[achieved]".green().to_string()
            } else {
                "[not available]".dimmed().to_string()
            }
        );
        let _ = writeln!(
            stdout,
            "  Level 4: Aeneas-verified implementation  {}",
            if report.attestation_level >= AttestationLevel::ImplementationVerified {
                "[achieved]".green().to_string()
            } else {
                "[not available]".dimmed().to_string()
            }
        );
    }

    if verbose {
        let _ = writeln!(stdout);
        let _ = writeln!(stdout, "Compiled Formulas ({}):", formulas.len());
        let _ = writeln!(stdout, "{}", "-".repeat(40));
        for (i, formula) in formulas.iter().enumerate() {
            let _ = writeln!(stdout, "  [{}] {}", i + 1, formula);
        }
    }

    if all_pass {
        let _ = writeln!(
            stdout,
            "\n{} All verification checks passed.",
            ui::Verdict::Pass.badge()
        );
    } else {
        let _ = writeln!(
            stdout,
            "\n{} One or more verification checks failed.",
            ui::Verdict::Fail.badge()
        );
    }

    code
}

fn preferred_verifier() -> PolicyVerifier {
    #[cfg(feature = "z3")]
    {
        PolicyVerifier::with_z3()
    }

    #[cfg(not(feature = "z3"))]
    {
        PolicyVerifier::new()
    }
}

fn outcome_label(outcome: &CheckOutcome) -> String {
    match outcome {
        CheckOutcome::Pass => "PASS".green().bold().to_string(),
        CheckOutcome::Fail => "FAIL".red().bold().to_string(),
        CheckOutcome::Skipped => "SKIP".yellow().bold().to_string(),
    }
}

fn verification_backend_label(backend: VerificationBackend) -> String {
    match backend {
        VerificationBackend::FormulaInspection => "Formula inspection".yellow().bold().to_string(),
        VerificationBackend::Z3 => "Z3 SMT".green().bold().to_string(),
    }
}

fn attestation_level_label(level: &AttestationLevel) -> String {
    match level {
        AttestationLevel::Heuristic => format!("{} (heuristic)", "Level 0".yellow().bold()),
        AttestationLevel::FormulaVerified => {
            format!("{} (formula_verified)", "Level 1".green().bold())
        }
        AttestationLevel::Z3Verified => format!("{} (z3_verified)", "Level 2".green().bold()),
        AttestationLevel::LeanProved => format!("{} (lean_proved)", "Level 3".green().bold()),
        AttestationLevel::ImplementationVerified => {
            format!("{} (implementation_verified)", "Level 4".green().bold())
        }
    }
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

fn emit_policy_verify_error(
    policy: PolicySource,
    error: PolicyLoadError,
    json: bool,
    stdout: &mut dyn Write,
    stderr: &mut dyn Write,
) -> ExitCode {
    let code = crate::policy_error_exit_code(&error.source);
    let error_kind = if code == ExitCode::RuntimeError {
        "runtime_error"
    } else {
        "config_error"
    };
    let message = error.message;

    if json {
        let output = PolicyVerifyJsonOutput {
            version: CLI_JSON_VERSION,
            command: "policy_verify",
            policy,
            outcome: "error",
            exit_code: code.as_i32(),
            attestation_level: AttestationLevel::Heuristic.as_u8(),
            attestation_level_name: AttestationLevel::Heuristic.name(),
            report: None,
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

    let _ = writeln!(stderr, "Error: {}", message);
    code
}

fn load_parent_policy_for_inheritance(
    loaded: &LoadedPolicy,
    remote_extends: &RemoteExtendsConfig,
) -> Result<Option<Policy>, PolicyLoadError> {
    let Some(extends_name) = loaded.original_extends.as_deref() else {
        return Ok(None);
    };

    let resolver = crate::remote_extends::RemotePolicyResolver::new(remote_extends.clone())
        .map_err(|e| PolicyLoadError {
            message: format!("Failed to initialize remote extends resolver: {}", e),
            source: e,
        })?;

    let resolved = resolver
        .resolve(extends_name, &loaded.source_location)
        .map_err(|e| PolicyLoadError {
            message: format!("Failed to resolve parent policy {:?}: {}", extends_name, e),
            source: e,
        })?;

    let parent = Policy::from_yaml_with_extends_location_resolver(
        &resolved.yaml,
        resolved.location.clone(),
        &resolver,
    )
    .map_err(|e| PolicyLoadError {
        message: format!("Failed to load parent policy {:?}: {}", extends_name, e),
        source: e,
    })?;

    Ok(Some(parent))
}

#[cfg(test)]
mod tests {
    use std::fs;

    use tempfile::tempdir;

    use super::*;

    #[test]
    fn resolve_keeps_parent_reference_for_inheritance_verification() {
        let dir = tempdir().expect("tempdir");
        let parent = dir.path().join("parent.yaml");
        let child = dir.path().join("child.yaml");

        fs::write(
            &parent,
            r#"
version: "1.1.0"
name: "parent"
guards:
  forbidden_path:
    enabled: true
    patterns:
      - "/etc/shadow"
"#,
        )
        .expect("write parent");

        fs::write(
            &child,
            r#"
version: "1.1.0"
name: "child"
extends: "parent.yaml"
guards:
  forbidden_path:
    enabled: true
    remove_patterns:
      - "/etc/shadow"
"#,
        )
        .expect("write child");

        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        let code = cmd_policy_verify(
            PolicyVerifyCommand {
                policy_ref: child.to_string_lossy().into_owned(),
                resolve: true,
                json: false,
                attestation_level: false,
                verbose: false,
            },
            &RemoteExtendsConfig::disabled(),
            &mut stdout,
            &mut stderr,
        );

        assert_eq!(code, ExitCode::Fail);
        let output = String::from_utf8(stdout).expect("utf8 stdout");
        assert!(output.contains("Inheritance"));
        assert!(output.contains("FAIL"));
    }

    #[test]
    fn missing_parent_policy_is_reported_as_error() {
        let dir = tempdir().expect("tempdir");
        let child = dir.path().join("child.yaml");

        fs::write(
            &child,
            r#"
version: "1.1.0"
name: "child"
extends: "missing-parent.yaml"
"#,
        )
        .expect("write child");

        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        let code = cmd_policy_verify(
            PolicyVerifyCommand {
                policy_ref: child.to_string_lossy().into_owned(),
                resolve: false,
                json: false,
                attestation_level: false,
                verbose: false,
            },
            &RemoteExtendsConfig::disabled(),
            &mut stdout,
            &mut stderr,
        );

        assert_eq!(code, ExitCode::ConfigError);
        let error = String::from_utf8(stderr).expect("utf8 stderr");
        assert!(error.contains("missing-parent.yaml"));
    }

    #[test]
    fn verification_resolves_grandparent_chain_even_without_flag() {
        let dir = tempdir().expect("tempdir");
        let grandparent = dir.path().join("grandparent.yaml");
        let parent = dir.path().join("parent.yaml");
        let child = dir.path().join("child.yaml");

        fs::write(
            &grandparent,
            r#"
version: "1.1.0"
name: "grandparent"
guards:
  forbidden_path:
    enabled: true
    patterns:
      - "/etc/shadow"
"#,
        )
        .expect("write grandparent");

        fs::write(
            &parent,
            r#"
version: "1.1.0"
name: "parent"
extends: "grandparent.yaml"
"#,
        )
        .expect("write parent");

        fs::write(
            &child,
            r#"
version: "1.1.0"
name: "child"
extends: "parent.yaml"
guards:
  forbidden_path:
    enabled: true
    exceptions:
      - "/etc/shadow"
"#,
        )
        .expect("write child");

        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        let code = cmd_policy_verify(
            PolicyVerifyCommand {
                policy_ref: child.to_string_lossy().into_owned(),
                resolve: false,
                json: false,
                attestation_level: false,
                verbose: false,
            },
            &RemoteExtendsConfig::disabled(),
            &mut stdout,
            &mut stderr,
        );

        assert_eq!(code, ExitCode::Fail);
        let output = String::from_utf8(stdout).expect("utf8 stdout");
        assert!(output.contains("access(/etc/shadow)"));
        assert!(output.contains("FAIL"));
    }
}
