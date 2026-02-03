use std::io::Write;

use crate::policy_diff::ResolvedPolicySource;
use crate::{CliJsonError, ExitCode, PolicySource, CLI_JSON_VERSION};

#[derive(Clone, Debug, serde::Serialize)]
pub struct PolicyVersionJsonOutput {
    pub version: u8,
    pub command: &'static str,
    pub policy: PolicySource,
    pub policy_version: Option<String>,
    pub supported_schema_version: String,
    pub compatible: bool,
    pub exit_code: i32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<CliJsonError>,
}

pub fn cmd_policy_version(
    policy_ref: String,
    resolve: bool,
    json: bool,
    stdout: &mut dyn Write,
    stderr: &mut dyn Write,
) -> ExitCode {
    let supported = clawdstrike::policy::POLICY_SCHEMA_VERSION.to_string();

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
                let output = PolicyVersionJsonOutput {
                    version: CLI_JSON_VERSION,
                    command: "policy_version",
                    policy: guess_policy_source(&policy_ref),
                    policy_version: None,
                    supported_schema_version: supported,
                    compatible: false,
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

    let policy = loaded.policy;
    let policy_source = policy_source_for_loaded(&loaded.source);

    let compatible = policy.version == supported;
    let code = if compatible {
        ExitCode::Ok
    } else {
        ExitCode::ConfigError
    };

    if json {
        let output = PolicyVersionJsonOutput {
            version: CLI_JSON_VERSION,
            command: "policy_version",
            policy: policy_source,
            policy_version: Some(policy.version),
            supported_schema_version: supported,
            compatible,
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

    let _ = writeln!(stdout, "Policy version: {}", policy.version);
    let _ = writeln!(stdout, "Supported schema: {}", supported);
    if compatible {
        let _ = writeln!(stdout, "Compatibility: OK");
    } else {
        let _ = writeln!(stderr, "Compatibility: INCOMPATIBLE");
    }

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
