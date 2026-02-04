use std::io::Write;

use clawdstrike::{PolicyBundle, SignedPolicyBundle};
use hush_core::{Keypair, PublicKey};

use crate::policy_diff::{load_policy_from_arg, ResolvedPolicySource};
use crate::{CliJsonError, ExitCode, PolicyBundleCommands, PolicySource, CLI_JSON_VERSION};

#[derive(Clone, Debug, serde::Serialize)]
struct PolicyBundleBuildJsonOutput {
    version: u8,
    command: &'static str,
    policy: PolicySource,
    output: String,
    bundle_id: Option<String>,
    policy_hash: Option<String>,
    signature: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    public_key: Option<String>,
    exit_code: i32,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<CliJsonError>,
}

#[derive(Clone, Debug, serde::Serialize)]
struct PolicyBundleVerifyJsonOutput {
    version: u8,
    command: &'static str,
    bundle: String,
    pubkey: Option<String>,
    valid: bool,
    exit_code: i32,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<CliJsonError>,
}

pub fn cmd_policy_bundle(
    command: PolicyBundleCommands,
    stdout: &mut dyn Write,
    stderr: &mut dyn Write,
) -> ExitCode {
    match command {
        PolicyBundleCommands::Build {
            policy_ref,
            resolve,
            key,
            output,
            embed_pubkey,
            source,
            json,
        } => cmd_policy_bundle_build(
            policy_ref,
            resolve,
            key,
            output,
            embed_pubkey,
            source,
            json,
            stdout,
            stderr,
        ),

        PolicyBundleCommands::Verify {
            bundle,
            pubkey,
            json,
        } => cmd_policy_bundle_verify(bundle, pubkey, json, stdout, stderr),
    }
}

#[allow(clippy::too_many_arguments)]
fn cmd_policy_bundle_build(
    policy_ref: String,
    resolve: bool,
    key: String,
    output: String,
    embed_pubkey: bool,
    source: Vec<String>,
    json: bool,
    stdout: &mut dyn Write,
    stderr: &mut dyn Write,
) -> ExitCode {
    let loaded = match load_policy_from_arg(&policy_ref, resolve) {
        Ok(v) => v,
        Err(e) => {
            let code = crate::policy_error_exit_code(&e.source);
            let kind = if code == ExitCode::RuntimeError {
                "runtime_error"
            } else {
                "config_error"
            };

            if json {
                let output = PolicyBundleBuildJsonOutput {
                    version: CLI_JSON_VERSION,
                    command: "policy_bundle_build",
                    policy: guess_policy_source(&policy_ref),
                    output,
                    bundle_id: None,
                    policy_hash: None,
                    signature: None,
                    public_key: None,
                    exit_code: code.as_i32(),
                    error: Some(CliJsonError {
                        kind,
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

    let key_hex = match std::fs::read_to_string(&key) {
        Ok(v) => v.trim().to_string(),
        Err(e) => {
            if json {
                let output = PolicyBundleBuildJsonOutput {
                    version: CLI_JSON_VERSION,
                    command: "policy_bundle_build",
                    policy: policy_source_for_loaded(&loaded.source),
                    output,
                    bundle_id: None,
                    policy_hash: None,
                    signature: None,
                    public_key: None,
                    exit_code: ExitCode::RuntimeError.as_i32(),
                    error: Some(CliJsonError {
                        kind: "runtime_error",
                        message: format!("Failed to read key file: {}", e),
                    }),
                };
                let _ = writeln!(
                    stdout,
                    "{}",
                    serde_json::to_string_pretty(&output).unwrap_or_else(|_| "{}".to_string())
                );
                return ExitCode::RuntimeError;
            }

            let _ = writeln!(stderr, "Error: Failed to read key file: {}", e);
            return ExitCode::RuntimeError;
        }
    };

    let keypair = match Keypair::from_hex(&key_hex) {
        Ok(v) => v,
        Err(e) => {
            if json {
                let output = PolicyBundleBuildJsonOutput {
                    version: CLI_JSON_VERSION,
                    command: "policy_bundle_build",
                    policy: policy_source_for_loaded(&loaded.source),
                    output,
                    bundle_id: None,
                    policy_hash: None,
                    signature: None,
                    public_key: None,
                    exit_code: ExitCode::ConfigError.as_i32(),
                    error: Some(CliJsonError {
                        kind: "config_error",
                        message: format!("Invalid signing key: {}", e),
                    }),
                };
                let _ = writeln!(
                    stdout,
                    "{}",
                    serde_json::to_string_pretty(&output).unwrap_or_else(|_| "{}".to_string())
                );
                return ExitCode::ConfigError;
            }

            let _ = writeln!(stderr, "Error: Invalid signing key: {}", e);
            return ExitCode::ConfigError;
        }
    };

    let mut sources = vec![loaded.source.describe()];
    sources.extend(source);

    let bundle = match PolicyBundle::new_with_sources(loaded.policy, sources) {
        Ok(v) => v,
        Err(e) => {
            let code = crate::policy_error_exit_code(&e);
            if json {
                let output = PolicyBundleBuildJsonOutput {
                    version: CLI_JSON_VERSION,
                    command: "policy_bundle_build",
                    policy: policy_source_for_loaded(&loaded.source),
                    output,
                    bundle_id: None,
                    policy_hash: None,
                    signature: None,
                    public_key: None,
                    exit_code: code.as_i32(),
                    error: Some(CliJsonError {
                        kind: "config_error",
                        message: format!("Failed to build bundle: {}", e),
                    }),
                };
                let _ = writeln!(
                    stdout,
                    "{}",
                    serde_json::to_string_pretty(&output).unwrap_or_else(|_| "{}".to_string())
                );
                return code;
            }

            let _ = writeln!(stderr, "Error: Failed to build bundle: {}", e);
            return code;
        }
    };

    let signed = if embed_pubkey {
        SignedPolicyBundle::sign_with_public_key(bundle, &keypair)
    } else {
        SignedPolicyBundle::sign(bundle, &keypair)
    };
    let signed = match signed {
        Ok(v) => v,
        Err(e) => {
            let code = crate::policy_error_exit_code(&e);
            if json {
                let output = PolicyBundleBuildJsonOutput {
                    version: CLI_JSON_VERSION,
                    command: "policy_bundle_build",
                    policy: policy_source_for_loaded(&loaded.source),
                    output,
                    bundle_id: None,
                    policy_hash: None,
                    signature: None,
                    public_key: None,
                    exit_code: code.as_i32(),
                    error: Some(CliJsonError {
                        kind: "runtime_error",
                        message: format!("Failed to sign bundle: {}", e),
                    }),
                };
                let _ = writeln!(
                    stdout,
                    "{}",
                    serde_json::to_string_pretty(&output).unwrap_or_else(|_| "{}".to_string())
                );
                return code;
            }

            let _ = writeln!(stderr, "Error: Failed to sign bundle: {}", e);
            return code;
        }
    };

    let json_out = match serde_json::to_string_pretty(&signed) {
        Ok(v) => v,
        Err(e) => {
            if json {
                let output = PolicyBundleBuildJsonOutput {
                    version: CLI_JSON_VERSION,
                    command: "policy_bundle_build",
                    policy: policy_source_for_loaded(&loaded.source),
                    output,
                    bundle_id: None,
                    policy_hash: None,
                    signature: None,
                    public_key: None,
                    exit_code: ExitCode::RuntimeError.as_i32(),
                    error: Some(CliJsonError {
                        kind: "runtime_error",
                        message: format!("Failed to serialize bundle: {}", e),
                    }),
                };
                let _ = writeln!(
                    stdout,
                    "{}",
                    serde_json::to_string_pretty(&output).unwrap_or_else(|_| "{}".to_string())
                );
                return ExitCode::RuntimeError;
            }

            let _ = writeln!(stderr, "Error: Failed to serialize bundle: {}", e);
            return ExitCode::RuntimeError;
        }
    };

    if let Err(e) = std::fs::write(&output, json_out.as_bytes()) {
        if json {
            let output = PolicyBundleBuildJsonOutput {
                version: CLI_JSON_VERSION,
                command: "policy_bundle_build",
                policy: policy_source_for_loaded(&loaded.source),
                output,
                bundle_id: None,
                policy_hash: None,
                signature: None,
                public_key: None,
                exit_code: ExitCode::RuntimeError.as_i32(),
                error: Some(CliJsonError {
                    kind: "runtime_error",
                    message: format!("Failed to write output file: {}", e),
                }),
            };
            let _ = writeln!(
                stdout,
                "{}",
                serde_json::to_string_pretty(&output).unwrap_or_else(|_| "{}".to_string())
            );
            return ExitCode::RuntimeError;
        }

        let _ = writeln!(stderr, "Error: Failed to write output file: {}", e);
        return ExitCode::RuntimeError;
    }

    let bundle_id = signed.bundle.bundle_id.clone();
    let policy_hash = signed.bundle.policy_hash.to_hex_prefixed();
    let signature = signed.signature.to_hex_prefixed();
    let public_key = signed.public_key.as_ref().map(|k| k.to_hex_prefixed());

    if json {
        let output = PolicyBundleBuildJsonOutput {
            version: CLI_JSON_VERSION,
            command: "policy_bundle_build",
            policy: policy_source_for_loaded(&loaded.source),
            output,
            bundle_id: Some(bundle_id),
            policy_hash: Some(policy_hash),
            signature: Some(signature),
            public_key,
            exit_code: ExitCode::Ok.as_i32(),
            error: None,
        };
        let _ = writeln!(
            stdout,
            "{}",
            serde_json::to_string_pretty(&output).unwrap_or_else(|_| "{}".to_string())
        );
        return ExitCode::Ok;
    }

    let _ = writeln!(stdout, "Wrote policy bundle: {}", output);
    let _ = writeln!(stdout, "  Bundle ID:   {}", bundle_id);
    let _ = writeln!(stdout, "  Policy hash: {}", policy_hash);
    if let Some(pk) = public_key {
        let _ = writeln!(stdout, "  Public key:  {}", pk);
    }
    ExitCode::Ok
}

fn cmd_policy_bundle_verify(
    bundle: String,
    pubkey: Option<String>,
    json: bool,
    stdout: &mut dyn Write,
    stderr: &mut dyn Write,
) -> ExitCode {
    let body = match std::fs::read_to_string(&bundle) {
        Ok(v) => v,
        Err(e) => {
            if json {
                let output = PolicyBundleVerifyJsonOutput {
                    version: CLI_JSON_VERSION,
                    command: "policy_bundle_verify",
                    bundle,
                    pubkey,
                    valid: false,
                    exit_code: ExitCode::RuntimeError.as_i32(),
                    error: Some(CliJsonError {
                        kind: "runtime_error",
                        message: format!("Failed to read bundle: {}", e),
                    }),
                };
                let _ = writeln!(
                    stdout,
                    "{}",
                    serde_json::to_string_pretty(&output).unwrap_or_else(|_| "{}".to_string())
                );
                return ExitCode::RuntimeError;
            }

            let _ = writeln!(stderr, "Error: Failed to read bundle: {}", e);
            return ExitCode::RuntimeError;
        }
    };

    let signed: SignedPolicyBundle = match serde_json::from_str(&body) {
        Ok(v) => v,
        Err(e) => {
            if json {
                let output = PolicyBundleVerifyJsonOutput {
                    version: CLI_JSON_VERSION,
                    command: "policy_bundle_verify",
                    bundle,
                    pubkey,
                    valid: false,
                    exit_code: ExitCode::ConfigError.as_i32(),
                    error: Some(CliJsonError {
                        kind: "config_error",
                        message: format!("Invalid bundle JSON: {}", e),
                    }),
                };
                let _ = writeln!(
                    stdout,
                    "{}",
                    serde_json::to_string_pretty(&output).unwrap_or_else(|_| "{}".to_string())
                );
                return ExitCode::ConfigError;
            }

            let _ = writeln!(stderr, "Error: Invalid bundle JSON: {}", e);
            return ExitCode::ConfigError;
        }
    };

    let (public_key, pubkey_path) = match pubkey {
        Some(path) => match std::fs::read_to_string(&path) {
            Ok(v) => {
                let v = v.trim().to_string();
                match PublicKey::from_hex(&v) {
                    Ok(pk) => (Some(pk), Some(path)),
                    Err(e) => {
                        if json {
                            let output = PolicyBundleVerifyJsonOutput {
                                version: CLI_JSON_VERSION,
                                command: "policy_bundle_verify",
                                bundle,
                                pubkey: Some(path),
                                valid: false,
                                exit_code: ExitCode::ConfigError.as_i32(),
                                error: Some(CliJsonError {
                                    kind: "config_error",
                                    message: format!("Invalid pubkey: {}", e),
                                }),
                            };
                            let _ = writeln!(
                                stdout,
                                "{}",
                                serde_json::to_string_pretty(&output)
                                    .unwrap_or_else(|_| "{}".to_string())
                            );
                            return ExitCode::ConfigError;
                        }

                        let _ = writeln!(stderr, "Error: Invalid pubkey: {}", e);
                        return ExitCode::ConfigError;
                    }
                }
            }
            Err(e) => {
                if json {
                    let output = PolicyBundleVerifyJsonOutput {
                        version: CLI_JSON_VERSION,
                        command: "policy_bundle_verify",
                        bundle,
                        pubkey: Some(path),
                        valid: false,
                        exit_code: ExitCode::RuntimeError.as_i32(),
                        error: Some(CliJsonError {
                            kind: "runtime_error",
                            message: format!("Failed to read pubkey file: {}", e),
                        }),
                    };
                    let _ = writeln!(
                        stdout,
                        "{}",
                        serde_json::to_string_pretty(&output).unwrap_or_else(|_| "{}".to_string())
                    );
                    return ExitCode::RuntimeError;
                }

                let _ = writeln!(stderr, "Error: Failed to read pubkey file: {}", e);
                return ExitCode::RuntimeError;
            }
        },
        None => (None, None),
    };

    let valid = match public_key.as_ref() {
        Some(pk) => signed.verify(pk),
        None => signed.verify_embedded(),
    };
    let valid = match valid {
        Ok(v) => v,
        Err(e) => {
            let code = crate::policy_error_exit_code(&e);
            if json {
                let output = PolicyBundleVerifyJsonOutput {
                    version: CLI_JSON_VERSION,
                    command: "policy_bundle_verify",
                    bundle,
                    pubkey: pubkey_path,
                    valid: false,
                    exit_code: code.as_i32(),
                    error: Some(CliJsonError {
                        kind: "config_error",
                        message: format!("Verification failed: {}", e),
                    }),
                };
                let _ = writeln!(
                    stdout,
                    "{}",
                    serde_json::to_string_pretty(&output).unwrap_or_else(|_| "{}".to_string())
                );
                return code;
            }

            let _ = writeln!(stderr, "Error: Verification failed: {}", e);
            return code;
        }
    };

    let code = if valid { ExitCode::Ok } else { ExitCode::Fail };

    if json {
        let output = PolicyBundleVerifyJsonOutput {
            version: CLI_JSON_VERSION,
            command: "policy_bundle_verify",
            bundle,
            pubkey: pubkey_path,
            valid,
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

    if valid {
        let _ = writeln!(stdout, "VALID: Policy bundle signature verified");
    } else {
        let _ = writeln!(stderr, "INVALID: Policy bundle signature failed");
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
