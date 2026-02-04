use std::io::{Read, Write};

use crate::{CliJsonError, ExitCode, CLI_JSON_VERSION};

#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PolicyMigrateMode {
    VersionBump,
    LegacyOpenclaw,
}

#[derive(Clone, Debug, serde::Serialize)]
pub struct PolicyMigrateJsonOutput {
    pub version: u8,
    pub command: &'static str,
    pub input: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub detected_from_version: Option<String>,
    pub to_version: String,
    pub mode: PolicyMigrateMode,
    pub dry_run: bool,
    pub wrote: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub output_path: Option<String>,
    pub warnings: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub migrated_yaml: Option<String>,
    /// Full legacy input (only set for legacy OpenClaw migrations).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub legacy_openclaw: Option<serde_json::Value>,
    pub exit_code: i32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<CliJsonError>,
}

#[derive(Clone, Debug)]
pub(crate) struct PolicyMigrateResult {
    pub migrated_yaml: String,
    pub detected_from_version: Option<String>,
    pub mode: PolicyMigrateMode,
    pub warnings: Vec<String>,
    pub legacy_openclaw: Option<serde_json::Value>,
}

#[derive(Clone, Debug)]
pub(crate) struct PolicyMigrateOptions {
    pub from: Option<String>,
    pub to: String,
    pub legacy_openclaw: bool,
}

#[derive(Clone, Debug)]
pub(crate) struct PolicyMigrateError {
    pub code: ExitCode,
    pub kind: &'static str,
    pub message: String,
}

pub fn cmd_policy_migrate(
    input: String,
    from: Option<String>,
    to: String,
    legacy_openclaw: bool,
    output: Option<String>,
    in_place: bool,
    json: bool,
    dry_run: bool,
    stdout: &mut dyn Write,
    stderr: &mut dyn Write,
) -> ExitCode {
    let supported_to = clawdstrike::policy::POLICY_SCHEMA_VERSION.to_string();
    if to != supported_to {
        return emit_error(
            json,
            PolicyMigrateJsonOutput {
                version: CLI_JSON_VERSION,
                command: "policy_migrate",
                input,
                detected_from_version: None,
                to_version: to,
                mode: PolicyMigrateMode::VersionBump,
                dry_run,
                wrote: false,
                output_path: output,
                warnings: vec![],
                migrated_yaml: None,
                legacy_openclaw: None,
                exit_code: ExitCode::InvalidArgs.as_i32(),
                error: Some(CliJsonError {
                    kind: "invalid_args",
                    message: format!(
                        "Unsupported target schema version. Supported: {}",
                        supported_to
                    ),
                }),
            },
            stdout,
            stderr,
        );
    }

    if in_place && input == "-" {
        return emit_error(
            json,
            PolicyMigrateJsonOutput {
                version: CLI_JSON_VERSION,
                command: "policy_migrate",
                input,
                detected_from_version: None,
                to_version: to,
                mode: PolicyMigrateMode::VersionBump,
                dry_run,
                wrote: false,
                output_path: output,
                warnings: vec![],
                migrated_yaml: None,
                legacy_openclaw: None,
                exit_code: ExitCode::InvalidArgs.as_i32(),
                error: Some(CliJsonError {
                    kind: "invalid_args",
                    message: "--in-place cannot be used when input is stdin ('-')".to_string(),
                }),
            },
            stdout,
            stderr,
        );
    }

    let output_path = if in_place { Some(input.clone()) } else { output };

    let input_yaml = match read_input_yaml(&input) {
        Ok(v) => v,
        Err(e) => {
            return emit_error(
                json,
                PolicyMigrateJsonOutput {
                    version: CLI_JSON_VERSION,
                    command: "policy_migrate",
                    input,
                    detected_from_version: None,
                    to_version: to,
                    mode: PolicyMigrateMode::VersionBump,
                    dry_run,
                    wrote: false,
                    output_path,
                    warnings: vec![],
                    migrated_yaml: None,
                    legacy_openclaw: None,
                    exit_code: ExitCode::RuntimeError.as_i32(),
                    error: Some(CliJsonError {
                        kind: "runtime_error",
                        message: format!("Failed to read input: {}", e),
                    }),
                },
                stdout,
                stderr,
            );
        }
    };

    let result = match migrate_policy_yaml(
        &input_yaml,
        &PolicyMigrateOptions {
            from,
            to: to.clone(),
            legacy_openclaw,
        },
    ) {
        Ok(v) => v,
        Err(e) => {
            return emit_error(
                json,
                PolicyMigrateJsonOutput {
                    version: CLI_JSON_VERSION,
                    command: "policy_migrate",
                    input,
                    detected_from_version: None,
                    to_version: to,
                    mode: PolicyMigrateMode::VersionBump,
                    dry_run,
                    wrote: false,
                    output_path,
                    warnings: vec![],
                    migrated_yaml: None,
                    legacy_openclaw: None,
                    exit_code: e.code.as_i32(),
                    error: Some(CliJsonError {
                        kind: e.kind,
                        message: e.message,
                    }),
                },
                stdout,
                stderr,
            );
        }
    };

    for w in &result.warnings {
        let _ = writeln!(stderr, "Warning: {}", w);
    }

    if dry_run {
        if json {
            let output = PolicyMigrateJsonOutput {
                version: CLI_JSON_VERSION,
                command: "policy_migrate",
                input,
                detected_from_version: result.detected_from_version,
                to_version: to,
                mode: result.mode,
                dry_run: true,
                wrote: false,
                output_path,
                warnings: result.warnings,
                migrated_yaml: None,
                legacy_openclaw: result.legacy_openclaw,
                exit_code: ExitCode::Ok.as_i32(),
                error: None,
            };

            let _ = writeln!(
                stdout,
                "{}",
                serde_json::to_string_pretty(&output).unwrap_or_else(|_| "{}".to_string())
            );
        } else if let Some(path) = output_path.as_deref() {
            let _ = writeln!(stdout, "Dry run: would write migrated policy to {}", path);
        } else {
            let _ = writeln!(stdout, "Dry run: would emit migrated policy to stdout");
        }

        return ExitCode::Ok;
    }

    let mut wrote = false;
    if let Some(path) = output_path.as_deref() {
        match std::fs::write(path, &result.migrated_yaml) {
            Ok(()) => wrote = true,
            Err(e) => {
                return emit_error(
                    json,
                    PolicyMigrateJsonOutput {
                        version: CLI_JSON_VERSION,
                        command: "policy_migrate",
                        input,
                        detected_from_version: result.detected_from_version,
                        to_version: to,
                        mode: result.mode,
                        dry_run: false,
                        wrote: false,
                        output_path,
                        warnings: result.warnings,
                        migrated_yaml: None,
                        legacy_openclaw: result.legacy_openclaw,
                        exit_code: ExitCode::RuntimeError.as_i32(),
                        error: Some(CliJsonError {
                            kind: "runtime_error",
                            message: format!("Failed to write output: {}", e),
                        }),
                    },
                    stdout,
                    stderr,
                );
            }
        }
    } else if !json {
        let _ = write!(stdout, "{}", result.migrated_yaml);
    }

    if json {
        let output = PolicyMigrateJsonOutput {
            version: CLI_JSON_VERSION,
            command: "policy_migrate",
            input,
            detected_from_version: result.detected_from_version,
            to_version: to,
            mode: result.mode,
            dry_run: false,
            wrote,
            output_path,
            warnings: result.warnings,
            migrated_yaml: if wrote { None } else { Some(result.migrated_yaml) },
            legacy_openclaw: result.legacy_openclaw,
            exit_code: ExitCode::Ok.as_i32(),
            error: None,
        };

        let _ = writeln!(
            stdout,
            "{}",
            serde_json::to_string_pretty(&output).unwrap_or_else(|_| "{}".to_string())
        );
    }

    ExitCode::Ok
}

fn emit_error(
    json: bool,
    output: PolicyMigrateJsonOutput,
    stdout: &mut dyn Write,
    stderr: &mut dyn Write,
) -> ExitCode {
    let code = exit_code_from_i32(output.exit_code);
    if json {
        let out = output;
        let _ = writeln!(
            stdout,
            "{}",
            serde_json::to_string_pretty(&out).unwrap_or_else(|_| "{}".to_string())
        );
    } else if let Some(err) = output.error {
        let _ = writeln!(stderr, "Error: {}", err.message);
    } else {
        let _ = writeln!(stderr, "Error");
    }

    code
}

fn exit_code_from_i32(code: i32) -> ExitCode {
    if code == ExitCode::Ok.as_i32() {
        return ExitCode::Ok;
    }
    if code == ExitCode::Warn.as_i32() {
        return ExitCode::Warn;
    }
    if code == ExitCode::Fail.as_i32() {
        return ExitCode::Fail;
    }
    if code == ExitCode::ConfigError.as_i32() {
        return ExitCode::ConfigError;
    }
    if code == ExitCode::RuntimeError.as_i32() {
        return ExitCode::RuntimeError;
    }
    if code == ExitCode::InvalidArgs.as_i32() {
        return ExitCode::InvalidArgs;
    }
    ExitCode::InvalidArgs
}

fn read_input_yaml(input: &str) -> std::io::Result<String> {
    if input == "-" {
        let mut buf = String::new();
        std::io::stdin().read_to_string(&mut buf)?;
        return Ok(buf);
    }
    std::fs::read_to_string(input)
}

pub(crate) fn migrate_policy_yaml(
    input_yaml: &str,
    opts: &PolicyMigrateOptions,
) -> Result<PolicyMigrateResult, PolicyMigrateError> {
    let mut input_value: serde_json::Value = serde_yaml::from_str(input_yaml).map_err(|e| {
        PolicyMigrateError {
            code: ExitCode::ConfigError,
            kind: "config_error",
            message: format!("Failed to parse YAML: {}", e),
        }
    })?;

    let obj = input_value.as_object_mut().ok_or_else(|| PolicyMigrateError {
        code: ExitCode::ConfigError,
        kind: "config_error",
        message: "Policy YAML must be a mapping/object".to_string(),
    })?;

    let detected_version = obj
        .get("version")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());

    let is_legacy =
        opts.legacy_openclaw || looks_like_legacy_openclaw(obj, detected_version.as_deref());

    if is_legacy && opts.from.is_some() {
        return Err(PolicyMigrateError {
            code: ExitCode::InvalidArgs,
            kind: "invalid_args",
            message: "Refusing to use --from with legacy OpenClaw-shaped inputs; use --legacy-openclaw (or omit --from)".to_string(),
        });
    }

    if !is_legacy {
        if let Some(from) = opts.from.as_deref() {
            match detected_version.as_deref() {
                Some(v) if v == from => {}
                Some(v) => {
                    return Err(PolicyMigrateError {
                        code: ExitCode::InvalidArgs,
                        kind: "invalid_args",
                        message: format!(
                            "Input policy version mismatch: detected {} but --from {} was provided",
                            v, from
                        ),
                    });
                }
                None => {
                    return Err(PolicyMigrateError {
                        code: ExitCode::InvalidArgs,
                        kind: "invalid_args",
                        message: "Input policy is missing a string 'version' field; specify --legacy-openclaw if this is an OpenClaw-shaped policy".to_string(),
                    });
                }
            }
        } else if detected_version.is_none() {
            return Err(PolicyMigrateError {
                code: ExitCode::InvalidArgs,
                kind: "invalid_args",
                message: "Input policy is missing a string 'version' field; specify --legacy-openclaw if this is an OpenClaw-shaped policy".to_string(),
            });
        }
    }

    let mut warnings: Vec<String> = Vec::new();
    let mut legacy_openclaw: Option<serde_json::Value> = None;

    let out_value = if is_legacy {
        legacy_openclaw = Some(input_value.clone());
        let translated = translate_legacy_openclaw(&input_value, &opts.to, &mut warnings);
        translated
    } else {
        obj.insert(
            "version".to_string(),
            serde_json::Value::String(opts.to.clone()),
        );
        input_value
    };

    let migrated_yaml = serde_yaml::to_string(&out_value).map_err(|e| PolicyMigrateError {
        code: ExitCode::RuntimeError,
        kind: "runtime_error",
        message: format!("Failed to serialize migrated policy: {}", e),
    })?;

    clawdstrike::Policy::from_yaml(&migrated_yaml).map_err(|e| PolicyMigrateError {
        code: ExitCode::ConfigError,
        kind: "config_error",
        message: format!(
            "Migrated policy failed validation under {}: {}",
            opts.to, e
        ),
    })?;

    Ok(PolicyMigrateResult {
        migrated_yaml,
        detected_from_version: detected_version,
        mode: if is_legacy {
            PolicyMigrateMode::LegacyOpenclaw
        } else {
            PolicyMigrateMode::VersionBump
        },
        warnings,
        legacy_openclaw,
    })
}

fn looks_like_legacy_openclaw(
    obj: &serde_json::Map<String, serde_json::Value>,
    version: Option<&str>,
) -> bool {
    if matches!(version, Some("clawdstrike-v1.0")) {
        return true;
    }

    // Heuristic: OpenClaw-shaped keys that never exist in canonical v1 policy schema.
    const LEGACY_KEYS: [&str; 6] = ["filesystem", "egress", "execution", "tools", "limits", "on_violation"];
    LEGACY_KEYS.iter().any(|k| obj.contains_key(*k))
}

fn translate_legacy_openclaw(
    legacy: &serde_json::Value,
    to_version: &str,
    warnings: &mut Vec<String>,
) -> serde_json::Value {
    let legacy_obj = legacy.as_object().cloned().unwrap_or_default();

    warnings.push(format!(
        "Loaded legacy OpenClaw policy schema; translated to canonical ({})",
        to_version
    ));

    let mut out = serde_json::Map::new();
    out.insert(
        "version".to_string(),
        serde_json::Value::String(to_version.to_string()),
    );

    if let Some(v) = legacy_obj.get("name").and_then(|v| v.as_str()) {
        out.insert("name".to_string(), serde_json::Value::String(v.to_string()));
    }
    if let Some(v) = legacy_obj.get("description").and_then(|v| v.as_str()) {
        out.insert(
            "description".to_string(),
            serde_json::Value::String(v.to_string()),
        );
    }
    if let Some(v) = legacy_obj.get("extends").and_then(|v| v.as_str()) {
        out.insert(
            "extends".to_string(),
            serde_json::Value::String(v.to_string()),
        );
    }

    // Preserve custom_guards if present (canonical feature).
    if let Some(v) = legacy_obj.get("custom_guards").and_then(|v| v.as_array()) {
        out.insert("custom_guards".to_string(), serde_json::Value::Array(v.clone()));
    }

    let mut guards: serde_json::Map<String, serde_json::Value> = serde_json::Map::new();

    // Preserve canonical custom guards (`guards.custom[]`) if present.
    if let Some(g) = legacy_obj.get("guards").and_then(|v| v.as_object()) {
        if let Some(v) = g.get("custom").and_then(|v| v.as_array()) {
            guards.insert("custom".to_string(), serde_json::Value::Array(v.clone()));
        }
    }

    // filesystem.forbidden_paths[] -> guards.forbidden_path.patterns[]
    if let Some(fs) = legacy_obj.get("filesystem").and_then(|v| v.as_object()) {
        if let Some(forbidden) = fs
            .get("forbidden_paths")
            .and_then(|v| v.as_array())
            .and_then(string_array)
        {
            guards.insert(
                "forbidden_path".to_string(),
                serde_json::json!({ "patterns": forbidden }),
            );
        }
    }

    // egress.* -> guards.egress_allowlist
    if let Some(egress) = legacy_obj.get("egress").and_then(|v| v.as_object()) {
        let mode = egress.get("mode").and_then(|v| v.as_str());
        let allow = egress
            .get("allowed_domains")
            .and_then(|v| v.as_array())
            .and_then(string_array)
            .unwrap_or_default();
        let block = egress
            .get("denied_domains")
            .and_then(|v| v.as_array())
            .and_then(string_array)
            .unwrap_or_default();

        if let Some(cidrs) = egress
            .get("allowed_cidrs")
            .and_then(|v| v.as_array())
            .and_then(string_array)
        {
            if !cidrs.is_empty() {
                warnings.push(
                    "Legacy field egress.allowed_cidrs is not supported in canonical schema and will be ignored."
                        .to_string(),
                );
            }
        }

        let egress_allowlist = match mode {
            Some("allowlist") => Some(serde_json::json!({
                "allow": allow,
                "block": block,
                "default_action": "block",
            })),
            Some("denylist") | Some("open") => Some(serde_json::json!({
                "allow": [],
                "block": block,
                "default_action": "allow",
            })),
            Some("deny_all") => Some(serde_json::json!({
                "allow": [],
                "block": [],
                "default_action": "block",
            })),
            _ => None,
        };

        if let Some(cfg) = egress_allowlist {
            guards.insert("egress_allowlist".to_string(), cfg);
        }
    }

    // tools.allowed/denied -> guards.mcp_tool
    if let Some(tools) = legacy_obj.get("tools").and_then(|v| v.as_object()) {
        let allow = tools
            .get("allowed")
            .and_then(|v| v.as_array())
            .and_then(string_array)
            .unwrap_or_default();
        let block = tools
            .get("denied")
            .and_then(|v| v.as_array())
            .and_then(string_array)
            .unwrap_or_default();

        if !allow.is_empty() || !block.is_empty() {
            guards.insert(
                "mcp_tool".to_string(),
                serde_json::json!({
                    "allow": allow,
                    "block": block,
                    "default_action": if !allow.is_empty() { "block" } else { "allow" },
                }),
            );
        }
    }

    out.insert("guards".to_string(), serde_json::Value::Object(guards));

    serde_json::Value::Object(out)
}

fn string_array(values: &Vec<serde_json::Value>) -> Option<Vec<String>> {
    if !values.iter().all(|v| v.is_string()) {
        return None;
    }
    Some(
        values
            .iter()
            .filter_map(|v| v.as_str().map(|s| s.to_string()))
            .collect(),
    )
}
