use std::io::{Read as _, Write};
use std::path::{Path, PathBuf};

use clawdstrike::plugins::{
    PluginCapabilities, PluginFilesystemCapabilities, PluginResourceLimits,
    PluginSecretsCapabilities, PluginTrustLevel,
};
use clawdstrike::{PluginLoader, PluginLoaderOptions, Severity};
use serde::Serialize;

use crate::{CliJsonError, ExitCode, GuardCommands, CLI_JSON_VERSION};

pub fn cmd_guard(
    command: GuardCommands,
    stdout: &mut dyn Write,
    stderr: &mut dyn Write,
) -> ExitCode {
    match command {
        GuardCommands::Inspect { plugin_ref, json } => {
            cmd_guard_inspect(&plugin_ref, json, stdout, stderr)
        }
        GuardCommands::Validate {
            plugin_ref,
            strict,
            json,
        } => cmd_guard_validate(&plugin_ref, strict, json, stdout, stderr),
        GuardCommands::WasmCheck {
            entrypoint,
            guard,
            input_json,
            action_type,
            config_json,
            allow_network,
            allow_subprocess,
            allow_fs_read,
            allow_fs_write,
            allow_secrets,
            max_memory_mb,
            max_cpu_ms,
            max_timeout_ms,
            json,
        } => cmd_guard_wasm_check(
            WasmCheckArgs {
                entrypoint,
                guard,
                input_json,
                action_type,
                config_json,
                allow_network,
                allow_subprocess,
                allow_fs_read,
                allow_fs_write,
                allow_secrets,
                max_memory_mb,
                max_cpu_ms,
                max_timeout_ms,
                json,
            },
            stdout,
            stderr,
        ),
    }
}

fn cmd_guard_inspect(
    plugin_ref: &str,
    json: bool,
    stdout: &mut dyn Write,
    stderr: &mut dyn Write,
) -> ExitCode {
    let loader = guard_loader();
    let inspected = match loader.inspect(plugin_ref) {
        Ok(v) => v,
        Err(e) => {
            return emit_guard_error(
                "guard_inspect",
                json,
                ExitCode::ConfigError,
                "config_error",
                &e.to_string(),
                stdout,
                stderr,
            )
        }
    };

    if json {
        #[derive(Serialize)]
        struct GuardInspectOutput<'a> {
            version: u8,
            command: &'a str,
            plugin_ref: &'a str,
            root: String,
            manifest_path: String,
            plugin_name: String,
            plugin_version: String,
            trust_level: String,
            sandbox: String,
            execution_mode: String,
            guards: Vec<String>,
            exit_code: i32,
            #[serde(skip_serializing_if = "Option::is_none")]
            error: Option<CliJsonError>,
        }

        let out = GuardInspectOutput {
            version: CLI_JSON_VERSION,
            command: "guard_inspect",
            plugin_ref,
            root: inspected.root.display().to_string(),
            manifest_path: inspected.manifest_path.display().to_string(),
            plugin_name: inspected.manifest.plugin.name.clone(),
            plugin_version: inspected.manifest.plugin.version.clone(),
            trust_level: match inspected.manifest.trust.level {
                PluginTrustLevel::Trusted => "trusted".to_string(),
                PluginTrustLevel::Untrusted => "untrusted".to_string(),
            },
            sandbox: format!("{:?}", inspected.manifest.trust.sandbox).to_ascii_lowercase(),
            execution_mode: format!("{:?}", inspected.execution_mode).to_ascii_lowercase(),
            guards: inspected
                .manifest
                .guards
                .iter()
                .map(|g| g.name.clone())
                .collect(),
            exit_code: ExitCode::Ok.as_i32(),
            error: None,
        };
        let _ = writeln!(
            stdout,
            "{}",
            serde_json::to_string_pretty(&out).unwrap_or_else(|_| "{}".to_string())
        );
        return ExitCode::Ok;
    }

    let _ = writeln!(stdout, "Plugin: {}", inspected.manifest.plugin.name);
    let _ = writeln!(stdout, "Version: {}", inspected.manifest.plugin.version);
    let _ = writeln!(stdout, "Root: {}", inspected.root.display());
    let _ = writeln!(stdout, "Manifest: {}", inspected.manifest_path.display());
    let _ = writeln!(
        stdout,
        "Trust: {:?} / {:?}",
        inspected.manifest.trust.level, inspected.manifest.trust.sandbox
    );
    let _ = writeln!(stdout, "Guards:");
    for guard in &inspected.manifest.guards {
        let _ = writeln!(stdout, "- {}", guard.name);
    }
    ExitCode::Ok
}

fn cmd_guard_validate(
    plugin_ref: &str,
    strict: bool,
    json: bool,
    stdout: &mut dyn Write,
    stderr: &mut dyn Write,
) -> ExitCode {
    let loader = guard_loader();
    let inspected = match loader.inspect(plugin_ref) {
        Ok(v) => v,
        Err(e) => {
            return emit_guard_error(
                "guard_validate",
                json,
                ExitCode::ConfigError,
                "config_error",
                &e.to_string(),
                stdout,
                stderr,
            )
        }
    };

    let plan = match loader.plan_load(plugin_ref) {
        Ok(v) => v,
        Err(e) => {
            return emit_guard_error(
                "guard_validate",
                json,
                ExitCode::ConfigError,
                "config_error",
                &e.to_string(),
                stdout,
                stderr,
            )
        }
    };

    if strict && format!("{:?}", inspected.execution_mode).eq_ignore_ascii_case("wasm") {
        #[cfg(feature = "wasm-plugin-runtime")]
        for guard in &inspected.manifest.guards {
            if let Some(entrypoint) = guard.entrypoint.as_deref() {
                let wasm_path = inspected.root.join(entrypoint);
                if let Err(e) = clawdstrike::validate_wasm_guard_module(&wasm_path) {
                    return emit_guard_error(
                        "guard_validate",
                        json,
                        ExitCode::ConfigError,
                        "config_error",
                        &e.to_string(),
                        stdout,
                        stderr,
                    );
                }
            }
        }

        #[cfg(not(feature = "wasm-plugin-runtime"))]
        {
            return emit_guard_error(
                "guard_validate",
                json,
                ExitCode::ConfigError,
                "config_error",
                "strict wasm validation requires `wasm-plugin-runtime` feature",
                stdout,
                stderr,
            );
        }
    }

    if json {
        #[derive(Serialize)]
        struct GuardValidateOutput<'a> {
            version: u8,
            command: &'a str,
            plugin_ref: &'a str,
            plugin_name: String,
            valid: bool,
            strict: bool,
            execution_mode: String,
            guard_ids: Vec<String>,
            exit_code: i32,
            #[serde(skip_serializing_if = "Option::is_none")]
            error: Option<CliJsonError>,
        }

        let out = GuardValidateOutput {
            version: CLI_JSON_VERSION,
            command: "guard_validate",
            plugin_ref,
            plugin_name: inspected.manifest.plugin.name.clone(),
            valid: true,
            strict,
            execution_mode: format!("{:?}", inspected.execution_mode).to_ascii_lowercase(),
            guard_ids: plan.guard_ids,
            exit_code: ExitCode::Ok.as_i32(),
            error: None,
        };
        let _ = writeln!(
            stdout,
            "{}",
            serde_json::to_string_pretty(&out).unwrap_or_else(|_| "{}".to_string())
        );
        return ExitCode::Ok;
    }

    let _ = writeln!(
        stdout,
        "Plugin {} is valid (mode: {:?}, strict: {}).",
        inspected.manifest.plugin.name, inspected.execution_mode, strict
    );
    for guard in &plan.guard_ids {
        let _ = writeln!(stdout, "- {}", guard);
    }
    ExitCode::Ok
}

#[derive(Clone, Debug)]
struct WasmCheckArgs {
    entrypoint: String,
    guard: String,
    input_json: String,
    action_type: Option<String>,
    config_json: String,
    allow_network: bool,
    allow_subprocess: bool,
    allow_fs_read: bool,
    allow_fs_write: bool,
    allow_secrets: bool,
    max_memory_mb: u32,
    max_cpu_ms: u32,
    max_timeout_ms: u32,
    json: bool,
}

fn cmd_guard_wasm_check(
    args: WasmCheckArgs,
    stdout: &mut dyn Write,
    stderr: &mut dyn Write,
) -> ExitCode {
    #[cfg(not(feature = "wasm-plugin-runtime"))]
    {
        return emit_guard_error(
            "guard_wasm_check",
            args.json,
            ExitCode::ConfigError,
            "config_error",
            "wasm guard runtime is not enabled in this build",
            stdout,
            stderr,
        );
    }

    #[cfg(feature = "wasm-plugin-runtime")]
    {
        let payload_json = match read_inline_or_stdin(&args.input_json) {
            Ok(v) => v,
            Err(e) => {
                return emit_guard_error(
                    "guard_wasm_check",
                    args.json,
                    ExitCode::RuntimeError,
                    "runtime_error",
                    &format!("failed to read --input-json: {}", e),
                    stdout,
                    stderr,
                )
            }
        };

        let payload: serde_json::Value = match serde_json::from_str(&payload_json) {
            Ok(v) => v,
            Err(e) => {
                return emit_guard_error(
                    "guard_wasm_check",
                    args.json,
                    ExitCode::ConfigError,
                    "config_error",
                    &format!("invalid --input-json payload: {}", e),
                    stdout,
                    stderr,
                )
            }
        };
        let config: serde_json::Value = match serde_json::from_str(&args.config_json) {
            Ok(v) => v,
            Err(e) => {
                return emit_guard_error(
                    "guard_wasm_check",
                    args.json,
                    ExitCode::ConfigError,
                    "config_error",
                    &format!("invalid --config-json payload: {}", e),
                    stdout,
                    stderr,
                )
            }
        };

        let action_type = args.action_type.clone().or_else(|| {
            payload
                .get("eventType")
                .and_then(|v| v.as_str())
                .map(|s| s.to_string())
        });

        let options = clawdstrike::WasmGuardRuntimeOptions {
            capabilities: PluginCapabilities {
                network: args.allow_network,
                subprocess: args.allow_subprocess,
                filesystem: PluginFilesystemCapabilities {
                    read: if args.allow_fs_read {
                        vec!["*".to_string()]
                    } else {
                        Vec::new()
                    },
                    write: args.allow_fs_write,
                },
                secrets: PluginSecretsCapabilities {
                    access: args.allow_secrets,
                },
            },
            resources: PluginResourceLimits {
                max_memory_mb: args.max_memory_mb,
                max_cpu_ms: args.max_cpu_ms,
                max_timeout_ms: args.max_timeout_ms,
            },
        };

        let envelope = clawdstrike::WasmGuardInputEnvelope {
            guard: args.guard.clone(),
            action_type,
            payload,
            config,
        };

        let execution = match clawdstrike::execute_wasm_guard_module(
            Path::new(&args.entrypoint),
            &envelope,
            &options,
        ) {
            Ok(v) => v,
            Err(e) => {
                return emit_guard_error(
                    "guard_wasm_check",
                    args.json,
                    ExitCode::ConfigError,
                    "config_error",
                    &e.to_string(),
                    stdout,
                    stderr,
                )
            }
        };

        let code = if !execution.result.allowed {
            ExitCode::Fail
        } else if execution.result.severity == Severity::Warning {
            ExitCode::Warn
        } else {
            ExitCode::Ok
        };

        if args.json {
            #[derive(Serialize)]
            struct GuardWasmCheckOutput {
                version: u8,
                command: &'static str,
                result: clawdstrike::GuardResult,
                audit: Vec<clawdstrike::WasmRuntimeAuditRecord>,
                exit_code: i32,
                #[serde(skip_serializing_if = "Option::is_none")]
                error: Option<CliJsonError>,
            }

            let out = GuardWasmCheckOutput {
                version: CLI_JSON_VERSION,
                command: "guard_wasm_check",
                result: execution.result,
                audit: execution.audit,
                exit_code: code.as_i32(),
                error: None,
            };
            let _ = writeln!(
                stdout,
                "{}",
                serde_json::to_string_pretty(&out).unwrap_or_else(|_| "{}".to_string())
            );
            return code;
        }

        if code == ExitCode::Ok || code == ExitCode::Warn {
            let _ = writeln!(stdout, "{}", execution.result.message);
        } else {
            let _ = writeln!(stderr, "{}", execution.result.message);
        }

        code
    }
}

fn guard_loader() -> PluginLoader {
    let from_dir = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."));
    PluginLoader::new(PluginLoaderOptions {
        from_dir,
        trusted_only: false,
        allow_wasm_sandbox: true,
        current_clawdstrike_version: env!("CARGO_PKG_VERSION").to_string(),
        max_resources: None,
    })
}

fn read_inline_or_stdin(raw: &str) -> std::io::Result<String> {
    if raw != "-" {
        return Ok(raw.to_string());
    }

    let mut buf = String::new();
    std::io::stdin().read_to_string(&mut buf)?;
    Ok(buf)
}

fn emit_guard_error(
    command: &'static str,
    json: bool,
    code: ExitCode,
    error_kind: &'static str,
    message: &str,
    stdout: &mut dyn Write,
    stderr: &mut dyn Write,
) -> ExitCode {
    if json {
        #[derive(Serialize)]
        struct GuardErrorOutput {
            version: u8,
            command: &'static str,
            exit_code: i32,
            error: CliJsonError,
        }

        let out = GuardErrorOutput {
            version: CLI_JSON_VERSION,
            command,
            exit_code: code.as_i32(),
            error: CliJsonError {
                kind: error_kind,
                message: message.to_string(),
            },
        };
        let _ = writeln!(
            stdout,
            "{}",
            serde_json::to_string_pretty(&out).unwrap_or_else(|_| "{}".to_string())
        );
        return code;
    }

    let _ = writeln!(stderr, "Error: {}", message);
    code
}
