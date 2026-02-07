use std::io::{Read as _, Write};

use crate::{CliJsonError, ExitCode, RegoCommands, CLI_JSON_VERSION};

pub fn cmd_policy_rego(
    command: RegoCommands,
    stdout: &mut dyn Write,
    stderr: &mut dyn Write,
) -> ExitCode {
    match command {
        RegoCommands::Compile {
            file,
            entrypoint,
            json,
        } => cmd_rego_compile(file, entrypoint, json, stdout, stderr),
        RegoCommands::Eval {
            file,
            input,
            entrypoint,
            trace,
            json,
        } => cmd_rego_eval(file, input, entrypoint, trace, json, stdout, stderr),
    }
}

#[cfg(feature = "rego-runtime")]
fn cmd_rego_compile(
    file: String,
    entrypoint: Option<String>,
    json: bool,
    stdout: &mut dyn Write,
    stderr: &mut dyn Write,
) -> ExitCode {
    let module = match std::fs::read_to_string(&file) {
        Ok(v) => v,
        Err(e) => {
            return emit_rego_error(
                "policy_rego_compile",
                json,
                ExitCode::RuntimeError,
                "runtime_error",
                &format!("Failed to read Rego file: {}", e),
                stdout,
                stderr,
            )
        }
    };

    let mut engine = regorus::Engine::new();
    if let Err(e) = engine.add_policy(file.clone(), module) {
        return emit_rego_error(
            "policy_rego_compile",
            json,
            ExitCode::ConfigError,
            "config_error",
            &format!("Failed to compile Rego module: {}", e),
            stdout,
            stderr,
        );
    }

    if let Some(ep) = entrypoint.as_deref() {
        let query = normalize_entrypoint(ep);
        if let Err(e) = engine.eval_query(query.clone(), false) {
            return emit_rego_error(
                "policy_rego_compile",
                json,
                ExitCode::ConfigError,
                "config_error",
                &format!("Entrypoint query failed ({query}): {}", e),
                stdout,
                stderr,
            );
        }
    }

    if json {
        #[derive(serde::Serialize)]
        struct RegoCompileOutput {
            version: u8,
            command: &'static str,
            file: String,
            entrypoint: Option<String>,
            compiled: bool,
            exit_code: i32,
            #[serde(skip_serializing_if = "Option::is_none")]
            error: Option<CliJsonError>,
        }

        let out = RegoCompileOutput {
            version: CLI_JSON_VERSION,
            command: "policy_rego_compile",
            file,
            entrypoint,
            compiled: true,
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

    let _ = writeln!(stdout, "Rego module compiled successfully.");
    ExitCode::Ok
}

#[cfg(feature = "rego-runtime")]
fn cmd_rego_eval(
    file: String,
    input: String,
    entrypoint: Option<String>,
    trace: bool,
    json: bool,
    stdout: &mut dyn Write,
    stderr: &mut dyn Write,
) -> ExitCode {
    let module = match std::fs::read_to_string(&file) {
        Ok(v) => v,
        Err(e) => {
            return emit_rego_error(
                "policy_rego_eval",
                json,
                ExitCode::RuntimeError,
                "runtime_error",
                &format!("Failed to read Rego file: {}", e),
                stdout,
                stderr,
            )
        }
    };
    let input_json = match read_json_input(&input) {
        Ok(v) => v,
        Err(e) => {
            return emit_rego_error(
                "policy_rego_eval",
                json,
                ExitCode::ConfigError,
                "config_error",
                &e,
                stdout,
                stderr,
            )
        }
    };

    let query = normalize_entrypoint(entrypoint.as_deref().unwrap_or("data"));
    let mut engine = regorus::Engine::new();
    if let Err(e) = engine.add_policy(file.clone(), module) {
        return emit_rego_error(
            "policy_rego_eval",
            json,
            ExitCode::ConfigError,
            "config_error",
            &format!("Failed to compile Rego module: {}", e),
            stdout,
            stderr,
        );
    }
    if let Err(e) = engine.set_input_json(&input_json) {
        return emit_rego_error(
            "policy_rego_eval",
            json,
            ExitCode::ConfigError,
            "config_error",
            &format!("Invalid input JSON: {}", e),
            stdout,
            stderr,
        );
    }

    let result = match engine.eval_query(query.clone(), trace) {
        Ok(v) => v,
        Err(e) => {
            return emit_rego_error(
                "policy_rego_eval",
                json,
                ExitCode::ConfigError,
                "config_error",
                &format!("Query evaluation failed ({query}): {}", e),
                stdout,
                stderr,
            )
        }
    };

    let traces = if trace {
        match engine.take_prints() {
            Ok(v) => v,
            Err(_) => Vec::new(),
        }
    } else {
        Vec::new()
    };

    if json {
        #[derive(serde::Serialize)]
        struct RegoEvalOutput {
            version: u8,
            command: &'static str,
            file: String,
            input: String,
            query: String,
            result: serde_json::Value,
            #[serde(skip_serializing_if = "Vec::is_empty")]
            trace: Vec<String>,
            exit_code: i32,
            #[serde(skip_serializing_if = "Option::is_none")]
            error: Option<CliJsonError>,
        }

        let result_json = serde_json::to_value(&result).unwrap_or_else(|_| serde_json::json!({}));
        let out = RegoEvalOutput {
            version: CLI_JSON_VERSION,
            command: "policy_rego_eval",
            file,
            input,
            query,
            result: result_json,
            trace: traces,
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

    let result_json = serde_json::to_string_pretty(&result).unwrap_or_else(|_| "{}".to_string());
    let _ = writeln!(stdout, "{}", result_json);
    if trace {
        for line in traces {
            let _ = writeln!(stderr, "trace: {}", line);
        }
    }
    ExitCode::Ok
}

#[cfg(not(feature = "rego-runtime"))]
fn cmd_rego_compile(
    file: String,
    _entrypoint: Option<String>,
    json: bool,
    stdout: &mut dyn Write,
    stderr: &mut dyn Write,
) -> ExitCode {
    emit_rego_error(
        "policy_rego_compile",
        json,
        ExitCode::ConfigError,
        "config_error",
        &format!(
            "Rego runtime is not enabled in this build (requested compile for {}).",
            file
        ),
        stdout,
        stderr,
    )
}

#[cfg(not(feature = "rego-runtime"))]
fn cmd_rego_eval(
    file: String,
    input: String,
    _entrypoint: Option<String>,
    _trace: bool,
    json: bool,
    stdout: &mut dyn Write,
    stderr: &mut dyn Write,
) -> ExitCode {
    emit_rego_error(
        "policy_rego_eval",
        json,
        ExitCode::ConfigError,
        "config_error",
        &format!(
            "Rego runtime is not enabled in this build (requested eval for {} with input {}).",
            file, input
        ),
        stdout,
        stderr,
    )
}

fn normalize_entrypoint(entrypoint: &str) -> String {
    let trimmed = entrypoint.trim();
    if trimmed.is_empty() {
        return "data".to_string();
    }
    trimmed.to_string()
}

fn read_json_input(input: &str) -> std::result::Result<String, String> {
    if input == "-" {
        let mut buf = String::new();
        std::io::stdin()
            .read_to_string(&mut buf)
            .map_err(|e| format!("failed to read stdin JSON input: {e}"))?;
        return Ok(buf);
    }

    std::fs::read_to_string(input).map_err(|e| format!("failed to read input JSON file: {e}"))
}

fn emit_rego_error(
    command: &'static str,
    json: bool,
    code: ExitCode,
    error_kind: &'static str,
    message: &str,
    stdout: &mut dyn Write,
    stderr: &mut dyn Write,
) -> ExitCode {
    if json {
        #[derive(serde::Serialize)]
        struct RegoErrorOutput {
            version: u8,
            command: &'static str,
            exit_code: i32,
            error: CliJsonError,
        }

        let out = RegoErrorOutput {
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
