//! Helper-tool invocation: command construction, environment scrubbing, and
//! JSON parsing for the macOS status helpers.

use std::ffi::OsString;
use std::path::PathBuf;
use std::process::Stdio;
use std::time::Duration;

use anyhow::{anyhow, Context, Result};
use serde::Deserialize;
use tokio::process::Command;
use tokio::time::timeout;

use super::paths::{
    default_endpoint_security_runtime_snapshot_path, default_network_extension_egress_policy_path,
    default_network_extension_runtime_snapshot_path,
};

pub(super) const STATUS_TOOL_TIMEOUT: Duration = Duration::from_secs(10);
pub(super) const ENDPOINT_SECURITY_TOOL_ENV: &str = "CLAWDSTRIKE_ENDPOINT_SECURITY_STATUS_TOOL";
pub(super) const ENDPOINT_SECURITY_RUNTIME_SNAPSHOT_ENV: &str =
    "CLAWDSTRIKE_ENDPOINT_SECURITY_RUNTIME_SNAPSHOT_PATH";
pub(super) const NETWORK_EXTENSION_TOOL_ENV: &str = "CLAWDSTRIKE_NETWORK_EXTENSION_STATUS_TOOL";
pub(super) const NETWORK_EXTENSION_EGRESS_POLICY_ENV: &str =
    "CLAWDSTRIKE_NETWORK_EXTENSION_EGRESS_POLICY_PATH";
pub(super) const NETWORK_EXTENSION_RUNTIME_SNAPSHOT_ENV: &str =
    "CLAWDSTRIKE_NETWORK_EXTENSION_RUNTIME_SNAPSHOT_PATH";
pub(super) const ALLOW_SWIFT_RUN_STATUS_TOOLS_ENV: &str =
    "CLAWDSTRIKE_ALLOW_SWIFT_RUN_STATUS_TOOLS";
pub(super) const ALLOW_DIRECT_STATUS_TOOL_OVERRIDES_ENV: &str =
    "CLAWDSTRIKE_ALLOW_DIRECT_STATUS_TOOL_OVERRIDES";
pub(super) const ENDPOINT_SECURITY_TOOL_NAME: &str = "endpoint-security-status-tool";
pub(super) const NETWORK_EXTENSION_TOOL_NAME: &str = "network-extension-status-tool";

const STATUS_TOOL_ENV_ALLOWLIST: &[&str] = &[
    "PATH",
    "HOME",
    "TMPDIR",
    "TEMP",
    "TMP",
    "DEVELOPER_DIR",
    "SDKROOT",
    "TOOLCHAINS",
    "XCODE_DEVELOPER_DIR_PATH",
];

#[derive(Debug, Clone)]
pub(super) enum ToolInvocation {
    Direct {
        program: PathBuf,
        args: Vec<OsString>,
    },
    SwiftRun {
        package_path: PathBuf,
        executable: &'static str,
    },
}

impl ToolInvocation {
    pub(super) fn command(&self) -> Command {
        match self {
            Self::Direct { args, .. } => self.command_with_args(args),
            Self::SwiftRun { .. } => self.command_with_args(&[OsString::from("live")]),
        }
    }

    pub(super) fn command_with_args(&self, args: &[OsString]) -> Command {
        match self {
            Self::Direct { program, .. } => {
                let mut command = Command::new(program);
                command.args(args);
                command
            }
            Self::SwiftRun {
                package_path,
                executable,
            } => {
                let mut command = Command::new("swift");
                command
                    .arg("run")
                    .arg("--package-path")
                    .arg(package_path)
                    .arg(executable)
                    .args(args);
                command
            }
        }
    }

    pub(super) fn display_name(&self) -> String {
        match self {
            Self::Direct { args, .. } => self.display_name_with_args(args),
            Self::SwiftRun { .. } => self.display_name_with_args(&[OsString::from("live")]),
        }
    }

    pub(super) fn display_name_with_args(&self, args: &[OsString]) -> String {
        let rendered_args = args
            .iter()
            .map(|arg| arg.to_string_lossy().into_owned())
            .collect::<Vec<_>>()
            .join(" ");
        match self {
            Self::Direct { program, .. } => {
                if rendered_args.is_empty() {
                    program.display().to_string()
                } else {
                    format!("{} {rendered_args}", program.display())
                }
            }
            Self::SwiftRun {
                package_path,
                executable,
            } => format!(
                "swift run --package-path {} {}{}{}",
                package_path.display(),
                executable,
                if rendered_args.is_empty() { "" } else { " " },
                rendered_args
            ),
        }
    }
}

pub(super) async fn run_json_tool<T>(tool: &ToolInvocation) -> Option<T>
where
    T: for<'de> Deserialize<'de>,
{
    match timeout(STATUS_TOOL_TIMEOUT, execute_tool(tool)).await {
        Ok(Ok(stdout)) => match serde_json::from_slice::<T>(&stdout) {
            Ok(sample) => Some(sample),
            Err(error) => {
                tracing::warn!(
                    tool = %tool.display_name(),
                    error = %error,
                    "macOS status helper returned invalid JSON"
                );
                None
            }
        },
        Ok(Err(error)) => {
            tracing::warn!(
                tool = %tool.display_name(),
                error = %error,
                "macOS status helper execution failed"
            );
            None
        }
        Err(_) => {
            tracing::warn!(
                tool = %tool.display_name(),
                timeout_secs = STATUS_TOOL_TIMEOUT.as_secs(),
                "macOS status helper timed out"
            );
            None
        }
    }
}

pub(super) async fn execute_tool(tool: &ToolInvocation) -> Result<Vec<u8>> {
    let command = tool.command();
    execute_tool_command(command, tool.display_name()).await
}

pub(super) async fn execute_tool_with_args(
    tool: &ToolInvocation,
    args: &[OsString],
) -> Result<Vec<u8>> {
    let command = tool.command_with_args(args);
    execute_tool_command(command, tool.display_name_with_args(args)).await
}

async fn execute_tool_command(mut command: Command, display_name: String) -> Result<Vec<u8>> {
    command.kill_on_drop(true);
    command.stdout(Stdio::piped());
    command.stderr(Stdio::piped());
    command.env_clear();
    propagate_status_tool_environment(&mut command);
    command.env(
        ENDPOINT_SECURITY_RUNTIME_SNAPSHOT_ENV,
        default_endpoint_security_runtime_snapshot_path(),
    );
    command.env(
        NETWORK_EXTENSION_EGRESS_POLICY_ENV,
        default_network_extension_egress_policy_path(),
    );
    command.env(
        NETWORK_EXTENSION_RUNTIME_SNAPSHOT_ENV,
        default_network_extension_runtime_snapshot_path(),
    );

    let output = command
        .output()
        .await
        .with_context(|| format!("spawn {display_name}"))?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
        return Err(anyhow!(
            "{} exited with status {}{}",
            display_name,
            output.status,
            if stderr.is_empty() {
                String::new()
            } else {
                format!(": {stderr}")
            }
        ));
    }

    Ok(output.stdout)
}

fn propagate_status_tool_environment(command: &mut Command) {
    for key in STATUS_TOOL_ENV_ALLOWLIST {
        if let Some(value) = std::env::var_os(key) {
            command.env(key, value);
        }
    }
}
