//! OpenClaw plugin integration.
//!
//! Installs the Clawdstrike security plugin into OpenClaw.

use anyhow::{Context, Result};
use std::process::{Command, Output};

const OPENCLAW_PLUGIN_PACKAGE: &str = "@clawdstrike/openclaw";
const OPENCLAW_PLUGIN_ID: &str = "clawdstrike-security";

/// OpenClaw plugin integration manager.
#[derive(Debug, Clone, Copy, Default)]
pub struct OpenClawPluginIntegration;

impl OpenClawPluginIntegration {
    /// Create a new integration manager.
    pub fn new() -> Self {
        Self
    }

    /// Check if the OpenClaw CLI is available on PATH.
    pub fn is_cli_available(&self) -> bool {
        which::which("openclaw").is_ok()
    }

    /// Install the Clawdstrike security plugin into OpenClaw.
    pub async fn install_plugin(&self) -> Result<()> {
        let install_output = run_openclaw_command(
            install_command_args().to_vec(),
            "Failed to run `openclaw plugins install`",
        )
        .await?;
        ensure_success(&install_output, "openclaw plugins install")?;
        tracing::info!("Installed {} plugin", OPENCLAW_PLUGIN_PACKAGE);

        let enable_output = run_openclaw_command(
            enable_command_args().to_vec(),
            "Failed to run `openclaw plugins enable`",
        )
        .await?;
        ensure_success(&enable_output, "openclaw plugins enable")?;
        tracing::info!("Enabled {} plugin", OPENCLAW_PLUGIN_ID);
        Ok(())
    }
}

fn install_command_args() -> [&'static str; 3] {
    ["plugins", "install", OPENCLAW_PLUGIN_PACKAGE]
}

fn enable_command_args() -> [&'static str; 3] {
    ["plugins", "enable", OPENCLAW_PLUGIN_ID]
}

async fn run_openclaw_command(
    args: Vec<&'static str>,
    error_context: &'static str,
) -> Result<Output> {
    tokio::task::spawn_blocking(move || {
        Command::new("openclaw")
            .args(args)
            .output()
            .with_context(|| error_context)
    })
    .await
    .with_context(|| "Failed to join OpenClaw command task")?
}

fn ensure_success(output: &Output, action: &str) -> Result<()> {
    if output.status.success() {
        return Ok(());
    }

    let stderr = String::from_utf8_lossy(&output.stderr);
    let stdout = String::from_utf8_lossy(&output.stdout);
    let details = if !stderr.trim().is_empty() {
        stderr.trim()
    } else {
        stdout.trim()
    };
    anyhow::bail!("{} failed (exit {}): {}", action, output.status, details);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn install_command_uses_current_package_id() {
        assert_eq!(
            install_command_args(),
            ["plugins", "install", "@clawdstrike/openclaw"]
        );
    }

    #[test]
    fn enable_command_uses_expected_plugin_id() {
        assert_eq!(
            enable_command_args(),
            ["plugins", "enable", "clawdstrike-security"]
        );
    }
}
