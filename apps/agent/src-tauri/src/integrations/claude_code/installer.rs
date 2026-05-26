//! Claude Code integration manager: install and configure pre-tool hook.

use anyhow::{Context, Result};
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;

use super::hook_script::{HOOK_CONFIG, HOOK_SCRIPT};

/// Claude Code integration manager.
pub struct ClaudeCodeIntegration {
    pub(super) claude_dir: PathBuf,
    pub(super) hooks_dir: PathBuf,
}

impl ClaudeCodeIntegration {
    /// Create a new integration manager.
    pub fn new() -> Self {
        let home = dirs::home_dir().unwrap_or_else(|| PathBuf::from("."));
        let claude_dir = home.join(".claude");
        let hooks_dir = claude_dir.join("hooks");

        Self {
            claude_dir,
            hooks_dir,
        }
    }

    /// Check if Claude Code is installed (has ~/.claude directory).
    pub fn is_installed(&self) -> bool {
        self.claude_dir.exists()
    }

    /// Install the pre-tool hook.
    pub fn install_hooks(&self) -> Result<()> {
        fs::create_dir_all(&self.hooks_dir)
            .with_context(|| format!("Failed to create hooks directory: {:?}", self.hooks_dir))?;

        let hook_path = self.hooks_dir.join("clawdstrike-check.sh");
        fs::write(&hook_path, HOOK_SCRIPT)
            .with_context(|| format!("Failed to write hook script: {:?}", hook_path))?;

        #[cfg(unix)]
        {
            let mut perms = fs::metadata(&hook_path)
                .with_context(|| "Failed to get hook script metadata")?
                .permissions();
            perms.set_mode(0o755);
            fs::set_permissions(&hook_path, perms)
                .with_context(|| "Failed to set hook script permissions")?;
        }

        tracing::info!(path = ?hook_path, "Installed Claude Code hook");

        self.update_hooks_config()?;
        Ok(())
    }

    /// Update the hooks.json configuration file.
    fn update_hooks_config(&self) -> Result<()> {
        let hooks_json = self.claude_dir.join("hooks.json");

        if hooks_json.exists() {
            let content =
                fs::read_to_string(&hooks_json).with_context(|| "Failed to read hooks.json")?;

            if let Ok(mut config) = serde_json::from_str::<serde_json::Value>(&content) {
                let hooks = config
                    .as_object_mut()
                    .and_then(|obj| obj.get_mut("hooks"))
                    .and_then(|h| h.as_object_mut());

                if let Some(hooks) = hooks {
                    let pre_tool = hooks
                        .entry("PreToolUse")
                        .or_insert_with(|| serde_json::json!([]));

                    if let Some(arr) = pre_tool.as_array_mut() {
                        let already_installed = arr.iter().any(|item| {
                            item.get("command")
                                .and_then(|c| c.as_str())
                                .map(|s| s.contains("clawdstrike-check.sh"))
                                .unwrap_or(false)
                        });

                        if !already_installed {
                            arr.push(serde_json::json!({
                                "type": "command",
                                "command": "~/.claude/hooks/clawdstrike-check.sh"
                            }));

                            let updated = serde_json::to_string_pretty(&config)
                                .with_context(|| "Failed to serialize hooks.json")?;
                            fs::write(&hooks_json, updated)
                                .with_context(|| "Failed to write hooks.json")?;

                            tracing::info!(path = ?hooks_json, "Updated hooks.json with Clawdstrike hook");
                        }
                    }
                }
            }
        } else {
            fs::write(&hooks_json, HOOK_CONFIG)
                .with_context(|| format!("Failed to create hooks.json: {:?}", hooks_json))?;
            tracing::info!(path = ?hooks_json, "Created hooks.json");
        }

        Ok(())
    }
}

impl Default for ClaudeCodeIntegration {
    fn default() -> Self {
        Self::new()
    }
}
