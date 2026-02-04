//! Claude Code integration via hooks
//!
//! Auto-installs pre-tool hooks to ~/.claude/hooks/ for policy checking.

use anyhow::{Context, Result};
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;

/// Hook script for pre-tool checks
const HOOK_SCRIPT: &str = r#"#!/bin/bash
# Clawdstrike pre-tool hook for Claude Code
# Checks actions against security policy before execution

set -e

# Configuration
CLAWDSTRIKE_PORT="${CLAWDSTRIKE_PORT:-9876}"
CLAWDSTRIKE_ENDPOINT="${CLAWDSTRIKE_ENDPOINT:-http://127.0.0.1:${CLAWDSTRIKE_PORT}}"

# Skip if enforcement is disabled
if [ "${CLAWDSTRIKE_DISABLED:-}" = "1" ]; then
    exit 0
fi

# Read hook input from stdin
INPUT=$(cat)

# Extract tool name and input from hook data
TOOL_NAME=$(echo "$INPUT" | jq -r '.tool_name // empty')
TOOL_INPUT=$(echo "$INPUT" | jq -c '.tool_input // {}')

# Skip if no tool name
if [ -z "$TOOL_NAME" ]; then
    exit 0
fi

# Map tool names to action types
case "$TOOL_NAME" in
    Read|Write|Edit|Glob|Grep)
        ACTION_TYPE="file_access"
        TARGET=$(echo "$TOOL_INPUT" | jq -r '.file_path // .path // .pattern // empty')
        ;;
    Bash)
        ACTION_TYPE="exec"
        TARGET=$(echo "$TOOL_INPUT" | jq -r '.command // empty')
        ;;
    WebFetch|WebSearch)
        ACTION_TYPE="network"
        TARGET=$(echo "$TOOL_INPUT" | jq -r '.url // .query // empty')
        ;;
    *)
        # Allow unknown tools by default
        exit 0
        ;;
esac

# Skip if no target
if [ -z "$TARGET" ]; then
    exit 0
fi

# Check with Clawdstrike
RESPONSE=$(curl -s -X POST "${CLAWDSTRIKE_ENDPOINT}/api/v1/check" \
    -H "Content-Type: application/json" \
    -d "{\"action_type\":\"${ACTION_TYPE}\",\"target\":\"${TARGET}\"}" \
    2>/dev/null || echo '{"allowed":true}')

# Parse response
ALLOWED=$(echo "$RESPONSE" | jq -r '.allowed // true')

if [ "$ALLOWED" = "false" ]; then
    MESSAGE=$(echo "$RESPONSE" | jq -r '.message // "Action blocked by security policy"')
    GUARD=$(echo "$RESPONSE" | jq -r '.guard // "unknown"')

    # Output block message to stderr
    echo "🚫 BLOCKED by Clawdstrike (${GUARD}): ${MESSAGE}" >&2
    echo "   Target: ${TARGET}" >&2

    exit 1
fi

exit 0
"#;

/// Hook configuration JSON
const HOOK_CONFIG: &str = r#"{
  "hooks": {
    "PreToolUse": [
      {
        "type": "command",
        "command": "~/.claude/hooks/clawdstrike-check.sh"
      }
    ]
  }
}
"#;

/// Claude Code integration manager
pub struct ClaudeCodeIntegration {
    claude_dir: PathBuf,
    hooks_dir: PathBuf,
}

impl ClaudeCodeIntegration {
    /// Create a new integration manager
    pub fn new() -> Self {
        let home = dirs::home_dir().unwrap_or_else(|| PathBuf::from("."));
        let claude_dir = home.join(".claude");
        let hooks_dir = claude_dir.join("hooks");

        Self {
            claude_dir,
            hooks_dir,
        }
    }

    /// Check if Claude Code is installed (has ~/.claude directory)
    pub fn is_installed(&self) -> bool {
        self.claude_dir.exists()
    }

    /// Check if hooks are already installed
    pub fn hooks_installed(&self) -> bool {
        let hook_script = self.hooks_dir.join("clawdstrike-check.sh");
        hook_script.exists()
    }

    /// Install the pre-tool hook
    pub fn install_hooks(&self) -> Result<()> {
        // Create hooks directory if needed
        fs::create_dir_all(&self.hooks_dir)
            .with_context(|| format!("Failed to create hooks directory: {:?}", self.hooks_dir))?;

        // Write hook script
        let hook_path = self.hooks_dir.join("clawdstrike-check.sh");
        fs::write(&hook_path, HOOK_SCRIPT)
            .with_context(|| format!("Failed to write hook script: {:?}", hook_path))?;

        // Make executable
        #[cfg(unix)]
        {
            let mut perms = fs::metadata(&hook_path)
                .with_context(|| "Failed to get hook script metadata")?
                .permissions();
            perms.set_mode(0o755);
            fs::set_permissions(&hook_path, perms)
                .with_context(|| "Failed to set hook script permissions")?;
        }

        tracing::info!("Installed Claude Code hook: {:?}", hook_path);

        // Check for existing hooks.json and update if needed
        self.update_hooks_config()?;

        Ok(())
    }

    /// Uninstall the hooks
    pub fn uninstall_hooks(&self) -> Result<()> {
        let hook_path = self.hooks_dir.join("clawdstrike-check.sh");

        if hook_path.exists() {
            fs::remove_file(&hook_path)
                .with_context(|| format!("Failed to remove hook script: {:?}", hook_path))?;
            tracing::info!("Removed Claude Code hook: {:?}", hook_path);
        }

        // Note: We don't remove the hooks.json entry as the user may have other hooks

        Ok(())
    }

    /// Update the hooks.json configuration file
    fn update_hooks_config(&self) -> Result<()> {
        let hooks_json = self.claude_dir.join("hooks.json");

        if hooks_json.exists() {
            // Read existing config
            let content = fs::read_to_string(&hooks_json)
                .with_context(|| "Failed to read hooks.json")?;

            // Parse and check if our hook is already there
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
                        // Check if already installed
                        let already_installed = arr.iter().any(|item| {
                            item.get("command")
                                .and_then(|c| c.as_str())
                                .map(|s| s.contains("clawdstrike"))
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

                            tracing::info!("Updated hooks.json with Clawdstrike hook");
                        }
                    }
                }
            }
        } else {
            // Create new hooks.json
            fs::write(&hooks_json, HOOK_CONFIG)
                .with_context(|| format!("Failed to create hooks.json: {:?}", hooks_json))?;
            tracing::info!("Created hooks.json: {:?}", hooks_json);
        }

        Ok(())
    }

    /// Get the path to the hook script
    pub fn hook_script_path(&self) -> PathBuf {
        self.hooks_dir.join("clawdstrike-check.sh")
    }

    /// Verify the hook is working
    pub fn verify_hook(&self) -> Result<bool> {
        let hook_path = self.hook_script_path();

        if !hook_path.exists() {
            return Ok(false);
        }

        // Check if executable
        #[cfg(unix)]
        {
            let metadata = fs::metadata(&hook_path)?;
            let permissions = metadata.permissions();
            if permissions.mode() & 0o111 == 0 {
                return Ok(false);
            }
        }

        Ok(true)
    }
}

impl Default for ClaudeCodeIntegration {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hook_script_contains_essentials() {
        assert!(HOOK_SCRIPT.contains("curl"));
        assert!(HOOK_SCRIPT.contains("/api/v1/check"));
        assert!(HOOK_SCRIPT.contains("CLAWDSTRIKE_PORT"));
    }

    #[test]
    fn test_integration_paths() {
        let integration = ClaudeCodeIntegration::new();
        assert!(integration.claude_dir.to_string_lossy().contains(".claude"));
        assert!(integration.hooks_dir.to_string_lossy().contains("hooks"));
    }
}
