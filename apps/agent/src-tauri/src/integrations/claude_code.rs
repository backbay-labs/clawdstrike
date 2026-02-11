//! Claude Code integration via hooks.
//!
//! Auto-installs pre-tool hooks to ~/.claude/hooks/ for policy checking.

use anyhow::{Context, Result};
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;

/// Hook script for pre-tool checks.
const HOOK_SCRIPT: &str = r#"#!/bin/bash
# Clawdstrike pre-tool hook for Claude Code
# Checks actions against security policy before execution

set -euo pipefail

# Configuration
CLAWDSTRIKE_ENDPOINT="${CLAWDSTRIKE_ENDPOINT:-http://127.0.0.1:9878}"
CLAWDSTRIKE_TOKEN_FILE="${CLAWDSTRIKE_TOKEN_FILE:-$HOME/.config/clawdstrike/agent-local-token}"
CLAWDSTRIKE_HOOK_FAIL_OPEN="${CLAWDSTRIKE_HOOK_FAIL_OPEN:-0}"

fail() {
  local reason="$1"
  echo "🚫 Clawdstrike hook error: ${reason}" >&2
  if [ "$CLAWDSTRIKE_HOOK_FAIL_OPEN" = "1" ]; then
    echo "⚠️  CLAWDSTRIKE_HOOK_FAIL_OPEN=1 is set; allowing action despite hook failure." >&2
    exit 0
  fi
  exit 1
}

# Read hook input from stdin
if ! INPUT=$(cat); then
  fail "failed to read hook input"
fi

# Extract tool name and input from hook data
if ! TOOL_NAME=$(echo "$INPUT" | jq -er '.tool_name // empty' 2>/dev/null); then
  fail "invalid hook payload: missing/invalid .tool_name"
fi

if ! TOOL_INPUT=$(echo "$INPUT" | jq -ec '.tool_input // {}' 2>/dev/null); then
  fail "invalid hook payload: .tool_input is not JSON"
fi

# Skip if no tool name
if [ -z "$TOOL_NAME" ]; then
  exit 0
fi

# Map tool names to action types
case "$TOOL_NAME" in
  Read|Write|Edit|Glob|Grep)
    ACTION_TYPE="file_access"
    TARGET=$(echo "$TOOL_INPUT" | jq -er '.file_path // .path // .pattern // empty' 2>/dev/null || true)
    ;;
  Bash)
    ACTION_TYPE="exec"
    TARGET=$(echo "$TOOL_INPUT" | jq -er '.command // empty' 2>/dev/null || true)
    ;;
  WebFetch|WebSearch)
    ACTION_TYPE="network"
    TARGET=$(echo "$TOOL_INPUT" | jq -er '.url // .query // empty' 2>/dev/null || true)
    ;;
  *)
    # Allow unknown tools by default
    exit 0
    ;;
esac

# Skip if no target
if [ -z "${TARGET:-}" ]; then
  exit 0
fi

# Build JSON safely.
if ! PAYLOAD=$(jq -cn --arg action_type "$ACTION_TYPE" --arg target "$TARGET" '{action_type:$action_type,target:$target}' 2>/dev/null); then
  fail "failed to encode policy request payload"
fi

if [ ! -f "$CLAWDSTRIKE_TOKEN_FILE" ]; then
  fail "agent auth token file not found at $CLAWDSTRIKE_TOKEN_FILE"
fi

if ! CLAWDSTRIKE_TOKEN=$(cat "$CLAWDSTRIKE_TOKEN_FILE"); then
  fail "failed to read agent auth token"
fi

if [ -z "$CLAWDSTRIKE_TOKEN" ]; then
  fail "agent auth token is empty"
fi

CHECK_URL="${CLAWDSTRIKE_ENDPOINT}/api/v1/agent/policy-check"

if ! RESPONSE=$(curl -sS --max-time 8 -X POST "$CHECK_URL" \
  -H "Authorization: Bearer ${CLAWDSTRIKE_TOKEN}" \
  -H "Content-Type: application/json" \
  --data "$PAYLOAD" 2>/dev/null); then
  fail "policy-check request failed"
fi

if ! ALLOWED=$(echo "$RESPONSE" | jq -er '.allowed' 2>/dev/null); then
  fail "policy-check returned malformed response"
fi

if [ "$ALLOWED" = "false" ]; then
  MESSAGE=$(echo "$RESPONSE" | jq -er '.message // "Action blocked by security policy"' 2>/dev/null || echo "Action blocked by security policy")
  GUARD=$(echo "$RESPONSE" | jq -er '.guard // "unknown"' 2>/dev/null || echo "unknown")

  echo "🚫 BLOCKED by Clawdstrike (${GUARD}): ${MESSAGE}" >&2
  echo "   Target: ${TARGET}" >&2
  exit 1
fi

exit 0
"#;

/// Hook configuration JSON.
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

/// Claude Code integration manager.
pub struct ClaudeCodeIntegration {
    claude_dir: PathBuf,
    hooks_dir: PathBuf,
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hook_script_contains_essentials() {
        assert!(HOOK_SCRIPT.contains("jq -cn"));
        assert!(HOOK_SCRIPT.contains("/api/v1/agent/policy-check"));
        assert!(HOOK_SCRIPT.contains("CLAWDSTRIKE_HOOK_FAIL_OPEN"));
    }

    #[test]
    fn test_hook_script_escapes_json_payload() {
        assert!(HOOK_SCRIPT.contains("--arg target \"$TARGET\""));
        assert!(!HOOK_SCRIPT.contains("\\\"target\\\":\\\"${TARGET}\\\""));
    }

    #[test]
    fn test_integration_paths() {
        let integration = ClaudeCodeIntegration::new();
        assert!(integration.claude_dir.to_string_lossy().contains(".claude"));
        assert!(integration.hooks_dir.to_string_lossy().contains("hooks"));
    }
}
