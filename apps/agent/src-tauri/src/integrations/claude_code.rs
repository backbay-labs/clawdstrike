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

fail() {
  local reason="$1"
  echo "🚫 Clawdstrike hook error: ${reason}" >&2
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

if ! TOOL_INPUT=$(echo "$INPUT" | jq -ec '.tool_input // {} | if type == "object" then . else {"tool_input": .} end' 2>/dev/null); then
  fail "invalid hook payload: .tool_input is not JSON"
fi

# Skip if no tool name
if [ -z "$TOOL_NAME" ]; then
  exit 0
fi

# Map tool names to hushd /api/v1/check action types.
CONTENT=""
case "$TOOL_NAME" in
  Read)
    ACTION_TYPE="file_access"
    TARGET=$(echo "$TOOL_INPUT" | jq -er '.file_path // .path // empty' 2>/dev/null || true)
    ;;
  Glob)
    ACTION_TYPE="file_access"
    TARGET=$(echo "$TOOL_INPUT" | jq -er '.pattern // empty' 2>/dev/null || true)
    ;;
  Grep)
    ACTION_TYPE="file_access"
    # Grep may be invoked without an explicit path (searching the full workspace). In that case
    # fall back to `.pattern` so we don't bypass the policy check entirely.
    TARGET=$(echo "$TOOL_INPUT" | jq -er '.file_path // .path // .pattern // empty' 2>/dev/null || true)
    ;;
  Write)
    ACTION_TYPE="file_write"
    TARGET=$(echo "$TOOL_INPUT" | jq -er '.file_path // .path // empty' 2>/dev/null || true)
    CONTENT=$(echo "$TOOL_INPUT" | jq -er '.content // .text // empty' 2>/dev/null || true)
    ;;
  Edit)
    ACTION_TYPE="file_write"
    TARGET=$(echo "$TOOL_INPUT" | jq -er '.file_path // .path // empty' 2>/dev/null || true)
    CONTENT=$(echo "$TOOL_INPUT" | jq -er '.new_string // .content // empty' 2>/dev/null || true)
    ;;
  Bash)
    ACTION_TYPE="shell"
    TARGET=$(echo "$TOOL_INPUT" | jq -er '.command // empty' 2>/dev/null || true)
    ;;
  WebFetch|WebSearch)
    ACTION_TYPE="egress"
    TARGET=$(echo "$TOOL_INPUT" | jq -er '.url // .query // empty' 2>/dev/null || true)
    ;;
  *)
    # Unknown tool: treat as an MCP tool and let policy decide.
    ACTION_TYPE="mcp_tool"
    TARGET="$TOOL_NAME"
    ;;
esac

# Skip if no target
if [ -z "${TARGET:-}" ]; then
  exit 0
fi

RUNTIME_AGENT_KIND="claude_code"
RUNTIME_AGENT_EXTERNAL_ID=$(echo "$TOOL_INPUT" | jq -er '.agent_id // .runtime_agent_id // .session_id // .conversation_id // empty' 2>/dev/null || true)
if [ -z "${RUNTIME_AGENT_EXTERNAL_ID:-}" ]; then
  RUNTIME_AGENT_EXTERNAL_ID="${CLAUDE_AGENT_ID:-claude-code}"
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

RUNTIME_AGENT_ID="$RUNTIME_AGENT_EXTERNAL_ID"
REGISTER_URL="${CLAWDSTRIKE_ENDPOINT}/api/v1/agent/runtimes/register"
if REGISTER_PAYLOAD=$(jq -cn --arg runtime_agent_kind "$RUNTIME_AGENT_KIND" --arg runtime_agent_id "$RUNTIME_AGENT_EXTERNAL_ID" '{runtime_agent_kind:$runtime_agent_kind,runtime_agent_id:$runtime_agent_id}' 2>/dev/null); then
  if REGISTER_RESPONSE=$(curl -sS --max-time 4 -X POST "$REGISTER_URL" \
    -H "Authorization: Bearer ${CLAWDSTRIKE_TOKEN}" \
    -H "Content-Type: application/json" \
    --data "$REGISTER_PAYLOAD" 2>/dev/null); then
    REGISTERED_ID=$(echo "$REGISTER_RESPONSE" | jq -er '.runtime_agent_id // empty' 2>/dev/null || true)
    if [ -n "${REGISTERED_ID:-}" ]; then
      RUNTIME_AGENT_ID="$REGISTERED_ID"
    fi
  fi
fi

# Build JSON safely.
if [ "$ACTION_TYPE" = "mcp_tool" ]; then
  if [ -n "${CONTENT:-}" ]; then
    if ! PAYLOAD=$(jq -cn --arg action_type "$ACTION_TYPE" --arg target "$TARGET" --arg content "$CONTENT" --arg runtime_agent_id "$RUNTIME_AGENT_ID" --arg runtime_agent_kind "$RUNTIME_AGENT_KIND" --argjson args "$TOOL_INPUT" '{action_type:$action_type,target:$target,content:$content,args:$args,runtime_agent_id:$runtime_agent_id,runtime_agent_kind:$runtime_agent_kind}' 2>/dev/null); then
      fail "failed to encode policy request payload"
    fi
  else
    if ! PAYLOAD=$(jq -cn --arg action_type "$ACTION_TYPE" --arg target "$TARGET" --arg runtime_agent_id "$RUNTIME_AGENT_ID" --arg runtime_agent_kind "$RUNTIME_AGENT_KIND" --argjson args "$TOOL_INPUT" '{action_type:$action_type,target:$target,args:$args,runtime_agent_id:$runtime_agent_id,runtime_agent_kind:$runtime_agent_kind}' 2>/dev/null); then
      fail "failed to encode policy request payload"
    fi
  fi
else
  if [ -n "${CONTENT:-}" ]; then
    if ! PAYLOAD=$(jq -cn --arg action_type "$ACTION_TYPE" --arg target "$TARGET" --arg content "$CONTENT" --arg runtime_agent_id "$RUNTIME_AGENT_ID" --arg runtime_agent_kind "$RUNTIME_AGENT_KIND" '{action_type:$action_type,target:$target,content:$content,runtime_agent_id:$runtime_agent_id,runtime_agent_kind:$runtime_agent_kind}' 2>/dev/null); then
      fail "failed to encode policy request payload"
    fi
  else
    if ! PAYLOAD=$(jq -cn --arg action_type "$ACTION_TYPE" --arg target "$TARGET" --arg runtime_agent_id "$RUNTIME_AGENT_ID" --arg runtime_agent_kind "$RUNTIME_AGENT_KIND" '{action_type:$action_type,target:$target,runtime_agent_id:$runtime_agent_id,runtime_agent_kind:$runtime_agent_kind}' 2>/dev/null); then
      fail "failed to encode policy request payload"
    fi
  fi
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
  GUARD=$(echo "$RESPONSE" | jq -er '.guard // "unknown"' 2>/dev/null || echo "unknown")

  # Treat daemon infrastructure denies as hook failures to preserve fail-closed behavior.
  if [[ "$GUARD" == hushd_* ]]; then
    fail "policy daemon error (${GUARD})"
  fi

  MESSAGE=$(echo "$RESPONSE" | jq -er '.message // "Action blocked by security policy"' 2>/dev/null || echo "Action blocked by security policy")

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
        assert!(!HOOK_SCRIPT.contains("CLAWDSTRIKE_HOOK_FAIL_OPEN"));
        assert!(HOOK_SCRIPT.contains("ACTION_TYPE=\"mcp_tool\""));
    }

    #[test]
    fn test_hook_script_escapes_json_payload() {
        assert!(HOOK_SCRIPT.contains("--arg target \"$TARGET\""));
        assert!(!HOOK_SCRIPT.contains("\\\"target\\\":\\\"${TARGET}\\\""));
    }

    #[test]
    fn test_hook_script_handles_unknown_tools_via_mcp_tool_args() {
        assert!(HOOK_SCRIPT.contains("--argjson args \"$TOOL_INPUT\""));
        assert!(HOOK_SCRIPT.contains("Unknown tool: treat as an MCP tool"));
    }

    #[test]
    fn test_hook_script_does_not_skip_grep_without_path() {
        // Grep can be invoked without a path (search full workspace); ensure we still produce a
        // non-empty TARGET by falling back to the search pattern.
        assert!(HOOK_SCRIPT.contains("Grep)"));
        assert!(HOOK_SCRIPT.contains(".file_path // .path // .pattern"));
    }

    #[test]
    fn test_integration_paths() {
        let integration = ClaudeCodeIntegration::new();
        assert!(integration.claude_dir.to_string_lossy().contains(".claude"));
        assert!(integration.hooks_dir.to_string_lossy().contains("hooks"));
    }
}
