#!/bin/bash
# Clawdstrike beforeMCPExecution hook for Cursor
# Policy-checks MCP tool invocations before execution
# Fail-closed by default (Cursor convention for beforeMCPExecution)
# Skips checking our own tools (mcp_server_name == "clawdstrike")
# Exit 0 = allow, Exit 2 = deny

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
source "$SCRIPT_DIR/lib/common.sh"

# Read hook input from stdin
if ! INPUT=$(cat); then
  fail "failed to read hook input"
fi

# Extract Cursor context
extract_cursor_context "$INPUT"

# Extract MCP execution details
MCP_SERVER_NAME=$(echo "$INPUT" | jq -er '.mcp_server_name // empty' 2>/dev/null) || true
TOOL_NAME=$(echo "$INPUT" | jq -er '.tool_name // empty' 2>/dev/null) || true
TOOL_ARGUMENTS=$(echo "$INPUT" | jq -ec '.tool_arguments // {}' 2>/dev/null) || TOOL_ARGUMENTS="{}"

# Skip if this is our own MCP server (don't block our own tools)
if [ "${MCP_SERVER_NAME:-}" = "clawdstrike" ]; then
  exit 0
fi

# If no server or tool name, allow (nothing meaningful to check)
if [ -z "${MCP_SERVER_NAME:-}" ] && [ -z "${TOOL_NAME:-}" ]; then
  exit 0
fi

# Build target as server/tool
TARGET="${MCP_SERVER_NAME:-unknown}/${TOOL_NAME:-unknown}"

# POST to hushd with action_type=mcp_tool
post_policy_check "mcp_tool" "$TARGET"

if [ "$ALLOWED" = "false" ]; then
  GUARD=$(echo "$RESPONSE" | jq -er '.guard // "unknown"' 2>/dev/null || echo "unknown")
  MESSAGE=$(echo "$RESPONSE" | jq -er '.message // "MCP tool blocked by security policy"' 2>/dev/null || echo "MCP tool blocked by security policy")

  # Write denial receipt
  TIMESTAMP=$(timestamp)
  write_receipt "$(jq -cn \
    --arg timestamp "$TIMESTAMP" \
    --arg session_id "$SESSION_ID" \
    --arg hook_event "beforeMCPExecution" \
    --arg action_type "mcp_tool" \
    --arg target "$TARGET" \
    --arg mcp_server "$MCP_SERVER_NAME" \
    --arg tool_name "${TOOL_NAME:-}" \
    --arg outcome "deny" \
    --arg guard "$GUARD" \
    --arg message "$MESSAGE" \
    '{timestamp:$timestamp,session_id:$session_id,hook_event:$hook_event,action_type:$action_type,target:$target,mcp_server:$mcp_server,tool_name:$tool_name,outcome:$outcome,guard:$guard,message:$message}')"

  DENY_MSG="BLOCKED by ClawdStrike (${GUARD}): ${MESSAGE}"
  echo "$DENY_MSG" >&2
  deny_response "$DENY_MSG" "MCP tool '${TARGET}' was blocked by ClawdStrike guard '${GUARD}': ${MESSAGE}"
fi

exit 0
