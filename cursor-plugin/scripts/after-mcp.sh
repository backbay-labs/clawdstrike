#!/bin/bash
# Clawdstrike afterMCPExecution hook for Cursor
# Writes receipt for MCP tool execution
# ALWAYS exits 0

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
source "$SCRIPT_DIR/lib/common.sh"

# Read hook input from stdin (best-effort)
INPUT=$(cat 2>/dev/null) || true

# Extract Cursor context
extract_cursor_context "$INPUT"

# Extract MCP execution details
MCP_SERVER_NAME=$(echo "$INPUT" | jq -er '.mcp_server_name // empty' 2>/dev/null) || true
TOOL_NAME=$(echo "$INPUT" | jq -er '.tool_name // empty' 2>/dev/null) || true

# Determine outcome
OUTCOME="success"
if echo "$INPUT" | jq -e '.isError == true or .error != null' >/dev/null 2>&1; then
  OUTCOME="error"
fi

# Build target
TARGET="${MCP_SERVER_NAME:-unknown}/${TOOL_NAME:-unknown}"

# Write receipt
TIMESTAMP=$(timestamp)
write_receipt "$(jq -cn \
  --arg timestamp "$TIMESTAMP" \
  --arg session_id "$SESSION_ID" \
  --arg hook_event "afterMCPExecution" \
  --arg action_type "mcp_tool" \
  --arg target "$TARGET" \
  --arg mcp_server "${MCP_SERVER_NAME:-}" \
  --arg tool_name "${TOOL_NAME:-}" \
  --arg outcome "$OUTCOME" \
  '{timestamp:$timestamp,session_id:$session_id,hook_event:$hook_event,action_type:$action_type,target:$target,mcp_server:$mcp_server,tool_name:$tool_name,outcome:$outcome}')"

exit 0
