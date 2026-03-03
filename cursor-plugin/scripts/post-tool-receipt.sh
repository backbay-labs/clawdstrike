#!/bin/bash
# Clawdstrike post-tool receipt logger for Cursor
# Writes one JSONL line per tool call for audit trail
# ALWAYS exits 0 -- never blocks on post-tool logging

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
source "$SCRIPT_DIR/lib/common.sh"

# Read hook input from stdin (best-effort)
INPUT=$(cat 2>/dev/null) || true

# Extract Cursor context
extract_cursor_context "$INPUT"

# Extract tool name
TOOL_NAME=$(echo "$INPUT" | jq -er '.tool_name // empty' 2>/dev/null) || true
if [ -z "${TOOL_NAME:-}" ]; then
  exit 0
fi

# Map tool names to action types
TOOL_INPUT=$(echo "$INPUT" | jq -ec '.tool_input // {}' 2>/dev/null) || TOOL_INPUT="{}"
map_tool_to_action

# Default target if extraction failed
TARGET="${TARGET:-unknown}"

# Determine actual outcome from tool result
OUTCOME="success"
if echo "$INPUT" | jq -e '.isError == true' >/dev/null 2>&1; then
  OUTCOME="error"
elif echo "$INPUT" | jq -e '.error != null' >/dev/null 2>&1; then
  OUTCOME="error"
fi

# Extract duration if available
DURATION_MS=""
if DURATION_MS_RAW=$(echo "$INPUT" | jq -er '.response_duration_ms // empty' 2>/dev/null); then
  DURATION_MS="$DURATION_MS_RAW"
fi

# Generate ISO8601 timestamp
TIMESTAMP=$(timestamp)

# Write JSONL receipt line (include duration_ms and conversation_id if available)
if [ -n "$DURATION_MS" ]; then
  write_receipt "$(jq -cn \
    --arg timestamp "$TIMESTAMP" \
    --arg session_id "$SESSION_ID" \
    --arg tool_name "$TOOL_NAME" \
    --arg action_type "$ACTION_TYPE" \
    --arg target "$TARGET" \
    --arg outcome "$OUTCOME" \
    --argjson duration_ms "$DURATION_MS" \
    --arg conversation_id "${CURSOR_CONVERSATION_ID:-}" \
    '{timestamp:$timestamp,session_id:$session_id,tool_name:$tool_name,action_type:$action_type,target:$target,outcome:$outcome,duration_ms:$duration_ms,conversation_id:$conversation_id}')"
else
  write_receipt "$(jq -cn \
    --arg timestamp "$TIMESTAMP" \
    --arg session_id "$SESSION_ID" \
    --arg tool_name "$TOOL_NAME" \
    --arg action_type "$ACTION_TYPE" \
    --arg target "$TARGET" \
    --arg outcome "$OUTCOME" \
    --arg conversation_id "${CURSOR_CONVERSATION_ID:-}" \
    '{timestamp:$timestamp,session_id:$session_id,tool_name:$tool_name,action_type:$action_type,target:$target,outcome:$outcome,conversation_id:$conversation_id}')"
fi

exit 0
