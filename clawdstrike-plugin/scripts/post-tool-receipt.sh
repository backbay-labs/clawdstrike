#!/bin/bash
# Clawdstrike post-tool receipt logger (plugin version)
# Writes one JSONL line per tool call for audit trail
# ALWAYS exits 0 -- never blocks on post-tool logging

set -uo pipefail

SESSION_ID="${CLAWDSTRIKE_SESSION_ID:-unknown}"
RECEIPT_DIR="$HOME/.clawdstrike/receipts"
RECEIPT_FILE="${RECEIPT_DIR}/session-${SESSION_ID}.jsonl"

# Read hook input from stdin (best-effort)
INPUT=$(cat 2>/dev/null) || true

# Extract tool name
TOOL_NAME=$(echo "$INPUT" | jq -er '.tool_name // empty' 2>/dev/null) || true
if [ -z "${TOOL_NAME:-}" ]; then
  exit 0
fi

# Map tool names to action types (same mapping as pre-tool-check.sh)
TOOL_INPUT=$(echo "$INPUT" | jq -ec '.tool_input // {}' 2>/dev/null) || TOOL_INPUT="{}"

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
    TARGET=$(echo "$TOOL_INPUT" | jq -er '.file_path // .path // .pattern // empty' 2>/dev/null || true)
    ;;
  Write)
    ACTION_TYPE="file_write"
    TARGET=$(echo "$TOOL_INPUT" | jq -er '.file_path // .path // empty' 2>/dev/null || true)
    ;;
  Edit)
    ACTION_TYPE="file_write"
    TARGET=$(echo "$TOOL_INPUT" | jq -er '.file_path // .path // empty' 2>/dev/null || true)
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
    ACTION_TYPE="mcp_tool"
    TARGET="$TOOL_NAME"
    ;;
esac

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

# Ensure receipt directory exists
mkdir -p "$RECEIPT_DIR" 2>/dev/null || true

# Generate ISO8601 timestamp
TIMESTAMP=$(date -u +"%Y-%m-%dT%H:%M:%SZ" 2>/dev/null) || TIMESTAMP="unknown"

# Write JSONL receipt line (include duration_ms if available)
if [ -n "$DURATION_MS" ]; then
  jq -cn \
    --arg timestamp "$TIMESTAMP" \
    --arg session_id "$SESSION_ID" \
    --arg tool_name "$TOOL_NAME" \
    --arg action_type "$ACTION_TYPE" \
    --arg target "$TARGET" \
    --arg outcome "$OUTCOME" \
    --argjson duration_ms "$DURATION_MS" \
    '{timestamp:$timestamp,session_id:$session_id,tool_name:$tool_name,action_type:$action_type,target:$target,outcome:$outcome,duration_ms:$duration_ms}' \
    >> "$RECEIPT_FILE" 2>/dev/null || true
else
  jq -cn \
    --arg timestamp "$TIMESTAMP" \
    --arg session_id "$SESSION_ID" \
    --arg tool_name "$TOOL_NAME" \
    --arg action_type "$ACTION_TYPE" \
    --arg target "$TARGET" \
    --arg outcome "$OUTCOME" \
    '{timestamp:$timestamp,session_id:$session_id,tool_name:$tool_name,action_type:$action_type,target:$target,outcome:$outcome}' \
    >> "$RECEIPT_FILE" 2>/dev/null || true
fi

exit 0
