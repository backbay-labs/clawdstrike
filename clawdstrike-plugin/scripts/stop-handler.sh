#!/bin/bash
# Clawdstrike stop hook handler (plugin version)
# Writes session_stop receipt and summary if session_end not yet written
# ALWAYS exits 0

set -uo pipefail

SESSION_ID="${CLAWDSTRIKE_SESSION_ID:-unknown}"
RECEIPT_DIR="$HOME/.clawdstrike/receipts"
RECEIPT_FILE="${RECEIPT_DIR}/session-${SESSION_ID}.jsonl"

# Read hook input from stdin (best-effort)
INPUT=$(cat 2>/dev/null) || true

# Extract reason if provided
REASON=$(echo "$INPUT" | jq -er '.reason // "unknown"' 2>/dev/null) || REASON="unknown"

# Generate ISO8601 timestamp
TIMESTAMP=$(date -u +"%Y-%m-%dT%H:%M:%SZ" 2>/dev/null) || TIMESTAMP="unknown"

# Ensure receipt directory exists
mkdir -p "$RECEIPT_DIR" 2>/dev/null || true

# Write session_stop receipt line
jq -cn \
  --arg timestamp "$TIMESTAMP" \
  --arg session_id "$SESSION_ID" \
  --arg event "session_stop" \
  --arg reason "$REASON" \
  '{timestamp:$timestamp,session_id:$session_id,event:$event,reason:$reason}' \
  >> "$RECEIPT_FILE" 2>/dev/null || true

# If session_end has not yet been written, write a summary now
if [ -f "$RECEIPT_FILE" ]; then
  if ! grep -q '"event":"session_end"' "$RECEIPT_FILE" 2>/dev/null; then
    TOTAL_CALLS=$(grep -c '"tool_name"' "$RECEIPT_FILE" 2>/dev/null) || TOTAL_CALLS=0
    DENIED_CALLS=$(grep -c '"outcome":"deny"' "$RECEIPT_FILE" 2>/dev/null) || DENIED_CALLS=0

    jq -cn \
      --arg timestamp "$TIMESTAMP" \
      --arg session_id "$SESSION_ID" \
      --arg event "session_end" \
      --argjson total_tool_calls "$TOTAL_CALLS" \
      --argjson denied_tool_calls "$DENIED_CALLS" \
      '{timestamp:$timestamp,session_id:$session_id,event:$event,total_tool_calls:$total_tool_calls,denied_tool_calls:$denied_tool_calls}' \
      >> "$RECEIPT_FILE" 2>/dev/null || true
  fi
fi

exit 0
