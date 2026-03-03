#!/bin/bash
# Clawdstrike stop hook handler for Cursor
# Writes session_stop receipt and summary if session_end not yet written
# Can output {followup_message} for session wrap-up
# ALWAYS exits 0

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
source "$SCRIPT_DIR/lib/common.sh"

# Read hook input from stdin (best-effort)
INPUT=$(cat 2>/dev/null) || true

# Extract Cursor context
extract_cursor_context "$INPUT"

# Extract reason/status if provided
REASON=$(echo "$INPUT" | jq -er '.reason // .status // "unknown"' 2>/dev/null) || REASON="unknown"

# Generate ISO8601 timestamp
TIMESTAMP=$(timestamp)

# Write session_stop receipt line
write_receipt "$(jq -cn \
  --arg timestamp "$TIMESTAMP" \
  --arg session_id "$SESSION_ID" \
  --arg event "session_stop" \
  --arg reason "$REASON" \
  '{timestamp:$timestamp,session_id:$session_id,event:$event,reason:$reason}')"

# If session_end has not yet been written, write a summary now
TOTAL_CALLS=0
DENIED_CALLS=0
if [ -f "$RECEIPT_FILE" ]; then
  if ! grep -q '"event":"session_end"' "$RECEIPT_FILE" 2>/dev/null; then
    TOTAL_CALLS=$(grep -c '"tool_name"' "$RECEIPT_FILE" 2>/dev/null) || TOTAL_CALLS=0
    DENIED_CALLS=$(grep -c '"outcome":"deny"' "$RECEIPT_FILE" 2>/dev/null) || DENIED_CALLS=0

    write_receipt "$(jq -cn \
      --arg timestamp "$TIMESTAMP" \
      --arg session_id "$SESSION_ID" \
      --arg event "session_end" \
      --argjson total_tool_calls "$TOTAL_CALLS" \
      --argjson denied_tool_calls "$DENIED_CALLS" \
      '{timestamp:$timestamp,session_id:$session_id,event:$event,total_tool_calls:$total_tool_calls,denied_tool_calls:$denied_tool_calls}')"
  fi
fi

# Output Cursor-format followup_message with session summary
if [ "$TOTAL_CALLS" -gt 0 ] || [ "$DENIED_CALLS" -gt 0 ]; then
  jq -cn \
    --arg followup_message "ClawdStrike session summary: ${TOTAL_CALLS} actions evaluated, ${DENIED_CALLS} denied." \
    '{followup_message:$followup_message}'
fi

exit 0
