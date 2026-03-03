#!/bin/bash
# Clawdstrike session end hook for Cursor
# Finalizes audit trail with session summary
# ALWAYS exits 0

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
source "$SCRIPT_DIR/lib/common.sh"

# Read hook input from stdin (best-effort)
INPUT=$(cat 2>/dev/null) || true
extract_cursor_context "$INPUT"

# If no receipt file exists for this session, nothing to summarize
if [ ! -f "$RECEIPT_FILE" ]; then
  exit 0
fi

# Count total action events (lines with hook_event or tool_name — session lifecycle
# uses "event" key so is naturally excluded without subtraction).
# Use -e flags instead of \| alternation for BSD grep (macOS) compatibility.
TOTAL_CALLS=$(grep -c -e '"hook_event"' -e '"tool_name"' "$RECEIPT_FILE" 2>/dev/null) || TOTAL_CALLS=0

# Count denied actions (lines with "deny" outcome)
DENIED_CALLS=$(grep -c '"outcome":"deny"' "$RECEIPT_FILE" 2>/dev/null) || DENIED_CALLS=0

# Generate ISO8601 timestamp
TIMESTAMP=$(timestamp)

# Write summary line to JSONL
jq -cn \
  --arg timestamp "$TIMESTAMP" \
  --arg session_id "$SESSION_ID" \
  --arg event "session_end" \
  --argjson total_tool_calls "$TOTAL_CALLS" \
  --argjson denied_tool_calls "$DENIED_CALLS" \
  '{timestamp:$timestamp,session_id:$session_id,event:$event,total_tool_calls:$total_tool_calls,denied_tool_calls:$denied_tool_calls}' \
  >> "$RECEIPT_FILE" 2>/dev/null || true

# Sign the receipt file if a signing key is configured (best-effort, never blocks)
if [ -n "${CLAWDSTRIKE_SIGNING_KEY:-}" ] && [ -f "$CLAWDSTRIKE_SIGNING_KEY" ]; then
  "$CLI" sign --key "$CLAWDSTRIKE_SIGNING_KEY" "$RECEIPT_FILE" -o "${RECEIPT_FILE}.sig" 2>/dev/null || true
fi

exit 0
