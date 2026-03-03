#!/bin/bash
# Clawdstrike session end hook (plugin version)
# Finalizes audit trail with session summary
# ALWAYS exits 0

set -uo pipefail

SESSION_ID="${CLAWDSTRIKE_SESSION_ID:-unknown}"
RECEIPT_DIR="$HOME/.clawdstrike/receipts"
RECEIPT_FILE="${RECEIPT_DIR}/session-${SESSION_ID}.jsonl"

# If no receipt file exists for this session, nothing to summarize
if [ ! -f "$RECEIPT_FILE" ]; then
  exit 0
fi

# Count total tool call lines (exclude session_start and session_end events)
TOTAL_CALLS=$(grep -c '"tool_name"' "$RECEIPT_FILE" 2>/dev/null) || TOTAL_CALLS=0

# Count denied actions (lines with "deny" outcome)
DENIED_CALLS=$(grep -c '"outcome":"deny"' "$RECEIPT_FILE" 2>/dev/null) || DENIED_CALLS=0

# Generate ISO8601 timestamp
TIMESTAMP=$(date -u +"%Y-%m-%dT%H:%M:%SZ" 2>/dev/null) || TIMESTAMP="unknown"

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
  CLI="${CLAWDSTRIKE_CLI:-clawdstrike}"
  "$CLI" sign --key "$CLAWDSTRIKE_SIGNING_KEY" "$RECEIPT_FILE" -o "${RECEIPT_FILE}.sig" 2>/dev/null || true
fi

exit 0
