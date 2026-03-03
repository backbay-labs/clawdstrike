#!/bin/bash
# Clawdstrike afterFileEdit hook for Cursor
# Writes receipt with file edit details
# ALWAYS exits 0

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
source "$SCRIPT_DIR/lib/common.sh"

# Read hook input from stdin (best-effort)
INPUT=$(cat 2>/dev/null) || true

# Extract Cursor context
extract_cursor_context "$INPUT"

# Extract file edit details
FILE_PATH=$(echo "$INPUT" | jq -er '.file_path // empty' 2>/dev/null) || true
# edits may be large; just count them
EDIT_COUNT=$(echo "$INPUT" | jq -er '.edits | length // 0' 2>/dev/null) || EDIT_COUNT=0

# Write receipt
TIMESTAMP=$(timestamp)
write_receipt "$(jq -cn \
  --arg timestamp "$TIMESTAMP" \
  --arg session_id "$SESSION_ID" \
  --arg hook_event "afterFileEdit" \
  --arg action_type "file_write" \
  --arg target "${FILE_PATH:-unknown}" \
  --argjson edit_count "$EDIT_COUNT" \
  --arg outcome "success" \
  '{timestamp:$timestamp,session_id:$session_id,hook_event:$hook_event,action_type:$action_type,target:$target,edit_count:$edit_count,outcome:$outcome}')"

exit 0
