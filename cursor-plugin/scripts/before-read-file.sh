#!/bin/bash
# Clawdstrike beforeReadFile hook for Cursor
# Policy-checks file reads before access
# Fail-closed by default (Cursor convention for beforeReadFile)
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

# Extract file_path directly (Cursor provides this at top level)
FILE_PATH=$(echo "$INPUT" | jq -er '.file_path // empty' 2>/dev/null) || true

# If no file path provided, allow (nothing to check)
if [ -z "${FILE_PATH:-}" ]; then
  exit 0
fi

# POST to hushd with action_type=file_access
post_policy_check "file_access" "$FILE_PATH"

if [ "$ALLOWED" = "false" ]; then
  GUARD=$(echo "$RESPONSE" | jq -er '.guard // "unknown"' 2>/dev/null || echo "unknown")
  MESSAGE=$(echo "$RESPONSE" | jq -er '.message // "File read blocked by security policy"' 2>/dev/null || echo "File read blocked by security policy")

  # Write denial receipt
  TIMESTAMP=$(timestamp)
  write_receipt "$(jq -cn \
    --arg timestamp "$TIMESTAMP" \
    --arg session_id "$SESSION_ID" \
    --arg hook_event "beforeReadFile" \
    --arg action_type "file_access" \
    --arg target "$FILE_PATH" \
    --arg outcome "deny" \
    --arg guard "$GUARD" \
    --arg message "$MESSAGE" \
    '{timestamp:$timestamp,session_id:$session_id,hook_event:$hook_event,action_type:$action_type,target:$target,outcome:$outcome,guard:$guard,message:$message}')"

  DENY_MSG="BLOCKED by ClawdStrike (${GUARD}): ${MESSAGE}"
  echo "$DENY_MSG" >&2
  deny_response "$DENY_MSG" "File read of '${FILE_PATH}' was blocked by ClawdStrike guard '${GUARD}': ${MESSAGE}"
fi

exit 0
