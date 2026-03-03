#!/bin/bash
# Clawdstrike beforeShellExecution hook for Cursor
# Policy-checks shell commands before execution
# Gets {command, cwd} directly from Cursor (no need to extract from tool_input)
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

# Extract command and cwd directly (Cursor provides these at top level)
COMMAND=$(echo "$INPUT" | jq -er '.command // empty' 2>/dev/null) || true
CWD=$(echo "$INPUT" | jq -er '.cwd // empty' 2>/dev/null) || true

# If no command provided, allow (nothing to check)
if [ -z "${COMMAND:-}" ]; then
  exit 0
fi

# POST to hushd with action_type=shell
post_policy_check "shell" "$COMMAND"

if [ "$ALLOWED" = "false" ]; then
  GUARD=$(echo "$RESPONSE" | jq -er '.guard // "unknown"' 2>/dev/null || echo "unknown")
  MESSAGE=$(echo "$RESPONSE" | jq -er '.message // "Shell command blocked by security policy"' 2>/dev/null || echo "Shell command blocked by security policy")

  # Write denial receipt
  TIMESTAMP=$(timestamp)
  write_receipt "$(jq -cn \
    --arg timestamp "$TIMESTAMP" \
    --arg session_id "$SESSION_ID" \
    --arg hook_event "beforeShellExecution" \
    --arg action_type "shell" \
    --arg target "$COMMAND" \
    --arg cwd "${CWD:-}" \
    --arg outcome "deny" \
    --arg guard "$GUARD" \
    --arg message "$MESSAGE" \
    '{timestamp:$timestamp,session_id:$session_id,hook_event:$hook_event,action_type:$action_type,target:$target,cwd:$cwd,outcome:$outcome,guard:$guard,message:$message}')"

  DENY_MSG="BLOCKED by ClawdStrike (${GUARD}): ${MESSAGE}"
  echo "$DENY_MSG" >&2
  deny_response "$DENY_MSG" "Shell command '${COMMAND}' was blocked by ClawdStrike guard '${GUARD}': ${MESSAGE}"
fi

# Write allow receipt
TIMESTAMP=$(timestamp)
write_receipt "$(jq -cn \
  --arg timestamp "$TIMESTAMP" \
  --arg session_id "$SESSION_ID" \
  --arg hook_event "beforeShellExecution" \
  --arg action_type "shell" \
  --arg target "$COMMAND" \
  --arg cwd "${CWD:-}" \
  --arg outcome "allow" \
  '{timestamp:$timestamp,session_id:$session_id,hook_event:$hook_event,action_type:$action_type,target:$target,cwd:$cwd,outcome:$outcome}')"

exit 0
