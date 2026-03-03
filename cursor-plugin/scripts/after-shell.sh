#!/bin/bash
# Clawdstrike afterShellExecution hook for Cursor
# Writes receipt with command outcome (exit code, stdout, stderr)
# ALWAYS exits 0

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
source "$SCRIPT_DIR/lib/common.sh"

# Read hook input from stdin (best-effort)
INPUT=$(cat 2>/dev/null) || true

# Extract Cursor context
extract_cursor_context "$INPUT"

# Extract shell execution details
COMMAND=$(echo "$INPUT" | jq -er '.command // empty' 2>/dev/null) || true
EXIT_CODE=$(echo "$INPUT" | jq -er '.exit_code // empty' 2>/dev/null) || true
# stdout/stderr may be large; just note their presence
if echo "$INPUT" | jq -e '.stdout != null and .stdout != ""' >/dev/null 2>&1; then
  HAS_STDOUT="true"
else
  HAS_STDOUT="false"
fi
if echo "$INPUT" | jq -e '.stderr != null and .stderr != ""' >/dev/null 2>&1; then
  HAS_STDERR="true"
else
  HAS_STDERR="false"
fi

# Determine outcome
OUTCOME="success"
if [ -n "$EXIT_CODE" ] && [ "$EXIT_CODE" != "0" ]; then
  OUTCOME="error"
fi

# Write receipt
TIMESTAMP=$(timestamp)
write_receipt "$(jq -cn \
  --arg timestamp "$TIMESTAMP" \
  --arg session_id "$SESSION_ID" \
  --arg hook_event "afterShellExecution" \
  --arg action_type "shell" \
  --arg target "${COMMAND:-unknown}" \
  --arg exit_code "${EXIT_CODE:-}" \
  --arg outcome "$OUTCOME" \
  --argjson has_stdout "$HAS_STDOUT" \
  --argjson has_stderr "$HAS_STDERR" \
  '{timestamp:$timestamp,session_id:$session_id,hook_event:$hook_event,action_type:$action_type,target:$target,exit_code:$exit_code,outcome:$outcome,has_stdout:$has_stdout,has_stderr:$has_stderr}')"

exit 0
