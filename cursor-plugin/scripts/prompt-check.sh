#!/bin/bash
# Clawdstrike prompt check hook for Cursor (beforeSubmitPrompt)
# Checks user prompts for prompt injection before processing
# Exit 0 = allow, Exit 2 = deny (block prompt)

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
source "$SCRIPT_DIR/lib/common.sh"

# Read hook input from stdin
if ! INPUT=$(cat); then
  fail "failed to read hook input"
fi

# Extract Cursor context
extract_cursor_context "$INPUT"

# Extract the prompt text — handle both .prompt and .user_message fields
PROMPT=$(echo "$INPUT" | jq -er '.prompt // .user_message // empty' 2>/dev/null) || true

if [ -z "${PROMPT:-}" ]; then
  exit 0
fi

# Truncate target to first 200 characters for the policy check target field
TARGET=$(printf '%.200s' "$PROMPT")

# Build policy-check payload
PAYLOAD_ARGS=(
  --arg action_type "prompt_injection"
  --arg target "$TARGET"
  --arg content "$PROMPT"
)
PAYLOAD_TEMPLATE='{action_type:$action_type,target:$target,content:$content'

if [ -n "${SESSION_ID:-}" ] && [ "$SESSION_ID" != "unknown" ]; then
  PAYLOAD_ARGS+=(--arg session_id "$SESSION_ID")
  PAYLOAD_TEMPLATE="${PAYLOAD_TEMPLATE},session_id:\$session_id"
fi

PAYLOAD_TEMPLATE="${PAYLOAD_TEMPLATE}}"

if ! PAYLOAD=$(jq -cn "${PAYLOAD_ARGS[@]}" "$PAYLOAD_TEMPLATE" 2>/dev/null); then
  fail "failed to encode policy request payload"
fi

read_token

CHECK_URL="${CLAWDSTRIKE_ENDPOINT}/api/v1/agent/policy-check"

if ! RESPONSE=$(curl -sS --max-time 8 -X POST "$CHECK_URL" \
  -H "Authorization: Bearer ${CLAWDSTRIKE_TOKEN}" \
  -H "Content-Type: application/json" \
  --data "$PAYLOAD" 2>/dev/null); then
  fail "policy-check request failed"
fi

if ! ALLOWED=$(echo "$RESPONSE" | jq -er '.allowed' 2>/dev/null); then
  fail "policy-check returned malformed response"
fi

# Write receipt line
TIMESTAMP=$(timestamp)

if [ "$ALLOWED" = "false" ]; then
  GUARD=$(echo "$RESPONSE" | jq -er '.guard // "unknown"' 2>/dev/null || echo "unknown")
  MESSAGE=$(echo "$RESPONSE" | jq -er '.message // "Prompt blocked by security policy"' 2>/dev/null || echo "Prompt blocked by security policy")

  write_receipt "$(jq -cn \
    --arg timestamp "$TIMESTAMP" \
    --arg session_id "$SESSION_ID" \
    --arg tool_name "beforeSubmitPrompt" \
    --arg action_type "prompt_injection" \
    --arg target "$TARGET" \
    --arg outcome "deny" \
    --arg guard "$GUARD" \
    --arg message "$MESSAGE" \
    '{timestamp:$timestamp,session_id:$session_id,tool_name:$tool_name,action_type:$action_type,target:$target,outcome:$outcome,guard:$guard,message:$message}')"

  DENY_MSG="BLOCKED by ClawdStrike (${GUARD}): ${MESSAGE}"
  echo "$DENY_MSG" >&2
  deny_response "$DENY_MSG" "Prompt blocked by ClawdStrike: potential prompt injection detected."
fi

write_receipt "$(jq -cn \
  --arg timestamp "$TIMESTAMP" \
  --arg session_id "$SESSION_ID" \
  --arg tool_name "beforeSubmitPrompt" \
  --arg action_type "prompt_injection" \
  --arg target "$TARGET" \
  --arg outcome "allow" \
  '{timestamp:$timestamp,session_id:$session_id,tool_name:$tool_name,action_type:$action_type,target:$target,outcome:$outcome}')"

exit 0
