#!/bin/bash
# Clawdstrike user prompt submission hook (plugin version)
# Checks user prompts for prompt injection before processing
# Exit 0 = allow, Exit 2 = deny (block prompt)

set -euo pipefail

# Configuration
CLAWDSTRIKE_ENDPOINT="${CLAWDSTRIKE_ENDPOINT:-http://127.0.0.1:9878}"
CLAWDSTRIKE_TOKEN_FILE="${CLAWDSTRIKE_TOKEN_FILE:-$HOME/.config/clawdstrike/agent-local-token}"
CLAWDSTRIKE_HOOK_FAIL_OPEN="${CLAWDSTRIKE_HOOK_FAIL_OPEN:-0}"
SESSION_ID="${CLAWDSTRIKE_SESSION_ID:-unknown}"
RECEIPT_DIR="$HOME/.clawdstrike/receipts"
RECEIPT_FILE="${RECEIPT_DIR}/session-${SESSION_ID}.jsonl"

fail() {
  local reason="$1"
  local remediation="${2:-}"
  echo "Clawdstrike prompt hook error: ${reason}" >&2
  if [ -n "$remediation" ]; then
    echo "  Fix: ${remediation}" >&2
  fi
  echo "  Bypass: set CLAWDSTRIKE_HOOK_FAIL_OPEN=true to allow actions while debugging" >&2
  echo "  Diagnose: run /clawdstrike:selftest for full status" >&2
  case "$CLAWDSTRIKE_HOOK_FAIL_OPEN" in
    1|true|True|TRUE|yes|Yes|YES)
      echo "CLAWDSTRIKE_HOOK_FAIL_OPEN is set; allowing prompt despite hook failure." >&2
      exit 0
      ;;
  esac
  exit 2
}

# Read hook input from stdin
if ! INPUT=$(cat); then
  fail "failed to read hook input"
fi

# Extract the prompt text
if ! PROMPT=$(echo "$INPUT" | jq -er '.prompt // empty' 2>/dev/null); then
  fail "invalid hook payload: missing/invalid .prompt"
fi

if [ -z "$PROMPT" ]; then
  exit 0
fi

# Truncate target to first 200 characters for the policy check target field
TARGET=$(printf '%.200s' "$PROMPT")

# Read auth token
if [ ! -f "$CLAWDSTRIKE_TOKEN_FILE" ]; then
  fail "agent auth token file not found at $CLAWDSTRIKE_TOKEN_FILE" \
    "Start the ClawdStrike Agent app, or set CLAWDSTRIKE_TOKEN_FILE to your token path"
fi

if ! CLAWDSTRIKE_TOKEN=$(cat "$CLAWDSTRIKE_TOKEN_FILE"); then
  fail "failed to read agent auth token from $CLAWDSTRIKE_TOKEN_FILE" \
    "Check file permissions on $CLAWDSTRIKE_TOKEN_FILE"
fi

if [ -z "$CLAWDSTRIKE_TOKEN" ]; then
  fail "agent auth token is empty" \
    "Restart the ClawdStrike Agent app to regenerate the token"
fi

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
  fail "failed to encode policy request payload" \
    "This is likely a bug; check the hook input JSON"
fi

CHECK_URL="${CLAWDSTRIKE_ENDPOINT}/api/v1/agent/policy-check"

if ! RESPONSE=$(curl -sS --max-time 8 -X POST "$CHECK_URL" \
  -H "Authorization: Bearer ${CLAWDSTRIKE_TOKEN}" \
  -H "Content-Type: application/json" \
  --data "$PAYLOAD" 2>/dev/null); then
  fail "policy-check request failed (hushd unreachable at ${CLAWDSTRIKE_ENDPOINT})" \
    "Start hushd: clawdstrike serve, or start the ClawdStrike Agent app"
fi

if ! ALLOWED=$(echo "$RESPONSE" | jq -er '.allowed' 2>/dev/null); then
  fail "policy-check returned malformed response" \
    "Check hushd health: curl -s ${CLAWDSTRIKE_ENDPOINT}/health"
fi

# Write receipt line
TIMESTAMP=$(date -u +"%Y-%m-%dT%H:%M:%SZ" 2>/dev/null) || TIMESTAMP="unknown"
mkdir -p "$RECEIPT_DIR" 2>/dev/null || true

if [ "$ALLOWED" = "false" ]; then
  GUARD=$(echo "$RESPONSE" | jq -er '.guard // "unknown"' 2>/dev/null || echo "unknown")
  MESSAGE=$(echo "$RESPONSE" | jq -er '.message // "Prompt blocked by security policy"' 2>/dev/null || echo "Prompt blocked by security policy")

  jq -cn \
    --arg timestamp "$TIMESTAMP" \
    --arg session_id "$SESSION_ID" \
    --arg tool_name "UserPromptSubmit" \
    --arg action_type "prompt_injection" \
    --arg target "$TARGET" \
    --arg outcome "deny" \
    --arg guard "$GUARD" \
    --arg message "$MESSAGE" \
    '{timestamp:$timestamp,session_id:$session_id,tool_name:$tool_name,action_type:$action_type,target:$target,outcome:$outcome,guard:$guard,message:$message}' \
    >> "$RECEIPT_FILE" 2>/dev/null || true

  echo "BLOCKED by Clawdstrike (${GUARD}): ${MESSAGE}" >&2
  exit 2
fi

jq -cn \
  --arg timestamp "$TIMESTAMP" \
  --arg session_id "$SESSION_ID" \
  --arg tool_name "UserPromptSubmit" \
  --arg action_type "prompt_injection" \
  --arg target "$TARGET" \
  --arg outcome "allow" \
  '{timestamp:$timestamp,session_id:$session_id,tool_name:$tool_name,action_type:$action_type,target:$target,outcome:$outcome}' \
  >> "$RECEIPT_FILE" 2>/dev/null || true

exit 0
