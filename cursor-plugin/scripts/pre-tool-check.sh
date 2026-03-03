#!/bin/bash
# Clawdstrike pre-tool hook for Cursor
# Checks actions against security policy before execution
# Exit 0 = allow, Exit 2 = deny (Cursor convention)
# On deny: outputs {permission:"deny", user_message, agent_message}

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
source "$SCRIPT_DIR/lib/common.sh"

# Read hook input from stdin
if ! INPUT=$(cat); then
  fail "failed to read hook input"
fi

# Extract Cursor context
extract_cursor_context "$INPUT"

# Extract tool name and input from hook data
if ! TOOL_NAME=$(echo "$INPUT" | jq -er '.tool_name // empty' 2>/dev/null); then
  fail "invalid hook payload: missing/invalid .tool_name"
fi

if ! TOOL_INPUT=$(echo "$INPUT" | jq -ec '.tool_input // {} | if type == "object" then . else {"tool_input": .} end' 2>/dev/null); then
  fail "invalid hook payload: .tool_input is not JSON"
fi

# Skip if no tool name
if [ -z "$TOOL_NAME" ]; then
  exit 0
fi

# Map tool names to action types
map_tool_to_action

# Handle empty target based on tool type (fail-closed for tools that require a target)
if [ -z "${TARGET:-}" ]; then
  case "$TOOL_NAME" in
    Read|Write|Edit|Bash)
      DENY_MSG="BLOCKED by ClawdStrike: ${TOOL_NAME} requires a target but none was provided"
      echo "$DENY_MSG" >&2
      # Write denial receipt
      TIMESTAMP=$(timestamp)
      write_receipt "$(jq -cn \
        --arg timestamp "$TIMESTAMP" \
        --arg session_id "$SESSION_ID" \
        --arg tool_name "$TOOL_NAME" \
        --arg action_type "$ACTION_TYPE" \
        --arg target "" \
        --arg outcome "deny" \
        --arg guard "empty_target" \
        --arg message "${TOOL_NAME} requires a target but none was provided" \
        '{timestamp:$timestamp,session_id:$session_id,tool_name:$tool_name,action_type:$action_type,target:$target,outcome:$outcome,guard:$guard,message:$message}')"
      deny_response "$DENY_MSG" "The tool ${TOOL_NAME} was blocked because no target was provided. Ensure a file path or command is specified."
      ;;
    Glob|Grep|WebSearch)
      # These tools can legitimately operate without an explicit target
      exit 0
      ;;
    *)
      echo "Clawdstrike: unknown tool '${TOOL_NAME}' with empty target, skipping check" >&2
      exit 0
      ;;
  esac
fi

# Build JSON safely, including session_id when available
build_payload() {
  local jq_args=()
  jq_args+=(--arg action_type "$ACTION_TYPE")
  jq_args+=(--arg target "$TARGET")

  local jq_template_fields='action_type:$action_type,target:$target'

  if [ -n "${CONTENT:-}" ]; then
    jq_args+=(--arg content "$CONTENT")
    jq_template_fields="${jq_template_fields},content:\$content"
  fi

  if [ "$ACTION_TYPE" = "mcp_tool" ]; then
    jq_args+=(--argjson args "$TOOL_INPUT")
    jq_template_fields="${jq_template_fields},args:\$args"
  fi

  if [ -n "${SESSION_ID:-}" ] && [ "$SESSION_ID" != "unknown" ]; then
    jq_args+=(--arg session_id "$SESSION_ID")
    jq_template_fields="${jq_template_fields},session_id:\$session_id"
  fi

  jq -cn "${jq_args[@]}" "{${jq_template_fields}}"
}

if ! PAYLOAD=$(build_payload 2>/dev/null); then
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

if [ "$ALLOWED" = "false" ]; then
  GUARD=$(echo "$RESPONSE" | jq -er '.guard // "unknown"' 2>/dev/null || echo "unknown")

  # When the agent returns a well-formed deny due to daemon infrastructure errors,
  # treat it as a hook failure so CLAWDSTRIKE_HOOK_FAIL_OPEN can apply.
  if [[ "$GUARD" == hushd_* ]]; then
    fail "policy daemon error (${GUARD})"
  fi

  MESSAGE=$(echo "$RESPONSE" | jq -er '.message // "Action blocked by security policy"' 2>/dev/null || echo "Action blocked by security policy")

  # Write denial receipt
  TIMESTAMP=$(timestamp)
  write_receipt "$(jq -cn \
    --arg timestamp "$TIMESTAMP" \
    --arg session_id "$SESSION_ID" \
    --arg tool_name "$TOOL_NAME" \
    --arg action_type "$ACTION_TYPE" \
    --arg target "$TARGET" \
    --arg outcome "deny" \
    --arg guard "$GUARD" \
    --arg message "$MESSAGE" \
    '{timestamp:$timestamp,session_id:$session_id,tool_name:$tool_name,action_type:$action_type,target:$target,outcome:$outcome,guard:$guard,message:$message}')"

  DENY_MSG="BLOCKED by ClawdStrike (${GUARD}): ${MESSAGE}"
  echo "$DENY_MSG" >&2
  echo "   Target: ${TARGET}" >&2
  deny_response "$DENY_MSG" "Action denied by ClawdStrike guard '${GUARD}': ${MESSAGE}. Target: ${TARGET}"
fi

exit 0
