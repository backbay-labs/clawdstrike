#!/bin/bash
# Shared functions for Cursor ClawdStrike hook scripts.
# Source this from hook scripts: source "$(dirname "$0")/lib/common.sh"

# Configuration defaults
CLAWDSTRIKE_ENDPOINT="${CLAWDSTRIKE_ENDPOINT:-http://127.0.0.1:9876}"
if [ -z "${CLAWDSTRIKE_TOKEN_FILE:-}" ]; then
  if [ -f "$HOME/Library/Application Support/clawdstrike/agent-local-token" ]; then
    CLAWDSTRIKE_TOKEN_FILE="$HOME/Library/Application Support/clawdstrike/agent-local-token"
  else
    CLAWDSTRIKE_TOKEN_FILE="$HOME/.config/clawdstrike/agent-local-token"
  fi
fi
CLAWDSTRIKE_HOOK_FAIL_OPEN="${CLAWDSTRIKE_HOOK_FAIL_OPEN:-0}"
SESSION_ID="${CLAWDSTRIKE_SESSION_ID:-unknown}"
RECEIPT_DIR="${CLAWDSTRIKE_RECEIPT_DIR:-$HOME/.clawdstrike/receipts}"
RECEIPT_FILE="${RECEIPT_DIR}/session-${SESSION_ID}.jsonl"
CLI="${CLAWDSTRIKE_CLI:-clawdstrike}"

# fail() — exit with error, respecting CLAWDSTRIKE_HOOK_FAIL_OPEN.
# In Cursor, deny exit code is always 2 (not 1).
# Args: reason [remediation]
fail() {
  local reason="$1"
  local remediation="${2:-}"
  echo "Clawdstrike hook error: ${reason}" >&2
  if [ -n "$remediation" ]; then
    echo "  Fix: ${remediation}" >&2
  fi
  echo "  Bypass: set CLAWDSTRIKE_HOOK_FAIL_OPEN=true to allow actions while debugging" >&2
  echo "  Diagnose: run /clawdstrike:selftest for full status" >&2
  case "$CLAWDSTRIKE_HOOK_FAIL_OPEN" in
    1|true|True|TRUE|yes|Yes|YES)
      echo "CLAWDSTRIKE_HOOK_FAIL_OPEN is set; allowing action despite hook failure." >&2
      exit 0
      ;;
  esac
  exit 2
}

# read_token() — read bearer token from $CLAWDSTRIKE_TOKEN_FILE.
# Sets CLAWDSTRIKE_TOKEN on success, calls fail() on error.
read_token() {
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

  export CLAWDSTRIKE_TOKEN
}

# post_policy_check() — POST to hushd policy-check endpoint.
# Args: action_type target [content] [extra_jq_args...]
# Sets RESPONSE, ALLOWED on success. Calls fail() on error.
post_policy_check() {
  local action_type="$1"
  local target="$2"
  local content="${3:-}"

  local jq_args=()
  jq_args+=(--arg action_type "$action_type")
  jq_args+=(--arg target "$target")
  local jq_template='action_type:$action_type,target:$target'

  if [ -n "$content" ]; then
    if [ "$action_type" = "mcp_tool" ]; then
      # MCP tool arguments must be sent as a JSON object, not a string
      jq_args+=(--argjson args "$content")
      jq_template="${jq_template},args:\$args"
    else
      jq_args+=(--arg content "$content")
      jq_template="${jq_template},content:\$content"
    fi
  fi

  if [ -n "${SESSION_ID:-}" ] && [ "$SESSION_ID" != "unknown" ]; then
    jq_args+=(--arg session_id "$SESSION_ID")
    jq_template="${jq_template},session_id:\$session_id"
  fi

  local payload
  if ! payload=$(jq -cn "${jq_args[@]}" "{${jq_template}}" 2>/dev/null); then
    fail "failed to encode policy request payload" \
      "This is likely a bug; check the hook input JSON"
  fi

  read_token

  local check_url="${CLAWDSTRIKE_ENDPOINT}/api/v1/agent/policy-check"

  if ! RESPONSE=$(curl -sS --max-time 8 -X POST "$check_url" \
    -H "Authorization: Bearer ${CLAWDSTRIKE_TOKEN}" \
    -H "Content-Type: application/json" \
    --data "$payload" 2>/dev/null); then
    fail "policy-check request failed (hushd unreachable at ${CLAWDSTRIKE_ENDPOINT})" \
      "Start hushd: clawdstrike serve, or start the ClawdStrike Agent app"
  fi

  if ! ALLOWED=$(echo "$RESPONSE" | jq -er '.allowed' 2>/dev/null); then
    fail "policy-check returned malformed response" \
      "Check hushd health: curl -s ${CLAWDSTRIKE_ENDPOINT}/health"
  fi

  export RESPONSE ALLOWED
}

# write_receipt() — append a JSONL line to the receipt file.
# Args: JSON string to write (must be valid JSON).
write_receipt() {
  local json_line="$1"
  mkdir -p "$RECEIPT_DIR" 2>/dev/null || true
  echo "$json_line" >> "$RECEIPT_FILE" 2>/dev/null || true
}

# map_tool_to_action() — map tool_name to action_type.
# Sets ACTION_TYPE and TARGET. Reads TOOL_NAME, TOOL_INPUT.
map_tool_to_action() {
  CONTENT=""
  case "$TOOL_NAME" in
    Read)
      ACTION_TYPE="file_access"
      TARGET=$(echo "$TOOL_INPUT" | jq -er '.file_path // .path // empty' 2>/dev/null || true)
      ;;
    Glob)
      ACTION_TYPE="file_access"
      TARGET=$(echo "$TOOL_INPUT" | jq -er '.pattern // empty' 2>/dev/null || true)
      ;;
    Grep)
      ACTION_TYPE="file_access"
      TARGET=$(echo "$TOOL_INPUT" | jq -er '.file_path // .path // .pattern // empty' 2>/dev/null || true)
      ;;
    Write)
      ACTION_TYPE="file_write"
      TARGET=$(echo "$TOOL_INPUT" | jq -er '.file_path // .path // empty' 2>/dev/null || true)
      CONTENT=$(echo "$TOOL_INPUT" | jq -er '.content // .text // empty' 2>/dev/null || true)
      ;;
    Edit)
      ACTION_TYPE="file_write"
      TARGET=$(echo "$TOOL_INPUT" | jq -er '.file_path // .path // empty' 2>/dev/null || true)
      CONTENT=$(echo "$TOOL_INPUT" | jq -er '.new_string // .content // empty' 2>/dev/null || true)
      ;;
    Bash)
      ACTION_TYPE="shell"
      TARGET=$(echo "$TOOL_INPUT" | jq -er '.command // empty' 2>/dev/null || true)
      ;;
    WebFetch|WebSearch)
      ACTION_TYPE="egress"
      TARGET=$(echo "$TOOL_INPUT" | jq -er '.url // .query // empty' 2>/dev/null || true)
      ;;
    *)
      ACTION_TYPE="mcp_tool"
      TARGET="$TOOL_NAME"
      ;;
  esac
}

# extract_cursor_context() — parse Cursor base fields from stdin JSON.
# Sets CURSOR_CONVERSATION_ID, CURSOR_GENERATION_ID, CURSOR_MODEL,
# CURSOR_HOOK_EVENT, CURSOR_VERSION, CURSOR_WORKSPACE_ROOTS, CURSOR_USER_EMAIL.
extract_cursor_context() {
  local input="$1"
  CURSOR_CONVERSATION_ID=$(echo "$input" | jq -er '.conversation_id // empty' 2>/dev/null || true)
  CURSOR_GENERATION_ID=$(echo "$input" | jq -er '.generation_id // empty' 2>/dev/null || true)
  CURSOR_MODEL=$(echo "$input" | jq -er '.model // empty' 2>/dev/null || true)
  CURSOR_HOOK_EVENT=$(echo "$input" | jq -er '.hook_event_name // empty' 2>/dev/null || true)
  CURSOR_VERSION=$(echo "$input" | jq -er '.cursor_version // empty' 2>/dev/null || true)
  CURSOR_WORKSPACE_ROOTS=$(echo "$input" | jq -ec '.workspace_roots // []' 2>/dev/null || echo "[]")
  CURSOR_USER_EMAIL=$(echo "$input" | jq -er '.user_email // empty' 2>/dev/null || true)
}

# timestamp() — generate ISO 8601 UTC timestamp.
timestamp() {
  date -u +"%Y-%m-%dT%H:%M:%SZ" 2>/dev/null || echo "unknown"
}

# deny_response() — output Cursor-format deny JSON and exit 2.
# Args: user_message agent_message
deny_response() {
  local user_message="$1"
  local agent_message="${2:-$1}"
  jq -cn \
    --arg permission "deny" \
    --arg user_message "$user_message" \
    --arg agent_message "$agent_message" \
    '{permission:$permission,user_message:$user_message,agent_message:$agent_message}'
  exit 2
}
