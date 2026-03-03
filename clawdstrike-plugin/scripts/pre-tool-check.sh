#!/bin/bash
# Clawdstrike pre-tool hook for Claude Code (plugin version)
# Checks actions against security policy before execution
# Ported from ~/.claude/hooks/clawdstrike-check.sh with session_id support

set -euo pipefail

# Configuration
CLAWDSTRIKE_ENDPOINT="${CLAWDSTRIKE_ENDPOINT:-http://127.0.0.1:9878}"
CLAWDSTRIKE_TOKEN_FILE="${CLAWDSTRIKE_TOKEN_FILE:-$HOME/.config/clawdstrike/agent-local-token}"
CLAWDSTRIKE_HOOK_FAIL_OPEN="${CLAWDSTRIKE_HOOK_FAIL_OPEN:-0}"

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
  exit 1
}

# Read hook input from stdin
if ! INPUT=$(cat); then
  fail "failed to read hook input"
fi

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

# Map tool names to hushd /api/v1/check action types.
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
    # Grep may be invoked without an explicit path (searching the full workspace). In that case
    # fall back to `.pattern` so we don't bypass the policy check entirely.
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
    # Unknown tool: treat as an MCP tool and let policy decide.
    ACTION_TYPE="mcp_tool"
    TARGET="$TOOL_NAME"
    ;;
esac

# Handle empty target based on tool type (fail-closed for tools that require a target)
if [ -z "${TARGET:-}" ]; then
  case "$TOOL_NAME" in
    Read|Write|Edit|Bash)
      echo "BLOCKED by Clawdstrike: ${TOOL_NAME} requires a target but none was provided" >&2
      # Write denial receipt
      if [ -n "${CLAWDSTRIKE_SESSION_ID:-}" ]; then
        _RECEIPT_DIR="$HOME/.clawdstrike/receipts"
        _RECEIPT_FILE="${_RECEIPT_DIR}/session-${CLAWDSTRIKE_SESSION_ID}.jsonl"
        _TS=$(date -u +"%Y-%m-%dT%H:%M:%SZ" 2>/dev/null) || _TS="unknown"
        mkdir -p "$_RECEIPT_DIR" 2>/dev/null || true
        jq -cn \
          --arg timestamp "$_TS" \
          --arg session_id "$CLAWDSTRIKE_SESSION_ID" \
          --arg tool_name "$TOOL_NAME" \
          --arg action_type "$ACTION_TYPE" \
          --arg target "" \
          --arg outcome "deny" \
          --arg guard "empty_target" \
          --arg message "${TOOL_NAME} requires a target but none was provided" \
          '{timestamp:$timestamp,session_id:$session_id,tool_name:$tool_name,action_type:$action_type,target:$target,outcome:$outcome,guard:$guard,message:$message}' \
          >> "$_RECEIPT_FILE" 2>/dev/null || true
      fi
      exit 1
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

# Build JSON safely, including session_id when available.
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

  if [ -n "${CLAWDSTRIKE_SESSION_ID:-}" ]; then
    jq_args+=(--arg session_id "$CLAWDSTRIKE_SESSION_ID")
    jq_template_fields="${jq_template_fields},session_id:\$session_id"
  fi

  jq -cn "${jq_args[@]}" "{${jq_template_fields}}"
}

if ! PAYLOAD=$(build_payload 2>/dev/null); then
  fail "failed to encode policy request payload" \
    "This is likely a bug; check the hook input JSON"
fi

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

if [ "$ALLOWED" = "false" ]; then
  GUARD=$(echo "$RESPONSE" | jq -er '.guard // "unknown"' 2>/dev/null || echo "unknown")

  # When the agent returns a well-formed deny due to daemon infrastructure errors,
  # treat it as a hook failure so CLAWDSTRIKE_HOOK_FAIL_OPEN can apply.
  if [[ "$GUARD" == hushd_* ]]; then
    fail "policy daemon error (${GUARD})" \
      "Start hushd: clawdstrike serve, or start the ClawdStrike Agent app"
  fi

  MESSAGE=$(echo "$RESPONSE" | jq -er '.message // "Action blocked by security policy"' 2>/dev/null || echo "Action blocked by security policy")

  # Write denial receipt for session audit trail (Item 13)
  if [ -n "${CLAWDSTRIKE_SESSION_ID:-}" ]; then
    _RECEIPT_DIR="$HOME/.clawdstrike/receipts"
    _RECEIPT_FILE="${_RECEIPT_DIR}/session-${CLAWDSTRIKE_SESSION_ID}.jsonl"
    _TS=$(date -u +"%Y-%m-%dT%H:%M:%SZ" 2>/dev/null) || _TS="unknown"
    mkdir -p "$_RECEIPT_DIR" 2>/dev/null || true
    jq -cn \
      --arg timestamp "$_TS" \
      --arg session_id "$CLAWDSTRIKE_SESSION_ID" \
      --arg tool_name "$TOOL_NAME" \
      --arg action_type "$ACTION_TYPE" \
      --arg target "$TARGET" \
      --arg outcome "deny" \
      --arg guard "$GUARD" \
      --arg message "$MESSAGE" \
      '{timestamp:$timestamp,session_id:$session_id,tool_name:$tool_name,action_type:$action_type,target:$target,outcome:$outcome,guard:$guard,message:$message}' \
      >> "$_RECEIPT_FILE" 2>/dev/null || true
  fi

  echo "BLOCKED by Clawdstrike (${GUARD}): ${MESSAGE}" >&2
  echo "   Target: ${TARGET}" >&2
  exit 1
fi

exit 0
