#!/bin/bash
# Clawdstrike session start hook for Cursor
# Initializes audit trail and probes hushd health
# Output: {env, additional_context, continue} (Cursor format)

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
source "$SCRIPT_DIR/lib/common.sh"

# Read hook input from stdin (best-effort)
INPUT=$(cat 2>/dev/null) || true
extract_cursor_context "$INPUT"

# Generate a unique session ID (UUID preferred, fallback to nanosecond timestamp + random bytes)
if command -v uuidgen >/dev/null 2>&1; then
  SESSION_ID="$(uuidgen | tr '[:upper:]' '[:lower:]')"
else
  SESSION_ID="$(date +%s%N 2>/dev/null || date +%s)-$(head -c 16 /dev/urandom | xxd -p)"
fi

# Create receipt directory
mkdir -p "$RECEIPT_DIR" 2>/dev/null || true

# Probe hushd health
HUSHD_STATUS="disconnected"
if HEALTH_RESPONSE=$(curl -s --max-time 2 "${CLAWDSTRIKE_ENDPOINT}/health" 2>/dev/null); then
  if echo "$HEALTH_RESPONSE" | jq -e '.status == "ok" or .status == "healthy"' >/dev/null 2>&1; then
    HUSHD_STATUS="connected"
  fi
fi

# Verify policy bundle if configured
if [ -n "${CLAWDSTRIKE_POLICY_BUNDLE:-}" ] && [ -f "$CLAWDSTRIKE_POLICY_BUNDLE" ]; then
  if BUNDLE_RESULT=$("$CLI" policy bundle verify "$CLAWDSTRIKE_POLICY_BUNDLE" --json 2>/dev/null); then
    if ! echo "$BUNDLE_RESULT" | jq -e '.valid == true' >/dev/null 2>&1; then
      echo "Clawdstrike: policy bundle verification failed" >&2
      exit 1
    fi
  else
    echo "Clawdstrike: policy bundle verification command failed" >&2
    exit 1
  fi
fi

# Get active policy info
POLICY_NAME="ai-agent"
GUARD_COUNT="unknown"
if POLICY_INFO=$("$CLI" policy show ai-agent --json 2>/dev/null); then
  POLICY_NAME=$(echo "$POLICY_INFO" | jq -er '.name // "ai-agent"' 2>/dev/null) || POLICY_NAME="ai-agent"
  GUARD_COUNT=$(echo "$POLICY_INFO" | jq -er '.guards | length' 2>/dev/null) || GUARD_COUNT="unknown"
fi

# Write initial session receipt line
TIMESTAMP=$(timestamp)
RECEIPT_FILE="${RECEIPT_DIR}/session-${SESSION_ID}.jsonl"

jq -cn \
  --arg timestamp "$TIMESTAMP" \
  --arg session_id "$SESSION_ID" \
  --arg event "session_start" \
  --arg hushd_status "$HUSHD_STATUS" \
  --arg policy "$POLICY_NAME" \
  --arg guard_count "$GUARD_COUNT" \
  --arg conversation_id "${CURSOR_CONVERSATION_ID:-}" \
  --arg cursor_version "${CURSOR_VERSION:-}" \
  '{timestamp:$timestamp,session_id:$session_id,event:$event,hushd_status:$hushd_status,policy:$policy,guard_count:$guard_count,conversation_id:$conversation_id,cursor_version:$cursor_version}' \
  >> "$RECEIPT_FILE" 2>/dev/null || true

# Check token file
if [ -z "${CLAWDSTRIKE_TOKEN_FILE:-}" ]; then
  if [ -f "$HOME/Library/Application Support/clawdstrike/agent-local-token" ]; then
    CLAWDSTRIKE_TOKEN_FILE="$HOME/Library/Application Support/clawdstrike/agent-local-token"
  else
    CLAWDSTRIKE_TOKEN_FILE="$HOME/.config/clawdstrike/agent-local-token"
  fi
fi
TOKEN_STATUS="missing"
if [ -f "$CLAWDSTRIKE_TOKEN_FILE" ]; then
  if [ -r "$CLAWDSTRIKE_TOKEN_FILE" ] && [ -s "$CLAWDSTRIKE_TOKEN_FILE" ]; then
    TOKEN_STATUS="ok"
  else
    TOKEN_STATUS="unreadable"
  fi
fi

# Build doctor check — detect issues upfront
ISSUES=""
if [ "$HUSHD_STATUS" != "connected" ]; then
  ISSUES="${ISSUES}WARNING: hushd is not running at ${CLAWDSTRIKE_ENDPOINT}
  -> Start the ClawdStrike Agent app, or run: clawdstrike serve
  -> Tool calls will be BLOCKED until hushd is available
"
fi
if [ "$TOKEN_STATUS" = "missing" ]; then
  ISSUES="${ISSUES}WARNING: Agent auth token missing at ${CLAWDSTRIKE_TOKEN_FILE}
  -> Start the ClawdStrike Agent app (creates this file automatically)
  -> Tool calls will be BLOCKED until the token is available
"
elif [ "$TOKEN_STATUS" = "unreadable" ]; then
  ISSUES="${ISSUES}WARNING: Agent auth token unreadable at ${CLAWDSTRIKE_TOKEN_FILE}
  -> Check file permissions: ls -la ${CLAWDSTRIKE_TOKEN_FILE}
  -> Tool calls will be BLOCKED until the token is readable
"
fi

# Build the additional context message
if [ -n "$ISSUES" ]; then
  CONTEXT="ClawdStrike Security - SETUP REQUIRED
Session: ${SESSION_ID}

${ISSUES}
Bypass: export CLAWDSTRIKE_HOOK_FAIL_OPEN=true
Diagnose: /clawdstrike:selftest"
else
  # Build enforcement status line
  ENFORCEMENT_LINE="Enforcement: ACTIVE (hushd ${CLAWDSTRIKE_ENDPOINT})"

  CONTEXT="ClawdStrike Security Active
Session: ${SESSION_ID}
Policy: ${POLICY_NAME} (${GUARD_COUNT} guards)
${ENFORCEMENT_LINE}

Available commands:
  /clawdstrike:scan    - Scan MCP configs for security issues
  /clawdstrike:audit   - View session audit trail
  /clawdstrike:posture - Assess security posture (A-F grade)
  /clawdstrike:policy  - Display active policy details
  /clawdstrike:tui     - Launch interactive TUI dashboard"
fi

# Output Cursor-format JSON to stdout
# Cursor sessionStart expects: {env, additional_context, continue}
jq -cn \
  --arg context "$CONTEXT" \
  --arg session_id "$SESSION_ID" \
  '{env:{CLAWDSTRIKE_SESSION_ID:$session_id},additional_context:$context,continue:true}'

exit 0
