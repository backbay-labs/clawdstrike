#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'USAGE'
OpenClaw + Agent smoke test harness.

Usage:
  scripts/openclaw-agent-smoke.sh [options]

Options:
  --gateway-url URL          Gateway WebSocket URL (default: ws://127.0.0.1:18789)
  --gateway-token TOKEN      Gateway token to store in the agent gateway config
  --device-token TOKEN       Optional OpenClaw device token
  --gateway-id ID            Gateway id used for the smoke test
  --gateway-label LABEL      Gateway label used for the smoke test
  --start-local-gateway      Start and manage a local openclaw gateway process
  --openclaw-bin PATH        OpenClaw CLI binary (default: openclaw)
  --no-reconnect-check       Skip reconnect-after-restart validation
  --help                     Show this message

Environment:
  XDG_CONFIG_HOME            Optional config override (default: $HOME/.config)
USAGE
}

log() {
  printf '[smoke] %s\n' "$*"
}

die() {
  printf '[smoke] ERROR: %s\n' "$*" >&2
  exit 1
}

require_cmd() {
  if ! command -v "$1" >/dev/null 2>&1; then
    die "Missing required command: $1"
  fi
}

GATEWAY_URL="ws://127.0.0.1:18789"
GATEWAY_TOKEN=""
DEVICE_TOKEN=""
GATEWAY_ID="smoke-gateway-$(date +%s)"
GATEWAY_LABEL="Smoke Gateway"
START_LOCAL_GATEWAY=0
OPENCLAW_BIN="openclaw"
RUN_RECONNECT_CHECK=1

while (($# > 0)); do
  case "$1" in
    --gateway-url)
      GATEWAY_URL="${2:-}"
      shift 2
      ;;
    --gateway-token)
      GATEWAY_TOKEN="${2:-}"
      shift 2
      ;;
    --device-token)
      DEVICE_TOKEN="${2:-}"
      shift 2
      ;;
    --gateway-id)
      GATEWAY_ID="${2:-}"
      shift 2
      ;;
    --gateway-label)
      GATEWAY_LABEL="${2:-}"
      shift 2
      ;;
    --start-local-gateway)
      START_LOCAL_GATEWAY=1
      shift
      ;;
    --openclaw-bin)
      OPENCLAW_BIN="${2:-}"
      shift 2
      ;;
    --no-reconnect-check)
      RUN_RECONNECT_CHECK=0
      shift
      ;;
    --help|-h)
      usage
      exit 0
      ;;
    *)
      die "Unknown argument: $1"
      ;;
  esac
done

require_cmd curl
require_cmd jq

if [[ "$START_LOCAL_GATEWAY" -eq 1 ]]; then
  require_cmd "$OPENCLAW_BIN"
  if [[ -z "$GATEWAY_TOKEN" ]]; then
    GATEWAY_TOKEN="${OPENCLAW_GATEWAY_TOKEN:-smoke-token}"
  fi
fi

CONFIG_DIR="${XDG_CONFIG_HOME:-$HOME/.config}/clawdstrike"
AGENT_SETTINGS="${CONFIG_DIR}/agent.json"
AGENT_TOKEN_FILE="${CONFIG_DIR}/agent-local-token"
AGENT_PORT=9878
AGENT_TOKEN=""
API_BASE=""
GATEWAY_PID=""
GATEWAY_LOG=""
ORIGINAL_ENFORCED=""

if [[ -f "$AGENT_SETTINGS" ]]; then
  AGENT_PORT="$(jq -r '.agent_api_port // 9878' "$AGENT_SETTINGS" 2>/dev/null || echo 9878)"
fi
if [[ -f "$AGENT_TOKEN_FILE" ]]; then
  AGENT_TOKEN="$(tr -d '[:space:]' < "$AGENT_TOKEN_FILE")"
fi
if [[ -z "$AGENT_TOKEN" ]]; then
  die "Agent token missing. Start the agent first to create ${AGENT_TOKEN_FILE}."
fi
API_BASE="http://127.0.0.1:${AGENT_PORT}"

api_health() {
  curl -fsS "${API_BASE}/api/v1/agent/health" >/dev/null
}

api_get() {
  local path="$1"
  curl -fsS \
    -H "Authorization: Bearer ${AGENT_TOKEN}" \
    "${API_BASE}${path}"
}

api_post() {
  local path="$1"
  local body="$2"
  curl -fsS \
    -X POST \
    -H "Authorization: Bearer ${AGENT_TOKEN}" \
    -H "Content-Type: application/json" \
    -d "$body" \
    "${API_BASE}${path}"
}

api_put() {
  local path="$1"
  local body="$2"
  curl -fsS \
    -X PUT \
    -H "Authorization: Bearer ${AGENT_TOKEN}" \
    -H "Content-Type: application/json" \
    -d "$body" \
    "${API_BASE}${path}"
}

api_delete() {
  local path="$1"
  curl -fsS \
    -X DELETE \
    -H "Authorization: Bearer ${AGENT_TOKEN}" \
    "${API_BASE}${path}" >/dev/null
}

wait_for_gateway_status() {
  local expected="$1"
  local attempts="${2:-40}"
  local delay_seconds="${3:-0.5}"

  local current="missing"
  local i
  for ((i = 1; i <= attempts; i++)); do
    current="$(
      api_get "/api/v1/openclaw/gateways" |
        jq -r --arg id "$GATEWAY_ID" '.gateways[] | select(.id == $id) | .runtime.status // "missing"'
    )"
    if [[ "$current" == "$expected" ]]; then
      return 0
    fi
    sleep "$delay_seconds"
  done

  die "Gateway ${GATEWAY_ID} status did not reach '${expected}' (last status: ${current})"
}

start_local_gateway() {
  GATEWAY_LOG="$(mktemp -t openclaw-gateway-smoke.XXXXXX.log)"
  log "Starting local gateway with ${OPENCLAW_BIN}; logs: ${GATEWAY_LOG}"
  OPENCLAW_GATEWAY_TOKEN="${GATEWAY_TOKEN}" "${OPENCLAW_BIN}" gateway run --force >"${GATEWAY_LOG}" 2>&1 &
  GATEWAY_PID="$!"
  sleep 2
}

stop_local_gateway() {
  if [[ -n "$GATEWAY_PID" ]] && kill -0 "$GATEWAY_PID" >/dev/null 2>&1; then
    kill "$GATEWAY_PID" >/dev/null 2>&1 || true
    wait "$GATEWAY_PID" >/dev/null 2>&1 || true
  fi
  GATEWAY_PID=""
}

cleanup() {
  if [[ -n "${ORIGINAL_ENFORCED}" ]]; then
    api_put "/api/v1/agent/settings" "$(jq -cn --argjson enabled "$ORIGINAL_ENFORCED" '{enabled: $enabled}')" >/dev/null 2>&1 || true
  fi

  api_post "/api/v1/openclaw/gateways/${GATEWAY_ID}/disconnect" '{}' >/dev/null 2>&1 || true
  api_delete "/api/v1/openclaw/gateways/${GATEWAY_ID}" || true

  stop_local_gateway
}

trap cleanup EXIT INT TERM

log "Validating agent local API health at ${API_BASE}"
api_health

if [[ "$START_LOCAL_GATEWAY" -eq 1 ]]; then
  start_local_gateway
fi

log "Capturing original enforcement mode"
ORIGINAL_ENFORCED="$(api_get "/api/v1/agent/settings" | jq -r '.enabled')"
if [[ "$ORIGINAL_ENFORCED" != "true" ]] && [[ "$ORIGINAL_ENFORCED" != "false" ]]; then
  die "Failed to determine current enforcement mode"
fi

log "Checking enforcement-disabled bypass semantics"
api_put "/api/v1/agent/settings" '{"enabled":false}' >/dev/null
POLICY_BYPASS="$(
  api_post "/api/v1/agent/policy-check" "$(jq -cn '{action_type:"exec",target:"echo smoke"}')"
)"
if [[ "$(echo "$POLICY_BYPASS" | jq -r '.allowed')" != "true" ]]; then
  die "Expected policy_check allowed=true while enforcement disabled"
fi
if [[ "$(echo "$POLICY_BYPASS" | jq -r '.guard // ""')" != "enforcement_disabled" ]]; then
  die "Expected policy_check guard=enforcement_disabled while enforcement disabled"
fi
api_put "/api/v1/agent/settings" "$(jq -cn --argjson enabled "$ORIGINAL_ENFORCED" '{enabled: $enabled}')" >/dev/null
ORIGINAL_ENFORCED=""

log "Creating/overwriting smoke gateway config: ${GATEWAY_ID}"
CREATE_GATEWAY_PAYLOAD="$(
  jq -cn \
    --arg id "$GATEWAY_ID" \
    --arg label "$GATEWAY_LABEL" \
    --arg gateway_url "$GATEWAY_URL" \
    --arg token "$GATEWAY_TOKEN" \
    --arg device_token "$DEVICE_TOKEN" \
    '{
      id: $id,
      label: $label,
      gateway_url: $gateway_url,
      token: (if $token == "" then null else $token end),
      device_token: (if $device_token == "" then null else $device_token end)
    }'
)"
api_post "/api/v1/openclaw/gateways" "$CREATE_GATEWAY_PAYLOAD" >/dev/null

log "Connecting gateway via agent-owned transport"
api_post "/api/v1/openclaw/gateways/${GATEWAY_ID}/connect" '{}' >/dev/null
wait_for_gateway_status "connected" 50 0.4

log "Issuing gateway request relay: node.list"
NODE_LIST_RESPONSE="$(
  api_post "/api/v1/openclaw/request" "$(jq -cn --arg gateway_id "$GATEWAY_ID" '{gateway_id:$gateway_id,method:"node.list",timeout_ms:10000}')"
)"
echo "$NODE_LIST_RESPONSE" | jq '.' >/dev/null
log "node.list relay succeeded"

if [[ "$RUN_RECONNECT_CHECK" -eq 1 ]] && [[ "$START_LOCAL_GATEWAY" -eq 1 ]]; then
  log "Restarting local gateway to validate reconnect behavior"
  stop_local_gateway
  sleep 1
  start_local_gateway
  wait_for_gateway_status "connected" 80 0.5
  log "Reconnect validated"
else
  log "Reconnect validation skipped (enable with --start-local-gateway)"
fi

log "Disconnecting and deleting smoke gateway"
api_post "/api/v1/openclaw/gateways/${GATEWAY_ID}/disconnect" '{}' >/dev/null
api_delete "/api/v1/openclaw/gateways/${GATEWAY_ID}"

log "Smoke test complete"
