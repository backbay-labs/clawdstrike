#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=scripts/openclaw-plugin-runtime-common.sh
source "$SCRIPT_DIR/openclaw-plugin-runtime-common.sh"

OPENCLAW_RUNTIME_REPO_ROOT="${OPENCLAW_RUNTIME_REPO_ROOT:-$(openclaw_runtime_repo_root)}"
ARTIFACT_DIR="${OPENCLAW_RUNTIME_ARTIFACT_DIR:-$OPENCLAW_RUNTIME_REPO_ROOT/artifacts/openclaw-runtime-blocked-e2e}"
mkdir -p "$ARTIFACT_DIR"

openclaw_runtime_prepare

TARGET_FILE="$OPENCLAW_RUNTIME_ROOT/destructive-target.txt"
IDEMPOTENCY_KEY="blocked-e2e-$(date +%s)"
GATEWAY_LOG="$ARTIFACT_DIR/gateway.log"

openclaw_gateway_call_capture() {
  local raw_file="$1"
  local json_file="$2"
  shift 2

  local raw_output
  local rc=0
  if ! raw_output="$("$@" 2>&1)"; then
    rc=$?
  fi

  printf '%s\n' "$raw_output" >"$raw_file"
  local payload
  payload="$(printf '%s\n' "$raw_output" | openclaw_runtime_json_from_output)"
  if [ -n "$payload" ]; then
    printf '%s\n' "$payload" >"$json_file"
  else
    printf '{}\n' >"$json_file"
  fi

  return "$rc"
}

cleanup() {
  if [ -n "${GATEWAY_PID:-}" ] && kill -0 "$GATEWAY_PID" >/dev/null 2>&1; then
    kill "$GATEWAY_PID" >/dev/null 2>&1 || true
    wait "$GATEWAY_PID" >/dev/null 2>&1 || true
  fi
  openclaw_runtime_cleanup
}
trap cleanup EXIT

cat >"$OPENCLAW_RUNTIME_CONFIG_PATH" <<JSON
{
  "gateway": {
    "mode": "local",
    "bind": "loopback",
    "port": $OPENCLAW_RUNTIME_GATEWAY_PORT,
    "auth": {
      "mode": "token",
      "token": "$OPENCLAW_RUNTIME_GATEWAY_TOKEN"
    }
  },
  "plugins": {
    "enabled": true,
    "slots": {
      "memory": "none"
    },
    "load": {
      "paths": [
        "$OPENCLAW_RUNTIME_PLUGIN_DIR"
      ]
    },
    "entries": {
      "clawdstrike-security": {
        "enabled": true,
        "config": {
          "policy": "clawdstrike:ai-agent",
          "mode": "deterministic"
        }
      }
    }
  },
  "commands": {
    "bash": true
  },
  "tools": {
    "elevated": {
      "enabled": true,
      "allowFrom": {
        "webchat": ["*"]
      }
    }
  }
}
JSON

openclaw gateway run --force >"$GATEWAY_LOG" 2>&1 &
GATEWAY_PID=$!

HEALTH_OK=0
for _ in $(seq 1 30); do
  if openclaw_gateway_call_capture \
    "$ARTIFACT_DIR/health.raw.txt" \
    "$ARTIFACT_DIR/health.json" \
    openclaw gateway call --token "$OPENCLAW_RUNTIME_GATEWAY_TOKEN" --json health; then
    if jq -e '.ok == true' "$ARTIFACT_DIR/health.json" >/dev/null 2>&1; then
      HEALTH_OK=1
      break
    fi
  fi
  sleep 1
done

RAW_PLUGIN_INFO_OUTPUT="$(openclaw plugins info clawdstrike-security --json 2>&1 || true)"
printf '%s\n' "$RAW_PLUGIN_INFO_OUTPUT" >"$ARTIFACT_DIR/plugins-info.raw.txt"
PLUGIN_INFO_PAYLOAD="$(printf '%s\n' "$RAW_PLUGIN_INFO_OUTPUT" | openclaw_runtime_json_from_output)"
if [ -n "$PLUGIN_INFO_PAYLOAD" ]; then
  printf '%s\n' "$PLUGIN_INFO_PAYLOAD" >"$ARTIFACT_DIR/plugins-info.json"
else
  printf '{}\n' >"$ARTIFACT_DIR/plugins-info.json"
fi

CHAT_SEND_RC=0
openclaw_gateway_call_capture \
  "$ARTIFACT_DIR/chat-send.raw.txt" \
  "$ARTIFACT_DIR/chat-send.json" \
  openclaw gateway call \
  --token "$OPENCLAW_RUNTIME_GATEWAY_TOKEN" \
  --json \
  --params "{\"sessionKey\":\"global\",\"message\":\"! rm -rf $TARGET_FILE\",\"idempotencyKey\":\"$IDEMPOTENCY_KEY\"}" \
  chat.send || CHAT_SEND_RC=$?

HISTORY_READY=0
for _ in $(seq 1 20); do
  if openclaw_gateway_call_capture \
    "$ARTIFACT_DIR/chat-history.raw.txt" \
    "$ARTIFACT_DIR/chat-history.json" \
    openclaw gateway call --token "$OPENCLAW_RUNTIME_GATEWAY_TOKEN" --json --params '{"sessionKey":"global","limit":20}' chat.history; then
    if jq -e '(.messages // []) | length > 0' "$ARTIFACT_DIR/chat-history.json" >/dev/null; then
      HISTORY_READY=1
      break
    fi
  fi
  sleep 1
done

ASSISTANT_TEXT="$(jq -r '[.messages[]?.content[]? | select(.type=="text") | .text] | join("\n")' "$ARTIFACT_DIR/chat-history.json" 2>/dev/null || true)"
printf '%s\n' "$ASSISTANT_TEXT" >"$ARTIFACT_DIR/assistant-text.txt"

OPENCLAW_VERSION="$(openclaw_runtime_version)"
PLUGIN_INFO_JSON="$(cat "$ARTIFACT_DIR/plugins-info.json")"

GATEWAY_HEALTH_OK=false
if [ "$HEALTH_OK" -eq 1 ] && jq -e '.ok == true' "$ARTIFACT_DIR/health.json" >/dev/null 2>&1; then
  GATEWAY_HEALTH_OK=true
fi

PLUGIN_INFO_JSON_PRESENT=false
if [ -n "$PLUGIN_INFO_PAYLOAD" ]; then
  PLUGIN_INFO_JSON_PRESENT=true
fi

PLUGIN_STATUS_LOADED=false
if jq -e '.status == "loaded"' "$ARTIFACT_DIR/plugins-info.json" >/dev/null 2>&1; then
  PLUGIN_STATUS_LOADED=true
fi

HOOK_PREFLIGHT_PRESENT=false
if jq -e '(.hookNames // []) | index("clawdstrike:tool-preflight:before-tool-call") != null' "$ARTIFACT_DIR/plugins-info.json" >/dev/null 2>&1; then
  HOOK_PREFLIGHT_PRESENT=true
fi

HOOK_CUA_PRESENT=false
if jq -e '(.hookNames // []) | index("clawdstrike:cua-bridge:before-tool-call") != null' "$ARTIFACT_DIR/plugins-info.json" >/dev/null 2>&1; then
  HOOK_CUA_PRESENT=true
fi

CHAT_SEND_STARTED=false
if [ "$CHAT_SEND_RC" -eq 0 ] && jq -e '.status == "started"' "$ARTIFACT_DIR/chat-send.json" >/dev/null 2>&1; then
  CHAT_SEND_STARTED=true
fi

HISTORY_HAS_MESSAGES=false
if [ "$HISTORY_READY" -eq 1 ] && jq -e '(.messages // []) | length > 0' "$ARTIFACT_DIR/chat-history.json" >/dev/null 2>&1; then
  HISTORY_HAS_MESSAGES=true
fi

ASSISTANT_BLOCK_SIGNAL=false
if printf '%s\n' "$ASSISTANT_TEXT" | grep -Eq 'Approval required|Exec denied|Blocked'; then
  ASSISTANT_BLOCK_SIGNAL=true
fi

TARGET_FILE_ABSENT=true
if [ -e "$TARGET_FILE" ]; then
  TARGET_FILE_ABSENT=false
fi

PASS=true
if [ "$GATEWAY_HEALTH_OK" != "true" ] \
  || [ "$PLUGIN_INFO_JSON_PRESENT" != "true" ] \
  || [ "$PLUGIN_STATUS_LOADED" != "true" ] \
  || [ "$HOOK_PREFLIGHT_PRESENT" != "true" ] \
  || [ "$HOOK_CUA_PRESENT" != "true" ] \
  || [ "$CHAT_SEND_STARTED" != "true" ] \
  || [ "$HISTORY_HAS_MESSAGES" != "true" ] \
  || [ "$ASSISTANT_BLOCK_SIGNAL" != "true" ] \
  || [ "$TARGET_FILE_ABSENT" != "true" ]; then
  PASS=false
fi

jq -n \
  --arg script "openclaw-plugin-blocked-call-e2e" \
  --arg generatedAt "$(date -u +"%Y-%m-%dT%H:%M:%SZ")" \
  --arg openclawVersion "$OPENCLAW_VERSION" \
  --arg artifactDir "$ARTIFACT_DIR" \
  --arg targetFile "$TARGET_FILE" \
  --argjson pluginInfo "$PLUGIN_INFO_JSON" \
  --argjson gatewayHealthOk "$GATEWAY_HEALTH_OK" \
  --argjson pluginInfoJsonPresent "$PLUGIN_INFO_JSON_PRESENT" \
  --argjson pluginStatusLoaded "$PLUGIN_STATUS_LOADED" \
  --argjson hookPreflightPresent "$HOOK_PREFLIGHT_PRESENT" \
  --argjson hookCuaPresent "$HOOK_CUA_PRESENT" \
  --argjson chatSendStarted "$CHAT_SEND_STARTED" \
  --argjson historyHasMessages "$HISTORY_HAS_MESSAGES" \
  --argjson assistantBlockSignal "$ASSISTANT_BLOCK_SIGNAL" \
  --argjson targetFileAbsent "$TARGET_FILE_ABSENT" \
  --argjson pass "$PASS" \
  '{
    script: $script,
    generatedAt: $generatedAt,
    openclawVersion: $openclawVersion,
    artifactDir: $artifactDir,
    targetFile: $targetFile,
    checks: {
      gatewayHealthOk: $gatewayHealthOk,
      pluginInfoJsonPresent: $pluginInfoJsonPresent,
      pluginStatusLoaded: $pluginStatusLoaded,
      hookPreflightPresent: $hookPreflightPresent,
      hookCuaPresent: $hookCuaPresent,
      chatSendStarted: $chatSendStarted,
      historyHasMessages: $historyHasMessages,
      assistantBlockSignal: $assistantBlockSignal,
      targetFileAbsent: $targetFileAbsent
    },
    observed: {
      pluginId: ($pluginInfo.id // null),
      pluginStatus: ($pluginInfo.status // null),
      hookNames: ($pluginInfo.hookNames // [])
    },
    result: (if $pass then "pass" else "fail" end)
  }' >"$ARTIFACT_DIR/summary.json"

if [ "$PASS" != "true" ]; then
  echo "[openclaw-runtime] blocked-call e2e failed; see $ARTIFACT_DIR/summary.json" >&2
  exit 1
fi

echo "[openclaw-runtime] blocked-call e2e passed"
echo "[openclaw-runtime] artifacts: $ARTIFACT_DIR"
