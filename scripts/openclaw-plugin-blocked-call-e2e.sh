#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=scripts/openclaw-plugin-runtime-common.sh
source "$SCRIPT_DIR/openclaw-plugin-runtime-common.sh"

openclaw_runtime_prepare

ARTIFACT_DIR="${OPENCLAW_RUNTIME_ARTIFACT_DIR:-$OPENCLAW_RUNTIME_REPO_ROOT/artifacts/openclaw-runtime-blocked-e2e}"
mkdir -p "$ARTIFACT_DIR"

TARGET_FILE="$OPENCLAW_RUNTIME_ROOT/destructive-target.txt"
IDEMPOTENCY_KEY="blocked-e2e-$(date +%s)"
GATEWAY_LOG="$ARTIFACT_DIR/gateway.log"

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
  if openclaw gateway call --token "$OPENCLAW_RUNTIME_GATEWAY_TOKEN" --json health >"$ARTIFACT_DIR/health.json" 2>"$ARTIFACT_DIR/health.err"; then
    HEALTH_OK=1
    break
  fi
  sleep 1
done
if [ "$HEALTH_OK" -ne 1 ]; then
  echo "[openclaw-runtime] gateway did not become healthy" >&2
  exit 1
fi

openclaw gateway call \
  --token "$OPENCLAW_RUNTIME_GATEWAY_TOKEN" \
  --json \
  --params "{\"sessionKey\":\"global\",\"message\":\"! rm -rf $TARGET_FILE\",\"idempotencyKey\":\"$IDEMPOTENCY_KEY\"}" \
  chat.send >"$ARTIFACT_DIR/chat-send.json"

HISTORY_READY=0
for _ in $(seq 1 20); do
  if openclaw gateway call --token "$OPENCLAW_RUNTIME_GATEWAY_TOKEN" --json --params '{"sessionKey":"global","limit":20}' chat.history >"$ARTIFACT_DIR/chat-history.json" 2>"$ARTIFACT_DIR/chat-history.err"; then
    if jq -e '(.messages // []) | length > 0' "$ARTIFACT_DIR/chat-history.json" >/dev/null; then
      HISTORY_READY=1
      break
    fi
  fi
  sleep 1
done
if [ "$HISTORY_READY" -ne 1 ]; then
  echo "[openclaw-runtime] timed out waiting for chat history response" >&2
  exit 1
fi

ASSISTANT_TEXT="$(jq -r '[.messages[]?.content[]? | select(.type=="text") | .text] | join("\n")' "$ARTIFACT_DIR/chat-history.json")"
printf '%s\n' "$ASSISTANT_TEXT" >"$ARTIFACT_DIR/assistant-text.txt"

if ! printf '%s\n' "$ASSISTANT_TEXT" | rg -q 'Approval required|Exec denied|Blocked'; then
  echo "[openclaw-runtime] expected a blocked/denied message for destructive command" >&2
  exit 1
fi

if [ -e "$TARGET_FILE" ]; then
  echo "[openclaw-runtime] destructive target was created unexpectedly: $TARGET_FILE" >&2
  exit 1
fi

echo "[openclaw-runtime] blocked-call e2e passed"
echo "[openclaw-runtime] artifacts: $ARTIFACT_DIR"
