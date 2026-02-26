#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=scripts/openclaw-plugin-runtime-common.sh
source "$SCRIPT_DIR/openclaw-plugin-runtime-common.sh"

openclaw_runtime_prepare
trap openclaw_runtime_cleanup EXIT

ARTIFACT_DIR="${OPENCLAW_RUNTIME_ARTIFACT_DIR:-$OPENCLAW_RUNTIME_REPO_ROOT/artifacts/openclaw-runtime-smoke}"
mkdir -p "$ARTIFACT_DIR"

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
  }
}
JSON

RAW_OUTPUT="$(openclaw plugins info clawdstrike-security --json 2>&1)"
printf '%s\n' "$RAW_OUTPUT" >"$ARTIFACT_DIR/plugins-info.raw.txt"

if printf '%s\n' "$RAW_OUTPUT" | rg -q 'plugin id mismatch'; then
  echo "[openclaw-runtime] unexpected plugin id mismatch warning in plugin info output" >&2
  exit 1
fi

JSON_PAYLOAD="$(printf '%s\n' "$RAW_OUTPUT" | openclaw_runtime_json_from_output)"
if [ -z "$JSON_PAYLOAD" ]; then
  echo "[openclaw-runtime] failed to extract JSON from plugin info output" >&2
  exit 1
fi

printf '%s\n' "$JSON_PAYLOAD" >"$ARTIFACT_DIR/plugins-info.json"

jq -e '.id == "clawdstrike-security"' "$ARTIFACT_DIR/plugins-info.json" >/dev/null
jq -e '.status == "loaded"' "$ARTIFACT_DIR/plugins-info.json" >/dev/null

EXPECTED_HOOKS=(
  "clawdstrike:cua-bridge:before-tool-call"
  "clawdstrike:tool-preflight:before-tool-call"
  "clawdstrike:cua-bridge:tool-call"
  "clawdstrike:tool-preflight:tool-call"
  "clawdstrike:tool-guard:tool-result-persist"
  "clawdstrike:agent-bootstrap"
)

for hook_name in "${EXPECTED_HOOKS[@]}"; do
  jq -e --arg hook "$hook_name" '(.hookNames // []) | index($hook) != null' "$ARTIFACT_DIR/plugins-info.json" >/dev/null
done

echo "[openclaw-runtime] runtime smoke passed"
echo "[openclaw-runtime] artifacts: $ARTIFACT_DIR"
