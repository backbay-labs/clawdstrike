#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=scripts/openclaw-plugin-runtime-common.sh
source "$SCRIPT_DIR/openclaw-plugin-runtime-common.sh"

OPENCLAW_RUNTIME_REPO_ROOT="${OPENCLAW_RUNTIME_REPO_ROOT:-$(openclaw_runtime_repo_root)}"
ARTIFACT_DIR="${OPENCLAW_RUNTIME_ARTIFACT_DIR:-$OPENCLAW_RUNTIME_REPO_ROOT/artifacts/openclaw-runtime-smoke}"
mkdir -p "$ARTIFACT_DIR"

openclaw_runtime_prepare
trap openclaw_runtime_cleanup EXIT

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

RAW_OUTPUT="$(openclaw plugins info clawdstrike-security --json 2>&1 || true)"
printf '%s\n' "$RAW_OUTPUT" >"$ARTIFACT_DIR/plugins-info.raw.txt"

JSON_PAYLOAD="$(printf '%s\n' "$RAW_OUTPUT" | openclaw_runtime_plugin_info_from_output)"
if [ -n "$JSON_PAYLOAD" ]; then
  printf '%s\n' "$JSON_PAYLOAD" >"$ARTIFACT_DIR/plugins-info.json"
else
  printf '{}\n' >"$ARTIFACT_DIR/plugins-info.json"
fi

EXPECTED_HOOKS_JSON='[
  "clawdstrike:cua-bridge:before-tool-call",
  "clawdstrike:tool-preflight:before-tool-call",
  "clawdstrike:cua-bridge:tool-call",
  "clawdstrike:tool-preflight:tool-call",
  "clawdstrike:tool-guard:tool-result-persist",
  "clawdstrike:agent-bootstrap"
]'
PLUGIN_INFO_ROOT_FILTER='(.plugin // .)'

PLUGIN_INFO_JSON_PRESENT=false
if [ -n "$JSON_PAYLOAD" ]; then
  PLUGIN_INFO_JSON_PRESENT=true
fi

PLUGIN_ID_MATCHES=false
if jq -e "$PLUGIN_INFO_ROOT_FILTER | .id == \"clawdstrike-security\"" "$ARTIFACT_DIR/plugins-info.json" >/dev/null 2>&1; then
  PLUGIN_ID_MATCHES=true
fi

PLUGIN_STATUS_LOADED=false
if jq -e "$PLUGIN_INFO_ROOT_FILTER | .status == \"loaded\"" "$ARTIFACT_DIR/plugins-info.json" >/dev/null 2>&1; then
  PLUGIN_STATUS_LOADED=true
fi

MISSING_HOOKS_JSON="$(jq -c --argjson expected "$EXPECTED_HOOKS_JSON" '($expected - ((.plugin // .).hookNames // []))' "$ARTIFACT_DIR/plugins-info.json")"
ALL_EXPECTED_HOOKS_PRESENT=false
if [ "$MISSING_HOOKS_JSON" = "[]" ]; then
  ALL_EXPECTED_HOOKS_PRESENT=true
fi

ID_MISMATCH_WARNING_PRESENT=false
if printf '%s\n' "$RAW_OUTPUT" | grep -Eqi 'plugin id mismatch'; then
  ID_MISMATCH_WARNING_PRESENT=true
fi

OPENCLAW_VERSION="$(openclaw_runtime_version)"
PLUGIN_INFO_JSON="$(cat "$ARTIFACT_DIR/plugins-info.json")"

PASS=true
if [ "$PLUGIN_INFO_JSON_PRESENT" != "true" ] \
  || [ "$PLUGIN_ID_MATCHES" != "true" ] \
  || [ "$PLUGIN_STATUS_LOADED" != "true" ] \
  || [ "$ALL_EXPECTED_HOOKS_PRESENT" != "true" ] \
  || [ "$ID_MISMATCH_WARNING_PRESENT" = "true" ]; then
  PASS=false
fi

jq -n \
  --arg script "openclaw-plugin-runtime-smoke" \
  --arg generatedAt "$(date -u +"%Y-%m-%dT%H:%M:%SZ")" \
  --arg openclawVersion "$OPENCLAW_VERSION" \
  --arg artifactDir "$ARTIFACT_DIR" \
  --argjson pluginInfo "$PLUGIN_INFO_JSON" \
  --argjson missingHooks "$MISSING_HOOKS_JSON" \
  --argjson pluginInfoJsonPresent "$PLUGIN_INFO_JSON_PRESENT" \
  --argjson pluginIdMatches "$PLUGIN_ID_MATCHES" \
  --argjson pluginStatusLoaded "$PLUGIN_STATUS_LOADED" \
  --argjson allExpectedHooksPresent "$ALL_EXPECTED_HOOKS_PRESENT" \
  --argjson idMismatchWarningPresent "$ID_MISMATCH_WARNING_PRESENT" \
  --argjson pass "$PASS" \
  'def pluginRoot: ($pluginInfo.plugin // $pluginInfo); {
    script: $script,
    generatedAt: $generatedAt,
    openclawVersion: $openclawVersion,
    artifactDir: $artifactDir,
    checks: {
      pluginInfoJsonPresent: $pluginInfoJsonPresent,
      pluginIdMatches: $pluginIdMatches,
      pluginStatusLoaded: $pluginStatusLoaded,
      allExpectedHooksPresent: $allExpectedHooksPresent,
      idMismatchWarningPresent: $idMismatchWarningPresent
    },
    observed: {
      pluginId: (pluginRoot.id // null),
      status: (pluginRoot.status // null),
      hookNames: (pluginRoot.hookNames // []),
      missingHooks: $missingHooks
    },
    result: (if $pass then "pass" else "fail" end)
  }' >"$ARTIFACT_DIR/summary.json"

if [ "$PASS" != "true" ]; then
  echo "[openclaw-runtime] runtime smoke failed; see $ARTIFACT_DIR/summary.json" >&2
  exit 1
fi

echo "[openclaw-runtime] runtime smoke passed"
echo "[openclaw-runtime] artifacts: $ARTIFACT_DIR"
