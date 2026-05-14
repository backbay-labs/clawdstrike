#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=scripts/openclaw-plugin-runtime-common.sh
source "$SCRIPT_DIR/openclaw-plugin-runtime-common.sh"

OPENCLAW_RUNTIME_REPO_ROOT="${OPENCLAW_RUNTIME_REPO_ROOT:-$(openclaw_runtime_repo_root)}"
ARTIFACT_DIR="${OPENCLAW_RUNTIME_ARTIFACT_DIR:-$OPENCLAW_RUNTIME_REPO_ROOT/artifacts/openclaw-install-link-smoke}"
mkdir -p "$ARTIFACT_DIR"

openclaw_runtime_prepare
trap openclaw_runtime_cleanup EXIT

LINK_PATH="${OPENCLAW_RUNTIME_LINK_PATH:-$OPENCLAW_RUNTIME_PLUGIN_PACKAGE_DIR/clawdstrike-security.js}"
if [ ! -f "$LINK_PATH" ]; then
  echo "[openclaw-runtime] install-link smoke missing expected plugin entry file: $LINK_PATH" >&2
  exit 1
fi

cat >"$OPENCLAW_RUNTIME_CONFIG_PATH" <<JSON
{
  "plugins": {
    "enabled": true,
    "slots": {
      "memory": "none"
    }
  }
}
JSON

INSTALL_RC=0
if ! openclaw plugins install --link "$LINK_PATH" >"$ARTIFACT_DIR/install.stdout.txt" 2>"$ARTIFACT_DIR/install.stderr.txt"; then
  INSTALL_RC=$?
fi

ENABLE_RC=0
if ! openclaw plugins enable clawdstrike-security >"$ARTIFACT_DIR/enable.stdout.txt" 2>"$ARTIFACT_DIR/enable.stderr.txt"; then
  ENABLE_RC=$?
fi

RAW_PLUGIN_INFO_OUTPUT="$(openclaw plugins info clawdstrike-security --json 2>&1 || true)"
printf '%s\n' "$RAW_PLUGIN_INFO_OUTPUT" >"$ARTIFACT_DIR/plugins-info.raw.txt"
PLUGIN_INFO_PAYLOAD="$(printf '%s\n' "$RAW_PLUGIN_INFO_OUTPUT" | openclaw_runtime_plugin_info_from_output)"
if [ -n "$PLUGIN_INFO_PAYLOAD" ]; then
  printf '%s\n' "$PLUGIN_INFO_PAYLOAD" >"$ARTIFACT_DIR/plugins-info.json"
else
  printf '{}\n' >"$ARTIFACT_DIR/plugins-info.json"
fi

cp "$OPENCLAW_RUNTIME_CONFIG_PATH" "$ARTIFACT_DIR/openclaw.config.json"

EXPECTED_HOOKS_JSON='[
  "clawdstrike:cua-bridge:before-tool-call",
  "clawdstrike:tool-preflight:before-tool-call",
  "clawdstrike:cua-bridge:tool-call",
  "clawdstrike:tool-preflight:tool-call",
  "clawdstrike:tool-guard:tool-result-persist",
  "clawdstrike:agent-bootstrap"
]'
PLUGIN_INFO_ROOT_FILTER='(.plugin // .)'

INSTALL_COMMAND_SUCCEEDED=false
if [ "$INSTALL_RC" -eq 0 ]; then
  INSTALL_COMMAND_SUCCEEDED=true
fi

ENABLE_COMMAND_SUCCEEDED=false
if [ "$ENABLE_RC" -eq 0 ]; then
  ENABLE_COMMAND_SUCCEEDED=true
fi

PLUGIN_INFO_JSON_PRESENT=false
if [ -n "$PLUGIN_INFO_PAYLOAD" ]; then
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

CONFIG_LOAD_PATH_CONTAINS_LINK=false
if jq -e --arg linkPath "$LINK_PATH" '(.plugins.load.paths // []) | index($linkPath) != null' "$ARTIFACT_DIR/openclaw.config.json" >/dev/null 2>&1; then
  CONFIG_LOAD_PATH_CONTAINS_LINK=true
fi

CONFIG_ENTRY_ENABLED=false
if jq -e '.plugins.entries["clawdstrike-security"].enabled == true' "$ARTIFACT_DIR/openclaw.config.json" >/dev/null 2>&1; then
  CONFIG_ENTRY_ENABLED=true
fi

MISSING_HOOKS_JSON="$(jq -c --argjson expected "$EXPECTED_HOOKS_JSON" '($expected - ((.plugin // .).hookNames // []))' "$ARTIFACT_DIR/plugins-info.json")"
ALL_EXPECTED_HOOKS_PRESENT=false
if [ "$MISSING_HOOKS_JSON" = "[]" ]; then
  ALL_EXPECTED_HOOKS_PRESENT=true
fi

ID_MISMATCH_WARNING_PRESENT=false
if printf '%s\n' "$RAW_PLUGIN_INFO_OUTPUT" | grep -Eqi 'plugin id mismatch'; then
  ID_MISMATCH_WARNING_PRESENT=true
fi

OPENCLAW_VERSION="$(openclaw_runtime_version)"
PLUGIN_INFO_JSON="$(cat "$ARTIFACT_DIR/plugins-info.json")"

PASS=true
if [ "$INSTALL_COMMAND_SUCCEEDED" != "true" ] \
  || [ "$ENABLE_COMMAND_SUCCEEDED" != "true" ] \
  || [ "$PLUGIN_INFO_JSON_PRESENT" != "true" ] \
  || [ "$PLUGIN_ID_MATCHES" != "true" ] \
  || [ "$PLUGIN_STATUS_LOADED" != "true" ] \
  || [ "$CONFIG_LOAD_PATH_CONTAINS_LINK" != "true" ] \
  || [ "$CONFIG_ENTRY_ENABLED" != "true" ] \
  || [ "$ALL_EXPECTED_HOOKS_PRESENT" != "true" ] \
  || [ "$ID_MISMATCH_WARNING_PRESENT" = "true" ]; then
  PASS=false
fi

jq -n \
  --arg script "openclaw-plugin-install-link-smoke" \
  --arg generatedAt "$(date -u +"%Y-%m-%dT%H:%M:%SZ")" \
  --arg openclawVersion "$OPENCLAW_VERSION" \
  --arg artifactDir "$ARTIFACT_DIR" \
  --arg linkPath "$LINK_PATH" \
  --argjson pluginInfo "$PLUGIN_INFO_JSON" \
  --argjson installCommandSucceeded "$INSTALL_COMMAND_SUCCEEDED" \
  --argjson enableCommandSucceeded "$ENABLE_COMMAND_SUCCEEDED" \
  --argjson pluginInfoJsonPresent "$PLUGIN_INFO_JSON_PRESENT" \
  --argjson pluginIdMatches "$PLUGIN_ID_MATCHES" \
  --argjson pluginStatusLoaded "$PLUGIN_STATUS_LOADED" \
  --argjson configLoadPathContainsLink "$CONFIG_LOAD_PATH_CONTAINS_LINK" \
  --argjson configEntryEnabled "$CONFIG_ENTRY_ENABLED" \
  --argjson allExpectedHooksPresent "$ALL_EXPECTED_HOOKS_PRESENT" \
  --argjson idMismatchWarningPresent "$ID_MISMATCH_WARNING_PRESENT" \
  --argjson missingHooks "$MISSING_HOOKS_JSON" \
  --argjson pass "$PASS" \
  'def pluginRoot: ($pluginInfo.plugin // $pluginInfo); {
    script: $script,
    generatedAt: $generatedAt,
    openclawVersion: $openclawVersion,
    artifactDir: $artifactDir,
    linkPath: $linkPath,
    checks: {
      installCommandSucceeded: $installCommandSucceeded,
      enableCommandSucceeded: $enableCommandSucceeded,
      pluginInfoJsonPresent: $pluginInfoJsonPresent,
      pluginIdMatches: $pluginIdMatches,
      pluginStatusLoaded: $pluginStatusLoaded,
      configLoadPathContainsLink: $configLoadPathContainsLink,
      configEntryEnabled: $configEntryEnabled,
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
  echo "[openclaw-runtime] install-link smoke failed; see $ARTIFACT_DIR/summary.json" >&2
  exit 1
fi

echo "[openclaw-runtime] install-link smoke passed"
echo "[openclaw-runtime] artifacts: $ARTIFACT_DIR"
