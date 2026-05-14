#!/usr/bin/env bash
set -euo pipefail

openclaw_runtime_require_cmd() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "[openclaw-runtime] missing required command: $1" >&2
    exit 1
  fi
}

openclaw_runtime_repo_root() {
  local script_dir
  script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
  cd "$script_dir/.."
  pwd
}

openclaw_runtime_pick_port() {
  python3 - <<'PY'
import socket
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.bind(("127.0.0.1", 0))
print(s.getsockname()[1])
s.close()
PY
}

openclaw_runtime_prepare() {
  openclaw_runtime_require_cmd openclaw
  openclaw_runtime_require_cmd jq
  openclaw_runtime_require_cmd npm
  openclaw_runtime_require_cmd python3

  OPENCLAW_RUNTIME_REPO_ROOT="${OPENCLAW_RUNTIME_REPO_ROOT:-$(openclaw_runtime_repo_root)}"
  OPENCLAW_RUNTIME_PLUGIN_PACKAGE_DIR="${OPENCLAW_RUNTIME_PLUGIN_PACKAGE_DIR:-$OPENCLAW_RUNTIME_REPO_ROOT/packages/adapters/clawdstrike-openclaw}"
  OPENCLAW_RUNTIME_ROOT="${OPENCLAW_RUNTIME_ROOT:-$(mktemp -d "${TMPDIR:-/tmp}/openclaw-runtime.XXXXXX")}"
  OPENCLAW_RUNTIME_HOME="${OPENCLAW_RUNTIME_HOME:-$OPENCLAW_RUNTIME_ROOT/home}"
  OPENCLAW_RUNTIME_STATE_DIR="${OPENCLAW_RUNTIME_STATE_DIR:-$OPENCLAW_RUNTIME_ROOT/state}"
  OPENCLAW_RUNTIME_PLUGIN_DIR="${OPENCLAW_RUNTIME_PLUGIN_DIR:-$OPENCLAW_RUNTIME_ROOT/plugins/clawdstrike-security}"
  OPENCLAW_RUNTIME_CONFIG_PATH="${OPENCLAW_RUNTIME_CONFIG_PATH:-$OPENCLAW_RUNTIME_ROOT/openclaw.json}"
  OPENCLAW_RUNTIME_GATEWAY_PORT="${OPENCLAW_RUNTIME_GATEWAY_PORT:-$(openclaw_runtime_pick_port)}"
  OPENCLAW_RUNTIME_GATEWAY_TOKEN="${OPENCLAW_RUNTIME_GATEWAY_TOKEN:-runtime-smoke-token}"

  if [ ! -d "$OPENCLAW_RUNTIME_PLUGIN_PACKAGE_DIR/dist" ]; then
    echo "[openclaw-runtime] expected built plugin dist at $OPENCLAW_RUNTIME_PLUGIN_PACKAGE_DIR/dist" >&2
    echo "[openclaw-runtime] run: npm --prefix packages/adapters/clawdstrike-openclaw run build" >&2
    exit 1
  fi
  if [ ! -d "$OPENCLAW_RUNTIME_PLUGIN_PACKAGE_DIR/node_modules" ] \
    || [ -z "$(find "$OPENCLAW_RUNTIME_PLUGIN_PACKAGE_DIR/node_modules" -mindepth 1 -maxdepth 1 -print -quit 2>/dev/null)" ] \
    || [ ! -f "$OPENCLAW_RUNTIME_PLUGIN_PACKAGE_DIR/node_modules/@clawdstrike/adapter-core/package.json" ] \
    || [ ! -f "$OPENCLAW_RUNTIME_PLUGIN_PACKAGE_DIR/node_modules/@clawdstrike/policy/package.json" ]; then
    echo "[openclaw-runtime] plugin dependencies missing; restoring with npm install" >&2
    npm --prefix "$OPENCLAW_RUNTIME_PLUGIN_PACKAGE_DIR" install
  fi
  if [ ! -d "$OPENCLAW_RUNTIME_PLUGIN_PACKAGE_DIR/node_modules" ]; then
    echo "[openclaw-runtime] expected plugin dependencies at $OPENCLAW_RUNTIME_PLUGIN_PACKAGE_DIR/node_modules" >&2
    echo "[openclaw-runtime] run: npm --prefix packages/adapters/clawdstrike-openclaw ci" >&2
    exit 1
  fi

  if [ ! -f "$OPENCLAW_RUNTIME_PLUGIN_PACKAGE_DIR/node_modules/@clawdstrike/policy/dist/index.js" ] \
    || [ ! -f "$OPENCLAW_RUNTIME_PLUGIN_PACKAGE_DIR/node_modules/@clawdstrike/adapter-core/dist/index.js" ]; then
    echo "[openclaw-runtime] plugin local dependency dist artifacts missing; building local deps" >&2
    npm --prefix "$OPENCLAW_RUNTIME_PLUGIN_PACKAGE_DIR" run build:local-deps
  fi

  if [ ! -f "$OPENCLAW_RUNTIME_PLUGIN_PACKAGE_DIR/node_modules/@clawdstrike/policy/dist/index.js" ] \
    || [ ! -f "$OPENCLAW_RUNTIME_PLUGIN_PACKAGE_DIR/node_modules/@clawdstrike/adapter-core/dist/index.js" ]; then
    echo "[openclaw-runtime] local dependency dist artifacts are still missing after build" >&2
    echo "[openclaw-runtime] expected: @clawdstrike/policy/dist/index.js and @clawdstrike/adapter-core/dist/index.js" >&2
    exit 1
  fi

  # Workspace installs may hoist transitive deps (for example js-yaml used by
  # @clawdstrike/policy) to the repo root. Ensure they are materialized in the
  # plugin package tree before copying into the isolated runtime directory.
  if [ ! -f "$OPENCLAW_RUNTIME_PLUGIN_PACKAGE_DIR/node_modules/js-yaml/package.json" ] \
    || [ ! -f "$OPENCLAW_RUNTIME_PLUGIN_PACKAGE_DIR/node_modules/lru-cache/package.json" ]; then
    echo "[openclaw-runtime] materializing plugin transitive deps (nested install)" >&2
    npm --prefix "$OPENCLAW_RUNTIME_PLUGIN_PACKAGE_DIR" install --install-strategy=nested --omit=dev --ignore-scripts
  fi

  mkdir -p "$OPENCLAW_RUNTIME_HOME" "$OPENCLAW_RUNTIME_STATE_DIR" "$OPENCLAW_RUNTIME_PLUGIN_DIR"

  cp "$OPENCLAW_RUNTIME_PLUGIN_PACKAGE_DIR/openclaw.plugin.json" "$OPENCLAW_RUNTIME_PLUGIN_DIR/openclaw.plugin.json"
  cp -R "$OPENCLAW_RUNTIME_PLUGIN_PACKAGE_DIR/dist" "$OPENCLAW_RUNTIME_PLUGIN_DIR/dist"
  cp -R "$OPENCLAW_RUNTIME_PLUGIN_PACKAGE_DIR/rulesets" "$OPENCLAW_RUNTIME_PLUGIN_DIR/rulesets"
  cp -RL "$OPENCLAW_RUNTIME_PLUGIN_PACKAGE_DIR/node_modules" "$OPENCLAW_RUNTIME_PLUGIN_DIR/node_modules"

  cat >"$OPENCLAW_RUNTIME_PLUGIN_DIR/index.js" <<'JS'
export { default } from './dist/plugin.js';
JS

  export HOME="$OPENCLAW_RUNTIME_HOME"
  export OPENCLAW_STATE_DIR="$OPENCLAW_RUNTIME_STATE_DIR"
  export OPENCLAW_CONFIG_PATH="$OPENCLAW_RUNTIME_CONFIG_PATH"
}

openclaw_runtime_cleanup() {
  if [ "${OPENCLAW_RUNTIME_KEEP_STATE:-0}" = "1" ]; then
    echo "[openclaw-runtime] keeping runtime state at $OPENCLAW_RUNTIME_ROOT"
    return
  fi
  rm -rf "$OPENCLAW_RUNTIME_ROOT"
}

openclaw_runtime_json_from_output() {
  python3 -c '
import json
import re
import sys

text = sys.stdin.read()
text = re.sub(r"\x1B\[[0-9;?]*[ -/]*[@-~]", "", text)
decoder = json.JSONDecoder()

for i, ch in enumerate(text):
    if ch not in "{[":
        continue
    try:
        payload, _ = decoder.raw_decode(text[i:])
    except Exception:
        continue
    json.dump(payload, sys.stdout)
    sys.stdout.write("\n")
    break
'
}

openclaw_runtime_plugin_info_from_output() {
  openclaw_runtime_json_from_output | jq -c '
    if type == "object" and (.plugin? | type == "object") then
      .plugin
    else
      .
    end
  ' 2>/dev/null || true
}

openclaw_runtime_version() {
  openclaw --version 2>&1 | tail -n 1 | tr -d '\r'
}
