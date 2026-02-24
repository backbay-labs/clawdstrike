#!/usr/bin/env bash
set -euo pipefail

# run.sh - Automated runner for the multi-framework red/blue swarm demo
# Builds hushd, builds TS adapter packages, starts hushd, installs deps,
# runs the demo, cleans up.

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/../.." && pwd)"
HUSHD_PORT="${HUSHD_PORT:-9876}"
HUSHD_RULESET="${HUSHD_RULESET:-strict}"
HUSHD_PID=""
VENV_DIR="$SCRIPT_DIR/.venv"

cleanup() {
  if [[ -n "$HUSHD_PID" ]]; then
    echo "[cleanup] Stopping hushd (PID $HUSHD_PID)..."
    kill "$HUSHD_PID" 2>/dev/null || true
    wait "$HUSHD_PID" 2>/dev/null || true
  fi
}
trap cleanup EXIT

describe_pid() {
  local pid="$1"
  ps -p "$pid" -o command= 2>/dev/null || true
}

port_listeners() {
  lsof -ti :"$HUSHD_PORT" 2>/dev/null || true
}

kill_hushd_on_port() {
  local pids
  pids="$(port_listeners)"
  if [[ -z "$pids" ]]; then
    return 0
  fi

  echo "[cleanup] Port $HUSHD_PORT is in use by:"
  for pid in $pids; do
    local cmd
    cmd="$(describe_pid "$pid")"
    echo "  - PID $pid: $cmd"
  done

  local killed_any=false
  for pid in $pids; do
    local cmd
    cmd="$(describe_pid "$pid")"
    if [[ "$cmd" == *"/hushd"* || "$cmd" == *" hushd "* ]]; then
      echo "[cleanup] Stopping hushd on port $HUSHD_PORT (PID $pid)..."
      kill "$pid" 2>/dev/null || true
      killed_any=true
    fi
  done

  if [[ "$killed_any" == true ]]; then
    # Wait briefly for the port to be released.
    for _ in $(seq 1 20); do
      sleep 0.2
      if ! lsof -ti :"$HUSHD_PORT" >/dev/null 2>&1; then
        return 0
      fi
    done
  fi

  if lsof -ti :"$HUSHD_PORT" >/dev/null 2>&1; then
    echo "[error] Port $HUSHD_PORT is still in use."
    echo "        Stop the process above, or run with a different port:"
    echo "        HUSHD_PORT=19876 ./run.sh"
    exit 1
  fi
}

kill_hushd_on_port

echo "=== Building hushd ==="
cargo build -p hushd --bin hushd --manifest-path "$ROOT_DIR/Cargo.toml"

echo "=== Starting hushd on port $HUSHD_PORT ==="
HUSHD_BIN="${HUSHD_BIN:-$ROOT_DIR/target/debug/hushd}"
if [[ ! -x "$HUSHD_BIN" ]]; then
  echo "[error] hushd binary not found at $HUSHD_BIN"
  exit 1
fi

"$HUSHD_BIN" start --port "$HUSHD_PORT" --ruleset "$HUSHD_RULESET" &
HUSHD_PID=$!

echo "[wait] Waiting for hushd to be ready..."
for i in $(seq 1 30); do
  if curl -sf "http://127.0.0.1:$HUSHD_PORT/health" > /dev/null 2>&1; then
    echo "[ok] hushd is running"
    break
  fi
  if [[ $i -eq 30 ]]; then
    echo "[error] hushd failed to start"
    exit 1
  fi
  sleep 0.5
done

echo "=== Building TypeScript adapter packages ==="
# Build order: adapter-core first (no deps), then packages that depend on it,
# then the policy package and adapters that depend on policy.
build_pkg() {
  local pkg_dir="$1"
  if [[ ! -d "$pkg_dir/dist" ]]; then
    echo "  building $(basename "$pkg_dir") ..."
    (cd "$pkg_dir" && npm install --silent 2>/dev/null && npm run build)
  else
    echo "  $(basename "$pkg_dir") already built"
  fi
}

# Layer 1: no internal deps
build_pkg "$ROOT_DIR/packages/adapters/clawdstrike-adapter-core"

# Layer 2: depends on adapter-core
build_pkg "$ROOT_DIR/packages/adapters/clawdstrike-hushd-engine"
build_pkg "$ROOT_DIR/packages/policy/clawdstrike-policy"

# Layer 3: depends on adapter-core + possibly policy
build_pkg "$ROOT_DIR/packages/adapters/clawdstrike-openclaw"
build_pkg "$ROOT_DIR/packages/adapters/clawdstrike-claude"
build_pkg "$ROOT_DIR/packages/adapters/clawdstrike-vercel-ai"
build_pkg "$ROOT_DIR/packages/adapters/clawdstrike-opencode"

echo "=== Installing Python SDK ==="
if [[ ! -d "$VENV_DIR" ]]; then
  python3 -m venv "$VENV_DIR"
fi
"$VENV_DIR/bin/pip" install -e "$ROOT_DIR/packages/sdk/hush-py" --quiet 2>/dev/null || {
  echo "[warn] Python SDK install failed; red-python agent may not work"
}

echo "=== Installing npm dependencies ==="
cd "$SCRIPT_DIR"
npm install --silent 2>/dev/null || npm install

echo "=== Running demo ==="
HUSHD_URL="http://127.0.0.1:$HUSHD_PORT" PYTHON_BIN="$VENV_DIR/bin/python" npx tsx index.ts

echo "=== Done ==="
