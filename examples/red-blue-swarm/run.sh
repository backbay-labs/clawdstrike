#!/usr/bin/env bash
set -euo pipefail

# run.sh - Automated runner for the multi-framework red/blue swarm demo
# Builds hushd, builds TS adapter packages, starts hushd, installs deps,
# runs the demo, cleans up.

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/../.." && pwd)"
HUSHD_PORT="${HUSHD_PORT:-9876}"
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

# Kill any lingering hushd on the same port
if lsof -ti :"$HUSHD_PORT" > /dev/null 2>&1; then
  echo "[cleanup] Killing existing process on port $HUSHD_PORT"
  kill "$(lsof -ti :"$HUSHD_PORT")" 2>/dev/null || true
  sleep 1
fi

echo "=== Building hushd ==="
cargo build -p hushd --bin hushd --manifest-path "$ROOT_DIR/Cargo.toml"

echo "=== Starting hushd on port $HUSHD_PORT ==="
cargo run -p hushd --bin hushd --manifest-path "$ROOT_DIR/Cargo.toml" -- start --port "$HUSHD_PORT" --ruleset strict &
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
