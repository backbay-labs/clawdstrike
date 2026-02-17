#!/usr/bin/env bash
set -euo pipefail

# run.sh - Automated runner for the swarm infection demo
#
# Builds hushd + required TS adapter packages, starts hushd, installs deps,
# runs the demo, then cleans up.

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/../.." && pwd)"
HUSHD_PORT="${HUSHD_PORT:-9876}"
HUSHD_RULESET="${HUSHD_RULESET:-strict}"
HUSHD_LOG_FILE="${HUSHD_LOG_FILE:-$SCRIPT_DIR/.hushd.${HUSHD_PORT}.log}"
HUSHD_PID=""

if [[ -t 1 && -z "${NO_COLOR:-}" ]]; then
  BOLD=$'\033[1m'
  DIM=$'\033[2m'
  RED=$'\033[31m'
  GREEN=$'\033[32m'
  YELLOW=$'\033[33m'
  RESET=$'\033[0m'
else
  BOLD=""
  DIM=""
  RED=""
  GREEN=""
  YELLOW=""
  RESET=""
fi

step() { echo "${BOLD}=== $* ===${RESET}"; }
ok() { echo "${GREEN}[ok]${RESET} $*"; }
warn() { echo "${YELLOW}[warn]${RESET} $*"; }
err() { echo "${RED}[error]${RESET} $*"; }
note() { echo "${DIM}$*${RESET}"; }

cleanup() {
  if [[ -n "$HUSHD_PID" ]]; then
    note "[cleanup] Stopping hushd (PID $HUSHD_PID)..."
    kill "$HUSHD_PID" 2>/dev/null || true
    wait "$HUSHD_PID" 2>/dev/null || true

    if [[ "${SHOW_HUSHD_LOG:-0}" == "1" && -f "$HUSHD_LOG_FILE" ]]; then
      note "[cleanup] hushd log tail ($HUSHD_LOG_FILE):"
      tail -n 20 "$HUSHD_LOG_FILE" | sed 's/^/  /'
    fi
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

  warn "Port $HUSHD_PORT is in use by:"
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
    err "Port $HUSHD_PORT is still in use."
    note "Stop the process above, or run with a different port:"
    note "HUSHD_PORT=19876 ./run.sh"
    exit 1
  fi
}

kill_hushd_on_port

step "Building hushd"
cargo build -p hushd --bin hushd --manifest-path "$ROOT_DIR/Cargo.toml"

step "Starting hushd on port $HUSHD_PORT"
HUSHD_BIN="${HUSHD_BIN:-$ROOT_DIR/target/debug/hushd}"
if [[ ! -x "$HUSHD_BIN" ]]; then
  err "hushd binary not found at $HUSHD_BIN"
  exit 1
fi

: > "$HUSHD_LOG_FILE"
note "hushd logs -> $HUSHD_LOG_FILE (set SHOW_HUSHD_LOG=1 to print tail on exit)"
"$HUSHD_BIN" start --port "$HUSHD_PORT" --ruleset "$HUSHD_RULESET" >"$HUSHD_LOG_FILE" 2>&1 &
HUSHD_PID=$!

note "[wait] Waiting for hushd to be ready..."
for i in $(seq 1 30); do
  if curl -sf "http://127.0.0.1:$HUSHD_PORT/health" > /dev/null 2>&1; then
    ok "hushd is running"
    break
  fi
  if [[ $i -eq 30 ]]; then
    err "hushd failed to start"
    if [[ -f "$HUSHD_LOG_FILE" ]]; then
      note "Last 60 lines from $HUSHD_LOG_FILE:"
      tail -n 60 "$HUSHD_LOG_FILE" | sed 's/^/  /'
    fi
    exit 1
  fi
  sleep 0.5
done

step "Building TypeScript adapter packages"
build_pkg() {
  local pkg_dir="$1"
  if [[ ! -d "$pkg_dir/dist" ]]; then
    echo "  building $(basename "$pkg_dir") ..."
    (cd "$pkg_dir" && npm ci --no-audit --no-fund --loglevel=error && npm run build)
  else
    echo "  $(basename "$pkg_dir") already built"
  fi
}

# Layer 1: no internal deps
build_pkg "$ROOT_DIR/packages/adapters/clawdstrike-adapter-core"

# Layer 2: depends on adapter-core
build_pkg "$ROOT_DIR/packages/adapters/clawdstrike-hushd-engine"

# Layer 3: depends on adapter-core
build_pkg "$ROOT_DIR/packages/adapters/clawdstrike-openai"

step "Installing npm dependencies"
cd "$SCRIPT_DIR"
if [[ "${SKIP_NPM_INSTALL:-0}" == "1" ]]; then
  note "Skipping npm install (SKIP_NPM_INSTALL=1)"
elif [[ -d node_modules && -f node_modules/tsx/package.json ]]; then
  ok "npm deps already installed (node_modules/)"
else
  note "First run: installing (this can take a minute)..."
  if [[ -f package-lock.json ]]; then
    npm ci --no-audit --no-fund --loglevel=warn
  else
    npm install --no-audit --no-fund --loglevel=warn
  fi
fi

step "Running demo"
HUSHD_URL="http://127.0.0.1:$HUSHD_PORT" npm run -s start

ok "Done"
