#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
desktop_dir="$repo_root/apps/desktop"

url="${HUNTRONOMER_SMOKE_URL:-http://localhost:1420}"
start_dev="${HUNTRONOMER_SMOKE_START_DEV:-1}"
headed="${HUNTRONOMER_SMOKE_HEADED:-0}"
keep_browser="${HUNTRONOMER_SMOKE_KEEP_BROWSER:-0}"
strict_console="${HUNTRONOMER_SMOKE_STRICT_CONSOLE:-0}"
timeout_secs="${HUNTRONOMER_SMOKE_TIMEOUT_SECS:-30}"

run_id="$(date -u +%Y%m%dT%H%M%SZ)"
session="hsm-$$-$(date -u +%H%M%S)"
output_dir="$repo_root/output/playwright/huntronomer-smoke/$run_id"
mkdir -p "$output_dir"

vite_log="$output_dir/vite.log"
overlay_text_file="$output_dir/launch-overlay.txt"
deck_text_file="$output_dir/command-deck.txt"
snapshot_file="$output_dir/command-deck-snapshot.md"
overlay_screenshot="$output_dir/launch-overlay.png"
deck_screenshot="$output_dir/command-deck.png"
console_file="$output_dir/console-errors.txt"
network_file="$output_dir/network.txt"
summary_file="$output_dir/summary.json"

dev_pid=""
close_browser_on_exit=1

require_cmd() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "error: required command not found: $1" >&2
    exit 1
  fi
}

pw() {
  PLAYWRIGHT_CLI_SESSION="$session" npx --yes --package @playwright/cli playwright-cli "$@"
}

wait_for_url() {
  local elapsed=0
  while (( elapsed < timeout_secs )); do
    if curl -fsS "$url" >/dev/null 2>&1; then
      return 0
    fi
    sleep 1
    elapsed=$((elapsed + 1))
  done
  return 1
}

cleanup() {
  local exit_code=$?

  if [[ "$close_browser_on_exit" == "1" && "$keep_browser" != "1" ]]; then
    pw close >/dev/null 2>&1 || true
  fi

  if [[ -n "$dev_pid" ]] && kill -0 "$dev_pid" >/dev/null 2>&1; then
    kill "$dev_pid" >/dev/null 2>&1 || true
    wait "$dev_pid" >/dev/null 2>&1 || true
  fi

  exit "$exit_code"
}
trap cleanup EXIT

require_cmd curl
require_cmd npx
require_cmd bun
require_cmd python3

if ! wait_for_url; then
  if [[ "$start_dev" != "1" ]]; then
    echo "error: Huntronomer dev server is not reachable at $url" >&2
    exit 1
  fi

  (
    cd "$desktop_dir"
    bun run dev --host localhost --port 1420
  ) >"$vite_log" 2>&1 &
  dev_pid=$!

  if ! wait_for_url; then
    echo "error: failed to start Huntronomer dev server at $url" >&2
    if [[ -f "$vite_log" ]]; then
      echo "--- vite log ---" >&2
      tail -n 80 "$vite_log" >&2 || true
    fi
    exit 1
  fi
fi

open_args=("$url")
if [[ "$headed" == "1" ]]; then
  open_args+=(--headed)
fi

pw open "${open_args[@]}" >/dev/null
pw screenshot --filename "$overlay_screenshot" >/dev/null
pw eval '() => document.body.innerText.slice(0, 4000)' >"$overlay_text_file"

grep -iq "huntronomer" "$overlay_text_file"
grep -iq "open command deck" "$overlay_text_file"
grep -iq "autonomous threat hunting command" "$overlay_text_file"

pw press Enter >/dev/null
sleep 1

pw snapshot --filename "$snapshot_file" >/dev/null
pw screenshot --filename "$deck_screenshot" >/dev/null
pw eval '() => document.body.innerText.slice(0, 4000)' >"$deck_text_file"

grep -q "LIVE" "$deck_text_file"
grep -q "REPLAY" "$deck_text_file"
grep -iq "security scene" "$deck_text_file"

pw console error >"$console_file" || true
pw network >"$network_file" || true

console_error_count="$(grep -c '^\[ERROR\]' "$console_file" 2>/dev/null || true)"
expected_agent_error=0
expected_daemon_error=0
if grep -q "Agent local API token is unavailable" "$console_file" 2>/dev/null; then
  expected_agent_error=1
fi
if grep -q "ERR_CONNECTION_REFUSED" "$console_file" 2>/dev/null; then
  expected_daemon_error=1
fi

if [[ "$strict_console" == "1" && "${console_error_count:-0}" != "0" ]]; then
  echo "error: strict console mode enabled and console errors were observed" >&2
  exit 1
fi

export HUNTRONOMER_SMOKE_SUMMARY_FILE="$summary_file"
export HUNTRONOMER_SMOKE_URL_VALUE="$url"
export HUNTRONOMER_SMOKE_RUN_ID="$run_id"
export HUNTRONOMER_SMOKE_SESSION="$session"
export HUNTRONOMER_SMOKE_OUTPUT_DIR="$output_dir"
export HUNTRONOMER_SMOKE_SERVER_STARTED="$([[ -n "$dev_pid" ]] && printf '1' || printf '0')"
export HUNTRONOMER_SMOKE_STRICT_CONSOLE_VALUE="$strict_console"
export HUNTRONOMER_SMOKE_CONSOLE_ERROR_COUNT="${console_error_count:-0}"
export HUNTRONOMER_SMOKE_EXPECTED_AGENT_ERROR="$expected_agent_error"
export HUNTRONOMER_SMOKE_EXPECTED_DAEMON_ERROR="$expected_daemon_error"
export HUNTRONOMER_SMOKE_OVERLAY_TEXT="$overlay_text_file"
export HUNTRONOMER_SMOKE_DECK_TEXT="$deck_text_file"
export HUNTRONOMER_SMOKE_SNAPSHOT="$snapshot_file"
export HUNTRONOMER_SMOKE_OVERLAY_SCREENSHOT="$overlay_screenshot"
export HUNTRONOMER_SMOKE_DECK_SCREENSHOT="$deck_screenshot"
export HUNTRONOMER_SMOKE_CONSOLE_FILE="$console_file"
export HUNTRONOMER_SMOKE_NETWORK_FILE="$network_file"
export HUNTRONOMER_SMOKE_VITE_LOG="$vite_log"

python3 - <<'PY'
import json
import os
from pathlib import Path

summary = {
    "status": "ok",
    "url": os.environ["HUNTRONOMER_SMOKE_URL_VALUE"],
    "run_id": os.environ["HUNTRONOMER_SMOKE_RUN_ID"],
    "session": os.environ["HUNTRONOMER_SMOKE_SESSION"],
    "output_dir": os.environ["HUNTRONOMER_SMOKE_OUTPUT_DIR"],
    "server_started_by_script": os.environ["HUNTRONOMER_SMOKE_SERVER_STARTED"] == "1",
    "strict_console": os.environ["HUNTRONOMER_SMOKE_STRICT_CONSOLE_VALUE"] == "1",
    "console_error_count": int(os.environ["HUNTRONOMER_SMOKE_CONSOLE_ERROR_COUNT"]),
    "expected_offline_agent_error_seen": os.environ["HUNTRONOMER_SMOKE_EXPECTED_AGENT_ERROR"] == "1",
    "expected_offline_daemon_error_seen": os.environ["HUNTRONOMER_SMOKE_EXPECTED_DAEMON_ERROR"] == "1",
    "artifacts": {
        "overlay_text": os.environ["HUNTRONOMER_SMOKE_OVERLAY_TEXT"],
        "deck_text": os.environ["HUNTRONOMER_SMOKE_DECK_TEXT"],
        "snapshot": os.environ["HUNTRONOMER_SMOKE_SNAPSHOT"],
        "overlay_screenshot": os.environ["HUNTRONOMER_SMOKE_OVERLAY_SCREENSHOT"],
        "deck_screenshot": os.environ["HUNTRONOMER_SMOKE_DECK_SCREENSHOT"],
        "console_errors": os.environ["HUNTRONOMER_SMOKE_CONSOLE_FILE"],
        "network": os.environ["HUNTRONOMER_SMOKE_NETWORK_FILE"],
        "vite_log": os.environ["HUNTRONOMER_SMOKE_VITE_LOG"],
    },
}
Path(os.environ["HUNTRONOMER_SMOKE_SUMMARY_FILE"]).write_text(json.dumps(summary, indent=2) + "\n")
print(json.dumps(summary, indent=2))
PY
