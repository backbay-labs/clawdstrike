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

route_mode="shell"
case "$url" in
  *"#/nexus/scene"*)
    route_mode="observatory-scene"
    ;;
esac

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
ritual_text_file="$output_dir/spirit-chamber.txt"
ritual_snapshot_file="$output_dir/spirit-chamber-snapshot.md"
ritual_screenshot="$output_dir/spirit-chamber.png"
ritual_release_file="$output_dir/spirit-release.json"
ritual_release_screenshot="$output_dir/spirit-release.png"
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

wait_for_shell_paint() {
  pw eval "$(cat <<'EOF'
async () => {
  const wait = (ms) => new Promise((resolve) => window.setTimeout(resolve, ms));
  const until = async (predicate, timeoutMs = 5000) => {
    const start = Date.now();
    while (Date.now() - start < timeoutMs) {
      if (predicate()) return true;
      await wait(50);
    }
    throw new Error("shell-not-ready");
  };

  await until(() => Boolean(document.querySelector('button[title="New hunt (Cmd+Shift+H)"]')));
  if ("fonts" in document && document.fonts?.ready) {
    try {
      await document.fonts.ready;
    } catch {
      // Ignore font readiness failures in smoke mode.
    }
  }

  await new Promise((resolve) =>
    requestAnimationFrame(() => requestAnimationFrame(() => resolve(undefined))),
  );
  await wait(450);

  return JSON.stringify(
    {
      ready: true,
      canvasCount: document.querySelectorAll("canvas").length,
      title: document.title,
    },
    null,
    2,
  );
}
EOF
)" >/dev/null
}

wait_for_chamber_paint() {
  pw eval "$(cat <<'EOF'
async () => {
  const wait = (ms) => new Promise((resolve) => window.setTimeout(resolve, ms));
  const until = async (predicate, timeoutMs = 5000) => {
    const start = Date.now();
    while (Date.now() - start < timeoutMs) {
      if (predicate()) return true;
      await wait(50);
    }
    throw new Error("chamber-not-ready");
  };

  await until(() => Boolean(document.querySelector('[data-testid="spirit-bind-sheet"]')));
  await new Promise((resolve) =>
    requestAnimationFrame(() => requestAnimationFrame(() => resolve(undefined))),
  );
  await wait(180);
  return JSON.stringify({ ready: true }, null, 2);
}
EOF
)" >/dev/null
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
wait_for_shell_paint
pw screenshot --filename "$overlay_screenshot" >/dev/null
pw eval '() => document.body.innerText.slice(0, 4000)' >"$overlay_text_file"

if [[ "$route_mode" == "observatory-scene" ]]; then
  grep -q "OBSERVATORY ATLAS" "$overlay_text_file"
  grep -q "WATCHFIELD" "$overlay_text_file"
  grep -q "LAYOUT" "$overlay_text_file"
  grep -q "OBSERVE" "$overlay_text_file"
else
  grep -q "WIRE" "$overlay_text_file"
  grep -q "SCOPES" "$overlay_text_file"
  grep -q "TAPE" "$overlay_text_file"
  grep -q "CONTEXT" "$overlay_text_file"
fi

wait_for_shell_paint
pw screenshot --filename "$deck_screenshot" >/dev/null
pw eval '() => document.body.innerText.slice(0, 4000)' >"$deck_text_file"
pw snapshot --filename "$snapshot_file" >/dev/null

if [[ "$route_mode" == "observatory-scene" ]]; then
  grep -q "OBSERVATORY ATLAS" "$deck_text_file"
  grep -q "WATCHFIELD" "$deck_text_file"
  grep -q "LAYOUT" "$deck_text_file"
  grep -q "OBSERVE" "$deck_text_file"
else
  grep -q "WIRE" "$deck_text_file"
  grep -q "SCOPES" "$deck_text_file"
  grep -q "TAPE" "$deck_text_file"
  grep -q "CONTEXT" "$deck_text_file"
fi

if [[ "$route_mode" != "observatory-scene" ]]; then
pw eval "$(cat <<'EOF'
async () => {
  const wait = (ms) => new Promise((resolve) => window.setTimeout(resolve, ms));
  const until = async (predicate, timeoutMs = 6000) => {
    const start = Date.now();
    while (Date.now() - start < timeoutMs) {
      if (predicate()) return true;
      await wait(50);
    }
    return false;
  };

  const button = document.querySelector('button[title="New hunt (Cmd+Shift+H)"]');
  if (!(button instanceof HTMLButtonElement)) {
    return JSON.stringify(
      {
        clicked: false,
        error: "new-hunt-button-missing",
      },
      null,
      2,
    );
  }
  button.click();
  await new Promise((resolve) => window.setTimeout(resolve, 250));

  const spiritEntry = document.querySelector('[data-testid="smart-bucket-spirit-open"]');
  if (!(spiritEntry instanceof HTMLButtonElement)) {
    return JSON.stringify(
      {
        clicked: false,
        error: "spirit-entry-missing",
      },
      null,
      2,
    );
  }

  spiritEntry.click();
  const chamberReady = await until(
    () =>
      Boolean(document.querySelector('[data-testid="spirit-bind-sheet"]'))
      && Boolean(document.querySelector('[data-testid="spirit-bind-mode-rail"]')),
  );

  return JSON.stringify(
    {
      clicked: true,
      hasSpiritEntry: true,
      hasChamber: chamberReady && Boolean(document.querySelector('[data-testid="spirit-bind-sheet"]')),
      hasModeRail: Boolean(
        document.querySelector('[data-testid="spirit-bind-mode-rail"]'),
      ),
      hasPinToggle: Boolean(
        document.querySelector('[data-testid="spirit-bind-pin-toggle"][role="switch"]'),
      ),
      hasReleaseButton: Array.from(document.querySelectorAll("button")).some(
        (element) => element.textContent?.includes("Apply spirit"),
      ),
      text: document.body.innerText.slice(0, 6000),
    },
    null,
    2,
  );
}
EOF
)" >"$ritual_text_file"

grep -q '\\"clicked\\": true' "$ritual_text_file"
grep -q '\\"hasSpiritEntry\\": true' "$ritual_text_file"
grep -q '\\"hasChamber\\": true' "$ritual_text_file"
grep -q '\\"hasModeRail\\": true' "$ritual_text_file"
grep -q '\\"hasPinToggle\\": true' "$ritual_text_file"
grep -q '\\"hasReleaseButton\\": true' "$ritual_text_file"
grep -qi "Spirit" "$ritual_text_file"
grep -qi "MANUAL" "$ritual_text_file"
grep -qi "PIN TO HUNT" "$ritual_text_file"
grep -qi "Apply spirit" "$ritual_text_file"

wait_for_chamber_paint
pw screenshot --filename "$ritual_screenshot" >/dev/null
pw snapshot --filename "$ritual_snapshot_file" >/dev/null

pw eval "$(cat <<'EOF'
async () => {
  const releaseButton = document.querySelector('[data-testid="spirit-bind-submit"]');
  if (!(releaseButton instanceof HTMLButtonElement)) {
    return JSON.stringify(
      {
        clicked: false,
        error: "release-button-missing",
      },
      null,
      2,
    );
  }
  releaseButton.click();
  const wait = (ms) => new Promise((resolve) => window.setTimeout(resolve, ms));
  const until = async (predicate, timeoutMs = 5000) => {
    const start = Date.now();
    while (Date.now() - start < timeoutMs) {
      if (predicate()) return true;
      await wait(60);
    }
    throw new Error("release-afterglow-not-ready");
  };

  await until(
    () => !document.querySelector('[data-testid="spirit-bind-sheet"]'),
    5000,
  );
  await until(
    () =>
      Boolean(document.querySelector('[data-testid="forensics-room-afterglow"]')) ||
      Boolean(document.querySelector('[data-testid="nexus-room-afterglow"]')) ||
      Boolean(document.querySelector('[data-testid="hunt-dock-spirit-aftermath"]')) ||
      Boolean(document.querySelector('[data-testid="smart-bucket-spirit-aftermath"]')),
    5000,
  );
  await new Promise((resolve) =>
    requestAnimationFrame(() => requestAnimationFrame(() => resolve(undefined))),
  );
  await wait(140);

  return JSON.stringify(
    {
      clicked: true,
      chamberStillOpen: Boolean(document.querySelector('[data-testid="spirit-bind-sheet"]')),
      roomAfterglowVisible:
        Boolean(document.querySelector('[data-testid="forensics-room-afterglow"]')) ||
        Boolean(document.querySelector('[data-testid="nexus-room-afterglow"]')),
      forensicsRoomAfterglowVisible: Boolean(
        document.querySelector('[data-testid="forensics-room-afterglow"]'),
      ),
      nexusRoomAfterglowVisible: Boolean(
        document.querySelector('[data-testid="nexus-room-afterglow"]'),
      ),
      dockAfterglowVisible: Boolean(document.querySelector('[data-testid="hunt-dock-spirit-aftermath"]')),
      bucketAfterglowVisible: Boolean(document.querySelector('[data-testid="smart-bucket-spirit-aftermath"]')),
      text: document.body.innerText.slice(0, 5000),
    },
    null,
    2,
  );
}
EOF
)" >"$ritual_release_file"

grep -q '\\"clicked\\": true' "$ritual_release_file"
grep -q '\\"chamberStillOpen\\": false' "$ritual_release_file"
if ! grep -q '\\"roomAfterglowVisible\\": true' "$ritual_release_file"; then
  grep -q '\\"dockAfterglowVisible\\": true' "$ritual_release_file"
fi
pw screenshot --filename "$ritual_release_screenshot" >/dev/null
else
  printf '{\n  "status": "not_applicable",\n  "route_mode": "observatory-scene"\n}\n' >"$ritual_text_file"
  printf '{\n  "status": "not_applicable",\n  "route_mode": "observatory-scene"\n}\n' >"$ritual_release_file"
  : >"$ritual_snapshot_file"
  : >"$ritual_screenshot"
  : >"$ritual_release_screenshot"
fi

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
export HUNTRONOMER_SMOKE_ROUTE_MODE="$route_mode"
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
export HUNTRONOMER_SMOKE_RITUAL_TEXT="$ritual_text_file"
export HUNTRONOMER_SMOKE_RITUAL_SNAPSHOT="$ritual_snapshot_file"
export HUNTRONOMER_SMOKE_RITUAL_SCREENSHOT="$ritual_screenshot"
export HUNTRONOMER_SMOKE_RITUAL_RELEASE="$ritual_release_file"
export HUNTRONOMER_SMOKE_RITUAL_RELEASE_SCREENSHOT="$ritual_release_screenshot"
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
    "route_mode": os.environ["HUNTRONOMER_SMOKE_ROUTE_MODE"],
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
        "ritual_text": os.environ["HUNTRONOMER_SMOKE_RITUAL_TEXT"],
        "ritual_snapshot": os.environ["HUNTRONOMER_SMOKE_RITUAL_SNAPSHOT"],
        "ritual_screenshot": os.environ["HUNTRONOMER_SMOKE_RITUAL_SCREENSHOT"],
        "ritual_release": os.environ["HUNTRONOMER_SMOKE_RITUAL_RELEASE"],
        "ritual_release_screenshot": os.environ["HUNTRONOMER_SMOKE_RITUAL_RELEASE_SCREENSHOT"],
        "console_errors": os.environ["HUNTRONOMER_SMOKE_CONSOLE_FILE"],
        "network": os.environ["HUNTRONOMER_SMOKE_NETWORK_FILE"],
        "vite_log": os.environ["HUNTRONOMER_SMOKE_VITE_LOG"],
    },
}
Path(os.environ["HUNTRONOMER_SMOKE_SUMMARY_FILE"]).write_text(json.dumps(summary, indent=2) + "\n")
print(json.dumps(summary, indent=2))
PY
