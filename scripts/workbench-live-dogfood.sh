#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
workbench_dir="$repo_root/apps/workbench"
fixture_script="$workbench_dir/scripts/fleet-fixture.ts"

base_url="${WORKBENCH_DOGFOOD_URL:-http://127.0.0.1:1421}"
hushd_url="${HUSHD_URL:-http://127.0.0.1:9876}"
control_api_url="${CONTROL_API_URL:-http://127.0.0.1:8090}"
tenant_id="${TENANT_ID:-874d572c-709c-49b7-8ecf-64b569e16710}"

namespace="${WORKBENCH_DOGFOOD_NAMESPACE:-clawdstrike}"
hushd_service="${WORKBENCH_DOGFOOD_HUSHD_SERVICE:-clawdstrike-helm-hushd}"
control_api_service="${WORKBENCH_DOGFOOD_CONTROL_SERVICE:-clawdstrike-helm-control-api}"
hushd_secret="${WORKBENCH_DOGFOOD_HUSHD_SECRET:-clawdstrike-helm-hushd}"
control_api_secret="${WORKBENCH_DOGFOOD_CONTROL_SECRET:-clawdstrike-helm-control-api}"

start_dev="${WORKBENCH_DOGFOOD_START_DEV:-1}"
start_port_forward="${WORKBENCH_DOGFOOD_START_PORT_FORWARD:-1}"
seed_fixture="${WORKBENCH_DOGFOOD_SEED_FIXTURE:-1}"
auto_cleanup="${WORKBENCH_DOGFOOD_AUTO_CLEANUP:-1}"
headed="${WORKBENCH_DOGFOOD_HEADED:-0}"
keep_browser="${WORKBENCH_DOGFOOD_KEEP_BROWSER:-0}"
keep_stack="${WORKBENCH_DOGFOOD_KEEP_STACK:-0}"
timeout_secs="${WORKBENCH_DOGFOOD_TIMEOUT_SECS:-45}"

run_id="$(date -u +%Y%m%dT%H%M%SZ)"
session="wbdog-$$-$(date -u +%H%M%S)"
operator_name="${WORKBENCH_DOGFOOD_OPERATOR_NAME:-Live Dogfood ${run_id}}"
output_dir="$repo_root/output/playwright/workbench-live-dogfood/$run_id"
mkdir -p "$output_dir"

vite_log="$output_dir/vite.log"
hushd_pf_log="$output_dir/hushd-port-forward.log"
control_pf_log="$output_dir/control-api-port-forward.log"
fixture_log="$output_dir/fleet-fixture.log"
session_file="$output_dir/session.txt"
console_file="$output_dir/console-errors.txt"
network_file="$output_dir/network.txt"
summary_file="$output_dir/summary.json"
auth_storage_file="$output_dir/auth-storage.txt"

dev_pid=""
hushd_pf_pid=""
control_pf_pid=""
seeded_fixture=0
close_browser_on_exit=1

printf '%s\n' "$session" >"$session_file"

require_cmd() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "error: required command not found: $1" >&2
    exit 1
  fi
}

pw() {
  PLAYWRIGHT_CLI_SESSION="$session" npx --yes --package @playwright/cli playwright-cli "$@"
}

pw_eval_result() {
  pw eval "$1" | python3 -c '
import json
import re
import sys

raw = sys.stdin.read()
match = re.search(r"^### Result[ \t]*\n(.*?)(?:\n### |\Z)", raw, re.S | re.M)
result = (match.group(1) if match else raw).strip()

try:
    value = json.loads(result)
except Exception:
    sys.stdout.write(result)
else:
    if isinstance(value, str):
        sys.stdout.write(value)
    elif value is None:
        sys.stdout.write("")
    elif isinstance(value, (int, float)) and not isinstance(value, bool):
        sys.stdout.write(str(value))
    else:
        sys.stdout.write(json.dumps(value))
'
}

js_string() {
  python3 -c 'import json,sys; print(json.dumps(sys.argv[1]))' "$1"
}

wait_for_url() {
  local target="$1"
  local elapsed=0
  while (( elapsed < timeout_secs )); do
    if curl -fsS "$target" >/dev/null 2>&1; then
      return 0
    fi
    sleep 1
    elapsed=$((elapsed + 1))
  done
  return 1
}

wait_for_text() {
  local needle="$1"
  local elapsed=0
  local current_file="$output_dir/wait-current.txt"

  while (( elapsed < timeout_secs )); do
    pw eval '() => document.body.innerText.slice(0, 20000)' >"$current_file" || true
    if grep -Fq "$needle" "$current_file"; then
      return 0
    fi
    sleep 1
    elapsed=$((elapsed + 1))
  done

  echo "error: timed out waiting for text: $needle" >&2
  if [[ -f "$current_file" ]]; then
    echo "--- current page text ---" >&2
    sed -n '1,160p' "$current_file" >&2 || true
  fi
  return 1
}

set_hash() {
  local hash="$1"
  pw eval "$(cat <<EOF
() => {
  window.location.hash = $(js_string "$hash");
}
EOF
)" >/dev/null
}

click_text() {
  local text="$1"
  pw eval "$(cat <<EOF
() => {
  const targetText = $(js_string "$text");
  const norm = (value) => (value ?? "").replace(/\\s+/g, " ").trim();
  const target = [...document.querySelectorAll("button, a, [role='button']")]
    .find((el) => norm(el.textContent) === targetText || norm(el.textContent).includes(targetText));
  if (!target) {
    throw new Error("Could not find clickable text: " + targetText);
  }
  target.click();
}
EOF
)" >/dev/null
}

set_input_placeholder() {
  local placeholder="$1"
  local value="$2"
  pw eval "$(cat <<EOF
() => {
  const targetPlaceholder = $(js_string "$placeholder");
  const nextValue = $(js_string "$value");
  const input = document.querySelector(\`input[placeholder="\${targetPlaceholder}"]\`);
  if (!(input instanceof HTMLInputElement)) {
    throw new Error("Missing input with placeholder: " + targetPlaceholder);
  }
  const descriptor = Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, "value");
  if (!descriptor?.set) {
    throw new Error("Missing native input setter");
  }
  input.focus();
  descriptor.set.call(input, nextValue);
  input.dispatchEvent(new Event("input", { bubbles: true }));
  input.dispatchEvent(new Event("change", { bubbles: true }));
  input.blur();
}
EOF
)" >/dev/null
}

wait_for_identity_prompt_gone() {
  local elapsed=0

  while (( elapsed < timeout_secs )); do
    local prompt_state
    prompt_state="$(
      pw_eval_result "$(cat <<'EOF'
() => document.querySelector('input[placeholder="Your name or callsign"]') ? "present" : "missing"
EOF
)"
    )"
    if [[ "$prompt_state" == "missing" ]]; then
      return 0
    fi
    sleep 1
    elapsed=$((elapsed + 1))
  done

  echo "error: timed out waiting for operator identity prompt to close" >&2
  return 1
}

ensure_operator_identity() {
  local prompt_state
  prompt_state="$(
    pw_eval_result "$(cat <<'EOF'
() => document.querySelector('input[placeholder="Your name or callsign"]') ? "present" : "missing"
EOF
)"
  )"
  if [[ "$prompt_state" == "missing" ]]; then
    return 0
  fi

  set_input_placeholder "Your name or callsign" "$operator_name"
  click_text "Create Identity"
  wait_for_identity_prompt_gone
}

capture_page() {
  local name="$1"
  pw eval '() => document.body.innerText.slice(0, 20000)' >"$output_dir/$name.txt"
  pw screenshot --filename "$output_dir/$name.png" >/dev/null
}

start_port_forwards() {
  if [[ -z "${HUSHD_API_KEY:-}" ]]; then
    export HUSHD_API_KEY
    HUSHD_API_KEY="$(kubectl get secret -n "$namespace" "$hushd_secret" -o jsonpath='{.data.CLAWDSTRIKE_API_KEY}' | base64 -d)"
  fi

  if [[ -z "${JWT_SECRET:-}" ]]; then
    export JWT_SECRET
    JWT_SECRET="$(kubectl get secret -n "$namespace" "$control_api_secret" -o jsonpath='{.data.JWT_SECRET}' | base64 -d)"
  fi

  if ! wait_for_url "$hushd_url/health"; then
    kubectl port-forward -n "$namespace" "svc/$hushd_service" 9876:9876 >"$hushd_pf_log" 2>&1 &
    hushd_pf_pid=$!
    wait_for_url "$hushd_url/health"
  fi

  if ! wait_for_url "$control_api_url/api/v1/health"; then
    kubectl port-forward -n "$namespace" "svc/$control_api_service" 8090:8080 >"$control_pf_log" 2>&1 &
    control_pf_pid=$!
    wait_for_url "$control_api_url/api/v1/health"
  fi
}

start_vite() {
  if wait_for_url "$base_url"; then
    return 0
  fi

  (
    cd "$workbench_dir"
    HUSHD_URL="$hushd_url" \
    HUSHD_API_KEY="${HUSHD_API_KEY:-}" \
    CONTROL_API_URL="$control_api_url" \
    WORKBENCH_CONTROL_PROXY_TOKEN="$control_api_token" \
      npm run dev -- --host 127.0.0.1 --port 1421
  ) >"$vite_log" 2>&1 &
  dev_pid=$!
  wait_for_url "$base_url"
}

cleanup() {
  local exit_code=$?

  if [[ "$close_browser_on_exit" == "1" && "$keep_browser" != "1" ]]; then
    pw close >/dev/null 2>&1 || true
  fi

  if [[ "$auto_cleanup" == "1" && "$seeded_fixture" == "1" ]]; then
    HUSHD_URL="$hushd_url" \
    CONTROL_API_URL="$control_api_url" \
    HUSHD_API_KEY="${HUSHD_API_KEY:-}" \
    JWT_SECRET="${JWT_SECRET:-}" \
    TENANT_ID="$tenant_id" \
      bun "$fixture_script" --cleanup >>"$fixture_log" 2>&1 || true
  fi

  if [[ "$keep_stack" != "1" ]]; then
    if [[ -n "$dev_pid" ]] && kill -0 "$dev_pid" >/dev/null 2>&1; then
      kill "$dev_pid" >/dev/null 2>&1 || true
      wait "$dev_pid" >/dev/null 2>&1 || true
    fi
    if [[ -n "$hushd_pf_pid" ]] && kill -0 "$hushd_pf_pid" >/dev/null 2>&1; then
      kill "$hushd_pf_pid" >/dev/null 2>&1 || true
      wait "$hushd_pf_pid" >/dev/null 2>&1 || true
    fi
    if [[ -n "$control_pf_pid" ]] && kill -0 "$control_pf_pid" >/dev/null 2>&1; then
      kill "$control_pf_pid" >/dev/null 2>&1 || true
      wait "$control_pf_pid" >/dev/null 2>&1 || true
    fi
  fi

  exit "$exit_code"
}
trap cleanup EXIT

require_cmd curl
if [[ "$start_port_forward" == "1" ]]; then
  require_cmd kubectl
fi
require_cmd npx
require_cmd npm
require_cmd bun
require_cmd python3

if [[ "$start_port_forward" == "1" ]]; then
  start_port_forwards
fi

auth_json="$(
  HUSHD_URL="$hushd_url" \
  CONTROL_API_URL="$control_api_url" \
  HUSHD_API_KEY="${HUSHD_API_KEY:-}" \
  JWT_SECRET="${JWT_SECRET:-}" \
  TENANT_ID="$tenant_id" \
    bun "$fixture_script" --print-auth-json
)"

control_api_token="$(
  AUTH_JSON="$auth_json" python3 - <<'PY'
import json
import os
print(json.loads(os.environ["AUTH_JSON"])["controlApiToken"])
PY
)"

if [[ "$seed_fixture" == "1" ]]; then
  HUSHD_URL="$hushd_url" \
  CONTROL_API_URL="$control_api_url" \
  HUSHD_API_KEY="${HUSHD_API_KEY:-}" \
  JWT_SECRET="${JWT_SECRET:-}" \
  TENANT_ID="$tenant_id" \
    bun "$fixture_script" --seed-only >"$fixture_log" 2>&1
  seeded_fixture=1
fi

if [[ "$start_dev" == "1" ]]; then
  start_vite
else
  wait_for_url "$base_url"
fi

open_args=("$base_url")
if [[ "$headed" == "1" ]]; then
  open_args+=(--headed)
fi

pw open "${open_args[@]}" >/dev/null
wait_for_text "CLAWDSTRIKE"
ensure_operator_identity

set_hash "#/settings"
wait_for_text "Configure connections, preferences, and integrations"
capture_page "settings-initial"

pw eval "$(cat <<EOF
() => {
  const setInput = (placeholder, value) => {
    const input = document.querySelector(\`input[placeholder="\${placeholder}"]\`);
    if (!(input instanceof HTMLInputElement)) {
      throw new Error("Missing input with placeholder: " + placeholder);
    }
    const descriptor = Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, "value");
    if (!descriptor?.set) {
      throw new Error("Missing native input value setter for: " + placeholder);
    }
    input.focus();
    descriptor.set.call(input, value);
    input.dispatchEvent(new InputEvent("input", { bubbles: true, data: value, inputType: "insertText" }));
    input.dispatchEvent(new Event("change", { bubbles: true }));
    input.blur();
  };

  setInput("http://localhost:9876", $(js_string "$hushd_url"));
  setInput("http://localhost:8090", $(js_string "$control_api_url"));
  setInput("eyJhbGci...", $(js_string "$control_api_token"));
  setInput("hush_...", $(js_string "${HUSHD_API_KEY:-}"));
}
EOF
)" >/dev/null

click_text "Test"
wait_for_text "Connected — hushd"

click_text "Connect to Fleet"
wait_for_text "FLEET SUMMARY"
pw eval '() => ({
  apiKey: sessionStorage.getItem("clawdstrike_api_key") ?? localStorage.getItem("clawdstrike_api_key"),
  controlApiToken: sessionStorage.getItem("clawdstrike_control_api_token") ?? localStorage.getItem("clawdstrike_control_api_token"),
})' >"$auth_storage_file"
grep -Fq "$HUSHD_API_KEY" "$auth_storage_file"
grep -Fq "$control_api_token" "$auth_storage_file"
capture_page "settings-connected"

set_hash "#/home"
wait_for_text "Fleet"
capture_page "home"

set_hash "#/fleet"
wait_for_text "Fleet Dashboard"
wait_for_text "agent-orchestrator-001"
capture_page "fleet"

set_hash "#/library"
wait_for_text "Policy Library"
click_text "Catalog"
wait_for_text "Live catalog connected"
capture_page "library-catalog-live"

set_hash "#/hierarchy"
wait_for_text "Org Hierarchy"
click_text "DEMO"
wait_for_text "Local Draft"
click_text "Pull from Fleet"
wait_for_text "Fleet Snapshot"
wait_for_text "Fleet Fixture Org"
capture_page "hierarchy-live-pulled"

set_hash "#/approvals"
wait_for_text "PENDING"
click_text "Demo"
wait_for_text "No pending approvals from fleet"
capture_page "approvals-live"

set_hash "#/delegation"
wait_for_text "FILTERS"
capture_page "delegation"

pw console error >"$console_file" || true
pw network >"$network_file" || true

export WORKBENCH_DOGFOOD_SUMMARY_FILE="$summary_file"
export WORKBENCH_DOGFOOD_BASE_URL="$base_url"
export WORKBENCH_DOGFOOD_HUSHD_URL="$hushd_url"
export WORKBENCH_DOGFOOD_CONTROL_API_URL="$control_api_url"
export WORKBENCH_DOGFOOD_RUN_ID="$run_id"
export WORKBENCH_DOGFOOD_OUTPUT_DIR="$output_dir"
export WORKBENCH_DOGFOOD_SESSION="$session"
export WORKBENCH_DOGFOOD_SEEDED="$seeded_fixture"

python3 - <<'PY'
import json
import os
from pathlib import Path

summary = {
    "status": "ok",
    "run_id": os.environ["WORKBENCH_DOGFOOD_RUN_ID"],
    "session": os.environ["WORKBENCH_DOGFOOD_SESSION"],
    "base_url": os.environ["WORKBENCH_DOGFOOD_BASE_URL"],
    "hushd_url": os.environ["WORKBENCH_DOGFOOD_HUSHD_URL"],
    "control_api_url": os.environ["WORKBENCH_DOGFOOD_CONTROL_API_URL"],
    "seeded_fixture": os.environ["WORKBENCH_DOGFOOD_SEEDED"] == "1",
    "output_dir": os.environ["WORKBENCH_DOGFOOD_OUTPUT_DIR"],
    "artifacts": {
        "settings_initial": "settings-initial.txt",
        "settings_connected": "settings-connected.txt",
        "auth_storage": "auth-storage.txt",
        "home": "home.txt",
        "fleet": "fleet.txt",
        "library_catalog_live": "library-catalog-live.txt",
        "hierarchy_live_pulled": "hierarchy-live-pulled.txt",
        "approvals_live": "approvals-live.txt",
        "delegation": "delegation.txt",
        "console_errors": "console-errors.txt",
        "network": "network.txt",
    },
}
Path(os.environ["WORKBENCH_DOGFOOD_SUMMARY_FILE"]).write_text(
    json.dumps(summary, indent=2) + "\n"
)
print(json.dumps(summary, indent=2))
PY
