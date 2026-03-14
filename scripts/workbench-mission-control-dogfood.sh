#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
workbench_dir="$repo_root/apps/workbench"

base_url="${WORKBENCH_MISSION_DOGFOOD_BASE_URL:-http://127.0.0.1:1421}"
hushd_url="${HUSHD_URL:-http://127.0.0.1:9876}"
hushd_api_key="${HUSHD_API_KEY:-3cg5Q2lAY-Xnf9N_-D3L90d-QYbIsBhd8g9b8Iur3Pw}"
start_dev="${WORKBENCH_MISSION_DOGFOOD_START_DEV:-1}"
headed="${WORKBENCH_MISSION_DOGFOOD_HEADED:-0}"
keep_browser="${WORKBENCH_MISSION_DOGFOOD_KEEP_BROWSER:-0}"
keep_stack="${WORKBENCH_MISSION_DOGFOOD_KEEP_STACK:-0}"
timeout_secs="${WORKBENCH_MISSION_DOGFOOD_TIMEOUT_SECS:-45}"

run_id="$(date -u +%Y%m%dT%H%M%SZ)"
run_id_slug="$(printf '%s' "$run_id" | tr '[:upper:]' '[:lower:]')"
session="wm$$"
output_dir="$repo_root/output/playwright/workbench-mission-control-dogfood/$run_id"
mkdir -p "$output_dir"

vite_log="$output_dir/vite.log"
console_file="$output_dir/console-errors.txt"
network_file="$output_dir/network.txt"
summary_file="$output_dir/summary.json"
status_before_file="$output_dir/hushd-status-before.json"
status_after_file="$output_dir/hushd-status-after.json"
swarm_share_state_file="$output_dir/swarm-share-state.json"
swarm_head_file="$output_dir/swarm-head.json"
swarm_replay_file="$output_dir/swarm-replay.json"

dev_pid=""
close_browser_on_exit=1

endpoint_id="agent-openclaw-dogfood-${run_id_slug}"
runtime_id="rt-openclaw-dogfood-${run_id_slug}"
claude_name="Scribe Dogfood ${run_id}"
openclaw_name="Prowl Dogfood ${run_id}"
openclaw_finding_title="Behavioral pattern on ${openclaw_name}"
claude_target="$repo_root/apps/workbench"
openclaw_target="gateway://hunt-pod-${run_id_slug}"
claude_mission_title="Claude blocked live check ${run_id}"
openclaw_mission_title="OpenClaw hunt live check ${run_id}"
operator_name="${WORKBENCH_MISSION_DOGFOOD_OPERATOR_NAME:-Mission Dogfood ${run_id}}"
swarm_name="${WORKBENCH_MISSION_DOGFOOD_SWARM_NAME:-Mission Swarm ${run_id}}"

require_cmd() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "error: required command not found: $1" >&2
    exit 1
  fi
}

log() {
  printf '[dogfood] %s\n' "$1" >&2
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

capture_playwright_report() {
  local target_file="$1"
  shift
  local raw_output
  local report_ref
  local report_path

  raw_output="$(pw "$@" || true)"
  report_ref="$(
    printf '%s' "$raw_output" | python3 -c '
import re
import sys

raw = sys.stdin.read()
match = re.search(r"\(([^)]+\.log)\)", raw)
print(match.group(1) if match else "")
'
  )"

  if [[ -n "$report_ref" ]]; then
    report_path="$repo_root/$report_ref"
    if [[ -f "$report_path" ]]; then
      cp "$report_path" "$target_file"
      return 0
    fi
  fi

  printf '%s\n' "$raw_output" >"$target_file"
}

js_string() {
  python3 -c 'import json,sys; print(json.dumps(sys.argv[1]))' "$1"
}

urlencode() {
  python3 -c 'import sys, urllib.parse; print(urllib.parse.quote(sys.argv[1], safe=""))' "$1"
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
  echo "error: timed out waiting for URL: $target" >&2
  return 1
}

wait_for_text() {
  local needle="$1"
  local current_file="$output_dir/current-page.txt"
  local elapsed=0

  while (( elapsed < timeout_secs )); do
    pw_eval_result '() => document.body.innerText.slice(0, 30000)' >"$current_file" || true
    if python3 - "$needle" "$current_file" <<'PY'
import pathlib
import sys

needle = sys.argv[1].lower()
haystack = pathlib.Path(sys.argv[2]).read_text().lower()
sys.exit(0 if needle in haystack else 1)
PY
    then
      return 0
    fi
    sleep 1
    elapsed=$((elapsed + 1))
  done

  echo "error: timed out waiting for text: $needle" >&2
  sed -n '1,220p' "$current_file" >&2 || true
  return 1
}

wait_for_button_enabled() {
  local label="$1"
  local elapsed=0

  while (( elapsed < timeout_secs )); do
    local button_state
    button_state="$(
      pw_eval_result "$(cat <<EOF
() => {
  const targetText = $(js_string "$label");
  const norm = (value) => (value ?? "").replace(/\\s+/g, " ").trim().toLowerCase();
  const expected = targetText.toLowerCase();
  const target = [...document.querySelectorAll("button, a, [role='button']")]
    .find((el) => norm(el.textContent) === expected || norm(el.textContent).includes(expected));
  if (!(target instanceof HTMLElement)) {
    return "missing";
  }
  if (target instanceof HTMLButtonElement) {
    return target.disabled ? "disabled" : "enabled";
  }
  return target.getAttribute("aria-disabled") === "true" ? "disabled" : "enabled";
}
EOF
)"
    )"
    if [[ "$button_state" == "enabled" ]]; then
      return 0
    fi
    sleep 1
    elapsed=$((elapsed + 1))
  done

  echo "error: timed out waiting for enabled button: $label" >&2
  return 1
}

read_first_local_intel_id() {
  pw_eval_result "$(cat <<'EOF'
() => {
  try {
    const parsed = JSON.parse(localStorage.getItem("clawdstrike_workbench_intel") ?? "{}");
    return parsed.localIntel?.[0]?.id ?? "";
  } catch {
    return "";
  }
}
EOF
)"
}

wait_for_first_local_intel_id() {
  local elapsed=0

  while (( elapsed < timeout_secs )); do
    local intel_id
    intel_id="$(read_first_local_intel_id)"
    if [[ -n "$intel_id" ]]; then
      printf '%s\n' "$intel_id"
      return 0
    fi
    sleep 1
    elapsed=$((elapsed + 1))
  done

  echo "error: timed out waiting for promoted intel id" >&2
  return 1
}

read_swarm_share_state() {
  pw_eval_result "$(cat <<'EOF'
() => {
  try {
    const intel = JSON.parse(localStorage.getItem("clawdstrike_workbench_intel") ?? "{}");
    const swarms = JSON.parse(localStorage.getItem("clawdstrike_workbench_swarms") ?? "{}");
    const feed = JSON.parse(localStorage.getItem("clawdstrike_workbench_swarm_feed") ?? "{}");
    const findingRecord = Array.isArray(feed.findingEnvelopes) ? feed.findingEnvelopes[0] ?? null : null;
    const headRecord = Array.isArray(feed.headAnnouncements) ? feed.headAnnouncements[0] ?? null : null;
    return {
      localIntelCount: Array.isArray(intel.localIntel) ? intel.localIntel.length : 0,
      swarmIntelCount: Array.isArray(intel.swarmIntel) ? intel.swarmIntel.length : 0,
      sharedIntelCount: Array.isArray(swarms.swarms?.[0]?.sharedIntel) ? swarms.swarms[0].sharedIntel.length : 0,
      findingEnvelopeCount: Array.isArray(feed.findingEnvelopes) ? feed.findingEnvelopes.length : 0,
      headAnnouncementCount: Array.isArray(feed.headAnnouncements) ? feed.headAnnouncements.length : 0,
      intelId: intel.localIntel?.[0]?.id ?? "",
      intelTitle: intel.localIntel?.[0]?.title ?? "",
      feedId: findingRecord?.envelope?.feedId ?? "",
      issuerId: findingRecord?.envelope?.issuerId ?? "",
      findingId: findingRecord?.envelope?.findingId ?? "",
      headSeq: headRecord?.announcement?.headSeq ?? 0,
    };
  } catch (error) {
    return { error: String(error) };
  }
}
EOF
)"
}

wait_for_swarm_share_state_ready() {
  local elapsed=0

  while (( elapsed < timeout_secs )); do
    local state_json
    state_json="$(read_swarm_share_state)"
    if STATE_JSON="$state_json" python3 - <<'PY'
import json
import os
import sys

state = json.loads(os.environ["STATE_JSON"])
ready = (
    state.get("sharedIntelCount", 0) >= 1
    and state.get("findingEnvelopeCount", 0) >= 1
    and state.get("headAnnouncementCount", 0) >= 1
    and bool(state.get("feedId"))
    and bool(state.get("issuerId"))
    and int(state.get("headSeq", 0)) >= 1
)
sys.exit(0 if ready else 1)
PY
    then
      printf '%s\n' "$state_json"
      return 0
    fi
    sleep 1
    elapsed=$((elapsed + 1))
  done

  echo "error: timed out waiting for swarm share state" >&2
  return 1
}

wait_for_launch_state() {
  local expected="$1"
  local elapsed=0

  while (( elapsed < timeout_secs )); do
    local current
    current="$(
      pw_eval_result "$(cat <<'EOF'
() => {
  const label = [...document.querySelectorAll("span")]
    .find((el) => (el.textContent ?? "").trim() === "Runtime Readiness");
  const row = label?.parentElement?.parentElement;
  const stateText = row
    ? ([...row.querySelectorAll("span")].at(-1)?.textContent ?? "").trim().toLowerCase()
    : "";
  if (stateText.includes("blocked")) return "blocked";
  if (stateText.includes("ready")) return "ready";
  if (stateText.includes("degraded")) return "degraded";
  return "";
}
EOF
)"
    )"
    if [[ "$current" == "$expected" ]]; then
      return 0
    fi
    sleep 1
    elapsed=$((elapsed + 1))
  done

  echo "error: timed out waiting for launch state: $expected" >&2
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
  const norm = (value) => (value ?? "").replace(/\\s+/g, " ").trim().toLowerCase();
  const expected = targetText.toLowerCase();
  const target = [...document.querySelectorAll("button, a, [role='button'], label")]
    .find((el) => norm(el.textContent) === expected || norm(el.textContent).includes(expected));
  if (!target) {
    throw new Error("Could not find clickable text: " + targetText);
  }
  target.click();
}
EOF
)" >/dev/null
}

click_text_exact() {
  local text="$1"
  pw eval "$(cat <<EOF
() => {
  const targetText = $(js_string "$text");
  const norm = (value) => (value ?? "").replace(/\\s+/g, " ").trim().toLowerCase();
  const expected = targetText.toLowerCase();
  const target = [...document.querySelectorAll("button, a, [role='button'], label")]
    .find((el) => norm(el.textContent) === expected);
  if (!target) {
    throw new Error("Could not find exact clickable text: " + targetText);
  }
  target.click();
}
EOF
)" >/dev/null
}

click_last_text() {
  local text="$1"
  pw eval "$(cat <<EOF
() => {
  const targetText = $(js_string "$text");
  const norm = (value) => (value ?? "").replace(/\\s+/g, " ").trim().toLowerCase();
  const expected = targetText.toLowerCase();
  const matches = [...document.querySelectorAll("button, a, [role='button'], label")]
    .filter((el) => norm(el.textContent) === expected || norm(el.textContent).includes(expected));
  const target = matches.at(-1);
  if (!target) {
    throw new Error("Could not find clickable text: " + targetText);
  }
  target.click();
}
EOF
)" >/dev/null
}

read_finding_action_state() {
  local finding_title="$1"
  pw_eval_result "$(cat <<EOF
() => {
  const targetTitle = $(js_string "$finding_title");
  const norm = (value) => (value ?? "").replace(/\\s+/g, " ").trim();
  const candidates = [...document.querySelectorAll("div")]
    .filter((el) =>
      (el.textContent ?? "").includes(targetTitle) &&
      [...el.querySelectorAll("button")].some((button) => {
        const label = norm(button.textContent);
        return label === "Confirm" || label === "Promote";
      }),
    );
  const row = candidates[0];
  if (!row) {
    return "";
  }
  const labels = [...row.querySelectorAll("button")].map((button) => norm(button.textContent));
  if (labels.includes("Promote")) {
    return "promote";
  }
  if (labels.includes("Confirm")) {
    return "confirm";
  }
  return "";
}
EOF
)"
}

click_finding_action() {
  local finding_title="$1"
  local action_label="$2"
  pw eval "$(cat <<EOF
() => {
  const targetTitle = $(js_string "$finding_title");
  const targetAction = $(js_string "$action_label");
  const norm = (value) => (value ?? "").replace(/\\s+/g, " ").trim();
  const candidates = [...document.querySelectorAll("div")]
    .filter((el) =>
      (el.textContent ?? "").includes(targetTitle) &&
      [...el.querySelectorAll("button")].some((button) => norm(button.textContent) === targetAction),
    );
  const row = candidates[0];
  if (!row) {
    throw new Error("Missing finding row for: " + targetTitle);
  }
  const button = [...row.querySelectorAll("button")]
    .find((candidate) => norm(candidate.textContent) === targetAction);
  if (!(button instanceof HTMLButtonElement)) {
    throw new Error("Missing finding action " + targetAction + " for: " + targetTitle);
  }
  button.click();
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

set_textarea_placeholder() {
  local placeholder="$1"
  local value="$2"
  pw eval "$(cat <<EOF
() => {
  const targetPlaceholder = $(js_string "$placeholder");
  const nextValue = $(js_string "$value");
  const input = document.querySelector(\`textarea[placeholder="\${targetPlaceholder}"]\`);
  if (!(input instanceof HTMLTextAreaElement)) {
    throw new Error("Missing textarea with placeholder: " + targetPlaceholder);
  }
  const descriptor = Object.getOwnPropertyDescriptor(HTMLTextAreaElement.prototype, "value");
  if (!descriptor?.set) {
    throw new Error("Missing native textarea setter");
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

select_first_option_by_text() {
  local text="$1"
  pw eval "$(cat <<EOF
() => {
  const targetText = $(js_string "$text");
  const expected = targetText.toLowerCase();
  const select = document.querySelector("select");
  if (!(select instanceof HTMLSelectElement)) {
    throw new Error("No select element found");
  }
  const option = [...select.options].find((candidate) =>
    (candidate.textContent ?? "").toLowerCase().includes(expected),
  );
  if (!option) {
    throw new Error("Missing option for: " + targetText);
  }
  select.value = option.value;
  select.dispatchEvent(new Event("change", { bubbles: true }));
}
EOF
)" >/dev/null
}

capture_page() {
  local name="$1"
  pw_eval_result '() => document.body.innerText.slice(0, 30000)' >"$output_dir/$name.txt"
  pw screenshot --filename "$output_dir/$name.png" >/dev/null
}

start_vite() {
  if curl -fsS "$base_url" >/dev/null 2>&1; then
    return 0
  fi

  (
    cd "$workbench_dir"
    HUSHD_URL="$hushd_url" \
    HUSHD_API_KEY="$hushd_api_key" \
      npm run dev -- --host 127.0.0.1 --port 1421
  ) >"$vite_log" 2>&1 &
  dev_pid=$!
  wait_for_url "$base_url"
}

clear_browser_state() {
  pw eval "$(cat <<'EOF'
async () => {
  localStorage.clear();
  sessionStorage.clear();
  const databases = [
    "clawdstrike_workbench_signals",
  ];
  await Promise.all(databases.map((name) => new Promise((resolve) => {
    const req = indexedDB.deleteDatabase(name);
    req.onsuccess = () => resolve(null);
    req.onerror = () => resolve(null);
    req.onblocked = () => resolve(null);
  })));
  window.location.reload();
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

  log "Creating operator identity"
  set_input_placeholder "Your name or callsign" "$operator_name"
  click_text "Create Identity"
  wait_for_identity_prompt_gone
}

capture_hushd_status() {
  local target_file="$1"
  curl -fsS \
    -H "Authorization: Bearer $hushd_api_key" \
    "$hushd_url/api/v1/agents/status?include_stale=true" >"$target_file"
}

seed_openclaw_heartbeat() {
  curl -fsS \
    -X POST \
    -H "Authorization: Bearer $hushd_api_key" \
    -H "Content-Type: application/json" \
    "$hushd_url/api/v1/agent/heartbeat" \
    -d "$(cat <<EOF
{"endpoint_agent_id":"$endpoint_id","posture":"strict","daemon_version":"0.2.5","policy_version":"sha256:mission-dogfood"}
EOF
)" >/dev/null

  curl -fsS \
    -X POST \
    -H "Authorization: Bearer $hushd_api_key" \
    -H "Content-Type: application/json" \
    "$hushd_url/api/v1/agent/heartbeat" \
    -d "$(cat <<EOF
{"endpoint_agent_id":"$endpoint_id","runtime_agent_id":"$runtime_id","runtime_agent_kind":"openclaw-gateway"}
EOF
)" >/dev/null
}

connect_hushd() {
  log "Connecting workbench to hushd"
  set_hash "#/settings"
  wait_for_text "Configure connections, preferences, and integrations"
  set_input_placeholder "http://localhost:9876" "$hushd_url"
  set_input_placeholder "hush_..." "$hushd_api_key"
  click_text "Test"
  wait_for_text "Connected — hushd"
  click_text "Connect to Fleet"
  wait_for_text "Fleet Summary"
  capture_page "settings-connected"
}

create_swarm_via_ui() {
  log "Creating mission dogfood swarm"
  set_hash "#/swarms"
  wait_for_text "Swarms"
  if ! click_text "Create Your First Swarm" 2>/dev/null; then
    click_text "Create Swarm"
  fi
  wait_for_text "Swarm Name"
  set_input_placeholder "e.g., SecOps Collective" "$swarm_name"
  click_text_exact "Trusted"
  click_last_text "Create Swarm"
  wait_for_text "$swarm_name"
  capture_page "swarm-created"
}

create_sentinel_via_ui() {
  local mode_label="$1"
  local sentinel_name="$2"
  local goal_description="$3"
  local runtime_target="$4"
  local artifact_name="$5"
  local mode_slug
  mode_slug="$(printf '%s' "$mode_label" | tr '[:upper:]' '[:lower:]')"

  log "Creating ${mode_slug} sentinel: $sentinel_name"
  set_hash "#/sentinels/create"
  wait_for_text "Create Sentinel"
  click_text "$mode_label"
  click_text "Next"
  wait_for_text "Identity & Goals"
  set_input_placeholder "e.g. Aegis, Prowl, Scribe..." "$sentinel_name"
  click_text "Add Goal"
  set_input_placeholder "What should this goal detect/monitor/hunt?" "$goal_description"
  click_text "Next"
  wait_for_text "Runtime Driver"
  if [[ -n "$runtime_target" ]]; then
    if [[ "$mode_label" == "Curator" || "$mode_label" == "Liaison" ]]; then
      set_input_placeholder "Local repo or workspace path" "$runtime_target"
    else
      set_input_placeholder "Gateway URL, node ID, or node label" "$runtime_target"
    fi
  fi
  click_text "Next"
  wait_for_text "Goal Summary"
  click_text "Create Sentinel"
  wait_for_text "$sentinel_name"
  capture_page "$artifact_name"
}

launch_claude_mission() {
  log "Launching blocked Claude mission"
  set_hash "#/missions"
  wait_for_text "Mission Control"
  select_first_option_by_text "$claude_name"
  wait_for_launch_state "blocked"
  set_input_placeholder "Credential harvest triage" "$claude_mission_title"
  set_textarea_placeholder \
    "Describe what the sentinel should verify, collect, or harden." \
    "Inspect the repo lane for a high-confidence fix path and stop at the tool boundary when the bridge is unavailable."
  capture_page "missions-claude-blocked-ready"
  click_text "Launch Blocked Mission"
  wait_for_text "$claude_mission_title"
  wait_for_text "Launch Posture"
  wait_for_launch_state "blocked"
  capture_page "missions-claude-blocked"
}

launch_openclaw_mission() {
  log "Launching ready OpenClaw mission"
  set_hash "#/missions"
  wait_for_text "Mission Control"
  select_first_option_by_text "$openclaw_name"
  wait_for_launch_state "ready"
  set_input_placeholder "Credential harvest triage" "$openclaw_mission_title"
  set_textarea_placeholder \
    "Describe what the sentinel should verify, collect, or harden." \
    "Walk the suspicious login flow, collect runtime evidence, and promote a finding if the broker blocks risky behavior."
  capture_page "missions-openclaw-ready"
  click_text_exact "Launch Mission"
  wait_for_text "$openclaw_mission_title"
  wait_for_text "Brokered Download Block"
  wait_for_text "Findings"
  capture_page "missions-openclaw-launched"
}

promote_openclaw_finding_to_intel() {
  log "Promoting mission finding to intel"
  set_hash "#/findings"
  wait_for_text "Findings"
  local action_state=""
  local elapsed=0

  while (( elapsed < timeout_secs )); do
    action_state="$(read_finding_action_state "$openclaw_finding_title")"
    if [[ "$action_state" == "promote" ]]; then
      break
    fi
    if [[ "$action_state" == "confirm" ]]; then
      click_finding_action "$openclaw_finding_title" "Confirm"
    fi
    sleep 1
    elapsed=$((elapsed + 1))
  done

  if [[ "$action_state" != "promote" ]]; then
    echo "error: timed out waiting for promote action on findings page" >&2
    return 1
  fi

  capture_page "findings-ready"
  click_finding_action "$openclaw_finding_title" "Promote"
  wait_for_first_local_intel_id
  capture_page "finding-promoted"
}

share_intel_to_swarm() {
  local intel_id="$1"

  log "Sharing promoted intel to the swarm"
  set_hash "#/intel/$intel_id"
  wait_for_text "Shareability"
  click_text_exact "Swarm"
  wait_for_button_enabled "Share to Swarm"
  capture_page "intel-share-ready"
  click_text "Share to Swarm"
  capture_page "intel-shared"
  wait_for_swarm_share_state_ready
}

capture_swarm_publish_evidence() {
  local share_state_json="$1"

  printf '%s\n' "$share_state_json" >"$swarm_share_state_file"

  local feed_id issuer_id head_seq
  feed_id="$(
    SHARE_STATE_JSON="$share_state_json" python3 - <<'PY'
import json
import os
print(json.loads(os.environ["SHARE_STATE_JSON"]).get("feedId", ""))
PY
  )"
  issuer_id="$(
    SHARE_STATE_JSON="$share_state_json" python3 - <<'PY'
import json
import os
print(json.loads(os.environ["SHARE_STATE_JSON"]).get("issuerId", ""))
PY
  )"
  head_seq="$(
    SHARE_STATE_JSON="$share_state_json" python3 - <<'PY'
import json
import os
print(json.loads(os.environ["SHARE_STATE_JSON"]).get("headSeq", 0))
PY
  )"

  if [[ -z "$feed_id" || -z "$issuer_id" || "$head_seq" == "0" ]]; then
    echo "error: missing swarm publish metadata after share" >&2
    return 1
  fi

  curl -fsS \
    -H "Authorization: Bearer $hushd_api_key" \
    "$hushd_url/api/v1/swarm/feeds/$(urlencode "$feed_id")/head?issuerId=$(urlencode "$issuer_id")" \
    >"$swarm_head_file"

  curl -fsS \
    -H "Authorization: Bearer $hushd_api_key" \
    "$hushd_url/api/v1/swarm/feeds/$(urlencode "$feed_id")/replay?issuerId=$(urlencode "$issuer_id")&fromSeq=1&toSeq=$head_seq" \
    >"$swarm_replay_file"
}

cleanup() {
  local exit_code=$?

  if [[ "$close_browser_on_exit" == "1" && "$keep_browser" != "1" ]]; then
    pw close >/dev/null 2>&1 || true
  fi

  if [[ "$keep_stack" != "1" ]]; then
    if [[ -n "$dev_pid" ]] && kill -0 "$dev_pid" >/dev/null 2>&1; then
      kill "$dev_pid" >/dev/null 2>&1 || true
      wait "$dev_pid" >/dev/null 2>&1 || true
    fi
  fi

  exit "$exit_code"
}
trap cleanup EXIT

require_cmd curl
require_cmd npx
require_cmd npm
require_cmd python3

log "Capturing live hushd status"
wait_for_url "$hushd_url/health"
capture_hushd_status "$status_before_file"
seed_openclaw_heartbeat
capture_hushd_status "$status_after_file"

if [[ "$start_dev" == "1" ]]; then
  log "Ensuring workbench dev server is up"
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
clear_browser_state
sleep 2
wait_for_text "CLAWDSTRIKE"
ensure_operator_identity

connect_hushd
create_swarm_via_ui
create_sentinel_via_ui \
  "Curator" \
  "$claude_name" \
  "Review the repo for a minimal remediation path and summarize any policy gaps." \
  "$claude_target" \
  "sentinel-claude-created"
create_sentinel_via_ui \
  "Hunter" \
  "$openclaw_name" \
  "Traverse suspicious external flows and collect evidence-backed hunt artifacts." \
  "$openclaw_target" \
  "sentinel-openclaw-created"

launch_claude_mission
launch_openclaw_mission

promoted_intel_id="$(promote_openclaw_finding_to_intel)"
swarm_share_state_json="$(share_intel_to_swarm "$promoted_intel_id")"
capture_swarm_publish_evidence "$swarm_share_state_json"

log "Collecting artifacts and summary"
capture_playwright_report "$console_file" console error
capture_playwright_report "$network_file" network

set_hash "#/missions" 2>/dev/null || true
sleep 2

if claude_launch_state="$(
  pw_eval_result "$(cat <<'EOF'
() => {
  const label = [...document.querySelectorAll("span")]
    .find((el) => (el.textContent ?? "").trim() === "Launch Posture");
  const row = label?.parentElement?.parentElement;
  const stateText = row
    ? ([...row.querySelectorAll("span")].at(-1)?.textContent ?? "").trim().toLowerCase()
    : "";
  if (stateText.includes("blocked")) return "blocked";
  if (stateText.includes("ready")) return "ready";
  if (stateText.includes("degraded")) return "degraded";
  return "unknown";
}
EOF
)" 2>/dev/null
)"; then true; else claude_launch_state="unknown"; fi

set_hash "#/findings" 2>/dev/null || true
sleep 1

if openclaw_finding_links="$(
  pw_eval_result "$(cat <<'EOF'
() => {
  return String(
    [...document.querySelectorAll('a[href*="#/findings/"], a[href*="/findings/"]')].length,
  );
}
EOF
)" 2>/dev/null
)"; then true; else openclaw_finding_links="0"; fi

RUN_ID="$run_id" \
SESSION="$session" \
BASE_URL="$base_url" \
HUSHD_URL="$hushd_url" \
CLAUDE_NAME="$claude_name" \
CLAUDE_MISSION_TITLE="$claude_mission_title" \
CLAUDE_LAUNCH_STATE="$claude_launch_state" \
OPENCLAW_NAME="$openclaw_name" \
OPENCLAW_MISSION_TITLE="$openclaw_mission_title" \
OPENCLAW_FINDING_LINKS="$openclaw_finding_links" \
PROMOTED_INTEL_ID="$promoted_intel_id" \
ENDPOINT_ID="$endpoint_id" \
RUNTIME_ID="$runtime_id" \
SWARM_NAME="$swarm_name" \
STATUS_BEFORE_FILE="$status_before_file" \
STATUS_AFTER_FILE="$status_after_file" \
SWARM_SHARE_STATE_FILE="$swarm_share_state_file" \
SWARM_HEAD_FILE="$swarm_head_file" \
SWARM_REPLAY_FILE="$swarm_replay_file" \
OUTPUT_DIR="$output_dir" \
SUMMARY_FILE="$summary_file" \
python3 - <<'PY'
import json
import os
from pathlib import Path

status_before = json.loads(Path(os.environ.get("STATUS_BEFORE_FILE", "")).read_text()) if os.environ.get("STATUS_BEFORE_FILE") else {}
status_after = json.loads(Path(os.environ.get("STATUS_AFTER_FILE", "")).read_text()) if os.environ.get("STATUS_AFTER_FILE") else {}
swarm_share_state = json.loads(Path(os.environ.get("SWARM_SHARE_STATE_FILE", "")).read_text()) if os.environ.get("SWARM_SHARE_STATE_FILE") else {}
swarm_head = json.loads(Path(os.environ.get("SWARM_HEAD_FILE", "")).read_text()) if os.environ.get("SWARM_HEAD_FILE") else {}
swarm_replay = json.loads(Path(os.environ.get("SWARM_REPLAY_FILE", "")).read_text()) if os.environ.get("SWARM_REPLAY_FILE") else {}

claude_launch_state = os.environ.get("CLAUDE_LAUNCH_STATE", "unknown")
if len(claude_launch_state) > 200:
    claude_launch_state = claude_launch_state[:200] + "..."

try:
    finding_links = int(os.environ.get("OPENCLAW_FINDING_LINKS", "0"))
except ValueError:
    finding_links = 0

summary = {
    "status": "ok",
    "run_id": os.environ.get("RUN_ID", ""),
    "session": os.environ.get("SESSION", ""),
    "base_url": os.environ.get("BASE_URL", ""),
    "hushd_url": os.environ.get("HUSHD_URL", ""),
    "claude": {
        "sentinel_name": os.environ.get("CLAUDE_NAME", ""),
        "mission_title": os.environ.get("CLAUDE_MISSION_TITLE", ""),
        "launch_state": claude_launch_state,
        "expected_runtime": "blocked_in_web_runtime",
    },
    "openclaw": {
        "sentinel_name": os.environ.get("OPENCLAW_NAME", ""),
        "mission_title": os.environ.get("OPENCLAW_MISSION_TITLE", ""),
        "finding_links": finding_links,
        "promoted_intel_id": os.environ.get("PROMOTED_INTEL_ID", ""),
        "seeded_endpoint_id": os.environ.get("ENDPOINT_ID", ""),
        "seeded_runtime_id": os.environ.get("RUNTIME_ID", ""),
    },
    "swarm": {
        "name": os.environ.get("SWARM_NAME", ""),
        "shared_intel_count": swarm_share_state.get("sharedIntelCount", 0),
        "finding_envelope_count": swarm_share_state.get("findingEnvelopeCount", 0),
        "head_announcement_count": swarm_share_state.get("headAnnouncementCount", 0),
        "feed_id": swarm_share_state.get("feedId"),
        "issuer_id": swarm_share_state.get("issuerId"),
        "finding_id": swarm_share_state.get("findingId"),
        "head_seq": swarm_share_state.get("headSeq"),
        "remote_head_seq": swarm_head.get("headSeq"),
        "replay_envelope_count": len(swarm_replay.get("envelopes", [])),
    },
    "hushd": {
        "endpoints_before": len(status_before.get("endpoints", [])),
        "endpoints_after": len(status_after.get("endpoints", [])),
        "online_after": sum(1 for item in status_after.get("endpoints", []) if item.get("online")),
        "runtimes_after": len(status_after.get("runtimes", [])),
    },
    "output_dir": os.environ.get("OUTPUT_DIR", ""),
    "artifacts": {
        "settings_connected": "settings-connected.png",
        "swarm_created": "swarm-created.png",
        "sentinel_claude_created": "sentinel-claude-created.png",
        "sentinel_openclaw_created": "sentinel-openclaw-created.png",
        "missions_claude_blocked_ready": "missions-claude-blocked-ready.png",
        "missions_claude_blocked": "missions-claude-blocked.png",
        "missions_openclaw_ready": "missions-openclaw-ready.png",
        "missions_openclaw_launched": "missions-openclaw-launched.png",
        "findings_ready": "findings-ready.png",
        "finding_promoted": "finding-promoted.png",
        "intel_share_ready": "intel-share-ready.png",
        "intel_shared": "intel-shared.png",
        "console_errors": "console-errors.txt",
        "network": "network.txt",
        "hushd_status_before": "hushd-status-before.json",
        "hushd_status_after": "hushd-status-after.json",
        "swarm_share_state": "swarm-share-state.json",
        "swarm_head": "swarm-head.json",
        "swarm_replay": "swarm-replay.json",
    },
}

summary_file = os.environ.get("SUMMARY_FILE", "")
if summary_file:
    Path(summary_file).write_text(json.dumps(summary, indent=2) + "\n")
print(json.dumps(summary, indent=2))
PY
