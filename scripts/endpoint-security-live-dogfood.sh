#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
agent_url="${CLAWDSTRIKE_AGENT_URL:-http://127.0.0.1:9878}"
run_id="${CLAWDSTRIKE_ES_DOGFOOD_RUN_ID:-$(date -u '+%Y%m%dT%H%M%SZ')}"
run_id_slug="$(printf '%s' "$run_id" | tr -c '[:alnum:]_' '-')"
output_dir="${CLAWDSTRIKE_ES_DOGFOOD_OUTPUT_DIR:-$repo_root/output/dogfood/endpoint-security-live/$run_id}"
if [[ "$(uname -s)" == "Darwin" && -z "${XDG_CONFIG_HOME:-}" ]]; then
  default_config_dir="$HOME/Library/Application Support/clawdstrike"
else
  default_config_dir="${XDG_CONFIG_HOME:-$HOME/.config}/clawdstrike"
fi
token_file="${CLAWDSTRIKE_AGENT_TOKEN_FILE:-$default_config_dir/agent-local-token}"
connect_timeout="${CLAWDSTRIKE_ES_DOGFOOD_CONNECT_TIMEOUT:-3}"
api_timeout="${CLAWDSTRIKE_ES_DOGFOOD_API_TIMEOUT:-30}"
poll_attempts="${CLAWDSTRIKE_ES_DOGFOOD_POLL_ATTEMPTS:-12}"
poll_sleep_secs="${CLAWDSTRIKE_ES_DOGFOOD_POLL_SLEEP_SECS:-2}"
require_healthy_provider="${CLAWDSTRIKE_ES_DOGFOOD_REQUIRE_HEALTHY_PROVIDER:-1}"
allow_bootstrap_provider="${CLAWDSTRIKE_ES_DOGFOOD_ALLOW_BOOTSTRAP_PROVIDER:-1}"
auth_open_observer_mode="${CLAWDSTRIKE_ES_DOGFOOD_OBSERVE_AUTH_OPEN:-auto}"
auth_open_observer_tool="${CLAWDSTRIKE_ES_DOGFOOD_STATUS_TOOL:-${CLAWDSTRIKE_ENDPOINT_SECURITY_STATUS_TOOL:-}}"
auth_open_observer_seconds="${CLAWDSTRIKE_ES_DOGFOOD_OBSERVE_SECONDS:-}"
auth_open_observer_snapshot_path="${CLAWDSTRIKE_ENDPOINT_SECURITY_RUNTIME_SNAPSHOT_PATH:-}"
allow_non_macos="${CLAWDSTRIKE_ES_DOGFOOD_ALLOW_NON_MACOS:-0}"
keep_probe="${CLAWDSTRIKE_ES_DOGFOOD_KEEP_PROBE:-0}"
probe_parent="${CLAWDSTRIKE_ES_DOGFOOD_PROBE_PARENT:-/tmp}"
marker="clawdstrike-es-dogfood-$run_id_slug"
probe_dir="$probe_parent/$marker"
probe_file="$probe_dir/$marker.txt"
auth_open_observer_pid=""
auth_open_observer_started=0
auth_open_observer_command=""
auth_open_observer_stdout_file="$output_dir/auth-open-observer.stdout.json"
auth_open_observer_stderr_file="$output_dir/auth-open-observer.stderr.log"
auth_open_observer_start_marker="$output_dir/auth-open-observer.started"

summary_written=0
last_flight_file=""
last_graph_file=""
last_match_file=""
last_receipts_file=""
last_receipt_match_file=""
before_observation_count=""
after_observation_count=""

log() {
  printf '[es-dogfood] %s\n' "$*" >&2
}

die() {
  log "ERROR: $*"
  exit 1
}

require_cmd() {
  command -v "$1" >/dev/null 2>&1 || die "required command not found: $1"
}

require_positive_int() {
  local name="$1"
  local value="$2"
  [[ "$value" =~ ^[1-9][0-9]*$ ]] || die "$name must be a positive integer, got: $value"
}

require_nonnegative_int() {
  local name="$1"
  local value="$2"
  [[ "$value" =~ ^[0-9]+$ ]] || die "$name must be a non-negative integer, got: $value"
}

require_run_id() {
  local name="$1"
  local value="$2"
  [[ "$value" =~ ^[0-9]{8}T[0-9]{6}Z$ ]] || die "$name must use YYYYMMDDTHHMMSSZ, got: $value"
}

require_positive_number() {
  local name="$1"
  local value="$2"
  python3 - "$name" "$value" <<'PY'
import sys

name, value = sys.argv[1:]
try:
    parsed = float(value)
except ValueError:
    raise SystemExit(f"{name} must be a positive number, got: {value}")
if parsed <= 0:
    raise SystemExit(f"{name} must be a positive number, got: {value}")
PY
}

default_endpoint_security_runtime_snapshot_path() {
  if [[ "$(uname -s)" == "Darwin" ]]; then
    printf '%s\n' "$HOME/Library/Application Support/clawdstrike/edr/endpoint-security-runtime.json"
  else
    printf '%s\n' "${XDG_CONFIG_HOME:-$HOME/.config}/clawdstrike/edr/endpoint-security-runtime.json"
  fi
}

compute_auth_open_observer_seconds() {
  python3 - "$poll_attempts" "$poll_sleep_secs" <<'PY'
import sys

poll_attempts = int(sys.argv[1])
poll_sleep_secs = int(sys.argv[2])
print(max(120, poll_attempts * (poll_sleep_secs + 5) + 30))
PY
}

validate_auth_open_observer_mode() {
  case "$auth_open_observer_mode" in
    auto|0|1|false|true|no|yes) ;;
    *) die "CLAWDSTRIKE_ES_DOGFOOD_OBSERVE_AUTH_OPEN must be auto, 0, or 1; got: $auth_open_observer_mode" ;;
  esac
}

usage() {
  cat >&2 <<'USAGE'
Usage:
  scripts/endpoint-security-live-dogfood.sh

Environment:
  CLAWDSTRIKE_AGENT_URL                         default: http://127.0.0.1:9878
  CLAWDSTRIKE_AGENT_TOKEN                       bearer token; otherwise read token file
  CLAWDSTRIKE_AGENT_TOKEN_FILE                  default: platform config dir / clawdstrike / agent-local-token
  CLAWDSTRIKE_ES_DOGFOOD_RUN_ID                 override YYYYMMDDTHHMMSSZ run ID for combined QA bundles
  CLAWDSTRIKE_ES_DOGFOOD_API_TIMEOUT            default: 30
  CLAWDSTRIKE_ES_DOGFOOD_POLL_ATTEMPTS          default: 12
  CLAWDSTRIKE_ES_DOGFOOD_POLL_SLEEP_SECS        default: 2
  CLAWDSTRIKE_ES_DOGFOOD_REQUIRE_HEALTHY_PROVIDER=0
                                                 skip strict provider precondition for debugging
  CLAWDSTRIKE_ES_DOGFOOD_ALLOW_BOOTSTRAP_PROVIDER=0
                                                 require healthy=true before the probe instead of
                                                 allowing live_authorization_signal_missing bootstrap
  CLAWDSTRIKE_ES_DOGFOOD_OBSERVE_AUTH_OPEN       auto|0|1; default: auto
                                                 auto starts a managed observer only when a status
                                                 tool path is supplied; 1 requires one or falls back
                                                 to swift run for local development
  CLAWDSTRIKE_ES_DOGFOOD_STATUS_TOOL             path to a signed endpoint-security-status-tool
                                                 (CLAWDSTRIKE_ENDPOINT_SECURITY_STATUS_TOOL also works)
  CLAWDSTRIKE_ES_DOGFOOD_OBSERVE_SECONDS         managed observer runtime; default derives from polling
  CLAWDSTRIKE_ENDPOINT_SECURITY_RUNTIME_SNAPSHOT_PATH
                                                 runtime snapshot path shared with the agent collector
  CLAWDSTRIKE_ES_DOGFOOD_PROBE_PARENT           default: /tmp
  CLAWDSTRIKE_ES_DOGFOOD_KEEP_PROBE=1           leave the probe directory for manual inspection

The script does not submit synthetic EndpointSecurity events. It requires the
local agent, checks macOS EndpointSecurity provider state, creates a unique
benign file/process probe, then polls the agent flight recorder and causal
graph plus the receipt ledger for a provider-delivered observation receipt
containing that probe path. When a managed AUTH_OPEN observer is enabled, the
script starts it before the provider precondition, passes the agent token and
shared runtime snapshot path, and tears it down on exit. A passing run also
writes summary-verification.json after rechecking the summary artifact.
USAGE
}

if [[ "${1:-}" == "-h" || "${1:-}" == "--help" ]]; then
  usage
  exit 0
fi

if [[ "$#" -gt 0 ]]; then
  usage
  exit 2
fi

require_cmd curl
require_cmd date
require_cmd dirname
require_cmd hostname
require_cmd mkdir
require_cmd python3
require_cmd rm
require_cmd tr
require_cmd uname

require_positive_number "CLAWDSTRIKE_ES_DOGFOOD_CONNECT_TIMEOUT" "$connect_timeout"
require_positive_number "CLAWDSTRIKE_ES_DOGFOOD_API_TIMEOUT" "$api_timeout"
require_positive_int "CLAWDSTRIKE_ES_DOGFOOD_POLL_ATTEMPTS" "$poll_attempts"
require_nonnegative_int "CLAWDSTRIKE_ES_DOGFOOD_POLL_SLEEP_SECS" "$poll_sleep_secs"
require_run_id "CLAWDSTRIKE_ES_DOGFOOD_RUN_ID" "$run_id"
validate_auth_open_observer_mode
if [[ -z "$auth_open_observer_seconds" ]]; then
  auth_open_observer_seconds="$(compute_auth_open_observer_seconds)"
fi
require_positive_number "CLAWDSTRIKE_ES_DOGFOOD_OBSERVE_SECONDS" "$auth_open_observer_seconds"
if [[ -z "$auth_open_observer_snapshot_path" ]]; then
  auth_open_observer_snapshot_path="$(default_endpoint_security_runtime_snapshot_path)"
fi

if [[ "$(uname -s)" != "Darwin" && "$allow_non_macos" != "1" ]]; then
  die "EndpointSecurity dogfood must run on macOS; set CLAWDSTRIKE_ES_DOGFOOD_ALLOW_NON_MACOS=1 only for syntax/debug dry work"
fi

mkdir -p "$output_dir"

agent_token="${CLAWDSTRIKE_AGENT_TOKEN:-}"
if [[ -z "$agent_token" ]]; then
  [[ -f "$token_file" ]] || die "agent token not set and token file missing: $token_file"
  agent_token="$(tr -d '[:space:]' < "$token_file")"
fi
[[ -n "$agent_token" ]] || die "agent token is empty"

host_id="${CLAWDSTRIKE_ES_DOGFOOD_HOST_ID:-$(hostname -s 2>/dev/null || hostname)}"
user_id="${CLAWDSTRIKE_ES_DOGFOOD_USER_ID:-${USER:-operator}}"

health_file="$output_dir/agent-health.json"
protection_file="$output_dir/protection-state.json"
provider_file="$output_dir/endpoint-security-provider.json"
graph_payload="$output_dir/causal-graph-request.json"
before_flight_file="$output_dir/flight-recorder-before.json"
before_graph_file="$output_dir/causal-graph-before.json"
summary_file="$output_dir/summary.json"
probe_activity_file="$output_dir/probe-activity.json"

curl_json() {
  local method="$1"
  local path="$2"
  local request_body="$3"
  local response_body="$4"
  local status

  if [[ -n "$request_body" ]]; then
    status="$(curl -sS -o "$response_body" -w '%{http_code}' \
      -X "$method" \
      --connect-timeout "$connect_timeout" \
      --max-time "$api_timeout" \
      -H "Authorization: Bearer $agent_token" \
      -H "Content-Type: application/json" \
      --data-binary "@$request_body" \
      "${agent_url%/}$path")" || return 1
  else
    status="$(curl -sS -o "$response_body" -w '%{http_code}' \
      -X "$method" \
      --connect-timeout "$connect_timeout" \
      --max-time "$api_timeout" \
      -H "Authorization: Bearer $agent_token" \
      "${agent_url%/}$path")" || return 1
  fi

  case "$status" in
    2*) return 0 ;;
    *)
      log "$method $path returned HTTP $status; response saved to $response_body"
      return 2
      ;;
  esac
}

write_graph_payload() {
  python3 - "$graph_payload" <<'PY'
import json
import sys

with open(sys.argv[1], "w", encoding="utf-8") as handle:
    json.dump({"observations": []}, handle, indent=2, sort_keys=True)
    handle.write("\n")
PY
}

flight_observation_count() {
  python3 - "$1" <<'PY'
import json
import sys

with open(sys.argv[1], "r", encoding="utf-8") as handle:
    payload = json.load(handle)
value = payload.get("observation_count", payload.get("observationCount"))
if not isinstance(value, int):
    raise SystemExit("flight recorder response is missing observation_count")
print(value)
PY
}

verify_endpoint_security_provider() {
  python3 - "$protection_file" "$provider_file" "$require_healthy_provider" "$allow_bootstrap_provider" <<'PY'
import json
import sys

protection_path, provider_path, require_healthy, allow_bootstrap = sys.argv[1:]
with open(protection_path, "r", encoding="utf-8") as handle:
    payload = json.load(handle)
sensor_state = payload.get("sensor_state") or payload.get("sensorState") or {}
providers = sensor_state.get("providers") or []
provider = next(
    (item for item in providers if item.get("providerId") == "macos.endpoint_security"),
    None,
)
if provider is None:
    raise SystemExit("missing macos.endpoint_security provider in protection state")
with open(provider_path, "w", encoding="utf-8") as handle:
    json.dump(provider, handle, indent=2, sort_keys=True)
    handle.write("\n")

if require_healthy != "1":
    print("provider precondition skipped")
    raise SystemExit(0)

failures = []
if provider.get("installed") is not True:
    failures.append("installed=false")
if provider.get("active") is not True:
    failures.append("active=false")
if provider.get("fullDiskAccess") is False:
    failures.append("fullDiskAccess=false")
reasons = provider.get("degradationReasons") or provider.get("degradedReasons") or []
reason_set = {str(reason) for reason in reasons}
bootstrap_only = reason_set == {"live_authorization_signal_missing"}
if provider.get("healthy") is not True or provider.get("degraded") is True:
    if allow_bootstrap == "1" and not failures and bootstrap_only:
        print("provider bootstrap precondition satisfied: live authorization signal missing")
        raise SystemExit(0)
    if provider.get("healthy") is not True:
        failures.append("healthy=false")
    if provider.get("degraded") is True:
        failures.append("degraded=true")
if failures:
    if reasons:
        failures.append("reasons=" + ",".join(str(reason) for reason in reasons))
    raise SystemExit("; ".join(failures))
print("provider precondition satisfied")
PY
}

trigger_probe_activity() {
  python3 - "$probe_dir" "$probe_file" "$marker" "$probe_activity_file" \
    "$host_id" "$user_id" "$agent_url" <<'PY'
import datetime as dt
import json
import pathlib
import subprocess
import sys

probe_dir, probe_file, marker, output, host_id, user_id, agent_url = sys.argv[1:]
probe_dir_path = pathlib.Path(probe_dir)
probe_file_path = pathlib.Path(probe_file)
probe_dir_path.mkdir(parents=True, exist_ok=True)
payload = f"ClawdStrike EndpointSecurity dogfood marker: {marker}\n"
probe_file_path.write_text(payload, encoding="utf-8")
probe_file_path.chmod(0o600)

commands = []
for command in (["/bin/ls", "-l", str(probe_file_path)], ["/usr/bin/stat", str(probe_file_path)]):
    try:
        completed = subprocess.run(command, check=False, capture_output=True, text=True, timeout=5)
        commands.append(
            {
                "argv": command,
                "exitCode": completed.returncode,
                "stdoutBytes": len(completed.stdout.encode("utf-8")),
                "stderrBytes": len(completed.stderr.encode("utf-8")),
            }
        )
    except FileNotFoundError:
        commands.append({"argv": command, "error": "not_found"})

_ = probe_file_path.read_text(encoding="utf-8")
summary = {
    "marker": marker,
    "probeDir": str(probe_dir_path),
    "probeFile": str(probe_file_path),
    "triggeredAt": dt.datetime.now(dt.timezone.utc).isoformat().replace("+00:00", "Z"),
    "hostId": host_id,
    "userId": user_id,
    "agentUrl": agent_url,
    "commands": commands,
}
with open(output, "w", encoding="utf-8") as handle:
    json.dump(summary, handle, indent=2, sort_keys=True)
    handle.write("\n")
PY
}

graph_match_probe() {
  local graph_file="$1"
  local flight_file="$2"
  local match_file="$3"
  python3 - "$graph_file" "$flight_file" "$match_file" "$probe_file" "$marker" "$before_observation_count" <<'PY'
import json
import sys

graph_path, flight_path, match_path, probe_file, marker, before_count_text = sys.argv[1:]
with open(graph_path, "r", encoding="utf-8") as handle:
    graph_payload = json.load(handle)
with open(flight_path, "r", encoding="utf-8") as handle:
    flight_payload = json.load(handle)

before_count = int(before_count_text)
after_count = flight_payload.get("observation_count", flight_payload.get("observationCount"))
if not isinstance(after_count, int):
    raise SystemExit("flight recorder response is missing observation count")

nodes = (graph_payload.get("graph") or {}).get("nodes") or {}
if isinstance(nodes, dict):
    node_items = list(nodes.items())
else:
    node_items = [(str(index), node) for index, node in enumerate(nodes)]

matches = []
for node_id, node in node_items:
    if not isinstance(node, dict):
        continue
    label = str(node.get("label") or "")
    attributes = node.get("attributes") or {}
    rendered = json.dumps({"label": label, "attributes": attributes}, sort_keys=True)
    if probe_file == label or marker in label or marker in rendered:
        matches.append(
            {
                "nodeId": node_id,
                "kind": node.get("kind"),
                "label": label,
                "matchedProbeFile": probe_file == label,
                "matchedMarker": marker in label or marker in rendered,
            }
        )

result = {
    "probeFile": probe_file,
    "marker": marker,
    "beforeObservationCount": before_count,
    "afterObservationCount": after_count,
    "observationCountIncreased": after_count > before_count,
    "matchedNodeCount": len(matches),
    "matches": matches[:20],
}
with open(match_path, "w", encoding="utf-8") as handle:
    json.dump(result, handle, indent=2, sort_keys=True)
    handle.write("\n")

if not result["observationCountIncreased"] or not matches:
    raise SystemExit(1)
PY
}

receipt_match_probe() {
  local receipts_file="$1"
  local match_file="$2"
  python3 - "$receipts_file" "$match_file" "$probe_file" <<'PY'
import hashlib
import json
import sys

receipts_path, match_path, probe_file = sys.argv[1:]
with open(receipts_path, "r", encoding="utf-8") as handle:
    payload = json.load(handle)

target_hash = "sha256:" + hashlib.sha256(probe_file.encode("utf-8")).hexdigest()
accepted_rules = {
    "endpoint.observation.file_access",
    "endpoint.observation.policy_decision",
}
matches = []
for receipt in payload.get("receipts") or []:
    endpoint = (
        ((receipt.get("receipt") or {}).get("metadata") or {}).get("endpointDecision")
        or {}
    )
    if endpoint.get("receiptFamily") != "observation":
        continue
    providers = ((endpoint.get("sensorState") or {}).get("providers") or [])
    if not any(provider.get("providerId") == "macos.endpoint_security" for provider in providers):
        continue
    rule_id = (endpoint.get("decision") or {}).get("ruleId")
    if rule_id not in accepted_rules:
        continue
    evidence = endpoint.get("evidence") or []
    if not any(
        item.get("key") == "target" and item.get("valueHash") == target_hash
        for item in evidence
    ):
        continue
    matches.append(
        {
            "receiptId": (receipt.get("receipt") or {}).get("receiptId"),
            "ruleId": rule_id,
            "observationId": (endpoint.get("decision") or {}).get("observationId"),
            "providerId": "macos.endpoint_security",
            "targetHash": target_hash,
        }
    )

result = {
    "probeFile": probe_file,
    "targetHash": target_hash,
    "matchedReceiptCount": len(matches),
    "matches": matches[:20],
}
with open(match_path, "w", encoding="utf-8") as handle:
    json.dump(result, handle, indent=2, sort_keys=True)
    handle.write("\n")

if not matches:
    raise SystemExit(1)
PY
}

start_auth_open_observer() {
  case "$auth_open_observer_mode" in
    0|false|no)
      log "Managed AUTH_OPEN observer disabled; expecting an installed EndpointSecurity provider to publish observations"
      return 0
      ;;
    auto)
      if [[ -z "$auth_open_observer_tool" ]]; then
        log "Managed AUTH_OPEN observer not started; set CLAWDSTRIKE_ES_DOGFOOD_STATUS_TOOL or CLAWDSTRIKE_ES_DOGFOOD_OBSERVE_AUTH_OPEN=1 to run it from the harness"
        return 0
      fi
      ;;
    1|true|yes) ;;
  esac

  mkdir -p "$(dirname "$auth_open_observer_snapshot_path")"
  : > "$auth_open_observer_start_marker"

  if [[ -n "$auth_open_observer_tool" ]]; then
    [[ -x "$auth_open_observer_tool" ]] \
      || die "managed AUTH_OPEN observer tool is not executable: $auth_open_observer_tool"
    auth_open_observer_command="$auth_open_observer_tool observe-auth-open $auth_open_observer_seconds"
    log "Starting managed AUTH_OPEN observer with $auth_open_observer_tool for ${auth_open_observer_seconds}s"
    env \
      "CLAWDSTRIKE_AGENT_URL=$agent_url" \
      "CLAWDSTRIKE_ENDPOINT_SECURITY_AGENT_URL=$agent_url" \
      "CLAWDSTRIKE_AGENT_TOKEN=$agent_token" \
      "CLAWDSTRIKE_AGENT_TOKEN_FILE=$token_file" \
      "CLAWDSTRIKE_ENDPOINT_SECURITY_RUNTIME_SNAPSHOT_PATH=$auth_open_observer_snapshot_path" \
      "CLAWDSTRIKE_ENDPOINT_SECURITY_OBSERVE_SECONDS=$auth_open_observer_seconds" \
      "$auth_open_observer_tool" observe-auth-open "$auth_open_observer_seconds" \
      >"$auth_open_observer_stdout_file" 2>"$auth_open_observer_stderr_file" &
  else
    require_cmd swift
    local package_path="$repo_root/apps/agent/src-tauri/macos/system-extension/endpoint-security"
    auth_open_observer_command="swift run --disable-sandbox --package-path $package_path endpoint-security-status-tool observe-auth-open $auth_open_observer_seconds"
    log "Starting managed AUTH_OPEN observer with swift run for ${auth_open_observer_seconds}s"
    env \
      "CLAWDSTRIKE_AGENT_URL=$agent_url" \
      "CLAWDSTRIKE_ENDPOINT_SECURITY_AGENT_URL=$agent_url" \
      "CLAWDSTRIKE_AGENT_TOKEN=$agent_token" \
      "CLAWDSTRIKE_AGENT_TOKEN_FILE=$token_file" \
      "CLAWDSTRIKE_ENDPOINT_SECURITY_RUNTIME_SNAPSHOT_PATH=$auth_open_observer_snapshot_path" \
      "CLAWDSTRIKE_ENDPOINT_SECURITY_OBSERVE_SECONDS=$auth_open_observer_seconds" \
      "CLANG_MODULE_CACHE_PATH=${CLANG_MODULE_CACHE_PATH:-/private/tmp/clawdstrike-clang-module-cache}" \
      swift run --disable-sandbox --package-path "$package_path" endpoint-security-status-tool observe-auth-open "$auth_open_observer_seconds" \
      >"$auth_open_observer_stdout_file" 2>"$auth_open_observer_stderr_file" &
  fi

  auth_open_observer_pid=$!
  auth_open_observer_started=1

  local ready_attempt=1
  while [[ "$ready_attempt" -le 10 ]]; do
    if python3 - "$auth_open_observer_snapshot_path" "$auth_open_observer_start_marker" <<'PY'
import os
import sys

snapshot_path, marker_path = sys.argv[1:]
if not os.path.exists(snapshot_path):
    raise SystemExit(1)
if os.path.getmtime(snapshot_path) < os.path.getmtime(marker_path):
    raise SystemExit(1)
PY
    then
      log "Managed AUTH_OPEN observer wrote runtime snapshot: $auth_open_observer_snapshot_path"
      return 0
    fi
    if ! kill -0 "$auth_open_observer_pid" 2>/dev/null; then
      local observer_status=0
      wait "$auth_open_observer_pid" 2>/dev/null || observer_status=$?
      die "managed AUTH_OPEN observer exited before readiness (status $observer_status); see $auth_open_observer_stderr_file"
    fi
    sleep 1
    ready_attempt=$((ready_attempt + 1))
  done

  die "managed AUTH_OPEN observer did not write runtime snapshot at $auth_open_observer_snapshot_path; see $auth_open_observer_stderr_file"
}

stop_auth_open_observer() {
  if [[ "$auth_open_observer_started" != "1" || -z "$auth_open_observer_pid" ]]; then
    return 0
  fi
  if kill -0 "$auth_open_observer_pid" 2>/dev/null; then
    kill "$auth_open_observer_pid" 2>/dev/null || true
  fi
  wait "$auth_open_observer_pid" 2>/dev/null || true
}

write_summary() {
  local status="$1"
  python3 - "$summary_file" "$status" "$run_id" "$output_dir" "$probe_file" "$marker" \
    "$provider_file" "$before_flight_file" "$last_flight_file" "$last_graph_file" \
    "$last_match_file" "$last_receipts_file" "$last_receipt_match_file" "$probe_activity_file" \
    "$keep_probe" "$auth_open_observer_mode" "$auth_open_observer_started" \
    "$auth_open_observer_pid" "$auth_open_observer_seconds" "$auth_open_observer_snapshot_path" \
    "$auth_open_observer_stdout_file" "$auth_open_observer_stderr_file" \
    "$auth_open_observer_command" "$host_id" "$user_id" "$agent_url" "$health_file" <<'PY'
import json
import os
import sys

(
    output,
    status,
    run_id,
    output_dir,
    probe_file,
    marker,
    provider_file,
    before_flight_file,
    last_flight_file,
    last_graph_file,
    last_match_file,
    last_receipts_file,
    last_receipt_match_file,
    probe_activity_file,
    keep_probe,
    auth_open_observer_mode,
    auth_open_observer_started,
    auth_open_observer_pid,
    auth_open_observer_seconds,
    auth_open_observer_snapshot_path,
    auth_open_observer_stdout_file,
    auth_open_observer_stderr_file,
    auth_open_observer_command,
    host_id,
    user_id,
    agent_url,
    health_file,
) = sys.argv[1:]

def read_json(path):
    if path and os.path.exists(path):
        with open(path, "r", encoding="utf-8") as handle:
            return json.load(handle)
    return None

provider = read_json(provider_file)
before_flight = read_json(before_flight_file)
last_flight = read_json(last_flight_file)
match = read_json(last_match_file)
receipt_match = read_json(last_receipt_match_file)
activity = read_json(probe_activity_file)
summary = {
    "runId": run_id,
    "status": status,
    "outputDir": output_dir,
    "hostId": host_id,
    "userId": user_id,
    "agentUrl": agent_url,
    "agentHealth": health_file if health_file and os.path.exists(health_file) else None,
    "protectionState": protection_file if protection_file and os.path.exists(protection_file) else None,
    "probeFile": probe_file,
    "marker": marker,
    "provider": provider,
    "beforeObservationCount": (before_flight or {}).get("observation_count"),
    "afterObservationCount": (last_flight or {}).get("observation_count"),
    "graphResponse": last_graph_file or None,
    "receiptResponse": last_receipts_file or None,
    "match": match,
    "receiptMatch": receipt_match,
    "probeActivityArtifact": probe_activity_file if probe_activity_file and os.path.exists(probe_activity_file) else None,
    "probeActivity": activity,
    "probeKept": keep_probe == "1",
    "authOpenObserver": {
        "mode": auth_open_observer_mode,
        "started": auth_open_observer_started == "1",
        "pid": int(auth_open_observer_pid) if auth_open_observer_pid else None,
        "seconds": float(auth_open_observer_seconds),
        "runtimeSnapshotPath": auth_open_observer_snapshot_path,
        "stdout": auth_open_observer_stdout_file or None,
        "stderr": auth_open_observer_stderr_file or None,
        "command": auth_open_observer_command or None,
    },
    "syntheticEndpointSecurityPostUsed": False,
}
with open(output, "w", encoding="utf-8") as handle:
    json.dump(summary, handle, indent=2, sort_keys=True)
    handle.write("\n")
PY
  summary_written=1
}

cleanup() {
  local status=$?
  stop_auth_open_observer || true
  if [[ "$summary_written" != "1" ]]; then
    if [[ "$status" -eq 0 ]]; then
      write_summary "passed" || true
    else
      write_summary "failed" || true
    fi
  fi
  if [[ "$keep_probe" != "1" && -d "$probe_dir" ]]; then
    rm -rf "$probe_dir" || true
  fi
  exit "$status"
}
trap cleanup EXIT

write_graph_payload

log "Output: $output_dir"
log "Checking agent health at ${agent_url%/}/api/v1/agent/health"
curl -sS --connect-timeout "$connect_timeout" --max-time "$api_timeout" \
  -o "$health_file" "${agent_url%/}/api/v1/agent/health" >/dev/null \
  || die "agent health check failed"

start_auth_open_observer

log "Checking EndpointSecurity provider state"
curl_json "GET" "/api/v1/agent/edr/protection-state" "" "$protection_file" \
  || die "protection-state request failed; see $protection_file"
verify_endpoint_security_provider \
  || die "EndpointSecurity provider is not ready for live dogfood; see $provider_file"

if [[ "$require_healthy_provider" != "1" ]]; then
  log "EndpointSecurity provider precondition was skipped by environment"
fi

log "Capturing flight-recorder and graph baseline"
curl_json "GET" "/api/v1/agent/edr/flight-recorder" "" "$before_flight_file" \
  || die "flight-recorder baseline failed; see $before_flight_file"
curl_json "POST" "/api/v1/agent/edr/causal-graph" "$graph_payload" "$before_graph_file" \
  || die "causal-graph baseline failed; see $before_graph_file"
before_observation_count="$(flight_observation_count "$before_flight_file")"

log "Triggering benign EndpointSecurity probe at $probe_file"
trigger_probe_activity

matched=0
attempt=1
while [[ "$attempt" -le "$poll_attempts" ]]; do
  flight_file="$output_dir/flight-recorder-attempt-$attempt.json"
  graph_file="$output_dir/causal-graph-attempt-$attempt.json"
  match_file="$output_dir/graph-match-attempt-$attempt.json"
  receipts_file="$output_dir/observation-receipts-attempt-$attempt.json"
  receipt_match_file="$output_dir/receipt-match-attempt-$attempt.json"
  if curl_json "GET" "/api/v1/agent/edr/flight-recorder" "" "$flight_file" \
    && curl_json "POST" "/api/v1/agent/edr/causal-graph" "$graph_payload" "$graph_file" \
    && curl_json "GET" "/api/v1/agent/edr/receipts?family=observation&limit=100" "" "$receipts_file"; then
    last_flight_file="$flight_file"
    last_graph_file="$graph_file"
    last_match_file="$match_file"
    last_receipts_file="$receipts_file"
    last_receipt_match_file="$receipt_match_file"
    after_observation_count="$(flight_observation_count "$flight_file")"
    graph_matched=0
    receipt_matched=0
    graph_match_probe "$graph_file" "$flight_file" "$match_file" && graph_matched=1
    receipt_match_probe "$receipts_file" "$receipt_match_file" && receipt_matched=1
    if [[ "$graph_matched" == "1" && "$receipt_matched" == "1" ]]; then
      matched=1
      log "Provider-delivered EndpointSecurity observation and receipt found on attempt $attempt"
      break
    fi
    log "Attempt $attempt did not prove the probe yet; graph=$graph_matched receipt=$receipt_matched observations $before_observation_count -> $after_observation_count"
  else
    log "Attempt $attempt failed to poll recorder/graph/receipts"
  fi
  attempt=$((attempt + 1))
  sleep "$poll_sleep_secs"
done

if [[ "$matched" != "1" ]]; then
  die "no provider-delivered EndpointSecurity observation receipt matched $probe_file; summary: $summary_file"
fi

write_summary "passed"
python3 "$repo_root/scripts/endpoint-security-live-dogfood-verify.py" "$summary_file" \
  >"$output_dir/summary-verification.json" \
  || die "EndpointSecurity dogfood summary verification failed; see $output_dir/summary-verification.json"
log "EndpointSecurity live dogfood passed; summary: $summary_file"
