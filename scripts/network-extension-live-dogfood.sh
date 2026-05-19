#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
agent_url="${CLAWDSTRIKE_AGENT_URL:-http://127.0.0.1:9878}"
target_input="${1:-${CLAWDSTRIKE_NE_DOGFOOD_TARGET:-}}"
run_id="${CLAWDSTRIKE_NE_DOGFOOD_RUN_ID:-$(date -u '+%Y%m%dT%H%M%SZ')}"
run_id_slug="$(printf '%s' "$run_id" | tr -c '[:alnum:]_' '-')"
output_dir="${CLAWDSTRIKE_NE_DOGFOOD_OUTPUT_DIR:-$repo_root/output/dogfood/network-extension-live/$run_id}"
if [[ "$(uname -s)" == "Darwin" && -z "${XDG_CONFIG_HOME:-}" ]]; then
  default_config_dir="$HOME/Library/Application Support/clawdstrike"
else
  default_config_dir="${XDG_CONFIG_HOME:-$HOME/.config}/clawdstrike"
fi
token_file="${CLAWDSTRIKE_AGENT_TOKEN_FILE:-$default_config_dir/agent-local-token}"
connect_timeout="${CLAWDSTRIKE_NE_DOGFOOD_CONNECT_TIMEOUT:-3}"
api_timeout="${CLAWDSTRIKE_NE_DOGFOOD_API_TIMEOUT:-30}"
ttl_seconds="${CLAWDSTRIKE_NE_DOGFOOD_TTL_SECONDS:-180}"
proof_attempts="${CLAWDSTRIKE_NE_DOGFOOD_PROOF_ATTEMPTS:-12}"
proof_sleep_secs="${CLAWDSTRIKE_NE_DOGFOOD_PROOF_SLEEP_SECS:-2}"
rollback_attempts="${CLAWDSTRIKE_NE_DOGFOOD_ROLLBACK_ATTEMPTS:-6}"
rollback_sleep_secs="${CLAWDSTRIKE_NE_DOGFOOD_ROLLBACK_SLEEP_SECS:-2}"
provider_refresh_timeout_ms="${CLAWDSTRIKE_NE_DOGFOOD_PROVIDER_REFRESH_TIMEOUT_MS:-3000}"
keep_restriction="${CLAWDSTRIKE_NE_DOGFOOD_KEEP_RESTRICTION:-0}"
allow_non_macos="${CLAWDSTRIKE_NE_DOGFOOD_ALLOW_NON_MACOS:-0}"

execution_id=""
rollback_done=0
last_proof_file=""
summary_written=0

log() {
  printf '[ne-dogfood] %s\n' "$*" >&2
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

usage() {
  cat >&2 <<'USAGE'
Usage:
  scripts/network-extension-live-dogfood.sh HOST:PORT

Environment:
  CLAWDSTRIKE_AGENT_URL                         default: http://127.0.0.1:9878
  CLAWDSTRIKE_AGENT_TOKEN                       bearer token; otherwise read token file
  CLAWDSTRIKE_AGENT_TOKEN_FILE                  default: platform config dir / clawdstrike / agent-local-token
  CLAWDSTRIKE_NE_DOGFOOD_RUN_ID                 override YYYYMMDDTHHMMSSZ run ID for combined QA bundles
  CLAWDSTRIKE_NE_DOGFOOD_API_TIMEOUT            default: 30
  CLAWDSTRIKE_NE_DOGFOOD_TTL_SECONDS            default: 180
  CLAWDSTRIKE_NE_DOGFOOD_PROOF_ATTEMPTS         default: 12
  CLAWDSTRIKE_NE_DOGFOOD_PROOF_SLEEP_SECS       default: 2
  CLAWDSTRIKE_NE_DOGFOOD_ROLLBACK_ATTEMPTS      default: 6
  CLAWDSTRIKE_NE_DOGFOOD_ROLLBACK_SLEEP_SECS    default: 2
  CLAWDSTRIKE_NE_DOGFOOD_PROVIDER_REFRESH_TIMEOUT_MS default: 3000
  CLAWDSTRIKE_NE_DOGFOOD_KEEP_RESTRICTION=1     skip rollback for manual inspection

The target must be reachable before containment. The script creates a live
restrict_egress execution, triggers real TCP flows, requires strict
liveEnforcementProven proof, then rolls the execution back and verifies target
reachability is restored unless KEEP is set. A passing run also writes
summary-verification.json after rechecking the summary artifact.
USAGE
}

if [[ "$target_input" == "-h" || "$target_input" == "--help" ]]; then
  usage
  exit 0
fi

if [[ -z "$target_input" ]]; then
  usage
  exit 2
fi

require_cmd curl
require_cmd date
require_cmd hostname
require_cmd python3
require_cmd tr
require_cmd uname

require_positive_number "CLAWDSTRIKE_NE_DOGFOOD_CONNECT_TIMEOUT" "$connect_timeout"
require_positive_number "CLAWDSTRIKE_NE_DOGFOOD_API_TIMEOUT" "$api_timeout"
require_positive_int "CLAWDSTRIKE_NE_DOGFOOD_TTL_SECONDS" "$ttl_seconds"
require_positive_int "CLAWDSTRIKE_NE_DOGFOOD_PROOF_ATTEMPTS" "$proof_attempts"
require_nonnegative_int "CLAWDSTRIKE_NE_DOGFOOD_PROOF_SLEEP_SECS" "$proof_sleep_secs"
require_positive_int "CLAWDSTRIKE_NE_DOGFOOD_ROLLBACK_ATTEMPTS" "$rollback_attempts"
require_nonnegative_int "CLAWDSTRIKE_NE_DOGFOOD_ROLLBACK_SLEEP_SECS" "$rollback_sleep_secs"
require_run_id "CLAWDSTRIKE_NE_DOGFOOD_RUN_ID" "$run_id"
require_positive_int "CLAWDSTRIKE_NE_DOGFOOD_PROVIDER_REFRESH_TIMEOUT_MS" "$provider_refresh_timeout_ms"
if [[ "$provider_refresh_timeout_ms" -gt 5000 ]]; then
  die "CLAWDSTRIKE_NE_DOGFOOD_PROVIDER_REFRESH_TIMEOUT_MS must be <= 5000, got: $provider_refresh_timeout_ms"
fi

if [[ "$(uname -s)" != "Darwin" && "$allow_non_macos" != "1" ]]; then
  die "NetworkExtension dogfood must run on macOS; set CLAWDSTRIKE_NE_DOGFOOD_ALLOW_NON_MACOS=1 only for syntax/debug dry work"
fi

mkdir -p "$output_dir"

parsed_target="$(
  python3 - "$target_input" <<'PY'
import re
import sys

target = sys.argv[1].strip()
host = ""
port = ""
if target.startswith("["):
    end = target.find("]")
    if end == -1 or len(target) <= end + 2 or target[end + 1] != ":":
        raise SystemExit("bracketed IPv6 targets must use [addr]:port")
    host = target[1:end]
    port = target[end + 2:]
else:
    if ":" not in target:
        raise SystemExit("target must be HOST:PORT")
    host, port = target.rsplit(":", 1)
host = host.strip()
if not host:
    raise SystemExit("target host must not be empty")
try:
    port_int = int(port)
except ValueError as exc:
    raise SystemExit("target port must be an integer") from exc
if port_int < 1 or port_int > 65535:
    raise SystemExit("target port must be between 1 and 65535")
if host.lower() == "localhost" or host in {"127.0.0.1", "::1", "0.0.0.0"}:
    raise SystemExit("refusing loopback/local target; use an external test host")
if re.search(r"\s", host):
    raise SystemExit("target host must not contain whitespace")
print(f"{host}\t{port_int}")
PY
)" || die "invalid target: $target_input"
IFS=$'\t' read -r target_host target_port <<EOF
$parsed_target
EOF

scheme="${CLAWDSTRIKE_NE_DOGFOOD_SCHEME:-}"
if [[ -z "$scheme" ]]; then
  if [[ "$target_port" == "443" ]]; then
    scheme="https"
  else
    scheme="tcp"
  fi
fi

agent_token="${CLAWDSTRIKE_AGENT_TOKEN:-}"
if [[ -z "$agent_token" ]]; then
  [[ -f "$token_file" ]] || die "agent token not set and token file missing: $token_file"
  agent_token="$(tr -d '[:space:]' < "$token_file")"
fi
[[ -n "$agent_token" ]] || die "agent token is empty"

endpoint_id="${CLAWDSTRIKE_NE_DOGFOOD_ENDPOINT_ID:-endpoint-ne-dogfood-$run_id_slug}"
host_id="${CLAWDSTRIKE_NE_DOGFOOD_HOST_ID:-$(hostname -s 2>/dev/null || hostname)}"
user_id="${CLAWDSTRIKE_NE_DOGFOOD_USER_ID:-${USER:-operator}}"
session_id="${CLAWDSTRIKE_NE_DOGFOOD_SESSION_ID:-session-ne-dogfood-$run_id_slug}"
agent_id="${CLAWDSTRIKE_NE_DOGFOOD_AGENT_ID:-agent-ne-dogfood-$run_id_slug}"
workload_id="${CLAWDSTRIKE_NE_DOGFOOD_WORKLOAD_ID:-network-extension-live-dogfood}"
approval_id="${CLAWDSTRIKE_NE_DOGFOOD_APPROVAL_ID:-approval-ne-dogfood-$run_id_slug}"
posture="${CLAWDSTRIKE_NE_DOGFOOD_POSTURE:-operator-live-dogfood}"
process_guid="proc-ne-dogfood-$run_id_slug"

health_file="$output_dir/agent-health.json"
findings_payload="$output_dir/findings-request.json"
findings_response="$output_dir/findings-response.json"
action_payload="$output_dir/response-action-request.json"
action_response="$output_dir/response-action-response.json"
rollback_payload="$output_dir/rollback-request.json"
rollback_response="$output_dir/rollback-response.json"
summary_file="$output_dir/summary.json"
preflight_flow="$output_dir/preflight-connect.json"
final_flow="$output_dir/final-blocked-flow.json"
post_rollback_flow="$output_dir/post-rollback-connect.json"

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

json_value() {
  python3 - "$1" "$2" <<'PY'
import json
import sys

path, selector = sys.argv[1], sys.argv[2]
with open(path, "r", encoding="utf-8") as handle:
    value = json.load(handle)
for part in selector.split("."):
    if isinstance(value, dict):
        value = value.get(part)
    else:
        value = None
    if value is None:
        raise SystemExit(1)
if isinstance(value, bool):
    print("true" if value else "false")
elif isinstance(value, (str, int, float)):
    print(value)
else:
    print(json.dumps(value, sort_keys=True))
PY
}

attempt_connect() {
  local output_file="$1"
  python3 - "$target_host" "$target_port" "$connect_timeout" "$output_file" <<'PY'
import datetime as dt
import json
import socket
import sys
import time

host = sys.argv[1]
port = int(sys.argv[2])
timeout = float(sys.argv[3])
output = sys.argv[4]
started = time.monotonic()
result = {
    "target": f"{host}:{port}",
    "attemptedAt": dt.datetime.now(dt.timezone.utc).isoformat().replace("+00:00", "Z"),
    "timeoutSeconds": timeout,
    "connectSucceeded": False,
    "elapsedMs": None,
    "error": None,
}
try:
    with socket.create_connection((host, port), timeout=timeout):
        result["connectSucceeded"] = True
except Exception as exc:  # noqa: BLE001 - operator evidence should preserve concrete OS error.
    result["error"] = f"{type(exc).__name__}: {exc}"
finally:
    result["elapsedMs"] = int((time.monotonic() - started) * 1000)
    with open(output, "w", encoding="utf-8") as handle:
        json.dump(result, handle, indent=2, sort_keys=True)
        handle.write("\n")
if not result["connectSucceeded"]:
    raise SystemExit(2)
PY
}

write_findings_payload() {
  python3 - "$findings_payload" "$run_id" "$host_id" "$user_id" "$session_id" \
    "$agent_id" "$workload_id" "$approval_id" "$posture" "$process_guid" \
    "$target_host" "$target_port" "$scheme" "$agent_url" <<'PY'
import datetime as dt
import json
import sys

(
    output,
    run_id,
    host_id,
    user_id,
    session_id,
    agent_id,
    workload_id,
    approval_id,
    posture,
    process_guid,
    target_host,
    target_port,
    scheme,
    agent_url,
) = sys.argv[1:]
target_port_int = int(target_port)
url_host = f"[{target_host}]" if ":" in target_host and not target_host.startswith("[") else target_host
url = f"{scheme}://{url_host}:{target_port_int}/clawdstrike-ne-dogfood"
payload = {
    "observations": [
        {
            "observationId": f"obs-ne-dogfood-{run_id}",
            "timestamp": dt.datetime.now(dt.timezone.utc).isoformat().replace("+00:00", "Z"),
            "hostId": host_id,
            "userId": user_id,
            "sessionId": session_id,
            "process": {
                "processGuid": process_guid,
                "image": "/usr/bin/python3",
                "commandLine": f"clawdstrike network-extension live dogfood flow to {target_host}:{target_port_int}",
            },
            "event": {
                "type": "network_flow",
                "host": target_host,
                "port": target_port_int,
                "protocol": "tcp",
                "url": url,
            },
            "metadata": {
                "source": "network-extension-live-dogfood",
                "dogfoodRunId": run_id,
                "agentId": agent_id,
                "workloadId": workload_id,
                "approvalId": approval_id,
                "posture": posture,
                "agentUrl": agent_url,
            },
        }
    ],
    "honeyArtifacts": [],
}
with open(output, "w", encoding="utf-8") as handle:
    json.dump(payload, handle, indent=2, sort_keys=True)
    handle.write("\n")
PY
}

write_action_payload() {
  python3 - "$action_payload" "$ttl_seconds" "$process_guid" "$endpoint_id" "$host_id" \
    "$user_id" "$session_id" "$agent_id" "$workload_id" "$approval_id" "$posture" \
    "$target_host" "$target_port" <<'PY'
import json
import sys

(
    output,
    ttl_seconds,
    process_guid,
    endpoint_id,
    host_id,
    user_id,
    session_id,
    agent_id,
    workload_id,
    approval_id,
    posture,
    target_host,
    target_port,
) = sys.argv[1:]
payload = {
    "action": "restrict_egress",
    "process": {"processGuid": process_guid},
    "ttlSeconds": int(ttl_seconds),
    "reason": f"live NetworkExtension dogfood containment for {target_host}:{target_port}",
    "actor": {
        "endpointId": endpoint_id,
        "hostId": host_id,
        "userId": user_id,
        "sessionId": session_id,
        "agentId": agent_id,
        "workloadId": workload_id,
        "approvalId": approval_id,
        "posture": posture,
    },
    "dryRun": False,
}
with open(output, "w", encoding="utf-8") as handle:
    json.dump(payload, handle, indent=2, sort_keys=True)
    handle.write("\n")
PY
}

write_proof_payload() {
  local output_file="$1"
  python3 - "$output_file" "$execution_id" "$provider_refresh_timeout_ms" <<'PY'
import json
import sys

output, execution_id, timeout_ms = sys.argv[1:]
payload = {
    "refreshProviders": True,
    "providerRefreshTimeoutMs": int(timeout_ms),
    "executionId": execution_id,
}
with open(output, "w", encoding="utf-8") as handle:
    json.dump(payload, handle, indent=2, sort_keys=True)
    handle.write("\n")
PY
}

write_rollback_payload() {
  python3 - "$rollback_payload" "$target_host" "$target_port" <<'PY'
import json
import sys

output, target_host, target_port = sys.argv[1:]
payload = {
    "reason": f"restore egress after NetworkExtension dogfood for {target_host}:{target_port}",
}
with open(output, "w", encoding="utf-8") as handle:
    json.dump(payload, handle, indent=2, sort_keys=True)
    handle.write("\n")
PY
}

proof_is_strict() {
  python3 - "$1" <<'PY'
import json
import sys

with open(sys.argv[1], "r", encoding="utf-8") as handle:
    proof = json.load(handle)
delivery = proof.get("providerReloadDelivery") or {}
ok = (
    proof.get("liveEnforcementProven") is True
    and delivery.get("matched") is True
    and int(proof.get("blockedFlowCount") or 0) > 0
    and int(proof.get("droppedVerdictCount") or 0) == 0
)
if not ok:
    reasons = proof.get("liveEnforcementProofReasons") or []
    print(",".join(reasons) if reasons else "strict proof predicates not satisfied")
    raise SystemExit(1)
print("strict proof satisfied")
PY
}

write_summary() {
  local status="$1"
  local proof_file="$2"
  python3 - "$summary_file" "$status" "$run_id" "$output_dir" "$target_host" "$target_port" \
    "$execution_id" "$proof_file" "$rollback_response" "$final_flow" "$post_rollback_flow" \
    "$keep_restriction" "$agent_url" "$host_id" "$user_id" "$session_id" "$agent_id" \
    "$workload_id" "$approval_id" "$findings_payload" "$action_payload" "$health_file" <<'PY'
import json
import os
import sys

(
    output,
    status,
    run_id,
    output_dir,
    target_host,
    target_port,
    execution_id,
    proof_file,
    rollback_file,
    final_flow_file,
    post_rollback_flow_file,
    keep_restriction,
    agent_url,
    host_id,
    user_id,
    session_id,
    agent_id,
    workload_id,
    approval_id,
    findings_file,
    action_file,
    health_file,
) = sys.argv[1:]

def read_json(path):
    if path and os.path.exists(path):
        with open(path, "r", encoding="utf-8") as handle:
            return json.load(handle)
    return None

proof = read_json(proof_file)
rollback = read_json(rollback_file)
final_flow = read_json(final_flow_file)
post_rollback_flow = read_json(post_rollback_flow_file)
summary = {
    "runId": run_id,
    "status": status,
    "target": f"{target_host}:{target_port}",
    "outputDir": output_dir,
    "agentUrl": agent_url,
    "agentHealth": health_file if health_file and os.path.exists(health_file) else None,
    "hostId": host_id,
    "userId": user_id,
    "sessionId": session_id,
    "agentId": agent_id,
    "workloadId": workload_id,
    "approvalId": approval_id,
    "executionId": execution_id or None,
    "findingsRequest": findings_file if findings_file and os.path.exists(findings_file) else None,
    "actionRequest": action_file if action_file and os.path.exists(action_file) else None,
    "actionResponse": os.path.join(output_dir, "response-action-response.json"),
    "proofResponse": proof_file or None,
    "rollbackResponse": rollback_file if rollback_file and os.path.exists(rollback_file) else None,
    "finalFlow": final_flow_file if final_flow_file and os.path.exists(final_flow_file) else None,
    "postRollbackFlow": (
        post_rollback_flow_file
        if post_rollback_flow_file and os.path.exists(post_rollback_flow_file)
        else None
    ),
    "liveEnforcementProven": bool(proof and proof.get("liveEnforcementProven") is True),
    "liveEnforcementProofReasons": (proof or {}).get("liveEnforcementProofReasons", []),
    "blockedFlowCount": (proof or {}).get("blockedFlowCount"),
    "droppedVerdictCount": (proof or {}).get("droppedVerdictCount"),
    "providerReloadDelivery": (proof or {}).get("providerReloadDelivery"),
    "finalConnectSucceeded": (final_flow or {}).get("connectSucceeded"),
    "rollbackSkipped": keep_restriction == "1",
    "rollbackSucceeded": bool(rollback and rollback.get("rollbackTransition")),
    "postRollbackConnectSucceeded": (post_rollback_flow or {}).get("connectSucceeded"),
}
with open(output, "w", encoding="utf-8") as handle:
    json.dump(summary, handle, indent=2, sort_keys=True)
    handle.write("\n")
PY
  summary_written=1
}

rollback_execution() {
  if [[ -z "$execution_id" || "$keep_restriction" == "1" || "$rollback_done" == "1" ]]; then
    return 0
  fi
  write_rollback_payload
  log "Rolling back response execution $execution_id"
  if curl_json "POST" "/api/v1/agent/edr/response-executions/$execution_id/rollback" "$rollback_payload" "$rollback_response"; then
    rollback_done=1
    return 0
  fi
  rollback_done=1
  return 1
}

verify_rollback_connectivity() {
  local attempt=1
  while [[ "$attempt" -le "$rollback_attempts" ]]; do
    if attempt_connect "$post_rollback_flow"; then
      log "Rollback restoration verified on attempt $attempt"
      return 0
    fi
    attempt=$((attempt + 1))
    sleep "$rollback_sleep_secs"
  done
  return 1
}

cleanup() {
  local status=$?
  if [[ "$status" -ne 0 ]]; then
    rollback_execution || true
    if [[ "$summary_written" != "1" && -n "$execution_id" ]]; then
      write_summary "failed" "$last_proof_file" || true
    fi
  fi
  exit "$status"
}
trap cleanup EXIT

log "Output: $output_dir"
log "Checking agent health at ${agent_url%/}/api/v1/agent/health"
curl -sS --connect-timeout "$connect_timeout" --max-time "$api_timeout" \
  -o "$health_file" "${agent_url%/}/api/v1/agent/health" >/dev/null \
  || die "agent health check failed"

log "Checking target reachability before containment: $target_host:$target_port"
attempt_connect "$preflight_flow" || die "target is not reachable before containment; see $preflight_flow"

write_findings_payload
log "Recording causal network-flow observation"
curl_json "POST" "/api/v1/agent/edr/findings" "$findings_payload" "$findings_response" \
  || die "failed to record EDR findings; see $findings_response"

write_action_payload
log "Executing live restrict_egress response action"
curl_json "POST" "/api/v1/agent/edr/response-action" "$action_payload" "$action_response" \
  || die "restrict_egress action failed; see $action_response"
execution_id="$(json_value "$action_response" "execution.executionId")" \
  || die "response action did not return execution.executionId"
execution_status="$(json_value "$action_response" "execution.status")" \
  || die "response action did not return execution.status"
[[ "$execution_status" == "succeeded" ]] \
  || die "response execution $execution_id status is $execution_status, expected succeeded"
log "Execution: $execution_id"

proof_success=0
attempt=1
while [[ "$attempt" -le "$proof_attempts" ]]; do
  flow_file="$output_dir/flow-attempt-$attempt.json"
  proof_payload="$output_dir/proof-request-$attempt.json"
  proof_response="$output_dir/proof-response-$attempt.json"
  attempt_connect "$flow_file" >/dev/null 2>&1 || true
  write_proof_payload "$proof_payload"
  if curl_json "POST" "/api/v1/agent/edr/network-extension/egress-policy/proof" "$proof_payload" "$proof_response"; then
    last_proof_file="$proof_response"
    if proof_is_strict "$proof_response" >/dev/null; then
      proof_success=1
      log "Strict NetworkExtension proof satisfied on attempt $attempt"
      break
    fi
    proof_reason="$(proof_is_strict "$proof_response" 2>/dev/null || true)"
    log "Proof attempt $attempt not strict yet: ${proof_reason:-not ready}"
  else
    log "Proof attempt $attempt failed; see $proof_response"
  fi
  attempt=$((attempt + 1))
  sleep "$proof_sleep_secs"
done

if [[ "$proof_success" != "1" ]]; then
  die "strict NetworkExtension proof was not observed; summary: $summary_file"
fi

log "Verifying final target flow is blocked"
if attempt_connect "$final_flow"; then
  die "final target connection unexpectedly succeeded after strict proof; see $final_flow"
fi

if [[ "$keep_restriction" == "1" ]]; then
  log "Keeping response execution active by request: $execution_id"
else
  rollback_execution || {
    write_summary "failed" "$last_proof_file"
    die "rollback failed; see $rollback_response"
  }
  verify_rollback_connectivity || {
    write_summary "failed" "$last_proof_file"
    die "target connectivity was not restored after rollback; see $post_rollback_flow"
  }
fi

write_summary "passed" "$last_proof_file"
python3 "$repo_root/scripts/network-extension-live-dogfood-verify.py" "$summary_file" \
  >"$output_dir/summary-verification.json" \
  || die "NetworkExtension dogfood summary verification failed; see $output_dir/summary-verification.json"
log "Passed. Summary: $summary_file"
