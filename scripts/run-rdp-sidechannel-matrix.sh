#!/usr/bin/env bash
set -euo pipefail

require_cmd() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "[rdp-matrix] missing command: $1" >&2
    exit 1
  fi
}

require_cmd jq
require_cmd aws
require_cmd ssh
require_cmd sdl-freerdp
require_cmd python3
require_cmd perl

TESTBED_JSON="${1:-${TESTBED_JSON:-$HOME/.config/clawdstrike-cua/testbeds/clawdstrike-cua-testbed-20260218-213949.json}}"
if [[ ! -f "$TESTBED_JSON" ]]; then
  echo "[rdp-matrix] testbed json not found: $TESTBED_JSON" >&2
  exit 1
fi

TS="$(date -u +%Y%m%d-%H%M%S)"
OUT_DIR="docs/roadmaps/cua/research/artifacts/rdp-sidechannel-${TS}"
mkdir -p "$OUT_DIR"
RDP_PROBE_TIMEOUT_SECONDS="${RDP_PROBE_TIMEOUT_SECONDS:-30}"
REMOTE_OP_TIMEOUT_SECONDS="${REMOTE_OP_TIMEOUT_SECONDS:-45}"
SSM_WAIT_TIMEOUT_SECONDS="${SSM_WAIT_TIMEOUT_SECONDS:-180}"

REGION="$(jq -r '.region' "$TESTBED_JSON")"
KEY_PATH="$(jq -r '.key_path' "$TESTBED_JSON")"
LINUX_IP="$(jq -r '.linux.public_ip' "$TESTBED_JSON")"
LINUX_SSH_USER="ubuntu"
LINUX_RDP_USER="$(jq -r '.linux.username' "$TESTBED_JSON")"
LINUX_RDP_PASS="$(jq -r '.linux.password' "$TESTBED_JSON")"
WIN_ID="$(jq -r '.windows.instance_id' "$TESTBED_JSON")"
WIN_IP="$(jq -r '.windows.public_ip' "$TESTBED_JSON")"
WIN_USER="$(jq -r '.windows.username' "$TESTBED_JSON")"
WIN_PASS="$(jq -r '.windows.password' "$TESTBED_JSON")"

run_cmd_timeout() {
  local timeout_seconds="$1"
  shift
  if [[ "$timeout_seconds" -gt 0 ]]; then
    perl -e 'alarm shift @ARGV; exec @ARGV' "$timeout_seconds" "$@"
  else
    "$@"
  fi
}

run_probe() {
  local host="$1"
  local user="$2"
  local pass="$3"
  local label="$4"
  local extra="$5"
  local log="$OUT_DIR/${label}.log"

  set +e
  local rc=0
  # auth-only is deterministic in CI/terminal contexts and avoids UI interaction.
  if [[ "$RDP_PROBE_TIMEOUT_SECONDS" -gt 0 ]]; then
    perl -e 'alarm shift @ARGV; exec @ARGV' "$RDP_PROBE_TIMEOUT_SECONDS" \
      sdl-freerdp \
      /v:"$host" /u:"$user" /p:"$pass" /cert:ignore +auth-only \
      ${extra} /log-level:INFO >"$log" 2>&1
    rc=$?
  else
    sdl-freerdp \
      /v:"$host" /u:"$user" /p:"$pass" /cert:ignore +auth-only \
      ${extra} /log-level:INFO >"$log" 2>&1
    rc=$?
  fi
  set -e

  local status="unknown"
  if [[ "$rc" -eq 142 ]]; then
    status="probe_timeout"
  elif rg -q "ERRCONNECT_CONNECT_FAILED" "$log"; then
    status="connect_failed"
  elif rg -q "ERRCONNECT_ACTIVATION_TIMEOUT" "$log"; then
    status="activation_timeout"
  elif rg -q "Authentication only" "$log"; then
    status="auth_only"
  fi

  jq -cn \
    --arg label "$label" \
    --arg extra "$extra" \
    --arg status "$status" \
    --argjson rc "$rc" \
    --arg log "$(basename "$log")" \
    '{label:$label,probe_option:$extra,status:$status,rc:$rc,log:$log}'
}

run_win_ps() {
  local script_file
  script_file="$(mktemp)"
  cat >"$script_file"

  local params_file
  params_file="$(mktemp)"
  python3 - "$script_file" >"$params_file" <<'PY'
import json
import pathlib
import sys
lines = pathlib.Path(sys.argv[1]).read_text().splitlines()
print(json.dumps({"commands": lines}))
PY

  local cmd_id
  cmd_id="$(aws --region "$REGION" ssm send-command \
    --instance-ids "$WIN_ID" \
    --document-name AWS-RunPowerShellScript \
    --parameters "file://${params_file}" \
    --query 'Command.CommandId' --output text)"

  set +e
  run_cmd_timeout "$SSM_WAIT_TIMEOUT_SECONDS" \
    aws --region "$REGION" ssm wait command-executed --command-id "$cmd_id" --instance-id "$WIN_ID"
  local wait_rc="$?"
  set -e

  if [[ "$wait_rc" -eq 142 ]]; then
    jq -cn \
      --arg status "Timeout" \
      --arg stdout "" \
      --arg stderr "ssm wait timed out after ${SSM_WAIT_TIMEOUT_SECONDS}s for command ${cmd_id}" \
      '{status:$status,stdout:$stdout,stderr:$stderr}'
  else
    aws --region "$REGION" ssm get-command-invocation --command-id "$cmd_id" --instance-id "$WIN_ID" \
      --query '{status:Status,stdout:StandardOutputContent,stderr:StandardErrorContent}' --output json
  fi

  rm -f "$script_file" "$params_file"
}

linux_set_channel() {
  local key="$1"
  local value="$2"
  run_cmd_timeout "$REMOTE_OP_TIMEOUT_SECONDS" \
    ssh -i "$KEY_PATH" -o StrictHostKeyChecking=no -o ConnectTimeout=10 "$LINUX_SSH_USER@$LINUX_IP" \
    "sudo python3 - '$key' '$value'" <<'PY'
import pathlib
import sys

k = sys.argv[1]
v = sys.argv[2]
p = pathlib.Path('/etc/xrdp/xrdp.ini')
lines = p.read_text().splitlines()
out = []
in_channels = False
for line in lines:
    stripped = line.strip()
    if stripped.startswith('['):
        in_channels = (stripped.lower() == '[channels]')
        out.append(line)
        continue
    if in_channels and stripped.startswith(f'{k}='):
        out.append(f'{k}={v}')
    else:
        out.append(line)
p.write_text('\n'.join(out) + '\n')
PY

  run_cmd_timeout "$REMOTE_OP_TIMEOUT_SECONDS" \
    ssh -n -i "$KEY_PATH" -o StrictHostKeyChecking=no -o ConnectTimeout=10 "$LINUX_SSH_USER@$LINUX_IP" \
    "sudo systemctl restart xrdp xrdp-sesman" </dev/null
}

linux_get_channels() {
  run_cmd_timeout "$REMOTE_OP_TIMEOUT_SECONDS" \
    ssh -i "$KEY_PATH" -o StrictHostKeyChecking=no -o ConnectTimeout=10 "$LINUX_SSH_USER@$LINUX_IP" \
    "python3 -" <<'PY'
import json
import pathlib

keys = ["cliprdr", "rdpsnd", "rdpdr", "rail", "drdynvc"]
vals = {k: None for k in keys}
text = pathlib.Path('/etc/xrdp/xrdp.ini').read_text().splitlines()
in_channels = False
for line in text:
    s = line.strip()
    if s.startswith('['):
        in_channels = (s.lower() == '[channels]')
        continue
    if not in_channels or '=' not in s:
        continue
    k, v = s.split('=', 1)
    if k in vals:
        vals[k] = v
print(json.dumps(vals))
PY
}

win_set_key() {
  local name="$1"
  local value="$2"
  run_win_ps <<PS
\$ErrorActionPreference = 'Stop'
\$p = 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\Terminal Services'
if (!(Test-Path \$p)) { New-Item -Path \$p -Force | Out-Null }
Set-ItemProperty -Path \$p -Name '${name}' -Type DWord -Value ${value}
\$o = [ordered]@{}
foreach (\$n in @('fDisableClip','fDisableCdm','fDisableAudioPlayback','fDisableAudioCapture','fDisableLPTPort','Shadow')) {
  \$v = (Get-ItemProperty -Path \$p -Name \$n -ErrorAction SilentlyContinue).\$n
  if (\$null -eq \$v) { \$v = 'unset' }
  \$o[\$n] = \$v
}
\$o | ConvertTo-Json -Compress
PS
}

RESTORE_DONE=0
restore_defaults() {
  if [[ "$RESTORE_DONE" -eq 1 ]]; then
    return
  fi
  RESTORE_DONE=1
  set +e
  linux_set_channel cliprdr true
  linux_set_channel rdpsnd true
  linux_set_channel rdpdr true
  linux_set_channel rail true
  linux_set_channel drdynvc true
  linux_get_channels > "$OUT_DIR/linux-channels-restored.json"

  win_set_key fDisableClip 0 > "$OUT_DIR/windows-restore-clip.json"
  win_set_key fDisableCdm 0 > "$OUT_DIR/windows-restore-cdm.json"
  win_set_key fDisableAudioPlayback 0 > "$OUT_DIR/windows-restore-audio-playback.json"
  win_set_key fDisableAudioCapture 0 > "$OUT_DIR/windows-restore-audio-capture.json"
  win_set_key fDisableLPTPort 0 > "$OUT_DIR/windows-restore-print.json"
  win_set_key Shadow 2 > "$OUT_DIR/windows-restore-shadow.json"
  set -e
}

trap restore_defaults EXIT

echo "[rdp-matrix] output: $OUT_DIR"

# Baseline snapshots
linux_get_channels > "$OUT_DIR/linux-channels-baseline.json"
run_win_ps <<'PS' > "$OUT_DIR/windows-reg-baseline.json"
$ErrorActionPreference = 'Stop'
$p = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services'
if (!(Test-Path $p)) { New-Item -Path $p -Force | Out-Null }
$o = [ordered]@{}
foreach ($n in @('fDisableClip','fDisableCdm','fDisableAudioPlayback','fDisableAudioCapture','fDisableLPTPort','Shadow')) {
  $v = (Get-ItemProperty -Path $p -Name $n -ErrorAction SilentlyContinue).$n
  if ($null -eq $v) { $v = 'unset' }
  $o[$n] = $v
}
$o | ConvertTo-Json -Compress
PS

# Test matrix definitions
cat > "$OUT_DIR/matrix.json" <<'JSON'
[
  {"name":"clipboard","linux_key":"cliprdr","win_key":"fDisableClip","win_deny":1,"win_allow":0,"probe":"+clipboard"},
  {"name":"audio","linux_key":"rdpsnd","win_key":"fDisableAudioPlayback","win_deny":1,"win_allow":0,"probe":"/sound:sys:fake"},
  {"name":"drive_mapping","linux_key":"rdpdr","win_key":"fDisableCdm","win_deny":1,"win_allow":0,"probe":"/drive:home,$HOME"},
  {"name":"printing","linux_key":"rdpdr","win_key":"fDisableLPTPort","win_deny":1,"win_allow":0,"probe":"/printer"},
  {"name":"session_share","linux_key":"rail","win_key":"Shadow","win_deny":0,"win_allow":2,"probe":"+dynamic-resolution"}
]
JSON

: > "$OUT_DIR/results.jsonl"

while IFS= read -r row; do
  NAME="$(jq -r '.name' <<<"$row")"
  LKEY="$(jq -r '.linux_key' <<<"$row")"
  WKEY="$(jq -r '.win_key' <<<"$row")"
  WDENY="$(jq -r '.win_deny' <<<"$row")"
  WALLOW="$(jq -r '.win_allow' <<<"$row")"
  PROBE_RAW="$(jq -r '.probe' <<<"$row")"
  PROBE="${PROBE_RAW/\$HOME/$HOME}"

  echo "[rdp-matrix] case=$NAME phase=deny"

  linux_set_channel "$LKEY" "false"
  linux_get_channels > "$OUT_DIR/linux-${NAME}-deny.json"
  run_probe "$LINUX_IP" "$LINUX_RDP_USER" "$LINUX_RDP_PASS" "linux-${NAME}-deny" "$PROBE" >> "$OUT_DIR/results.jsonl"

  win_set_key "$WKEY" "$WDENY" > "$OUT_DIR/windows-${NAME}-deny.json"
  run_probe "$WIN_IP" "$WIN_USER" "$WIN_PASS" "windows-${NAME}-deny" "$PROBE" >> "$OUT_DIR/results.jsonl"

  echo "[rdp-matrix] case=$NAME phase=allow"

  linux_set_channel "$LKEY" "true"
  linux_get_channels > "$OUT_DIR/linux-${NAME}-allow.json"
  run_probe "$LINUX_IP" "$LINUX_RDP_USER" "$LINUX_RDP_PASS" "linux-${NAME}-allow" "$PROBE" >> "$OUT_DIR/results.jsonl"

  win_set_key "$WKEY" "$WALLOW" > "$OUT_DIR/windows-${NAME}-allow.json"
  run_probe "$WIN_IP" "$WIN_USER" "$WIN_PASS" "windows-${NAME}-allow" "$PROBE" >> "$OUT_DIR/results.jsonl"
done < <(jq -c '.[]' "$OUT_DIR/matrix.json")

python3 - "$OUT_DIR/results.jsonl" "$OUT_DIR/summary.json" <<'PY'
import json
import pathlib
import sys

in_path = pathlib.Path(sys.argv[1])
out_path = pathlib.Path(sys.argv[2])
rows = [json.loads(line) for line in in_path.read_text().splitlines() if line.strip()]
summary = {
    "cases": len(rows),
    "status_counts": {},
    "results": rows,
}
for row in rows:
    s = row.get("status", "unknown")
    summary["status_counts"][s] = summary["status_counts"].get(s, 0) + 1
out_path.write_text(json.dumps(summary, indent=2) + "\n")
PY

restore_defaults

echo "[rdp-matrix] done"
echo "[rdp-matrix] summary: $OUT_DIR/summary.json"
