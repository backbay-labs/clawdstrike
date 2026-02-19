#!/usr/bin/env bash
set -euo pipefail

require_cmd() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "[soak] missing required command: $1" >&2
    exit 1
  fi
}

require_cmd jq
require_cmd date
require_cmd perl

DURATION_HOURS="${DURATION_HOURS:-6}"
SLEEP_SECONDS="${SLEEP_SECONDS:-30}"
SOAK_ITER_TIMEOUT_SECONDS="${SOAK_ITER_TIMEOUT_SECONDS:-180}"
MAX_ITERATIONS="${MAX_ITERATIONS:-0}"
GATEWAY_URL="${GATEWAY_URL:-ws://127.0.0.1:18789}"
GATEWAY_TOKEN="${GATEWAY_TOKEN:-${OPENCLAW_GATEWAY_TOKEN:-}}"
XDG_CONFIG_HOME="${XDG_CONFIG_HOME:-$HOME/Library/Application Support}"

if [[ -z "$GATEWAY_TOKEN" ]]; then
  echo "[soak] set OPENCLAW_GATEWAY_TOKEN or GATEWAY_TOKEN" >&2
  exit 1
fi

START_TS="$(date -u +%Y%m%d-%H%M%S)"
START_EPOCH="$(date +%s)"
END_EPOCH="$((START_EPOCH + DURATION_HOURS * 3600))"
OUT_DIR="docs/roadmaps/cua/research/artifacts/soak-${START_TS}"
mkdir -p "$OUT_DIR"

ITER=0
PASS=0
FAIL=0

run_smoke_iteration() {
  if [[ "$SOAK_ITER_TIMEOUT_SECONDS" -gt 0 ]]; then
    perl -e 'alarm shift @ARGV; exec @ARGV' "$SOAK_ITER_TIMEOUT_SECONDS" \
      env XDG_CONFIG_HOME="$XDG_CONFIG_HOME" \
      scripts/openclaw-agent-smoke.sh \
      --start-local-gateway \
      --gateway-url "$GATEWAY_URL" \
      --gateway-token "$GATEWAY_TOKEN"
  else
    XDG_CONFIG_HOME="$XDG_CONFIG_HOME" scripts/openclaw-agent-smoke.sh \
      --start-local-gateway \
      --gateway-url "$GATEWAY_URL" \
      --gateway-token "$GATEWAY_TOKEN"
  fi
}

while [[ "$(date +%s)" -lt "$END_EPOCH" ]]; do
  if [[ "$MAX_ITERATIONS" -gt 0 && "$ITER" -ge "$MAX_ITERATIONS" ]]; then
    break
  fi

  ITER="$((ITER + 1))"
  ITER_LOG="$OUT_DIR/iter-${ITER}.log"

  echo "[soak] iteration ${ITER} starting" | tee -a "$OUT_DIR/soak.log"

  EXIT_CODE=0
  REASON="ok"
  if run_smoke_iteration >"$ITER_LOG" 2>&1; then
    PASS="$((PASS + 1))"
    STATUS="pass"
  else
    EXIT_CODE="$?"
    if [[ "$EXIT_CODE" -eq 142 ]]; then
      REASON="timeout"
    else
      REASON="nonzero_exit"
    fi
    FAIL="$((FAIL + 1))"
    STATUS="fail"
  fi

  NOW_EPOCH="$(date +%s)"
  jq -cn \
    --argjson iteration "$ITER" \
    --arg status "$STATUS" \
    --argjson epoch "$NOW_EPOCH" \
    --arg log "$(basename "$ITER_LOG")" \
    --argjson exit_code "$EXIT_CODE" \
    --arg reason "$REASON" \
    '{iteration:$iteration,status:$status,epoch:$epoch,log:$log,exit_code:$exit_code,reason:$reason}' \
    >> "$OUT_DIR/results.jsonl"

  echo "[soak] iteration ${ITER} ${STATUS} reason=${REASON} exit=${EXIT_CODE}" | tee -a "$OUT_DIR/soak.log"

  if [[ "$NOW_EPOCH" -lt "$END_EPOCH" ]]; then
    sleep "$SLEEP_SECONDS"
  fi

done

END_TS="$(date -u +%Y%m%d-%H%M%S)"
TOTAL="$((PASS + FAIL))"
SUCCESS_RATE="0"
if [[ "$TOTAL" -gt 0 ]]; then
  SUCCESS_RATE="$(awk -v p="$PASS" -v t="$TOTAL" 'BEGIN { printf "%.4f", p / t }')"
fi

cat > "$OUT_DIR/summary.json" <<JSON
{
  "started_at_utc": "${START_TS}",
  "ended_at_utc": "${END_TS}",
  "duration_hours": ${DURATION_HOURS},
  "iterations": ${TOTAL},
  "pass": ${PASS},
  "fail": ${FAIL},
  "success_rate": ${SUCCESS_RATE},
  "gateway_url": "${GATEWAY_URL}",
  "sleep_seconds": ${SLEEP_SECONDS},
  "iteration_timeout_seconds": ${SOAK_ITER_TIMEOUT_SECONDS},
  "max_iterations": ${MAX_ITERATIONS}
}
JSON

echo "[soak] done"
echo "[soak] summary: $OUT_DIR/summary.json"
