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

DURATION_HOURS="${DURATION_HOURS:-6}"
SLEEP_SECONDS="${SLEEP_SECONDS:-30}"
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

while [[ "$(date +%s)" -lt "$END_EPOCH" ]]; do
  ITER="$((ITER + 1))"
  ITER_LOG="$OUT_DIR/iter-${ITER}.log"

  echo "[soak] iteration ${ITER} starting" | tee -a "$OUT_DIR/soak.log"

  if XDG_CONFIG_HOME="$XDG_CONFIG_HOME" scripts/openclaw-agent-smoke.sh \
    --start-local-gateway \
    --gateway-url "$GATEWAY_URL" \
    --gateway-token "$GATEWAY_TOKEN" >"$ITER_LOG" 2>&1; then
    PASS="$((PASS + 1))"
    STATUS="pass"
  else
    FAIL="$((FAIL + 1))"
    STATUS="fail"
  fi

  NOW_EPOCH="$(date +%s)"
  cat <<JSON >> "$OUT_DIR/results.jsonl"
{"iteration":${ITER},"status":"${STATUS}","epoch":${NOW_EPOCH},"log":"$(basename "$ITER_LOG")"}
JSON

  echo "[soak] iteration ${ITER} ${STATUS}" | tee -a "$OUT_DIR/soak.log"

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
  "sleep_seconds": ${SLEEP_SECONDS}
}
JSON

echo "[soak] done"
echo "[soak] summary: $OUT_DIR/summary.json"
