#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'USAGE'
Adaptive OpenClaw + Spine E2E smoke runner.

Usage:
  scripts/adaptive-openclaw-spine-e2e.sh [options]

Options:
  --artifact-dir PATH        Output directory (default: dist/adaptive-openclaw-spine-e2e/<timestamp>)
  --skip-openclaw            Skip OpenClaw blocked-call E2E script
  --skip-control             Skip control-api signed envelope integration test
  -h, --help                 Show this message

The script currently validates:
  1) OpenClaw tool-call interception blocks a destructive call.
  2) Control API approval resolve emits a signed Spine envelope.
USAGE
}

log() {
  printf '[adaptive-e2e] %s\n' "$*"
}

ARTIFACT_DIR="dist/adaptive-openclaw-spine-e2e/$(date -u +%Y%m%dT%H%M%SZ)"
RUN_OPENCLAW=1
RUN_CONTROL=1

while (($# > 0)); do
  case "$1" in
    --artifact-dir)
      ARTIFACT_DIR="${2:-}"
      shift 2
      ;;
    --skip-openclaw)
      RUN_OPENCLAW=0
      shift
      ;;
    --skip-control)
      RUN_CONTROL=0
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      printf '[adaptive-e2e] ERROR: unknown argument: %s\n' "$1" >&2
      usage
      exit 2
      ;;
  esac
done

mkdir -p "$ARTIFACT_DIR"

RESULT=0
FAILURES=()

OPENCLAW_STATUS="skipped"
CONTROL_STATUS="skipped"

if [[ "$RUN_OPENCLAW" -eq 1 ]]; then
  log "Running OpenClaw blocked-call E2E"
  OPENCLAW_STATUS="running"
  if [[ ! -d "packages/adapters/clawdstrike-openclaw/dist" ]]; then
    log "OpenClaw plugin dist missing; building package first"
    if npm --prefix packages/adapters/clawdstrike-openclaw run build:local-deps \
      >"${ARTIFACT_DIR}/openclaw-build.log" 2>&1 \
      && npm --prefix packages/adapters/clawdstrike-openclaw run build \
      >>"${ARTIFACT_DIR}/openclaw-build.log" 2>&1; then
      :
    elif npm --prefix packages/adapters/clawdstrike-openclaw run build \
      >>"${ARTIFACT_DIR}/openclaw-build.log" 2>&1; then
      :
    else
      OPENCLAW_STATUS="failed"
      RESULT=1
      FAILURES+=("openclaw plugin build failed")
    fi
  fi
  if [[ "$OPENCLAW_STATUS" != "failed" ]]; then
    if bash scripts/openclaw-plugin-blocked-call-e2e.sh \
      >"${ARTIFACT_DIR}/openclaw-blocked-call.log" 2>&1; then
      OPENCLAW_STATUS="passed"
    else
      OPENCLAW_STATUS="failed"
      RESULT=1
      FAILURES+=("openclaw blocked-call e2e failed")
    fi
  fi
fi

if [[ "$RUN_CONTROL" -eq 1 ]]; then
  log "Running control-api signed envelope integration test"
  CONTROL_STATUS="running"
  if cargo test -p clawdstrike-control-api \
    integration_tests::approvals_list_and_resolve_publish_signed_payload_and_mark_outbox_sent \
    -- --nocapture \
    >"${ARTIFACT_DIR}/control-approval-envelope.log" 2>&1; then
    CONTROL_STATUS="passed"
  else
    CONTROL_STATUS="failed"
    RESULT=1
    FAILURES+=("control API approval signed-envelope integration test failed")
  fi
fi

if ((${#FAILURES[@]})); then
  failures_json="$(printf '%s\n' "${FAILURES[@]}" | jq -R . | jq -s .)"
else
  failures_json='[]'
fi

jq -n \
  --arg generated_at "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
  --arg artifact_dir "$ARTIFACT_DIR" \
  --arg git_sha "$(git rev-parse --short HEAD)" \
  --arg openclaw_status "$OPENCLAW_STATUS" \
  --arg control_status "$CONTROL_STATUS" \
  --argjson failures "$failures_json" \
  --arg result "$(if [[ "$RESULT" -eq 0 ]]; then echo pass; else echo fail; fi)" \
  '{
    generated_at: $generated_at,
    git_sha: $git_sha,
    artifact_dir: $artifact_dir,
    checks: {
      openclaw_blocked_call_e2e: $openclaw_status,
      control_signed_envelope_integration: $control_status
    },
    failures: $failures,
    result: $result
  }' >"${ARTIFACT_DIR}/summary.json"

{
  printf '# Adaptive OpenClaw + Spine E2E Summary\n\n'
  printf -- '- generated_at: `%s`\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  printf -- '- git_sha: `%s`\n' "$(git rev-parse --short HEAD)"
  printf -- '- openclaw_blocked_call_e2e: `%s`\n' "$OPENCLAW_STATUS"
  printf -- '- control_signed_envelope_integration: `%s`\n' "$CONTROL_STATUS"
  printf -- '- artifact_dir: `%s`\n' "$ARTIFACT_DIR"
  if ((${#FAILURES[@]})); then
    printf '\n## Failures\n'
    for failure in "${FAILURES[@]}"; do
      printf -- '- %s\n' "$failure"
    done
  fi
} >"${ARTIFACT_DIR}/summary.md"

log "Summary: ${ARTIFACT_DIR}/summary.json"
exit "$RESULT"
