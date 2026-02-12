#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=scripts/lib/helm-ci-common.sh
source "${SCRIPT_DIR}/lib/helm-ci-common.sh"

LOG_PREFIX="helm-e2e"

usage() {
  cat <<'USAGE'
Helm E2E smoke test for Clawdstrike chart installs from OCI.

Usage:
  scripts/helm-e2e-smoke.sh --chart-ref <oci-ref> --chart-version <version> [options]

Required:
  --chart-ref REF            OCI chart reference (for example: oci://ghcr.io/backbay-labs/clawdstrike/helm/clawdstrike)
  --chart-version VERSION    Chart version tag to install

Optional:
  --release NAME             Helm release name (default: clawdstrike-smoke)
  --namespace NAME           Kubernetes namespace (default: clawdstrike-smoke-<timestamp>)
  --values PATH              Helm values file path
  --timeout DURATION         Helm wait timeout (default: 10m)
  --kube-context NAME        Kubernetes context override
  --artifact-dir PATH        Output directory for diagnostics (default: dist/helm-smoke/<release>-<namespace>)
  --skip-cleanup             Keep namespace/release after completion
  -h, --help                 Show this help

Environment:
  GHCR_PULL_USERNAME         Optional GHCR username for image pull secret bootstrap
  GHCR_PULL_TOKEN            Optional GHCR token for image pull secret bootstrap
  HUSHD_SERVICE_PORT         Override hushd service port for health check (default: 9876)
  PROOFS_API_SERVICE_PORT    Override proofs-api service port for health check (default: 8080)
USAGE
}

log() {
  hc_log "$LOG_PREFIX" "$*"
}

CHART_REF=""
CHART_VERSION=""
RELEASE="clawdstrike-smoke"
NAMESPACE="clawdstrike-smoke-$(date +%s)"
VALUES_FILE=""
TIMEOUT="10m"
KUBE_CONTEXT=""
ARTIFACT_DIR=""
SKIP_CLEANUP=0

while (($# > 0)); do
  case "$1" in
    --chart-ref)
      CHART_REF="${2:-}"
      shift 2
      ;;
    --chart-version)
      CHART_VERSION="${2:-}"
      shift 2
      ;;
    --release)
      RELEASE="${2:-}"
      shift 2
      ;;
    --namespace)
      NAMESPACE="${2:-}"
      shift 2
      ;;
    --values)
      VALUES_FILE="${2:-}"
      shift 2
      ;;
    --timeout)
      TIMEOUT="${2:-}"
      shift 2
      ;;
    --kube-context)
      KUBE_CONTEXT="${2:-}"
      shift 2
      ;;
    --artifact-dir)
      ARTIFACT_DIR="${2:-}"
      shift 2
      ;;
    --skip-cleanup)
      SKIP_CLEANUP=1
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      printf '[%s] ERROR: unknown argument: %s\n' "$LOG_PREFIX" "$1" >&2
      usage
      exit 2
      ;;
  esac
done

if [[ -z "$CHART_REF" || -z "$CHART_VERSION" ]]; then
  printf '[%s] ERROR: --chart-ref and --chart-version are required\n' "$LOG_PREFIX" >&2
  usage
  exit 2
fi

if [[ -n "$VALUES_FILE" && ! -f "$VALUES_FILE" ]]; then
  printf '[%s] ERROR: values file not found: %s\n' "$LOG_PREFIX" "$VALUES_FILE" >&2
  exit 2
fi

if [[ -z "$ARTIFACT_DIR" ]]; then
  ARTIFACT_DIR="dist/helm-smoke/${RELEASE}-${NAMESPACE}"
fi

HUSHD_SERVICE_PORT="${HUSHD_SERVICE_PORT:-9876}"
PROOFS_API_SERVICE_PORT="${PROOFS_API_SERVICE_PORT:-8080}"
TIMESTAMP="$(date -u +%Y-%m-%dT%H:%M:%SZ)"

HELM_STATUS="not_run"
HELM_TEST_STATUS="not_run"
HEALTH_STATUS="not_run"
RESULT=0
FAILURES=()

hc_init_context_args "$KUBE_CONTEXT"
hc_require_cmd helm "$LOG_PREFIX"
hc_require_cmd kubectl "$LOG_PREFIX"
hc_require_cmd jq "$LOG_PREFIX"
hc_require_cmd curl "$LOG_PREFIX"

mkdir -p "$ARTIFACT_DIR"

NAMESPACE_OVERRIDE_VALUES="$ARTIFACT_DIR/namespace-values.yaml"
hc_write_namespace_override_values "$NAMESPACE_OVERRIDE_VALUES"

hc_ensure_namespace
hc_bootstrap_ghcr_pull_secret

if [[ "$RESULT" -eq 0 ]]; then
  log "Installing chart ${CHART_REF}:${CHART_VERSION} as ${RELEASE} in ${NAMESPACE}"
  upgrade_args=(
    upgrade --install "$RELEASE" "$CHART_REF"
    --version "$CHART_VERSION"
    --namespace "$NAMESPACE"
    --wait
    --timeout "$TIMEOUT"
  )
  if [[ -n "$VALUES_FILE" ]]; then
    upgrade_args+=(-f "$VALUES_FILE")
  fi
  upgrade_args+=(-f "$NAMESPACE_OVERRIDE_VALUES")
  if hc_helm "${upgrade_args[@]}"; then
    HELM_STATUS="deployed"
  else
    HELM_STATUS="failed"
    hc_record_failure "helm upgrade --install failed"
  fi
fi

if [[ "$RESULT" -eq 0 ]]; then
  log "Running helm test for ${RELEASE}"
  if hc_helm test "$RELEASE" -n "$NAMESPACE" --timeout 5m; then
    HELM_TEST_STATUS="passed"
  else
    HELM_TEST_STATUS="failed"
    hc_record_failure "helm test failed"
  fi
fi

if [[ "$RESULT" -eq 0 ]]; then
  log "Waiting for pod readiness"
  if ! hc_kctl -n "$NAMESPACE" wait --for=condition=Ready pod -l "app.kubernetes.io/instance=${RELEASE}" --timeout="$TIMEOUT" >/dev/null; then
    hc_record_failure "pods did not become Ready before timeout"
  fi
fi

if [[ "$RESULT" -eq 0 ]]; then
  log "Validating service health"
  HEALTH_STATUS="running"
  hc_health_check_service "${RELEASE}-hushd" "$HUSHD_SERVICE_PORT" "/health" || true
  hc_health_check_service "${RELEASE}-proofs-api" "$PROOFS_API_SERVICE_PORT" "/healthz" || true
  if [[ "$RESULT" -eq 0 ]]; then
    HEALTH_STATUS="healthy"
  else
    HEALTH_STATUS="failed"
  fi
fi

hc_collect_diagnostics 0 0
hc_write_summary "Helm E2E Smoke Summary"

printf '\n'
log "Release/version: ${CHART_REF}:${CHART_VERSION}"
log "Namespace/context: ${NAMESPACE} / $(hc_kctl config current-context 2>/dev/null || printf 'unknown')"
log "Helm test result: ${HELM_TEST_STATUS}"
log "Health result: ${HEALTH_STATUS}"
log "Diagnostics: ${ARTIFACT_DIR}"

hc_cleanup_release
exit "$RESULT"
