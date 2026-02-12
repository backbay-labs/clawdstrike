#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=scripts/lib/helm-ci-common.sh
source "${SCRIPT_DIR}/lib/helm-ci-common.sh"

LOG_PREFIX="helm-resilience"

usage() {
  cat <<'USAGE'
Nightly resilience + security validation for Clawdstrike Helm deployments.

Usage:
  scripts/helm-resilience-security.sh --chart-ref <oci-ref> --chart-version <version> [options]

Required:
  --chart-ref REF            OCI chart reference (for example: oci://ghcr.io/backbay-labs/clawdstrike/helm/clawdstrike)
  --chart-version VERSION    Target chart version under test

Optional:
  --previous-version VERSION Previous stable chart version (auto-resolved from OCI tags if omitted)
  --release NAME             Helm release name (default: clawdstrike-resilience)
  --namespace NAME           Kubernetes namespace (default: clawdstrike-resilience-<timestamp>)
  --values PATH              Helm values file path
  --timeout DURATION         Timeout budget for waits (default: 12m)
  --kube-context NAME        Kubernetes context override
  --artifact-dir PATH        Output directory for diagnostics (default: dist/helm-resilience/<release>-<namespace>)
  --skip-cleanup             Keep namespace/release after completion
  --run-openclaw-smoke       Attempt openclaw agent smoke check on this host
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
PREVIOUS_VERSION=""
RELEASE="clawdstrike-resilience"
NAMESPACE="clawdstrike-resilience-$(date +%Y%m%d-%H%M%S)"
VALUES_FILE=""
TIMEOUT="12m"
KUBE_CONTEXT=""
ARTIFACT_DIR=""
SKIP_CLEANUP=0
RUN_OPENCLAW_SMOKE=0

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
    --previous-version)
      PREVIOUS_VERSION="${2:-}"
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
    --run-openclaw-smoke)
      RUN_OPENCLAW_SMOKE=1
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
  ARTIFACT_DIR="dist/helm-resilience/${RELEASE}-${NAMESPACE}"
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
hc_require_cmd cargo "$LOG_PREFIX"
hc_require_cmd rg "$LOG_PREFIX"

resolve_previous_version() {
  if [[ -n "$PREVIOUS_VERSION" ]]; then
    return
  fi
  hc_require_cmd oras "$LOG_PREFIX"

  local repo
  repo="${CHART_REF#oci://}"
  mapfile -t tags < <(oras repo tags "$repo" 2>/dev/null | grep -E '^[0-9]+\.[0-9]+\.[0-9]+$' | sort -V)
  if ((${#tags[@]} < 2)); then
    hc_record_failure "unable to auto-resolve previous version from ${repo}"
    return
  fi

  local idx
  for ((idx=${#tags[@]}-1; idx>=0; idx--)); do
    if [[ "${tags[$idx]}" != "$CHART_VERSION" ]]; then
      PREVIOUS_VERSION="${tags[$idx]}"
      break
    fi
  done

  if [[ -z "$PREVIOUS_VERSION" ]]; then
    hc_record_failure "unable to select previous version distinct from ${CHART_VERSION}"
  fi
}

mkdir -p "$ARTIFACT_DIR"

NAMESPACE_OVERRIDE_VALUES="$ARTIFACT_DIR/namespace-values.yaml"
hc_write_namespace_override_values "$NAMESPACE_OVERRIDE_VALUES"

hc_ensure_namespace
hc_bootstrap_ghcr_pull_secret

if [[ "$RESULT" -eq 0 ]]; then
  resolve_previous_version
fi

upgrade_args_base=(
  --namespace "$NAMESPACE"
  --wait
  --timeout "$TIMEOUT"
)
if [[ -n "$VALUES_FILE" ]]; then
  upgrade_args_base+=(-f "$VALUES_FILE")
fi
upgrade_args_base+=(-f "$NAMESPACE_OVERRIDE_VALUES")

if [[ "$RESULT" -eq 0 ]]; then
  log "Installing previous stable version ${PREVIOUS_VERSION}"
  if ! hc_helm upgrade --install "$RELEASE" "$CHART_REF" --version "$PREVIOUS_VERSION" "${upgrade_args_base[@]}"; then
    HELM_STATUS="failed"
    hc_record_failure "failed to install previous version ${PREVIOUS_VERSION}"
  fi
fi

if [[ "$RESULT" -eq 0 ]]; then
  log "Upgrading to candidate version ${CHART_VERSION}"
  if hc_helm upgrade "$RELEASE" "$CHART_REF" --version "$CHART_VERSION" "${upgrade_args_base[@]}"; then
    HELM_STATUS="deployed"
  else
    HELM_STATUS="failed"
    hc_record_failure "upgrade to candidate version ${CHART_VERSION} failed"
  fi
fi

if [[ "$RESULT" -eq 0 ]]; then
  log "Restarting all release deployments"
  mapfile -t deployments < <(hc_kctl -n "$NAMESPACE" get deploy -l "app.kubernetes.io/instance=${RELEASE}" -o name 2>/dev/null)
  if ((${#deployments[@]} > 0)); then
    hc_kctl -n "$NAMESPACE" rollout restart "${deployments[@]}" >/dev/null
    for deploy in "${deployments[@]}"; do
      if ! hc_kctl -n "$NAMESPACE" rollout status "$deploy" --timeout="$TIMEOUT" >/dev/null; then
        hc_record_failure "deployment restart failed to recover: ${deploy}"
      fi
    done
  else
    hc_record_failure "no deployments found for restart test"
  fi
fi

if [[ "$RESULT" -eq 0 ]]; then
  log "Recycling nats pod"
  nats_pod="$(
    hc_kctl -n "$NAMESPACE" get pods \
      -l "app.kubernetes.io/instance=${RELEASE},app.kubernetes.io/component=nats" \
      -o jsonpath='{.items[0].metadata.name}' 2>/dev/null || true
  )"
  nats_sts="$(
    hc_kctl -n "$NAMESPACE" get sts \
      -l "app.kubernetes.io/instance=${RELEASE},app.kubernetes.io/component=nats" \
      -o jsonpath='{.items[0].metadata.name}' 2>/dev/null || true
  )"
  if [[ -n "$nats_pod" ]]; then
    hc_kctl -n "$NAMESPACE" delete pod "$nats_pod" --wait=true >/dev/null || true
  fi
  if [[ -n "$nats_sts" ]]; then
    if ! hc_kctl -n "$NAMESPACE" rollout status "statefulset/${nats_sts}" --timeout="$TIMEOUT" >/dev/null; then
      hc_record_failure "nats statefulset failed to recover after pod recycle"
    fi
  else
    hc_record_failure "nats statefulset not found for recycle test"
  fi
fi

if [[ "$RESULT" -eq 0 ]]; then
  log "Running helm test and health checks"
  if hc_helm test "$RELEASE" -n "$NAMESPACE" --timeout 5m; then
    HELM_TEST_STATUS="passed"
  else
    HELM_TEST_STATUS="failed"
    hc_record_failure "helm test failed after restart/recycle"
  fi

  if [[ "$RESULT" -eq 0 ]]; then
    HEALTH_STATUS="running"
    hc_health_check_service "${RELEASE}-hushd" "$HUSHD_SERVICE_PORT" "/health" || true
    hc_health_check_service "${RELEASE}-proofs-api" "$PROOFS_API_SERVICE_PORT" "/healthz" || true
    if [[ "$RESULT" -eq 0 ]]; then
      HEALTH_STATUS="healthy"
    else
      HEALTH_STATUS="failed"
    fi
  fi
fi

if [[ "$RESULT" -eq 0 ]]; then
  bad_pods="$(
    hc_kctl -n "$NAMESPACE" get pods -o json \
      | jq -r '.items[]
          | select(any(.status.containerStatuses[]?; (.state.waiting.reason // "") == "ImagePullBackOff" or (.state.waiting.reason // "") == "CrashLoopBackOff"))
          | .metadata.name'
  )"
  if [[ -n "$bad_pods" ]]; then
    hc_record_failure "detected unhealthy pods: ${bad_pods//$'\n'/, }"
  fi
fi

if [[ "$RESULT" -eq 0 ]]; then
  rendered="$ARTIFACT_DIR/rendered.yaml"
  render_args=(template "$RELEASE" "$CHART_REF" --version "$CHART_VERSION" --namespace "$NAMESPACE")
  if [[ -n "$VALUES_FILE" ]]; then
    render_args+=(-f "$VALUES_FILE")
  fi
  render_args+=(-f "$NAMESPACE_OVERRIDE_VALUES")
  hc_helm "${render_args[@]}" >"$rendered"
  if ! rg -q 'runAsNonRoot: true' "$rendered"; then
    hc_record_failure "rendered manifests missing runAsNonRoot: true"
  fi
  if ! rg -q 'readOnlyRootFilesystem: true' "$rendered"; then
    hc_record_failure "rendered manifests missing readOnlyRootFilesystem: true"
  fi
  if rg -q 'allowPrivilegeEscalation: true' "$rendered"; then
    hc_record_failure "rendered manifests contain allowPrivilegeEscalation: true"
  fi
fi

if [[ "$RESULT" -eq 0 ]]; then
  previous_revision="$(
    hc_helm history "$RELEASE" -n "$NAMESPACE" -o json \
      | jq -r '.[-1].revision'
  )"
  if [[ -z "$previous_revision" || "$previous_revision" == "null" ]]; then
    hc_record_failure "failed to resolve previous revision for rollback test"
  else
    log "Executing intentional bad upgrade to validate rollback"
    if hc_helm upgrade "$RELEASE" "$CHART_REF" --version "$CHART_VERSION" "${upgrade_args_base[@]}" --set hushd.image.tag=nonexistent-bad-tag >/dev/null 2>&1; then
      hc_record_failure "intentional bad upgrade unexpectedly succeeded"
    fi
    if ! hc_helm rollback "$RELEASE" "$previous_revision" -n "$NAMESPACE" --wait --timeout "$TIMEOUT" >/dev/null; then
      hc_record_failure "helm rollback failed"
    fi
    if [[ "$RESULT" -eq 0 ]]; then
      hc_health_check_service "${RELEASE}-hushd" "$HUSHD_SERVICE_PORT" "/health" || true
      hc_health_check_service "${RELEASE}-proofs-api" "$PROOFS_API_SERVICE_PORT" "/healthz" || true
    fi
  fi
fi

if [[ "$RESULT" -eq 0 ]]; then
  log "Running agent security tests"
  if ! cargo test --manifest-path apps/agent/src-tauri/Cargo.toml api_server::tests; then
    hc_record_failure "agent api_server::tests failed"
  fi
  if ! cargo test --manifest-path apps/agent/src-tauri/Cargo.toml openclaw::manager::tests; then
    hc_record_failure "agent openclaw::manager::tests failed"
  fi
fi

if [[ "$RUN_OPENCLAW_SMOKE" -eq 1 ]]; then
  log "Running optional OpenClaw smoke test"
  if [[ "$(uname -s)" != "Darwin" ]]; then
    hc_record_failure "openclaw smoke requested but runner is not macOS"
  elif [[ ! -f "${XDG_CONFIG_HOME:-$HOME/.config}/clawdstrike/agent-local-token" ]]; then
    hc_record_failure "openclaw smoke requested but agent-local-token is missing"
  elif ! scripts/openclaw-agent-smoke.sh --start-local-gateway --gateway-token nightly-smoke-token; then
    hc_record_failure "openclaw smoke script failed"
  fi
fi

hc_collect_diagnostics 1 1
hc_write_summary "Helm Resilience/Security Summary" "- previous_version: \`${PREVIOUS_VERSION}\`"

printf '\n'
log "Release/version: ${CHART_REF}:${CHART_VERSION} (prev: ${PREVIOUS_VERSION})"
log "Namespace/context: ${NAMESPACE} / $(hc_kctl config current-context 2>/dev/null || printf 'unknown')"
log "Helm test result: ${HELM_TEST_STATUS}"
log "Health result: ${HEALTH_STATUS}"
log "Diagnostics: ${ARTIFACT_DIR}"

hc_cleanup_release
exit "$RESULT"
