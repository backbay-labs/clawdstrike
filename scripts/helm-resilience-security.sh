#!/usr/bin/env bash
set -euo pipefail

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
  printf '[helm-resilience] %s\n' "$*"
}

require_cmd() {
  if ! command -v "$1" >/dev/null 2>&1; then
    printf '[helm-resilience] ERROR: missing required command: %s\n' "$1" >&2
    exit 2
  fi
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
      printf '[helm-resilience] ERROR: unknown argument: %s\n' "$1" >&2
      usage
      exit 2
      ;;
  esac
done

if [[ -z "$CHART_REF" || -z "$CHART_VERSION" ]]; then
  printf '[helm-resilience] ERROR: --chart-ref and --chart-version are required\n' >&2
  usage
  exit 2
fi

if [[ -n "$VALUES_FILE" && ! -f "$VALUES_FILE" ]]; then
  printf '[helm-resilience] ERROR: values file not found: %s\n' "$VALUES_FILE" >&2
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

KCTL_ARGS=()
HELM_ARGS=()
if [[ -n "$KUBE_CONTEXT" ]]; then
  KCTL_ARGS+=(--context "$KUBE_CONTEXT")
  HELM_ARGS+=(--kube-context "$KUBE_CONTEXT")
fi

kctl() {
  if ((${#KCTL_ARGS[@]})); then
    kubectl "${KCTL_ARGS[@]}" "$@"
  else
    kubectl "$@"
  fi
}

helm_cmd() {
  if ((${#HELM_ARGS[@]})); then
    helm "${HELM_ARGS[@]}" "$@"
  else
    helm "$@"
  fi
}

record_failure() {
  FAILURES+=("$1")
  RESULT=1
}

collect_diagnostics() {
  mkdir -p "$ARTIFACT_DIR"/describe "$ARTIFACT_DIR"/logs
  kctl config current-context >"$ARTIFACT_DIR/context.txt" 2>/dev/null || true
  helm_cmd list -n "$NAMESPACE" >"$ARTIFACT_DIR/helm-list.txt" 2>/dev/null || true
  helm_cmd status "$RELEASE" -n "$NAMESPACE" >"$ARTIFACT_DIR/helm-status.txt" 2>/dev/null || true
  helm_cmd history "$RELEASE" -n "$NAMESPACE" >"$ARTIFACT_DIR/helm-history.txt" 2>/dev/null || true
  kctl -n "$NAMESPACE" get pods -o wide >"$ARTIFACT_DIR/pods.txt" 2>/dev/null || true
  kctl -n "$NAMESPACE" get deploy,sts,svc >"$ARTIFACT_DIR/workloads.txt" 2>/dev/null || true
  kctl -n "$NAMESPACE" get events --sort-by=.lastTimestamp >"$ARTIFACT_DIR/events.txt" 2>/dev/null || true

  while IFS= read -r pod; do
    [[ -n "$pod" ]] || continue
    kctl -n "$NAMESPACE" describe pod "$pod" >"$ARTIFACT_DIR/describe/${pod}.txt" 2>/dev/null || true
    while IFS= read -r container; do
      [[ -n "$container" ]] || continue
      kctl -n "$NAMESPACE" logs "$pod" -c "$container" >"$ARTIFACT_DIR/logs/${pod}-${container}.log" 2>/dev/null || true
      kctl -n "$NAMESPACE" logs "$pod" -c "$container" --previous >"$ARTIFACT_DIR/logs/${pod}-${container}.previous.log" 2>/dev/null || true
    done < <(kctl -n "$NAMESPACE" get pod "$pod" -o jsonpath='{.spec.containers[*].name}' 2>/dev/null | tr ' ' '\n')
  done < <(kctl -n "$NAMESPACE" get pods -o jsonpath='{.items[*].metadata.name}' 2>/dev/null | tr ' ' '\n')
}

write_summary() {
  local failures_json
  if ((${#FAILURES[@]})); then
    failures_json="$(printf '%s\n' "${FAILURES[@]}" | jq -R . | jq -s .)"
  else
    failures_json='[]'
  fi

  local context_value
  context_value="$(kctl config current-context 2>/dev/null || printf 'unknown')"

  jq -n \
    --arg chart_ref "$CHART_REF" \
    --arg chart_version "$CHART_VERSION" \
    --arg cluster_context "$context_value" \
    --arg namespace "$NAMESPACE" \
    --arg helm_status "$HELM_STATUS" \
    --arg helm_test "$HELM_TEST_STATUS" \
    --arg health "$HEALTH_STATUS" \
    --arg timestamp "$TIMESTAMP" \
    --argjson failures "$failures_json" \
    '{
      chart_ref: $chart_ref,
      chart_version: $chart_version,
      cluster_context: $cluster_context,
      namespace: $namespace,
      helm_status: $helm_status,
      helm_test: $helm_test,
      health: $health,
      timestamp: $timestamp,
      failures: $failures
    }' >"$ARTIFACT_DIR/summary.json"

  {
    printf '# Helm Resilience/Security Summary\n\n'
    printf -- '- chart_ref: `%s`\n' "$CHART_REF"
    printf -- '- chart_version: `%s`\n' "$CHART_VERSION"
    printf -- '- previous_version: `%s`\n' "$PREVIOUS_VERSION"
    printf -- '- cluster_context: `%s`\n' "$context_value"
    printf -- '- namespace: `%s`\n' "$NAMESPACE"
    printf -- '- helm_status: `%s`\n' "$HELM_STATUS"
    printf -- '- helm_test: `%s`\n' "$HELM_TEST_STATUS"
    printf -- '- health: `%s`\n' "$HEALTH_STATUS"
    printf -- '- artifacts: `%s`\n' "$ARTIFACT_DIR"
    if ((${#FAILURES[@]})); then
      printf '\n## Failures\n'
      for failure in "${FAILURES[@]}"; do
        printf -- '- %s\n' "$failure"
      done
    fi
  } >"$ARTIFACT_DIR/summary.md"
}

health_check_service() {
  local svc="$1"
  local target_port="$2"
  local path="$3"
  local pf_log="$ARTIFACT_DIR/port-forward-${svc}.log"

  kctl -n "$NAMESPACE" port-forward "svc/${svc}" ":${target_port}" >"$pf_log" 2>&1 &
  local pf_pid="$!"
  local local_port=""
  for _ in $(seq 1 30); do
    local_port="$(
      sed -nE 's/.*127\.0\.0\.1:([0-9]+) -> .*/\1/p' "$pf_log" 2>/dev/null | head -n 1
    )"
    if [[ -n "$local_port" ]]; then
      break
    fi
    if ! kill -0 "$pf_pid" >/dev/null 2>&1; then
      break
    fi
    sleep 0.2
  done

  if [[ -z "$local_port" ]]; then
    kill "$pf_pid" >/dev/null 2>&1 || true
    wait "$pf_pid" >/dev/null 2>&1 || true
    record_failure "failed to start port-forward for service: ${svc}"
    return 1
  fi

  local ok=0
  for _ in $(seq 1 25); do
    if curl -fsS "http://127.0.0.1:${local_port}${path}" >/dev/null 2>&1; then
      ok=1
      break
    fi
    sleep 1
  done

  kill "$pf_pid" >/dev/null 2>&1 || true
  wait "$pf_pid" >/dev/null 2>&1 || true

  if [[ "$ok" -ne 1 ]]; then
    record_failure "health check failed: ${svc}${path}"
    return 1
  fi

  return 0
}

resolve_previous_version() {
  if [[ -n "$PREVIOUS_VERSION" ]]; then
    return
  fi
  require_cmd oras

  local repo
  repo="${CHART_REF#oci://}"
  mapfile -t tags < <(oras repo tags "$repo" 2>/dev/null | grep -E '^[0-9]+\.[0-9]+\.[0-9]+$' | sort -V)
  if ((${#tags[@]} < 2)); then
    record_failure "unable to auto-resolve previous version from ${repo}"
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
    record_failure "unable to select previous version distinct from ${CHART_VERSION}"
  fi
}

cleanup() {
  if [[ "$SKIP_CLEANUP" -eq 1 ]]; then
    return
  fi
  helm_cmd uninstall "$RELEASE" -n "$NAMESPACE" >/dev/null 2>&1 || true
  if [[ "${NAMESPACE_CREATED:-0}" -eq 1 ]]; then
    kctl delete namespace "$NAMESPACE" --wait=false >/dev/null 2>&1 || true
  fi
}

require_cmd helm
require_cmd kubectl
require_cmd jq
require_cmd curl
require_cmd cargo
require_cmd rg

mkdir -p "$ARTIFACT_DIR"

NAMESPACE_OVERRIDE_VALUES="$ARTIFACT_DIR/namespace-values.yaml"
cat >"$NAMESPACE_OVERRIDE_VALUES" <<EOF
global:
  namespace: "$NAMESPACE"
namespace:
  create: false
  name: "$NAMESPACE"
EOF

NAMESPACE_CREATED=0
if ! kctl get namespace "$NAMESPACE" >/dev/null 2>&1; then
  if [[ "$(kctl auth can-i create namespaces 2>/dev/null || printf 'no')" != "yes" ]]; then
    record_failure "missing permission: create namespaces"
  else
    kctl create namespace "$NAMESPACE" >/dev/null
    NAMESPACE_CREATED=1
  fi
fi

if [[ -n "${GHCR_PULL_USERNAME:-}" || -n "${GHCR_PULL_TOKEN:-}" ]]; then
  if [[ -z "${GHCR_PULL_USERNAME:-}" || -z "${GHCR_PULL_TOKEN:-}" ]]; then
    record_failure "set both GHCR_PULL_USERNAME and GHCR_PULL_TOKEN for pull-secret bootstrap"
  else
    kctl -n "$NAMESPACE" create secret docker-registry ghcr-pull \
      --docker-server=ghcr.io \
      --docker-username="$GHCR_PULL_USERNAME" \
      --docker-password="$GHCR_PULL_TOKEN" \
      --dry-run=client -o yaml | kctl -n "$NAMESPACE" apply -f - >/dev/null
  fi
fi

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
  if ! helm_cmd upgrade --install "$RELEASE" "$CHART_REF" --version "$PREVIOUS_VERSION" "${upgrade_args_base[@]}"; then
    HELM_STATUS="failed"
    record_failure "failed to install previous version ${PREVIOUS_VERSION}"
  fi
fi

if [[ "$RESULT" -eq 0 ]]; then
  log "Upgrading to candidate version ${CHART_VERSION}"
  if helm_cmd upgrade "$RELEASE" "$CHART_REF" --version "$CHART_VERSION" "${upgrade_args_base[@]}"; then
    HELM_STATUS="deployed"
  else
    HELM_STATUS="failed"
    record_failure "upgrade to candidate version ${CHART_VERSION} failed"
  fi
fi

if [[ "$RESULT" -eq 0 ]]; then
  log "Restarting all release deployments"
  mapfile -t deployments < <(kctl -n "$NAMESPACE" get deploy -l "app.kubernetes.io/instance=${RELEASE}" -o name 2>/dev/null)
  if ((${#deployments[@]} > 0)); then
    kctl -n "$NAMESPACE" rollout restart "${deployments[@]}" >/dev/null
    for deploy in "${deployments[@]}"; do
      if ! kctl -n "$NAMESPACE" rollout status "$deploy" --timeout="$TIMEOUT" >/dev/null; then
        record_failure "deployment restart failed to recover: ${deploy}"
      fi
    done
  else
    record_failure "no deployments found for restart test"
  fi
fi

if [[ "$RESULT" -eq 0 ]]; then
  log "Recycling nats pod"
  nats_pod="$(
    kctl -n "$NAMESPACE" get pods \
      -l "app.kubernetes.io/instance=${RELEASE},app.kubernetes.io/component=nats" \
      -o jsonpath='{.items[0].metadata.name}' 2>/dev/null || true
  )"
  nats_sts="$(
    kctl -n "$NAMESPACE" get sts \
      -l "app.kubernetes.io/instance=${RELEASE},app.kubernetes.io/component=nats" \
      -o jsonpath='{.items[0].metadata.name}' 2>/dev/null || true
  )"
  if [[ -n "$nats_pod" ]]; then
    kctl -n "$NAMESPACE" delete pod "$nats_pod" --wait=true >/dev/null || true
  fi
  if [[ -n "$nats_sts" ]]; then
    if ! kctl -n "$NAMESPACE" rollout status "statefulset/${nats_sts}" --timeout="$TIMEOUT" >/dev/null; then
      record_failure "nats statefulset failed to recover after pod recycle"
    fi
  else
    record_failure "nats statefulset not found for recycle test"
  fi
fi

if [[ "$RESULT" -eq 0 ]]; then
  log "Running helm test and health checks"
  if helm_cmd test "$RELEASE" -n "$NAMESPACE" --timeout 5m; then
    HELM_TEST_STATUS="passed"
  else
    HELM_TEST_STATUS="failed"
    record_failure "helm test failed after restart/recycle"
  fi

  if [[ "$RESULT" -eq 0 ]]; then
    HEALTH_STATUS="running"
    health_check_service "${RELEASE}-hushd" "$HUSHD_SERVICE_PORT" "/health" || true
    health_check_service "${RELEASE}-proofs-api" "$PROOFS_API_SERVICE_PORT" "/healthz" || true
    if [[ "$RESULT" -eq 0 ]]; then
      HEALTH_STATUS="healthy"
    else
      HEALTH_STATUS="failed"
    fi
  fi
fi

if [[ "$RESULT" -eq 0 ]]; then
  bad_pods="$(
    kctl -n "$NAMESPACE" get pods -o json \
      | jq -r '.items[]
          | select(any(.status.containerStatuses[]?; (.state.waiting.reason // "") == "ImagePullBackOff" or (.state.waiting.reason // "") == "CrashLoopBackOff"))
          | .metadata.name'
  )"
  if [[ -n "$bad_pods" ]]; then
    record_failure "detected unhealthy pods: ${bad_pods//$'\n'/, }"
  fi
fi

if [[ "$RESULT" -eq 0 ]]; then
  rendered="$ARTIFACT_DIR/rendered.yaml"
  render_args=(template "$RELEASE" "$CHART_REF" --version "$CHART_VERSION" --namespace "$NAMESPACE")
  if [[ -n "$VALUES_FILE" ]]; then
    render_args+=(-f "$VALUES_FILE")
  fi
  render_args+=(-f "$NAMESPACE_OVERRIDE_VALUES")
  helm_cmd "${render_args[@]}" >"$rendered"
  if ! rg -q 'runAsNonRoot: true' "$rendered"; then
    record_failure "rendered manifests missing runAsNonRoot: true"
  fi
  if ! rg -q 'readOnlyRootFilesystem: true' "$rendered"; then
    record_failure "rendered manifests missing readOnlyRootFilesystem: true"
  fi
  if rg -q 'allowPrivilegeEscalation: true' "$rendered"; then
    record_failure "rendered manifests contain allowPrivilegeEscalation: true"
  fi
fi

if [[ "$RESULT" -eq 0 ]]; then
  previous_revision="$(
    helm_cmd history "$RELEASE" -n "$NAMESPACE" -o json \
      | jq -r '.[-1].revision'
  )"
  if [[ -z "$previous_revision" || "$previous_revision" == "null" ]]; then
    record_failure "failed to resolve previous revision for rollback test"
  else
    log "Executing intentional bad upgrade to validate rollback"
    if helm_cmd upgrade "$RELEASE" "$CHART_REF" --version "$CHART_VERSION" "${upgrade_args_base[@]}" --set hushd.image.tag=nonexistent-bad-tag >/dev/null 2>&1; then
      record_failure "intentional bad upgrade unexpectedly succeeded"
    fi
    if ! helm_cmd rollback "$RELEASE" "$previous_revision" -n "$NAMESPACE" --wait --timeout "$TIMEOUT" >/dev/null; then
      record_failure "helm rollback failed"
    fi
    if [[ "$RESULT" -eq 0 ]]; then
      health_check_service "${RELEASE}-hushd" "$HUSHD_SERVICE_PORT" "/health" || true
      health_check_service "${RELEASE}-proofs-api" "$PROOFS_API_SERVICE_PORT" "/healthz" || true
    fi
  fi
fi

if [[ "$RESULT" -eq 0 ]]; then
  log "Running agent security tests"
  if ! cargo test --manifest-path apps/agent/src-tauri/Cargo.toml api_server::tests; then
    record_failure "agent api_server::tests failed"
  fi
  if ! cargo test --manifest-path apps/agent/src-tauri/Cargo.toml openclaw::manager::tests; then
    record_failure "agent openclaw::manager::tests failed"
  fi
fi

if [[ "$RUN_OPENCLAW_SMOKE" -eq 1 ]]; then
  log "Running optional OpenClaw smoke test"
  if [[ "$(uname -s)" != "Darwin" ]]; then
    record_failure "openclaw smoke requested but runner is not macOS"
  elif [[ ! -f "${XDG_CONFIG_HOME:-$HOME/.config}/clawdstrike/agent-local-token" ]]; then
    record_failure "openclaw smoke requested but agent-local-token is missing"
  elif ! scripts/openclaw-agent-smoke.sh --start-local-gateway --gateway-token nightly-smoke-token; then
    record_failure "openclaw smoke script failed"
  fi
fi

collect_diagnostics
write_summary

printf '\n'
log "Release/version: ${CHART_REF}:${CHART_VERSION} (prev: ${PREVIOUS_VERSION})"
log "Namespace/context: ${NAMESPACE} / $(kctl config current-context 2>/dev/null || printf 'unknown')"
log "Helm test result: ${HELM_TEST_STATUS}"
log "Health result: ${HEALTH_STATUS}"
log "Diagnostics: ${ARTIFACT_DIR}"

cleanup
exit "$RESULT"
