#!/usr/bin/env bash
set -euo pipefail

LOG_PREFIX="helm-all-on-preflight"

usage() {
  cat <<'USAGE'
Validate strict prerequisites before deploying the all-on Clawdstrike Helm profile.

Usage:
  scripts/helm-all-on-preflight.sh [options]

Options:
  --profile PATH          Values profile to validate
                          (default: infra/deploy/helm/clawdstrike/profiles/all-on-dev-platform.yaml)
  --chart PATH            Helm chart path (default: infra/deploy/helm/clawdstrike)
  --kube-context NAME     Kubernetes context override
  -h, --help              Show this help

Checks:
  - helm lint + template render with profile
  - bridge image references exist in GHCR
  - IngressClass/alb exists
  - ServiceMonitor CRD exists
  - Hubble relay has at least one ready endpoint
  - Tetragon daemonset is fully ready
USAGE
}

log() {
  printf '[%s] %s\n' "$LOG_PREFIX" "$*"
}

require_cmd() {
  if ! command -v "$1" >/dev/null 2>&1; then
    printf '[%s] ERROR: missing command: %s\n' "$LOG_PREFIX" "$1" >&2
    exit 2
  fi
}

PROFILE="infra/deploy/helm/clawdstrike/profiles/all-on-dev-platform.yaml"
CHART_PATH="infra/deploy/helm/clawdstrike"
KUBE_CONTEXT=""

while (($# > 0)); do
  case "$1" in
    --profile)
      PROFILE="${2:-}"
      shift 2
      ;;
    --chart)
      CHART_PATH="${2:-}"
      shift 2
      ;;
    --kube-context)
      KUBE_CONTEXT="${2:-}"
      shift 2
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

for cmd in helm kubectl jq oras; do
  require_cmd "$cmd"
done

if [[ ! -f "$PROFILE" ]]; then
  printf '[%s] ERROR: profile not found: %s\n' "$LOG_PREFIX" "$PROFILE" >&2
  exit 2
fi

if [[ ! -d "$CHART_PATH" ]]; then
  printf '[%s] ERROR: chart path not found: %s\n' "$LOG_PREFIX" "$CHART_PATH" >&2
  exit 2
fi

KCTL=(kubectl)
if [[ -n "$KUBE_CONTEXT" ]]; then
  KCTL+=(--context "$KUBE_CONTEXT")
fi

HELM=(helm)
if [[ -n "$KUBE_CONTEXT" ]]; then
  HELM+=(--kube-context "$KUBE_CONTEXT")
fi

FAILURES=()

record_failure() {
  FAILURES+=("$1")
}

check_cmd() {
  local description="$1"
  shift
  if "$@"; then
    log "PASS: ${description}"
  else
    log "FAIL: ${description}"
    record_failure "$description"
  fi
}

check_cmd "helm lint succeeds" "${HELM[@]}" lint "$CHART_PATH" >/dev/null
check_cmd "helm template succeeds with all-on profile" "${HELM[@]}" template preflight "$CHART_PATH" -f "$PROFILE" >/dev/null

check_cmd "IngressClass alb exists" "${KCTL[@]}" get ingressclass alb >/dev/null
check_cmd "ServiceMonitor CRD exists" "${KCTL[@]}" get crd servicemonitors.monitoring.coreos.com >/dev/null

check_cmd "Tetragon daemonset is ready" \
  bash -lc "${KCTL[*]} -n kube-system get ds tetragon -o json | jq -e '.status.desiredNumberScheduled > 0 and .status.numberReady == .status.desiredNumberScheduled' >/dev/null"

check_cmd "Hubble relay has ready endpoints" \
  bash -lc "${KCTL[*]} -n kube-system get endpointslice -l kubernetes.io/service-name=hubble-relay -o json | jq -e '[.items[].endpoints[]? | select(.conditions.ready==true)] | length > 0' >/dev/null"

render_bridge_image_ref() {
  local template_path="$1"
  "${HELM[@]}" template preflight "$CHART_PATH" -f "$PROFILE" --show-only "$template_path" 2>/dev/null \
    | awk '/^[[:space:]]*image:[[:space:]]*/ { print $2; exit }'
}

check_bridge_image() {
  local bridge_name="$1"
  local template_path="$2"
  local image_ref

  image_ref="$(render_bridge_image_ref "$template_path")"
  if [[ -z "$image_ref" ]]; then
    log "INFO: ${bridge_name} bridge not rendered by profile; skipping image existence check"
    return 0
  fi

  if [[ "$image_ref" != *:* ]]; then
    log "FAIL: ${bridge_name} bridge rendered image has no explicit tag (${image_ref})"
    record_failure "${bridge_name} bridge rendered image has no explicit tag (${image_ref})"
    return 1
  fi

  if oras manifest fetch --descriptor "$image_ref" >/dev/null 2>&1; then
    log "PASS: image exists ${image_ref}"
  else
    log "FAIL: image missing ${image_ref}"
    record_failure "image missing ${image_ref}"
    return 1
  fi
}

check_bridge_image "tetragon" "templates/bridges/tetragon-bridge-daemonset.yaml"
check_bridge_image "hubble" "templates/bridges/hubble-bridge-daemonset.yaml"

if ((${#FAILURES[@]} > 0)); then
  printf '\n[%s] Preflight failed with %d issue(s):\n' "$LOG_PREFIX" "${#FAILURES[@]}" >&2
  for failure in "${FAILURES[@]}"; do
    printf '[%s] - %s\n' "$LOG_PREFIX" "$failure" >&2
  done
  exit 1
fi

log "All strict preflight checks passed."
