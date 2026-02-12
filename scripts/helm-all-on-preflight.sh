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

for cmd in helm kubectl jq oras python3; do
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

PROFILE_JSON="$(python3 - "$PROFILE" <<'PY'
import json
import sys
from pathlib import Path
import yaml

profile = yaml.safe_load(Path(sys.argv[1]).read_text())
bridges = profile.get("bridges", {})
items = []
for name in ("tetragon", "hubble"):
    cfg = bridges.get(name, {})
    enabled = bool(cfg.get("enabled", False))
    image = cfg.get("image", {}) or {}
    repo = image.get("repository", f"ghcr.io/backbay-labs/clawdstrike/{name}-bridge")
    tag = image.get("tag", "")
    items.append({"name": name, "enabled": enabled, "repository": repo, "tag": tag})

print(json.dumps({"bridges": items}))
PY
)"

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

while IFS= read -r bridge; do
  enabled="$(jq -r '.enabled' <<<"$bridge")"
  if [[ "$enabled" != "true" ]]; then
    continue
  fi
  name="$(jq -r '.name' <<<"$bridge")"
  repo="$(jq -r '.repository' <<<"$bridge")"
  tag="$(jq -r '.tag' <<<"$bridge")"
  if [[ -z "$tag" ]]; then
    record_failure "${name} bridge image tag is empty in profile"
    log "FAIL: ${name} bridge image tag is empty in profile"
    continue
  fi
  ref="${repo}:${tag}"
  if oras manifest fetch --descriptor "$ref" >/dev/null 2>&1; then
    log "PASS: image exists ${ref}"
  else
    log "FAIL: image missing ${ref}"
    record_failure "image missing ${ref}"
  fi
done < <(jq -c '.bridges[]' <<<"$PROFILE_JSON")

if ((${#FAILURES[@]} > 0)); then
  printf '\n[%s] Preflight failed with %d issue(s):\n' "$LOG_PREFIX" "${#FAILURES[@]}" >&2
  for failure in "${FAILURES[@]}"; do
    printf '[%s] - %s\n' "$LOG_PREFIX" "$failure" >&2
  done
  exit 1
fi

log "All strict preflight checks passed."
