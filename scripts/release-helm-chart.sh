#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'EOF'
Build, validate, and optionally publish the ClawdStrike Helm chart.

Usage:
  scripts/release-helm-chart.sh --version <semver> [--push]
  scripts/release-helm-chart.sh <semver> [--push]

Environment:
  HELM_OCI_REPO            OCI repository (default: oci://ghcr.io/backbay-labs/clawdstrike/helm)
  HELM_REGISTRY_USERNAME   Optional registry username for helm registry login
  HELM_REGISTRY_PASSWORD   Optional registry password for helm registry login
  CHART_APP_VERSION        Optional chart appVersion override (defaults to Chart.yaml)

Examples:
  scripts/release-helm-chart.sh 0.1.0
  HELM_REGISTRY_USERNAME="$GITHUB_ACTOR" HELM_REGISTRY_PASSWORD="$GITHUB_TOKEN" \
    scripts/release-helm-chart.sh --version 0.1.0 --push
EOF
}

VERSION=""
PUSH=0

while [[ $# -gt 0 ]]; do
  case "$1" in
    --version)
      VERSION="${2:-}"
      shift 2
      ;;
    --push)
      PUSH=1
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      if [[ -z "$VERSION" ]]; then
        VERSION="$1"
        shift
      else
        echo "Unexpected argument: $1" >&2
        usage
        exit 1
      fi
      ;;
  esac
done

if [[ -z "$VERSION" ]]; then
  echo "Missing required chart version." >&2
  usage
  exit 1
fi

if ! [[ "$VERSION" =~ ^[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.-]+)?$ ]]; then
  echo "Version must match semver: X.Y.Z or X.Y.Z-prerelease" >&2
  exit 1
fi

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CHART_PATH="$REPO_ROOT/infra/deploy/helm/clawdstrike"
OUTPUT_DIR="$REPO_ROOT/dist/helm"
OCI_REPO="${HELM_OCI_REPO:-oci://ghcr.io/backbay-labs/clawdstrike/helm}"
PACKAGE_PATH="$OUTPUT_DIR/clawdstrike-$VERSION.tgz"
APP_VERSION="${CHART_APP_VERSION:-}"

helm lint "$CHART_PATH"
helm template release-check "$CHART_PATH" -f "$CHART_PATH/ci/test-values.yaml" > /dev/null

mkdir -p "$OUTPUT_DIR"
rm -f "$OUTPUT_DIR"/clawdstrike-*.tgz

PACKAGE_CMD=(helm package "$CHART_PATH" --version "$VERSION" --destination "$OUTPUT_DIR")
if [[ -n "$APP_VERSION" ]]; then
  PACKAGE_CMD+=(--app-version "$APP_VERSION")
fi
"${PACKAGE_CMD[@]}"

if [[ ! -f "$PACKAGE_PATH" ]]; then
  echo "Expected chart package not found: $PACKAGE_PATH" >&2
  exit 1
fi

echo "Chart packaged: $PACKAGE_PATH"

if [[ "$PUSH" -eq 1 ]]; then
  if [[ -n "${HELM_REGISTRY_USERNAME:-}" || -n "${HELM_REGISTRY_PASSWORD:-}" ]]; then
    if [[ -z "${HELM_REGISTRY_USERNAME:-}" || -z "${HELM_REGISTRY_PASSWORD:-}" ]]; then
      echo "Set both HELM_REGISTRY_USERNAME and HELM_REGISTRY_PASSWORD, or neither." >&2
      exit 1
    fi
    registry_host="${OCI_REPO#oci://}"
    registry_host="${registry_host%%/*}"
    echo "$HELM_REGISTRY_PASSWORD" | helm registry login "$registry_host" \
      --username "$HELM_REGISTRY_USERNAME" \
      --password-stdin
  fi

  helm push "$PACKAGE_PATH" "$OCI_REPO"
  echo "Chart pushed to $OCI_REPO"
fi
