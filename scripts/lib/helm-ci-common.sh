#!/usr/bin/env bash

# Shared helpers for Helm CI smoke/resilience scripts.

hc_log() {
  local prefix="$1"
  shift
  printf '[%s] %s\n' "$prefix" "$*"
}

hc_require_cmd() {
  local cmd="$1"
  local prefix="${2:-helm-ci}"
  if ! command -v "$cmd" >/dev/null 2>&1; then
    printf '[%s] ERROR: missing required command: %s\n' "$prefix" "$cmd" >&2
    exit 2
  fi
}

hc_init_context_args() {
  local kube_context="${1:-}"
  KCTL_ARGS=()
  HELM_ARGS=()
  if [[ -n "$kube_context" ]]; then
    KCTL_ARGS+=(--context "$kube_context")
    HELM_ARGS+=(--kube-context "$kube_context")
  fi
}

hc_kctl() {
  if ((${#KCTL_ARGS[@]})); then
    kubectl "${KCTL_ARGS[@]}" "$@"
  else
    kubectl "$@"
  fi
}

hc_helm() {
  if ((${#HELM_ARGS[@]})); then
    helm "${HELM_ARGS[@]}" "$@"
  else
    helm "$@"
  fi
}

hc_record_failure() {
  FAILURES+=("$1")
  RESULT=1
}

hc_collect_diagnostics() {
  local include_history="${1:-0}"
  local include_workloads="${2:-0}"

  mkdir -p "$ARTIFACT_DIR"/describe "$ARTIFACT_DIR"/logs
  hc_kctl config current-context >"$ARTIFACT_DIR/context.txt" 2>/dev/null || true
  hc_helm list -n "$NAMESPACE" >"$ARTIFACT_DIR/helm-list.txt" 2>/dev/null || true
  hc_helm status "$RELEASE" -n "$NAMESPACE" >"$ARTIFACT_DIR/helm-status.txt" 2>/dev/null || true
  if [[ "$include_history" == "1" ]]; then
    hc_helm history "$RELEASE" -n "$NAMESPACE" >"$ARTIFACT_DIR/helm-history.txt" 2>/dev/null || true
  fi
  hc_kctl -n "$NAMESPACE" get pods -o wide >"$ARTIFACT_DIR/pods.txt" 2>/dev/null || true
  hc_kctl -n "$NAMESPACE" get svc >"$ARTIFACT_DIR/services.txt" 2>/dev/null || true
  if [[ "$include_workloads" == "1" ]]; then
    hc_kctl -n "$NAMESPACE" get deploy,sts,svc >"$ARTIFACT_DIR/workloads.txt" 2>/dev/null || true
  fi
  hc_kctl -n "$NAMESPACE" get events --sort-by=.lastTimestamp >"$ARTIFACT_DIR/events.txt" 2>/dev/null || true

  while IFS= read -r pod; do
    [[ -n "$pod" ]] || continue
    hc_kctl -n "$NAMESPACE" describe pod "$pod" >"$ARTIFACT_DIR/describe/${pod}.txt" 2>/dev/null || true
    while IFS= read -r container; do
      [[ -n "$container" ]] || continue
      hc_kctl -n "$NAMESPACE" logs "$pod" -c "$container" >"$ARTIFACT_DIR/logs/${pod}-${container}.log" 2>/dev/null || true
      hc_kctl -n "$NAMESPACE" logs "$pod" -c "$container" --previous >"$ARTIFACT_DIR/logs/${pod}-${container}.previous.log" 2>/dev/null || true
    done < <(hc_kctl -n "$NAMESPACE" get pod "$pod" -o jsonpath='{.spec.containers[*].name}' 2>/dev/null | tr ' ' '\n')
  done < <(hc_kctl -n "$NAMESPACE" get pods -o jsonpath='{.items[*].metadata.name}' 2>/dev/null | tr ' ' '\n')
}

hc_write_summary() {
  local summary_title="$1"
  local extra_summary_lines="${2:-}"

  local failures_json
  if ((${#FAILURES[@]})); then
    failures_json="$(printf '%s\n' "${FAILURES[@]}" | jq -R . | jq -s .)"
  else
    failures_json='[]'
  fi

  local context_value
  context_value="$(hc_kctl config current-context 2>/dev/null || printf 'unknown')"

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
    printf '# %s\n\n' "$summary_title"
    printf -- '- chart_ref: `%s`\n' "$CHART_REF"
    printf -- '- chart_version: `%s`\n' "$CHART_VERSION"
    if [[ -n "$extra_summary_lines" ]]; then
      printf '%s\n' "$extra_summary_lines"
    fi
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

hc_health_check_service() {
  local svc="$1"
  local target_port="$2"
  local path="$3"

  if ! hc_kctl -n "$NAMESPACE" get svc "$svc" >/dev/null 2>&1; then
    hc_record_failure "missing service: $svc"
    return 1
  fi

  local pf_log="$ARTIFACT_DIR/port-forward-${svc}.log"
  hc_kctl -n "$NAMESPACE" port-forward "svc/${svc}" ":${target_port}" >"$pf_log" 2>&1 &
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
    hc_record_failure "failed to start port-forward for service: ${svc}"
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
    hc_record_failure "health check failed: ${svc}${path}"
    return 1
  fi

  return 0
}

hc_write_namespace_override_values() {
  local output_file="$1"
  cat >"$output_file" <<EOF
global:
  namespace: "$NAMESPACE"
namespace:
  create: false
  name: "$NAMESPACE"
EOF
}

hc_ensure_namespace() {
  NAMESPACE_CREATED=0
  if ! hc_kctl get namespace "$NAMESPACE" >/dev/null 2>&1; then
    if [[ "$(hc_kctl auth can-i create namespaces 2>/dev/null || printf 'no')" != "yes" ]]; then
      hc_record_failure "missing permission: create namespaces"
    else
      hc_kctl create namespace "$NAMESPACE" >/dev/null
      NAMESPACE_CREATED=1
    fi
  fi
}

hc_bootstrap_ghcr_pull_secret() {
  if [[ -n "${GHCR_PULL_USERNAME:-}" || -n "${GHCR_PULL_TOKEN:-}" ]]; then
    if [[ -z "${GHCR_PULL_USERNAME:-}" || -z "${GHCR_PULL_TOKEN:-}" ]]; then
      hc_record_failure "set both GHCR_PULL_USERNAME and GHCR_PULL_TOKEN for pull-secret bootstrap"
    else
      hc_kctl -n "$NAMESPACE" create secret docker-registry ghcr-pull \
        --docker-server=ghcr.io \
        --docker-username="$GHCR_PULL_USERNAME" \
        --docker-password="$GHCR_PULL_TOKEN" \
        --dry-run=client -o yaml | hc_kctl -n "$NAMESPACE" apply -f - >/dev/null
    fi
  fi
}

hc_cleanup_release() {
  if [[ "$SKIP_CLEANUP" -eq 1 ]]; then
    return
  fi
  hc_helm uninstall "$RELEASE" -n "$NAMESPACE" >/dev/null 2>&1 || true
  if [[ "${NAMESPACE_CREATED:-0}" -eq 1 ]]; then
    hc_kctl delete namespace "$NAMESPACE" --wait=false >/dev/null 2>&1 || true
  fi
}
