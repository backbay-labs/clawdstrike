#!/usr/bin/env bash
set -euo pipefail

# Runs a repeatable “sanity gate” loop for a fixed horizon.
# Output logs go to target/ (gitignored).

DURATION_MINUTES="${DURATION_MINUTES:-180}"
INTERVAL_MINUTES="${INTERVAL_MINUTES:-30}"
OUT_DIR="${OUT_DIR:-target/rust-killa/cadence}"

mkdir -p "${OUT_DIR}"

start_ts="$(date +%s)"
end_ts="$((start_ts + DURATION_MINUTES * 60))"

run_gate() {
  local ts log
  ts="$(date -u +"%Y%m%dT%H%M%SZ")"
  log="${OUT_DIR}/${ts}.log"

  {
    echo "=== rust-killa cadence: ${ts} ==="
    echo "cwd: $(pwd)"
    echo "git: $(git rev-parse --short HEAD 2>/dev/null || echo '(no git)')"
    echo
    echo "--- cargo fmt --check ---"
  } | tee "${log}"

  cargo fmt --check 2>&1 | tee -a "${log}"

  echo -e "\n--- cargo clippy (deny warnings) ---" | tee -a "${log}"
  cargo clippy --workspace --all-targets -- -D warnings 2>&1 | tee -a "${log}"

  echo -e "\n--- cargo test (workspace) ---" | tee -a "${log}"
  cargo test --workspace --all-targets 2>&1 | tee -a "${log}"

  if command -v mdbook >/dev/null 2>&1; then
    echo -e "\n--- mdbook build docs ---" | tee -a "${log}"
    mdbook build docs 2>&1 | tee -a "${log}"
  else
    echo -e "\n--- mdbook build docs (skipped: mdbook not found) ---" | tee -a "${log}"
  fi

  cp "${log}" "${OUT_DIR}/latest.log"
}

while true; do
  now_ts="$(date +%s)"
  if (( now_ts >= end_ts )); then
    echo "Cadence complete: duration=${DURATION_MINUTES}m interval=${INTERVAL_MINUTES}m" | tee -a "${OUT_DIR}/latest.log"
    exit 0
  fi

  run_gate

  sleep_seconds="$((INTERVAL_MINUTES * 60))"
  sleep "${sleep_seconds}"
done
