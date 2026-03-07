#!/usr/bin/env bash

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=scripts/codex-swarm/common.sh
source "$SCRIPT_DIR/common.sh"

if (($# == 0)); then
  printf 'Usage: %s <lane> [lane...]\n' "$0" >&2
  exit 1
fi

repo_root="$(swarm_repo_root)"

for lane in "$@"; do
  swarm_run_lane_bootstrap "$lane" "$repo_root"
done
