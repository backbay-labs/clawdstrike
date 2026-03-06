#!/usr/bin/env bash

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

if (($# < 1)); then
  printf 'Usage: %s <wave> [--note "text"] [--dangerous]\n' "$0" >&2
  exit 1
fi

wave="$1"
shift
note=""
dangerous=()

while (($# > 0)); do
  case "$1" in
    --note)
      note="$2"
      shift 2
      ;;
    --dangerous)
      dangerous=(--dangerous)
      shift
      ;;
    *)
      printf 'Unknown argument: %s\n' "$1" >&2
      exit 1
      ;;
  esac
done

# shellcheck source=scripts/codex-swarm/common.sh
source "$SCRIPT_DIR/common.sh"
repo_root="$(swarm_repo_root)"
declare -a lanes=()
while IFS= read -r lane; do
  lanes+=("$lane")
done < <(swarm_wave_lanes "$wave" "$repo_root")
"$SCRIPT_DIR/setup-worktrees.sh" "${lanes[@]}"

for lane in "${lanes[@]}"; do
  if ((${#dangerous[@]} > 0)); then
    "$SCRIPT_DIR/launch-lane.sh" "$lane" "${dangerous[@]}" --note "${note:-Launched as part of ${wave}. Follow the lane brief and leave a clean handoff.}"
  else
    "$SCRIPT_DIR/launch-lane.sh" "$lane" --note "${note:-Launched as part of ${wave}. Follow the lane brief and leave a clean handoff.}"
  fi
done
