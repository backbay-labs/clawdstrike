#!/usr/bin/env bash

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=scripts/codex-swarm/common.sh
source "$SCRIPT_DIR/common.sh"

repo_root="$(swarm_repo_root)"
base_ref="HEAD"
declare -a lanes=()

while (($# > 0)); do
  case "$1" in
    --base)
      base_ref="$2"
      shift 2
      ;;
    *)
      lanes+=("$1")
      shift
      ;;
  esac
done

if ((${#lanes[@]} == 0)); then
  while IFS= read -r lane; do
    lanes+=("$lane")
  done < <(swarm_all_lanes "$repo_root")
fi

swarm_ensure_dirs "$repo_root"

for lane in "${lanes[@]}"; do
  swarm_require_lane "$lane" "$repo_root"
  worktree_path="$(swarm_lane_worktree_path "$lane" "$repo_root")"
  branch_name="$(swarm_lane_field "$lane" branch "$repo_root")"
  mkdir -p "$(swarm_lane_orch_dir "$lane" "$repo_root")"

  if [[ -e "$worktree_path" ]]; then
    printf 'skip %s: %s already exists\n' "$lane" "$worktree_path"
    continue
  fi

  if git -C "$repo_root" show-ref --verify --quiet "refs/heads/$branch_name"; then
    git -C "$repo_root" worktree add "$worktree_path" "$branch_name"
  else
    git -C "$repo_root" worktree add -b "$branch_name" "$worktree_path" "$base_ref"
  fi

  printf 'created %s: %s (%s)\n' "$lane" "$worktree_path" "$branch_name"
done

for lane in "${lanes[@]}"; do
  swarm_run_lane_bootstrap "$lane" "$repo_root"
done
