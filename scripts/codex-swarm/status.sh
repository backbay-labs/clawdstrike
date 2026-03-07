#!/usr/bin/env bash

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=scripts/codex-swarm/common.sh
source "$SCRIPT_DIR/common.sh"

repo_root="$(swarm_repo_root)"
declare -a lanes=()

if (($# > 0)); then
  lanes=("$@")
else
  while IFS= read -r lane; do
    lanes+=("$lane")
  done < <(swarm_all_lanes "$repo_root")
fi

printf '%-5s %-10s %-28s %-7s %-6s %-6s %s\n' "lane" "state" "branch" "changes" "final" "review" "worktree"

for lane in "${lanes[@]}"; do
  swarm_require_lane "$lane" "$repo_root"
  branch_name="$(swarm_lane_field "$lane" branch "$repo_root")"
  worktree_path="$(swarm_lane_worktree_path "$lane" "$repo_root")"
  lane_dir="$(swarm_lane_orch_dir "$lane" "$repo_root")"
  run_pid="$lane_dir/run.pid"
  resume_pid="$lane_dir/resume.pid"
  run_exit="$lane_dir/run.exit"
  resume_exit="$lane_dir/resume.exit"
  final_file="$lane_dir/final.md"
  review_file="$lane_dir/review.md"

  if swarm_pid_is_running "$run_pid"; then
    state="running"
  elif swarm_pid_is_running "$resume_pid"; then
    state="resumed"
  elif [[ -f "$final_file" ]]; then
    state="done"
  elif [[ -f "$resume_exit" ]] || [[ -f "$run_exit" ]]; then
    state="failed"
  elif [[ -d "$worktree_path" ]]; then
    state="ready"
  else
    state="missing"
  fi

  if [[ -d "$worktree_path" ]]; then
    changes="$(git -C "$worktree_path" status --short | wc -l | tr -d '[:space:]')"
  else
    changes="-"
  fi

  if [[ -f "$final_file" ]]; then
    final_flag="yes"
  else
    final_flag="no"
  fi

  if [[ -f "$review_file" ]]; then
    review_flag="yes"
  else
    review_flag="no"
  fi

  printf '%-5s %-10s %-28s %-7s %-6s %-6s %s\n' \
    "$lane" "$state" "$branch_name" "$changes" "$final_flag" "$review_flag" "$worktree_path"
done
