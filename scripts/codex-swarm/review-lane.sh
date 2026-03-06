#!/usr/bin/env bash

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=scripts/codex-swarm/common.sh
source "$SCRIPT_DIR/common.sh"

if (($# < 1)); then
  printf 'Usage: %s <lane> [base-branch]\n' "$0" >&2
  exit 1
fi

lane="$1"
base_branch="${2:-main}"

swarm_assert_codex
repo_root="$(swarm_repo_root)"
swarm_require_lane "$lane" "$repo_root"

worktree_path="$(swarm_lane_worktree_path "$lane" "$repo_root")"
lane_dir="$(swarm_lane_orch_dir "$lane" "$repo_root")"
profile_name="$(swarm_lane_field "$lane" profile "$repo_root")"
review_file="$lane_dir/review.md"
log_file="$lane_dir/review.jsonl"
stderr_file="$lane_dir/review.stderr"
declare -a codex_args=()
extra_overrides_sandbox="false"

if [[ ! -d "$worktree_path" ]]; then
  printf 'worktree missing for %s: %s\n' "$lane" "$worktree_path" >&2
  exit 1
fi

extra_overrides_sandbox="$(swarm_codex_extra_overrides_sandbox)"
while IFS= read -r arg; do
  if [[ "$extra_overrides_sandbox" == "true" && "$arg" == "--sandbox" ]]; then
    read -r _ || true
    continue
  fi
  codex_args+=("$arg")
done < <(swarm_codex_profile_args "$profile_name")
while IFS= read -r arg; do
  codex_args+=("$arg")
done < <(swarm_codex_extra_args)

(
  cd "$worktree_path"
  exec codex "${codex_args[@]}" exec review --base "$base_branch" --json -o "$review_file"
) > "$log_file" 2> "$stderr_file"

printf 'review complete for %s\n' "$lane"
printf '  review: %s\n' "$review_file"
printf '  log:    %s\n' "$log_file"
