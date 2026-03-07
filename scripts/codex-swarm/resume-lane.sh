#!/usr/bin/env bash

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=scripts/codex-swarm/common.sh
source "$SCRIPT_DIR/common.sh"

if (($# < 1)); then
  printf 'Usage: %s <lane> [--message "text"]\n' "$0" >&2
  exit 1
fi

lane="$1"
shift
message="Continue from the current branch state. Keep file ownership boundaries. Finish outstanding verification and handoff items."

while (($# > 0)); do
  case "$1" in
    --message)
      if (($# < 2)); then
        printf 'Missing value for --message\n' >&2
        exit 1
      fi
      message="$2"
      shift 2
      ;;
    *)
      printf 'Unknown argument: %s\n' "$1" >&2
      exit 1
      ;;
  esac
done

swarm_assert_codex
repo_root="$(swarm_repo_root)"
swarm_require_lane "$lane" "$repo_root"

worktree_path="$(swarm_lane_worktree_path "$lane" "$repo_root")"
lane_dir="$(swarm_lane_orch_dir "$lane" "$repo_root")"
profile_name="$(swarm_lane_field "$lane" profile "$repo_root")"
resume_prompt="$lane_dir/resume-prompt.md"
runner_file="$lane_dir/resume-runner.sh"
log_file="$lane_dir/resume.jsonl"
stderr_file="$lane_dir/resume.stderr"
final_file="$lane_dir/resume-final.md"
pid_file="$lane_dir/resume.pid"

if [[ ! -d "$worktree_path" ]]; then
  printf 'worktree missing for %s: %s\n' "$lane" "$worktree_path" >&2
  exit 1
fi

if swarm_pid_is_running "$pid_file"; then
  printf 'lane %s already has a running resume process (pid %s)\n' "$lane" "$(cat "$pid_file")" >&2
  exit 1
fi

printf '%s\n' "$message" > "$resume_prompt"

cat > "$runner_file" <<EOF
#!/usr/bin/env bash
set -euo pipefail
cd "$worktree_path"
exec codex exec resume --last --profile "$profile_name" --json -o "$final_file" - < "$resume_prompt"
EOF
chmod +x "$runner_file"

nohup "$runner_file" > "$log_file" 2> "$stderr_file" &
pid="$!"
printf '%s\n' "$pid" > "$pid_file"

printf 'resumed %s (pid %s)\n' "$lane" "$pid"
printf '  final: %s\n' "$final_file"
printf '  log:   %s\n' "$log_file"
