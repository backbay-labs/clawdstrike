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
exit_file="$lane_dir/resume.exit"
declare -a codex_args=()
extra_overrides_sandbox="false"

if [[ ! -d "$worktree_path" ]]; then
  printf 'worktree missing for %s: %s\n' "$lane" "$worktree_path" >&2
  exit 1
fi

if swarm_pid_is_running "$pid_file"; then
  printf 'lane %s already has a running resume process (pid %s)\n' "$lane" "$(cat "$pid_file")" >&2
  exit 1
fi

rm -f "$log_file" "$stderr_file" "$final_file" "$pid_file" "$exit_file"
printf '%s\n' "$message" > "$resume_prompt"
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

cat > "$runner_file" <<EOF
#!/usr/bin/env bash
set -uo pipefail
cd "$worktree_path"
prompt="\$(cat "$resume_prompt")"
unset CODEX_THREAD_ID
unset CODEX_MANAGED_BY_BUN
if env codex \\
EOF

for arg in "${codex_args[@]}"; do
  printf '  %q \\\n' "$arg" >> "$runner_file"
done

cat >> "$runner_file" <<EOF
  exec resume --last \\
  --json \\
  -o "$final_file" \\
  "\$prompt"
then
  status=0
else
  status=\$?
fi
printf '%s\n' "\$status" > "$exit_file"
rm -f "$pid_file"
exit "\$status"
EOF
chmod +x "$runner_file"

nohup bash "$runner_file" > "$log_file" 2> "$stderr_file" &
pid="$!"
printf '%s\n' "$pid" > "$pid_file"

if ! swarm_wait_for_background_start "$pid_file" "$final_file" "$log_file" "$stderr_file" "$exit_file"; then
  rm -f "$pid_file"
  printf 'resume for %s failed to start: no pid, log, stderr, final, or exit marker appeared\n' "$lane" >&2
  exit 1
fi

sleep 1
if [[ -f "$exit_file" ]] && [[ ! -f "$final_file" ]]; then
  status="$(tr -d '[:space:]' < "$exit_file")"
  printf 'resume for %s exited before producing a final handoff (status %s)\n' "$lane" "${status:-unknown}" >&2
  if [[ -s "$stderr_file" ]]; then
    printf '%s\n' '--- stderr ---' >&2
    sed -n '1,40p' "$stderr_file" >&2
  fi
  exit 1
fi

printf 'resumed %s (pid %s)\n' "$lane" "$pid"
printf '  final: %s\n' "$final_file"
printf '  log:   %s\n' "$log_file"
