#!/usr/bin/env bash

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=scripts/codex-swarm/common.sh
source "$SCRIPT_DIR/common.sh"

if (($# < 1)); then
  printf 'Usage: %s <lane> [--note "text"] [--dangerous]\n' "$0" >&2
  exit 1
fi

lane="$1"
shift
note=""
dangerous="false"

while (($# > 0)); do
  case "$1" in
    --note)
      note="$2"
      shift 2
      ;;
    --dangerous)
      dangerous="true"
      shift
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
swarm_ensure_dirs "$repo_root"

worktree_path="$(swarm_lane_worktree_path "$lane" "$repo_root")"
lane_dir="$(swarm_lane_orch_dir "$lane" "$repo_root")"
profile_name="$(swarm_lane_field "$lane" profile "$repo_root")"
prompt_file="$lane_dir/prompt.md"
runner_file="$lane_dir/run.sh"
log_file="$lane_dir/run.jsonl"
stderr_file="$lane_dir/run.stderr"
final_file="$lane_dir/final.md"
pid_file="$lane_dir/run.pid"
cmd_file="$lane_dir/run.cmd"
declare -a codex_args=()

if [[ ! -d "$worktree_path" ]]; then
  printf 'worktree missing for %s: %s\n' "$lane" "$worktree_path" >&2
  printf 'run scripts/codex-swarm/setup-worktrees.sh %s first\n' "$lane" >&2
  exit 1
fi

if swarm_pid_is_running "$pid_file"; then
  printf 'lane %s already has a running process (pid %s)\n' "$lane" "$(cat "$pid_file")" >&2
  exit 1
fi

swarm_write_lane_prompt "$lane" "$prompt_file" "$note" "$repo_root"
while IFS= read -r arg; do
  codex_args+=("$arg")
done < <(swarm_codex_profile_args "$profile_name")

cat > "$runner_file" <<EOF
#!/usr/bin/env bash
set -euo pipefail
cd "$worktree_path"
exec codex exec \\
EOF

for arg in "${codex_args[@]}"; do
  printf '  %q \\\n' "$arg" >> "$runner_file"
done

cat >> "$runner_file" <<EOF
  --json \\
  -o "$final_file" \\
EOF

if [[ "$dangerous" == "true" ]]; then
  cat >> "$runner_file" <<'EOF'
  --dangerously-bypass-approvals-and-sandbox \
EOF
fi

cat >> "$runner_file" <<EOF
  - < "$prompt_file"
EOF

chmod +x "$runner_file"
cp "$runner_file" "$cmd_file"

nohup "$runner_file" > "$log_file" 2> "$stderr_file" &
pid="$!"
printf '%s\n' "$pid" > "$pid_file"

printf 'launched %s (pid %s)\n' "$lane" "$pid"
printf '  worktree: %s\n' "$worktree_path"
printf '  final:    %s\n' "$final_file"
printf '  log:      %s\n' "$log_file"
