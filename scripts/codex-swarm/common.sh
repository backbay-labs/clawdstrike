#!/usr/bin/env bash

set -euo pipefail

swarm_repo_root() {
  git -C "${1:-$(pwd)}" rev-parse --show-toplevel
}

swarm_repo_parent_dir() {
  local repo_root
  repo_root="$(swarm_repo_root "${1:-$(pwd)}")"
  (
    cd "$repo_root/.."
    pwd
  )
}

swarm_repo_name() {
  local repo_root
  local repo_parent
  local parent_name
  repo_root="$(swarm_repo_root "${1:-$(pwd)}")"
  repo_parent="$(swarm_repo_parent_dir "$repo_root")"
  parent_name="$(basename "$repo_parent")"

  case "$parent_name" in
    *-worktrees)
      printf '%s\n' "${parent_name%-worktrees}"
      ;;
    *-orchestration)
      printf '%s\n' "${parent_name%-orchestration}"
      ;;
    *)
      basename "$repo_root"
      ;;
  esac
}

swarm_worktrees_dir() {
  local repo_root
  local repo_parent
  local parent_name
  local repo_name
  repo_root="$(swarm_repo_root "${1:-$(pwd)}")"
  repo_parent="$(swarm_repo_parent_dir "$repo_root")"
  parent_name="$(basename "$repo_parent")"
  repo_name="$(swarm_repo_name "$repo_root")"
  if [[ -n "${CLAWDSTRIKE_SWARM_WORKTREES_DIR:-}" ]]; then
    printf '%s\n' "$CLAWDSTRIKE_SWARM_WORKTREES_DIR"
    return
  fi
  case "$parent_name" in
    *-worktrees)
      printf '%s\n' "$repo_parent"
      ;;
    *-orchestration)
      printf '%s/%s-worktrees\n' "$(dirname "$repo_parent")" "$repo_name"
      ;;
    *)
      printf '%s/%s-worktrees\n' "$repo_parent" "$repo_name"
      ;;
  esac
}

swarm_orchestration_dir() {
  local repo_root
  local repo_parent
  local parent_name
  local repo_name
  repo_root="$(swarm_repo_root "${1:-$(pwd)}")"
  repo_parent="$(swarm_repo_parent_dir "$repo_root")"
  parent_name="$(basename "$repo_parent")"
  repo_name="$(swarm_repo_name "$repo_root")"
  if [[ -n "${CLAWDSTRIKE_SWARM_ORCH_DIR:-}" ]]; then
    printf '%s\n' "$CLAWDSTRIKE_SWARM_ORCH_DIR"
    return
  fi
  case "$parent_name" in
    *-orchestration)
      printf '%s\n' "$repo_parent"
      ;;
    *-worktrees)
      printf '%s/%s-orchestration\n' "$(dirname "$repo_parent")" "$repo_name"
      ;;
    *)
      printf '%s/%s-orchestration\n' "$repo_parent" "$repo_name"
      ;;
  esac
}

swarm_lane_table() {
  local repo_root
  repo_root="$(swarm_repo_root "${1:-$(pwd)}")"
  printf '%s/.codex/swarm/lanes.tsv\n' "$repo_root"
}

swarm_wave_table() {
  local repo_root
  repo_root="$(swarm_repo_root "${1:-$(pwd)}")"
  printf '%s/.codex/swarm/waves.tsv\n' "$repo_root"
}

swarm_lane_field() {
  local lane="$1"
  local field="$2"
  local repo_root="${3:-$(swarm_repo_root)}"
  awk -F '\t' -v lane="$lane" -v field="$field" '
    NR == 1 {
      for (i = 1; i <= NF; i++) {
        idx[$i] = i
      }
      next
    }
    $1 == lane {
      if (field in idx) {
        print $(idx[field])
      }
      exit
    }
  ' "$(swarm_lane_table "$repo_root")"
}

swarm_lane_docs() {
  local lane="$1"
  local repo_root="${2:-$(swarm_repo_root)}"
  local docs
  docs="$(swarm_lane_field "$lane" docs "$repo_root")"
  if [[ -z "$docs" ]]; then
    return 0
  fi
  printf '%s\n' "$docs" | tr ',' '\n' | sed '/^$/d'
}

swarm_require_lane() {
  local lane="$1"
  local repo_root="${2:-$(swarm_repo_root)}"
  if [[ -z "$(swarm_lane_field "$lane" lane "$repo_root")" ]]; then
    printf 'Unknown lane: %s\n' "$lane" >&2
    exit 1
  fi
}

swarm_all_lanes() {
  local repo_root="${1:-$(swarm_repo_root)}"
  awk -F '\t' 'NR > 1 { print $1 }' "$(swarm_lane_table "$repo_root")"
}

swarm_wave_lanes() {
  local wave="$1"
  local repo_root="${2:-$(swarm_repo_root)}"
  local lanes
  lanes="$(
    awk -F '\t' -v wave="$wave" '
      NR == 1 { next }
      $1 == wave {
        print $2
        exit
      }
    ' "$(swarm_wave_table "$repo_root")"
  )"
  if [[ -z "$lanes" ]]; then
    printf 'Unknown wave: %s\n' "$wave" >&2
    exit 1
  fi
  printf '%s\n' "$lanes" | tr ',' '\n'
}

swarm_lane_worktree_path() {
  local lane="$1"
  local repo_root="${2:-$(swarm_repo_root)}"
  printf '%s/%s\n' \
    "$(swarm_worktrees_dir "$repo_root")" \
    "$(swarm_lane_field "$lane" worktree "$repo_root")"
}

swarm_lane_orch_dir() {
  local lane="$1"
  local repo_root="${2:-$(swarm_repo_root)}"
  printf '%s/%s\n' \
    "$(swarm_orchestration_dir "$repo_root")" \
    "$lane"
}

swarm_lane_bootstrap_cmd() {
  local lane="$1"
  local repo_root="${2:-$(swarm_repo_root)}"
  swarm_lane_field "$lane" bootstrap "$repo_root"
}

swarm_ensure_dirs() {
  local repo_root="${1:-$(swarm_repo_root)}"
  local lane
  mkdir -p "$(swarm_worktrees_dir "$repo_root")"
  mkdir -p "$(swarm_orchestration_dir "$repo_root")"
  while IFS= read -r lane; do
    mkdir -p "$(swarm_lane_orch_dir "$lane" "$repo_root")"
  done < <(swarm_all_lanes "$repo_root")
}

swarm_assert_codex() {
  if ! command -v codex >/dev/null 2>&1; then
    printf 'codex is not installed or not on PATH\n' >&2
    exit 1
  fi
}

swarm_codex_profile_args() {
  local profile="$1"
  case "$profile" in
    swarm-docs)
      printf '%s\n' \
        --enable \
        multi_agent \
        --sandbox \
        read-only \
        -c \
        'model_reasoning_effort="high"'
      ;;
    swarm-orchestrator)
      printf '%s\n' \
        --enable \
        multi_agent \
        --sandbox \
        workspace-write \
        -c \
        'model_reasoning_effort="high"'
      ;;
    swarm-worker)
      printf '%s\n' \
        --enable \
        multi_agent \
        --sandbox \
        workspace-write \
        -c \
        'model_reasoning_effort="medium"'
      ;;
    swarm-review)
      printf '%s\n' \
        --enable \
        multi_agent \
        --sandbox \
        read-only \
        -c \
        'model_reasoning_effort="high"'
      ;;
    *)
      printf 'Unknown Codex profile: %s\n' "$profile" >&2
      exit 1
      ;;
  esac
}

swarm_codex_extra_args() {
  python3 - <<'PY'
import os
import shlex

value = os.environ.get("CLAWDSTRIKE_SWARM_CODEX_ARGS", "").strip()
for arg in shlex.split(value):
    print(arg)
PY
}

swarm_codex_extra_overrides_sandbox() {
  python3 - <<'PY'
import os
import shlex

args = shlex.split(os.environ.get("CLAWDSTRIKE_SWARM_CODEX_ARGS", "").strip())
i = 0
while i < len(args):
    arg = args[i]
    if arg in ("-s", "--sandbox"):
        print("true")
        raise SystemExit(0)
    if arg.startswith("--sandbox="):
        print("true")
        raise SystemExit(0)
    i += 2 if arg in ("-a", "--ask-for-approval", "-s", "--sandbox") else 1
print("false")
PY
}

swarm_run_lane_bootstrap() {
  local lane="$1"
  local repo_root="${2:-$(swarm_repo_root)}"
  local worktree_path
  local bootstrap_cmd

  swarm_require_lane "$lane" "$repo_root"
  worktree_path="$(swarm_lane_worktree_path "$lane" "$repo_root")"
  bootstrap_cmd="$(swarm_lane_bootstrap_cmd "$lane" "$repo_root")"

  if [[ -z "$bootstrap_cmd" ]]; then
    return 0
  fi

  if [[ ! -d "$worktree_path" ]]; then
    printf 'cannot bootstrap %s: worktree missing at %s\n' "$lane" "$worktree_path" >&2
    exit 1
  fi

  printf 'bootstrap %s: %s\n' "$lane" "$bootstrap_cmd"
  (
    cd "$worktree_path"
    eval "$bootstrap_cmd"
  )
}

swarm_pid_is_running() {
  local pid_file="$1"
  if [[ ! -f "$pid_file" ]]; then
    return 1
  fi
  local pid
  pid="$(tr -d '[:space:]' < "$pid_file")"
  if [[ -z "$pid" ]]; then
    return 1
  fi
  kill -0 "$pid" >/dev/null 2>&1
}

swarm_wait_for_background_start() {
  local pid_file="$1"
  local final_file="$2"
  local log_file="$3"
  local stderr_file="$4"
  local exit_file="$5"
  local attempts="${6:-10}"
  local attempt

  for ((attempt = 0; attempt < attempts; attempt++)); do
    if swarm_pid_is_running "$pid_file" || [[ -f "$final_file" ]] || [[ -s "$log_file" ]] || [[ -s "$stderr_file" ]] || [[ -f "$exit_file" ]]; then
      return 0
    fi
    sleep 1
  done

  return 1
}

swarm_prompt_docs_block() {
  local lane="$1"
  local repo_root="${2:-$(swarm_repo_root)}"
  {
    printf '%s\n' 'docs/plans/multi-agent/codex-swarm-playbook.md'
    printf '%s\n' '.codex/swarm/lanes.tsv'
    printf '%s\n' '.codex/swarm/waves.tsv'
    swarm_lane_docs "$lane" "$repo_root"
  } | awk 'NF && !seen[$0]++ { print "- " $0 }'
}

swarm_write_lane_prompt() {
  local lane="$1"
  local prompt_file="$2"
  local note="${3:-}"
  local repo_root="${4:-$(swarm_repo_root)}"
  local brief_id
  local description
  local docs_block
  local profile
  local role

  swarm_require_lane "$lane" "$repo_root"
  brief_id="$(swarm_lane_field "$lane" brief_id "$repo_root")"
  description="$(swarm_lane_field "$lane" description "$repo_root")"
  docs_block="$(swarm_prompt_docs_block "$lane" "$repo_root")"
  profile="$(swarm_lane_field "$lane" profile "$repo_root")"
  role="$(swarm_lane_field "$lane" role "$repo_root")"

  if [[ "$profile" == "swarm-orchestrator" || "$role" == "workstream_orchestrator" ]]; then
    cat > "$prompt_file" <<EOF_PROMPT
Use \$clawdstrike-swarm-supervisor.

Current lane: ${brief_id}.
Lane purpose: ${description}

Read these docs first:
${docs_block}

Operate as the orchestrator lane only.

Requirements:
- own shared wiring, review, merge sequencing, wave advancement, and swarm metadata
- do not drift into implementing a worker lane unless the operator explicitly redirects you
- keep .codex/swarm/lanes.tsv and .codex/swarm/waves.tsv aligned with reality
- inspect repo state and orchestration artifacts before deciding the next action

Operator note:
${note:-No extra operator note. Start by checking repo state and active orchestration artifacts.}
EOF_PROMPT
    return
  fi

  cat > "$prompt_file" <<EOF_PROMPT
Use \$clawdstrike-lane-executor.

Current lane: ${brief_id}.
Lane purpose: ${description}

Read these docs first:
${docs_block}

Execution requirements:
- follow the lane docs above as the source of truth
- stay within lane-owned files
- do not edit orchestrator-owned shared registration files
- inspect the existing code before editing
- run the lane verification commands before handoff
- leave a final handoff with changed files, commands run, and unresolved items

Operator note:
${note:-No extra operator note. Start from the current branch state and execute the lane cleanly.}
EOF_PROMPT
}
