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
    .worktrees)
      basename "$(dirname "$repo_parent")"
      ;;
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

swarm_orchestrator_lane() {
  local repo_root="${1:-$(swarm_repo_root)}"
  local lane

  lane="$(
    awk -F '\t' '
      NR == 1 {
        for (i = 1; i <= NF; i++) {
          idx[$i] = i
        }
        next
      }
      ("role" in idx) && $(idx["role"]) == "workstream_orchestrator" {
        print $1
        exit
      }
    ' "$(swarm_lane_table "$repo_root")"
  )"
  if [[ -n "$lane" ]]; then
    printf '%s\n' "$lane"
    return
  fi

  lane="$(
    awk -F '\t' '
      NR == 1 {
        for (i = 1; i <= NF; i++) {
          idx[$i] = i
        }
        next
      }
      ("profile" in idx) && $(idx["profile"]) == "swarm-orchestrator" {
        print $1
        exit
      }
    ' "$(swarm_lane_table "$repo_root")"
  )"
  if [[ -n "$lane" ]]; then
    printf '%s\n' "$lane"
    return
  fi

  awk -F '\t' '
    NR == 1 {
      for (i = 1; i <= NF; i++) {
        idx[$i] = i
      }
      next
    }
    tolower($1) == "orch" {
      print $1
      exit
    }
    ("brief_id" in idx) && toupper($(idx["brief_id"])) == "ORCH" {
      print $1
      exit
    }
  ' "$(swarm_lane_table "$repo_root")"
}

swarm_orchestrator_lane_count() {
  local repo_root="${1:-$(swarm_repo_root)}"

  awk -F '\t' '
    NR == 1 {
      for (i = 1; i <= NF; i++) {
        idx[$i] = i
      }
      next
    }
    (("role" in idx) && $(idx["role"]) == "workstream_orchestrator") ||
    (("profile" in idx) && $(idx["profile"]) == "swarm-orchestrator") ||
    tolower($1) == "orch" ||
    (("brief_id" in idx) && toupper($(idx["brief_id"])) == "ORCH") {
      count++
    }
    END {
      print count + 0
    }
  ' "$(swarm_lane_table "$repo_root")"
}

swarm_namespace() {
  local repo_root
  local namespace
  local orch_lane
  local orch_worktree
  local orch_branch
  repo_root="$(swarm_repo_root "${1:-$(pwd)}")"
  if [[ -n "${CLAWDSTRIKE_SWARM_NAMESPACE:-}" ]]; then
    swarm_assert_safe_namespace_name "$CLAWDSTRIKE_SWARM_NAMESPACE"
    printf '%s\n' "$CLAWDSTRIKE_SWARM_NAMESPACE"
    return
  fi
  namespace="$(
    awk -F '\t' '
      NR == 1 {
        for (i = 1; i <= NF; i++) {
          idx[$i] = i
        }
        next
      }
      ("swarm" in idx) && $(idx["swarm"]) != "" {
        print $(idx["swarm"])
        exit
      }
    ' "$(swarm_lane_table "$repo_root")"
  )"
  if [[ -n "$namespace" ]]; then
    swarm_assert_safe_namespace_name "$namespace"
    printf '%s\n' "$namespace"
    return
  fi
  if [[ "$(swarm_orchestrator_lane_count "$repo_root")" == "1" ]]; then
    orch_lane="$(swarm_orchestrator_lane "$repo_root")"
    orch_worktree="$(swarm_lane_field "$orch_lane" worktree "$repo_root")"
    if [[ "$orch_worktree" == *-orch ]]; then
      namespace="${orch_worktree%-orch}"
      swarm_assert_safe_namespace_name "$namespace"
      printf '%s\n' "$namespace"
      return
    fi
    orch_branch="$(swarm_lane_field "$orch_lane" branch "$repo_root")"
    if [[ -n "$orch_branch" ]]; then
      namespace="${orch_branch##*/}"
      namespace="${namespace%-orchestrator}"
      namespace="${namespace%-orch}"
      if [[ -n "$namespace" ]] && [[ "${namespace,,}" != "orch" ]]; then
        swarm_assert_safe_namespace_name "$namespace"
        printf '%s\n' "$namespace"
        return
      fi
    fi
  fi
  namespace="$(swarm_repo_name "$repo_root")"
  swarm_assert_safe_namespace_name "$namespace"
  printf '%s\n' "$namespace"
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
  local namespace
  repo_root="$(swarm_repo_root "${1:-$(pwd)}")"
  repo_parent="$(swarm_repo_parent_dir "$repo_root")"
  parent_name="$(basename "$repo_parent")"
  namespace="$(swarm_namespace "$repo_root")"
  if [[ -n "${CLAWDSTRIKE_SWARM_ORCH_DIR:-}" ]]; then
    printf '%s\n' "$CLAWDSTRIKE_SWARM_ORCH_DIR"
    return
  fi
  case "$parent_name" in
    *-orchestration)
      printf '%s\n' "$repo_parent"
      ;;
    *-worktrees)
      printf '%s/%s-orchestration\n' "$(dirname "$repo_parent")" "$namespace"
      ;;
    *)
      printf '%s/%s-orchestration\n' "$repo_parent" "$namespace"
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

swarm_assert_safe_lane_name() {
  local lane="$1"
  if [[ ! "$lane" =~ ^[A-Za-z0-9_-]+$ ]]; then
    printf 'Unsafe lane name: %s\n' "$lane" >&2
    exit 1
  fi
}

swarm_assert_safe_worktree_name() {
  local worktree="$1"
  if [[ -z "$worktree" || "$worktree" == /* || "$worktree" == *..* || "$worktree" =~ [[:space:]] || ! "$worktree" =~ ^[A-Za-z0-9._-]+$ ]]; then
    printf 'Unsafe worktree name: %s\n' "$worktree" >&2
    exit 1
  fi
}

swarm_assert_safe_namespace_name() {
  local namespace="$1"
  if [[ -z "$namespace" || "$namespace" == /* || "$namespace" == *..* || "$namespace" =~ [[:space:]] || ! "$namespace" =~ ^[A-Za-z0-9._-]+$ ]]; then
    printf 'Unsafe swarm namespace: %s\n' "$namespace" >&2
    exit 1
  fi
}

swarm_assert_safe_branch_name() {
  local branch="$1"
  if [[ -z "$branch" || "$branch" == /* || "$branch" == *..* || "$branch" == *'@{'* || "$branch" =~ [[:space:]] || ! "$branch" =~ ^[A-Za-z0-9._/-]+$ ]]; then
    printf 'Unsafe branch name: %s\n' "$branch" >&2
    exit 1
  fi
  if ! git check-ref-format --branch "$branch" >/dev/null 2>&1; then
    printf 'Invalid branch name: %s\n' "$branch" >&2
    exit 1
  fi
}

swarm_require_lane() {
  local lane="$1"
  local repo_root="${2:-$(swarm_repo_root)}"
  swarm_assert_safe_lane_name "$lane"
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
  local worktree_name
  worktree_name="$(swarm_lane_field "$lane" worktree "$repo_root")"
  swarm_assert_safe_worktree_name "$worktree_name"
  printf '%s/%s\n' \
    "$(swarm_worktrees_dir "$repo_root")" \
    "$worktree_name"
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
        --sandbox \
        read-only \
        -c \
        'model_reasoning_effort="high"'
      ;;
    swarm-orchestrator)
      printf '%s\n' \
        --sandbox \
        workspace-write \
        -c \
        'model_reasoning_effort="high"'
      ;;
    swarm-worker)
      printf '%s\n' \
        --sandbox \
        workspace-write \
        -c \
        'model_reasoning_effort="medium"'
      ;;
    swarm-review)
      printf '%s\n' \
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
  local bootstrap_preset
  local -a bootstrap_args=()

  swarm_require_lane "$lane" "$repo_root"
  worktree_path="$(swarm_lane_worktree_path "$lane" "$repo_root")"
  bootstrap_preset="$(swarm_lane_bootstrap_cmd "$lane" "$repo_root")"

  if [[ -z "$bootstrap_preset" || "$bootstrap_preset" == "none" ]]; then
    return 0
  fi

  if [[ ! -d "$worktree_path" ]]; then
    printf 'cannot bootstrap %s: worktree missing at %s\n' "$lane" "$worktree_path" >&2
    exit 1
  fi

  case "$bootstrap_preset" in
    cargo-fetch-locked)
      bootstrap_args=(cargo fetch --locked)
      ;;
    cargo-fetch-agent-locked)
      bootstrap_args=(cargo fetch --locked --manifest-path apps/agent/src-tauri/Cargo.toml)
      ;;
    *)
      printf 'unsupported bootstrap preset for %s: %s\n' "$lane" "$bootstrap_preset" >&2
      printf '%s\n' 'bootstrap presets must be reviewed fixed argv IDs, not shell source' >&2
      exit 1
      ;;
  esac

  printf 'bootstrap %s: %s\n' "$lane" "$bootstrap_preset"
  (
    cd "$worktree_path"
    "${bootstrap_args[@]}"
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
  local role
  local profile

  swarm_require_lane "$lane" "$repo_root"
  brief_id="$(swarm_lane_field "$lane" brief_id "$repo_root")"
  description="$(swarm_lane_field "$lane" description "$repo_root")"
  docs_block="$(swarm_prompt_docs_block "$lane" "$repo_root")"
  role="$(swarm_lane_field "$lane" role "$repo_root")"
  profile="$(swarm_lane_field "$lane" profile "$repo_root")"

  if [[ "$role" == "workstream_orchestrator" || "$profile" == "swarm-orchestrator" ]]; then
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

  if [[ "$role" == "merge_reviewer" || "$profile" == "swarm-review" ]]; then
    cat > "$prompt_file" <<EOF_PROMPT
Use \$clawdstrike-merge-verifier.

Current lane: ${brief_id}.
Lane purpose: ${description}

Read these docs first:
${docs_block}

Review requirements:
- read the dependency graph and verification matrix before reviewing
- inspect the reviewed lane diff, owned files, and handoff evidence first
- run the lane verification commands or explain exactly why they could not run
- prioritize findings: regressions, ownership violations, missing verification, and scope drift
- if shared registration files are touched, hand them back to ORCH instead of silently accepting them
- leave a merge recommendation with blocking and non-blocking findings

Operator note:
${note:-No extra operator note. Start from the lane handoff and produce a findings-first review.}
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
