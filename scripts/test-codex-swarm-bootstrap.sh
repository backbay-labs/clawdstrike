#!/usr/bin/env bash

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

tmp_dir="$(mktemp -d)"
trap 'rm -rf "$tmp_dir"' EXIT

repo="$tmp_dir/repo"
worktrees="$tmp_dir/worktrees"
bin_dir="$tmp_dir/bin"
marker="$tmp_dir/marker"
mkdir -p "$repo/.codex/swarm" "$worktrees/bad-wt" "$worktrees/good-wt" "$bin_dir"
git init -q "$repo"

cat >"$repo/.codex/swarm/lanes.tsv" <<'TSV'
lane	worktree	branch	profile	role	brief_id	description	docs	bootstrap
bad	bad-wt	test/bad	swarm-worker	lane_worker	BAD	Bad lane	docs	touch /tmp/clawdstrike-swarm-bootstrap-pwned
good	good-wt	test/good	swarm-worker	lane_worker	GOOD	Good lane	docs	cargo-fetch-locked
TSV

if CLAWDSTRIKE_SWARM_WORKTREES_DIR="$worktrees" bash -c \
  "source '$REPO_ROOT/scripts/codex-swarm/common.sh'; swarm_run_lane_bootstrap bad '$repo'" \
  >"$tmp_dir/bad.out" 2>"$tmp_dir/bad.err"; then
  echo "expected arbitrary bootstrap shell source to fail closed" >&2
  exit 1
fi

if [[ -e /tmp/clawdstrike-swarm-bootstrap-pwned ]]; then
  echo "arbitrary bootstrap shell source was executed" >&2
  rm -f /tmp/clawdstrike-swarm-bootstrap-pwned
  exit 1
fi

grep -q "unsupported bootstrap preset" "$tmp_dir/bad.err"

cat >"$bin_dir/cargo" <<EOF
#!/usr/bin/env bash
printf '%s\n' "\$*" >"$marker"
EOF
chmod +x "$bin_dir/cargo"

PATH="$bin_dir:$PATH" CLAWDSTRIKE_SWARM_WORKTREES_DIR="$worktrees" bash -c \
  "source '$REPO_ROOT/scripts/codex-swarm/common.sh'; swarm_run_lane_bootstrap good '$repo'" \
  >"$tmp_dir/good.out" 2>"$tmp_dir/good.err"

grep -qx "fetch --locked" "$marker"
