---
name: clawdstrike-swarm-supervisor
description: Use when it is time to create worktrees, launch Codex worker lanes, monitor background jobs, resume finished or stalled sessions, run review, and advance a ClawdStrike swarm through its waves.
---

# ClawdStrike Swarm Supervisor

Use this skill when execution should move from docs and plans into live Codex worker orchestration.

## Outcomes

Drive toward:

- worktree setup
- lane launches
- wave launches
- status checks
- resume runs
- review runs
- controlled advancement from one wave to the next

## Commands

Prefer the repo-local command suite:

- `scripts/codex-swarm/setup-worktrees.sh`
- `scripts/codex-swarm/bootstrap-lane.sh`
- `scripts/codex-swarm/launch-lane.sh`
- `scripts/codex-swarm/launch-wave.sh`
- `scripts/codex-swarm/status.sh`
- `scripts/codex-swarm/resume-lane.sh`
- `scripts/codex-swarm/review-lane.sh`

Use plain `git worktree` and `codex exec` only when you need to inspect or patch
the orchestration flow itself.

## Workflow

1. Confirm the workstream docs and `.codex/swarm/*.tsv` metadata are current.
2. Create only the worktrees needed for the next wave.
3. Launch only the lanes allowed by the dependency graph.
4. Monitor status instead of blindly launching more workers.
5. Review and merge completed lanes before advancing the wave.
6. Keep orchestration artifacts current as reality changes.

## Required Inputs

- `.codex/swarm/lanes.tsv`
- `.codex/swarm/waves.tsv`
- the initiative docs and verification commands

## Stop Condition

Do not treat "workers are running" as success. Success is controlled progress: bounded lane execution, review, merge, and wave advancement.
