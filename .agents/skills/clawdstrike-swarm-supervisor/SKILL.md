---
name: clawdstrike-swarm-supervisor
description: Use when it is time to create worktrees, launch Codex worker lanes, monitor background jobs, resume finished or stalled sessions, run review, and advance the Clawdstrike swarm through its waves.
---

# Clawdstrike Swarm Supervisor

Use this skill when execution should move from docs and plans into live Codex
worker orchestration.

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
- `scripts/codex-swarm/launch-lane.sh`
- `scripts/codex-swarm/launch-wave.sh`
- `scripts/codex-swarm/status.sh`
- `scripts/codex-swarm/resume-lane.sh`
- `scripts/codex-swarm/review-lane.sh`

## Workflow

1. Confirm the workstream docs are current.
2. Set up worktrees and orchestration directories.
3. Launch only the lanes allowed by the dependency graph.
4. Monitor status instead of blindly launching more workers.
5. Review and merge completed lanes before advancing the wave.
6. Keep the backend ahead of the UI and telemetry expansion.

## Required Docs

- `docs/src/fleet-security/execution-orchestration.md`
- `docs/src/fleet-security/workstream-map.md`
- `docs/src/fleet-security/dependency-graph.md`
- `docs/src/fleet-security/verification-matrix.md`
- `docs/src/fleet-security/codex-cli-playbook.md`

## Stop Condition

Do not treat “workers are running” as success. Success is controlled progress:
bounded lane execution, review, merge, and wave advancement.
