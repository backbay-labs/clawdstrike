---
name: clawdstrike-lane-executor
description: Use when a Codex worker is running inside one Clawdstrike worktree and must implement exactly one assigned lane, stay within owned files, run verification, and leave a clean handoff.
---

# Clawdstrike Lane Executor

Use this skill for bounded implementation work inside a single lane worktree.

## Inputs

You should have:

- a lane ID such as `A1`, `A2`, or `ORCH`
- the fleet-security execution docs
- a worktree dedicated to the lane

## Workflow

1. Read the lane brief and owned-file boundaries first.
2. Inspect the current code before editing.
3. Stay inside the lane’s owned files.
4. If a needed edit touches a shared registration file, stop and hand it back
   to the orchestrator instead of quietly taking ownership.
5. Run the lane verification commands.
6. Leave a final handoff with changed files, commands run, and unresolved items.

## Required Docs

Read these before editing:

- `docs/src/fleet-security/workstream-map.md`
- `docs/src/fleet-security/verification-matrix.md`
- `docs/src/fleet-security/agent-briefs.md`

Then read the lane-specific docs referenced by the brief.

## Implementation Rules

- Keep migrations additive unless the brief explicitly says otherwise.
- Do not rename or renumber migrations on your own.
- Do not edit shared registration files owned by `ORCH`.
- Keep diffs narrow and reviewable.
- Verify before handoff.

## Stop Condition

The job is done only when the lane leaves a mergeable handoff, not when the
first code change lands.
