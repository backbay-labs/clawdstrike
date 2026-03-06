---
name: clawdstrike-workstream-orchestrator
description: Use when specs are mature enough to split work into parallel ClawdStrike lanes with explicit ownership, dependency graphs, verification gates, merge order, and agent briefs.
---

# ClawdStrike Workstream Orchestrator

Use this skill when execution is near and the missing artifact is coordination: workstreams, lane boundaries, dependencies, verification, and merge discipline.

## Outcomes

Produce:

- workstream map
- dependency and merge graph
- verification matrix
- lane ownership and shared-file boundaries
- `.codex/swarm/lanes.tsv` and `.codex/swarm/waves.tsv`
- agent briefs or lane prompts

## Workflow

1. Read the current roadmap and implementation docs.
2. Split the program into bounded lanes with non-overlapping file ownership.
3. Call out the shared files that must stay orchestrator-owned.
4. Serialize migrations and other high-conflict assets.
5. Define verification commands per lane.
6. Define merge order and wave advancement.
7. Write or update `.codex/swarm/lanes.tsv` and `.codex/swarm/waves.tsv` so execution metadata matches the docs.

## Repo Discipline

- Prefer explicit lane IDs like `ORCH`, `P1A`, or `A3`.
- Tie every lane to real crate, app, package, or docs paths.
- Avoid vague ownership like "backend" or "frontend" with no file boundaries.
- Keep shared registration files, migration ordering, and release wiring orchestrator-owned.

## Documents To Reuse

- `docs/plans/multi-agent/overview.md`
- `docs/plans/multi-agent/isolation-boundaries.md`
- `docs/plans/multi-agent/coordination-protocols.md`
- initiative-local docs such as `apps/terminal/docs/dispatch-*.md`
- `.codex/swarm/lanes.tsv`
- `.codex/swarm/waves.tsv`

## Stop Condition

Do not launch workers from this skill unless the user explicitly asks. The job here is to make the execution topology real and unambiguous.
