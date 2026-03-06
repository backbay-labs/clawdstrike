---
name: clawdstrike-workstream-orchestrator
description: Use when the specs are mature enough to split work into parallel Clawdstrike lanes with explicit ownership, dependency graphs, verification gates, merge order, and agent briefs.
---

# Clawdstrike Workstream Orchestrator

Use this skill when execution is near and the missing artifact is coordination:
workstreams, lane boundaries, dependencies, verification, and merge discipline.

## Outcomes

Produce:

- workstream map
- dependency and merge graph
- verification matrix
- migration slot reservations
- merge gates
- agent briefs or lane prompts

## Workflow

1. Read the current roadmap and implementation docs.
2. Split the program into bounded lanes with non-overlapping file ownership.
3. Call out the shared files that must stay orchestrator-owned.
4. Serialize migrations and other high-conflict assets.
5. Define verification commands per lane.
6. Define the merge order and integration gates.

## Repo Discipline

- Reuse the fleet-security docs section as the source of truth.
- Prefer explicit lane IDs like `A1`, `A2`, `ORCH`.
- Tie every lane to real crate or app paths.
- Avoid vague ownership like “backend” or “frontend” with no file boundaries.
- Validate with `mdbook build docs`.

## Documents To Reuse

- `docs/src/fleet-security/workstream-map.md`
- `docs/src/fleet-security/dependency-graph.md`
- `docs/src/fleet-security/verification-matrix.md`
- `docs/src/fleet-security/agent-briefs.md`

If these docs do not exist yet, create them in that order.

## Stop Condition

Do not launch workers from this skill unless the user explicitly asks. The job
here is to make the execution topology real and unambiguous.
