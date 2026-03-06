# Multi-Agent Execution Overview

> **Status:** Draft | **Date:** 2026-03-06
>
> This document defines how the fleet-security program is executed through
> parallel Codex CLI workstreams without losing schema safety, file ownership
> clarity, or merge discipline.

## Purpose

The fleet-security initiative is now documented deeply enough to support
execution. The next problem is not architecture ambiguity. The next problem is
coordination.

This execution model exists to make these constraints true at the same time:

- multiple Codex worker lanes can run in parallel
- control-plane contracts stay coherent
- migrations do not collide
- shared registration files do not turn into merge-conflict hot spots
- every worker lane produces reviewable, verifiable output

## Operator Model

The program uses three execution roles:

- `ORCH`: the orchestration lane that creates worktrees, assigns migration
  slots, dispatches workers, runs review, and merges in dependency order
- `A*`: worker lanes that implement one bounded workstream each
- `REVIEW`: a review pass run through `codex exec review` before a worker branch
  is merged

The orchestrator may be a human operator, a primary Codex session, or both.
The important rule is that merge authority stays centralized even if
implementation does not.

## Hard Rules

1. One worker, one git worktree, one branch.
2. One worker owns one bounded workstream.
3. Shared wiring files are orchestrator-owned.
4. Database migrations are serialized and numbered by the orchestrator.
5. Every worker must leave a verification bundle before review.
6. No worker merges directly to `main`.

## Shared Coordination Files

These files are reserved for the orchestrator unless a worker brief explicitly
states otherwise:

- `crates/services/control-api/src/routes/mod.rs`
- `crates/services/control-api/src/models/mod.rs`
- `crates/services/control-api/src/services/mod.rs`
- `crates/services/control-api/src/main.rs`
- `crates/services/control-api/src/state.rs`
- `crates/services/control-api/src/routes/events.rs`
- `crates/services/control-api/src/services/agent_heartbeat_consumer.rs`
- `crates/services/control-api/src/services/approval_request_consumer.rs`
- `apps/control-console/src/App.tsx`
- `apps/control-console/src/main.tsx`
- `docs/src/SUMMARY.md`

The reason is simple: these are high-conflict files that represent shared
registration or integration seams. Workers should add isolated modules and
tests. The orchestrator wires those modules together after review.

## Wave Plan

The workstreams are grouped into waves.

### Wave 0

Preparation only.

- freeze the directory, detection, response, and hunt specs as the execution
  baseline
- create worktrees and branch names
- reserve migration slots
- dispatch worker briefs

### Wave 1

Foundation lanes that can start first.

- `A1`: directory foundation
- `A2`: detection core
- `A3`: response execution

These lanes are the minimum viable parallel set. They define the core cloud
objects, detection state, and operator action ledger needed for the rest of the
 system.

### Wave 2

Investigation substrate.

- `A4`: hunt backend

`A4` should start only after the A1/A2/A3 contracts are stable enough that the
event model, principal joins, and response artifacts are not moving daily.

### Wave 3

Operator-facing and investigation-adjacent lanes.

- `A5`: fleet console
- `A6`: cases and evidence bundles
- `A7`: delegation and provenance graph

These can run in parallel once the hunt and control-plane surfaces are stable.

### Wave 4

Coverage expansion.

- `A8`: telemetry and coverage expansion

This lane broadens the EDR story only after the normalized event and detection
surfaces are already coherent.

## Handoff Contract

Every worker lane must leave the same artifacts:

- a concise summary of what changed
- the list of touched files
- the commands run and their result
- open questions or follow-up items
- any assumptions that were made

The handoff should be good enough that the orchestrator can run review and
merge the lane without having to rediscover intent from the diff.

## Merge Philosophy

The merge queue should prefer small, dependency-correct branches over “big
bang” convergence branches.

Recommended order:

1. `A1` directory foundation
2. `A2` detection core
3. `A3` response execution
4. orchestrator integration pass over shared wiring
5. `A4` hunt backend
6. `A5`, `A6`, and `A7` in whichever order produces the fewest shared-file
   touches
7. `A8` telemetry expansion

## Related Documents

This document should be read with:

- [Workstream Map](workstream-map.md)
- [Dependency and Merge Graph](dependency-graph.md)
- [Verification Matrix](verification-matrix.md)
- [Codex CLI Orchestration Playbook](codex-cli-playbook.md)
- [Agent Brief Pack](agent-briefs.md)

## Exit Criteria

This execution model is working when:

- every planned lane has a bounded file-ownership contract
- migration and merge order are explicit
- the orchestrator can dispatch and review worker lanes using Codex CLI without
  inventing process on the fly
- the program can move from documentation into implementation without losing the
  architecture thread
