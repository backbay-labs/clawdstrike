# Dependency and Merge Graph

> **Status:** Draft | **Date:** 2026-03-06
>
> This document defines the hard dependencies, serialization points, and merge
> gates for the fleet-security workstreams.

## Dependency Types

Three dependency types matter:

- **Hard dependency:** a workstream should not begin until the upstream lane is
  merged or contract-frozen
- **Soft dependency:** a workstream can begin, but must expect rebase churn
- **Serialization point:** work can happen in parallel, but final integration
  must be done by the orchestrator in sequence

## Program Graph

```text
                               ORCH
                                 |
                +----------------+----------------+
                |                |                |
               A1               A2               A3
                |                |                |
                +--------+-------+-------+--------+
                         |               |
                         |               |
                        A4              A6
                         |
             +-----------+-----------+
             |                       |
            A5                      A7
             |
            A8
```

The graph above is intentionally conservative. It favors clean merges over
maximum theoretical parallelism.

## Wave Graph

```text
Wave 0: ORCH

Wave 1: A1  ||  A2  ||  A3

Wave 2: A4

Wave 3: A5  ||  A6  ||  A7

Wave 4: A8
```

`A5` may begin early with local scaffolding if needed, but the full lane should
be treated as Wave 3 because the useful console work depends on the backend
surfaces actually existing.

## Hard Dependencies

| Downstream | Upstream | Why |
|---|---|---|
| `A4` | `A1` | hunt needs stable `principal_id` joins and directory-backed identity |
| `A4` | `A2` | hunt needs stable detection rule/finding shapes |
| `A4` | `A3` | hunt needs response-action and acknowledgement artifacts to query |
| `A5` | `A1` | console needs cloud principal, swarm, project, and policy state |
| `A5` | `A2` | console needs findings, rules, suppressions, and pack metadata |
| `A5` | `A3` | console needs response-action APIs and posture controls |
| `A5` | `A4` | console needs hunt, timeline, and investigation surfaces |
| `A6` | `A3` | cases need response actions and operator state changes |
| `A6` | `A4` | cases need hunt outputs and evidence references |
| `A7` | `A1` | graph needs durable principals and memberships |
| `A7` | `A3` | graph needs response actions and grant revocation events |
| `A7` | `A4` | graph becomes useful only when hunt events are queryable |
| `A8` | `A4` | telemetry expansion must target the normalized event envelope the hunt backend expects |

## Soft Dependencies

| Downstream | Upstream | Notes |
|---|---|---|
| `A2` | `A1` | detection findings should prefer principal joins if available, but rule storage can land first |
| `A3` | `A1` | response actions can be built against current agent identity, then upgraded to principals |
| `A5` | `A6` | console case pages can start from mock models before case APIs land |
| `A5` | `A7` | graph UI work can start from placeholder graph contracts |
| `A8` | `A2` | some detection content may require new telemetry fields later |

## Serialization Points

These are the main merge hot spots:

| Surface | Policy |
|---|---|
| `crates/services/control-api/migrations/` | orchestrator assigns numbers and rebases |
| `crates/services/control-api/src/routes/mod.rs` | orchestrator-only integration |
| `crates/services/control-api/src/models/mod.rs` | orchestrator-only integration |
| `crates/services/control-api/src/services/mod.rs` | orchestrator-only integration |
| `crates/services/control-api/src/main.rs` | orchestrator-only integration |
| `crates/services/control-api/src/state.rs` | orchestrator-only integration |
| `apps/control-console/src/App.tsx` | orchestrator-only navigation integration |
| `apps/control-console/src/main.tsx` | orchestrator-only app bootstrap integration |

Workers should build isolated modules that can be wired in later rather than
touching these files early.

## Merge Gates

### Gate G0: Dispatch Ready

Required before parallel execution starts:

- [Multi-Agent Execution Overview](execution-orchestration.md) is accepted
- worktree naming and branch naming are fixed
- migration slots are reserved
- worker briefs are frozen

### Gate G1: Control Plane Foundation

Required to unlock `A4`:

- `A1` merged
- `A2` merged
- `A3` merged
- shared route/model/service wiring landed
- targeted control-api tests passing

### Gate G2: Investigation Foundation

Required to unlock `A5`, `A6`, and `A7`:

- `A4` merged
- normalized event retrieval works end-to-end
- findings and response actions can be joined in backend APIs

### Gate G3: Operator Surface

Required before broader telemetry work:

- `A5` merged
- at least one end-to-end operator flow works from console to backend

### Gate G4: Expansion and Hardening

Required before large coverage pushes:

- `A6` and `A7` merged
- case export and graph queries are stable enough to absorb more data volume

## Recommended PR Stack

The orchestrator should bias toward this stack:

1. orchestration docs and dispatch artifacts
2. `A1` directory foundation
3. `A2` detection core
4. `A3` response execution
5. shared integration pass over control-api registry files
6. `A4` hunt backend
7. `A6` cases and evidence
8. `A7` delegation graph
9. `A5` fleet console
10. `A8` telemetry expansion

The `A5` vs `A6`/`A7` ordering can move if the console lane is mostly isolated,
but the backend should stay ahead of the UI.

## Failure Handling

If a worker lane slips or stalls:

- do not let adjacent workers quietly edit the stalled lane’s owned files
- either reassign the lane as a new worker brief or let the orchestrator land a
  reduced-scope integration slice
- update the workstream map rather than allowing ownership drift
