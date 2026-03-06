# Workstream Map

> **Status:** Draft | **Date:** 2026-03-06
>
> This document defines the end-to-end implementation lanes for the
> fleet-security program. It is the file-ownership and merge-boundary map for
> Codex CLI worker execution.

## Workstream Table

| ID | Name | Wave | Goal | Primary Code Surfaces | Hard Deps |
|---|---|---|---|---|---|
| `ORCH` | Orchestrator | 0-4 | dispatch, review, merge, shared wiring | shared registration files, docs, integration tests | none |
| `A1` | Directory Foundation | 1 | directory schema, principals, memberships, policy attachments | `crates/services/control-api` | docs freeze |
| `A2` | Detection Core | 1 | rules, findings, suppressions, detection-pack metadata extension | `crates/services/control-api`, `crates/libs/hunt-correlate`, `crates/libs/clawdstrike-ocsf` | docs freeze |
| `A3` | Response Execution | 1 | response actions, ledger, publish and ack scaffolding | `crates/services/control-api`, `apps/agent/src-tauri` | docs freeze |
| `A4` | Hunt Backend | 2 | normalized store, query, timeline, correlate, IOC, saved hunts | `crates/services/control-api`, `crates/libs/hunt-query`, `crates/libs/hunt-correlate`, `crates/libs/clawdstrike-ocsf` | `A1`, `A2`, `A3` |
| `A5` | Fleet Console | 3 | cloud fleet UI, read models, response controls, hunt views | `apps/control-console` | `A1`, `A2`, `A3`, `A4` |
| `A6` | Cases and Evidence | 3 | cases, evidence references, export bundles | `crates/services/control-api`, `crates/libs/hush-certification` | `A3`, `A4` |
| `A7` | Delegation Graph | 3 | grant lineage, spawn graph, graph queries | `crates/services/control-api`, `crates/libs/hush-multi-agent` | `A1`, `A3`, `A4` |
| `A8` | Telemetry Expansion | 4 | bridge coverage expansion and envelope normalization | `crates/bridges/*`, `crates/libs/clawdstrike-ocsf` | `A4` |

## Migration Slot Reservation

The orchestrator owns migration numbering. The initial reservation plan is:

| Slot | Owner | Purpose |
|---|---|---|
| `006` | `A1` | fleet directory core |
| `007` | `A1` | principal backfill and compatibility links |
| `008` | `A1` | policy attachments and effective policy support |
| `009` | `A1` | principal-aware joins |
| `010` | `A2` | detection core storage |
| `011` | `A3` | response actions and execution ledger |
| `012` | `A4` | hunt backend storage |
| `013` | `A6` | cases and evidence storage |
| `014` | `A7` | graph storage |

If a lane discovers it needs more than its reserved slot count, the worker does
not self-assign new numbers. The worker leaves draft SQL in its branch and asks
the orchestrator to allocate the next slot.

## `ORCH`: Orchestrator Lane

### Mission

Own the program-level coordination work that should not be spread across
parallel workers.

### Owns

- worktree creation and cleanup
- branch naming
- migration numbering
- shared registration files
- merge queue
- review queue
- cross-lane integration tests
- docs updates to execution status

### Must Not Delegate

- final edits to `routes/mod.rs`, `models/mod.rs`, `services/mod.rs`
- final edits to `main.rs`, `state.rs`, `App.tsx`, `main.tsx`
- migration renumbering and rebase work

### Produces

- lane branches with clean merge order
- review summaries
- final integration commits

## `A1`: Directory Foundation

### Mission

Implement the cloud directory foundation defined by the directory specs and
implementation plan.

### Owns

- `crates/services/control-api/migrations/006_*`
- `crates/services/control-api/migrations/007_*`
- `crates/services/control-api/migrations/008_*`
- `crates/services/control-api/migrations/009_*`
- new directory models under `crates/services/control-api/src/models/`
- new directory routes under `crates/services/control-api/src/routes/`
- directory helpers under `crates/services/control-api/src/services/`
- `crates/services/control-api/src/routes/agents.rs`
- `crates/services/control-api/src/routes/tenants.rs`
- `crates/services/control-api/src/error.rs`
- `crates/services/control-api/src/integration_tests.rs`

### Avoid

- shared registration files owned by `ORCH`
- detection, hunt, case, graph, and console UI files

### Handoff

- additive schema and backfill
- principal-backed CRUD surfaces
- effective-policy resolution helpers
- tests proving compatibility with existing `agents` flows

## `A2`: Detection Core

### Mission

Implement the rule, finding, suppression, and distribution surfaces described
by the detection specs, while keeping detection pack distribution as a metadata
extension of `policy-pack`.

### Owns

- `crates/services/control-api/migrations/010_*`
- new detection models under `crates/services/control-api/src/models/`
- new detection routes under `crates/services/control-api/src/routes/`
- new detection services under `crates/services/control-api/src/services/`
- detection-specific tests in `crates/services/control-api/src/integration_tests.rs`
- detection rule execution surfaces in `crates/libs/hunt-correlate/`
- detection finding/OCSF mapping in `crates/libs/clawdstrike-ocsf/`

### Avoid

- shared registration files owned by `ORCH`
- principal lifecycle and membership files owned by `A1`
- response transport and ack files owned by `A3`

### Handoff

- `detection_rules`, `detection_findings`, and `detection_suppressions`
- CRUD and list APIs
- native correlation rule support
- Sigma import contract and YARA hook points
- detection-pack metadata extension for `policy-pack`

## `A3`: Response Execution

### Mission

Implement the durable response-action plane that turns operator intent into
tracked, signed, and acknowledged response execution.

### Owns

- `crates/services/control-api/migrations/011_*`
- new response models under `crates/services/control-api/src/models/`
- new response routes under `crates/services/control-api/src/routes/`
- new response services under `crates/services/control-api/src/services/`
- response tests in `crates/services/control-api/src/integration_tests.rs`
- `apps/agent/src-tauri/src/posture_commands.rs`
- related agent-side command handling modules added for cloud response delivery

### Avoid

- shared registration files owned by `ORCH`
- directory object and principal backfill files owned by `A1`
- hunt query and timeline surfaces owned by `A4`

### Handoff

- response-action ledger
- publish and ack contract
- operator actions for quarantine, revoke, observe-only, and policy reload
- tests for delivery state transitions

## `A4`: Hunt Backend

### Mission

Turn the existing hunt substrate into a service-backed investigation plane.

### Owns

- `crates/services/control-api/migrations/012_*`
- new hunt models under `crates/services/control-api/src/models/`
- new hunt routes under `crates/services/control-api/src/routes/`
- new hunt services under `crates/services/control-api/src/services/`
- `crates/libs/hunt-query/`
- `crates/libs/hunt-correlate/` for service-facing execution support
- `crates/libs/clawdstrike-ocsf/` for normalized envelope and export joins

### Avoid

- shared registration files owned by `ORCH`
- rule authoring surfaces owned by `A2`
- case-management storage owned by `A6`

### Handoff

- normalized event store
- query, timeline, IOC, and correlation APIs
- saved hunts and execution jobs
- fleet event retrieval that joins to principals and findings

## `A5`: Fleet Console

### Mission

Realign the control console around the cloud fleet model instead of the current
mostly local desktop API shape.

### Owns

- new fleet-specific API client files under `apps/control-console/src/api/`
- new fleet read-model and stream context files under
  `apps/control-console/src/context/`
- new fleet hooks under `apps/control-console/src/hooks/`
- new fleet pages and components under `apps/control-console/src/pages/` and
  `apps/control-console/src/components/`
- frontend tests under `apps/control-console/src/**/*.test.ts*`

### Avoid

- `apps/control-console/src/App.tsx`
- `apps/control-console/src/main.tsx`
- shared navigation wiring reserved for `ORCH`

### Handoff

- cloud-backed principal, posture, policy, finding, and response views
- hunt and case entry points
- typed client calls for the new backend APIs

## `A6`: Cases and Evidence

### Mission

Implement case management and evidence bundle surfaces on top of the hunt and
response outputs.

### Owns

- `crates/services/control-api/migrations/013_*`
- new case and evidence models, routes, and services under
  `crates/services/control-api/src/`
- evidence bundle integration points with `crates/libs/hush-certification/`

### Avoid

- shared registration files owned by `ORCH`
- core hunt query files owned by `A4`
- console rendering owned by `A5`

### Handoff

- cases, case events, and evidence references
- exportable evidence bundles
- retention-aware bundle metadata

## `A7`: Delegation Graph

### Mission

Make grant lineage, spawn chains, and downstream effects queryable as a first
class investigation surface.

### Owns

- `crates/services/control-api/migrations/014_*`
- graph models, routes, and services under `crates/services/control-api/src/`
- lineage and graph-query support in `crates/libs/hush-multi-agent/`

### Avoid

- shared registration files owned by `ORCH`
- case/export flows owned by `A6`
- console layout wiring owned by `A5`

### Handoff

- persisted delegation graph
- graph query endpoints
- joins from principals and grants to hunt events and response actions

## `A8`: Telemetry Expansion

### Mission

Expand host and bridge coverage only after the normalized event model is
stable.

### Owns

- touched bridge crates under `crates/bridges/`
- OCSF conversion updates under `crates/libs/clawdstrike-ocsf/`
- bridge-specific mapper and fixture tests

### Avoid

- control-plane storage and route files owned by earlier lanes
- console files owned by `A5`

### Handoff

- broader normalized telemetry coverage
- new mapper fixtures
- explicit gaps and platform caveats for anything still missing

## Related Documents

- [Multi-Agent Execution Overview](execution-orchestration.md)
- [Dependency and Merge Graph](dependency-graph.md)
- [Verification Matrix](verification-matrix.md)
- [Codex CLI Orchestration Playbook](codex-cli-playbook.md)
- [Agent Brief Pack](agent-briefs.md)
