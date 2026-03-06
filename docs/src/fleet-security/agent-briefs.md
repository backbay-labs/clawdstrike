# Agent Brief Pack

> **Status:** Draft | **Date:** 2026-03-06
>
> This document contains ready-to-paste worker briefs for Codex CLI execution.
> Each brief assumes the workstream boundaries defined in
> [Workstream Map](workstream-map.md).

## How to Use

1. create the lane worktree
2. start `codex exec` in that worktree
3. paste the corresponding brief below
4. let the worker complete its bounded scope
5. review the result through `codex exec review`

## `ORCH` Brief

```text
You are the orchestration lane for the Fleet Security program in the Clawdstrike
repository.

Your job is not to implement a feature lane. Your job is to manage the worker
lanes.

Read these docs first:
- docs/src/fleet-security/execution-orchestration.md
- docs/src/fleet-security/workstream-map.md
- docs/src/fleet-security/dependency-graph.md
- docs/src/fleet-security/verification-matrix.md
- docs/src/fleet-security/codex-cli-playbook.md

Rules:
- own shared registration files and merge wiring
- do not let worker lanes drift out of their owned files
- assign migration numbers and rebase conflicting SQL changes
- run review before merge
- keep the backend ahead of the UI

Deliverables:
- up-to-date orchestration notes
- shared-file integration commits
- merge-ready branch stack
- clear next-step guidance for whichever worker lane runs next
```

## `A1` Brief

```text
You are worker lane A1: Directory Foundation.

Read these docs first:
- docs/src/fleet-security/directory-object-model.md
- docs/src/fleet-security/effective-policy-resolution.md
- docs/src/fleet-security/principal-lifecycle.md
- docs/src/fleet-security/directory-api-contract.md
- docs/src/fleet-security/directory-implementation.md
- docs/src/fleet-security/directory-migrations.md
- docs/src/fleet-security/workstream-map.md
- docs/src/fleet-security/verification-matrix.md

Your goal:
- implement the cloud directory foundation in control-api
- land additive schema, principal backfill, directory CRUD surfaces, and policy attachment support

Owned surfaces:
- crates/services/control-api/migrations/006_*
- crates/services/control-api/migrations/007_*
- crates/services/control-api/migrations/008_*
- crates/services/control-api/migrations/009_*
- directory-related models, routes, services, and tests under crates/services/control-api/src/
- crates/services/control-api/src/routes/agents.rs
- crates/services/control-api/src/routes/tenants.rs
- crates/services/control-api/src/error.rs

Do not edit:
- crates/services/control-api/src/routes/mod.rs
- crates/services/control-api/src/models/mod.rs
- crates/services/control-api/src/services/mod.rs
- crates/services/control-api/src/main.rs
- crates/services/control-api/src/state.rs

Execution requirements:
- inspect the existing control-api code first
- keep migrations additive
- preserve compatibility with existing agents and enrollment flows
- add or update tests
- run the verification commands from verification-matrix.md

Final handoff must include:
- summary of implemented slices
- list of changed files
- commands run
- unresolved questions
```

## `A2` Brief

```text
You are worker lane A2: Detection Core.

Read these docs first:
- docs/src/fleet-security/detection-rule-model.md
- docs/src/fleet-security/suppression-tuning-model.md
- docs/src/fleet-security/rule-packaging-distribution.md
- docs/src/fleet-security/detection-api-contract.md
- docs/src/fleet-security/detection-storage-model.md
- docs/src/fleet-security/workstream-map.md
- docs/src/fleet-security/verification-matrix.md

Your goal:
- implement rule, finding, suppression, and detection-pack distribution support
- keep detection pack as a metadata extension of policy-pack

Owned surfaces:
- crates/services/control-api/migrations/010_*
- detection-related models, routes, services, and tests under crates/services/control-api/src/
- crates/libs/hunt-correlate/
- detection-related OCSF mapping in crates/libs/clawdstrike-ocsf/

Do not edit:
- crates/services/control-api/src/routes/mod.rs
- crates/services/control-api/src/models/mod.rs
- crates/services/control-api/src/services/mod.rs
- crates/services/control-api/src/main.rs
- crates/services/control-api/src/state.rs

Execution requirements:
- inspect current alerting and hunt-correlate surfaces first
- keep native correlation as the canonical execution model
- support Sigma through import or translation boundaries rather than replacing the native model
- leave YARA execution as first-class hook points where appropriate
- add tests and fixtures
- run the verification commands from verification-matrix.md

Final handoff must include:
- summary of storage and API additions
- changed files
- verification commands
- unresolved design or implementation questions
```

## `A3` Brief

```text
You are worker lane A3: Response Execution.

Read these docs first:
- docs/src/fleet-security/response-action-contract.md
- docs/src/fleet-security/response-execution-pipeline.md
- docs/src/fleet-security/workstream-map.md
- docs/src/fleet-security/verification-matrix.md

Your goal:
- implement the durable response-action plane for the fleet backend and agent command handling

Owned surfaces:
- crates/services/control-api/migrations/011_*
- response-related models, routes, services, and tests under crates/services/control-api/src/
- apps/agent/src-tauri/src/posture_commands.rs
- new agent-side response delivery modules if needed

Do not edit:
- crates/services/control-api/src/routes/mod.rs
- crates/services/control-api/src/models/mod.rs
- crates/services/control-api/src/services/mod.rs
- crates/services/control-api/src/main.rs
- crates/services/control-api/src/state.rs

Execution requirements:
- inspect the existing posture commands and approval flow first
- design for durable operator intent, publish state, ack state, and terminal outcomes
- keep actions tenant-scoped and signed where appropriate
- preserve compatibility with existing local posture controls
- add tests and sample payloads
- run the verification commands from verification-matrix.md

Final handoff must include:
- summary of the state machine and storage changes
- changed files
- commands run
- unresolved questions
```

## `A4` Brief

```text
You are worker lane A4: Hunt Backend.

Read these docs first:
- docs/src/fleet-security/normalized-fleet-event-envelope.md
- docs/src/fleet-security/hunt-backend.md
- docs/src/fleet-security/detection-api-contract.md
- docs/src/fleet-security/detection-storage-model.md
- docs/src/fleet-security/workstream-map.md
- docs/src/fleet-security/verification-matrix.md

Your goal:
- build the service-backed hunt plane: normalized event storage, search, timeline, IOC, correlate, and saved hunts

Owned surfaces:
- crates/services/control-api/migrations/012_*
- hunt-related models, routes, services, and tests under crates/services/control-api/src/
- crates/libs/hunt-query/
- service-facing hunt support in crates/libs/hunt-correlate/
- normalized export/join helpers in crates/libs/clawdstrike-ocsf/

Do not edit:
- crates/services/control-api/src/routes/mod.rs
- crates/services/control-api/src/models/mod.rs
- crates/services/control-api/src/services/mod.rs
- crates/services/control-api/src/main.rs
- crates/services/control-api/src/state.rs

Execution requirements:
- inspect the existing CLI hunt surfaces first
- do not rebuild the query model from scratch if existing crates already provide primitives
- keep the normalized event model aligned with the fleet event envelope spec
- add tests and fixtures for query, timeline, and correlation
- run the verification commands from verification-matrix.md

Final handoff must include:
- summary of storage and API surfaces
- changed files
- commands run
- sample event and query fixtures
```

## `A5` Brief

```text
You are worker lane A5: Fleet Console.

Read these docs first:
- docs/src/fleet-security/fleet-console-read-model.md
- docs/src/fleet-security/detection-api-contract.md
- docs/src/fleet-security/response-action-contract.md
- docs/src/fleet-security/hunt-backend.md
- docs/src/fleet-security/workstream-map.md
- docs/src/fleet-security/verification-matrix.md

Your goal:
- realign the control console around the cloud fleet backend

Owned surfaces:
- new fleet-oriented API client files under apps/control-console/src/api/
- new fleet contexts under apps/control-console/src/context/
- new fleet hooks, components, pages, and tests under apps/control-console/src/

Do not edit:
- apps/control-console/src/App.tsx
- apps/control-console/src/main.tsx

Execution requirements:
- inspect the existing client and SSE context first
- keep the visual language consistent with the existing console unless a target doc says otherwise
- prefer new fleet-specific modules rather than rewriting broad existing pages immediately
- add frontend tests and run the verification commands from verification-matrix.md

Final handoff must include:
- summary of new cloud-backed UI surfaces
- changed files
- commands run
- any gaps that still require backend follow-up
```

## `A6` Brief

```text
You are worker lane A6: Cases and Evidence.

Read these docs first:
- docs/src/fleet-security/case-evidence-bundle-model.md
- docs/src/fleet-security/hunt-backend.md
- docs/src/fleet-security/response-execution-pipeline.md
- docs/src/fleet-security/workstream-map.md
- docs/src/fleet-security/verification-matrix.md

Your goal:
- implement cases, evidence references, and exportable evidence bundles

Owned surfaces:
- crates/services/control-api/migrations/013_*
- case and evidence models, routes, services, and tests under crates/services/control-api/src/
- evidence bundle integration points in crates/libs/hush-certification/

Do not edit:
- crates/services/control-api/src/routes/mod.rs
- crates/services/control-api/src/models/mod.rs
- crates/services/control-api/src/services/mod.rs
- crates/services/control-api/src/main.rs
- crates/services/control-api/src/state.rs

Execution requirements:
- inspect the existing certification and evidence primitives first
- keep bundle artifacts reproducible and retention-aware
- make evidence references point back to hunt and response entities cleanly
- add tests and fixtures
- run the verification commands from verification-matrix.md

Final handoff must include:
- summary of case and bundle semantics
- changed files
- commands run
- unresolved risks
```

## `A7` Brief

```text
You are worker lane A7: Delegation Graph.

Read these docs first:
- docs/src/fleet-security/grants-delegation-graph.md
- docs/src/fleet-security/enrollment-join-protocol.md
- docs/src/fleet-security/workstream-map.md
- docs/src/fleet-security/verification-matrix.md

Your goal:
- implement persisted delegation and lineage graph surfaces for the fleet backend

Owned surfaces:
- crates/services/control-api/migrations/014_*
- graph-related models, routes, services, and tests under crates/services/control-api/src/
- lineage and graph helpers in crates/libs/hush-multi-agent/

Do not edit:
- crates/services/control-api/src/routes/mod.rs
- crates/services/control-api/src/models/mod.rs
- crates/services/control-api/src/services/mod.rs
- crates/services/control-api/src/main.rs
- crates/services/control-api/src/state.rs

Execution requirements:
- inspect current token, revocation, and identity-registry primitives first
- model graph storage so investigations can pivot from principal to grant to event to response action
- add query fixtures and tests
- run the verification commands from verification-matrix.md

Final handoff must include:
- summary of graph schema and query support
- changed files
- commands run
- open questions
```

## `A8` Brief

```text
You are worker lane A8: Telemetry Expansion.

Read these docs first:
- docs/src/fleet-security/normalized-fleet-event-envelope.md
- docs/src/fleet-security/detection-rule-model.md
- docs/src/fleet-security/hunt-backend.md
- docs/src/fleet-security/workstream-map.md
- docs/src/fleet-security/verification-matrix.md

Your goal:
- expand bridge and endpoint telemetry coverage against the normalized fleet event envelope

Owned surfaces:
- touched bridge crates under crates/bridges/
- normalization and conversion support in crates/libs/clawdstrike-ocsf/

Do not edit:
- control-api storage or route files owned by earlier lanes
- console files owned by A5

Execution requirements:
- inspect existing bridge mappers before making schema changes
- add new fields only when a downstream hunt, detection, or response use case justifies them
- keep platform-specific caveats explicit
- add fixtures and tests for each touched bridge
- run the verification commands from verification-matrix.md

Final handoff must include:
- summary of coverage additions
- changed files
- commands run
- remaining platform gaps
```

## `T1` Brief

```text
You are worker lane T1: Integration Harness Hardening.

Read these docs first:
- docs/src/fleet-security/verification-matrix.md
- docs/src/fleet-security/codex-cli-playbook.md
- docs/src/fleet-security/execution-orchestration.md

Your goal:
- make the control-api integration harness safe under the default parallel test runner
- remove or materially reduce flaky Docker port-allocation failures in CI

Owned surfaces:
- crates/services/control-api/src/integration_tests.rs
- test-only helper modules or scripts that are directly required by the control-api suite
- CI docs or verification notes if the harness contract changes

Do not edit:
- product code unrelated to test stability unless the harness proves it is required
- swarm-orchestrator shared files owned by ORCH

Execution requirements:
- inspect the current harness setup, container launch path, and any port allocation helpers first
- prefer deterministic container/network allocation or serialized test grouping over fragile host-port probing
- keep the suite runnable on developer machines and in GitHub Actions
- add or update regression coverage where possible
- run the relevant verification commands from verification-matrix.md

Final handoff must include:
- root cause summary for the flake
- changed files
- commands run
- any remaining CI caveats
```

## `T2` Brief

```text
You are worker lane T2: CI Parity and Verification.

Read these docs first:
- docs/src/fleet-security/verification-matrix.md
- docs/src/fleet-security/codex-cli-playbook.md

Your goal:
- run the merge-relevant validation stack for the fleet security branch
- close gaps between local verification and CI expectations

Owned surfaces:
- repo verification scripts under scripts/ if changes are needed for parity
- docs or notes that clarify required verification for this branch
- lane-local issue summaries and handoff artifacts

Do not edit:
- feature implementation files unless a verification failure requires a minimal targeted fix
- shared merge wiring owned by ORCH

Execution requirements:
- start from the current fleet-security feature branch state
- prioritize the exact jobs likely to gate merge: Rust, docs, frontend build/typecheck/test, changed-file coverage, and any offline/vendored checks that are relevant
- if a failure is real, fix it minimally and verify the fix
- if a failure is environmental, document it cleanly for ORCH

Final handoff must include:
- commands run
- pass/fail summary by gate
- any fixes applied
- any remaining blockers to merge
```

## `T3` Brief

```text
You are worker lane T3: Merge Shepherding.

Read these docs first:
- docs/src/fleet-security/execution-orchestration.md
- docs/src/fleet-security/dependency-graph.md
- docs/src/fleet-security/verification-matrix.md

Your goal:
- prepare the fleet security branch for final merge while other stabilization lanes run
- act as the bounded worker that watches branch state, outstanding review risk, and merge prerequisites

Owned surfaces:
- orchestration notes and handoff artifacts for merge readiness
- minimal branch hygiene changes if they are clearly required for merge

Do not edit:
- broad feature code that belongs to another lane
- shared route/model registration unless ORCH explicitly redirects you

Execution requirements:
- inspect current branch status, active review state, and likely merge blockers first
- keep a clear checklist of what must be true before merge
- if CI or review feedback uncovers a small isolated fix, note it and defer to the correct lane unless it is clearly in your bounded scope
- leave a concise operator-grade handoff for ORCH

Final handoff must include:
- merge readiness checklist
- outstanding blockers or risks
- recommended next action for ORCH
- commands run
```
