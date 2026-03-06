# Delivery Roadmap

This roadmap sequences the work needed to make the fleet-security architecture
real without forcing a single all-or-nothing rewrite.

## Phase 0: Documentation and Model Convergence

Goal: stabilize vocabulary, system boundaries, and source-of-truth decisions.

Deliverables:

- this documentation section
- initial directory object model
- current-state inventory tied to code
- architectural decisions on cloud vs local ownership

Exit criteria:

- engineering can point to one canonical architecture set for the initiative
- local and cloud identity semantics are no longer being described differently

## Phase 1: Cloud Directory MVP

Goal: turn the existing control API into a real directory-backed fleet control plane.

Deliverables:

- durable objects for swarm, project, capability group, and principal membership
- cloud-side inherited policy attachments
- effective policy resolution contract
- principal lifecycle transitions: revoke, quarantine, observe-only, restricted
- cloud publication of signed posture and response commands

Primary code surfaces:

- `crates/services/control-api`
- `crates/services/hushd`
- `apps/agent/src-tauri`

Exit criteria:

- operators can model fleet structure in the cloud
- policy inheritance is decided centrally and enforced locally
- the cloud can issue signed response actions beyond approval resolution

## Phase 2: Fleet Console Realignment

Goal: make the control console a real fleet console rather than a mostly local desktop surface.

Deliverables:

- cloud-backed fleet views for principals, liveness, posture, and policy state
- operator flows for quarantine, revoke, posture change, and session termination
- UI support for swarm/project/group browsing
- clear split between local endpoint views and fleet-wide views

Primary code surfaces:

- `apps/control-console`
- `apps/agent/src-tauri/src/api_server.rs`
- `crates/services/control-api`

Exit criteria:

- a connected deployment can manage and investigate fleets from the cloud console

## Phase 3: Hunt Backend MVP

Goal: convert the current hunt substrate into a service-backed investigation plane.

Deliverables:

- normalized fleet event store
- historical search API
- timeline reconstruction API
- saved hunts
- correlation job execution
- case and evidence export model

Primary code surfaces:

- `crates/libs/hunt-query`
- `crates/libs/hunt-correlate`
- `crates/services/control-api` or a dedicated hunt service

Exit criteria:

- hunt is no longer only a CLI workflow
- the console can run investigations against fleet data directly

## Phase 4: Provenance Graph and Delegation Intelligence

Goal: make principal lineage, delegation, and downstream effects queryable.

Deliverables:

- persisted delegation and spawn graph
- graph query APIs
- joins from grants to events to response actions
- UI graph exploration for investigations

Primary code surfaces:

- `crates/libs/hush-multi-agent`
- hunt backend services
- `apps/control-console`

Exit criteria:

- operators can reconstruct lateral movement and trust-chain breakpoints

## Phase 5: Endpoint and Response Expansion

Goal: deepen the EDR story and close the biggest coverage gaps.

Deliverables:

- broader host telemetry coverage
- Windows-native endpoint telemetry strategy
- richer detection packs and suppressions
- automation-safe response runbooks
- stronger evidence retention and replay packaging

Primary code surfaces:

- `crates/bridges/*`
- detection and hunt services
- control-plane response services

Exit criteria:

- the platform has a credible cross-platform fleet EDR story
- response is systematic, signed, and operator-safe

## Sequence Rationale

The order matters:

1. Directory first, because identity is the control plane.
2. Console second, because operators need one backend model.
3. Hunt backend third, because investigations need normalized fleet state.
4. Graph fourth, because lineage becomes much more valuable once state is unified.
5. Coverage expansion last, because broader telemetry without a coherent control model creates noise faster than value.
