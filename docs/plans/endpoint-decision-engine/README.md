# Endpoint Decision Engine

> **Status:** Draft | **Date:** 2026-05-15
> **Audience:** endpoint, agent, policy, evidence, response, and console implementers
> **Scope:** repo-grounded architecture set for ClawdStrike as a local runtime-integrity EDR

This planning set defines the next-generation EDR direction for ClawdStrike:

**local runtime integrity + causal evidence + controlled response.**

The product should not be another alert dashboard, SIEM forwarding shim, or AI wrapper. The local
endpoint should answer, in seconds:

1. what happened
2. what caused it
3. which identity, tool, agent, or session was responsible
4. what would break if the proposed rule blocked
5. whether the endpoint can contain it locally without bricking the machine
6. whether the decision can be proven later

## Reading Order

1. [Current State](./current-state.md)
2. [Target Architecture](./target-architecture.md)
3. [Implementation Roadmap](./roadmap.md)

## Initial Thesis

- ClawdStrike already has enough primitives to make this a natural evolution, not a greenfield
  product pivot.
- The repo currently has policy events, simulation, receipt signing, local agent EDR APIs, pure
  causal-graph/deception primitives, macOS ES/NE planning, and fleet response ledgers.
- The weak point is integration: sensors, graph, policy simulation, evidence receipts, and response
  actions are not yet one coherent local decision loop. The first local graph recorder and
  detection receipt schema now exist, but route-level receipt emission and response execution
  remain open.
- The differentiator should be causal explainability and provable safe action, not just more
  telemetry collection.
- AI-agent and developer-workstation protection is the wedge because the repo already models agent
  policy boundaries, MCP/tool calls, secret access, package-manager risk, brokered egress, and
  local agent APIs.

## Repo-Backed Product Contract

The endpoint decision engine must treat the endpoint as a local security decision point:

```text
OS and agent sensors
  -> canonical endpoint observations
  -> local causal graph
  -> policy and detection decisions
  -> impact simulation
  -> bounded local response
  -> signed receipts and replayable evidence
  -> optional cloud correlation
```

That is stricter than "collect events and upload them." The endpoint has to keep operating when
cloud assistance is unavailable, and every allow, block, quarantine, containment, and degradation
state needs a durable evidence story.

## Existing Code Touchpoints

| Area | Current files | Direction |
| --- | --- | --- |
| Endpoint EDR primitives | `crates/libs/clawdstrike-policy-event/src/edr.rs`, `src/facade.rs` | Keep as the pure model for endpoint observations, supply-chain guard findings, deception plans, and causal graph recording |
| Local agent EDR API | `apps/agent/src-tauri/src/api_server.rs`, `apps/agent/README.md` | Promote from helper endpoints into the local decision-engine API surface |
| macOS event and enforcement plan | `docs/plans/clawdstrike/macos-es-ne/**`, `apps/agent/src-tauri/macos/system-extension/**`, `apps/agent/src-tauri/src/macos/**` | Use as the first privileged endpoint-provider lane |
| Darwin telemetry bridge | `crates/bridges/darwin-telemetry-bridge/**` | Reuse signed Spine emission and outbox/health patterns for endpoint sensor ingestion |
| Policy events and simulation | `crates/libs/clawdstrike-policy-event/src/event.rs`, `src/simulate.rs`, `crates/services/hush-cli/src/policy_impact.rs`, `src/policy_observe.rs` | Extend from event replay to graph-aware rule impact and staged enforcement |
| Receipts and proofs | `crates/libs/hush-core/src/receipt.rs`, `src/signing.rs`, `src/merkle.rs`, `crates/libs/spine/**` | Make endpoint decisions receipt-first, including degraded sensor state |
| Detection, hunt, and response control plane | `crates/services/control-api/migrations/010_detection_core.sql`, `011_response_actions_and_execution_ledger.sql`, `012_hunt_backend.sql`, `013_case_evidence_bundles.sql` | Keep as cloud/operator projection of local endpoint decisions and evidence |
| Identity and delegation | `crates/services/control-api/src/models/delegation_graph.rs`, `crates/services/hushd/src/identity/**`, `docs/plans/multi-agent/**` | Bind decisions to user, session, agent, workload identity, approval, and policy epoch |
| Operator surfaces | `apps/control-console/**`, `apps/workbench/**`, `apps/desktop/**` | Expose process-cause, replay, simulation, containment, and proof workflows without reducing them to alert cards |
| Agent/tool security | `cursor-plugin/**`, `packages/adapters/**`, `rulesets/ai-agent*.yaml`, `docs/plans/clawdstrike/secret-broker/**` | Keep AI-agent and developer workstation protection as the first focused wedge |

## Non-Goals For The First Planning Set

- Do not claim full commodity EDR parity until real endpoint provider coverage, persistence, and
  local response execution are verified on supported operating systems.
- Do not collapse macOS EndpointSecurity and NetworkExtension semantics into the older Linux
  supervised-exec model.
- Do not make cloud verdicts mandatory for local allow/block/containment.
- Do not treat the existing in-memory graph recorder as sufficient for durable investigation.
- Do not describe response as "autonomous" unless the action has TTL, rollback, acknowledgement,
  and receipts.

## Deliverables In This Set

- a current-state assessment tied to real repo files
- a target architecture for the local endpoint decision loop
- a phased roadmap that separates shipped primitives, integration work, and release gates
