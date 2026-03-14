# Sentinel Swarm - Next Wave Roadmap

> Concrete sequencing plan for the next sentinel-swarm wave after PR #190.

**Status:** Active roadmap
**Date:** 2026-03-12
**Branch:** `feat/sentinel-swarm`

---

## Goal

Turn sentinels from local workbench records into runtime-backed principals that
can execute missions, emit evidence-native signals, propose policy changes, and
participate in trusted federation.

## Workstreams

| Workstream | User value | Repo anchors |
|------------|------------|--------------|
| Sentinel Drivers | Real runtime identity, health, receipts, and sessions | `apps/workbench/src/lib/workbench/sentinel-*`, `crates/services/control-api/src/routes/agents.rs`, `apps/workbench/mcp-server/index.ts` |
| Claude Code Sentinel | Repo-native code sentinel that can inspect, patch, and verify | `packages/adapters/clawdstrike-claude/`, `apps/workbench/mcp-server/` |
| OpenClaw Hunt Pod | Browser and computer-use sentinel execution | `packages/adapters/clawdstrike-openclaw/`, `apps/desktop/src/features/openclaw/` |
| Swarm Mission Control | Explicit multi-sentinel objectives with handoffs | `apps/workbench/src/lib/workbench/swarm-*`, `finding-store.tsx`, `approval-*` |
| Evidence-Native Signal Ingestion | Tool calls, approvals, receipts, and transcripts become first-class signals | `signal-pipeline.ts`, `signal-store.tsx`, `speakeasy-bridge.ts`, `fleet-client.ts` |
| Policy Forge | Curators can propose policy diffs from findings and route to compare/editor approval | `policy-store.tsx`, `compare`, `editor`, `approvals` |
| Federated Intel Exchange | Signed, reputation-aware intel sharing across trusted/federated swarms | `reputation-tracker.ts`, Speakeasy bridge, Backbay witness/notary packages |
| Observe / Assist / Enforce | Clear operator-facing trust model for every sentinel | `docs/src/concepts/enforcement-tiers.md`, sentinel detail/create surfaces |

## Execution Order

### Phase 0 - Shared runtime substrate

Land the types, storage, and UI scaffolding required by every driver:

1. Add `SentinelRuntimeBinding` to the workbench sentinel model.
2. Add product-facing execution modes and explicit enforcement-tier mapping.
3. Capture runtime target metadata, health, receipt behavior, and session refs.
4. Expose the binding in create/list/detail surfaces.
5. Migrate persisted local sentinels forward without data loss.

### Phase 1 - Driver pilots

Build the first two concrete runtime paths:

1. Claude Code Sentinel for repo-local code execution.
2. OpenClaw Hunt Pod for browser/computer-use execution.
3. Hushd/Fleet-backed watcher binding for continuously monitored sentinels.

### Phase 2 - Mission and evidence loop

1. Introduce mission objects with stages, owners, deadlines, and receipts.
2. Convert tool calls, approvals, runtime events, and transcripts into `Signal`.
3. Promote correlated runtime evidence into `Finding` and `Intel`.

### Phase 3 - Policy closing loop

1. Let curator sentinels draft policy patches.
2. Route policy proposals through compare/editor with approvals.
3. Attach findings and receipts directly to policy proposals.

### Phase 4 - Federation

1. Publish signed intel envelopes with provenance and reputation.
2. Enable trusted and federated swarm subscriptions.
3. Bind witness/notary proofs to exported intel artifacts.

## Dependency Graph

| Depends on | Unlocks |
|------------|---------|
| Runtime substrate | Driver pilots, missions, evidence ingestion |
| Driver pilots | Mission execution, tool receipts, OpenClaw transcripts |
| Evidence ingestion | Finding promotion, policy forge, federation |
| Mission control | Coordinated swarm operations, approval routing |
| Policy forge | Closed-loop remediation |
| Federated intel | Cross-org network effects |

## Definition of Done

### Sentinel Drivers

- A sentinel records which runtime is bound to it.
- The operator can see execution mode, tier, target, health, and receipt status.
- A runtime session can be traced back to a sentinel from UI and data model state.

### Claude Code Sentinel

- A sentinel can start a code session against a repo/workspace.
- Tool events and checks are converted into signals with receipts.
- Findings can cite the exact session and command/tool lineage.

### OpenClaw Hunt Pod

- A sentinel can bind to a gateway/node target.
- Browser/computer-use transcripts become evidence.
- Approval and security posture are visible from the mission timeline.

### Swarm Mission Control

- Missions have objective, assignments, stages, deadlines, and status.
- Sentinel handoffs are explicit and receipted.
- Findings and policy proposals can attach to a mission.

### Evidence-Native Signal Ingestion

- Tool events, approvals, receipts, and runtime transcripts flow into `Signal`.
- The pipeline preserves provenance and receipt links.
- Findings can be created from runtime evidence without manual copy/paste.

### Policy Forge

- Curator sentinels can draft policy deltas with linked evidence.
- Operators can review them in existing compare/editor flows.
- Accepted proposals update policy history with traceable provenance.

### Federated Intel Exchange

- Intel can be signed, shared, scored, and verified.
- Reputation affects ingest/promotion decisions.
- Witness/notary provenance can be attached or verified.

## Current Execution Slice

This branch begins with Phase 0. The first deliverable is workbench-visible
runtime binding support:

- runtime driver selection
- execution mode and enforcement-tier display
- runtime target metadata
- persisted runtime config on sentinels

That slice is intentionally foundational. It avoids building one-off flows that
would have to be reworked once runtimes, missions, and evidence ingestion are
real.
