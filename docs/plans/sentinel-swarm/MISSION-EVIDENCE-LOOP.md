# Mission, Evidence, and Policy Forge Plan

> Concrete plan for Swarm Mission Control, Evidence-Native Signal Ingestion,
> and Policy Forge.

**Status:** Planned after runtime substrate
**Date:** 2026-03-12
**Branch:** `feat/sentinel-swarm`

---

## Why This Wave Matters

The current workbench already has most of the right nouns:

- Sentinels
- Signals
- Findings
- Intel
- Swarms
- approvals, compare, editor, and delegation views

What is missing is the operating loop that ties them together.

## Swarm Mission Control

Introduce a mission object that coordinates multiple sentinels around a single
objective.

### Proposed mission shape

```ts
interface SwarmMission {
  id: string;
  title: string;
  objective: string;
  status: "draft" | "active" | "blocked" | "completed" | "aborted";
  priority: "low" | "medium" | "high" | "critical";
  assignedSentinels: MissionAssignment[];
  stages: MissionStage[];
  evidenceIds: string[];
  findingIds: string[];
  policyProposalIds: string[];
  createdAt: number;
  dueAt: number | null;
}
```

### Mission stages

- intake
- reconnaissance
- validation
- containment
- policy-hardening
- publish-intel

Each stage has an owner sentinel, expected deliverables, and completion
receipts.

## Evidence-Native Signal Ingestion

Every meaningful runtime event should become signal material without manual
translation.

### Priority evidence sources

| Source | Existing anchor | Output |
|--------|-----------------|--------|
| Tool preflight/postflight | Claude/OpenClaw adapters | policy or behavioral signals |
| Approvals | `approval-*` | approval-linked signals and findings |
| Fleet runtime events | `fleet-client.ts`, control-api | heartbeat, drift, or posture signals |
| OpenClaw transcripts | OpenClaw gateway/node runtime | mission evidence and detections |
| Speakeasy exchanges | `speakeasy-bridge.ts` | shared intel or mission coordination signals |
| Receipts | `use-persisted-receipts.ts`, receipt inspector | signed evidence attachments |

### Pipeline rule

All ingested evidence must preserve:

- source sentinel or runtime
- provenance type
- timestamp
- receipt or transcript pointer
- mission linkage when present

## Policy Forge

Curator sentinels should be able to convert evidence and findings into concrete
policy change proposals.

### Policy proposal shape

```ts
interface PolicyProposal {
  id: string;
  findingIds: string[];
  missionId: string | null;
  basePolicyRef: PolicyRef;
  patchSummary: string;
  diffText: string;
  riskReduction: "low" | "medium" | "high";
  status: "draft" | "pending_approval" | "accepted" | "rejected";
  createdBySentinelId: string;
}
```

### Routing flow

1. Curator sentinel drafts a proposal from findings.
2. Proposal opens in compare/editor with linked evidence.
3. High-risk proposals route through approvals.
4. Accepted changes update the policy store and leave a receipt trail.

## Sequencing

### Phase 1

- define `SwarmMission` and `PolicyProposal` types/stores
- add mission timeline UI
- add evidence attachment schema

### Phase 2

- stream runtime tool events into `signal-store`
- link findings to missions automatically
- attach receipt links in finding detail

### Phase 3

- enable curator-generated policy proposals
- wire proposal review into compare/editor
- persist approval and acceptance history

## Definition of Done

- A mission can assign multiple sentinels with explicit handoffs.
- Runtime events automatically produce signals with provenance.
- Findings can cite mission evidence directly.
- Policy proposals can be drafted, reviewed, and accepted through existing
  workbench flows.
