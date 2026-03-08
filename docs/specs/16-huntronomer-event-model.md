# Spec 16: Huntronomer Event Model

> **Status:** Draft | **Date:** 2026-03-07
> **Author:** Codex
> **Dependencies:** Spec 15 (Adaptive SDR Architecture), desktop OpenClaw integration research, Huntronomer product spec v0.1

## 1. Overview

This specification defines the normalized object and event model for Huntronomer v1. The purpose
is to give the desktop app one canonical typed layer for:

- the Signal Wire
- Huntboard transitions
- receipt and replay linkage
- watchlists and visibility
- publication back into the network

Without this layer, the product will remain coupled to transport-specific shapes such as daemon
audit events or gateway runtime snapshots.

## 2. Scope

This spec defines:

- core v1 object types
- the normalized wire envelope
- the signal-to-hunt launch contract
- proof linkage requirements
- visibility and redaction rules for typed objects

This spec does not define:

- ranking algorithms
- monetization
- full reputation scoring math
- backend persistence format

## 3. Design Invariants

1. Every primary feed row resolves to one canonical object type.
2. Every execution-backed claim can link to the relevant swarm run, receipt set, posture, and
   replay entry point.
3. `Fork Hunt` and `Assign Swarm` preserve source context rather than re-asking the operator to
   reconstruct it.
4. Visibility is explicit on each object and must survive citations and promotions.
5. The event model must support both local-only and network-backed deployments.

## 4. Core Object Types

### 4.1 Visibility

```ts
type Visibility = "private" | "team" | "public" | "unlisted";
```

### 4.2 Validation State

```ts
type ValidationState = "emerging" | "validated" | "challenged" | "disputed" | "retracted";
```

### 4.3 Signal

```ts
interface Signal {
  id: string;
  title: string;
  summary: string;
  source: { kind: string; label: string; url?: string };
  severity: "low" | "medium" | "high" | "critical";
  confidence: "low" | "medium" | "high";
  tags: string[];
  linkedEntities: string[];
  linkedArtifacts: string[];
  visibility: Visibility;
  validationState: ValidationState;
  linkedReceiptIds: string[];
  linkedHuntIds: string[];
  createdAt: string;
  updatedAt: string;
}
```

### 4.4 Hunt

```ts
interface Hunt {
  id: string;
  title: string;
  scope: string;
  ownerId: string;
  teamId?: string;
  posture: string;
  queryDefinition?: string;
  associatedSwarmId?: string;
  state: "draft" | "queued" | "running" | "blocked" | "completed" | "promoted";
  evidenceCount: number;
  linkedReceiptIds: string[];
  sourceObject?: { type: WireObjectType; id: string };
  visibility: Visibility;
  createdAt: string;
  updatedAt: string;
}
```

### 4.5 Swarm Run

```ts
interface SwarmRun {
  id: string;
  huntId: string;
  roles: Array<{ role: string; agentId?: string; label: string }>;
  branchTopology: string;
  currentState: "queued" | "running" | "blocked" | "completed" | "failed";
  taskCount: number;
  approvalCount: number;
  blockedActionCount: number;
  latencyMs?: number;
  costEstimate?: number;
  outcomeSummary?: string;
}
```

### 4.6 Receipt

```ts
interface Receipt {
  id: string;
  signer: string;
  action: string;
  target: string;
  outcome: "allow" | "deny" | "observe" | "error";
  policyVersion: string;
  timestamp: string;
  evidencePointers: string[];
  replayRef?: string;
  runRef?: string;
  visibility: Visibility;
  redactionState: "none" | "partial" | "metadata-only";
}
```

### 4.7 Brief

```ts
interface Brief {
  id: string;
  title: string;
  summary: string;
  authorId: string;
  citedObjectIds: string[];
  validationState: ValidationState;
  visibility: Visibility;
  createdAt: string;
  updatedAt: string;
}
```

### 4.8 Future-Compatible Objects

The v1 model must leave room for:

- `Rule`
- `Case`
- `Challenge`
- `ProfileRecord`

These may ship in later v1 waves, but envelope and linking rules must already tolerate them.

## 5. Wire Envelope

All feed rows, inspector selections, and omnibox results should resolve through one normalized
envelope.

```ts
type WireObjectType =
  | "signal"
  | "hunt"
  | "swarm_run"
  | "receipt"
  | "brief"
  | "rule"
  | "case"
  | "challenge"
  | "profile";

interface WireObjectEnvelope {
  id: string;
  type: WireObjectType;
  title: string;
  summary: string;
  severity?: "low" | "medium" | "high" | "critical";
  confidence?: "low" | "medium" | "high";
  tags: string[];
  linkedEntities: string[];
  linkedObjectIds: string[];
  visibility: Visibility;
  validationState?: ValidationState;
  sourceLabel?: string;
  timestamp: string;
  actions: WireAction[];
  backingRefs?: {
    huntId?: string;
    swarmRunId?: string;
    receiptIds?: string[];
    replayRef?: string;
  };
}
```

## 6. Supported Wire Actions

```ts
type WireAction =
  | "boost"
  | "validate"
  | "challenge"
  | "fork_hunt"
  | "assign_swarm"
  | "watch"
  | "cite"
  | "promote";
```

The UI may hide actions by object type, but the vocabulary should stay consistent across the
product.

## 7. Signal-to-Hunt Launch Contract

Any `fork_hunt` or `assign_swarm` action must produce a structured launch payload:

```ts
interface HuntLaunchContext {
  sourceObject: { type: WireObjectType; id: string };
  titleSeed: string;
  selectedEntityIds: string[];
  selectedTags: string[];
  confidence?: "low" | "medium" | "high";
  severity?: "low" | "medium" | "high" | "critical";
  linkedReceiptIds: string[];
  visibility: Visibility;
  initialPosture?: string;
  preferredSwarmProfile?: string;
}
```

The Huntboard must open from this context without losing lineage back to the source object.

## 8. Source Projection Rules

Huntronomer may ingest from several transport-specific sources, but they must all project into the
same normalized model.

### 8.1 Daemon Audit Stream

Current source: `apps/desktop/src/services/eventStream.ts`

Projection:

- may emit `receipt` envelopes directly
- may contribute proof links or evidence counts to existing `hunt` envelopes
- must not become the only home-screen data model

### 8.2 OpenClaw Runtime

Current source:

- `apps/desktop/src/services/openclaw/gatewayClient.ts`
- `apps/desktop/src/context/OpenClawContext.tsx`

Projection:

- may emit `swarm_run` summaries
- may enrich `hunt` state and approval counts
- may add live runtime context to Huntboard inspectors

### 8.3 User or Team Signals

Projection:

- emit first-class `signal` envelopes
- may later promote to `brief`, `case`, or `rule`

## 9. Proof Linkage Rules

For any object derived from execution, the product must be able to resolve:

- associated hunt ID, if any
- associated swarm run ID, if any
- relevant receipt IDs
- replay reference
- effective visibility
- redaction state

If any of those are unavailable, the UI must mark the proof chain as partial rather than implying
strong proof.

## 10. Visibility and Redaction

Rules:

1. Public objects may link to private proof material only through redacted metadata.
2. A public brief may cite a private receipt, but the cited representation must expose only allowed
   metadata.
3. A team-scoped hunt may be launched from a public signal without changing the signal's visibility.
4. Unlisted objects are addressable by direct link but should not rank in general feeds.

## 11. Acceptance Criteria

- The desktop app can render v1 wire rows using only `WireObjectEnvelope`.
- `Signal`, `Hunt`, `Receipt`, and `Brief` can all appear in one feed with type-specific actions.
- A hunt launch action carries preserved source context.
- Receipt-backed objects expose proof links without requiring transport-specific UI code at the row
  level.
- Visibility and redaction state are explicit and renderable on every v1 object type.
