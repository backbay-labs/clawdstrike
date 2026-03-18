# Hunt Observatory Spec

> **Status:** Draft
> **Date:** 2026-03-09
> **Audience:** Product, design, desktop, workbench, and 3D/runtime implementers
> **Scope:** Harden the Hunt Observatory concept into a concrete implementation spec for
> Huntronomer’s 3D operating surface

## Purpose

This spec defines the concrete contract for the **Hunt Observatory**: the shared 3D operating
surface that should unify today’s Forensics River and Cyber Nexus work into one active-hunt world.

It is the implementation follow-on to [Hunt Observatory Concept](./hunt-observatory-concept.md).

This document is intentionally specific about:

- station taxonomy
- shared scene state
- shared actor contracts
- mode behavior
- what belongs in-room vs outside the room
- implementation order against current code

## Product Definition

The Hunt Observatory is the default 3D operating surface for an active hunt.

It is not:

- a free-roam simulation
- a generic graph playground
- a collection of separate 3D demo views
- a replacement for editor-grade detail surfaces

It is:

- one stable spatial world per active hunt
- one set of semantic stations around that world
- one shared actor pipeline for runs, receipts, evidence, watch state, and spirit posture
- two primary scene modes over the same hunt world

## Scene Modes

The observatory has two required 3D modes in v1.

### `flow`

`flow` is the direct successor to today’s
[ForensicsRiverView.tsx](../../../../apps/desktop/src/features/forensics/ForensicsRiverView.tsx).

Purpose:

- show live execution lanes
- show policy rails and interruptions
- show receipt generation and evidence accumulation
- show directional movement through the hunt

Visual bias:

- horizontal or lane-oriented motion
- active stream emphasis
- policy and approval consequence
- receipt and evidence emergence

### `atlas`

`atlas` is the direct successor to today’s
[CyberNexusView.tsx](../../../../apps/desktop/src/features/cyber-nexus/CyberNexusView.tsx) and
[NexusCanvas.tsx](../../../../apps/desktop/src/features/cyber-nexus/components/NexusCanvas.tsx).

Purpose:

- show the hunt as a stable semantic field
- show station affinity and topology
- show where the hunt is pulling attention next
- show the relationship between targets, watch state, notes/case posture, and run pressure

Visual bias:

- anchored stations
- clear central field
- topology and affinity over streaming motion
- spirit and posture as field weather, not hero objects

### Non-3D Supporting Modes

The larger Huntboard still includes `timeline` and `replay` as subviews from
[surface-map.md](./surface-map.md), but those are not observatory scene modes in v1. They should
open as supporting detail surfaces around the same hunt.

## Station Model

The first-class station taxonomy for the observatory is semantic.

```ts
type HuntStationId =
  | "signal"
  | "targets"
  | "run"
  | "receipts"
  | "case-notes"
  | "watch";

type HuntStationState = {
  id: HuntStationId;
  label: string;
  status: "idle" | "warming" | "active" | "receiving" | "blocked";
  affinity: number; // 0..1, derived from current hunt context
  emphasis: number; // 0..1, scene-local rendering weight
  artifactCount: number;
  hasUnread: boolean;
  reason?: string | null;
};
```

### Station Semantics

| Station | Meaning | Current best substrate |
| --- | --- | --- |
| `signal` | ingress, fresh detections, upstream activity | Forensics entry / scene source, current Wire connection |
| `targets` | entities, scopes, hosts, active subjects | Hunt artifacts + entity rows + target semantics |
| `run` | active execution, mounted files, task posture | OpenClaw runtime + Forensics actions |
| `receipts` | proof, policy outputs, replayable artifacts | River receipts + receipt panels |
| `case-notes` | authored understanding, citations, promoted case memory | notes/case surfaces, spirit rationale carry-through |
| `watch` | watchlists, long-tail observation, persistent attention | watch semantics + triage posture |

### Station Placement Rule

Stations must remain spatially stable across modes. `flow` may bias camera and connective effects,
but the operator should not have to relearn where stations live when switching to `atlas`.

### Current Code Mapping

- current strikecell/state scaffolding:
  [types.ts](../../../../apps/desktop/src/features/cyber-nexus/types.ts)
- current station-like scene IDs in Forensics:
  [ForensicsRiverView.tsx](../../../../apps/desktop/src/features/forensics/ForensicsRiverView.tsx)
- current spirit station affinity logic:
  [runtime.ts](../../../../apps/desktop/src/features/cyber-nexus/scene/spirits/runtime.ts)

## Shared Observatory State

The observatory should not be derived separately in Forensics and Nexus. It needs one shared
state contract that both modes project differently.

```ts
type HuntObservatoryMode = "flow" | "atlas";

type HuntObservatorySelection =
  | { type: "station"; stationId: HuntStationId }
  | { type: "run"; runId: string }
  | { type: "receipt"; receiptId: string }
  | { type: "artifact"; artifactId: string }
  | { type: "entity"; entityId: string }
  | { type: "none" };

type HuntObservatorySceneState = {
  huntId: string;
  mode: HuntObservatoryMode;
  stations: HuntStationState[];
  activeSelection: HuntObservatorySelection;
  likelyStationId: HuntStationId | null;
  roomReceiveState: "idle" | "receiving" | "aftermath";
  spiritFieldBias: number; // 0..1
  confidence: number; // 0..1
  cameraPreset: "overview" | "follow-run" | "focus-station";
  openedDetailSurface: "none" | "tab" | "rail" | "bottom";
};
```

## Shared Actor Contracts

The room should render actor types, not raw feature-specific view data.

### Required Actor Families

```ts
type HuntObservatoryActor =
  | HuntCoreActor
  | HuntStationActor
  | RunFlowActor
  | ReceiptActor
  | EvidenceLinkActor
  | WatchBeaconActor
  | SpiritFieldActor;

type HuntCoreActor = {
  type: "hunt-core";
  huntId: string;
  title: string;
  posture: "triage" | "investigate" | "report";
  centerStrength: number;
};

type HuntStationActor = {
  type: "station";
  stationId: HuntStationId;
  label: string;
  affinity: number;
  emphasis: number;
  status: HuntStationState["status"];
  reason?: string | null;
};

type RunFlowActor = {
  type: "run-flow";
  runId: string;
  status: "queued" | "running" | "blocked" | "completed";
  sourceStationId: HuntStationId;
  targetStationId: HuntStationId;
  intensity: number;
  policyPressure: number;
};

type ReceiptActor = {
  type: "receipt";
  receiptId: string;
  stationId: HuntStationId;
  severity: number;
  freshness: number;
  grouped: boolean;
};

type EvidenceLinkActor = {
  type: "evidence-link";
  sourceId: string;
  targetId: string;
  semantic: "target" | "evidence" | "cite" | "watch" | "run-input";
  strength: number;
};

type WatchBeaconActor = {
  type: "watch-beacon";
  stationId: "watch";
  count: number;
  urgency: number;
};

type SpiritFieldActor = {
  type: "spirit-field";
  kind: "tracker" | "lantern" | "forge" | "loom" | "ledger";
  stance: "watchful" | "focus" | "witness" | "absorb" | "transit";
  likelyStationId: HuntStationId | null;
  emphasis: string[];
  cueKind: "bind" | "focus" | "transit" | "witness" | "absorb" | null;
};
```

### Contract Rules

1. `flow` and `atlas` consume the same actor families.
2. A mode can ignore an actor family visually, but should not invent a separate semantic model.
3. Actor derivation should happen once from hunt + runtime + anticipation state.
4. Spirits remain one actor family among others, not the center of the scene contract.

### Current Code To Reconcile

- current Forensics spirit actor:
  [runtime.ts](../../../../apps/desktop/src/features/forensics/components/hunt-spirit/runtime.ts)
- current Nexus spirit actor:
  [runtime.ts](../../../../apps/desktop/src/features/cyber-nexus/scene/spirits/runtime.ts)
- current Nexus strikecell graph input:
  [types.ts](../../../../apps/desktop/src/features/cyber-nexus/types.ts)

These should be folded into one observatory actor derivation layer rather than extended separately.

## In-Room UI Rules

The room may show only lightweight diegetic UI.

Allowed in-room UI:

- station label or status ring
- one short reason line near the selected or likely station
- one short active-hunt title plate
- one transient receive/aftermath cue
- one short spirit/weather cue

Disallowed in-room UI:

- dense paragraphs
- permanent multi-card side summaries
- heavy filter trays
- receipt metadata tables
- note editor content

## Out-Of-Room Detail Rules

The observatory must cooperate with workbench tabs, the inspector, and the bottom panel.

### Goes To A Workbench Tab

- receipt detail and compare
- note/case authoring
- file content
- spirit configuration
- run logs or authored hunt brief content

### Goes To The Right Rail

- selected station summary
- selected entity/receipt snapshot
- short relationship explanation
- one-click follow/open actions

### Goes To The Bottom Surface

- proof tape
- replay timeline
- command/log stream
- diff/compare strips

The rule is simple: if the operator needs to read, edit, compare, or retain detail, the content
belongs outside the 3D field.

## Interaction Grammar

### Selection

- Clicking a station focuses it and opens only a lightweight diegetic readout.
- Double action or explicit open sends richer detail into a rail or tab.

### Camera

- Camera remains orbit/bounded, not free-roam.
- `flow` may bias toward directional follow.
- `atlas` may bias toward centered overview.
- Recenter returns to a stable hunt overview, not to a cinematic flythrough.

### Hover / Dwell

- Hover warms likely stations and connective links.
- Dwell may reveal a short station reason.
- Hover must never explode into multiple floating cards.

### Drag / Drop

- Dragging a compatible artifact should warm the relevant station(s).
- Dwell over a station can reveal semantic landing meaning.
- Drop consequence should register in-room as a link, pulse, stain, or lane change.

### Open / Detail

- Opening detail should preserve observatory continuity.
- If a receipt or note opens in a tab, the hunt world remains visible as the operator’s spatial
  frame.

## Layout And Camera Constraints

### `flow`

- lane-oriented geometry is primary
- policy rails and causal links remain always legible
- receipts and evidence emerge from flow, not as separate dashboards

### `atlas`

- station relationships and affinities are primary
- graph complexity must be capped to preserve hunt readability
- active/hot stations should be readable at a glance without zooming into every node

### Shared Constraints

- hard DPR caps, matching current `glia-three` practice
- explicit error boundary for WebGL/runtime faults
- reduced-motion fallback for spirit/aftermath cues
- object count limits for non-critical decorative actors

## Migration Strategy

### `OBS-01` Shared observatory contracts

Create a dedicated observatory contract layer for:

- `HuntStationId`
- `HuntStationState`
- `HuntObservatorySceneState`
- shared actor unions

Expected code area:

- `apps/desktop/src/features/hunt-observatory/**` or a dedicated shared scene contract module

### `OBS-02` Shared actor derivation

Refactor current Forensics and Nexus spirit/runtime derivation into one shared pipeline that
produces observatory actors from:

- workbench hunt state
- runtime/OpenClaw state
- anticipation/signals
- spirit state

Expected code touchpoints:

- [ForensicsRiverView.tsx](../../../../apps/desktop/src/features/forensics/ForensicsRiverView.tsx)
- [CyberNexusView.tsx](../../../../apps/desktop/src/features/cyber-nexus/CyberNexusView.tsx)
- current spirit runtime files

### `OBS-03` Flow mode migration

Treat Forensics as the first observatory mode.

Tasks:

- rename or reframe its station vocabulary around the shared taxonomy
- introduce shared station actors into the river field
- reduce screen-edge explanatory HUD in favor of station and lane cues

### `OBS-04` Atlas mode migration

Treat Nexus as the second observatory mode.

Tasks:

- re-map strikecells onto observatory stations and hunt-aware topology
- demote decorative Nexus chrome
- make the scene answer hunt questions instead of module questions

### `OBS-05` Hunt Dock and bucket simplification

Make Hunt Dock and Smart Bucket feed the observatory rather than compete with it.

Tasks:

- reduce copy
- simplify spirit affordances
- treat dock as hunt selector and pulse strip
- make the smart bucket a compact hunt HUD, not a parallel explanation card

### `OBS-06` Detail-surface integration

Complete the observatory split with:

- right-rail detail contract
- bottom proof/replay contract
- workbench tab deep links

## Acceptance Criteria

The Hunt Observatory is ready for a first implementation wave when all of the following are true:

1. One active hunt is represented by one shared observatory scene state.
2. Forensics and Nexus consume the same station taxonomy and actor families.
3. A station can be selected, focused, and opened without losing the hunt field.
4. Dragging or releasing into the hunt produces visible in-room consequence.
5. Dense detail is consistently routed into rails or tabs rather than layered permanently into the
   3D scene.
6. Spirit remains visible as posture and field bias, but no longer behaves like a primary carded
   surface.

## Initial Code Touchpoints

The likely first implementation pass should work primarily in:

- `apps/desktop/src/features/forensics/ForensicsRiverView.tsx`
- `apps/desktop/src/features/forensics/components/**`
- `apps/desktop/src/features/cyber-nexus/CyberNexusView.tsx`
- `apps/desktop/src/features/cyber-nexus/components/NexusCanvas.tsx`
- `apps/desktop/src/features/cyber-nexus/scene/**`
- `apps/desktop/src/shell/workbench/HuntDock.tsx`
- `apps/desktop/src/shell/workbench/anticipation/SmartBucketHeader.tsx`
- a new shared observatory state/actor module

## Reading Order

1. [Hunt Observatory Concept](./hunt-observatory-concept.md)
2. this spec
3. [Surface Map](./surface-map.md)
4. [Current State Review](./current-state.md)
5. follow-on roadmap or swarm-plan doc for implementation
