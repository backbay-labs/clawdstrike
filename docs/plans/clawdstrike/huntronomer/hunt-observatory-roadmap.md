# Hunt Observatory Roadmap

> **Status:** Proposed
> **Date:** 2026-03-09
> **Audience:** Product, design, desktop, workbench, and 3D/runtime implementers
> **Scope:** Turn the Hunt Observatory spec into executable implementation phases and ticket slices

## Why This Exists

The concept and spec are now specific enough that the missing artifact is delivery structure.

This roadmap translates [Hunt Observatory Spec](./hunt-observatory-spec.md) into:

- phased implementation goals
- ticketable work slices
- dependencies
- concrete code touchpoints
- exit criteria for each phase

## Current-State Read

The observatory already has strong building blocks, but they are still split across separate
feature trees and separate semantic models.

### What exists

- [ForensicsRiverView.tsx](../../../../apps/desktop/src/features/forensics/ForensicsRiverView.tsx)
  already carries the richest live-flow grammar in the desktop app.
- [CyberNexusView.tsx](../../../../apps/desktop/src/features/cyber-nexus/CyberNexusView.tsx) and
  [NexusCanvas.tsx](../../../../apps/desktop/src/features/cyber-nexus/components/NexusCanvas.tsx)
  already provide a real 3D station/topology substrate.
- [HuntDock.tsx](../../../../apps/desktop/src/shell/workbench/HuntDock.tsx) and
  [SmartBucketHeader.tsx](../../../../apps/desktop/src/shell/workbench/anticipation/SmartBucketHeader.tsx)
  already hold the active-hunt entry and summary seams.
- Spirit runtime and room-consequence logic already exist in both Forensics and Nexus.

### What is missing

- there is no shared observatory contract for stations, scene state, or actor families
- Forensics and Nexus still derive scene meaning separately
- Hunt Dock and Smart Bucket still behave like parallel control surfaces instead of observatory seams
- detail routing rules between room, tabs, rail, and bottom surfaces are not formalized
- the current room still carries too much duplicated explanatory chrome

## Program Principles

- One active hunt should feel like one world.
- `flow` and `atlas` are two modes of one observatory, not separate products.
- Shared contracts land before scene polish.
- The room should grow more useful before it grows more theatrical.
- Dense detail belongs in tabs and rails, not permanently inside the scene.
- Dock and bucket should feed the observatory, not compete with it.

## Delivery Phases

| Phase | Goal | Exit Criteria |
| --- | --- | --- |
| `P0` | Observatory contract spine | Shared station, scene-state, and actor contracts exist |
| `P1` | Shared actor derivation | Forensics and Nexus derive from one observatory model |
| `P2` | Flow mode migration | Forensics reads as observatory `flow`, not a separate module |
| `P3` | Atlas mode migration | Nexus reads as observatory `atlas`, not a separate module |
| `P4` | Hunt shell integration | Hunt Dock and Smart Bucket become compact observatory seams |
| `P5` | Detail-surface integration | Room, tabs, right rail, and bottom surfaces follow one observatory contract |
| `P6` | Hardening and dogfood | Verification, performance, and operator dogfood are green |

## Ticket Breakdown

## Phase P0: Observatory Contract Spine

### `OBS-P0-01` Station taxonomy and placement contract

- Create a dedicated observatory module for:
  - `HuntStationId`
  - `HuntStationState`
  - station placement metadata
  - semantic mapping from current hunt/runtime state into stations
- Make this the single source of truth for station IDs instead of keeping Nexus strikecells and
  Forensics station-like identifiers separate.

Primary paths:

- `apps/desktop/src/features/hunt-observatory/**` (new)
- `apps/desktop/src/features/cyber-nexus/types.ts`

Dependencies:

- none

### `OBS-P0-02` Shared scene-state contract

- Add `HuntObservatorySceneState` and selection/camera/detail-surface contracts.
- Keep it intentionally scene-facing rather than reducer-facing at first.

Primary paths:

- `apps/desktop/src/features/hunt-observatory/**`

Dependencies:

- `OBS-P0-01`

### `OBS-P0-03` Shared actor-family contract

- Add shared actor unions for:
  - hunt core
  - stations
  - runs
  - receipts
  - evidence links
  - watch beacons
  - spirit field
- Map current feature-local scene actor shapes onto the new shared contract.

Primary paths:

- `apps/desktop/src/features/hunt-observatory/**`
- `apps/desktop/src/features/forensics/components/hunt-spirit/runtime.ts`
- `apps/desktop/src/features/cyber-nexus/scene/spirits/runtime.ts`

Dependencies:

- `OBS-P0-02`

## Phase P1: Shared Actor Derivation

### `OBS-P1-01` Shared observatory selectors

- Build one derivation layer that turns:
  - workbench hunt state
  - runtime/OpenClaw state
  - anticipation state
  - spirit state
  into the shared observatory scene model.

Primary paths:

- `apps/desktop/src/features/hunt-observatory/selectors/**` (new)
- `apps/desktop/src/shell/workbench/spirit/**`

Dependencies:

- `OBS-P0-01`
- `OBS-P0-02`
- `OBS-P0-03`

### `OBS-P1-02` Forensics adapter

- Replace the feature-local Forensics actor derivation path with an adapter onto the shared
  observatory selectors.

Primary paths:

- `apps/desktop/src/features/forensics/ForensicsRiverView.tsx`
- `apps/desktop/src/features/forensics/components/**`

Dependencies:

- `OBS-P1-01`

### `OBS-P1-03` Nexus adapter

- Replace the feature-local Nexus actor derivation path with an adapter onto the shared
  observatory selectors.

Primary paths:

- `apps/desktop/src/features/cyber-nexus/CyberNexusView.tsx`
- `apps/desktop/src/features/cyber-nexus/components/NexusCanvas.tsx`
- `apps/desktop/src/features/cyber-nexus/scene/**`

Dependencies:

- `OBS-P1-01`

## Phase P2: Flow Mode Migration

### `OBS-P2-01` Reframe Forensics as observatory `flow`

- Reduce module-specific copy and control chrome in the current Forensics scene.
- Make the mode legible in terms of stations, lanes, receipts, and policy pressure.

Primary paths:

- `apps/desktop/src/features/forensics/ForensicsRiverView.tsx`

Dependencies:

- `OBS-P1-02`

### `OBS-P2-02` Station-aware lane cues

- Add station cues and station-bound readouts to Forensics.
- Connect run and receipt flow to the shared station taxonomy.

Primary paths:

- `apps/desktop/src/features/forensics/ForensicsRiverView.tsx`
- `apps/desktop/src/features/forensics/components/**`

Dependencies:

- `OBS-P2-01`

### `OBS-P2-03` Flow-mode detail boundaries

- Strip dense explanatory HUD from the room.
- Keep only lightweight in-room readouts and route richer detail outward.

Primary paths:

- `apps/desktop/src/features/forensics/ForensicsRiverView.tsx`
- `apps/desktop/src/features/forensics/components/**`

Dependencies:

- `OBS-P2-01`

## Phase P3: Atlas Mode Migration

### `OBS-P3-01` Reframe Nexus as observatory `atlas`

- Demote current Nexus module language and recast the scene as a stable observatory field.
- Preserve the strongest current topology affordances.

Primary paths:

- `apps/desktop/src/features/cyber-nexus/CyberNexusView.tsx`
- `apps/desktop/src/features/cyber-nexus/components/NexusControlStrip.tsx`
- `apps/desktop/src/features/cyber-nexus/components/NexusCanvas.tsx`

Dependencies:

- `OBS-P1-03`

### `OBS-P3-02` Station silhouettes and affinities

- Replace or reinterpret current strikecell emphasis using the observatory station taxonomy.
- Make affinity and likely-next pressure legible at a glance.

Primary paths:

- `apps/desktop/src/features/cyber-nexus/components/NexusCanvas.tsx`
- `apps/desktop/src/features/cyber-nexus/scene/**`

Dependencies:

- `OBS-P3-01`

### `OBS-P3-03` Atlas-mode diegetic readouts

- Add or refine small world-anchored readouts for selected/likely stations.
- Keep all dense detail out of the scene.

Primary paths:

- `apps/desktop/src/features/cyber-nexus/components/NexusCanvas.tsx`
- `apps/desktop/src/features/cyber-nexus/components/**`

Dependencies:

- `OBS-P3-01`

## Phase P4: Hunt Shell Integration

### `OBS-P4-01` Hunt Dock simplification

- Turn Hunt Dock into hunt selector + state pulse rather than a parallel explanation surface.
- Keep spirit present, but quiet.

Primary paths:

- `apps/desktop/src/shell/workbench/HuntDock.tsx`

Dependencies:

- `OBS-P2-01`
- `OBS-P3-01`

### `OBS-P4-02` Smart Bucket as compact hunt HUD

- Make the smart bucket a compact summary and entry seam into the observatory.
- Reduce duplicated intent and state prose.

Primary paths:

- `apps/desktop/src/shell/workbench/anticipation/SmartBucketHeader.tsx`

Dependencies:

- `OBS-P4-01`

### `OBS-P4-03` Observatory entry and mode-switch rules

- Define how the operator enters `flow` vs `atlas`.
- Make mode switching feel like viewpoint change inside one hunt world.

Primary paths:

- `apps/desktop/src/shell/workbench/**`
- `apps/desktop/src/features/forensics/**`
- `apps/desktop/src/features/cyber-nexus/**`

Dependencies:

- `OBS-P2-01`
- `OBS-P3-01`

## Phase P5: Detail-Surface Integration

### `OBS-P5-01` Right-rail observatory detail contract

- Define exactly what selected-room detail may appear in the right rail.
- Ensure station/entity/receipt detail opens consistently.

Primary paths:

- `apps/desktop/src/shell/workbench/ContextInspector.tsx`
- `apps/desktop/src/features/cyber-nexus/components/NexusDetailPanel.tsx`
- `apps/desktop/src/features/hunt-observatory/**`

Dependencies:

- `OBS-P2-03`
- `OBS-P3-03`

### `OBS-P5-02` Bottom proof/replay contract

- Route proof tape, replay, and command/log surfaces consistently beneath the room.
- Remove scene-local duplicated proof cards where they exist.

Primary paths:

- `apps/desktop/src/shell/workbench/BottomPanel.tsx`
- related proof/replay components

Dependencies:

- `OBS-P5-01`

### `OBS-P5-03` Workbench tab integration

- Define which observatory interactions open editor/workbench tabs.
- Keep room continuity visible while tabs carry dense detail.

Primary paths:

- `apps/desktop/src/shell/workbench/workbenchState.ts`
- `apps/desktop/src/shell/workbench/tabRegistry.ts`
- related tab renderer surfaces

Dependencies:

- `OBS-P5-01`

## Phase P6: Hardening And Dogfood

### `OBS-P6-01` Performance and rendering hardening

- Add or refine:
  - WebGL error boundaries
  - DPR caps
  - reduced-motion paths
  - actor-count limits

Primary paths:

- observatory scene files
- `glia-three` integration seams

Dependencies:

- `OBS-P2-01`
- `OBS-P3-01`

### `OBS-P6-02` Verification and smoke coverage

- Add focused tests and smoke assertions for:
  - mode switching
  - station focus
  - room consequence
  - detail opening without losing field continuity

Primary paths:

- observatory tests
- `scripts/huntronomer-playwright-smoke.sh`

Dependencies:

- `OBS-P5-03`

### `OBS-P6-03` Dogfood and polish pass

- Run live browser/native dogfood.
- Cut residual ornamental HUD, dead copy, and redundant scene chrome.

Primary paths:

- all observatory-facing surfaces
- dogfood docs

Dependencies:

- `OBS-P6-02`

## Delivery Order

1. `P0` contracts
2. `P1` shared derivation
3. `P2` flow mode
4. `P3` atlas mode
5. `P4` hunt-shell simplification
6. `P5` detail integration
7. `P6` hardening

## Acceptance Gate

The roadmap is complete only when:

- `flow` and `atlas` behave like one active-hunt world
- shared station taxonomy is real in both modes
- dense detail is consistently pushed into tabs/rails/bottom surfaces
- Hunt Dock and Smart Bucket no longer compete with the room
- the observatory is more useful than the current separate surfaces
- verification and dogfood pass on one clean run
