---
phase: 43-station-interior-zones
plan: "02"
subsystem: observatory-interior
tags: [r3f, camera-transition, interior-zones, station-interior, hud]
dependency_graph:
  requires: ["43-01"]
  provides: ["interior-camera-transition", "exterior-dimmer", "interior-entry-triggers", "exit-button"]
  affects: ["ObservatoryWorldScene", "ObservatoryWorldCanvas", "ObservatoryTab", "ObservatoryStatusStrip"]
tech_stack:
  added: []
  patterns:
    - "useFrame camera lerp with quadratic ease-out (1 - (1-t)^2)"
    - "ExteriorDimmer component — material.opacity traversal via useFrame"
    - "Double-click detection via ref with 400ms window"
    - "OrbitControls constraint manipulation via unknown cast"
key_files:
  created:
    - apps/workbench/src/features/observatory/components/world-canvas/useInteriorCameraTransition.ts
  modified:
    - apps/workbench/src/features/observatory/components/world-canvas/observatory-world-scene-types.ts
    - apps/workbench/src/features/observatory/components/world-canvas/ObservatoryWorldScene.tsx
    - apps/workbench/src/features/observatory/components/ObservatoryWorldCanvas.tsx
    - apps/workbench/src/features/observatory/components/ObservatoryTab.tsx
    - apps/workbench/src/features/observatory/components/hud/ObservatoryStatusStrip.tsx
decisions:
  - "ExteriorDimmer stays mounted at all times — material opacity lerped via useFrame, not unmounted — enables smooth reverse transition"
  - "Escape key handler combined: interior exit takes priority over fly-by skip"
  - "400ms double-click window on ATLAS station click triggers interior entry"
  - "Enter key entry gated on dockingState.zone === dock — reuses existing docking system"
  - "EXIT INTERIOR button styled with reddish accent (#ff8888) to distinguish from blue preset pills"
metrics:
  duration: "468s"
  completed_date: "2026-03-23"
  tasks: 2
  files: 6
---

# Phase 43 Plan 02: Station Interior Wiring Summary

One-liner: 1.2s quadratic-ease-out camera push into station interiors wired end-to-end with exterior dimming, dual entry triggers (double-click/Enter), and EXIT INTERIOR button.

## What Was Built

### Task 1: useInteriorCameraTransition hook + scene types extension

Created `useInteriorCameraTransition.ts` — the core R3F hook that manages smooth camera transitions between exterior observatory and station interiors.

Key implementation:
- `TRANSITION_DURATION = 1.2` seconds
- `INTERIOR_FOV = 50`, `EXTERIOR_FOV = 60` — narrows during entry
- `INTERIOR_NEAR = 0.02` — prevents z-fighting in close-quarters geometry (INTR-06)
- Quadratic ease-out: `t = 1 - (1 - progress) * (1 - progress)`
- Captures exterior camera state (position, controls.target, fov, near) on entry for exact restoration on exit
- Updates OrbitControls constraints on entry: minDistance=3, maxDistance=12, enableRotate=true, enablePan=false
- Restores exterior constraints on exit: enableRotate=false per existing observatory config

Extended `ObservatoryWorldSceneProps` with 4 new optional props: `interiorActive`, `interiorStationId`, `interiorTransitionPhase`, `onInteriorTransitionComplete`.

### Task 2: End-to-end interior wiring (4 files)

**ObservatoryWorldScene.tsx:**
- Added `ExteriorDimmer` helper component — traverses group children each frame, lerps `material.opacity` toward `targetOpacity` at `EXTERIOR_DIM_SPEED = 4`
- Wrapped all exterior layers (ThesisCore, transit, districts, ghost traces, heatmap, presets, constellations, spirit trails, annotation pins) in ExteriorDimmer
- ExteriorDimmer stays mounted at all times — unmounting would prevent smooth reverse transition
- Target opacity: `0.2` when `interiorActive && transitionPhase === "inside"`, else `1.0`
- Mounts `StationInteriorScene` when `interiorActive && interiorStationId && interiorTargetPosition`
- Calls `useInteriorCameraTransition` with station world position from OBSERVATORY_STATION_POSITIONS

**ObservatoryWorldCanvas.tsx:**
- Reads `interiorState` via `useObservatoryStore.use.interiorState()`
- Threads `interiorActive`, `interiorStationId`, `interiorTransitionPhase`, `onInteriorTransitionComplete` to ExtractedObservatoryWorldScene
- `onInteriorTransitionComplete` callback: on `"inside"` → `setInteriorState({ transitionPhase: "inside" })`; on `null` → `clearInterior()`

**ObservatoryTab.tsx:**
- Added `interiorState` and `dockingState` store reads
- `handleEnterInterior(stationId)` — calls `setInteriorState({ active: true, stationId, transitionPhase: "entering" })`
- `handleExitInterior()` — calls `setInteriorState({ transitionPhase: "exiting" })`
- Double-click detection: `lastClickedStationRef` tracks `{ id, time }` — same station within 400ms in ATLAS mode triggers `handleEnterInterior`
- Enter key listener: triggers entry when `mode === "flow"` and `dockingState.zone === "dock"`
- Escape key handler updated: interior exit takes priority over fly-by skip
- Threads `interiorActive` and `onExitInterior` to ObservatoryStatusStrip

**ObservatoryStatusStrip.tsx:**
- Extended `ObservatoryStatusStripProps` with optional `interiorActive` and `onExitInterior`
- Renders "EXIT INTERIOR" button before speed readout when `interiorActive && onExitInterior`
- `data-testid="status-strip-exit-interior"` for test targeting
- Reddish styling: `color: #ff8888`, `background: rgba(255, 100, 100, 0.08)`, `border: 1px solid rgba(255, 100, 100, 0.3)` — visually distinct from blue preset pills

## Deviations from Plan

None - plan executed exactly as written.

## Self-Check

**Files created:**
- [x] apps/workbench/src/features/observatory/components/world-canvas/useInteriorCameraTransition.ts — FOUND
- [x] apps/workbench/src/features/observatory/components/world-canvas/observatory-world-scene-types.ts (modified) — FOUND
- [x] apps/workbench/src/features/observatory/components/world-canvas/ObservatoryWorldScene.tsx (modified) — FOUND
- [x] apps/workbench/src/features/observatory/components/ObservatoryWorldCanvas.tsx (modified) — FOUND
- [x] apps/workbench/src/features/observatory/components/ObservatoryTab.tsx (modified) — FOUND
- [x] apps/workbench/src/features/observatory/components/hud/ObservatoryStatusStrip.tsx (modified) — FOUND

**Commits:**
- 8aa8d4daf — feat(43-02): add useInteriorCameraTransition hook and extend scene types
- 7830114fe — feat(43-02): wire station interior end-to-end — camera, entries, exits, dimmer, status strip

## Self-Check: PASSED
