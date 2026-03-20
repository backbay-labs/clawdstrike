---
phase: 27-flight-state-bridge-autopilot-wiring
plan: "01"
subsystem: observatory-flight
tags: [flight, autopilot, store-bridge, onStateChange, MAP-02, MAP-03]
dependency_graph:
  requires: []
  provides: [store.flightState-live-updates, autopilot-ref-bridge]
  affects: [TRN-01, TRN-02, TRN-03, TRN-04, TRN-05, DSC-02, MAP-02, MAP-03, HUD-01, HUD-02]
tech_stack:
  added: []
  patterns: [zustand-getState-imperative-write, useRef-zero-render-sync, zustand-subscribe-full-state]
key_files:
  created: []
  modified:
    - apps/workbench/src/features/observatory/components/flow-runtime/observatory-player-types.ts
    - apps/workbench/src/features/observatory/components/ObservatoryFlowRuntimeScene.tsx
    - apps/workbench/src/features/observatory/components/ObservatoryWorldCanvas.tsx
    - apps/workbench/src/features/observatory/character/ship/SpaceFlightController.tsx
decisions:
  - "[27-01]: handleFlightStateChange uses getState().actions.setFlightState (imperative write) — 60fps callback must not cause React re-renders"
  - "[27-01]: autopilotRef uses zustand v5 full-state subscribe (not selector-subscribe) — store created without subscribeWithSelector middleware"
  - "[27-01]: autopilotRef initialized synchronously from getState() then subscribed — avoids race on first frame before effect runs"
metrics:
  duration: ~7min
  completed_date: "2026-03-20"
  tasks_completed: 2
  files_modified: 4
---

# Phase 27 Plan 01: Flight State Bridge + Autopilot Wiring Summary

**One-liner:** Live FlightState store bridge via onStateChange prop chain + autopilot ref sync from store.autopilotTargetStationId to useFlightLoop.

## What Was Built

Two cross-phase integration gaps identified by the v6.0 milestone audit are now closed:

### Task 1: FlightState Store Bridge (onStateChange prop chain)

Wired `onStateChange` from `ObservatoryWorldCanvas` through `ObservatoryFlowRuntimeScene` to `SpaceFlightController` (which already forwarded it to `useFlightLoop`). The missing links were:

1. `observatory-player-types.ts` — Added `onStateChange?: (state: FlightState) => void` to `ObservatoryFlowRuntimeSceneProps` (alphabetically between `onInteractProp` and `onWorldStateChange`), with the required `import type { FlightState }` from flight-types.

2. `ObservatoryFlowRuntimeScene.tsx` — Destructured `onStateChange` and forwarded it as a prop to `LazySpaceFlightController`.

3. `ObservatoryWorldCanvas.tsx` — Added `handleFlightStateChange` callback using `useObservatoryStore.getState().actions.setFlightState(state)` (imperative write via `getState()` — zero React re-renders in the 60fps callback). Passed it as `onStateChange={handleFlightStateChange}` on the `<LazyObservatoryFlowRuntimeScene>` JSX element.

`store.flightState` now receives live position/quaternion/speedTier/currentSpeed at ~100ms intervals, restoring runtime functionality for 9 downstream requirements (TRN-01..05, DSC-02, MAP-02, HUD-01, HUD-02).

### Task 2: Autopilot Ref Bridge (store.autopilotTargetStationId -> useFlightLoop)

Updated `SpaceFlightController.tsx` to create and sync an `autopilotRef` consumed by `useFlightLoop`:

1. Added `import type { HuntStationId }` from world/types.
2. Created `autopilotRef = useRef<HuntStationId | null>(null)`.
3. Added `useEffect` with `useObservatoryStore.subscribe((state) => { autopilotRef.current = state.autopilotTargetStationId; })` — full-state subscription (Zustand v5 without subscribeWithSelector middleware). Initialized synchronously from `getState()` to avoid race on first frame.
4. Added `handleAutopilotCancel = useCallback(() => { useObservatoryStore.getState().actions.clearAutopilot(); }, [])`.
5. Passed `autopilotRef` and `onAutopilotCancel: handleAutopilotCancel` to `useFlightLoop`.

`useFlightLoop` already handles all autopilot slerp logic internally. Star chart click → `setAutopilotTarget` → `autopilotRef.current` → `useFlightLoop` slerp → ship flies to station. WASD/mouse input fires `onAutopilotCancel` → `clearAutopilot()` → store cleared. MAP-03 fully functional.

## Commits

| Task | Commit | Description |
|------|--------|-------------|
| 1 | f01fd620e | feat(27-01): wire FlightState store bridge via onStateChange prop chain |
| 2 | 09382c8ff | feat(27-01): wire autopilot ref bridge (store.autopilotTargetStationId -> useFlightLoop) |

## Decisions Made

- `handleFlightStateChange` uses `getState().actions.setFlightState` (imperative write) — 60fps callbacks must not trigger React re-renders via selector subscriptions.
- Autopilot sync uses Zustand v5 full-state `subscribe((state) => ...)` pattern since the store was created with plain `create()` without `subscribeWithSelector` middleware.
- `autopilotRef.current` initialized from `getState()` synchronously before the subscription fires — prevents first-frame gap where the ref would be `null` even if autopilot was already active.

## Deviations from Plan

None — plan executed exactly as written.

## Verification

- TypeScript compilation passes (only 2 pre-existing errors in test fixtures unrelated to flight/autopilot).
- All observatory and flight-related tests pass.
- Grep checks confirm all artifacts are present: `onStateChange` chain, `handleFlightStateChange`, `autopilotRef`, `handleAutopilotCancel`.

## Self-Check: PASSED

Files exist:
- FOUND: apps/workbench/src/features/observatory/components/flow-runtime/observatory-player-types.ts
- FOUND: apps/workbench/src/features/observatory/components/ObservatoryFlowRuntimeScene.tsx
- FOUND: apps/workbench/src/features/observatory/components/ObservatoryWorldCanvas.tsx
- FOUND: apps/workbench/src/features/observatory/character/ship/SpaceFlightController.tsx

Commits exist:
- FOUND: f01fd620e
- FOUND: 09382c8ff
