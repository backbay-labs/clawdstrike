---
phase: 23-station-detail-docking
plan: "03"
subsystem: observatory-space-flight
tags: [docking, flight, three-zone, magnet-pull, dock-lock, zustand]
dependency_graph:
  requires: [23-01, 23-02]
  provides: [docking-types, useDockingSystem, useFlightLoop-velRef, dockingState-store]
  affects: [SpaceFlightController, useFlightLoop, observatory-store, observatory-types]
tech_stack:
  added: []
  patterns:
    - three-zone-docking (approach/magnet/dock)
    - easeOutCubic lerp for dock lock sequence
    - additive velocity bias for magnet-pull (mapLinear distance-proportional)
    - ref-forwarding velRef from useFlightLoop for cross-hook velocity mutation
    - flightInputEnabled ref to gate thrust/rotation without re-renders
    - throttled store updates at 100ms via onDockingStateChange callback
key_files:
  created:
    - apps/workbench/src/features/observatory/character/ship/docking-types.ts
    - apps/workbench/src/features/observatory/character/ship/useDockingSystem.ts
  modified:
    - apps/workbench/src/features/observatory/character/ship/useFlightLoop.ts
    - apps/workbench/src/features/observatory/character/ship/SpaceFlightController.tsx
    - apps/workbench/src/features/observatory/types.ts
    - apps/workbench/src/features/observatory/stores/observatory-store.ts
decisions:
  - "DOCKING_CONFIG.approachRadius=180 (outer approach boundary) vs magnetRadius=50 — plan said approach 50-180, magnet 15-50, dock <15"
  - "easeOutCubic chosen for dock lock lerp: fast approach, gentle landing, matches Elite Dangerous auto-dock feel"
  - "velRef returned from useFlightLoop instead of passed as prop — hook callers own the ref, docking system accesses it through SpaceFlightController"
  - "flightInputEnabled gates rotation+thrust blocks only; damping+position update still run so ship decelerates naturally during dock lock"
  - "interactTriggered (E key) cleared by useDockingSystem not useFlightLoop — single consumer of undock intent"
metrics:
  duration: ~7min
  completed_date: "2026-03-20"
  tasks_completed: 2
  files_created: 2
  files_modified: 4
---

# Phase 23 Plan 03: Three-Zone Docking System Summary

**One-liner:** Three-zone docking with mapLinear magnet-pull bias, easeOutCubic 800ms dock lock lerp, and E-key undock push using velRef forwarded from useFlightLoop.

## Tasks Completed

| # | Task | Commit | Files |
|---|------|--------|-------|
| 1 | Docking types + dockingState store slice | 6b44c5da5 | docking-types.ts, types.ts, observatory-store.ts |
| 2 | useDockingSystem hook + flight loop magnet-pull + controller wiring | 2ba15a7c5 | useDockingSystem.ts, useFlightLoop.ts, SpaceFlightController.tsx |

## What Was Built

### docking-types.ts

New file establishing the docking data contract:
- `DockingZone`: `"approach" | "magnet" | "dock" | null`
- `DockingState`: `{ stationId, zone, dockLockStartMs, undockGracePeriodActive }`
- `DOCKING_CONFIG`: all constants (approachRadius=180, magnetRadius=50, dockLockRadius=15, dockLockMaxSpeed=12, magnetPullMaxStrength=0.3, dockLockDurationMs=800, undockPushVelocity=15, undockGracePeriodMs=500)

### dockingState store slice

Added `dockingState: DockingState` field to `ObservatoryState` and `observatory-store.ts`:
- `setDockingState(updater)`: function updater or value updater, same pattern as `setFlightState`
- `resetDockingState()`: resets to `DEFAULT_DOCKING_STATE`

### useDockingSystem.ts

`useFrame`-driven hook managing the full docking lifecycle. All scratch vectors pre-allocated at module level for zero GC pressure. Per-frame logic:

1. **Undock grace period**: clears after 500ms, re-opens dock-lock trigger window
2. **Docked hold**: snaps ship to dock point each frame, zero velocity, listens for E key undock
3. **Dock lock sequence**: easeOutCubic lerp from `dockLockStartPos` to station center over 800ms; zeros velocity during lock; transitions to "dock" zone at completion
4. **Free flight scan**: nearest station in 180-unit approach radius; in magnet zone (15-50u) applies additive velocity bias via `addScaledVector(_pullDir, pullStrength * 60 * dt)`; dock-lock trigger when <15u and speed <12 u/s

### useFlightLoop.ts extensions

- `flightInputEnabled` ref option: when `false`, rotation and thrust blocks are skipped; damping + position update still run
- Returns `UseFlightLoopResult { velRef }` instead of `void` — exposes velocity vector for docking system bias injection
- `interactTriggered` flag no longer consumed here (moved to useDockingSystem)

### SpaceFlightController.tsx wiring

- `flightInputEnabledRef = useRef(true)` with `setFlightInputEnabled` callback
- Destructures `{ velRef }` from `useFlightLoop`
- Mounts `useDockingSystem` with all props wired
- `handleDockingStateChange` calls `useObservatoryStore.getState().actions.setDockingState` (stable, no closure issues)
- `handleStateChange` skips playerFocusRef update when `flightInputEnabledRef.current === false` (docking owns position)

## Deviations from Plan

### Minor clarification applied

**approachRadius: 180 not 50** — The plan listed `approachRadius: 50` in the DOCKING_CONFIG spec but described the approach zone as "50-180 units" in the truths and task description. The magnet zone is 15-50 units and approach is the outer zone beyond that. `approachRadius=180` is used as the outer scan boundary, with `magnetRadius=50` as the magnet zone outer boundary. The DOCKING_CONFIG constant was named to reflect the actual zone boundary rather than duplicating `magnetRadius`.

No architectural changes. All other constants match plan spec exactly.

## Self-Check

Files created/modified:
- [x] `apps/workbench/src/features/observatory/character/ship/docking-types.ts` — FOUND
- [x] `apps/workbench/src/features/observatory/character/ship/useDockingSystem.ts` — FOUND
- [x] `apps/workbench/src/features/observatory/character/ship/useFlightLoop.ts` — FOUND (modified)
- [x] `apps/workbench/src/features/observatory/character/ship/SpaceFlightController.tsx` — FOUND (modified)
- [x] `apps/workbench/src/features/observatory/types.ts` — FOUND (modified)
- [x] `apps/workbench/src/features/observatory/stores/observatory-store.ts` — FOUND (modified)

Commits:
- [x] 6b44c5da5 — feat(23-03): docking types + dockingState store slice
- [x] 2ba15a7c5 — feat(23-03): useDockingSystem hook + flight loop magnet-pull + controller wiring

TypeScript: clean (no errors)

## Self-Check: PASSED
