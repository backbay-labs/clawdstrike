---
phase: 21-flight-controller
plan: "03"
subsystem: observatory/character/ship
tags: [flight, speed-tiers, boost, dock-proximity, physics]
dependency_graph:
  requires: [21-02]
  provides: [FLT-04]
  affects: [observatory-store, SpaceFlightController, FovController]
tech_stack:
  added: []
  patterns:
    - Pre-allocated module-level scratch vectors for GC-free hot path proximity checks
    - Ref-based state machine (no setState) for boost/cooldown tracking at 60Hz
    - Smooth lerp speed transitions instead of hard velocity snaps
key_files:
  created: []
  modified:
    - apps/workbench/src/features/observatory/character/ship/useFlightLoop.ts
decisions:
  - "Boost cooldown timer anchored to boostActivatedAtMs; elapsed >= durationMs + cooldownMs clears it (single ref, no separate cooldown start time)"
  - "Dock zone cancels active boost immediately and sets cooldown to prevent overshooting stations via re-boost"
  - "Speed cap lerp uses dt*5 factor (~0.2s convergence) — smooth deceleration, not frame-rate dependent snap"
  - "findNearestStation is module-level pure function iterating HUNT_STATION_ORDER with pre-allocated _stationPos/_shipPos vectors"
  - "Snapshot throttle reuses nowMs already computed for boost state machine (single performance.now() call per frame)"
metrics:
  duration: ~5m
  completed: "2026-03-20"
  tasks_completed: 1
  tasks_total: 1
  files_changed: 1
---

# Phase 21 Plan 03: Speed Tier System Summary

**One-liner:** Three-tier speed state machine (cruise 40/boost 120/dock 8 u/s) with boost double-tap activation, 2s duration + 4s cooldown, dock proximity cancellation, and smooth lerp transitions.

## What Was Built

Extended `useFlightLoop.ts` with a complete speed tier system. The physics loop now manages three tiers driven by a ref-based state machine that never triggers React re-renders:

- **Cruise (40 u/s):** Default mode. Reached after boost expires or dock zone exit.
- **Boost (120 u/s):** Activated by double-tap W (handled by `useFlightInput`). Lasts 2000ms then enters 4000ms cooldown. Cannot activate during cooldown or in dock zone.
- **Dock (8 u/s):** Auto-applied when within 50 units of any station. Overrides boost (with cooldown penalty). Returns to cruise on exit.

Speed transitions use a smooth lerp (`dt * 5`, ~0.2s convergence) instead of a hard velocity snap, preventing jarring deceleration.

A new module-level `findNearestStation()` helper scans all 6 stations each frame using pre-allocated `_stationPos` / `_shipPos` scratch vectors — zero GC pressure in the hot path.

The store snapshot (`onStateChange`, ~100ms throttle) now carries live `speedTier`, `boostActivatedAtMs`, `boostOnCooldown`, `nearestStationId`, and accurate `currentSpeed`. `SpaceFlightController.tsx` already wired `sprinting: state.speedTier === "boost"` in Plan 02, which drives `FovController` to lerp FOV to 90 during boost.

## Tasks Completed

| Task | Description | Commit |
|------|-------------|--------|
| 1 | Speed tier system — boost activation/cooldown + dock proximity detection | 459de1c72 |

## Deviations from Plan

None — plan executed exactly as written.

## Verification

- TypeScript: `npx tsc --noEmit` exits 0 (clean)
- Tests: 44 observatory test files, 209 tests — all pass

## Self-Check: PASSED

- useFlightLoop.ts: FOUND
- Commit 459de1c72: FOUND
