---
phase: 21-flight-controller
plan: "04"
subsystem: ui
tags: [r3f, three.js, wawa-vfx, chase-camera, particle-effects, space-flight]

# Dependency graph
requires:
  - phase: 21-02
    provides: "SpaceFlightController with shipRef, FlightState, SHIP_THRUSTER_LAYOUT"
  - phase: 21-01
    provides: "flight-types.ts type system, DEFAULT_FLIGHT_CONFIG constants"
provides:
  - "ChaseCamera component: lerp-lagged chase camera following ship in local-space offset"
  - "ShipThrusterVFX component: 4-nozzle particle exhaust scaling with thrust intensity"
  - "ship-thruster-exhaust VFX pool registered in ObservatoryVFXPools"
  - "FLT-05 and FLT-06 requirements fulfilled"
affects: [22-space-stations, phase-23-hud, post-flight-polish]

# Tech tracking
tech-stack:
  added: []
  patterns:
    - "Frame-rate independent exponential lerp: alpha = 1 - exp(-k * 60 * dt)"
    - "Chase camera fast-convergence on mount (2.0 factor for 0.8s then 0.07)"
    - "Ship-local offset rotated by ship.quaternion for stable behind+above positioning"
    - "VFX emitter start/stop via wasThrustingRef transition detection"
    - "Nozzle world positions via applyMatrix4(ship.matrixWorld)"

key-files:
  created:
    - apps/workbench/src/features/observatory/character/ship/ChaseCamera.tsx
    - apps/workbench/src/features/observatory/character/ship/ShipThrusterVFX.tsx
  modified:
    - apps/workbench/src/features/observatory/character/ship/SpaceFlightController.tsx
    - apps/workbench/src/features/observatory/vfx/ObservatoryVFXPools.tsx

key-decisions:
  - "Chase camera offset (0,4,14) in ship-local space rotated by ship quaternion — stays behind+above regardless of orientation"
  - "followFactor=0.07 per CONTEXT.md; fast-convergence window of 0.8s at factor=2.0 snaps camera into place on mode switch"
  - "thrustIntensityRef and boostingRef are plain refs not state — no re-renders in 60Hz flight loop"
  - "Nozzle world positions computed via ship.matrixWorld rather than manual quaternion rotation — cleaner and handles parent transforms"
  - "ship-thruster-exhaust pool: 400 particles, StretchBillboard, gravity [0,0.5,0] for slight backward drift"

patterns-established:
  - "ChaseCamera pattern: renders null, only mutates camera each frame via useFrame"
  - "VFX intensity pattern: thrustIntensityRef updated in onStateChange callback, read by sibling component"

requirements-completed: [FLT-05, FLT-06]

# Metrics
duration: 8min
completed: 2026-03-20
---

# Phase 21 Plan 04: Flight Controller — Chase Camera + Thruster VFX Summary

**Lerp-lagged chase camera (offset 0,4,14 ship-local) and 4-nozzle wawa-vfx thruster exhaust scaling from blue cruise trails to bright orange boost plumes**

## Performance

- **Duration:** ~8 min
- **Started:** 2026-03-20T17:18:32Z
- **Completed:** 2026-03-20T17:26:40Z
- **Tasks:** 2
- **Files modified:** 4

## Accomplishments
- ChaseCamera follows ship with frame-rate independent exponential lerp (followFactor=0.07); fast-convergence snap on mode switch
- 4-nozzle ShipThrusterVFX with cruise (6 blue particles) and boost (24 bright orange) modes; idle emits nothing
- ship-thruster-exhaust VFX pool (400 particles, StretchBillboard) registered in ObservatoryVFXPools
- All 209 existing observatory tests pass; TypeScript compiles clean

## Task Commits

Each task was committed atomically:

1. **Task 1: ChaseCamera with lerp-lagged following** - `4a5a76693` (feat)
2. **Task 2: ShipThrusterVFX + VFX pool registration** - `3964bedf1` (feat)

## Files Created/Modified
- `apps/workbench/src/features/observatory/character/ship/ChaseCamera.tsx` - Chase camera component, renders null, mutates camera each frame
- `apps/workbench/src/features/observatory/character/ship/ShipThrusterVFX.tsx` - 4-nozzle thruster exhaust, cruise/boost particle settings
- `apps/workbench/src/features/observatory/character/ship/SpaceFlightController.tsx` - Imports and mounts ChaseCamera + ShipThrusterVFX, thrustIntensityRef/boostingRef tracking
- `apps/workbench/src/features/observatory/vfx/ObservatoryVFXPools.tsx` - ship-thruster-exhaust pool added (400 particles, StretchBillboard)

## Decisions Made
- Used `1 - Math.exp(-k * 60 * dt)` exponential lerp for frame-rate independence — consistent lag at 30fps and 144fps
- Chase camera fast-convergence window: first 0.8s after mount uses factor=2.0 so camera snaps into position when switching from atlas mode, then settles to followFactor=0.07
- thrustIntensityRef/boostingRef are plain refs (not state) — avoids React re-renders in the high-frequency flight loop; values read directly in JSX (not reactive, but VFX reads them imperatively each frame)
- Nozzle world positions via `applyMatrix4(ship.matrixWorld)` rather than manual quaternion math — handles any parent transforms correctly

## Deviations from Plan

None — plan executed exactly as written.

## Issues Encountered

None.

## User Setup Required

None — no external service configuration required.

## Next Phase Readiness

- FLT-05 and FLT-06 complete; all 6 FLT requirements now fulfilled (FLT-01 through FLT-06)
- Phase 21 is complete — all 4 plans done
- Phase 22 (Space Stations) can proceed: ChaseCamera + thruster VFX provide visual feedback for docking approach

---
*Phase: 21-flight-controller*
*Completed: 2026-03-20*
