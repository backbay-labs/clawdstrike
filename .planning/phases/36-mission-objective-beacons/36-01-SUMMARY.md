---
phase: 36-mission-objective-beacons
plan: 01
subsystem: ui
tags: [r3f, three.js, observatory, mission, beacons, animation]

# Dependency graph
requires:
  - phase: 26-mission-waypoint-trail
    provides: MissionWaypointTrail pattern for emissive mission-linked R3F components
  - phase: 35-ghost-trace-markers
    provides: ObservatoryGhostLayer AdditiveBlending + emissive pattern
provides:
  - MissionObjectiveBeacons.tsx R3F component with shouldShowBeacons + getBeaconStations helpers
  - Per-objective emissive CylinderGeometry beacon columns (180u tall, tapered)
  - Active beacon sin-oscillated emissiveIntensity + opacity (~2s cycle via π multiplier)
  - Completed beacon static desaturated glow via offsetHSL(0,-0.7,0) at opacity 0.25
  - 6 unit tests covering all MSN-01–04 requirements
affects:
  - 36-02 (mounts MissionObjectiveBeacons in ObservatoryWorldCanvas)

# Tech tracking
tech-stack:
  added: []
  patterns:
    - Pure helper functions (shouldShowBeacons, getBeaconStations) exported for unit-testability
    - Pre-allocated materialRef at component level — no allocations in useFrame
    - AdditiveBlending + depthWrite:false + toneMapped:false for fog-piercing emissive visibility

key-files:
  created:
    - apps/workbench/src/features/observatory/components/MissionObjectiveBeacons.tsx
    - apps/workbench/src/features/observatory/__tests__/mission-objective-beacons.test.ts
  modified: []

key-decisions:
  - "MissionObjectiveBeacons is fully self-contained and prop-driven — reads nothing from store, accepts mission prop only (MSN-04 enforced at top level with shouldShowBeacons null check)"
  - "Sin oscillation uses Math.PI multiplier for ~2s cycle; emissiveIntensity range 1.2-2.8 (center 2.0 ± 0.8)"
  - "getBeaconStations returns only stations present in mission.objectives — no phantom beacons for stations without objectives in current mission"

patterns-established:
  - "Phase 36: Export pure beacon-state helpers from R3F component for pure-function unit tests without rendering"

requirements-completed: [MSN-01, MSN-02, MSN-03, MSN-04]

# Metrics
duration: 3min
completed: 2026-03-22
---

# Phase 36 Plan 01: Mission Objective Beacons Component Summary

**Self-contained R3F MissionObjectiveBeacons component with AdditiveBlending emissive CylinderGeometry columns — active station pulses via sin oscillation, completed stations show offsetHSL desaturation, null mission returns null**

## Performance

- **Duration:** 3 min
- **Started:** 2026-03-22T17:12:01Z
- **Completed:** 2026-03-22T17:14:05Z
- **Tasks:** 2 (TDD: RED + GREEN)
- **Files modified:** 2

## Accomplishments
- MissionObjectiveBeacons.tsx component with correct beacon column geometry and animation
- shouldShowBeacons + getBeaconStations pure helpers enabling isolated unit tests
- 6 vitest unit tests covering all MSN-01 through MSN-04 requirements
- TypeScript compiles without errors

## Task Commits

Each task was committed atomically:

1. **Tasks 1+2: MissionObjectiveBeacons component + unit tests** - `08fbd0a15` (feat)

## Files Created/Modified
- `apps/workbench/src/features/observatory/components/MissionObjectiveBeacons.tsx` - R3F component: emissive beacon columns at mission objective stations, active pulses, completed desaturated
- `apps/workbench/src/features/observatory/__tests__/mission-objective-beacons.test.ts` - 6 unit tests for shouldShowBeacons and getBeaconStations pure helpers

## Decisions Made
- Exported pure helpers (shouldShowBeacons, getBeaconStations) from component file so unit tests require no R3F rendering setup
- Pre-allocated `materialRef` at component level (no `useRef` inside useFrame callback) following observatory performance patterns
- Sin cycle uses `Math.PI` multiplier on `clock.elapsedTime` for a ~2-second period matching MSN-02 spec

## Deviations from Plan

None - plan executed exactly as written.

## Issues Encountered
None

## User Setup Required
None - no external service configuration required.

## Next Phase Readiness
- MissionObjectiveBeacons.tsx is ready to mount in ObservatoryWorldCanvas (Plan 36-02)
- Import path: `./MissionObjectiveBeacons` from ObservatoryWorldCanvas.tsx location
- No blockers

---
*Phase: 36-mission-objective-beacons*
*Completed: 2026-03-22*
