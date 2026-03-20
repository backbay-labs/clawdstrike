---
phase: 21-flight-controller
plan: "01"
subsystem: ui
tags: [react-three-fiber, three.js, zustand, flight-controller, ship-mesh]

# Dependency graph
requires:
  - phase: 20-spatial-foundation
    provides: "WORLD_RADIUS=300, stationPosition(), HuntStationId type, SpaceStationMesh pattern"
provides:
  - "FlightState, FlightConfig, SpeedTier, FlightIntent types (flight-types.ts)"
  - "DEFAULT_FLIGHT_CONFIG constants (cruiseSpeed:40, boost:3x, damp:1.5)"
  - "SHIP_THRUSTER_LAYOUT (4 nozzle positions for VFX anchoring)"
  - "ShipMesh React component (low-poly geometric ship from Three.js primitives)"
  - "Observatory store flightState slice with setFlightState/resetFlightState actions"
affects: [21-02, 21-03, 21-04, 22-chase-camera, 23-docking, 24-hud]

# Tech tracking
tech-stack:
  added: []
  patterns:
    - "useMemo for R3F geometry/material creation (no re-creation on re-render)"
    - "useRef + useFrame for idle animation (no setState, ref mutation only)"
    - "SHIP_THRUSTER_LAYOUT constant provides nozzle positions for downstream VFX plans"
    - "Observatory Zustand store: flight slice added as flat fields + actions (not nested store)"

key-files:
  created:
    - apps/workbench/src/features/observatory/character/ship/flight-types.ts
    - apps/workbench/src/features/observatory/character/ship/ShipMesh.tsx
  modified:
    - apps/workbench/src/features/observatory/stores/observatory-store.ts
    - apps/workbench/src/features/observatory/types.ts

key-decisions:
  - "SpeedTier: cruise | boost | dock — three distinct speed regimes with type safety"
  - "DEFAULT_FLIGHT_STATE spawns at [0, 80, 200] — safe position near center at moderate elevation"
  - "ShipMesh uses ReactElement return type (not JSX.Element) for workspace TypeScript compat"
  - "SHIP_THRUSTER_LAYOUT is a const (not computed) so Plans 02-04 can import deterministic nozzle positions"
  - "flightState added as flat field in ObservatoryState (not separate store) — stays colocated with other observatory state"

patterns-established:
  - "Ship geometry: ConeGeometry hull (tip at -Z/forward) + SphereGeometry cockpit + BoxGeometry wings + CylinderGeometry nozzles"
  - "Nozzle rotation: CylinderGeometry default +Y axis rotated -90° around X to point +Z (matching nozzleDirection)"
  - "Spirit accent color: applied as emissive on wing struts at 0.3 intensity for subtle personal tint"
  - "toneMapped: false on nozzle material so bloom post-processing picks up emissive at full intensity"

requirements-completed: [FLT-01]

# Metrics
duration: 4min
completed: 2026-03-20
---

# Phase 21 Plan 01: Flight Controller Foundation Summary

**Flight type system (FlightState/FlightConfig/FlightIntent/SpeedTier), DEFAULT_FLIGHT_CONFIG constants, geometric ShipMesh component, and observatory store flight slice establishing all contracts Plans 02-04 implement against**

## Performance

- **Duration:** 4 min
- **Started:** 2026-03-20T16:59:57Z
- **Completed:** 2026-03-20T17:04:11Z
- **Tasks:** 2
- **Files modified:** 4 (2 created, 2 modified)

## Accomplishments
- Flight type contracts established — FlightState, FlightConfig, FlightIntent, SpeedTier, DEFAULT_FLIGHT_CONFIG, DEFAULT_FLIGHT_STATE, SHIP_THRUSTER_LAYOUT all importable by downstream plans
- ShipMesh renders a recognizable low-poly ship from Three.js primitives (ConeGeometry hull, SphereGeometry cockpit, BoxGeometry wings, CylinderGeometry nozzles) with spirit accent color tinting and idle bob animation
- Observatory store flight slice added — flightState initialized from DEFAULT_FLIGHT_STATE, setFlightState/resetFlightState actions available via useObservatoryStore.use.flightState()
- Zero test regressions — all 44 observatory test files pass (209 tests)

## Task Commits

Each task was committed atomically:

1. **Task 1: Flight type contracts + DEFAULT_FLIGHT_CONFIG constants** - `6f0d75a81` (feat)
2. **Task 2: ShipMesh component + observatory-store flight slice** - `d5f00bc0f` (feat)

## Files Created/Modified
- `apps/workbench/src/features/observatory/character/ship/flight-types.ts` - Types, interfaces, constants, factory function (123 lines)
- `apps/workbench/src/features/observatory/character/ship/ShipMesh.tsx` - Geometric low-poly ship component with spirit accent color and idle animation
- `apps/workbench/src/features/observatory/stores/observatory-store.ts` - Added flightState initial value and setFlightState/resetFlightState actions
- `apps/workbench/src/features/observatory/types.ts` - Added FlightState import, flightState field, and action types to ObservatoryState

## Decisions Made
- ShipMesh uses `ReactElement` return type instead of `JSX.Element` — the workspace TypeScript config does not expose the global `JSX` namespace (consistent with districtGeometry.tsx pattern)
- Hull ConeGeometry tip faces -Z (forward) by rotating 90° around X — Three.js cone default is tip at +Y, so `rotation={[Math.PI / 2, 0, 0]}` on the mesh points it forward
- Nozzle CylinderGeometry rotated via memoized Quaternion (not Euler) using `setFromEuler(-PI/2, 0, 0)` — quaternion prop on mesh avoids Euler re-parsing per frame

## Deviations from Plan

**1. [Rule 1 - Bug] Fixed JSX namespace TypeScript error in ShipMesh.tsx**
- **Found during:** Task 2 verification (TypeScript compile check)
- **Issue:** `JSX.Element` return type caused `TS2503: Cannot find namespace 'JSX'` — global JSX namespace not available in this workspace TypeScript config
- **Fix:** Changed return type to `ReactElement` (imported from 'react'), same as districtGeometry.tsx
- **Files modified:** apps/workbench/src/features/observatory/character/ship/ShipMesh.tsx
- **Verification:** `npx tsc --noEmit` exits 0
- **Committed in:** d5f00bc0f (Task 2 commit)

---

**Total deviations:** 1 auto-fixed (Rule 1 - TypeScript bug)
**Impact on plan:** Necessary fix for correct TypeScript compilation. No scope change.

## Issues Encountered
None beyond the JSX namespace fix documented above.

## Next Phase Readiness
- All types exportable by Plans 02-04 — flight-types.ts is complete contract
- ShipMesh ready to be placed in scene once SpaceFlightController (Plan 02) is implemented
- Observatory store queryable via `useObservatoryStore.use.flightState()`
- SHIP_THRUSTER_LAYOUT provides nozzle positions for Plan 04 (thruster VFX)

## Self-Check: PASSED

- FOUND: apps/workbench/src/features/observatory/character/ship/flight-types.ts
- FOUND: apps/workbench/src/features/observatory/character/ship/ShipMesh.tsx
- FOUND: commit 6f0d75a81 (feat(21-01): flight type contracts)
- FOUND: commit d5f00bc0f (feat(21-01): ShipMesh + store flight slice)

---
*Phase: 21-flight-controller*
*Completed: 2026-03-20*
