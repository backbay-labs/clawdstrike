---
phase: 24-space-flight-hud
plan: "01"
subsystem: ui
tags: [react, three.js, r3f, hud, space-flight, rAF, ref-mutation]

# Dependency graph
requires:
  - phase: 21-space-flight-controller
    provides: FlightState/FlightConfig types, useObservatoryStore.flightState, DEFAULT_FLIGHT_CONFIG
  - phase: 22-space-environment-art
    provides: HUNT_STATION_PLACEMENTS, HUNT_STATION_LABELS, STATION_COLORS
  - phase: 23-docking-system
    provides: DockingState, dockingSystem context

provides:
  - camera-bridge.ts: HudCameraBridge R3F component + module-level hudCameraRef for DOM-side camera matrix reads
  - hud-constants.ts: SPEED_TIER_COLORS, STATION_COLORS_HEX, HUD_COLORS, sizing constants shared by all HUD components
  - SpaceFlightHud.tsx: Root HUD overlay shell, opacity-based visibility (always mounted per HUD-06)
  - SpeedIndicator.tsx: Vertical speed bar updating at 60fps via rAF+getState(), zero useState
  - HeadingCompass.tsx: Horizontal compass strip with cardinal markers and station labels at angular positions, rAF+ref-mutation

affects:
  - 24-02: plan 02 reuses camera-bridge hudCameraRef for projection-based target bracket placement
  - observatory-tab: SpaceFlightHud and HudCameraBridge need mounting in ObservatoryTab/ObservatoryWorldCanvas

# Tech tracking
tech-stack:
  added: []
  patterns:
    - "rAF+getState() pattern: 60fps DOM updates via requestAnimationFrame + useObservatoryStore.getState() reads — zero React subscriptions, zero re-renders in frame loop"
    - "opacity-toggle HUD: visible prop controls opacity (0/1) not mount/unmount — keeps DOM nodes alive and rAF loops running"
    - "pre-allocated math objects: THREE.Quaternion/Euler allocated once at module level, mutated via .set()/.setFromQuaternion() in rAF — zero GC pressure in 60fps loop"
    - "HudCameraBridge pattern: R3F useFrame(-100) component writes camera matrices to module-level ref for DOM-side code outside Canvas context"

key-files:
  created:
    - apps/workbench/src/features/observatory/components/hud/camera-bridge.ts
    - apps/workbench/src/features/observatory/components/hud/hud-constants.ts
    - apps/workbench/src/features/observatory/components/hud/SpaceFlightHud.tsx
    - apps/workbench/src/features/observatory/components/hud/SpeedIndicator.tsx
    - apps/workbench/src/features/observatory/components/hud/HeadingCompass.tsx
    - apps/workbench/src/features/observatory/__tests__/space-flight-hud.test.tsx
  modified: []

key-decisions:
  - "rAF+getState() chosen over useSelector for HUD frame loop — zero subscriptions means zero React re-renders during 60fps flight"
  - "opacity:0 visibility toggle instead of conditional render — HUD-06 requirement to keep DOM nodes pre-rendered and avoid rAF teardown on hide"
  - "Module-level pre-allocated THREE.Quaternion/Euler for HeadingCompass yaw extraction — avoids `new` in 60fps loop"
  - "HudCameraBridge uses useFrame priority -100 — runs before render so DOM reads see current-frame camera matrices"
  - "Inner compass strip rendered 3x (0px, 1200px, 2400px) for seamless heading wrapping"
  - "STATION_COLORS_HEX replicated from observatory-world-template.ts (not exported there) — own the constant in hud-constants.ts"

patterns-established:
  - "HUD update pattern: useEffect → rAF loop → getState() read → ref.style mutation → cancelAnimationFrame on cleanup"
  - "Camera bridge pattern: HudCameraBridge (inside Canvas) writes to hudCameraRef; DOM components read hudCameraRef.current directly"

requirements-completed: [HUD-01, HUD-02, HUD-06]

# Metrics
duration: 5min
completed: 2026-03-20
---

# Phase 24 Plan 01: Space Flight HUD Foundation Summary

**DOM overlay HUD with vertical speed bar (rAF+ref, zero useState) + horizontal heading compass (quaternion-to-yaw, pre-allocated math) + camera bridge (useFrame -100, .copy() no-alloc) establishing the 60fps ref-mutation pattern**

## Performance

- **Duration:** ~5 min
- **Started:** 2026-03-20T18:50:01Z
- **Completed:** 2026-03-20T18:54:30Z
- **Tasks:** 2
- **Files modified:** 6

## Accomplishments
- Camera bridge (HudCameraBridge + hudCameraRef) bridges R3F camera matrices to DOM-side code outside the Canvas context using useFrame(-100) with zero allocations
- SpeedIndicator vertical bar fills proportionally to currentSpeed/tierCap with color keyed to speed tier (cruise/boost/dock), updates via rAF+getState()
- HeadingCompass horizontal strip scrolls to ship yaw extracted from quaternion, shows N/E/S/W cardinals and all 6 station labels at their angleDeg positions using pre-allocated THREE objects
- SpaceFlightHud shell uses opacity-toggle (never unmounted) per HUD-06, pointer-events:none throughout
- 10 tests pass covering DOM structure, visibility, cardinals, and all 6 station labels

## Task Commits

1. **Task 1: Camera bridge + HUD constants + SpaceFlightHud shell** - `d7b687ac3` (feat)
2. **Task 2: SpeedIndicator + HeadingCompass with rAF ref-mutation updates** - `4490fa70e` (feat)

## Files Created/Modified
- `apps/workbench/src/features/observatory/components/hud/camera-bridge.ts` - HudCameraBridge R3F component + hudCameraRef module ref
- `apps/workbench/src/features/observatory/components/hud/hud-constants.ts` - SPEED_TIER_COLORS, STATION_COLORS_HEX, HUD_COLORS, sizing constants
- `apps/workbench/src/features/observatory/components/hud/SpaceFlightHud.tsx` - Root HUD overlay shell with opacity-based visibility
- `apps/workbench/src/features/observatory/components/hud/SpeedIndicator.tsx` - Vertical speed bar, rAF loop, zero useState
- `apps/workbench/src/features/observatory/components/hud/HeadingCompass.tsx` - Horizontal compass strip, quaternion yaw extraction, station labels
- `apps/workbench/src/features/observatory/__tests__/space-flight-hud.test.tsx` - 10 unit tests

## Decisions Made
- rAF+getState() chosen over useSelector for HUD frame loop — zero subscriptions means zero React re-renders during 60fps flight
- opacity:0 visibility toggle instead of conditional render — HUD-06 requirement to keep DOM nodes pre-rendered and avoid rAF teardown on hide
- Module-level pre-allocated THREE.Quaternion/Euler for HeadingCompass yaw extraction — avoids `new` in 60fps loop
- HudCameraBridge uses useFrame priority -100 — runs before render so DOM reads see current-frame camera matrices
- Inner compass strip rendered 3x (0px, 1200px, 2400px) for seamless heading wrapping
- STATION_COLORS_HEX replicated from observatory-world-template.ts (not exported there) — own the constant in hud-constants.ts

## Deviations from Plan

None - plan executed exactly as written.

## Issues Encountered
- Test runner needs to be invoked from the `apps/workbench/` directory (not workspace root) for the `@/` alias to resolve correctly. Tests passed when run from `apps/workbench/`.

## User Setup Required

None - no external service configuration required.

## Next Phase Readiness
- Plan 02 can immediately use `hudCameraRef` from camera-bridge.ts for projection-based target bracket placement
- `SpaceFlightHud` needs to be mounted in `ObservatoryTab` or `ObservatoryWorldCanvas` with a `visible` prop tied to flight mode state
- `HudCameraBridge` needs mounting inside the R3F Canvas in `ObservatoryWorldCanvas`

## Self-Check: PASSED

All created files verified present. Both task commits (d7b687ac3, 4490fa70e) verified in git log. 10 tests pass.

---
*Phase: 24-space-flight-hud*
*Completed: 2026-03-20*
