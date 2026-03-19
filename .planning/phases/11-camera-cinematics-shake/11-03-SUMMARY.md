---
phase: 11-camera-cinematics-shake
plan: 03
subsystem: ui
tags: [react-three-fiber, three.js, camera, animation, mission, zustand]

# Dependency graph
requires:
  - phase: 11-camera-cinematics-shake
    plan: 02
    provides: WorldCameraRig Bezier flight machinery, flyByActive/onFlyByComplete plumbing

provides:
  - missionFocusDwellMs field on ObservatoryCameraRecipe (required, non-optional)
  - deriveCameraRecipe returns 1800ms dwell for atlas+focusStation, 0 otherwise
  - dwellRef dwell suppression in WorldCameraRig (1.8s hold after flight completes)
  - ObservatoryTab wires mission objective stationId as activeStationId (post fly-by guard)
  - Mission start handler increments cameraResetToken to guarantee goalChanged
  - CAM-04 mission focus pull fully implemented

affects:
  - phase 12 (particles — probe dispatch uses mission objective stationId)
  - phase 13 (character controller — mission mode station focus may interact with flow mode camera)

# Tech tracking
tech-stack:
  added: []
  patterns:
    - "dwellRef pattern: useRef<{expiresAt:number}|null> suppresses goal-change flights for a fixed duration after flight completion"
    - "Mission focus guard: flyByActive ? null : missionObjectiveStationId prevents early focus before fly-by completes"
    - "cameraResetToken increment on mission start: ensures goalChanged fires even when desiredPosition is unchanged"

key-files:
  created: []
  modified:
    - apps/workbench/src/features/observatory/world/deriveObservatoryWorld.ts
    - apps/workbench/src/features/observatory/components/ObservatoryWorldCanvas.tsx
    - apps/workbench/src/features/observatory/components/ObservatoryTab.tsx

key-decisions:
  - "missionFocusDwellMs is a required (non-optional) field on ObservatoryCameraRecipe to force all construction sites to declare a value"
  - "Dwell value is 1800ms for atlas+focusStation, 0 for flow mode (player-follow makes dwell non-meaningful in flow)"
  - "isDwelling block uses slow lerp (lerpSpeed*0.4) during hold so camera gently settles rather than snapping"
  - "flyByActive guard on activeStationId prevents mission focus flight from racing with opening fly-by sequence"

patterns-established:
  - "dwellRef: useRef<{expiresAt:number}|null> for timed camera hold suppression post-flight"
  - "Mission focus via activeStationId: derive stationId from getCurrentObservatoryMissionObjective, guard with flyByActive"

requirements-completed: [CAM-04]

# Metrics
duration: 4min
completed: 2026-03-19
---

# Phase 11 Plan 03: Mission Focus Pull Summary

**CAM-04: camera flies to and dwells on mission objective station for 1.8s using dwellRef suppression after Bezier flight completion**

## Performance

- **Duration:** 4 min
- **Started:** 2026-03-19T18:19:59Z
- **Completed:** 2026-03-19T18:24:14Z
- **Tasks:** 2
- **Files modified:** 3

## Accomplishments

- Added `missionFocusDwellMs: number` (required field) to `ObservatoryCameraRecipe` — forces all construction sites to declare a value; `deriveCameraRecipe` returns 1800 for atlas+focusStation, 0 otherwise
- Added `dwellRef` to `WorldCameraRig`: set on flight completion when `missionFocusDwellMs > 0`, suppresses new goal-change flights for 1.8 seconds with a slow soft-lerp hold, cleared after expiry
- `ObservatoryTab` now derives `missionObjectiveStationId` from `getCurrentObservatoryMissionObjective(mission)` and passes it as `activeStationId` (guarded by `flyByActive`); mission start handler also increments `cameraResetToken` to guarantee `goalChanged`

## Task Commits

1. **Task 1: Add missionFocusDwellMs to ObservatoryCameraRecipe + deriveCameraRecipe** - `89f80d2d8` (feat)
2. **Task 2: dwellRef dwell suppression in WorldCameraRig + mission objective activeStationId in ObservatoryTab** - `4611917d1` (feat)

## Files Created/Modified

- `apps/workbench/src/features/observatory/world/deriveObservatoryWorld.ts` - Added `missionFocusDwellMs` to `ObservatoryCameraRecipe` interface; both return branches in `deriveCameraRecipe` now populate the field
- `apps/workbench/src/features/observatory/components/ObservatoryWorldCanvas.tsx` - Added `dwellRef` to `WorldCameraRig`; flight completion sets dwell; `isDwelling` guard suppresses new flights during hold period
- `apps/workbench/src/features/observatory/components/ObservatoryTab.tsx` - Imported `getCurrentObservatoryMissionObjective`; derived `missionObjectiveStationId`; updated `activeStationId` prop with fly-by guard; mission start increments `cameraResetToken`

## Decisions Made

- `missionFocusDwellMs` is a non-optional required field on the interface — this forces all literal construction sites to handle it at compile time rather than silently inheriting `undefined`
- Flow mode gets `missionFocusDwellMs: 0` because in flow mode the camera follows the player character; a station dwell would conflict with character tracking
- The `isDwelling` lerp uses `camera.lerpSpeed * 0.4` (slow) so the camera gently settles on the objective rather than snapping during the hold period
- `flyByActive ? null : missionObjectiveStationId` ensures the opening cinematic fly-by always completes before any mission focus flight launches

## Deviations from Plan

None - plan executed exactly as written.

## Issues Encountered

- Observatory tests (8 files) fail with `document is not defined` — confirmed pre-existing before our changes (same failure count before and after; test environment lacks DOM setup)

## User Setup Required

None - no external service configuration required.

## Next Phase Readiness

- CAM-04 complete; all 4 CAM requirements (CAM-01 through CAM-04) are now addressed
- Phase 11 plan 03 is the final plan in the camera/cinematics/shake phase
- Ready to move to Phase 12 (particles/VFX)

---
*Phase: 11-camera-cinematics-shake*
*Completed: 2026-03-19*
