---
phase: 25-star-chart-transitions
plan: 04
subsystem: ui
tags: [react, three, r3f, observatory, cinematics, proximity-fade, animation]

# Dependency graph
requires:
  - phase: 24-space-flight-hud
    provides: characterControllerEnabled, flyByActive, replay state (guards for arrival card)
  - phase: 23-docking-lod
    provides: StationNpcCrew component, drei Detailed LOD distances for stations
  - phase: 21-space-flight
    provides: flightState.position in observatory-store for proximity detection
provides:
  - Station arrival name card cinematic (StationArrivalCard) in ObservatoryCinematicOverlay.tsx
  - Arrival trigger logic in ObservatoryTab (arrivedStationsRef + 180-unit proximity check)
  - Module-level stationProximityRef updated once per frame by ObservatoryWorldScene
  - StationNpcCrewFade wrapper applying per-frame proximityOpacity to NPC crew
  - computeNpcProximityOpacity and computeDistanceFadeOpacity utility functions
affects: [26-mission-cinematics, future-station-ui-layers]

# Tech tracking
tech-stack:
  added: []
  patterns:
    - Module-level distance ref pattern: stationProximityRef updated in useFrame, read by per-station wrappers via 1% threshold gate
    - State machine phase sequence for multi-step CSS animation without @keyframes
    - StationArrivalCard uses ArrivalCardPhase state machine (bars-in -> name-in -> hold -> name-out -> bars-out -> done)
    - Arrival once-per-session tracking via Set in useRef (arrivedStationsRef)
    - useObservatoryStore.subscribe() for rare event detection (not rAF) in ObservatoryTab

key-files:
  created: []
  modified:
    - apps/workbench/src/features/observatory/components/ObservatoryCinematicOverlay.tsx
    - apps/workbench/src/features/observatory/components/ObservatoryTab.tsx
    - apps/workbench/src/features/observatory/components/ObservatoryWorldCanvas.tsx
    - apps/workbench/src/features/observatory/world/npcCrew.tsx

key-decisions:
  - "StationArrivalCard uses setTimeout-based state machine (bars-in/name-in/hold/name-out/bars-out) instead of @keyframes — simpler to test and control"
  - "arrivedStationsRef uses useRef(new Set<HuntStationId>()) for session state — avoids React state overhead for a rare UI concern"
  - "useObservatoryStore.subscribe() (plain form) used in ObservatoryTab — store doesn't have subscribeWithSelector middleware"
  - "Module-level stationProximityRef avoids prop drilling; StationNpcCrewFade reads it in its own useFrame with 1% threshold to gate setState calls"
  - "computeNpcProximityOpacity: (180 - distance) / 60 clamped 0-1; fade between 120-180 units"
  - "computeDistanceFadeOpacity: (distance - 60) / 120 clamped 0-1; labels fade out at close range"
  - "StationNpcCrew proximityOpacity prop: applies transparent=true + opacity when < 1 to meshStandardMaterial"

patterns-established:
  - "TRN-05 proximity pattern: module-level ref + per-frame update + per-component threshold gate for smooth 3D opacity without subscription overhead"
  - "Session-once UI: useRef(new Set()) tracks shown states without React state to avoid re-renders"

requirements-completed: [TRN-03, TRN-05]

# Metrics
duration: 5min
completed: 2026-03-20
---

# Phase 25 Plan 04: Star Chart Transitions Summary

**Station arrival name card cinematic (TRN-03) with letterbox bars + station-colored name card, plus proximity-based NPC crew opacity fade (TRN-05) via module-level distance ref updated 60fps**

## Performance

- **Duration:** ~5 min
- **Started:** 2026-03-20T19:31:21Z
- **Completed:** 2026-03-20T19:36:32Z
- **Tasks:** 2
- **Files modified:** 4

## Accomplishments

- Station arrival name card: `StationArrivalCard` component in ObservatoryCinematicOverlay plays 2.4s cinematic on first approach within 180 units (letterbox bars slide in, station name fades in station color, holds 1.2s, fades out, bars retract)
- Arrival trigger: ObservatoryTab subscribes to flightState, checks 180-unit distance for all 6 stations, shows card once per session per station, suppressed during fly-by and replay
- Proximity fade: Module-level `stationProximityRef` updated once per frame in ObservatoryWorldScene; `StationNpcCrewFade` wrapper applies NPC opacity (120-180 unit fade range) without subscription overhead

## Task Commits

1. **Task 1: Station arrival name card cinematic** - `5fab24bcb` (feat)
2. **Task 2: Proximity-based detail fade** - `2c735b184` (feat)

## Files Created/Modified

- `apps/workbench/src/features/observatory/components/ObservatoryCinematicOverlay.tsx` - Added `StationArrivalCard` component with phase state machine, HUNT_STATION_LABELS + STATION_COLORS_HEX for name/color display
- `apps/workbench/src/features/observatory/components/ObservatoryTab.tsx` - Added arrivedStationsRef, arrivalStation state, store subscription for proximity detection, StationArrivalCard mount
- `apps/workbench/src/features/observatory/components/ObservatoryWorldCanvas.tsx` - Added stationProximityRef, StationNpcCrewFade component, useFrame proximity update, computeNpcProximityOpacity/computeDistanceFadeOpacity
- `apps/workbench/src/features/observatory/world/npcCrew.tsx` - Added proximityOpacity prop to StationNpcCrew with transparent material support

## Decisions Made

- `StationArrivalCard` uses `setTimeout`-based phase state machine rather than CSS `@keyframes` — easier to test, phases are explicit and controllable
- `arrivedStationsRef` uses `useRef(new Set())` rather than `useState(new Set())` — avoids React re-renders for a once-per-session UI concern
- Plain `useObservatoryStore.subscribe()` used in ObservatoryTab (not `subscribeWithSelector`) because the store doesn't include that Zustand middleware
- Module-level `stationProximityRef` avoids prop drilling to deep 3D components; each `StationNpcCrewFade` reads it in its own `useFrame` with a 1% threshold gate on `setState` to avoid thrashing React at 60fps

## Deviations from Plan

None - plan executed exactly as written.

## Issues Encountered

None.

## Next Phase Readiness

- Station arrival cinematics and proximity fade are fully wired; ready for further polish (sound cues, particle bursts on arrival) in later phases
- `computeDistanceFadeOpacity` is defined and exported but not yet wired to distance labels — available for future use in station label fade-out

---
*Phase: 25-star-chart-transitions*
*Completed: 2026-03-20*
