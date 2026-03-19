---
phase: 03-full-immersive-panes-observatory-forensics
plan: 01
subsystem: ui
tags: [r3f, three, observatory, react-three-fiber, drei, webgl, store-bridge, canvas]

# Dependency graph
requires:
  - phase: 02-r3f-infrastructure-spirit-embeds
    provides: spirit-store (kind/accentColor), useObservatoryStore (stations), separate-Canvas-per-pane ADR, frameloop="demand" pattern
provides:
  - ObservatoryWorldCanvas: R3F Canvas with 6 station spheres at HUNT_STATION_PLACEMENTS positions, WorldCameraRig (bezier flight), drei Text labels, probe ring animation
  - ObservatoryTab: store bridge reading useObservatoryStore.use.stations() + useSpiritStore, renders ObservatoryWorldCanvas at absolute inset-0
  - /observatory route: now points to ObservatoryTab (WebGLSpikeCanvas removed)
  - world/types.ts: HuntObservatoryMode, HuntStationId, HuntStationState, HuntObservatorySceneState
  - world/stations.ts: HUNT_STATION_PLACEMENTS, HUNT_STATION_LABELS, HUNT_STATION_ORDER
  - world/deriveObservatoryWorld.ts: pure function mapping mode+sceneState -> DerivedObservatoryWorld
  - world/probeRuntime.ts: probe state machine (createInitial/dispatch/advance/canDispatch/getCharge/getRemainingMs)
  - world/probeConsequences.ts: applyObservatoryProbeConsequences (mission-system-free)
  - world/grounding.ts: traversal half-extents helpers
  - world/propAssets.ts: hero prop asset manifest (all slot availability — fallback geometry only)
  - FlowModeController: minimal stub satisfying OBS-06 test contract
  - Test scaffolds: observatory-tab, probe-runtime, flow-mode-controller
affects:
  - 03-02-probe-flow-mode: depends on ObservatoryTab setMode/setCharacterControllerEnabled, ObservatoryWorldCanvas frameloop prop
  - 03-03-character-controller: depends on FlowModeController stub, characterControllerEnabled prop in ObservatoryWorldCanvas
  - 04-nexus-full-port: derives from same pattern (Canvas-per-pane, store bridge)

# Tech tracking
tech-stack:
  added: []  # three/r3f/drei already in workbench from Phase 2
  patterns:
    - "ObservatoryTab as Store Bridge: reads workbench stores, builds HuntObservatorySceneState, passes to canvas as props"
    - "WORKBENCH_STATION_IDS fixed set: maps workbench stations to huntronomer HuntStationId by index position"
    - "fallback-geometry-only: all hero props use availability=slot; no useGLTF calls in workbench canvas"
    - "WorldCameraRig: bezier flight path + smoothstep easing, settle orbit on arrival (ported verbatim)"

key-files:
  created:
    - apps/workbench/src/features/observatory/world/types.ts
    - apps/workbench/src/features/observatory/world/stations.ts
    - apps/workbench/src/features/observatory/world/probeRuntime.ts
    - apps/workbench/src/features/observatory/world/probeConsequences.ts
    - apps/workbench/src/features/observatory/world/grounding.ts
    - apps/workbench/src/features/observatory/world/deriveObservatoryWorld.ts
    - apps/workbench/src/features/observatory/world/propAssets.ts
    - apps/workbench/src/features/observatory/components/ObservatoryWorldCanvas.tsx
    - apps/workbench/src/features/observatory/components/ObservatoryTab.tsx
    - apps/workbench/src/features/observatory/components/FlowModeController.tsx
    - apps/workbench/src/features/observatory/__tests__/observatory-tab.test.tsx
    - apps/workbench/src/features/observatory/__tests__/probe-runtime.test.ts
    - apps/workbench/src/features/observatory/__tests__/flow-mode-controller.test.tsx
  modified:
    - apps/workbench/src/components/desktop/workbench-routes.tsx

key-decisions:
  - "probeConsequences.ts adapted: missionLoop dependency removed (missions deferred to OBS-07); buildMissionRead simplified to not accept mission parameter"
  - "ObservatoryWorldCanvas Physics not included in Plan 03-01: Physics wrapping deferred to 03-03 character controller plan (pitfall 1 from RESEARCH.md — Physics always-on adds overhead)"
  - "propAssets.ts all set to availability=slot: GLB assets not in workbench public folder; fallback procedural geometry only in Phase 3 (pitfall 3)"
  - "deriveObservatoryWorld.ts ported verbatim (1793 lines) with only the @/features/hunt-observatory import remapped to local world/types.ts and world/stations.ts"

patterns-established:
  - "ObservatoryTab as Store Bridge: workbench store types converted to huntronomer HuntStationState at component boundary — canvas stays pure"
  - "FlowModeController stub pattern: minimal stub returns null when disabled, satisfies test contract, full impl in later plan"

requirements-completed: [OBS-03]

# Metrics
duration: 9min
completed: 2026-03-18
---

# Phase 3 Plan 1: Observatory World Foundation Summary

**R3F observatory world with 6 station spheres, WorldCameraRig bezier flight, drei Text labels, and store-bridge ObservatoryTab at /observatory route — WebGLSpikeCanvas replaced**

## Performance

- **Duration:** 9 min
- **Started:** 2026-03-18T23:57:56Z
- **Completed:** 2026-03-18T00:07:00Z
- **Tasks:** 3
- **Files modified:** 14

## Accomplishments
- World pure-function layer ported: types, stations, deriveObservatoryWorld (1793 lines), probeRuntime, probeConsequences, grounding, propAssets
- ObservatoryWorldCanvas: R3F Canvas rendering 6 station spheres at HUNT_STATION_PLACEMENTS angular positions, WorldCameraRig (bezier flight + smoothstep), drei Text labels, probe ring animation, CoreNode, Stars, floor grid, lighting
- ObservatoryTab bridges workbench stores to canvas; /observatory route now shows real 3D world instead of WebGLSpikeCanvas placeholder
- All 3 test scaffolds exist; probe-runtime (9 tests) and observatory-tab (4 tests) pass GREEN

## Task Commits

1. **Task 1: Wave 0 test scaffolds** - `5da745f92` (test)
2. **Task 2: World types + probeRuntime** - `14fd5f3df` (feat)
3. **Task 3: ObservatoryWorldCanvas + ObservatoryTab + route swap** - `2532f7621` (feat)

## Files Created/Modified

- `world/types.ts` - HuntObservatoryMode, HuntStationId, HuntStationState, HuntObservatorySceneState (verbatim port)
- `world/stations.ts` - HUNT_STATION_PLACEMENTS (6 entries with angleDeg + radius), HUNT_STATION_LABELS (verbatim port)
- `world/probeRuntime.ts` - probe state machine: createInitial/dispatch/advance/canDispatch/getCharge (verbatim port)
- `world/deriveObservatoryWorld.ts` - pure function mapping mode+sceneState -> DerivedObservatoryWorld (1793 lines, imports remapped)
- `world/probeConsequences.ts` - applyObservatoryProbeConsequences (mission dependency removed)
- `world/grounding.ts` - resolveObservatoryTraversalHalfExtents, shouldAdhereObservatoryPlayerToGround (verbatim port)
- `world/propAssets.ts` - hero prop asset manifest, all availability="slot" (GLB deferred)
- `components/ObservatoryWorldCanvas.tsx` - R3F Canvas: 6 StationSphere, WorldCameraRig, OrbitControls, Stars, ProbeRingEffect, CoreNode, ObservatoryFloor
- `components/ObservatoryTab.tsx` - store bridge: reads stations+kind+accentColor, builds HuntObservatorySceneState, absolute inset-0 wrapper
- `components/FlowModeController.tsx` - minimal stub (returns null when disabled, satisfies test contract)
- `workbench-routes.tsx` - WebGLSpikeCanvas removed, ObservatoryTab at /observatory

## Decisions Made

- probeConsequences.ts missionLoop dependency stripped (missions = OBS-07, deferred). buildMissionRead simplified.
- Physics NOT included in ObservatoryWorldCanvas — deferred to 03-03 character controller plan (pitfall 1: Physics always-on overhead even with no bodies).
- All hero prop assets set to availability="slot" — GLBs not in workbench public folder; fallback procedural geometry is the correct Phase 3 approach.
- deriveObservatoryWorld.ts ported verbatim (1793 lines); only the import paths changed from @/features/hunt-observatory to local world/types.ts + world/stations.ts.

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 1 - Bug] probeConsequences.ts mission import removed**
- **Found during:** Task 2 (world porting)
- **Issue:** probeConsequences.ts imported from missionLoop.ts (explicitly marked DO NOT PORT in RESEARCH.md). Direct port would fail to compile.
- **Fix:** Adapted probeConsequences.ts to remove ObservatoryMissionLoopState parameter from applyObservatoryProbeConsequences. buildMissionRead simplified to not reference mission objectives.
- **Files modified:** apps/workbench/src/features/observatory/world/probeConsequences.ts
- **Verification:** probe-runtime tests pass; probeConsequences.ts compiles
- **Committed in:** 14fd5f3df (Task 2 commit)

---

**Total deviations:** 1 auto-fixed (1 blocking import removal)
**Impact on plan:** Required to compile. Mission system is explicitly deferred to OBS-07. No scope change.

## Issues Encountered

- R3F jsdom warnings in test output (ambientLight casing etc.) — expected behavior when Canvas mock renders R3F scene children in jsdom. Tests pass despite warnings.

## User Setup Required

None - no external service configuration required.

## Next Phase Readiness

- ObservatoryTab is at /observatory and renders 6 station spheres in atlas mode
- `frameloop` prop in ObservatoryWorldCanvas ready for Plan 03-02 probe animation (switch to "always" during active probe)
- `setMode` (via state in ObservatoryTab) ready for Plan 03-02 flow mode toggle button
- `characterControllerEnabled` prop path exists through ObservatoryWorldCanvas for Plan 03-03
- FlowModeController stub ready for Plan 03-03 full Rapier physics implementation
- Remaining pre-existing test failures (32 files) are unrelated to observatory work — no regressions introduced

## Self-Check: PASSED

All created files verified to exist on disk. All task commits verified in git log.

- 11/11 created files: FOUND
- 3/3 task commits: FOUND (5da745f92, 14fd5f3df, 2532f7621)

---
*Phase: 03-full-immersive-panes-observatory-forensics*
*Completed: 2026-03-18*
