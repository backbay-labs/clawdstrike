---
phase: 03-full-immersive-panes-observatory-forensics
plan: 02
subsystem: ui
tags: [r3f, three, observatory, probe, flow-mode, camera-controls, hud, command-palette]

# Dependency graph
requires:
  - phase: 03-01
    provides: ObservatoryTab (store bridge), ObservatoryWorldCanvas (frameloop prop), probeRuntime.ts (state machine), ObservatoryWorldCanvas.tsx
provides:
  - probe-state-machine: ObservatoryProbeState in ObservatoryTab local useState, wired to window event "observatory:probe"
  - frameloop-switching: "always" during active probe (5200ms), "demand" on cooldown/ready
  - ObservatoryProbeHud: HUD overlay (absolute bottom-4 right-4) showing PROBING/cooldown/charge-bar
  - observatory.probe-command: registered in hunt-commands.ts, dispatches CustomEvent "observatory:probe"
  - flow-mode-toggle: ATLAS/FLOW button in ObservatoryTab (absolute top-2 right-2)
  - CameraControls: drei CameraControls in flow mode (OrbitControls in atlas)
  - FogExp2: density 0.04 in flow mode atmosphere
  - FlowModeTerrain: PlaneGeometry 100x100 dark floor in flow mode
  - label-visibility: Text labels hidden in flow mode, visible in atlas
affects:
  - 03-03-character-controller: FlowModeController (Easter-egg) depends on flow mode being active

# Tech tracking
tech-stack:
  added: []  # CameraControls already in @react-three/drei
  patterns:
    - "probe-state-machine: dispatchProbe in ObservatoryTab local state, window CustomEvent 'observatory:probe' bridges command palette to component"
    - "frameloop-switching: setFrameloop('always') on probe dispatch, setFrameloop('demand') in useEffect when status leaves active"
    - "CameraControls-atlas-split: mode==='atlas' renders OrbitControls, mode==='flow' renders CameraControls makeDefault"
    - "FogExp2-flow: fogExp2 attach='fog' replaces linear fog in flow mode"

key-files:
  created:
    - apps/workbench/src/features/observatory/components/ObservatoryProbeHud.tsx
  modified:
    - apps/workbench/src/features/observatory/components/ObservatoryTab.tsx
    - apps/workbench/src/features/observatory/components/ObservatoryWorldCanvas.tsx
    - apps/workbench/src/lib/commands/hunt-commands.ts
    - apps/workbench/src/features/observatory/__tests__/observatory-tab.test.tsx

key-decisions:
  - "ObservatoryWorldCanvas probeState moved to prop (from local useState): probe lifecycle is owned by ObservatoryTab, canvas is a pure renderer"
  - "CameraControls used in flow mode without ref passing to WorldCameraRig: WorldCameraRig still handles the bezier camera lerp on mode change, CameraControls takes over after arrival for user navigation"
  - "ObservatoryProbeHud charge bar is scoped to HUD feedback only (not OBS-08 cooldown timer): distinction noted in component comments"
  - "Labels hidden in flow mode via labelsVisible prop on StationSphere: flow mode is immersive, atlas is overview"

patterns-established:
  - "window CustomEvent bridge: command palette → ObservatoryTab via 'observatory:probe' event (avoids coupling command registry to component refs)"
  - "frameloop-reactive: mode-dependent frameloop controlled by parent (ObservatoryTab) not canvas"
  - "HUD overlay pattern: absolute positioned div sibling to Canvas, pointer-events-none, z-10"

requirements-completed: [OBS-04, OBS-05]

# Metrics
duration: 8min
completed: 2026-03-19
---

# Phase 3 Plan 2: Probe State Machine Integration + Flow Mode Toggle Summary

**Probe state machine with frameloop switching, ObservatoryProbeHud overlay, observatory.probe command (Hunt category), and ATLAS/FLOW mode toggle with CameraControls + FogExp2 + terrain in flow mode**

## Performance

- **Duration:** 8 min
- **Started:** 2026-03-19T00:10:50Z
- **Completed:** 2026-03-19T00:18:00Z
- **Tasks:** 3
- **Files modified:** 5

## Accomplishments

- Probe state machine in ObservatoryTab: `probeState` useState + `frameloop` useState that switches "always" during active probe and "demand" otherwise. `dispatchProbe` callback wired to window CustomEvent "observatory:probe".
- ObservatoryWorldCanvas: `probeState` moved from internal useState to external prop. Accepts probe lifecycle state from parent.
- ObservatoryProbeHud: absolute bottom-4 right-4 HUD overlay. Renders null when ready, shows "PROBING station..." when active, charge bar (green fill, 0-100%) + countdown seconds when cooldown. 100ms setInterval ticks the bar.
- observatory.probe command: registered in hunt-commands.ts under Hunt category, dispatches window CustomEvent "observatory:probe" to trigger probe in active ObservatoryTab.
- Flow mode: ATLAS/FLOW toggle button in top-right corner. CameraControls (drei) replaces OrbitControls in flow mode. FogExp2 (density 0.04, #07090f) adds dense atmosphere. PlaneGeometry 100x100 terrain floor visible in flow mode. Text labels hidden in flow mode (labelsVisible prop on StationSphere).
- Tests: 14 tests all passing (5 existing + 9 new probe/toggle/HUD/command tests).

## Task Commits

1. **Task 1: Probe state machine + frameloop switching** - `c605445aa` (feat)
2. **Task 2: ObservatoryProbeHud + observatory.probe command** - `ab691b0fa` (feat)
3. **Task 3: Flow mode toggle + CameraControls mode switch** - `949729f64` (feat)

## Files Created/Modified

- `components/ObservatoryProbeHud.tsx` - HUD overlay: PROBING text on active, charge bar on cooldown, null on ready
- `components/ObservatoryTab.tsx` - probe state machine (probeState+frameloop useStates), dispatchProbe, window event listener, ATLAS/FLOW toggle button, ObservatoryProbeHud wired
- `components/ObservatoryWorldCanvas.tsx` - probeState as prop (not local state), CameraControls in flow mode, FogExp2 in flow mode, FlowModeTerrain, labels hidden in flow
- `lib/commands/hunt-commands.ts` - observatory.probe command (Hunt category, dispatches CustomEvent)
- `__tests__/observatory-tab.test.tsx` - 9 new tests: probe event listener, toggle button, HUD states (ready/active/cooldown), command registration + dispatch

## Decisions Made

- ObservatoryWorldCanvas `probeState` moved from internal `useState(null)` to external prop: the probe lifecycle is owned by ObservatoryTab (which also owns frameloop switching), so the canvas is a pure renderer receiving state via props. Clean separation.
- CameraControls used in flow mode without connecting to WorldCameraRig ref: WorldCameraRig handles the bezier lerp during the mode transition (camera smoothly moves to flow position), then CameraControls takes over for user navigation. Two separate concerns.
- ObservatoryProbeHud charge bar scoped to OBS-04 probe lifecycle feedback only, not OBS-08 cooldown timer (deferred). Comment in component code makes this distinction clear.
- Labels hidden in flow mode via `labelsVisible` prop: atlas is the "overview" mode where you need labels; flow is immersive "exploration" mode where labels break immersion.

## Deviations from Plan

None — plan executed exactly as written.

## Self-Check: PASSED

All created files verified to exist on disk. All task commits verified in git log.

- 1/1 created files: FOUND (ObservatoryProbeHud.tsx)
- 3/3 task commits: FOUND (c605445aa, ab691b0fa, 949729f64)
