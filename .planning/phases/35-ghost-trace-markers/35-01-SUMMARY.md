---
phase: 35-ghost-trace-markers
plan: 01
subsystem: ui
tags: [r3f, three, observatory, ghost-traces, holographic-markers, animation]

requires:
  - phase: 34-ghost-memory-ui
    provides: ObservatoryGhostTrace type and observatory-ghost-memory module
  - phase: 26-mission-waypoint-trail
    provides: OBSERVATORY_STATION_POSITIONS from observatory-world-template
provides:
  - GhostTraceLayer R3F component rendering holographic ring+glyph markers per station
  - GhostTraceLayerProps interface (traces, opacityScale)
affects:
  - 35-02-PLAN (wires GhostTraceLayer into ObservatoryWorldCanvas scene tree)

tech-stack:
  added: []
  patterns:
    - opacityScaleRef pattern for live prop sync into useFrame without stale closure
    - useMemo grouping by stationId to avoid per-frame map construction
    - useFrame with zero allocations — mutate refs only, never create THREE objects in loop

key-files:
  created:
    - apps/workbench/src/features/observatory/components/GhostTraceLayer.tsx
    - apps/workbench/src/features/observatory/__tests__/ghost-trace-layer.test.tsx
  modified: []

key-decisions:
  - "JSX toneMapped={false} (not object-literal style) used in meshBasicMaterial — functionally identical"
  - "glyphMatRefs accumulated via mesh ref callback instead of pre-alloc array to avoid stale length issues"
  - "BASE_RING_OPACITY=0.72 constant; multiplied by opacityScale in both initial render and useFrame"

patterns-established:
  - "opacityScaleRef: useRef(prop) + useEffect sync = live prop read in useFrame without triggering re-render"
  - "phaseOffset derived from position tuple to stagger float animations across stations"

requirements-completed: [GHO-01, GHO-02, GHO-04]

duration: 8min
completed: 2026-03-22
---

# Phase 35 Plan 01: Ghost Trace Markers Summary

**GhostTraceLayer R3F component — translucent torus ring + sphere/octahedron glyph markers at observatory station positions using AdditiveBlending and toneMapped=false for bloom compatibility**

## Performance

- **Duration:** 8 min
- **Started:** 2026-03-22T17:02:07Z
- **Completed:** 2026-03-22T17:10:00Z
- **Tasks:** 1 (TDD: RED+GREEN)
- **Files modified:** 2

## Accomplishments

- GhostTraceLayer groups traces by stationId via useMemo, renders one GhostStationMarkers per unique station at exact OBSERVATORY_STATION_POSITIONS coordinates (+1.2 Y elevation offset)
- Each marker renders a torus ring (color #7ad7d0) and per-trace glyphs: sphere (gold #b88f4d) for receipt, octahedron (violet #b49cff) for finding
- Float animation via useFrame: ±0.4 Y over ~3s with station-specific phaseOffset to prevent synchronized bobbing; zero allocations in the loop
- opacityScale prop is synced to opacityScaleRef via useEffect so useFrame always reads the current value without stale closure
- Returns null when traces array is empty — no geometry rendered
- 8/8 tests pass (TDD RED→GREEN)

## Task Commits

1. **Task 1: GhostTraceLayer component** - `ef9ca10f9` (feat + test)

## Files Created/Modified

- `apps/workbench/src/features/observatory/components/GhostTraceLayer.tsx` - R3F component with GhostTraceLayer and GhostTraceLayerProps exports
- `apps/workbench/src/features/observatory/__tests__/ghost-trace-layer.test.tsx` - 8 behavior tests

## Decisions Made

- Used JSX attribute style `toneMapped={false}` (not object literal `toneMapped: false`) — functionally identical in R3F JSX
- glyphMatRefs accumulated via mesh `ref` callback rather than pre-allocated array, to correctly handle dynamic trace counts
- GhostStationMarkers is an internal sub-component (not exported) since it is only used inside GhostTraceLayer

## Deviations from Plan

None - plan executed exactly as written. Test file used `render()` from @testing-library/react (not direct function calls) to provide the React render context required by hooks.

## Issues Encountered

Two test assertions called `GhostTraceLayer({...})` as a plain function (not JSX render), which failed because `useMemo` requires a React render context. Fixed by wrapping in `render(<GhostTraceLayer ... />)` — standard testing-library pattern used throughout the rest of the test suite.

## Next Phase Readiness

- GhostTraceLayer ready to be mounted in ObservatoryWorldScene (Plan 35-02)
- Props interface: `{ traces: ObservatoryGhostTrace[], opacityScale: number }`
- No blocking issues

---
*Phase: 35-ghost-trace-markers*
*Completed: 2026-03-22*
