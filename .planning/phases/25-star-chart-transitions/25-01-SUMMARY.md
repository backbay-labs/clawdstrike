---
phase: 25-star-chart-transitions
plan: 01
subsystem: ui
tags: [react, svg, three, zustand, observatory, minimap, star-chart, raf]

# Dependency graph
requires:
  - phase: 24-space-flight-hud
    provides: STATION_COLORS_HEX, HUD_COLORS, rAF+getState() pattern, THREE.Quaternion/Euler yaw extraction
  - phase: 20-spatial-foundation
    provides: OBSERVATORY_STATION_POSITIONS (real XZ world coordinates for all 6 stations)
  - phase: 23-docking-system
    provides: DockingState (zone, stationId) for docked status icon
  - phase: 21-space-flight
    provides: FlightState (position, quaternion) for player arrow

provides:
  - Star chart minimap in observatory-minimap-panel sidebar slot
  - worldToChart(worldX, worldZ) pure function (exported, tested)
  - Station dots at real XZ world positions with station-colored fills
  - 4 LANE_PAIRS SVG line connections (signal-targets, targets-run, run-receipts, receipts-case-notes)
  - Per-station status icons: docked=diamond, mission=asterisk(*), unvisited=ring
  - Player arrow at ship XZ position rotated by yaw — 60fps via rAF + getState(), zero React re-renders

affects:
  - 25-02 (flight path trail — reads player position from same rAF pattern)
  - 25-03 (click-to-autopilot — replaces onClick with autopilot dispatch)
  - Any phase that uses observatory-minimap-panel tests as a reference

# Tech tracking
tech-stack:
  added: []
  patterns:
    - "worldToChart: pure XZ→SVG coordinate mapping, exported for unit testing"
    - "rAF + useObservatoryStore.getState() for zero-re-render DOM mutation on player arrow"
    - "Pre-allocated THREE.Quaternion + THREE.Euler at module level (zero GC in rAF loop)"
    - "data-station-id / data-status / data-testid attributes for targeted test selection"

key-files:
  created: []
  modified:
    - apps/workbench/src/features/observatory/panels/observatory-minimap-panel.tsx
    - apps/workbench/src/features/observatory/__tests__/observatory-minimap.test.tsx

key-decisions:
  - "worldToChart uses dynamic bounds from all station positions + 15% padding, not hardcoded scale"
  - "SVG Y-axis inversion: positive world Z → smaller SVG Y (map north = up convention)"
  - "DockingState uses zone==='dock' (not phase==='docked') — actual field name in docking-types.ts"
  - "visitedStations is a module-level Set — persists across renders, cleared only on module reload"
  - "Lane lines use data-testid='lane-{from}-{to}' for reliable test targeting"
  - "Player arrow initial position is chart center; rAF tick moves it to actual ship XZ on first frame"

patterns-established:
  - "worldToChart pattern: compute WORLD_HALF_EXTENT from all positions, scale CHART_RADIUS / WORLD_HALF_EXTENT"
  - "SVG status icons: data-status attribute distinguishes docked/mission/unvisited for tests"
  - "Mock OBSERVATORY_STATION_POSITIONS in tests with explicit tuple values to avoid THREE.CatmullRomCurve3 chain"

requirements-completed: [MAP-01, MAP-04]

# Metrics
duration: 3min
completed: 2026-03-20
---

# Phase 25 Plan 01: Star Chart Minimap Summary

**SVG star chart replacing polar ring minimap: station dots at real XZ world coordinates, lane topology lines, per-station status icons (docked/mission/unvisited), and rAF-driven player arrow at 60fps with zero React re-renders**

## Performance

- **Duration:** ~3 min
- **Started:** 2026-03-20T19:30:56Z
- **Completed:** 2026-03-20T19:33:41Z
- **Tasks:** 2
- **Files modified:** 2

## Accomplishments
- Replaced polar SVG ring minimap with tactical star chart using real XZ world coordinates
- Exported `worldToChart()` pure coordinate mapping function with dynamic bounds scaling
- Player arrow tracks ship position and heading at 60fps via rAF + getState() — zero React re-renders
- 4 lane connection lines showing station topology; 3 per-station status icon types
- 23 test cases covering coordinate mapping, station colors, lanes, click routing, and status icons

## Task Commits

Each task was committed atomically:

1. **Task 1: Rewrite observatory-minimap-panel.tsx as StarChartMinimap** - `bb9f55952` (feat)
2. **Task 2: Update minimap tests for star chart** - `f2b621966` (test)

## Files Created/Modified
- `apps/workbench/src/features/observatory/panels/observatory-minimap-panel.tsx` — Full rewrite: star chart with worldToChart, OBSERVATORY_STATION_POSITIONS, LANE_PAIRS, status icons, rAF player arrow
- `apps/workbench/src/features/observatory/__tests__/observatory-minimap.test.tsx` — Full rewrite: worldToChart tests, lane tests, status icon tests, color tests, 23 passing

## Decisions Made
- **worldToChart bounds**: Dynamic from all station positions + 15% padding instead of hardcoded scale — ensures all stations visible regardless of world layout changes.
- **SVG Y-axis**: Positive world Z maps to smaller SVG Y (north = up) — standard top-down map convention.
- **DockingState fields**: Used actual `zone === "dock"` and `stationId` — the plan interface description mentioned `phase` and `targetStationId` but the real type uses `zone` and `stationId`. Auto-corrected during read-first step.
- **test mock structure**: Mock `OBSERVATORY_STATION_POSITIONS` in tests to avoid THREE.CatmullRomCurve3 initialization chain from the real world template.

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 1 - Bug] DockingState field names differ from plan interface description**
- **Found during:** Task 1 (reading docking-types.ts)
- **Issue:** Plan's `<interfaces>` block described `dockingState.phase === "docked"` and `dockingState.targetStationId`, but actual type has `zone: DockingZone` (values: `"approach" | "magnet" | "dock" | null`) and `stationId: HuntStationId | null`
- **Fix:** Used `zone === "dock"` and `stationId` throughout implementation and tests
- **Files modified:** observatory-minimap-panel.tsx, observatory-minimap.test.tsx
- **Committed in:** bb9f55952 / f2b621966 (Task 1 & 2 commits)

---

**Total deviations:** 1 auto-fixed (Rule 1 — interface description mismatch with actual code)
**Impact on plan:** Fix was essential for correct behavior. No scope creep.

## Issues Encountered
- Test file used `await import()` inside a non-async `it()` callback — fixed by adding `async` to the test callback.

## Next Phase Readiness
- Star chart minimap is complete and ready for Plan 25-02 (flight path trail — polyline of last 50 ship positions)
- worldToChart() is exported and battle-tested — Plan 25-02 can use it directly for trail point mapping
- rAF + getState() pattern is established — Plan 25-03 (click-to-autopilot) can extend the existing arrow loop

## Self-Check: PASSED

- FOUND: apps/workbench/src/features/observatory/panels/observatory-minimap-panel.tsx
- FOUND: apps/workbench/src/features/observatory/__tests__/observatory-minimap.test.tsx
- FOUND: .planning/phases/25-star-chart-transitions/25-01-SUMMARY.md
- FOUND commit: bb9f55952 (feat: rewrite observatory-minimap-panel as StarChartMinimap)
- FOUND commit: f2b621966 (test: update minimap tests for star chart)
- 23 tests passing

---
*Phase: 25-star-chart-transitions*
*Completed: 2026-03-20*
