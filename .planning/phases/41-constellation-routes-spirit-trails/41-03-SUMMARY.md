---
phase: 41-constellation-routes-spirit-trails
plan: 03
subsystem: ui
tags: [react, svg, zustand, observatory, minimap, constellation]

# Dependency graph
requires:
  - phase: 39-store-persistence-derivation-foundations
    provides: constellations array in observatory store with ConstellationRoute type
  - phase: 41-01
    provides: ConstellationRoute type and observatory-store constellations field

provides:
  - Constellation route polylines rendered on star chart minimap SVG
  - Click-to-tooltip interaction showing constellation name and creation date

affects:
  - observatory-minimap-panel.tsx consumers
  - Any future plan testing the minimap component

# Tech tracking
tech-stack:
  added: []
  patterns:
    - useState for UI-local tooltip state (not promoted to store)
    - useMemo for deriving SVG chart coordinates from store constellations
    - data-testid pattern on SVG polylines for testability

key-files:
  created: []
  modified:
    - apps/workbench/src/features/observatory/panels/observatory-minimap-panel.tsx
    - apps/workbench/src/features/observatory/__tests__/observatory-minimap.test.tsx

key-decisions:
  - "CNST-04: Click (not hover) as primary interaction for constellation polylines — hover on small SVG polylines is imprecise"
  - "Tooltip positioned at bottom-center of minimap div using absolute positioning + relative parent"
  - "Selected constellation highlighted with #e8e4f0 stroke and 1.5px width; unselected uses #8b7fc7 at 50% opacity"

patterns-established:
  - "Constellation polylines rendered in SVG layer between lane connections and core links"
  - "Toggle selection: click selected constellation to dismiss tooltip"

requirements-completed: [CNST-04]

# Metrics
duration: 4min
completed: 2026-03-23
---

# Phase 41 Plan 03: Constellation Routes on Minimap Summary

**SVG polyline constellation routes with click-to-tooltip showing name + creation date on the observatory star chart minimap**

## Performance

- **Duration:** 4 min (269s)
- **Started:** 2026-03-23T02:53:40Z
- **Completed:** 2026-03-23T02:58:09Z
- **Tasks:** 1
- **Files modified:** 2

## Accomplishments

- Extended ObservatoryMinimapPanel to subscribe to `constellations` from observatory store
- Derived `constellationChartPaths` via useMemo mapping `stationPath` HuntStationIds to SVG chart coordinates using the existing `worldToChart` function
- Rendered constellation polylines (CNST-04 comment) in the SVG between lane connections and core links
- Click interaction: selecting a polyline shows tooltip with constellation name and `toLocaleDateString` creation date; clicking again or clicking tooltip dismisses it
- Added `relative` class to SVG wrapper div to enable absolute tooltip positioning

## Task Commits

Each task was committed atomically:

1. **Task 1: Add constellation markers and tooltip to minimap** - `2d4016afb` (feat)

**Plan metadata:** (to follow)

## Files Created/Modified

- `apps/workbench/src/features/observatory/panels/observatory-minimap-panel.tsx` - Added constellations subscription, constellationChartPaths memo, polyline rendering block, tooltip overlay
- `apps/workbench/src/features/observatory/__tests__/observatory-minimap.test.tsx` - Added `constellations: []` to mock state to fix 18 pre-existing test failures caused by missing field

## Decisions Made

- Click interaction selected over hover — hover on small SVG polylines is too imprecise per plan spec note
- Tooltip uses absolute positioning at bottom-center of the minimap wrapper div (not SVG foreignObject) for clean DOM styling
- UI tooltip state (`tooltipConstellation`) stays local with `useState` — no store promotion needed

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 1 - Bug] Added constellations field to observatory-minimap.test.tsx mock state**
- **Found during:** Task 1 (Add constellation markers and tooltip to minimap)
- **Issue:** The test mock `observatoryState` object was missing `constellations: []`. When `useObservatoryStore((state) => state.constellations)` was evaluated in the component, it returned `undefined`, causing `constellations.map(...)` to throw `Cannot read properties of undefined (reading 'map')`. This broke 18 existing tests.
- **Fix:** Added `constellations: []` field to the hoisted `observatoryState` mock and reset it in `beforeEach`
- **Files modified:** `apps/workbench/src/features/observatory/__tests__/observatory-minimap.test.tsx`
- **Verification:** All 25 minimap tests pass after fix
- **Committed in:** `2d4016afb` (part of Task 1 commit)

---

**Total deviations:** 1 auto-fixed (Rule 1 - bug in test mock missing field introduced by this plan's new store subscription)
**Impact on plan:** Required fix — the test mock needed to reflect the new store field. No scope creep.

## Issues Encountered

None beyond the test mock fix documented above.

## User Setup Required

None - no external service configuration required.

## Next Phase Readiness

- Constellation polylines now visible on the minimap for any routes in the store
- Ready for Phase 41 remaining plans (spirit trails, resonance connections)
- No blockers

---
*Phase: 41-constellation-routes-spirit-trails*
*Completed: 2026-03-23*
