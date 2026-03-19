---
phase: 04-nexus-spirit-creation
plan: "02"
subsystem: ui
tags: [react, r3f, three, zustand, workbench, nexus, observatory]

requires:
  - phase: 04-01
    provides: nexus types (StrikecellDomainId, STRIKECELL_BY_STATION, STRIKECELL_ROUTE_MAP), nexus-store (useNexusStore), Wave 0 test scaffold

provides:
  - NexusTab.tsx — store bridge that reads nexus-store + spirit-store and renders ObservatoryWorldCanvas in atlas mode
  - /nexus route now renders NexusTab (lazy) instead of PlaceholderPane

affects:
  - workbench-routes — nexus route now live with real 3D content
  - pane-store — hunt.openNexus command now opens a real tab with content

tech-stack:
  added: []
  patterns:
    - NexusTab mirrors ObservatoryTab store bridge pattern exactly
    - resolveNexusObservatoryStationId ported inline (not imported from huntronomer)

key-files:
  created:
    - apps/workbench/src/features/nexus/components/NexusTab.tsx
  modified:
    - apps/workbench/src/components/desktop/workbench-routes.tsx

key-decisions:
  - "NexusTab mode fixed to atlas (no mode toggle — nexus is always an atlas overview, not a walkable world)"
  - "resolveNexusObservatoryStationId ported inline — avoids importing from huntronomer, keeps workbench self-contained"
  - "Pre-existing App.test.tsx + desktop-layout.test.tsx failures (ResizeObserver, SystemHeartbeat mock) confirmed pre-existing and out of scope"

patterns-established:
  - "NexusTab store bridge: useNexusStore.use.strikecells() → HuntStationState[] → ObservatoryWorldCanvas props"
  - "Station select: STRIKECELL_BY_STATION[stationId] → strikecellId → STRIKECELL_ROUTE_MAP[strikecellId] → usePaneStore.getState().openApp(route)"

requirements-completed:
  - NXS-01

duration: 3min
completed: 2026-03-19
---

# Phase 4 Plan 02: NexusTab Store Bridge + /nexus Route Summary

**NexusTab renders ObservatoryWorldCanvas in atlas mode, wired to nexus-store + spirit-store with strikecell-to-route routing via STRIKECELL_BY_STATION/STRIKECELL_ROUTE_MAP**

## Performance

- **Duration:** ~3 min
- **Started:** 2026-03-19T01:13:01Z
- **Completed:** 2026-03-19T01:16:10Z
- **Tasks:** 2
- **Files modified:** 2

## Accomplishments

- NexusTab.tsx created as a pure store bridge — reads workbench stores, builds HuntObservatorySceneState, delegates to ObservatoryWorldCanvas in atlas mode
- Station click routing complete: STRIKECELL_BY_STATION lookup + usePaneStore.getState().openApp(STRIKECELL_ROUTE_MAP[id])
- /nexus route in workbench-routes.tsx swapped from PlaceholderPane to lazy NexusTab
- Wave 0 nexus-tab.test.tsx: 2/2 tests passing

## Task Commits

Each task was committed atomically:

1. **Task 1: NexusTab store bridge component** - `d5b19dd97` (feat)
2. **Task 2: Wire /nexus route in workbench-routes.tsx** - `4eef1155b` (feat)

## Files Created/Modified

- `apps/workbench/src/features/nexus/components/NexusTab.tsx` - Store bridge: reads nexus-store + spirit-store, builds HuntObservatorySceneState, renders ObservatoryWorldCanvas in atlas mode with strikecell routing
- `apps/workbench/src/components/desktop/workbench-routes.tsx` - /nexus route now renders NexusTab (lazy, Suspense) instead of PlaceholderPane

## Decisions Made

- NexusTab mode fixed to "atlas" (no mode toggle) — nexus is an overview surface, not a walkable world; flow mode belongs to ObservatoryTab only
- resolveNexusObservatoryStationId ported inline from huntronomer observatory.ts (the switch statement) rather than importing from huntronomer — keeps workbench self-contained, avoids cross-worktree coupling
- Pre-existing test failures in App.test.tsx (ResizeObserver not defined) and desktop-layout.test.tsx (SystemHeartbeat mock gap) confirmed pre-existing by git stash test; out of scope per deviation rule SCOPE BOUNDARY

## Deviations from Plan

None — plan executed exactly as written.

## Issues Encountered

- Pre-existing test failures (2 test files, 18 tests) verified to pre-date this plan. Not caused by this plan's changes.

## Next Phase Readiness

- Phase 4 complete. All 3 plans (04-01, 04-02, 04-03) shipped.
- hunt.openNexus command opens /nexus route → NexusTab renders full 3D atlas scene
- Spirit system (SpiritChamberTab), Observatory full pane, and Nexus Hunt Deck all live

---
*Phase: 04-nexus-spirit-creation*
*Completed: 2026-03-19*
