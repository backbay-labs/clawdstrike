---
phase: 33-drawer-chrome-glassmorphism
plan: 02
subsystem: ui
tags: [react, observatory, hud, glassmorphism, zustand, drawer, header]

# Dependency graph
requires:
  - phase: 33-drawer-chrome-glassmorphism
    provides: "Phase 33 Plan 01 — glassmorphism drawer tokens and always-mounted slide/fade transitions"
  - phase: 31-explainability-panel
    provides: "ObservatoryLeftDrawer component with panel routing (ExplainabilityDrawerPanel, MissionDrawerPanel, ReplayDrawerPanel, GhostMemoryDrawerPanel)"
provides:
  - "PANEL_LABELS Record<HudPanelId, string> mapping panel IDs to uppercase display labels"
  - "HUD_DRAWER_HEADER_HEIGHT = 36 constant for header sizing"
  - "Drawer header bar: 36px, bottom border separator, uppercase monospace panel label"
  - "Close button (×) in drawer header that calls closePanel() — mouse-based dismiss"
  - "4 new tests covering label rendering per panel ID and close button presence/absence"
affects: [34-status-strip-polish, any phase adding new HudPanelId values]

# Tech tracking
tech-stack:
  added: []
  patterns:
    - "PANEL_LABELS map in hud-constants.ts is the single source of truth for panel display names"
    - "Header bar uses data-testid=drawer-header / drawer-header-label / drawer-close-button for test targeting"
    - "Close button calls useObservatoryStore.getState().actions.closePanel() via getState() — avoids React subscription for a click handler"

key-files:
  created: []
  modified:
    - apps/workbench/src/features/observatory/components/hud/hud-constants.ts
    - apps/workbench/src/features/observatory/components/hud/ObservatoryLeftDrawer.tsx
    - apps/workbench/src/features/observatory/__tests__/observatory-left-drawer.test.tsx

key-decisions:
  - "HudPanelId added to existing import statement in hud-constants.ts alongside HuntStationId and ObservatoryAnalystPresetId"
  - "PANEL_LABELS and HUD_DRAWER_HEADER_HEIGHT placed between HUD_LEFT_DRAWER_WIDTH and ANALYST_PRESETS — grouped by Phase 33 additions"
  - "Header bar hidden (not rendered) when activePanel is null — avoids any visible artifact in closed state"
  - "Close button uses getState().actions.closePanel() not a hook subscription — clicking is a rare user action, hook would be unnecessary"
  - "Unicode multiplication sign &#x2715; for X character — no icon library dependency"

patterns-established:
  - "Pattern: Panel label constants live in hud-constants.ts and are keyed by HudPanelId — any new panel must add its label there"
  - "Pattern: Drawer header always shows when activePanel is non-null; hidden when null — parallel to renderPanel() guard"

requirements-completed: [DRW-01, DRW-02]

# Metrics
duration: 8min
completed: 2026-03-22
---

# Phase 33 Plan 02: Drawer Chrome Glassmorphism — Header Bar Summary

**Drawer header bar with uppercase monospace panel label (EXPLAINABILITY / MISSION / REPLAY / GHOST MEMORY) and close button that calls closePanel(), providing mouse-based dismiss alongside the existing Escape hotkey**

## Performance

- **Duration:** 8 min
- **Started:** 2026-03-22T00:03:00Z
- **Completed:** 2026-03-22T00:11:00Z
- **Tasks:** 2
- **Files modified:** 3

## Accomplishments
- Added `PANEL_LABELS` mapping and `HUD_DRAWER_HEADER_HEIGHT = 36` to hud-constants.ts
- Added 36px drawer header bar with bottom border separator and uppercase label derived from PANEL_LABELS
- Added close button (×) calling `closePanel()` — operators can now dismiss the drawer with the mouse in addition to Escape
- Added 4 new tests: EXPLAINABILITY label, GHOST MEMORY label, close button presence (DRW-02), header absent when panel is null

## Task Commits

Each task was committed atomically:

1. **Task 1: Add panel label map and header height constant** - `053818ae4` (feat)
2. **Task 2: Add header bar with panel label and close button to drawer** - `89f58f1ab` (feat)

## Files Created/Modified
- `apps/workbench/src/features/observatory/components/hud/hud-constants.ts` - Added HudPanelId import, HUD_DRAWER_HEADER_HEIGHT constant, PANEL_LABELS map
- `apps/workbench/src/features/observatory/components/hud/ObservatoryLeftDrawer.tsx` - Added drawer header bar div with label span and close button; adjusted padding; updated JSDoc
- `apps/workbench/src/features/observatory/__tests__/observatory-left-drawer.test.tsx` - Added tests i (duplicate letter for GLS-01 existing), j, k, l covering DRW-01 and DRW-02

## Decisions Made
- Header bar conditionally rendered only when `activePanel !== null`, matching the same null guard used for `renderPanel()` — avoids any visible header artifact in the closed drawer state
- Close button uses `useObservatoryStore.getState().actions.closePanel()` not a React subscription, consistent with how `useObservatoryHotkeys.ts` calls `closePanel()` for the Escape key path

## Deviations from Plan

None - plan executed exactly as written.

## Issues Encountered
- Test runner must be invoked from within `apps/workbench/` directory (not workspace root) for the `@/` path alias to resolve correctly in Vitest. All 13 tests pass when run correctly.

## Next Phase Readiness
- Phase 33 Plan 02 complete. Drawer now has full chrome: glassmorphism glass (Plan 01) + header label + close button (Plan 02)
- Phase 34 (status strip polish) can proceed independently
- Any future HudPanelId additions must add a corresponding entry to PANEL_LABELS in hud-constants.ts

---
*Phase: 33-drawer-chrome-glassmorphism*
*Completed: 2026-03-22*

## Self-Check: PASSED

- hud-constants.ts — FOUND
- ObservatoryLeftDrawer.tsx — FOUND
- observatory-left-drawer.test.tsx — FOUND
- 33-02-SUMMARY.md — FOUND
- Commit 053818ae4 — FOUND
- Commit 89f58f1ab — FOUND
