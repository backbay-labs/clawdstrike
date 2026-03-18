---
phase: 01-spirit-observatory-state-foundation
plan: 03
subsystem: ui
tags: [react, zustand, activity-bar, command-palette, routing, typescript]

# Dependency graph
requires:
  - phase: 01-spirit-observatory-state-foundation
    plan: 01
    provides: useObservatoryStore with seamSummary.artifactCount

provides:
  - SigilHunt SVG icon (crosshair motif) in sidebar-icons.tsx
  - "hunt" in ActivityBarItemId union and ACTIVITY_BAR_ITEMS (before sentinels)
  - badge prop on ActivityBarItem (8x8px green pulse dot when badge > 0)
  - ActivityBar subscribes to useObservatoryStore and passes artifactCount as badge to Hunt item
  - /observatory, /spirit-chamber, /nexus routes with PlaceholderPane elements
  - getWorkbenchRouteLabel cases for Observatory, Spirit Chamber, Nexus
  - hunt-commands.ts with 5 Hunt-category commands
  - "Hunt" added to CommandCategory union
  - registerHuntronomerCommands() wired into InitCommands useEffect

affects:
  - Phase 2 (mini R3F inspector companion — hunt icon will need panel open support)
  - Phase 3 (observatory full tab — will replace PlaceholderPane)
  - Phase 4 (nexus tab — will replace PlaceholderPane)

# Tech tracking
tech-stack:
  added: []
  patterns:
    - badge prop on ActivityBarItem is sparse (undefined = no badge, number > 0 = render dot)
    - liveness: ActivityBar passes badge when any count; ActivityBarItem always renders green pulse
    - PlaceholderPane pattern for routes not yet implemented (replaces lazy imports in later phases)

key-files:
  created:
    - apps/workbench/src/lib/commands/hunt-commands.ts
  modified:
    - apps/workbench/src/components/desktop/sidebar-icons.tsx
    - apps/workbench/src/features/activity-bar/types.ts
    - apps/workbench/src/features/activity-bar/components/activity-bar-item.tsx
    - apps/workbench/src/features/activity-bar/components/activity-bar.tsx
    - apps/workbench/src/lib/command-registry.ts
    - apps/workbench/src/components/desktop/workbench-routes.tsx
    - apps/workbench/src/lib/commands/index.ts
    - apps/workbench/src/lib/commands/init-commands.tsx

key-decisions:
  - "ActivityBarItem badge prop is always green pulse when badge > 0; liveness differentiation (stale steel color) deferred to later phase via badgeLive prop extension"
  - "PlaceholderPane is an inline function in workbench-routes.tsx (not a separate component file) since it is only used for transitional routes"
  - "hunt.bindSpirit opens /spirit-chamber as a proxy until a dedicated bind-spirit flow is built in Phase 3"

patterns-established:
  - "badge={item.id === 'hunt' ? huntArtifactCount : undefined}: sparse conditional badge pass in ACTIVITY_BAR_ITEMS.map"
  - "registerHuntronomerCommands() follows same pattern as registerNavigateCommands() — no React deps, uses getState() internally"

requirements-completed: [OBS-01, OBS-02]

# Metrics
duration: 2min
completed: 2026-03-18
---

# Phase 01 Plan 03: Activity Bar Hunt Item, Routes, and Commands Summary

**Hunt activity bar item with live seam badge wired to observatory store, 3 placeholder routes (/observatory, /spirit-chamber, /nexus), and 5 Hunt-category commands registered in the command palette**

## Performance

- **Duration:** 2 min
- **Started:** 2026-03-18T21:34:31Z
- **Completed:** 2026-03-18T21:36:43Z
- **Tasks:** 2
- **Files modified:** 8 (1 created)

## Accomplishments

- Hunt activity bar item (SigilHunt crosshair SVG) renders in the icon rail before Sentinels
- Live seam badge (8x8px bg-[#3dbf84] animate-pulse) appears on Hunt icon when observatoryStore.seamSummary.artifactCount > 0
- Three placeholder routes (/observatory, /spirit-chamber, /nexus) registered with PlaceholderPane elements so the app renders without errors pending Phase 2-4 implementations
- Command palette (Cmd+K) now shows 5 Hunt commands: Open Hunt, Open Observatory, Open Spirit Chamber, Open Nexus, Bind Spirit

## Task Commits

Each task was committed atomically:

1. **Task 1: Hunt activity bar item with seam badge** - `fe49daeaf` (feat)
2. **Task 2: Observatory routes, hunt commands, Hunt category** - `8a8ee3687` (feat)

## Files Created/Modified

- `apps/workbench/src/components/desktop/sidebar-icons.tsx` - Added SigilHunt SVG (crosshair target motif)
- `apps/workbench/src/features/activity-bar/types.ts` - Added "hunt" to ActivityBarItemId union and ACTIVITY_BAR_ITEMS array
- `apps/workbench/src/features/activity-bar/components/activity-bar-item.tsx` - Added optional badge prop with 8x8px green pulse dot rendering
- `apps/workbench/src/features/activity-bar/components/activity-bar.tsx` - Subscribed to useObservatoryStore, passes huntArtifactCount as badge to Hunt item
- `apps/workbench/src/lib/command-registry.ts` - Added "Hunt" to CommandCategory union
- `apps/workbench/src/components/desktop/workbench-routes.tsx` - Added PlaceholderPane helper, 3 new routes, 3 new getWorkbenchRouteLabel cases
- `apps/workbench/src/lib/commands/hunt-commands.ts` - NEW: 5 Hunt-category commands using usePaneStore.getState().openApp()
- `apps/workbench/src/lib/commands/index.ts` - Re-exported registerHuntronomerCommands
- `apps/workbench/src/lib/commands/init-commands.tsx` - Added import + call to registerHuntronomerCommands()

## Decisions Made

- ActivityBarItem badge is always green pulse when badge > 0; liveness color split (green vs steel) deferred to later phase via a future `badgeLive?: boolean` prop extension — ActivityBar can differentiate when needed.
- PlaceholderPane is an inline function in workbench-routes.tsx (not a separate file) since it only serves as a transitional route element until Phase 3/4 builds the real views.
- `hunt.bindSpirit` opens `/spirit-chamber` as a proxy until a dedicated bind-spirit UI flow is implemented in Phase 3.

## Deviations from Plan

None - plan executed exactly as written.

## Issues Encountered

None.

## User Setup Required

None - no external service configuration required.

## Next Phase Readiness

- Phase 01 Plan 03 completes the state foundation phase. All 3 plans complete.
- Phase 2 can now build the mini R3F inspector companion tab — the Hunt activity bar item exists for toggling panel state.
- Phase 3 observatory full tab will replace PlaceholderPane at /observatory.
- Phase 4 nexus tab will replace PlaceholderPane at /nexus.

---
*Phase: 01-spirit-observatory-state-foundation*
*Completed: 2026-03-18*

## Self-Check: PASSED

- hunt-commands.ts: FOUND
- activity-bar/types.ts: FOUND
- 01-03-SUMMARY.md: FOUND
- Commit fe49daeaf: FOUND
- Commit 8a8ee3687: FOUND
