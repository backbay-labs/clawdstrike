---
phase: 31-rebuilt-panels
plan: "02"
subsystem: observatory-hud
tags: [hud, drawer, panel-routing, wiring, tests]
dependency_graph:
  requires: [31-01]
  provides: [left-drawer-panel-routing]
  affects: [ObservatoryLeftDrawer, observatory-left-drawer.test]
tech_stack:
  added: []
  patterns: [panel-router-function, switch-statement-routing]
key_files:
  created: []
  modified:
    - apps/workbench/src/features/observatory/components/hud/ObservatoryLeftDrawer.tsx
    - apps/workbench/src/features/observatory/__tests__/observatory-left-drawer.test.tsx
decisions:
  - "renderPanel() helper uses exhaustive switch on HudPanelId — TypeScript ensures all 4 cases are covered with no default needed"
  - "JSX import from react (not global namespace) — required by project tsconfig for JSX.Element return type annotation"
metrics:
  duration_seconds: 180
  completed_date: "2026-03-21"
  tasks_completed: 2
  files_modified: 2
---

# Phase 31 Plan 02: Wire Drawer Panels Summary

**One-liner:** Left drawer now routes to real panel components (Explainability/Mission/Replay/GhostMemory) via exhaustive switch, replacing the Phase 30 uppercase placeholder span.

## What Was Built

ObservatoryLeftDrawer.tsx wired to the four panel components created in Plan 01. Pressing E/R/M/G in the observatory now opens a drawer with real data-driven content instead of an uppercase label.

### Changes

**ObservatoryLeftDrawer.tsx:**
- Added imports for `ExplainabilityDrawerPanel`, `MissionDrawerPanel`, `ReplayDrawerPanel`, `GhostMemoryDrawerPanel`
- Added `import type { JSX } from "react"` and `import type { HudPanelId } from "../../types"`
- Added `renderPanel(panelId: HudPanelId): JSX.Element` helper with exhaustive switch
- Replaced Phase 30 `<span data-testid="observatory-left-drawer-panel-name">` placeholder with `{activePanel !== null && renderPanel(activePanel)}`
- Updated content wrapper: removed `alignItems: "center"` and `justifyContent: "center"`, added `overflow: "hidden"` (panels manage their own layout/scroll)
- Updated doc comment to reflect Phase 31 routing

**observatory-left-drawer.test.tsx:**
- Replaced test d (placeholder name) with explainability panel render assertion
- Replaced test e (switching placeholder) with mission panel render assertion
- Added test f: ReplayDrawerPanel renders when `activePanel === 'replay'`
- Added test g: GhostMemoryDrawerPanel renders when `activePanel === 'ghost'`
- Added test h: no panel content when `activePanel === null`
- Removed all `observatory-left-drawer-panel-name` testid references

## Verification Results

- TypeScript: zero errors (`npx tsc --noEmit`)
- Drawer tests: 8/8 pass
- Panel regression tests (Plan 01): 18/18 pass
- Total: 26/26 tests pass

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 3 - Blocking] Missing JSX namespace import**
- **Found during:** Task 1 (TypeScript verification)
- **Issue:** `JSX.Element` return type annotation failed with TS2503 "Cannot find namespace 'JSX'" — project tsconfig requires explicit `import type { JSX } from "react"` rather than global JSX namespace
- **Fix:** Added `import type { JSX } from "react"` at top of ObservatoryLeftDrawer.tsx, following pattern used in `ObservatoryPostFX.tsx`
- **Files modified:** `apps/workbench/src/features/observatory/components/hud/ObservatoryLeftDrawer.tsx`
- **Commit:** 2cb871860 (inline fix, no separate commit)

## Self-Check: PASSED

- ObservatoryLeftDrawer.tsx: FOUND
- observatory-left-drawer.test.tsx: FOUND
- Commit 2cb871860 (Task 1): FOUND
- Commit 4be7760ca (Task 2): FOUND
