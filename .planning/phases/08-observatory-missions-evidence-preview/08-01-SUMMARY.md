---
phase: 08-observatory-missions-evidence-preview
plan: "01"
subsystem: observatory/mission
tags: [missionLoop, observatory-store, state-machine, tdd]
dependency_graph:
  requires: []
  provides: [observatory-mission-loop-state, observatory-store-mission-actions]
  affects: [observatory-store, ObservatoryState, missionLoop]
tech_stack:
  added: []
  patterns: [pure-ts-state-machine, tdd-red-green, verbatim-port]
key_files:
  created:
    - apps/workbench/src/features/observatory/world/missionLoop.ts
    - apps/workbench/src/features/observatory/__tests__/mission-loop.test.ts
  modified:
    - apps/workbench/src/features/observatory/types.ts
    - apps/workbench/src/features/observatory/stores/observatory-store.ts
decisions:
  - "missionLoop.ts ported verbatim from huntronomer; only import paths adjusted (../types -> ./types)"
  - "deriveObservatoryMissionBranch has comment noting synthetic scene state always yields operations-first until live status flows"
  - "6 tests (not 8): huntronomer source had 6 it() blocks covering all 8 described behaviors"
metrics:
  duration: ~5 min
  completed_date: "2026-03-19"
  tasks_completed: 2
  files_created: 2
  files_modified: 2
---

# Phase 08 Plan 01: Mission Loop Port and Observatory Store Extension Summary

Pure TypeScript mission state machine ported verbatim from huntronomer; observatory-store extended with mission field and startMission/completeObjective/resetMission actions.

## Tasks Completed

| Task | Name | Commit | Files |
|------|------|--------|-------|
| 1 | Port missionLoop.ts (TDD) | f6410176d | world/missionLoop.ts, __tests__/mission-loop.test.ts |
| 2 | Extend ObservatoryState + store | c567b8f56 | types.ts, stores/observatory-store.ts |

## Verification

All 6 unit tests pass:

- starts at Horizon, adds Subjects, and follows the operations-first branch
- can branch to evidence before operations after Subjects
- derives the evidence-first branch from live scene pressure
- ignores out-of-order prop activations
- targets the current mission objective for operator probes before fallback stations
- falls back to active or likely stations when there is no current objective

TypeScript: no errors in changed files (pre-existing errors in ObservatoryWorldCanvas, sidebar-icons, tauri-bridge are out-of-scope).

## Deviations from Plan

### Notes

**1. Test count: 6 vs 8 described**
- **Found during:** Task 1
- **Issue:** Plan states "8 unit tests" but huntronomer source missionLoop.test.ts has 6 `it()` blocks. The plan's 8 behavior items map to assertions within those 6 tests.
- **Fix:** Ported all 6 `it()` blocks from the source exactly as written. All 8 described behaviors are covered.
- **Impact:** None — all behaviors are tested.

No bug fixes or architectural changes were needed.

## Self-Check: PASSED

- [x] apps/workbench/src/features/observatory/world/missionLoop.ts exists
- [x] apps/workbench/src/features/observatory/__tests__/mission-loop.test.ts exists
- [x] Commit f6410176d exists
- [x] Commit c567b8f56 exists
- [x] All 6 tests pass
- [x] mission: null initialized in observatory-store
- [x] startMission, completeObjective, resetMission implemented
