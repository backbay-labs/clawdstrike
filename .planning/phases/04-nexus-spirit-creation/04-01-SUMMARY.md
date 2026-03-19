---
phase: 04-nexus-spirit-creation
plan: "01"
subsystem: nexus
tags: [types, zustand-store, tdd, wave-0]
dependency_graph:
  requires: []
  provides:
    - apps/workbench/src/features/nexus/types.ts
    - apps/workbench/src/features/nexus/stores/nexus-store.ts
    - apps/workbench/src/features/nexus/__tests__/nexus-tab.test.tsx
  affects:
    - apps/workbench/src/features/nexus/components/NexusTab.tsx (Plan 02 — depends on these types)
tech_stack:
  added: []
  patterns:
    - zustand create() with createSelectors wrapper
    - Wave 0 @ts-expect-error test stubs
    - Pure types file with static const data (no runtime logic beyond mock arrays)
key_files:
  created:
    - apps/workbench/src/features/nexus/types.ts
    - apps/workbench/src/features/nexus/stores/nexus-store.ts
    - apps/workbench/src/features/nexus/__tests__/nexus-tab.test.tsx
  modified: []
decisions:
  - "DEMO_STRIKECELLS all set to status=offline: workbench has no live backend, all nodes=[] per plan spec"
  - "STRIKECELL_BY_STATION placed in types.ts (not NexusCanvas.tsx as in huntronomer): workbench has no NexusCanvas yet, routing map belongs at the types layer"
  - "Wave 0 test stubs fail with Vite module resolution error (not syntax error): @ts-expect-error guards NexusTab import, import error at Vite transform time is the expected Wave 0 failure mode"
metrics:
  duration: "154s (~3 min)"
  completed_date: "2026-03-19"
  tasks_completed: 2
  files_created: 3
  files_modified: 0
---

# Phase 04 Plan 01: Nexus Types + Store + Test Stubs Summary

Nexus feature foundation: ported strikecell types from huntronomer, built minimal Zustand store initialized with 9-entry DEMO_STRIKECELLS, and scaffolded Wave 0 test stubs that fail gracefully until NexusTab ships in Plan 02.

## Tasks Completed

| Task | Name | Commit | Files |
|------|------|--------|-------|
| 1 | nexus types + DEMO_STRIKECELLS + routing maps | 1aaa2e7d5 | apps/workbench/src/features/nexus/types.ts |
| 2 | nexus-store minimal Zustand store + Wave 0 test scaffold | bcb0bb4e7 | nexus/stores/nexus-store.ts, nexus/__tests__/nexus-tab.test.tsx |

## What Was Built

**nexus/types.ts** — Pure types file ported from huntronomer `apps/desktop/src/features/cyber-nexus/types.ts`:
- Types retained: `StrikecellStatus`, `StrikecellDomainId` (9 values), `StrikecellNode`, `StrikecellConnection`, `Strikecell`, `NexusLayoutMode`, `NexusViewMode`, `NexusGraph`
- Types removed: `StrikecellSourceSnapshot` (glia-three/tauri deps), `NexusHudState`, `NexusSelectionState`, `NexusOperationMode`, `NexusEscLayer` (full NexusStateContext types not needed)
- Added: `DEMO_STRIKECELLS` (9 entries, all `status="offline"`, `nodes=[]`), `STRIKECELL_BY_STATION` (6 HuntStationId → StrikecellDomainId mappings from NexusCanvas.tsx), `STRIKECELL_ROUTE_MAP` (9 StrikecellDomainId → workbench route mappings)

**nexus/stores/nexus-store.ts** — Minimal Zustand store following spirit-store pattern:
- `strikecells: Strikecell[]` initialized to `DEMO_STRIKECELLS`
- `actions.setStrikecells` for future live data hydration
- `createSelectors` wrapper: `useNexusStore.use.strikecells()` selector available

**nexus/__tests__/nexus-tab.test.tsx** — Wave 0 stubs:
- Test 1: "renders ObservatoryWorldCanvas in atlas mode" — checks `data-observatory-mode="atlas"` on mocked canvas
- Test 2: "station select calls pane-store.openApp with mapped route" — fires `onSelectStation("signal")`, checks `openApp("/home")` called
- Both tests fail with Vite module resolution error (`NexusTab` component not created yet) — expected Wave 0 behavior

## Deviations from Plan

None — plan executed exactly as written.

## Self-Check

- [x] `apps/workbench/src/features/nexus/types.ts` exists
- [x] `apps/workbench/src/features/nexus/stores/nexus-store.ts` exists
- [x] `apps/workbench/src/features/nexus/__tests__/nexus-tab.test.tsx` exists
- [x] `DEMO_STRIKECELLS.length === 9`
- [x] All 9 `StrikecellDomainId` values present in `DEMO_STRIKECELLS`
- [x] `STRIKECELL_BY_STATION` has 6 keys
- [x] `STRIKECELL_ROUTE_MAP` has 9 keys
- [x] No nexus TypeScript errors (`npx tsc --noEmit` clean for nexus files)
- [x] Wave 0 tests fail with import error (not syntax error) — expected
- [x] Commits: 1aaa2e7d5, bcb0bb4e7
