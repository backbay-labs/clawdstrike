---
phase: 09-nexus-force-graph
plan: "02"
subsystem: ui
tags: [zustand, nexus, force-directed-graph, layout-toggle, react, testing]

# Dependency graph
requires:
  - phase: 09-nexus-force-graph
    plan: "01"
    provides: NexusForceCanvas, nexus-store connections slice, r3f-forcegraph@1.1.1
provides:
  - layoutMode: NexusLayoutMode field (default "radial") + setLayoutMode action in nexus-store
  - NexusTab toggle button (data-testid="nexus-layout-toggle") switching atlas/force-directed views
  - Conditional render: ObservatoryWorldCanvas when layoutMode!=="force-directed", NexusForceCanvas when "force-directed"
  - nexus-store.test.ts: 4 tests for layoutMode slice
  - nexus-tab.test.tsx extended: 7 total tests (2 NXS-01 + 5 NXS-02)
affects:
  - NXS-02 requirement fully satisfied

# Tech tracking
tech-stack:
  added: []
  patterns:
    - Toggle pattern: useNexusStore.getState().actions.setLayoutMode() called from useCallback handler
    - Conditional canvas render: isForceMode ternary switching NexusForceCanvas vs ObservatoryWorldCanvas
    - Test pattern: mockReturnValue on vi.fn() selector to simulate store state changes per test

key-files:
  created:
    - apps/workbench/src/features/nexus/__tests__/nexus-store.test.ts
  modified:
    - apps/workbench/src/features/nexus/stores/nexus-store.ts
    - apps/workbench/src/features/nexus/components/NexusTab.tsx
    - apps/workbench/src/features/nexus/__tests__/nexus-tab.test.tsx

key-decisions:
  - "layoutMode default is 'radial' (not 'atlas') — NexusLayoutMode union is radial|typed-lanes|force-directed; atlas is not a valid value; NexusTab renders ObservatoryWorldCanvas when layoutMode!=='force-directed'"
  - "Toggle calls useNexusStore.getState().actions.setLayoutMode() (not hook selector) to avoid re-render loop — same pattern as usePaneStore.getState().openApp in handleSelectStation"
  - "NexusTab test mock extended with getState() returning setLayoutMode to match production toggle handler pattern"

# Metrics
duration: 4min
completed: 2026-03-19
---

# Phase 09 Plan 02: NexusTab Layout Toggle Summary

**layoutMode (default "radial") added to nexus-store + NexusTab toggle button switching between ObservatoryWorldCanvas (atlas) and NexusForceCanvas (force-directed) — 11 tests passing**

## Performance

- **Duration:** ~4 min
- **Started:** 2026-03-19T14:23:21Z
- **Completed:** 2026-03-19T14:27:15Z
- **Tasks:** 2
- **Files modified:** 3 (nexus-store.ts, NexusTab.tsx, nexus-tab.test.tsx) + 1 created (nexus-store.test.ts)

## Accomplishments

- Added `layoutMode: NexusLayoutMode` (default `"radial"`) to NexusState interface and store
- Added `setLayoutMode` action; `createSelectors` exposes `useNexusStore.use.layoutMode()`
- Created `nexus-store.test.ts` with 4 tests covering default value, setLayoutMode transitions, and selector exposure
- Updated NexusTab to read `layoutMode` from store and conditionally render `NexusForceCanvas` vs `ObservatoryWorldCanvas`
- Added toggle button (data-testid="nexus-layout-toggle") with labels "Force Graph" / "Atlas View" per mode
- Removed `@ts-expect-error` Wave 0 guard from nexus-tab.test.tsx (NexusTab exists)
- Extended nexus-tab.test.tsx with 5 NXS-02 layout toggle tests; 7 total pass (2 NXS-01 + 5 NXS-02)
- TypeScript: zero new errors in nexus feature files

## Task Commits

Each task committed atomically:

1. **Task 1: Add layoutMode to nexus-store** — `0e9f61d69` (feat)
2. **Task 2: Wire layoutMode toggle in NexusTab + extend tests** — `4d81bfbd7` (feat)

## Files Created/Modified

- `apps/workbench/src/features/nexus/stores/nexus-store.ts` — Added `layoutMode: NexusLayoutMode` field + `setLayoutMode` action
- `apps/workbench/src/features/nexus/__tests__/nexus-store.test.ts` — New: 4 tests for layoutMode slice
- `apps/workbench/src/features/nexus/components/NexusTab.tsx` — Added toggle button + conditional canvas render + NexusForceCanvas import
- `apps/workbench/src/features/nexus/__tests__/nexus-tab.test.tsx` — Removed @ts-expect-error, added NexusForceCanvas mock + layoutMode mock + 5 NXS-02 tests

## Decisions Made

- `layoutMode` defaults to `"radial"` — the `NexusLayoutMode` union is `"radial" | "typed-lanes" | "force-directed"`; "atlas" is not a valid member. NexusTab renders ObservatoryWorldCanvas for any non-force-directed value.
- Toggle handler uses `useNexusStore.getState().actions.setLayoutMode()` inside `useCallback` — same Zustand getState() pattern as `usePaneStore.getState().openApp()` already in NexusTab, avoids dependency on setter in callback deps.
- Test mock extended with `getState` returning `{ actions: { setLayoutMode: mockSetLayoutMode } }` to match production toggle handler call site.

## Deviations from Plan

None — plan executed exactly as written.

## Self-Check: PASSED

- [x] `apps/workbench/src/features/nexus/stores/nexus-store.ts` — exists, contains `layoutMode` and `setLayoutMode`
- [x] `apps/workbench/src/features/nexus/components/NexusTab.tsx` — exists, contains `nexus-layout-toggle` and `NexusForceCanvas`
- [x] `apps/workbench/src/features/nexus/__tests__/nexus-store.test.ts` — exists, 4 tests
- [x] `apps/workbench/src/features/nexus/__tests__/nexus-tab.test.tsx` — exists, 7 tests
- [x] Task 1 commit `0e9f61d69` — confirmed in git log
- [x] Task 2 commit `4d81bfbd7` — confirmed in git log
- [x] All 11 nexus tests pass
- [x] TypeScript clean (no nexus errors)

---
*Phase: 09-nexus-force-graph*
*Completed: 2026-03-19*
