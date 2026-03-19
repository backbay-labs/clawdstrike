---
phase: 07-spirit-evolution-persistence
plan: "01"
subsystem: ui
tags: [zustand, persist, spirit, xp, localStorage, vitest, tdd]

# Dependency graph
requires:
  - phase: 05-spirit-reactivity-editor-integration
    provides: SpiritMoodReactor signal pattern (activeProbes + hasLintErrors subscriptions)
  - phase: 01-spirit-observatory-state-foundation
    provides: useSpiritStore (kind selector), useObservatoryStore (seamSummary.activeProbes)
provides:
  - useSpiritEvolutionStore: per-kind XP+level state persisted to localStorage
  - deriveLevel: pure XP-to-level function (thresholds 0/50/150/350/700)
  - XP_THRESHOLDS: exported constants for level-gating in Plan 07-02
  - SpiritExperienceTracker: zero-render component wired to probe-complete and lint-pass transitions
affects:
  - 07-spirit-evolution-persistence/07-02 (reads useSpiritEvolutionStore for level-gated geometry)

# Tech tracking
tech-stack:
  added: [zustand/middleware (persist)]
  patterns:
    - "Zustand persist with partialize: persists only evolution record, not actions"
    - "Imperative getState().actions.grantXp() in effect to avoid tracker re-renders"
    - "useRef prev-value transition detection for edge-triggered XP grants"
    - "Per-event-type cooldown (10s) via useRef<number>(0) timestamps"

key-files:
  created:
    - apps/workbench/src/features/spirit/stores/spirit-evolution-store.ts
    - apps/workbench/src/features/spirit/components/spirit-experience-tracker.tsx
    - apps/workbench/src/features/spirit/__tests__/spirit-evolution-store.test.ts
  modified:
    - apps/workbench/src/components/desktop/desktop-layout.tsx

key-decisions:
  - "partialize in persist excludes actions from localStorage — only evolution Record<SpiritKind, KindEvolution> is serialized"
  - "grantXp called via getState() not hook — zero re-renders in the tracker component itself"
  - "10s cooldown per event type prevents XP grinding during rapid probe/lint cycles"
  - "level stored redundantly alongside xp in KindEvolution for O(1) reads by 07-02 canvas"

patterns-established:
  - "SpiritExperienceTracker: same zero-render/return-null pattern as SpiritMoodReactor"
  - "TDD: test file written before store exists (RED import error), then GREEN on all 8"

requirements-completed: [SPRT-12, SPRT-13]

# Metrics
duration: 3min
completed: 2026-03-19
---

# Phase 7 Plan 01: Spirit Evolution Store Summary

**Zustand persist store tracking per-SpiritKind XP/level in localStorage, with zero-render SpiritExperienceTracker granting 10 XP on probe completion and 5 XP on lint pass**

## Performance

- **Duration:** ~3 min
- **Started:** 2026-03-19T13:24:53Z
- **Completed:** 2026-03-19T13:27:32Z
- **Tasks:** 2
- **Files modified:** 4

## Accomplishments

- Per-kind XP/level store with Zustand persist middleware (`clawdstrike.spirit-evolution` localStorage key)
- Pure `deriveLevel` function with L1=0, L2=50, L3=150, L4=350, L5=700 thresholds
- 8 unit tests via TDD (RED import error → GREEN all pass)
- `SpiritExperienceTracker` detects probe-complete and lint-pass transitions with 10s cooldown
- Mounted in DesktopLayout immediately after SpiritMoodReactor

## Task Commits

Each task was committed atomically:

1. **Task 1: spirit-evolution-store + unit tests (TDD)** - `143a5bd0b` (feat + test)
2. **Task 2: SpiritExperienceTracker + desktop-layout mount** - `8a6b18eb7` (feat)

**Plan metadata:** (docs commit below)

_Note: Task 1 used TDD — tests written first (RED), store implemented second (GREEN), no separate refactor needed_

## Files Created/Modified

- `apps/workbench/src/features/spirit/stores/spirit-evolution-store.ts` - Zustand store with persist, deriveLevel, XP_THRESHOLDS, grantXp action
- `apps/workbench/src/features/spirit/__tests__/spirit-evolution-store.test.ts` - 8 unit tests covering thresholds, isolation, localStorage persistence
- `apps/workbench/src/features/spirit/components/spirit-experience-tracker.tsx` - Zero-render XP event detector with useRef prev-value tracking and 10s cooldowns
- `apps/workbench/src/components/desktop/desktop-layout.tsx` - Added SpiritExperienceTracker import + JSX mount after SpiritMoodReactor

## Decisions Made

- `partialize` in persist excludes actions from localStorage — only the evolution Record is serialized (actions are reconstructed at store init)
- `grantXp` called via `getState()` inside effects, not through a hook, to avoid causing re-renders of the tracker component itself
- 10s cooldown per event type via `useRef<number>(0)` timestamps prevents XP grinding during rapid probe/lint cycles
- `level` stored redundantly alongside `xp` in KindEvolution for O(1) reads by the 07-02 canvas without recomputing thresholds

## Deviations from Plan

None - plan executed exactly as written.

## Issues Encountered

Pre-existing TypeScript errors in `observatory/`, `nexus/`, and `sidebar-icons.tsx` appear in `tsc --noEmit` output but are unrelated to this plan's changes. Zero errors in the four files created/modified by this plan.

## User Setup Required

None - no external service configuration required.

## Next Phase Readiness

- `useSpiritEvolutionStore`, `deriveLevel`, `XP_THRESHOLDS` fully exported and ready for 07-02 to read for level-gated geometry
- XP accumulates silently while operator works — no visual feedback yet (07-02 adds level-up burst and geometry scaling)
- localStorage persistence verified: evolution survives workbench restart

---
*Phase: 07-spirit-evolution-persistence*
*Completed: 2026-03-19*
