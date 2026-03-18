---
phase: 01-spirit-observatory-state-foundation
plan: 01
subsystem: ui
tags: [zustand, spirit, observatory, state-management, huntronomer]

# Dependency graph
requires: []
provides:
  - "useSpiritStore — Zustand store with kind/mood/fieldStrength/accentColor state and createSelectors"
  - "useObservatoryStore — Zustand store with stations/seamSummary/connected state and createSelectors"
  - "SpiritKind, SpiritMood, SpiritState types from features/spirit/types.ts"
  - "ObservatorySeamSummary, ObservatoryStation, ObservatoryState types from features/observatory/types.ts"
affects:
  - 01-02-PLAN  # SpiritFieldInjector subscribes to spirit-store
  - 01-03-PLAN  # ActivityBar badge subscribes to observatory-store
  - 02-PLAN     # Phase 2 Mini R3F inspector reads spirit state
  - 03-PLAN     # Phase 3 Observatory tab reads observatory state

# Tech tracking
tech-stack:
  added: []
  patterns:
    - "Zustand store with createSelectors (no immer) pattern for pure state slices"
    - "Feature directory convention: features/{name}/stores/{name}-store.ts + features/{name}/types.ts"
    - "Actions nested inside state interface (actions property) — prevents createSelectors from generating action selectors"

key-files:
  created:
    - apps/workbench/src/features/spirit/types.ts
    - apps/workbench/src/features/spirit/stores/spirit-store.ts
    - apps/workbench/src/features/observatory/types.ts
    - apps/workbench/src/features/observatory/stores/observatory-store.ts
  modified: []

key-decisions:
  - "Spirit store uses no-immer create() pattern (same as search-store) — state is simple enough not to need immer"
  - "SPIRIT_ACCENT_MAP is a module-level constant (not in state) — derived, not stored"
  - "bindSpirit sets fieldStrength: 1 and mood: active atomically — single set call avoids transient invalid state"
  - "Observatory setStations recomputes artifactCount aggregate inline — keeps seamSummary always in sync"
  - "Default spirit state has kind: null so no CSS stain renders until spirit explicitly bound"
  - "Default observatory seamSummary has zeros so no activity bar badge renders until hunt data arrives"

patterns-established:
  - "Spirit stores: import from @/lib/create-selectors, wrap with createSelectors(useXStoreBase)"
  - "Observatory stores: use get() inside set() for reading current state during multi-field updates"

requirements-completed:
  - SPRT-01
  - SPRT-02
  - OBS-01
  - OBS-02

# Metrics
duration: 2min
completed: 2026-03-18
---

# Phase 1 Plan 01: Spirit + Observatory State Foundation Summary

**Zustand spirit-store and observatory-store with createSelectors — four typed files providing zero-render state foundation for all Phase 1 visual integrations**

## Performance

- **Duration:** ~2 min
- **Started:** 2026-03-18T21:30:02Z
- **Completed:** 2026-03-18T21:32:22Z
- **Tasks:** 2
- **Files modified:** 4 created

## Accomplishments

- Created `useSpiritStore` with SpiritKind (ember/tide/verdant/void/neutral), SpiritMood, fieldStrength 0.0-1.0, and accentColor hex; default unbound state renders zero CSS stain
- Created `useObservatoryStore` with stations array, seamSummary (stationCount/artifactCount/activeProbes), and aggregate artifact recomputation in setStations/addArtifacts; default zeros render no activity bar badge
- Both stores follow the exact `create + createSelectors` pattern from search-store.ts; TypeScript reports zero errors in new files

## Task Commits

Each task was committed atomically:

1. **Task 1: Create spirit types and spirit-store** - `6a054e0d3` (feat)
2. **Task 2: Create observatory types and observatory-store** - `75cc449f9` (feat)

## Files Created/Modified

- `apps/workbench/src/features/spirit/types.ts` - SpiritKind, SpiritMood, SpiritState types
- `apps/workbench/src/features/spirit/stores/spirit-store.ts` - useSpiritStore with bindSpirit/unbindSpirit/setMood/setFieldStrength actions
- `apps/workbench/src/features/observatory/types.ts` - ObservatoryStationKind, ObservatoryStation, ObservatorySeamSummary, ObservatoryState types
- `apps/workbench/src/features/observatory/stores/observatory-store.ts` - useObservatoryStore with setStations/updateSeamSummary/setConnected/addArtifacts actions

## Decisions Made

- Spirit store uses no-immer `create()` pattern (same as search-store) — state is simple flat objects, no deep nesting requires immer
- `SPIRIT_ACCENT_MAP` is a module-level constant not stored in state — it is derived/static, not user-controllable
- `bindSpirit` sets `fieldStrength: 1` and `mood: "active"` atomically in a single `set()` call to avoid transient partial state
- Observatory `setStations` recomputes `artifactCount` aggregate inline to keep `seamSummary` always consistent with `stations` array

## Deviations from Plan

None - plan executed exactly as written.

## Issues Encountered

None. Pre-existing TypeScript errors in unrelated files (missing @base-ui/react modules, react-syntax-highlighter) were present before this plan and are out of scope.

## User Setup Required

None - no external service configuration required.

## Next Phase Readiness

- `useSpiritStore` and `useObservatoryStore` are ready for import in Plan 02 (SpiritFieldInjector) and Plan 03 (ActivityBar badge)
- Both stores default to zero/null state — app renders identically to pre-Phase-1 until spirit bound or observatory data arrives
- No blockers for Plan 02 or Plan 03

## Self-Check: PASSED

- FOUND: apps/workbench/src/features/spirit/stores/spirit-store.ts
- FOUND: apps/workbench/src/features/spirit/types.ts
- FOUND: apps/workbench/src/features/observatory/stores/observatory-store.ts
- FOUND: apps/workbench/src/features/observatory/types.ts
- FOUND commit: 6a054e0d3
- FOUND commit: 75cc449f9

---
*Phase: 01-spirit-observatory-state-foundation*
*Completed: 2026-03-18*
