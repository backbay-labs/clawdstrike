---
phase: 09-nexus-force-graph
plan: "01"
subsystem: ui
tags: [r3f-forcegraph, react-three-fiber, three, force-directed-graph, nexus, zustand]

# Dependency graph
requires:
  - phase: 04-nexus-strikecell-overlay
    provides: StrikecellConnection type, DEMO_STRIKECELLS, STRIKECELL_ROUTE_MAP, NexusTab, nexus-store
provides:
  - r3f-forcegraph@1.1.1 installed (three >=0.154 peer dep, compatible with ^0.170.0)
  - DEMO_CONNECTIONS: 13 StrikecellConnection entries covering all 9 strikecell domains
  - nexus-store connections slice: connections: StrikecellConnection[] + setConnections action
  - NexusForceCanvas: standalone R3F Canvas with force-directed graph, OrbitControls, click-to-navigate
affects:
  - 09-nexus-force-graph/09-02 (NexusTab will conditionally mount NexusForceCanvas)

# Tech tracking
tech-stack:
  added: [r3f-forcegraph@1.1.1]
  patterns:
    - Force graph data shape: nodes[] with {id, color, val} + links[] with {source, target, value}
    - DOMAIN_COLOR map: StrikecellDomainId -> hex color (sentinel/oracle/witness/specter palette)
    - ForceGraph props typed via GraphProps generic with eslint-disable-next-line for any-typed ref

key-files:
  created:
    - apps/workbench/src/features/nexus/components/NexusForceCanvas.tsx
  modified:
    - apps/workbench/package.json
    - bun.lockb
    - apps/workbench/src/features/nexus/types.ts
    - apps/workbench/src/features/nexus/stores/nexus-store.ts

key-decisions:
  - "r3f-forcegraph@1.1.1 peer deps verified: { react: '*', three: '>=0.154' } — no R3F version constraint, compatible with three ^0.170.0"
  - "r3f-forcegraph@1.1.1 does not expose onNodeDrag/onNodeDragEnd in its typed API — drag-pin behavior omitted; OrbitControls handle camera manipulation"
  - "ForceGraph ref uses any-typed MutableRefObject + eslint-disable to bypass FCwithRef generic inference complexity; type-safe at component boundary"
  - "nodeLabel prop not in GraphProps types — removed; node identification handled by color coding"

patterns-established:
  - "NexusForceCanvas: self-contained R3F Canvas (not root Canvas + drei View) — consistent with SpiritCompanionCanvas and ObservatoryWorldCanvas patterns"
  - "graphData memo: derived from strikecells + connections stores, recomputes only on store changes"

requirements-completed: [NXS-02]

# Metrics
duration: 10min
completed: 2026-03-19
---

# Phase 09 Plan 01: Nexus Force Graph Foundation Summary

**r3f-forcegraph@1.1.1 installed with 13 DEMO_CONNECTIONS, nexus-store connections slice, and NexusForceCanvas — standalone R3F Canvas with force-directed layout, DOMAIN_COLOR palette, and click-to-navigate via STRIKECELL_ROUTE_MAP**

## Performance

- **Duration:** ~10 min
- **Started:** 2026-03-19T14:10:00Z
- **Completed:** 2026-03-19T14:20:17Z
- **Tasks:** 2
- **Files modified:** 4 (package.json, bun.lockb, types.ts, nexus-store.ts) + 1 created (NexusForceCanvas.tsx)

## Accomplishments
- Verified r3f-forcegraph peer deps (`{ react: '*', three: '>=0.154' }`), installed@1.1.1
- Added 13 DEMO_CONNECTIONS covering all 9 strikecell domains with mixed kinds (data-flow, dependency, related) and strength 0.3–1.0
- Extended nexus-store with `connections: StrikecellConnection[]` seeded from DEMO_CONNECTIONS + `setConnections` action
- Created NexusForceCanvas: standalone R3F Canvas with OrbitControls, force-directed graph, DOMAIN_COLOR palette, and click-to-navigate routing
- All 2 existing NexusTab tests pass; zero new TypeScript errors in nexus feature files

## Task Commits

Each task was committed atomically:

1. **Task 1: Peer dep check + install r3f-forcegraph + author DEMO_CONNECTIONS** - `17972f2cb` (feat)
2. **Task 2: Add connections to nexus-store + create NexusForceCanvas** - `e9e97de02` (feat)

## Files Created/Modified
- `apps/workbench/package.json` - Added r3f-forcegraph@^1.1.1 dependency
- `bun.lockb` - Updated lockfile
- `apps/workbench/src/features/nexus/types.ts` - Added DEMO_CONNECTIONS: 13 StrikecellConnection[]
- `apps/workbench/src/features/nexus/stores/nexus-store.ts` - Added connections slice + setConnections action
- `apps/workbench/src/features/nexus/components/NexusForceCanvas.tsx` - New: force graph canvas component

## Decisions Made
- r3f-forcegraph@1.1.1 peer dep verified compatible; installed without conflicts against three ^0.170.0 and @react-three/fiber ^9
- r3f-forcegraph@1.1.1 `onNodeDrag`/`onNodeDragEnd` are absent from the typed API (only in three-forcegraph). Drag-pin deferred. OrbitControls provide camera manipulation.
- `nodeLabel` is not in `GraphProps` types; removed from component. Node identity communicated via DOMAIN_COLOR.
- ForceGraph ref uses `any`-typed `MutableRefObject` with `eslint-disable-next-line` to bypass the complex `FCwithRef` generic inference — component boundary remains type-safe.

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 1 - Bug] r3f-forcegraph API differs from plan spec — nodeLabel absent, onNodeDrag absent**
- **Found during:** Task 2 (NexusForceCanvas creation)
- **Issue:** Plan spec listed `nodeLabel` and `onNodeDrag`/`onNodeDragEnd` props, but r3f-forcegraph@1.1.1 types (`GraphProps`) do not include these — `nodeLabel` is not in the typed interface; drag events are absent entirely.
- **Fix:** Removed `nodeLabel` prop (not supported). Omitted drag-pin handlers (library doesn't expose them). Used `eslint-disable` for ref typing to avoid FCwithRef generic complexity.
- **Files modified:** NexusForceCanvas.tsx
- **Verification:** TypeScript reports zero errors in nexus feature files; existing nexus-tab tests pass
- **Committed in:** e9e97de02 (Task 2 commit)

---

**Total deviations:** 1 auto-fixed (Rule 1 - API mismatch)
**Impact on plan:** Core functionality (force-directed layout, OrbitControls, click-to-navigate, DOMAIN_COLOR palette) delivered as specified. Drag-pin deferred pending r3f-forcegraph API support.

## Issues Encountered
- r3f-forcegraph@1.1.1 TypeScript types (`FCwithRef` generic function) caused complex inference issues with `ref` prop. Resolved with `as any` cast on ForceGraph props with eslint-disable comment.

## User Setup Required
None - no external service configuration required.

## Next Phase Readiness
- NexusForceCanvas.tsx ready for conditional mounting in NexusTab (plan 09-02)
- nexus-store `connections` slice ready for plan 09-02 to wire to NexusTab view toggle
- Existing NexusTab (atlas/Observatory mode) unaffected — plan 09-02 adds force-graph as second view mode

---
*Phase: 09-nexus-force-graph*
*Completed: 2026-03-19*
