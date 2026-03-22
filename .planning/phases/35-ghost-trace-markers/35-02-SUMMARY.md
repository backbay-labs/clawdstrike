---
phase: 35-ghost-trace-markers
plan: 02
subsystem: ui
tags: [r3f, observatory, ghost-traces, analyst-preset, opacity-gating]

requires:
  - phase: 35-ghost-trace-markers plan-01
    provides: GhostTraceLayer component with GhostTraceLayerProps interface
  - phase: prior-observatory-store
    provides: analystPresetId in useObservatoryStore state

provides:
  - GhostTraceLayer mounted in ObservatoryWorldScene R3F scene tree
  - GHOST analyst preset drives full opacity (1.0); all others dim to 20%
  - ghostTraces threaded from ObservatoryWorldCanvas prop to scene without new store reads
affects:
  - future analyst preset plans that add new overlay layers

tech-stack:
  added: []
  patterns:
    - Derive scalar (ghostOpacityScale) from store state in outer component, pass down as prop — avoids inner component store subscription
    - Optional props with defaults on destructure (ghostTraces=[], ghostOpacityScale=0.2) for backward compat

key-files:
  created: []
  modified:
    - apps/workbench/src/features/observatory/components/world-canvas/observatory-world-scene-types.ts
    - apps/workbench/src/features/observatory/components/world-canvas/ObservatoryWorldScene.tsx
    - apps/workbench/src/features/observatory/components/ObservatoryWorldCanvas.tsx

key-decisions:
  - "analystPresetIdOuter === 'ghost' ? 1.0 : 0.2 handles null preset correctly (null !== 'ghost' → 0.2)"
  - "ghostOpacityScale derived in outer ObservatoryWorldCanvas rather than inner scene to co-locate store read with other derived values"

patterns-established:
  - "ghostOpacityScale pattern: derive scalar from store in outer canvas, pass as prop to scene — reusable for future analyst presets"

requirements-completed: [GHO-03, GHO-04]

duration: 5min
completed: 2026-03-22
---

# Phase 35 Plan 02: Ghost Trace Markers Summary

**GhostTraceLayer wired into ObservatoryWorldScene with analystPresetId==="ghost" driving 1.0 opacity and all other states dimmed to 0.2 via prop threading from ObservatoryWorldCanvas**

## Performance

- **Duration:** 5 min
- **Started:** 2026-03-22T17:10:00Z
- **Completed:** 2026-03-22T17:15:00Z
- **Tasks:** 2
- **Files modified:** 3

## Accomplishments

- `ObservatoryWorldSceneProps` extended with `ghostTraces?: ObservatoryGhostTrace[]` and `ghostOpacityScale?: number` (import added for ObservatoryGhostTrace)
- `ObservatoryWorldScene` destructures both new props with defaults (`[]` and `0.2`) and mounts `<GhostTraceLayer traces={ghostTraces} opacityScale={ghostOpacityScale} />` immediately after `<ObservatoryDistrictLayer />`
- `ObservatoryWorldCanvas` reads `analystPresetId` from observatory store and derives `ghostOpacityScale = analystPresetIdOuter === "ghost" ? 1.0 : 0.2`
- Both `ghostTraces` (existing prop already on ObservatoryWorldCanvas) and `ghostOpacityScale` threaded to `ExtractedObservatoryWorldScene` — zero new store reads inside the scene
- Full TypeScript clean build, zero new errors

## Task Commits

1. **Task 1: Extend scene types + mount GhostTraceLayer** - `d7061d9fd` (feat)
2. **Task 2: Wire ghostOpacityScale from analystPresetId** - `d7061d9fd` (combined in same commit)

## Files Created/Modified

- `apps/workbench/src/features/observatory/components/world-canvas/observatory-world-scene-types.ts` - Added ghostTraces? and ghostOpacityScale? to ObservatoryWorldSceneProps; added ObservatoryGhostTrace import
- `apps/workbench/src/features/observatory/components/world-canvas/ObservatoryWorldScene.tsx` - Added GhostTraceLayer import; destructured ghostTraces/ghostOpacityScale; mounted GhostTraceLayer after ObservatoryDistrictLayer
- `apps/workbench/src/features/observatory/components/ObservatoryWorldCanvas.tsx` - Added analystPresetIdOuter store read; derived ghostOpacityScale; passed both to ExtractedObservatoryWorldScene

## Decisions Made

- Derived `ghostOpacityScale` in the outer `ObservatoryWorldCanvas` component (not inside the R3F scene) to co-locate store reads with other derived values like `speedTierOuter`. This keeps the inner scene as a pure presentational layer.
- `null !== "ghost"` evaluates to `0.2` correctly — no null-handling needed.

## Deviations from Plan

None - plan executed exactly as written.

## Issues Encountered

None.

## Next Phase Readiness

All four GHO requirements are now fully satisfied:
- GHO-01: translucent holographic markers at station positions (GhostTraceLayer, 35-01)
- GHO-02: sphere/octahedron glyphs by sourceKind (GhostTraceLayer, 35-01)
- GHO-03: GHOST preset drives full/dim opacity via ghostOpacityScale (this plan)
- GHO-04: data from existing ghostTraces prop, no new data fetching (this plan)

Phase 35 complete. No blocking issues for Phase 36.

---
*Phase: 35-ghost-trace-markers*
*Completed: 2026-03-22*
