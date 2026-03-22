---
phase: 37-analyst-preset-overlays
plan: 02
subsystem: ui
tags: [react-three-fiber, three.js, r3f, observatory, analyst-presets, tdd, vitest]

requires:
  - phase: 37-analyst-preset-overlays
    plan: 01
    provides: "ThreatPresetOverlay, EvidencePresetOverlay, ReceiptsPresetOverlay components from Plan 01"
  - phase: 35-ghost-trace-markers
    provides: "ghostOpacityScale pattern and ghostTraces prop already wired in ObservatoryWorldCanvas"

provides:
  - "GhostPresetOverlay: replaces ambientLight with 40% dim + cool #1a1a2e desaturation tint when GHOST preset active"
  - "getGhostAmbientIntensity: pure helper (baseIntensity * 0.6) — unit tested"
  - "ObservatoryWorldScene: conditionally mounts all four preset overlays gated on analystPresetId prop"
  - "ObservatoryWorldSceneProps.analystPresetId: new optional field wired from ObservatoryWorldCanvas"
  - "APR-05 instant restore: React conditional render ensures zero-frame delay on preset deactivation"

affects:
  - ObservatoryWorldCanvas (passes analystPresetId={analystPresetIdOuter} to scene)
  - ObservatoryWorldScene (conditional overlay rendering logic)
  - observatory-world-scene-types (new prop field)

tech-stack:
  added: []
  patterns:
    - "GHOST preset replaces (not supplements) the base ambientLight via ternary — caller owns light lifecycle"
    - "TDD: RED (failing import of non-existent GhostPresetOverlay) → GREEN (implement) → 24 tests passing"
    - "React conditional render with null (not undefined) for preset-inactive branches — idiomatic unmount pattern"
    - "analystPresetIdOuter already read from store in ObservatoryWorldCanvas — scene is pure presentational layer"

key-files:
  created:
    - apps/workbench/src/features/observatory/components/GhostPresetOverlay.tsx
  modified:
    - apps/workbench/src/features/observatory/components/world-canvas/observatory-world-scene-types.ts
    - apps/workbench/src/features/observatory/components/world-canvas/ObservatoryWorldScene.tsx
    - apps/workbench/src/features/observatory/components/ObservatoryWorldCanvas.tsx
    - apps/workbench/src/features/observatory/__tests__/analyst-preset-overlays.test.ts

key-decisions:
  - "GhostPresetOverlay renders two additive ambientLights: dimmed base color + dark-blue #1a1a2e tint at 15% base — the cool tint desaturates scene colors without a post-processing pass"
  - "GHOST ternary replaces ambientLight rather than adding on top — prevents double-lighting artifacts when preset is active"
  - "analystPresetId prop added to ObservatoryWorldSceneProps as optional with null default — backward compatible, no callers need updating except ObservatoryWorldCanvas"
  - "APR-05 (instant neutral restore) implemented for free by React conditional render — no animation/transition needed"

requirements-completed:
  - APR-04
  - APR-05

duration: 3min
completed: 2026-03-22
---

# Phase 37 Plan 02: Analyst Preset Overlays — GhostPresetOverlay + World Scene Wiring Summary

**GhostPresetOverlay with 40%-dim ambient + cool desaturation tint, wired alongside ThreatPresetOverlay/EvidencePresetOverlay/ReceiptsPresetOverlay into ObservatoryWorldScene behind analystPresetId conditional rendering — all five APR requirements complete**

## Performance

- **Duration:** 3 min
- **Started:** 2026-03-22T23:31:16Z
- **Completed:** 2026-03-22T23:34:19Z
- **Tasks:** 2
- **Files modified:** 5 (1 created, 4 modified)

## Accomplishments

- `GhostPresetOverlay.tsx` created with `getGhostAmbientIntensity(base * 0.6)` pure helper and two additive ambientLights (APR-04)
- `ObservatoryWorldSceneProps` extended with `analystPresetId?: ObservatoryAnalystPresetId | null` — backward compatible
- `ObservatoryWorldScene` now conditionally renders GHOST (replaces ambientLight), THREAT, EVIDENCE, RECEIPTS overlays in one-frame React unmount pattern (APR-05)
- `ObservatoryWorldCanvas` passes `analystPresetId={analystPresetIdOuter}` — already reading from store via Phase 37 Plan 01 setup
- 3 new unit tests for `getGhostAmbientIntensity` added — 24 total passing (21 from Plan 01 + 3 new)
- TypeScript compiles with zero errors

## Task Commits

Each task was committed atomically:

1. **Task 1: GhostPresetOverlay + tests** - `ed693ce8d` (feat)
2. **Task 2: Wire all overlays into ObservatoryWorldScene** - `f7a8100da` (feat)

## Files Created/Modified

- `apps/workbench/src/features/observatory/components/GhostPresetOverlay.tsx` — GHOST preset ambient dim component with pure helper (APR-04)
- `apps/workbench/src/features/observatory/components/world-canvas/observatory-world-scene-types.ts` — Added `analystPresetId` field to `ObservatoryWorldSceneProps`
- `apps/workbench/src/features/observatory/components/world-canvas/ObservatoryWorldScene.tsx` — 4 imports + 4 conditional overlay renders (8 PresetOverlay references)
- `apps/workbench/src/features/observatory/components/ObservatoryWorldCanvas.tsx` — Passes `analystPresetId={analystPresetIdOuter}` to scene
- `apps/workbench/src/features/observatory/__tests__/analyst-preset-overlays.test.ts` — 3 new tests for `getGhostAmbientIntensity`

## Decisions Made

- GhostPresetOverlay renders two additive lights: dimmed base color + `#1a1a2e` dark-blue tint at 15% base intensity for cool desaturation effect without a post-processing pass
- GHOST ternary replaces the base `ambientLight` rather than adding on top — prevents double-lighting artifacts
- `analystPresetId` prop defaults to `null` — all existing callers work without changes
- APR-05 (instant neutral restore) is free — React conditional render with `null` ensures all overlay components unmount in one render cycle

## Deviations from Plan

None — plan executed exactly as written.

## Self-Check: PASSED

- `apps/workbench/src/features/observatory/components/GhostPresetOverlay.tsx` FOUND
- Commits `ed693ce8d` and `f7a8100da` FOUND in git log
- TypeScript: 0 errors
- Tests: 24/24 passing
