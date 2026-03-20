---
phase: 24-space-flight-hud
plan: "02"
subsystem: hud
tags: [hud, projection, three, raf, dom-overlay, station-targeting]
dependency_graph:
  requires: [24-01]
  provides: [HUD-03, HUD-04, HUD-05]
  affects: [ObservatoryTab, ObservatoryWorldCanvas, SpaceFlightHud]
tech_stack:
  added: []
  patterns:
    - rAF+ref-mutation pattern for zero-React 60fps DOM updates
    - CSS custom property (--bracket-color) for dynamic L-corner bracket coloring
    - THREE.Matrix4.copy + Vector3.applyMatrix4 for NDC projection in DOM context
    - Module-level pre-allocated THREE scratch objects to avoid GC in rAF loop
key_files:
  created:
    - apps/workbench/src/features/observatory/components/hud/useHudProjection.ts
    - apps/workbench/src/features/observatory/components/hud/TargetBrackets.tsx
    - apps/workbench/src/features/observatory/components/hud/OffScreenArrows.tsx
    - apps/workbench/src/features/observatory/__tests__/space-flight-hud-projection.test.tsx
  modified:
    - apps/workbench/src/features/observatory/components/hud/SpaceFlightHud.tsx
    - apps/workbench/src/features/observatory/components/ObservatoryTab.tsx
    - apps/workbench/src/features/observatory/components/ObservatoryWorldCanvas.tsx
    - apps/workbench/src/features/observatory/__tests__/space-flight-hud.test.tsx
decisions:
  - "useHudProjection drives a single rAF loop updating a stable projectionsRef; TargetBrackets and OffScreenArrows each run their own rAF reading that ref — decoupled consumers"
  - "CSS custom property --bracket-color used for L-corner color changes without per-frame style string concatenation"
  - "Module-level _projVec and _viewProjectionMatrix scratch objects prevent GC pressure at 60fps"
  - "SpaceFlightHud visibility gates: mode=flow AND characterControllerEnabled AND !flyByActive AND !replay.enabled"
  - "space-flight-hud.test.tsx mocks useHudProjection to prevent observatory-world-template CatmullRomCurve3 import chain breaking the mocked THREE.Vector3"
metrics:
  duration: ~7min
  completed_date: "2026-03-20"
  tasks: 2
  files: 8
---

# Phase 24 Plan 02: Space Flight HUD Projection Elements Summary

Target brackets (L-corner markers), off-screen directional arrows, and distance readouts wired into SpaceFlightHud via a unified rAF-based projection hook — 60fps spatial awareness without a single React re-render.

## What Was Built

### Task 1: Projection hook + bracket + arrow components

**useHudProjection** — single rAF loop that computes per-frame screen-space projections for all 6 stations using `hudCameraRef.current` (camera matrices from HudCameraBridge). Pre-allocated module-level `_projVec` and `_viewProjectionMatrix` eliminate GC pressure. Reads store via `getState()`. Writes into a stable `projectionsRef` consumed by TargetBrackets and OffScreenArrows.

Key projection math:
- `_viewProjectionMatrix.copy(projectionMatrix).multiply(matrixWorldInverse)`
- `_projVec.applyMatrix4(_viewProjectionMatrix)` → NDC
- NDC to screen pixels, behind-camera coord flip, edge-clamping, arrowRotation via `atan2`
- `bracketSize = clamp(800/distance, 24, 80)` — inverse-distance scaling
- `distanceOpacity = clamp((500-distance)/400, 0, 1)` — fade in on approach

**TargetBrackets** — 6 pre-rendered bracket containers, each with 4 corner divs forming an L-corner bracket. Color via CSS custom property `--bracket-color`: green (#3dbf84) default, gold (#f4d982) selected/mission target, cyan (#5ab4f0) docked. CSS keyframe `hudBracketPulse` applied via classList for mission targets. Distance readout spans with `distanceOpacity` fade.

**OffScreenArrows** — 6 pre-rendered arrow containers, each with an SVG triangle (rotated by `arrowRotation`), station name label, and distance label. `filter: drop-shadow(0 0 4px rgba(0,0,0,0.8))` for nebula visibility. Arrow fill color matches station colorHex.

### Task 2: Full HUD wiring

**SpaceFlightHud** updated to call `useHudProjection(containerRef)` and pass `projectionsRef` to both `TargetBrackets` and `OffScreenArrows`. Placeholder divs from Plan 01 replaced with real components.

**ObservatoryWorldCanvas** mounts `<HudCameraBridge />` inside the Canvas tree (before scene content, before `ObservatoryInvalidationController`) so camera matrices are fresh each frame.

**ObservatoryTab** mounts `<SpaceFlightHud visible={...} />` as a sibling after the Canvas div (inside the relative container, before letterbox bars, z-index 15). Visibility gate: `!flyByActive && !replay.enabled && characterControllerEnabled && mode === "flow"`.

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 1 - Bug] space-flight-hud.test.tsx: THREE.Vector3 mock missing distanceToSquared**

- **Found during:** Task 2 — after SpaceFlightHud imported useHudProjection which triggered observatory-world-template.ts import at module init time, calling CatmullRomCurve3.getPoints which requires Vector3.distanceToSquared
- **Issue:** Mocked Vector3 in existing test only had `copy`, `set` methods — CatmullRomCurve3 called `distanceToSquared` at module scope
- **Fix:** Added `vi.mock` for `useHudProjection` and `camera-bridge` in space-flight-hud.test.tsx to break the import chain before it reaches observatory-world-template.ts
- **Files modified:** apps/workbench/src/features/observatory/__tests__/space-flight-hud.test.tsx
- **Commit:** bd4a27a5d

## Test Results

- `space-flight-hud.test.tsx`: 10 tests passed (SpaceFlightHud shell + SpeedIndicator + HeadingCompass)
- `space-flight-hud-projection.test.tsx`: 8 tests passed (TargetBrackets structure + OffScreenArrows structure)
- Full observatory suite: 213 tests passed, 0 regressions

## Self-Check

All files confirmed present. All commits confirmed in git log.

## Self-Check: PASSED

- All 8 files (4 created, 4 modified) confirmed on disk
- Commits 00aa3d733 and bd4a27a5d confirmed in git log
- 213 observatory tests passing
