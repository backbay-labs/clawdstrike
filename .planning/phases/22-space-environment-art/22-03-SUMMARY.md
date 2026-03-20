---
phase: 22-space-environment-art
plan: "03"
subsystem: ui
tags: [three.js, r3f, wawa-vfx, shader, CatmullRomCurve3, TubeGeometry, particles, bloom]

# Dependency graph
requires:
  - phase: 22-01
    provides: OBSERVATORY_STATION_POSITIONS + buildLanePoints from observatory-world-template.ts
  - phase: 21
    provides: wawa-vfx VFXPools pattern (ObservatoryVFXPools, ShipThrusterVFX)
provides:
  - ObservatorySpaceLanes component — emissive TubeGeometry lanes with animated energy flow
  - lane-particle-stream VFX pool (600 particles, StretchBillboard)
  - ObservatoryTransitLayer updated to include space lanes
affects: [world-canvas, ObservatoryTransitLayer, ObservatoryVFXPools, future space art phases]

# Tech tracking
tech-stack:
  added: []
  patterns:
    - ShaderMaterial with dashOffset uniform for animated dash-offset tube energy flow
    - CatmullRomCurve3 + TubeGeometry for 3D lane rendering (reusing buildLanePoints from template)
    - VFXEmitter position updated each frame via curve.getPointAt(t) for streaming particles
    - toneMapped:false + AdditiveBlending on ShaderMaterial for bloom glow pipeline

key-files:
  created:
    - apps/workbench/src/features/observatory/components/world-canvas/ObservatorySpaceLanes.tsx
    - apps/workbench/src/features/observatory/__tests__/observatory-space-lanes.test.tsx
  modified:
    - apps/workbench/src/features/observatory/vfx/ObservatoryVFXPools.tsx
    - apps/workbench/src/features/observatory/components/world-canvas/ObservatoryTransitLayer.tsx

key-decisions:
  - "ShaderMaterial with GLSL dashOffset uniform chosen over LineDashedMaterial — enables smooth per-frame scroll on TubeGeometry UVs without a separate Line geometry"
  - "VFXEmitter position updated imperatively in useFrame via curve.getPointAt(t) — matches existing ShipThrusterVFX.tsx pattern"
  - "dashOffset per-lane offset (i * 2.1) staggers lane flow phase so not all lanes pulse together"
  - "t advances at delta * 0.4 so particles cycle in ~2.5s (matches 2s lifetime budget in pool settings)"

patterns-established:
  - "Lane streaming pattern: curve.getPointAt(t) in useFrame + emitter.position.copy(_emitPos) + startEmitting(false) per frame"
  - "toneMapped:false + AdditiveBlending + depthWrite:false on emissive ShaderMaterial for bloom compatibility"

requirements-completed: [SPC-05, SPC-06]

# Metrics
duration: ~3min
completed: 2026-03-20
---

# Phase 22 Plan 03: Space Environment Art — Space Lanes Summary

**Emissive CatmullRom TubeGeometry lanes connecting 4 station pairs with GLSL dash-offset energy flow animation and wawa-vfx StretchBillboard particle streams**

## Performance

- **Duration:** ~3 min
- **Started:** 2026-03-20T17:50:24Z
- **Completed:** 2026-03-20T17:53:31Z
- **Tasks:** 2
- **Files modified:** 4

## Accomplishments
- Added lane-particle-stream pool (600 particles, StretchBillboard, zero gravity) to ObservatoryVFXPools
- Created ObservatorySpaceLanes with 4 CatmullRomCurve3 TubeGeometry lanes (signal-targets, targets-run, run-receipts, receipts-case-notes)
- GLSL ShaderMaterial with dashOffset uniform scrolls at 3 units/s; toneMapped:false + AdditiveBlending for bloom glow
- VFXEmitter per lane streams particles along curve at ~20 units/s with 2s lifetime
- Wired into ObservatoryTransitLayer alongside existing coreLinks/transitLinks rendering
- All 195 observatory tests pass, no TypeScript errors

## Task Commits

Each task was committed atomically:

1. **Task 1: Lane particle stream VFX pool declaration** - `79645294d` (feat)
2. **Task 2 RED: Failing tests for ObservatorySpaceLanes** - `0b51c1883` (test)
3. **Task 2 GREEN: Implement ObservatorySpaceLanes** - `060e98ac4` (feat)

**Plan metadata:** (docs commit follows)

_Note: TDD task has separate RED (test) and GREEN (feat) commits per TDD protocol_

## Files Created/Modified
- `apps/workbench/src/features/observatory/components/world-canvas/ObservatorySpaceLanes.tsx` - New component: 4 CatmullRom TubeGeometry lanes with GLSL dash animation + VFX particles
- `apps/workbench/src/features/observatory/components/world-canvas/ObservatoryTransitLayer.tsx` - Added `<ObservatorySpaceLanes />` after existing transit route rendering
- `apps/workbench/src/features/observatory/vfx/ObservatoryVFXPools.tsx` - Added lane-particle-stream pool declaration
- `apps/workbench/src/features/observatory/__tests__/observatory-space-lanes.test.tsx` - Export + smoke test for ObservatorySpaceLanes

## Decisions Made
- ShaderMaterial with GLSL dashOffset uniform chosen over LineDashedMaterial — TubeGeometry UVs map cleanly and the fract() scroll is GPU-cheap
- Per-lane dashOffset offset (i * 2.1 radians) staggers phase so lanes feel independent
- t advances at delta * 0.4 per frame so particles take ~2.5s to cycle the full lane (matches 2s particle lifetime)
- Emission uses `startEmitting(false)` each frame at updated position (not loop=true) — imperative control matches ShipThrusterVFX.tsx pattern

## Deviations from Plan

None — plan executed exactly as written.

## Issues Encountered
None.

## User Setup Required
None — no external service configuration required.

## Next Phase Readiness
- Space lanes visually connect the 4 primary station pairs with glowing energy flow
- Particles stream along lane curves providing motion cues for navigation
- Ready for Phase 22 Plan 04 or additional space environment art passes

## Self-Check: PASSED

- FOUND: ObservatorySpaceLanes.tsx
- FOUND: ObservatoryTransitLayer.tsx (updated)
- FOUND: ObservatoryVFXPools.tsx (updated)
- FOUND: observatory-space-lanes.test.tsx
- FOUND: 22-03-SUMMARY.md
- FOUND: commits 79645294d, 0b51c1883, 060e98ac4
- 195 tests pass, 0 TypeScript errors

---
*Phase: 22-space-environment-art*
*Completed: 2026-03-20*
