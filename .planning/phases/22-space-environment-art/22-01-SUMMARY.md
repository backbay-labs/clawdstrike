---
phase: 22-space-environment-art
plan: "01"
subsystem: ui
tags: [three.js, r3f, glsl, shaders, starfield, observatory, space, fog]

# Dependency graph
requires:
  - phase: 21-flight-controller
    provides: ObservatoryFlowRuntimeScene, SpaceFlightController, 300-unit world radius
  - phase: 20-spatial-foundation
    provides: WORLD_RADIUS, station positions, ObservatoryWorldScene
provides:
  - starNest.glsl — Star Nest Shadertoy port for volumetric procedural star background
  - ObservatoryStarfield component — 3-layer cinematic starfield (shader sphere + 15K instanced stars + Sparkles)
  - FogExp2 density 0.0008 replacing linear fog in ObservatoryWorldScene
affects:
  - 22-space-environment-art (nebula, lanes layers build on top of this starfield)
  - observatory visual foundation

# Tech tracking
tech-stack:
  added: []
  patterns:
    - inline GLSL ShaderMaterial in TSX (no ?raw import needed)
    - BackSide sphere + depthWrite:false for background layers rendering behind scene geometry
    - InstancedMesh with useMemo pre-computed matrices for high-count star distribution
    - dual-hemisphere distribution for uniform 3D star coverage
    - FogExp2 for space-appropriate exponential depth fade vs linear fog

key-files:
  created:
    - apps/workbench/src/features/observatory/shaders/starNest.glsl
    - apps/workbench/src/features/observatory/components/world-canvas/ObservatoryStarfield.tsx
    - apps/workbench/src/features/observatory/__tests__/observatory-starfield.test.tsx
  modified:
    - apps/workbench/src/features/observatory/components/world-canvas/ObservatoryWorldScene.tsx

key-decisions:
  - "Star Nest shader inlined as template literal in ObservatoryStarfield.tsx (avoids ?raw Vite import complexity in tests)"
  - "FogExp2 density 0.0008 chosen — stations visible ~500 units, geometry fades at 800+ per plan spec"
  - "Mid-field star distribution uses dual hemisphere technique (2x7500 at radii 800-1600) for uniform coverage"
  - "depthWrite:false and depthTest:false on far shader sphere ensures it renders behind all scene geometry"
  - "renderOrder:-1000 on shader sphere ensures correct draw order relative to scene elements"

patterns-established:
  - "Background layers: renderOrder negative + depthWrite:false + depthTest:false for correct z-ordering"
  - "15K InstancedMesh stars initialized via onUpdate callback with pre-computed Matrix4 array"
  - "GLSL shader uniforms animated via useFrame delta accumulation (time uniform)"

requirements-completed: [SPC-02, SPC-04]

# Metrics
duration: 3min
completed: 2026-03-20
---

# Phase 22 Plan 01: Space Environment Art Summary

**3-layer cinematic deep-space starfield (Star Nest shader sphere + 15K instanced mid-field stars + Sparkles dust) with FogExp2 depth fade replacing linear fog in ObservatoryWorldScene**

## Performance

- **Duration:** ~3 min
- **Started:** 2026-03-20T17:43:55Z
- **Completed:** 2026-03-20T17:47:02Z
- **Tasks:** 2
- **Files modified:** 4

## Accomplishments
- Star Nest GLSL fragment shader (Shadertoy XlfGRj port) with volsteps=15, brightness=0.003, saturation=0.65 — subtle volumetric procedural star background
- ObservatoryStarfield component with all 3 layers: far BackSide shader sphere (depthWrite:false), 15K instanced mid-field stars (dual-hemisphere distribution, 800-1600 unit radius), and drei Sparkles near-dust parallax
- FogExp2(0.0008, #060a14) replaces linear fog — exponential fade appropriate for deep space; drei Stars removed from scene
- TDD flow: test→commit→implement→pass; all 193 observatory tests pass with no regressions

## Task Commits

Each task was committed atomically:

1. **Test: Star Nest GLSL + ObservatoryStarfield (TDD RED)** - `3866d5f4d` (test)
2. **Task 1: Star Nest GLSL shader + 3-layer ObservatoryStarfield** - `477c6b25a` (feat)
3. **Task 2: Wire ObservatoryStarfield into scene + FogExp2** - `83abcbc2f` (feat)

## Files Created/Modified
- `apps/workbench/src/features/observatory/shaders/starNest.glsl` - Star Nest Shadertoy port, volsteps=15, brightness=0.003
- `apps/workbench/src/features/observatory/components/world-canvas/ObservatoryStarfield.tsx` - 3-layer starfield: ShaderMaterial sphere, 15K InstancedMesh, Sparkles
- `apps/workbench/src/features/observatory/__tests__/observatory-starfield.test.tsx` - Smoke tests for export, render, and GLSL file presence
- `apps/workbench/src/features/observatory/components/world-canvas/ObservatoryWorldScene.tsx` - Stars removed, ObservatoryStarfield added, fogExp2 replaces linear fog

## Decisions Made
- Inlined GLSL as a template literal in the TSX component rather than using Vite's `?raw` import — avoids test environment import issues and keeps the component self-contained
- FogExp2 density 0.0008 per plan spec (stations visible ~500 units, geometry fades at 800+)
- The `renderOrder={-1000}` on the shader sphere guarantees it draws behind all scene elements even though depthTest:false is set

## Deviations from Plan

**Minor adaptation:** ObservatoryWorldScene.tsx already had `ObservatoryNebulaClouds` added by a concurrent plan (phase 22 nebula work had begun). This import was preserved — it was not in the original plan's view of the file but is not a conflict. The Stars removal and fogExp2 addition were applied cleanly around this existing addition.

---

**Total deviations:** 0 auto-fixes required. Minor file state difference preserved correctly.
**Impact on plan:** None — all acceptance criteria met exactly as specified.

## Issues Encountered
None — implementation proceeded cleanly. The GLSL-as-template-literal approach sidestepped the `?raw` import pattern for test compatibility.

## Next Phase Readiness
- 3-layer starfield is the visual foundation for Phase 22 plans 02+ (nebula, lane particles)
- FogExp2 density can be tuned per-mode if needed — currently a flat #060a14/0.0008
- The star shader `time` uniform animates automatically via useFrame; no external clock needed

---
*Phase: 22-space-environment-art*
*Completed: 2026-03-20*
