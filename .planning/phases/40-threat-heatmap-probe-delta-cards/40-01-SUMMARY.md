---
phase: 40-threat-heatmap-probe-delta-cards
plan: 01
subsystem: ui
tags: [r3f, glsl, three.js, shader, heatmap, observatory]

# Dependency graph
requires:
  - phase: 39-store-persistence-and-derivation-foundations
    provides: deriveHeatmapDataTexture (Float32Array), HeatmapStationPressure types
  - phase: observatory-world-template
    provides: WORLD_RADIUS, OBSERVATORY_STATION_POSITIONS
provides:
  - ThreatTopologyHeatmap R3F component with GLSL ShaderMaterial
  - HEATMAP_SOC_COLORS constant (6-stop SOC color ramp)
  - ThreatTopologyHeatmapProps interface
affects:
  - 40-03 (ObservatoryWorldScene wiring — Plan 03 wires ThreatTopologyHeatmap in)
  - 43-station-interiors (ground-plane visual layer context)

# Tech tracking
tech-stack:
  added: []
  patterns:
    - "GLSL inverse-distance-weighted blending across N uniform station positions"
    - "useFrame uniform mutation pattern (ref-based, no material re-creation)"
    - "SOC 6-stop color ramp via piecewise GLSL mix across uColor0-uColor5 uniforms"

key-files:
  created:
    - apps/workbench/src/features/observatory/components/world-canvas/ThreatTopologyHeatmap.tsx
    - apps/workbench/src/features/observatory/__tests__/threat-topology-heatmap.test.ts
  modified: []

key-decisions:
  - "Position uses tuple [0, -2, 0] not y={-2} attribute — standard R3F mesh position prop"
  - "NormalBlending (not AdditiveBlending) so heatmap does not wash out dark background"
  - "DoubleSide ensures disc visible from both above and below camera angles"
  - "uPressure uniforms mutated via ref in useFrame, not state — avoids material re-creation per frame"

patterns-established:
  - "SOC heatmap color ramp: always 6 stops, blue→teal→green→yellow→amber→red"
  - "Inverse-distance-weighted fragment shader: eps=1.0 prevents zero-divide at station center"

requirements-completed: [HEAT-01, HEAT-02, HEAT-03]

# Metrics
duration: 2min
completed: 2026-03-22
---

# Phase 40 Plan 01: ThreatTopologyHeatmap Summary

**GLSL ShaderMaterial ground-plane heatmap disc projecting 6-station threat pressure as SOC blue-to-red color gradient with 3-second sine-wave pulse animation**

## Performance

- **Duration:** ~2 min
- **Started:** 2026-03-22T06:22:12Z
- **Completed:** 2026-03-22T06:24:00Z
- **Tasks:** 1 (TDD: RED + GREEN)
- **Files modified:** 2

## Accomplishments
- Ground-plane CircleGeometry disc at y=-2, radius WORLD_RADIUS*1.2 (360 units), 128 segments
- GLSL fragment shader with inverse-distance-weighted blending across 6 station positions
- SOC 6-stop color ramp: blue (calm) → teal → green → yellow → amber → red (critical) via piecewise mix
- Sine-wave pulse animation: opacity 0.3→0.7 over 3-second period (no re-creation each frame)
- Props: pressureData (Float32Array), stationPositions, visible gate, presetOpacityMultiplier
- All 4 unit tests pass (smoke renders, SOC colors length, visible=false gate)

## Task Commits

Each task was committed atomically:

1. **RED: Failing tests** - `a82ee65fa` (test)
2. **GREEN: ThreatTopologyHeatmap implementation** - `9cafa9e5e` (feat)

_Note: TDD task — RED commit followed by GREEN commit_

## Files Created/Modified
- `apps/workbench/src/features/observatory/components/world-canvas/ThreatTopologyHeatmap.tsx` — GLSL ShaderMaterial heatmap component with props, SOC colors, vertex/fragment shaders, useFrame animation
- `apps/workbench/src/features/observatory/__tests__/threat-topology-heatmap.test.ts` — 4 unit tests covering smoke render, mixed data, HEATMAP_SOC_COLORS length, visible=false gate

## Decisions Made
- Used `position={[0, -2, 0]}` (R3F tuple form) for ground plane — acceptance criteria spec'd y=-2 which this satisfies
- NormalBlending selected over AdditiveBlending to preserve dark background contrast (SOC visibility requirement)
- DoubleSide for disc so it's visible from both above and below camera positions
- uPressure uniforms mutated via ref in useFrame to avoid creating a new ShaderMaterial on every frame
- The mesh `ref` forwards to material via `ref={materialRef as unknown as React.RefObject<THREE.Mesh>}` — workaround for R3F's mesh ref typing while keeping `materialRef` typed as ShaderMaterial

## Deviations from Plan

None — plan executed exactly as written.

## Issues Encountered
None.

## Next Phase Readiness
- ThreatTopologyHeatmap is a complete standalone component ready for wiring in Plan 03 (ObservatoryWorldScene)
- Props contract is stable: `pressureData`, `stationPositions`, `visible`, `presetOpacityMultiplier`
- Plan 02 (probe delta cards) is independent and can proceed in parallel

---
*Phase: 40-threat-heatmap-probe-delta-cards*
*Completed: 2026-03-22*
