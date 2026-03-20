---
phase: 22-space-environment-art
plan: "02"
subsystem: ui
tags: [react-three-fiber, drei, three.js, billboard, nebula, AdditiveBlending, postprocessing, bloom]

# Dependency graph
requires:
  - phase: 20-spatial-foundation
    provides: OBSERVATORY_STATION_POSITIONS, HUNT_STATION_ORDER, WORLD_RADIUS
  - phase: 21-flight-controller
    provides: ObservatoryWorldScene as scene host
provides:
  - Billboard nebula cloud patches colored per station with AdditiveBlending
  - Station-colored PointLights for bloom glow interaction
  - ObservatoryNebulaClouds component wired into ObservatoryWorldScene
affects: [22-space-environment-art, flight approach visual polish]

# Tech tracking
tech-stack:
  added: []
  patterns:
    - mulberry32 seeded PRNG for deterministic per-station patch placement
    - Canvas2D radial gradient texture built at init time via useMemo (no external PNG assets)
    - AdditiveBlending + depthWrite=false + toneMapped=false for ethereal cloud look

key-files:
  created:
    - apps/workbench/src/features/observatory/components/world-canvas/ObservatoryNebulaClouds.tsx
    - apps/workbench/src/features/observatory/__tests__/observatory-nebula-clouds.test.tsx
  modified:
    - apps/workbench/src/features/observatory/components/world-canvas/ObservatoryWorldScene.tsx

key-decisions:
  - "HUNT_STATION_ORDER used (all 6 stations) instead of HUNT_PRIMARY_STATION_ORDER (5) so watch station also gets nebula clouds"
  - "Patch positions use separate mulberry32 PRNG streams (seed + index * 7919) to avoid correlation between patches"
  - "Procedural Canvas2D radial gradient avoids external PNG asset dependency"

patterns-established:
  - "Billboard nebula patches: PlaneGeometry + MeshBasicMaterial with AdditiveBlending + depthWrite=false + toneMapped=false"
  - "Per-station point lights at station world position for bloom-driven glow"

requirements-completed: [SPC-03]

# Metrics
duration: 7min
completed: 2026-03-20
---

# Phase 22 Plan 02: Space Environment Art — Nebula Clouds Summary

**Billboard nebula cloud patches near all 6 stations via drei Billboard + AdditiveBlending + procedural Canvas2D gradient textures, with colored PointLights for bloom glow**

## Performance

- **Duration:** ~7 min
- **Started:** 2026-03-20T17:43:55Z
- **Completed:** 2026-03-20T17:51:00Z
- **Tasks:** 2 (+ TDD RED commit)
- **Files modified:** 3

## Accomplishments
- ObservatoryNebulaClouds component generating 3 billboard cloud patches per station (18 total across 6 stations)
- Station-colored PointLights (intensity=2.0, distance=60, decay=2) feed the bloom pipeline for ethereal glow
- Deterministic mulberry32 PRNG ensures consistent patch positions/rotations/opacities across renders
- Procedural radial gradient texture from Canvas2D — no external PNG assets required
- All 193 observatory tests pass with no regressions

## Task Commits

1. **RED: Failing test** - `7f5be5c3c` (test)
2. **Task 1: ObservatoryNebulaClouds component** - `c80c3d7e5` (feat)
3. **Task 2: Wire into ObservatoryWorldScene** - `c2221176e` (feat)

## Files Created/Modified
- `apps/workbench/src/features/observatory/components/world-canvas/ObservatoryNebulaClouds.tsx` - Billboard nebula cloud patches + station point lights
- `apps/workbench/src/features/observatory/__tests__/observatory-nebula-clouds.test.tsx` - Smoke render tests (TDD)
- `apps/workbench/src/features/observatory/components/world-canvas/ObservatoryWorldScene.tsx` - Import + JSX child added after lighting block

## Decisions Made
- Used `HUNT_STATION_ORDER` (all 6 stations) rather than `HUNT_PRIMARY_STATION_ORDER` (5 stations) so `watch` station also gets nebula aura
- Separate mulberry32 PRNG stream per patch (seed + index * 7919) avoids spatial correlation between patches of the same station
- `typeof document !== "undefined"` guard in texture factory so tests running in jsdom don't crash on CanvasTexture

## Deviations from Plan

None - plan executed exactly as written.

## Issues Encountered
None

## Next Phase Readiness
- Nebula clouds layer is complete and wired in
- Plan 03 (space lane particles or additional environment art) can build on ObservatoryWorldScene directly
- All station colors and positions available via OBSERVATORY_STATION_POSITIONS / STATION_COLORS pattern

---
*Phase: 22-space-environment-art*
*Completed: 2026-03-20*

## Self-Check: PASSED
- ObservatoryNebulaClouds.tsx: FOUND
- observatory-nebula-clouds.test.tsx: FOUND
- 22-02-SUMMARY.md: FOUND
- Commits 7f5be5c3c, c80c3d7e5, c2221176e: FOUND
