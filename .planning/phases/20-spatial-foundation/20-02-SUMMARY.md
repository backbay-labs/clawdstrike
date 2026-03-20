---
phase: 20-spatial-foundation
plan: "02"
subsystem: observatory-geometry
tags: [space-stations, r3f, three.js, prng, geometry, STN-01]
dependency_graph:
  requires: [20-01]
  provides: [SpaceStationMesh, createSpaceStationLayout, createSpaceStationSeed]
  affects: [ObservatoryWorldCanvas, ObservatoryDistrictLayer, district-geometry-resources.test]
tech_stack:
  added: []
  patterns:
    - "mulberry32 PRNG for seeded deterministic station geometry"
    - "composable Three.js primitives (torus, cylinder, plane, cone, box)"
    - "createSpaceStationLayout pure function for testable layout derivation"
key_files:
  created: []
  modified:
    - apps/workbench/src/features/observatory/world/districtGeometryResources.ts
    - apps/workbench/src/features/observatory/world/districtGeometry.tsx
    - apps/workbench/src/features/observatory/components/world-canvas/ObservatoryDistrictLayer.tsx
    - apps/workbench/src/features/observatory/components/ObservatoryWorldCanvas.tsx
    - apps/workbench/src/features/observatory/__tests__/district-geometry-resources.test.ts
    - apps/workbench/src/features/observatory/__tests__/observatory-world-canvas.performance.test.tsx
decisions:
  - "SpaceStationMesh exports createSpaceStationLayout as pure function for independent test coverage without React"
  - "Panel transforms use a second PRNG pass consuming same calls as layout to stay in sync with seed"
  - "Docking bay angle uses seed+77 offset to avoid correlation with layout PRNG stream"
  - "Antenna transforms use seed+99 offset to produce independent random angles per antenna"
metrics:
  duration: "~15 minutes"
  completed_date: "2026-03-20"
  tasks_completed: 2
  files_modified: 6
---

# Phase 20 Plan 02: Space Station Geometry (STN-01) Summary

**One-liner:** Composable floating space station from Three.js primitives (torus ring, cylinder hub, solar panels, docking arm, antennae) with mulberry32-seeded deterministic variation per station.

## What Was Built

Replaced ground-level district buildings, ground planes, and env props with a `SpaceStationMesh` component that renders floating space station geometry from composable Three.js primitives. Each station produces a unique but deterministic shape driven by a seed derived from the station's world position.

### Task 1: SpaceStationMesh + clean districtGeometryResources (commit e4fadc73f)

- Stripped `districtGeometryResources.ts` of all old geometry/material constants and layout functions (`StationBuildingInstanceLayout`, `DistrictEnvPropLayout`, `createStationBuildingLayout`, `createDistrictEnvPropLayout`, `DISTRICT_BUILDING_GEOMETRY`, `DISTRICT_BUILDING_MATERIAL`, `DISTRICT_ANTENNA_GEOMETRY`, `DISTRICT_ANTENNA_MATERIAL`, `DISTRICT_GROUND_GEOMETRY`, `DISTRICT_CRATE_GEOMETRY`, `DISTRICT_CRATE_MATERIAL`)
- Kept `mulberry32` PRNG and `normalizeSeed` helper; added `createSpaceStationSeed(posX, posZ)`
- Rewrote `districtGeometry.tsx` as `SpaceStationMesh` component with five composable elements:
  - Torus habitat ring (radius 2-4, slow Y-rotation via `useFrame`)
  - Cylinder hub (height 1-3, radius 0.6-1.0)
  - Solar panels (2-6, emissive blue `#4488cc`)
  - Docking bay arm (60% of stations, BoxGeometry)
  - Antenna array (1-3, CylinderGeometry shaft + ConeGeometry dish, emissive station color)
- Exported `createSpaceStationLayout(seed)` pure function for isolated test coverage
- Triangle budget per station: well under 5K at near LOD

### Task 2: Wire SpaceStationMesh into scene + update tests (commit 2cc329591)

- Added `SpaceStationMesh` to `ObservatoryDistrictLayer.tsx` (extracted world scene path), rendering one per district with `floatAmplitude` and `pulseSpeed` from district template
- Added `SpaceStationMesh` to `ObservatoryWorldCanvas.tsx` inline scene path (same rendering pattern)
- Updated performance test mock: `SpaceStationMesh: () => null` replaces old `StationBuilding/DistrictGround/DistrictEnvProps`
- Rewrote `district-geometry-resources.test.ts`: tests for `mulberry32` determinism, `createSpaceStationSeed` positive integer output, `createSpaceStationLayout` range checks and cross-seed variation

## Test Results

All 44 observatory test files pass — 209 tests total.

## Deviations from Plan

None — plan executed exactly as written.

## Self-Check: PASSED

- `apps/workbench/src/features/observatory/world/districtGeometry.tsx` — exists, exports `SpaceStationMesh` and `createSpaceStationLayout`
- `apps/workbench/src/features/observatory/world/districtGeometryResources.ts` — exists, exports `mulberry32` and `createSpaceStationSeed`, no DISTRICT_* constants
- `apps/workbench/src/features/observatory/components/world-canvas/ObservatoryDistrictLayer.tsx` — imports and renders `SpaceStationMesh`
- `apps/workbench/src/features/observatory/components/ObservatoryWorldCanvas.tsx` — imports and renders `SpaceStationMesh`
- Commits e4fadc73f and 2cc329591 — both present in git log
- `npx vitest run src/features/observatory/` — 44 passed, 209 tests
- `npx tsc --noEmit` — exits 0
