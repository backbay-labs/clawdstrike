# Phase 20: Spatial Foundation - Context

**Gathered:** 2026-03-20
**Status:** Ready for planning

<domain>
## Phase Boundary

Expand the observatory from a flat 14-unit-radius ground ring to a 300-unit-radius 3D space with stations at varied elevations. Swap the Canvas renderer to WebGPU (with WebGL2 fallback) via three 0.171+ async gl prop. Replace ground-level district buildings/ground/env-props with floating space station geometry built from composable Three.js primitives. All existing observatory features (missions, probes, replay, weather, NPCs, ghosts) must continue working after the scale change.

</domain>

<decisions>
## Implementation Decisions

### World Scale Constants
- Base radius: 300 units (WORLD_RADIUS = 300 in a new constants file or in stations.ts)
- World unit ≈ 1 meter — intuitive for speed/distance readouts in later HUD phase
- HUNT_STATION_PLACEMENTS keeps angleDeg + radius pattern, but radius values scaled: primary stations radius=1.0 → world position = angleDeg on a 300-unit circle; watch at radius=1.26 → ~378 units
- stationPosition() in observatory-world-template.ts is THE function that converts placements to [x, y, z] — this is the single place to apply the scale multiplier
- Fog, camera near/far, stars radius, grid size all scale proportionally
- Fly-by waypoints (FLY_BY_WAYPOINTS) must be rescaled to match new world radius

### Station Elevation Distribution
- Add `elevationY` field to HuntStationPlacement type
- Per-station fixed Y offsets (not random):
  - Signal (Horizon): Y = +35 — high vantage, first thing you see
  - Targets (Subjects): Y = +10 — slightly elevated
  - Run (Operations): Y = -5 — just below center, industrial feel
  - Receipts (Evidence): Y = -15 — deep, vault-like
  - Case-Notes (Judgment): Y = +20 — elevated, tribunal feel
  - Watch (Watchfield): Y = +40 — highest, perimeter sentinel lookout
- stationPosition() applies elevationY as the Y component

### Station Primitive Composition
- New SpaceStationMesh component replaces StationBuilding + DistrictGround + DistrictEnvProps
- All stations share the same composable primitive set, varied by seed:
  - **Torus habitat ring**: TorusGeometry — always present, radius varies 2-4 units
  - **Cylinder hub**: CylinderGeometry — always present, height varies 1-3 units
  - **Solar panel pairs**: PlaneGeometry — 2-6 panels, angled outward, emissive blue material
  - **Docking bay arm**: BoxGeometry — 0-1 per station (seed-driven), extends from hub
  - **Antenna array**: CylinderGeometry — 1-3 thin cylinders with ConeGeometry dish tips
- Total target: <5K triangles per station at near LOD
- Use existing mulberry32 PRNG with station seed for deterministic variation
- Station colorHex from ObservatoryDistrictTemplate drives emissive accent on ring and panels

### Existing Geometry Migration
- StationBuilding component: REMOVED — replaced by SpaceStationMesh
- DistrictGround component: REMOVED — no ground planes in space
- DistrictEnvProps component: REMOVED — no ground-level crates/cables in space
- districtGeometryResources.ts: Keep mulberry32 (reuse in SpaceStationMesh), remove building/ground/crate geometry constants
- districtGeometry.tsx: Gutted and replaced with SpaceStationMesh
- ObservatoryWorldCanvas: Replace StationBuilding/DistrictGround/DistrictEnvProps JSX with SpaceStationMesh per station
- Floor grid (gridHelper): REMOVED — no ground plane
- NPC crew: Keep NPCs but they now patrol ON the station platforms (adjust waypoint Y to match station elevationY)
- Hero props: Keep but reposition to station center (adjust Y to match elevationY + hub height offset)

### WebGPU Renderer Swap
- Bump three from ^0.170.0 to ^0.171.0 (or latest)
- Canvas gl prop changes from object to async function:
  ```
  gl={async (canvas) => {
    const { WebGPURenderer } = await import('three/webgpu');
    const renderer = new WebGPURenderer({ canvas, antialias: true });
    await renderer.init();
    return renderer;
  }}
  ```
- Remove gl.antialias: false (WebGPU handles this differently)
- logarithmicDepthBuffer: enabled via renderer config
- Verify @react-three/postprocessing EffectComposer works with WebGPURenderer — if not, keep WebGL for now (WebGPU is a nice-to-have constraint, not a hard requirement)

### Claude's Discretion
- Exact fog near/far values for the new 300-unit scale
- Camera orbit control limits (minDistance, maxDistance) for the expanded world
- Whether to keep the floor grid as a faint reference plane or remove entirely
- Ambient/directional light positions and intensities for the larger scene
- Star radius and count scaling

</decisions>

<canonical_refs>
## Canonical References

**Downstream agents MUST read these before planning or implementing.**

### World geometry and constants
- `apps/workbench/src/features/observatory/world/stations.ts` — HUNT_STATION_PLACEMENTS (the data being modified), HUNT_STATION_LABELS, station IDs
- `apps/workbench/src/features/observatory/world/observatory-world-template.ts` — stationPosition() (THE function converting placements to world coords), OBSERVATORY_WORLD_TEMPLATE (all default recipes)
- `apps/workbench/src/features/observatory/world/deriveObservatoryWorld.ts` — ObservatoryEnvironmentRecipe, ObservatoryCameraRecipe, full world derivation from station state

### Existing geometry being replaced
- `apps/workbench/src/features/observatory/world/districtGeometry.tsx` — StationBuilding, DistrictGround, DistrictEnvProps (all being replaced)
- `apps/workbench/src/features/observatory/world/districtGeometryResources.ts` — mulberry32 PRNG (keeping), building/ground geometry constants (removing)

### Canvas and rendering
- `apps/workbench/src/features/observatory/components/ObservatoryWorldCanvas.tsx` — Main canvas composition root, imports StationBuilding/DistrictGround/DistrictEnvProps, fly-by waypoints, camera rig
- `apps/workbench/src/features/observatory/components/ObservatoryPostFX.tsx` — Post-processing pipeline (must work after renderer swap)

### NPCs and hero props (must survive the migration)
- `apps/workbench/src/features/observatory/world/npcCrew.tsx` — NPC patrol waypoints need Y adjustment
- `apps/workbench/src/features/observatory/world/propAssets.ts` — Hero prop positions need Y adjustment

### Types
- `apps/workbench/src/features/observatory/world/types.ts` — HuntStationPlacement type (needs elevationY field)

### Minimap (affected by scale change)
- `apps/workbench/src/features/observatory/panels/observatory-minimap-panel.tsx` — SVG minimap reads HUNT_STATION_PLACEMENTS for positions

</canonical_refs>

<code_context>
## Existing Code Insights

### Reusable Assets
- `mulberry32` PRNG in districtGeometryResources.ts — reuse for seeded station primitive variation
- `stationPosition()` in observatory-world-template.ts — single place to apply scale multiplier and elevation
- `ObservatoryDistrictTemplate` in observatory-world-template.ts — already has colorHex, pulseSpeed, floatAmplitude per station
- `OBSERVATORY_WORLD_TEMPLATE` — environment recipe with fog, stars, camera, lighting defaults (all need rescaling)

### Established Patterns
- InstancedMesh for repeated geometry (used by StationBuilding for buildings, NPC crew for capsules)
- Seeded deterministic layout via mulberry32 (buildings, env props)
- `useLayoutEffect` for setting instanced mesh matrices (StationBuilding pattern)
- Lazy-loaded components via React.lazy for heavy scene elements (FlowModeController, PostFX, VFXPools)

### Integration Points
- `ObservatoryWorldCanvas` is the composition root — all station geometry is rendered inside district layer groups
- `deriveObservatoryWorld()` produces all recipes from station state — camera, environment, districts, transit routes, growth structures all derive from station positions
- `observatory-world-template.ts` buildLanePoints/buildLocalArcPoints generate transit route geometry between stations — these use stationPosition() and will automatically scale
- NPC waypoints are local offsets from station position — they'll move with the station but need Y offset
- Minimap SVG uses polar-to-Cartesian from HUNT_STATION_PLACEMENTS — still works if placements keep angleDeg/radius pattern

</code_context>

<specifics>
## Specific Ideas

- Stations should feel like they're floating in a void — no ground reference, just stars and fog behind them
- The "Thesis Core" center (currently the grid center at 0,0,0) should remain as a reference point — maybe a dim beacon or hub marker at origin
- Watch (Watchfield) station should feel the most isolated — furthest out, highest up, sentinel outpost vibe
- The elevation differences should be dramatic enough to be visible during the fly-by intro sequence

</specifics>

<deferred>
## Deferred Ideas

- Station LOD tiers — Phase 23 (STN-02)
- Station beacon lights — Phase 23 (STN-03)
- Fresnel rim glow — Phase 23 (STN-04)
- Docking ring geometry — Phase 23 (STN-05)
- Starfield/nebula/lanes — Phase 22 (SPC-02 through SPC-06)
- Ship flight controller — Phase 21 (FLT-01 through FLT-06)

</deferred>

---

*Phase: 20-spatial-foundation*
*Context gathered: 2026-03-20 via --auto mode*
