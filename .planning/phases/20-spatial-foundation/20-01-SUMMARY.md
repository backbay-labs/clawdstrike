---
phase: 20-spatial-foundation
plan: 01
subsystem: ui
tags: [three, react-three-fiber, observatory, webgpu, webgl2, 3d-world, spatial]

# Dependency graph
requires: []
provides:
  - "Space-scale observatory world at 300-unit radius with per-station Y elevations"
  - "WebGPU-first renderer with WebGL2+logarithmicDepthBuffer fallback"
  - "WORLD_RADIUS=300 constant exported from observatory-world-template.ts"
  - "elevationY field on HuntStationPlacement type and HUNT_STATION_PLACEMENTS data"
  - "Ground plane, grid helper, floor disc removed — stations float in void"
  - "Fly-by waypoints and camera recipes rescaled for space-scale world"
  - "NPC patrol waypoints use station elevationY as Y baseline"
affects:
  - 20-spatial-foundation
  - 21-flight-controller
  - 22-space-lanes
  - 23-docking

# Tech tracking
tech-stack:
  added: ["three@0.171.0 (bumped from 0.170.0)", "three/webgpu (dynamic import, WebGPU renderer)"]
  patterns:
    - "WORLD_RADIUS constant drives all geometry sizing downstream — multiply by placement.radius for station distance"
    - "Canvas gl async function pattern for WebGPU-first renderer with WebGL2 fallback"
    - "Station positions include elevationY baked in — no separate Y offset needed at render site"

key-files:
  created: []
  modified:
    - "apps/workbench/package.json"
    - "apps/workbench/src/features/observatory/world/types.ts"
    - "apps/workbench/src/features/observatory/world/stations.ts"
    - "apps/workbench/src/features/observatory/world/observatory-world-template.ts"
    - "apps/workbench/src/features/observatory/components/ObservatoryWorldCanvas.tsx"
    - "apps/workbench/src/features/observatory/components/world-canvas/ObservatoryWorldScene.tsx"
    - "apps/workbench/src/features/observatory/components/world-canvas/ObservatoryDistrictLayer.tsx"
    - "apps/workbench/src/features/observatory/world/npcCrew.tsx"
    - "apps/workbench/src/features/observatory/world/deriveObservatoryWorld.ts"

key-decisions:
  - "WebGPU is attempted first via async dynamic import of three/webgpu; WebGL2 with logarithmicDepthBuffer is the fallback — prevents Z-fighting at space scale"
  - "WORLD_RADIUS=300 drives all geometry; station radius is placement.radius * WORLD_RADIUS (primary 300, watch 378)"
  - "elevationY baked into station position tuples so every consumer (NPC, camera, hero props) gets correct Y without manual offset"
  - "StationBuilding/DistrictGround/DistrictEnvProps removed from scene (pending Plan 02 SpaceStationMesh replacement) — mulberry32 left in districtGeometry.tsx"
  - "District float animation fixed to use district.position[1] as Y baseline (was hardcoded STATION_HEIGHT=0.72 which ignored elevationY)"
  - "buildLanePoints midY = (from[1]+to[1])*0.5 + arc offset (was flat 1.8/1.2) so lanes arc naturally between stations at different elevations"

patterns-established:
  - "Space-scale constants: fogNear/Far 400/1200, starsRadius 2400, camera min/maxDistance 40/1200"
  - "Fly-by waypoints at ~420/330/550 unit radii sweep the expanded world in 1800ms legs"

requirements-completed:
  - SPC-01

# Metrics
duration: 8min
completed: 2026-03-20
---

# Phase 20 Plan 01: Space-Scale Foundation Summary

**Observatory expanded from 14-unit flat ring to 300-unit space-scale void: per-station elevations (-15 to +40), WebGPU renderer with log depth buffer, ground plane removed, all 203 tests passing**

## Performance

- **Duration:** 8 min
- **Started:** 2026-03-20T16:22:09Z
- **Completed:** 2026-03-20T16:30:21Z
- **Tasks:** 1
- **Files modified:** 10

## Accomplishments
- Added `elevationY` field to `HuntStationPlacement` with per-station values (signal+35, targets+10, run-5, receipts-15, case-notes+20, watch+40)
- Rescaled world template to WORLD_RADIUS=300; all geometry (fog, stars, lights, core, watchfield, districts) scaled proportionally
- WebGPU renderer async-imported with WebGL2+logarithmicDepthBuffer fallback — no Z-fighting at any camera distance
- Removed flat ground plane, grid helper, and floor disc — stations float in void
- Rescaled FLY_BY_WAYPOINTS, camera initialPosition [0,310,560], and STATION_CAMERA_PROFILES by ~15x
- Fixed two latent bugs: district float animation was overwriting elevationY with hardcoded 0.72; NPC patrol waypoints used hardcoded Y=0

## Task Commits

1. **Task 1: Space-scale world constants + elevation type + renderer swap** - `5e7846514` (feat)

## Files Created/Modified
- `apps/workbench/package.json` - three bumped to 0.171.0
- `apps/workbench/src/features/observatory/world/types.ts` - Added elevationY to HuntStationPlacement
- `apps/workbench/src/features/observatory/world/stations.ts` - Per-station elevationY values
- `apps/workbench/src/features/observatory/world/observatory-world-template.ts` - WORLD_RADIUS=300, rescaled all geometry, removed floor/grid, WebGPU
- `apps/workbench/src/features/observatory/components/ObservatoryWorldCanvas.tsx` - WebGPU gl prop, removed gridHelper/floor/district-geo JSX, rescaled FLY_BY_WAYPOINTS
- `apps/workbench/src/features/observatory/components/world-canvas/ObservatoryWorldScene.tsx` - Removed gridHelper and floor mesh
- `apps/workbench/src/features/observatory/components/world-canvas/ObservatoryDistrictLayer.tsx` - Removed StationBuilding/DistrictGround/DistrictEnvProps
- `apps/workbench/src/features/observatory/world/npcCrew.tsx` - NPC patrol Y uses stationWorldPos[1]
- `apps/workbench/src/features/observatory/world/deriveObservatoryWorld.ts` - Camera recipes and station profiles rescaled 15x

## Decisions Made
- WebGPU attempted via `import("three/webgpu")` async; WebGL2 fallback has `logarithmicDepthBuffer: true` — CONTEXT.md said WebGPU is nice-to-have, WebGL2 is guaranteed path
- WORLD_RADIUS=300 chosen to give 200-500 unit station spread with the existing radius multipliers (1x primary, 1.26x watch)
- StationBuilding/DistrictGround/DistrictEnvProps stripped from scene JSX but source files preserved — Plan 02 will replace with SpaceStationMesh using mulberry32 from districtGeometryResources

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 1 - Bug] Fixed district float animation ignoring elevationY**
- **Found during:** Task 1 (reviewing StationDistrict useFrame logic)
- **Issue:** `groupRef.current.position.y = STATION_HEIGHT + ...` hardcoded Y=0.72 baseline, overwriting the elevationY embedded in `district.position`
- **Fix:** Changed baseline to `district.position[1]` so float animation preserves station elevation
- **Files modified:** `apps/workbench/src/features/observatory/components/ObservatoryWorldCanvas.tsx`
- **Verification:** TypeScript clean, all 203 tests pass
- **Committed in:** 5e7846514 (Task 1 commit)

**2. [Rule 1 - Bug] Fixed NPC patrol waypoints using hardcoded Y=0**
- **Found during:** Task 1 (Step 8: NPC waypoint Y offsets)
- **Issue:** NPC waypoints computed as `new THREE.Vector3(x, 0, z)` — all NPCs patrolled at Y=0 regardless of station elevation; initial spawn position also hardcoded `[spawnX, 0, spawnZ]`
- **Fix:** Changed to use `stationWorldPos[1]` for Y in both waypoints and spawn position
- **Files modified:** `apps/workbench/src/features/observatory/world/npcCrew.tsx`
- **Verification:** TypeScript clean, all 203 tests pass
- **Committed in:** 5e7846514 (Task 1 commit)

---

**Total deviations:** 2 auto-fixed (both Rule 1 - Bug)
**Impact on plan:** Both bugs directly caused by the Y elevation change — required fixing to prevent NPCs and districts from sinking to Y=0 in the new space-scale world.

## Issues Encountered
- R3F Canvas `gl` prop type expected `(defaultProps: DefaultGLProps) => Promise<Renderer>` not `(canvas: HTMLCanvasElement) => Promise<Renderer>` — fixed by using `_defaultProps` signature matching R3F's GLProps type definition

## User Setup Required
None - no external service configuration required.

## Next Phase Readiness
- Space-scale spatial substrate is complete — stations at 200-500 unit radius with Y elevations, no ground plane
- Phase 21 (Flight Controller) can build on this foundation: player ship needs orbit/approach/dock positions derived from the 300-unit station positions
- Phase 22 (Space Lanes) can use the rescaled buildLanePoints which already arc in 3D between different Y elevations
- districtGeometry.tsx still present with mulberry32 — Plan 02 should replace StationBuilding with SpaceStationMesh

---
*Phase: 20-spatial-foundation*
*Completed: 2026-03-20*
