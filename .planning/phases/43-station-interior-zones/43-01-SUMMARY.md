---
phase: 43-station-interior-zones
plan: 01
subsystem: ui
tags: [r3f, three, observatory, station-interior, instanced-rendering]

# Dependency graph
requires:
  - phase: 39-store-persistence-and-derivation-foundations
    provides: ObservatoryInteriorState type and store slice
  - phase: 42-replay-annotation-canvas
    provides: world-canvas component patterns

provides:
  - STATION_INTERIOR_CONFIGS record with all 6 station interior definitions
  - StationInteriorConfig, InteriorNpcPlacement, InteriorPropMesh interfaces
  - StationInteriorScene R3F component rendering complete 20x8x20 interior rooms

affects: [44-station-interior-zones, observatory-world-scene, station-interior-mounting]

# Tech tracking
tech-stack:
  added: []
  patterns:
    - InteriorNpcInstance uses useRef + useFrame for idle bobbing (sin wave, no state)
    - HeroPropMarker uses meshRef scale oscillation for mission-target pulse
    - Config-driven geometry dispatch: prop.type === "box" | "cylinder" | "torus" | "cone"
    - Accent stripe meshes as thin box overlays at eye level (y=1.6) on all 4 walls

key-files:
  created:
    - apps/workbench/src/features/observatory/world/station-interior-config.ts
    - apps/workbench/src/features/observatory/components/world-canvas/StationInteriorScene.tsx
  modified: []

key-decisions:
  - "HuntStationId imported from ./types (world-local) not ../types (parent) — station-interior-config.ts is inside world/"
  - "cursor prop removed from R3F mesh — not a valid R3F prop; onClick sufficient for interaction"
  - "ObservatoryHeroPropRecipe constructed with as unknown as cast — interior scene passes minimal recipe, real recipe sourced from world derivation"
  - "InteriorNpcCrew uses Instances limit=4 — 3 NPCs per station, 1 spare slot for safety"

patterns-established:
  - "InteriorNpcInstance: position in props, index for sin phase offset, baseY captured from props"
  - "Wall accent stripes: thin boxGeometry at eye level (y=1.6) offset 0.05 units from wall plane"
  - "Hero prop pulse: scale oscillation via useFrame + Math.sin only when missionTargetAssetId matches"

requirements-completed: [INTR-02, INTR-03, INTR-06]

# Metrics
duration: 5min
completed: 2026-03-23
---

# Phase 43 Plan 01: Station Interior Zones Summary

**Pure-data station interior configs for all 6 stations plus R3F StationInteriorScene rendering 20x8x20 rooms with walls, NPC crew, accent lighting, and hero prop interaction zones**

## Performance

- **Duration:** ~5 min
- **Started:** 2026-03-23T03:51:00Z
- **Completed:** 2026-03-23T03:56:07Z
- **Tasks:** 2
- **Files modified:** 2 created, 0 modified

## Accomplishments

- Created `station-interior-config.ts` with `STATION_INTERIOR_CONFIGS` for all 6 stations — each with distinct accent color, wall color, 2-3 unique prop meshes, 3 NPC placements, and correct `roomSize [20, 8, 20]` / `lightIntensity 1.5` per locked CONTEXT.md values
- Created `StationInteriorScene.tsx` rendering a complete interior room: floor, ceiling, 4 walls with emissive accent stripes, per-station point light, config-driven prop geometry, 3 idle-bobbing NPC instances, and a glowing hero prop interaction zone
- Hero prop marker pulses (scale oscillation) when `missionTargetAssetId` matches station's `heroPropAssetId`, and calls `onTriggerHeroProp` on click

## Task Commits

Each task was committed atomically:

1. **Task 1: Create station interior configuration data** - `480d564a2` (feat)
2. **Task 2: Create StationInteriorScene R3F component** - `468e111f5` (feat)

## Files Created/Modified

- `apps/workbench/src/features/observatory/world/station-interior-config.ts` - Per-station interior definitions: geometry, accent colors, NPC placements, hero prop layout for all 6 stations
- `apps/workbench/src/features/observatory/components/world-canvas/StationInteriorScene.tsx` - R3F component rendering a complete 20x8x20 interior room with lighting, props, NPCs, and hero prop interaction

## Decisions Made

- `HuntStationId` imported from `./types` not `../types` — the config file lives inside `world/`, so the sibling import path is correct (plan spec had the wrong path, auto-fixed)
- `cursor` prop removed from R3F mesh — not a valid R3F/Three.js prop; `onClick` is sufficient for interaction detection
- `ObservatoryHeroPropRecipe` constructed with `as unknown as` cast in the hero prop marker — the interior scene provides a minimal recipe stub; the real recipe is sourced from world derivation in callers
- `Instances limit={4}` for interior NPC crew — 3 NPCs needed per station, 1 spare slot for safety margin

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 3 - Blocking] Wrong import path for HuntStationId in station-interior-config.ts**
- **Found during:** Task 1 verification (tsc --noEmit)
- **Issue:** Plan spec said `import type { HuntStationId } from "../types"` but `HuntStationId` lives in `./types` (same directory) — `../types` is the workbench-level types.ts which re-exports from store types, not world types
- **Fix:** Changed import to `from "./types"`
- **Files modified:** apps/workbench/src/features/observatory/world/station-interior-config.ts
- **Verification:** `npx tsc --noEmit` shows no errors for the file
- **Committed in:** `480d564a2` (Task 1 commit)

**2. [Rule 1 - Bug] cursor prop removed from R3F mesh in StationInteriorScene**
- **Found during:** Task 2 verification (tsc --noEmit)
- **Issue:** `cursor="pointer"` is not a valid R3F mesh prop — TypeScript error TS2322
- **Fix:** Removed the `cursor` prop; `onClick` provides the interaction signal
- **Files modified:** apps/workbench/src/features/observatory/components/world-canvas/StationInteriorScene.tsx
- **Verification:** `npx tsc --noEmit` shows no errors for the file
- **Committed in:** `468e111f5` (Task 2 commit)

---

**Total deviations:** 2 auto-fixed (1 blocking path error, 1 invalid prop bug)
**Impact on plan:** Both auto-fixes necessary for correctness. No scope creep.

## Issues Encountered

None - both fixes were quick and straightforward.

## Next Phase Readiness

- `station-interior-config.ts` and `StationInteriorScene.tsx` are ready for mounting into ObservatoryWorldScene
- Next phase should add the interior transition controller: entering/inside/exiting state machine that conditionally mounts StationInteriorScene and adjusts camera
- Blocker noted in STATE.md: log-Z depth buffer mitigation (camera near-plane adjustment vs renderer mode swap) needs prototype validation before production use

---
*Phase: 43-station-interior-zones*
*Completed: 2026-03-23*
