---
phase: 40-threat-heatmap-probe-delta-cards
plan: 03
subsystem: ui
tags: [react-three-fiber, three.js, observatory, heatmap, probe-delta, glsl, shader]

# Dependency graph
requires:
  - phase: 40-01
    provides: ThreatTopologyHeatmap component with GLSL shader and Float32Array pressure API
  - phase: 40-02
    provides: ProbeDeltaLayer component with auto-dismiss and floating Html cards
  - phase: 39-03
    provides: ObservatoryInvalidationController with probeStatus source key
provides:
  - ThreatTopologyHeatmap wired into ObservatoryWorldScene with live pressure data from district emphasis
  - ProbeDeltaLayer wired into ObservatoryWorldScene receiving probeGuidance from ObservatoryTab
  - heatmapPressureData derived from world.districts.emphasis via deriveHeatmapDataTexture
  - heatmapVisible gated by performanceProfile.weatherBudget !== "off" (HEAT-04)
  - heatmapPresetMultiplier = 1.5 for threat preset, 1.0 otherwise (HEAT-05)
  - probeGuidance threaded: ObservatoryTab -> ObservatoryWorldCanvas -> ObservatoryWorldScene -> ProbeDeltaLayer (PRBI-06)
affects: [phase-41, phase-42, phase-43, observatory-analyst-toolkit]

# Tech tracking
tech-stack:
  added: []
  patterns:
    - "heatmapVisible gates rendering via weatherBudget !== 'off' — mirrors effectiveWeatherState null guard pattern"
    - "useMemo over world.districts.emphasis produces stable Float32Array for shader uniforms"
    - "probeGuidance threaded as optional prop through ObservatoryWorldCanvas to ObservatoryWorldScene"

key-files:
  created: []
  modified:
    - apps/workbench/src/features/observatory/components/world-canvas/observatory-world-scene-types.ts
    - apps/workbench/src/features/observatory/components/world-canvas/ObservatoryWorldScene.tsx
    - apps/workbench/src/features/observatory/components/ObservatoryWorldCanvas.tsx
    - apps/workbench/src/features/observatory/components/ObservatoryTab.tsx

key-decisions:
  - "heatmapPressureData derived from world.districts.emphasis (pre-probe-consequence world) rather than reactiveWorld — simpler dependency, emphasis is the natural pressure proxy"
  - "heatmapVisible = weatherBudget !== 'off' mirrors the weather layer gate — single budget concept controls both layers"
  - "ProbeDeltaLayer always mounted in JSX (no outer conditional) — it internally returns null when probeGuidance is null, matching its own guard pattern"
  - "Invalidation for delta cards handled by existing probeStatus source key in ObservatoryInvalidationController — no new source key needed (PRBI-06)"

patterns-established:
  - "weatherBudget !== 'off' as standard gate for ground-plane visual effects"
  - "Analyst preset multiplier as prop: 1.5x for threat, 1.0x default — avoids preset logic inside child components"

requirements-completed: [HEAT-04, HEAT-05, PRBI-06]

# Metrics
duration: ~4min
completed: 2026-03-23
---

# Phase 40 Plan 03: Wire Heatmap and Delta Cards into Observatory Scene Summary

**ThreatTopologyHeatmap and ProbeDeltaLayer wired into the live observatory scene with district-emphasis pressure data, weatherBudget gating, THREAT preset 1.5x multiplier, and probeGuidance flowing from ObservatoryTab through the full prop chain**

## Performance

- **Duration:** ~4 min
- **Started:** 2026-03-23T02:00:00Z
- **Completed:** 2026-03-23T02:04:00Z
- **Tasks:** 2
- **Files modified:** 4

## Accomplishments

- Extended `ObservatoryWorldSceneProps` with 4 new optional fields (heatmapPressureData, heatmapVisible, heatmapPresetMultiplier, probeGuidance)
- Wired `ThreatTopologyHeatmap` into ObservatoryWorldScene gated by `heatmapVisible && heatmapPressureData`
- Wired `ProbeDeltaLayer` into ObservatoryWorldScene unconditionally (internally null when no guidance)
- Derived heatmap data in ObservatoryWorldCanvas via `deriveHeatmapDataTexture` from `world.districts.emphasis`
- Threaded `probeGuidance` from ObservatoryTab through the full prop chain to ProbeDeltaLayer

## Task Commits

1. **Task 1: Extend scene types and wire heatmap + delta layer into ObservatoryWorldScene** - `e6c3cf8fc` (feat)
2. **Task 2: Derive heatmap data and thread props through ObservatoryWorldCanvas** - `5a2b110ab` (feat)

## Files Created/Modified

- `apps/workbench/src/features/observatory/components/world-canvas/observatory-world-scene-types.ts` - Added 4 new optional props + ObservatoryProbeGuidance import
- `apps/workbench/src/features/observatory/components/world-canvas/ObservatoryWorldScene.tsx` - Added ThreatTopologyHeatmap + ProbeDeltaLayer renders with OBSERVATORY_STATION_POSITIONS
- `apps/workbench/src/features/observatory/components/ObservatoryWorldCanvas.tsx` - Added derivations (heatmapPressureData, heatmapVisible, heatmapPresetMultiplier), probeGuidance prop, and prop threading to ExtractedObservatoryWorldScene
- `apps/workbench/src/features/observatory/components/ObservatoryTab.tsx` - Passes probeGuidance to ObservatoryWorldCanvas

## Decisions Made

- Used `world.districts.emphasis` (pre-probe-consequence `world`) rather than `reactiveWorld.districts` because `reactiveWorld` is defined later in the component. `world.districts.emphasis` is the correct pressure proxy and avoids forward-reference issues.
- `heatmapVisible = performanceProfile.weatherBudget !== "off"` reuses the existing weather budget concept as a single performance gate for all ground-plane effects.
- `ProbeDeltaLayer` is always mounted (no outer conditional) — it returns null internally when probeGuidance is null, which is its designed behavior.

## Deviations from Plan

None - plan executed exactly as written. The one deviation from the exact plan spec: heatmapPressureData uses `world.districts` instead of `reactiveWorld.districts` (which the plan notes as "world.districts" in prose), since `reactiveWorld` is computed later in the function from `world` via `applyObservatoryProbeConsequences`. This matches the plan intent.

## Issues Encountered

None. TypeScript compiled cleanly after both tasks.

## User Setup Required

None - no external service configuration required.

## Next Phase Readiness

- Both heatmap and delta card layers are now live in the observatory with real pressure data
- Phase 40 complete: all three plans (heatmap component, delta layer component, scene wiring) are done
- Phase 41 (Spirit Resonance Layer) can proceed — no blockers from this plan
- HEAT-04, HEAT-05, PRBI-06 requirements satisfied

---
*Phase: 40-threat-heatmap-probe-delta-cards*
*Completed: 2026-03-23*
