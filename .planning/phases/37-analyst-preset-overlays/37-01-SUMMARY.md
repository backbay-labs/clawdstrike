---
phase: 37-analyst-preset-overlays
plan: 01
subsystem: ui
tags: [react-three-fiber, three.js, r3f, observatory, analyst-presets, tdd, vitest]

requires:
  - phase: 35-ghost-trace-markers
    provides: "ObservatoryGhostTrace type, GhostTraceLayer additive-blending pattern, OBSERVATORY_STATION_POSITIONS"
  - phase: 36-mission-objective-beacons
    provides: "MissionObjectiveBeacons pure-helper export pattern used as reference"

provides:
  - "ThreatPresetOverlay: red additive wash disc + 5 orbital mote spheres per active/high-pressure district"
  - "EvidencePresetOverlay: gold spinning torus halo rings at receipt-bearing stations"
  - "ReceiptsPresetOverlay: verdict-colored badge meshes (ALLOW=green, DENY=red, AUDIT=amber) per station"
  - "getThreatDistricts: pure helper filtering districts where active||artifactCount>=3"
  - "getEvidenceStationIds: pure helper extracting unique stationIds from receipt traces"
  - "groupReceiptTracesByStation: pure helper grouping receipt traces by stationId"
  - "verdictColor: pure helper deriving verdict color from trace headline/detail/score"

affects:
  - 37-02 (plan 02 mounts these overlays conditionally based on activePreset)

tech-stack:
  added: []
  patterns:
    - "Pure helper exports for unit testing (getThreatDistricts, getEvidenceStationIds, groupReceiptTracesByStation, verdictColor)"
    - "Sub-component per station for isolated useRef+useFrame animation scope"
    - "MeshBasicMaterial with AdditiveBlending+toneMapped=false+depthWrite=false for bloom-friendly overlays"
    - "Zero state mutations in useFrame — only ref.position/ref.rotation mutations"
    - "Double-cast 'as unknown as T' for partial fixture objects in test makeXxx helpers"

key-files:
  created:
    - apps/workbench/src/features/observatory/components/ThreatPresetOverlay.tsx
    - apps/workbench/src/features/observatory/components/EvidencePresetOverlay.tsx
    - apps/workbench/src/features/observatory/components/ReceiptsPresetOverlay.tsx
    - apps/workbench/src/features/observatory/__tests__/analyst-preset-overlays.test.ts
  modified: []

key-decisions:
  - "Flat CircleGeometry disc placed at y=0 (ground plane) for threat wash — visually grounds the danger zone"
  - "5 orbital motes per threat district orbit at radius 5.5 (midpoint 4-7) using single MOTE_ANGULAR_SPEED=0.7"
  - "EvidenceStationHalo torus at station y+1.0 spins via delta * 0.4 in useFrame (no clock.elapsedTime needed)"
  - "ReceiptBadge uses useRef<THREE.Mesh> and mutates mesh.position.y directly in useFrame — zero allocations per frame"
  - "verdictColor checks headline for 'denied' first (highest priority), then detail/score for audit, then defaults to green allow"

patterns-established:
  - "Analyst preset overlay: self-contained R3F component + pure helper exported for unit tests"
  - "TDD cycle: write failing tests importing all helpers → create all impl files → run GREEN"

requirements-completed:
  - APR-01
  - APR-02
  - APR-03

duration: 4min
completed: 2026-03-22
---

# Phase 37 Plan 01: Analyst Preset Overlays Summary

**Three self-contained R3F overlay components (ThreatPresetOverlay, EvidencePresetOverlay, ReceiptsPresetOverlay) with 7 pure helpers TDD-covered by 21 passing unit tests — additive-blended geometry at observatory station positions for THREAT/EVIDENCE/RECEIPTS analyst presets**

## Performance

- **Duration:** 4 min
- **Started:** 2026-03-22T23:25:28Z
- **Completed:** 2026-03-22T23:28:49Z
- **Tasks:** 2
- **Files modified:** 4 (all created)

## Accomplishments
- `ThreatPresetOverlay` renders a flat red wash disc (CircleGeometry r=8) + 5 orbital danger mote spheres per active/high-pressure district, animated in useFrame with zero state mutations
- `EvidencePresetOverlay` renders gold spinning torus rings (TorusGeometry r=1.8, tube=0.06) at stations with receipt traces, spin driven by `delta * 0.4` rotation in useFrame
- `ReceiptsPresetOverlay` renders up to 3 verdict-colored badge meshes per station stacked vertically, bobbing via `Math.sin` in useFrame — ALLOW=green, DENY=red, AUDIT=amber
- 21 unit tests covering all 4 pure helpers pass in Vitest; TypeScript compiles clean in all new files

## Task Commits

Each task was committed atomically:

1. **Task 1: ThreatPresetOverlay** - `c0157aca3` (feat)
2. **Task 2: EvidencePresetOverlay + ReceiptsPresetOverlay** - `eeba456c1` (feat)

## Files Created/Modified
- `apps/workbench/src/features/observatory/components/ThreatPresetOverlay.tsx` — Red wash disc + orbital mote overlay for high-pressure districts (APR-01)
- `apps/workbench/src/features/observatory/components/EvidencePresetOverlay.tsx` — Gold spinning torus halo at receipt-bearing stations (APR-02)
- `apps/workbench/src/features/observatory/components/ReceiptsPresetOverlay.tsx` — Verdict-colored badge meshes with bob animation (APR-03)
- `apps/workbench/src/features/observatory/__tests__/analyst-preset-overlays.test.ts` — 21 unit tests for all 4 pure helpers

## Decisions Made
- Flat CircleGeometry disc at y=0 for threat wash to visually ground the danger zone at the floor
- Orbital motes use a single `MOTE_ANGULAR_SPEED=0.7` constant and phase-stagger per index to prevent synchronized orbits
- `EvidenceStationHalo` torus spins via `delta * 0.4` (frame-rate independent) rather than `clock.elapsedTime`
- `verdictColor` priority order: "denied" headline check first (denial is most critical signal), then audit detail/negative score, then green default
- `as unknown as ObservatoryDistrictRecipe` double-cast in tests for partial fixture objects (TypeScript requires this for non-overlapping types)

## Deviations from Plan

None — plan executed exactly as written.

## Issues Encountered
- TypeScript rejected `as ObservatoryDistrictRecipe` in test's `makeDistrict` helper (non-overlapping types). Fixed with `as unknown as ObservatoryDistrictRecipe` double-cast (standard TS pattern for test fixtures). Rule 1 auto-fix — minor, no behavior change.

## User Setup Required
None - no external service configuration required.

## Next Phase Readiness
- All three overlay components are ready for conditional mounting in Plan 02
- Plan 02 will import and mount them inside `ObservatoryWorldCanvas` or scene root, gated by `activePreset` store value
- No blockers

---
*Phase: 37-analyst-preset-overlays*
*Completed: 2026-03-22*
