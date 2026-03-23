---
phase: 39
plan: 03
subsystem: observatory-derivations
tags: [derivations, invalidation, pure-functions, tdd, v10.0]
dependency_graph:
  requires: ["39-01"]
  provides: ["observatory-derivations", "extended-invalidation-controller"]
  affects: ["40-threat-topology-heatmap", "41-spirit-resonance-layer", "42-annotation-pins", "43-interior-zones"]
tech_stack:
  added: []
  patterns: ["pure-function-derivation", "Float32Array-texture-data", "optional-field-backward-compat"]
key_files:
  created:
    - apps/workbench/src/features/observatory/utils/observatory-derivations.ts
    - apps/workbench/src/features/observatory/__tests__/observatory-derivations.test.ts
  modified:
    - apps/workbench/src/features/observatory/utils/observatory-performance.ts
    - apps/workbench/src/features/observatory/components/world-canvas/ObservatoryInvalidationController.tsx
decisions:
  - "RESONANCE_CONNECTIONS hardcoded as module-level constant (3 cross-ring pairs: signal-receipts, targets-case-notes, run-watch) — product decisions pre-made in plan"
  - "All 5 new ObservatoryRuntimeActivitySources fields are optional (?) for backward compatibility with existing callers"
  - "deriveHeatmapDataTexture uses reduce-max normalization — a single pass to find max, then one loop to normalize"
metrics:
  duration: "145s"
  completed_date: "2026-03-22"
  tasks_completed: 2
  files_changed: 4
---

# Phase 39 Plan 03: Derivation Utilities and Invalidation Controller Extensions Summary

Three pure derivation functions for the v10.0 Observatory Analyst Toolkit, plus extended invalidation controller sourceKey with 5 new fields for the new visual systems in Phases 40-43.

## Tasks Completed

| Task | Name | Commit | Files |
|------|------|--------|-------|
| 1 | Create derivation utilities with unit tests (TDD) | 70028c94c | observatory-derivations.ts, observatory-derivations.test.ts |
| 2 | Extend invalidation controller with 5 new source keys | 6891cd41d | observatory-performance.ts, ObservatoryInvalidationController.tsx |

## What Was Built

### Task 1: Pure Derivation Utilities

Created `apps/workbench/src/features/observatory/utils/observatory-derivations.ts` with three functions:

**`deriveConstellationFromMission(mission, nowMs?)`** — Converts a completed `ObservatoryMissionLoopState` into a `ConstellationRoute`. Returns null for in-progress missions. Station path is ordered by `completedObjectiveIds` sequence, deduplicating repeated stations. ID is deterministic: `constellation-{huntId}-{completedAtMs}`.

**`deriveSpiritResonanceConnections(spiritLevel)`** — Returns 3 cross-ring `SpiritResonanceConnection` pairs when `spiritLevel >= 5`, empty array otherwise. The 3 pairs (signal-receipts, targets-case-notes, run-watch) skip adjacent stations in the normal transit ring, creating the "hidden" Level 5 overlay in Phase 41.

**`deriveHeatmapDataTexture(pressures, stationOrder)`** — Produces a `Float32Array` of length 6 (matching `HUNT_STATION_ORDER`) with pressure values normalized to 0-1 range. All-zeros guard prevents division-by-zero. Used as shader uniform data in the Phase 40 ThreatTopologyHeatmap.

9 unit tests covering all three functions pass with TDD protocol (RED commit first, GREEN commit with implementation).

### Task 2: Invalidation Controller Extensions

Extended `ObservatoryRuntimeActivitySources` interface with 5 optional fields:
- `annotationDropCount?: number` — invalidate when annotation pins are added/removed
- `heatmapPulseVersion?: number` — invalidate when heatmap texture data changes
- `spiritTrailSegmentCount?: number` — invalidate when spirit trail geometry changes
- `constellationCount?: number` — invalidate when constellation routes are added
- `interiorTransitionPhase?: string | null` — invalidate when interior zone transitions

`ObservatoryInvalidationController.tsx` sourceKey array grows from 10 to 15 fields with null-coalesced defaults (`?? 0` or `?? "none"`). All existing callers remain valid since the interface fields are optional.

## Deviations from Plan

None — plan executed exactly as written. The `operations-scan-rig` assetId in the test fixture was corrected from `operations-scan-array` (plan used wrong asset name) to match the actual `ObservatoryHeroPropAssetId` type — this was a Rule 1 auto-fix (test data matched real type constraints).

## Self-Check: PASSED

- FOUND: apps/workbench/src/features/observatory/utils/observatory-derivations.ts
- FOUND: apps/workbench/src/features/observatory/__tests__/observatory-derivations.test.ts
- FOUND: commit 70028c94c (feat: derivation utilities)
- FOUND: commit 6891cd41d (feat: invalidation controller extensions)
