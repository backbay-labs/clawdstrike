---
phase: 39
plan: 02
subsystem: observatory-persistence
tags: [persistence, localStorage, schema-migration, tdd, annotation-pins, constellation-routes]
dependency_graph:
  requires: [39-01]
  provides: [observatory-replay-persistence-v2]
  affects: [41-constellation-persistence, 42-annotation-pin-persistence]
tech_stack:
  added: []
  patterns: [v1-to-v2-migration, validator-filter-pattern, fail-safe-fallback]
key_files:
  created: []
  modified:
    - apps/workbench/src/features/observatory/utils/observatory-replay-persistence.ts
    - apps/workbench/src/features/observatory/__tests__/observatory-replay-persistence.test.ts
decisions:
  - v2 load function tries v2 key first then falls back to v1 migration — preserves all existing data without data loss
  - validator functions use filter-not-throw pattern — malformed entries are silently dropped, matching v1 asBookmarks/asAnnotations precedent
  - v2 save function writes only to v2 key — v1 key is never updated after v2 schema is live
metrics:
  duration: 2min
  completed: "2026-03-23"
  tasks: 1
  files: 2
---

# Phase 39 Plan 02: v2 Observatory Persistence Schema Summary

**One-liner:** localStorage v2 persistence schema adding annotation pins and constellation routes, with fail-safe v1 migration that zero-initializes new fields.

## Tasks Completed

| # | Task | Commit | Status |
|---|------|--------|--------|
| 1 | Add v2 persistence schema with v1 migration (TDD) | f221b171a, 3d356c293 | Done |

## What Was Built

Extended `observatory-replay-persistence.ts` with a complete v2 schema layer:

- `OBSERVATORY_REPLAY_PERSISTENCE_KEY_V2` — new key `"clawdstrike:observatory:replay:v2"`
- `PersistedObservatoryReplayArtifactsV2` — extends v1 interface with `annotationPins: ObservatoryAnnotationPin[]` and `constellations: ConstellationRoute[]`
- `asAnnotationPins` — validator that filters entries missing required fields (id, frameIndex, timestampMs, worldPosition[3], note, districtId)
- `asConstellationRoutes` — validator that filters entries missing required fields (id, name, createdAtMs, stationPath[], missionHuntId)
- `loadPersistedObservatoryReplayArtifactsV2` — tries v2 key first, falls back to v1 key migration (annotationPins and constellations default to `[]`), returns empty defaults on error
- `savePersistedObservatoryReplayArtifactsV2` — writes only to v2 key; v1 key is untouched

All v1 exports remain intact for backward compatibility with existing code.

## Test Coverage (9 tests, all passing)

**v1 tests (2, unchanged):**
- round-trips authored replay artifacts
- falls back cleanly on malformed payloads

**v2 tests (7, new):**
1. Round-trips annotation pins and constellation routes alongside bookmarks and annotations
2. v1 data migrates to v2 with empty annotationPins and constellations
3. Prefers v2 data when both v1 and v2 keys are present
4. Falls back to empty arrays for malformed annotationPins/constellations without throwing
5. v2 save writes to v2 key only; v1 key not updated
6. asAnnotationPins validator rejects entries missing required fields
7. asConstellationRoutes validator rejects entries missing required fields

## Deviations from Plan

None — plan executed exactly as written.

## Self-Check: PASSED

- `observatory-replay-persistence.ts` contains `OBSERVATORY_REPLAY_PERSISTENCE_KEY_V2`: FOUND
- `observatory-replay-persistence.ts` contains `PersistedObservatoryReplayArtifactsV2`: FOUND
- `observatory-replay-persistence.ts` contains `loadPersistedObservatoryReplayArtifactsV2`: FOUND
- `observatory-replay-persistence.ts` contains `savePersistedObservatoryReplayArtifactsV2`: FOUND
- `observatory-replay-persistence.ts` contains `asAnnotationPins`: FOUND
- `observatory-replay-persistence.ts` contains `asConstellationRoutes`: FOUND
- Commits f221b171a (RED) and 3d356c293 (GREEN): FOUND
- 9/9 tests pass: VERIFIED
