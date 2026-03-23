---
phase: 41-constellation-routes-spirit-trails
plan: "01"
subsystem: observatory
tags: [constellation, r3f, persistence, spirit-accent, three.js]
dependency_graph:
  requires:
    - 39-01 (ConstellationRoute type + store actions)
    - 39-03 (observatory-derivations: deriveConstellationFromMission)
    - 39-02 (observatory-replay-persistence v2 schema)
    - 40-03 (ProbeDeltaLayer — scene position reference)
  provides:
    - ConstellationRoutesLayer R3F component (CNST-01)
    - Prop threading: ObservatoryTab -> ObservatoryWorldCanvas -> ObservatoryWorldScene -> ConstellationRoutesLayer (CNST-02)
    - localStorage v2 persistence for constellations (CNST-03)
    - Mission completion auto-derivation (CNST-01)
    - 12-constellation cap with oldest eviction (CNST-04)
  affects:
    - ObservatoryWorldScene scene graph (new layer after ProbeDeltaLayer)
    - ObservatoryWorldCanvas (new store subscription)
    - ObservatoryTab (new effects: hydrate, auto-derive, auto-save)
tech_stack:
  added:
    - "drei Line component for CatmullRom curve rendering"
  patterns:
    - "CatmullRomCurve3 with catmullrom type + tension=0.4, sampled at 64 points"
    - "THREE.Color.lerp for 30% spirit accent tint blend"
    - "depthWrite=false + toneMapped=false for bloom-ready transparent lines"
    - "prevMissionStatusRef pattern for detecting completed-status transitions"
    - "replayArtifactsHydrated guard prevents premature localStorage writes"
key_files:
  created:
    - apps/workbench/src/features/observatory/components/world-canvas/ConstellationRoutesLayer.tsx
  modified:
    - apps/workbench/src/features/observatory/components/world-canvas/observatory-world-scene-types.ts
    - apps/workbench/src/features/observatory/components/world-canvas/ObservatoryWorldScene.tsx
    - apps/workbench/src/features/observatory/components/ObservatoryWorldCanvas.tsx
    - apps/workbench/src/features/observatory/components/ObservatoryTab.tsx
decisions:
  - "CatmullRomCurve3 with catmullrom type and tension=0.4 for smooth arcs (per CONTEXT.md)"
  - "Y elevation arc 40-60 per control point index (CONSTELLATION_Y_BASE + Y_RANGE gradient)"
  - "30% spirit accent tint via THREE.Color.lerp on #e8e4f0 base (per locked CONTEXT.md decision)"
  - "depthWrite=false per locked CONTEXT.md decision"
  - "CONSTELLATION_MAX_COUNT=12 cap — oldest evicted when limit reached (per locked CONTEXT.md decision)"
  - "prevMissionStatusRef edge-case: cap check uses pre-add constellations.length >= 12 rather than > 12 since addConstellation appends"
  - "spiritAccentColor threaded via spirit?.accentColor from ObservatorySpiritVisual (already available in ObservatoryWorldCanvas outer component)"
metrics:
  duration: "308s"
  completed_date: "2026-03-22"
  tasks: 2
  files: 5
---

# Phase 41 Plan 01: Constellation Routes and Spirit Trails Summary

**One-liner:** CatmullRom constellation routes in starfield (y=40-60) with 30% spirit accent tint, localStorage v2 persistence, and mission-completion auto-derivation.

## What Was Built

**Task 1: ConstellationRoutesLayer R3F component** (`661901b43`)

Created `ConstellationRoutesLayer.tsx` — an R3F component that renders each `ConstellationRoute` in the store as a luminous CatmullRom curve elevated into the observatory star layer (Y range 40–60). Key properties:
- `drei <Line>` with `lineWidth=1.5`, `opacity=0.65`, `depthWrite=false`, `toneMapped=false`
- Station positions from `OBSERVATORY_STATION_POSITIONS` mapped to control points; Y elevated by index fraction
- `THREE.Color("#e8e4f0").lerp(new THREE.Color(spiritAccentColor), 0.3)` for the tint blend when accent color is provided
- Module constants: `CONSTELLATION_Y_BASE=40`, `CONSTELLATION_Y_RANGE=20`, `CONSTELLATION_CURVE_TENSION=0.4`, `CONSTELLATION_SAMPLE_POINTS=64`, `CONSTELLATION_MAX_COUNT=12`
- Wrapped in `<group name="constellation-routes">` with `key={route.id}`
- `useMemo` keyed on `constellations.map(c => c.id).join(",")` for referential stability

**Task 2: Prop threading and persistence** (`6565d0eb6`)

Wired the full data path from store through rendering, and persistence in both directions:

1. **Type extension** — `observatory-world-scene-types.ts` gains `constellations?: ConstellationRoute[]` and `spiritAccentColor?: string | null`
2. **Scene mount** — `ObservatoryWorldScene.tsx` destructures the new props (defaulting to `[]` / `null`) and mounts `<ConstellationRoutesLayer>` after `ProbeDeltaLayer` when `constellations.length > 0`
3. **Canvas threading** — `ObservatoryWorldCanvas.tsx` adds `const constellations = useObservatoryStore((state) => state.constellations)` and passes `constellations={constellations}` + `spiritAccentColor={spirit?.accentColor ?? null}` to the extracted scene
4. **ObservatoryTab wiring** — Three new effects added:
   - **Hydrate on mount**: calls `loadPersistedObservatoryReplayArtifactsV2()`, iterates `persistedV2.constellations` calling `observatoryActions.addConstellation` for each
   - **Auto-derive on completion**: `prevMissionStatusRef` pattern detects `"completed"` transition, calls `deriveConstellationFromMission(mission)`, overrides `name` from `firstObj.title at Station`, calls `addConstellation`, enforces 12-cap by evicting `constellations[0]` when `length >= 12`
   - **Auto-save on change**: `loadPersistedObservatoryReplayArtifactsV2()` + spread-merge + `savePersistedObservatoryReplayArtifactsV2` guarded by `replayArtifactsHydrated`

## Deviations from Plan

None — plan executed exactly as written.

## Success Criteria Verification

- [x] ConstellationRoutesLayer renders luminous curves at y=40-60 for each constellation
- [x] Mission completion triggers constellation creation via `deriveConstellationFromMission`
- [x] Constellations persist across sessions via localStorage v2
- [x] Multiple constellations accumulate (up to 12 max)
- [x] Spirit accent color tints constellation curves at 30% blend

## Self-Check

Files verified:

- [x] `apps/workbench/src/features/observatory/components/world-canvas/ConstellationRoutesLayer.tsx` — created
- [x] `apps/workbench/src/features/observatory/components/world-canvas/observatory-world-scene-types.ts` — modified
- [x] `apps/workbench/src/features/observatory/components/world-canvas/ObservatoryWorldScene.tsx` — modified
- [x] `apps/workbench/src/features/observatory/components/ObservatoryWorldCanvas.tsx` — modified
- [x] `apps/workbench/src/features/observatory/components/ObservatoryTab.tsx` — modified

Commits verified:
- `661901b43` — feat(41-01): create ConstellationRoutesLayer R3F component
- `6565d0eb6` — feat(41-01): wire constellation props through scene graph and persist to localStorage

TypeScript: `tsc --noEmit` passed with 0 errors.
Tests: 56/56 observatory test files passing; 160/193 total test files passing (33 pre-existing unrelated failures).

## Self-Check: PASSED
