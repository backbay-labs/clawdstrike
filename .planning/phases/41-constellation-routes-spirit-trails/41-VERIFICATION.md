---
phase: 41-constellation-routes-spirit-trails
verified: 2026-03-22T00:00:00Z
status: passed
score: 7/7 must-haves verified
---

# Phase 41: Constellation Routes + Spirit Trails Verification Report

**Phase Goal:** Investigation history becomes permanently visible in the star layer — each completed mission traces a named constellation curve through the starfield, and the bound spirit leaves luminous trails between stations as the analyst navigates, revealing hidden connections at level 5
**Verified:** 2026-03-22
**Status:** passed
**Re-verification:** No — initial verification

## Goal Achievement

### Observable Truths

| # | Truth | Status | Evidence |
|---|-------|--------|----------|
| 1 | Completing a mission causes a luminous curve to appear in the starfield connecting the stations visited | VERIFIED | `ObservatoryTab.tsx` `prevMissionStatusRef` pattern detects `status === "completed"` transition, calls `deriveConstellationFromMission`, calls `observatoryActions.addConstellation`; `ConstellationRoutesLayer.tsx` renders CatmullRom curves at Y=40-60 via drei `<Line>` |
| 2 | Constellations persist to localStorage and are visible across sessions | VERIFIED | `savePersistedObservatoryReplayArtifactsV2` called on every constellation change (guarded by `replayArtifactsHydrated`); `loadPersistedObservatoryReplayArtifactsV2` called on mount with `addConstellation` loop; v2 persistence schema includes `constellations: ConstellationRoute[]` |
| 3 | Multiple completed missions accumulate multiple constellations in the starfield | VERIFIED | Store `constellations: []` array; `addConstellation` appends with dedup check; 12-cap with oldest eviction; `ConstellationRoutesLayer` maps all entries; `CONSTELLATION_MAX_COUNT = 12` |
| 4 | With a spirit bound, navigating between stations leaves a luminous trail in the observatory | VERIFIED | `SpiritTrailsLayer.tsx` accumulates player positions in `useFrame` via `playerFocusRef`, samples every 8 world units into 150-point ring buffer; mounted in `ObservatoryWorldScene` when `spiritAccentColor && spiritMood && spiritMood !== "dormant"` |
| 5 | Trail color and intensity reflect the spirit's current mood; trail brightness scales with spirit XP level | VERIFIED | `MOOD_CONFIG` record drives `opacityBase`/`widthBase`/`pulse` per mood; `levelMultiplier = 0.3 + (spiritLevel - 1) * 0.175` scales intensity from level 1 (faint) to level 5 (vivid); alert pulse via `Math.sin(clock.elapsedTime * 4)` |
| 6 | At spirit level 5, additional glowing dashed connections appear between non-adjacent stations | VERIFIED | `SpiritResonanceConnections.tsx` calls `deriveSpiritResonanceConnections(spiritLevel)` returning 3 cross-ring pairs; rendered with `dashed`, `dashSize=3`, `gapSize=2`; mounted in scene only when `spiritLevel >= 5` |
| 7 | Analyst can click a constellation on the star chart minimap to see its name and creation date | VERIFIED | `observatory-minimap-panel.tsx` subscribes to `state.constellations`, derives `constellationChartPaths` via useMemo, renders `<polyline>` elements in SVG; click toggles `tooltipConstellation` state; tooltip renders `name` + `toLocaleDateString` of `createdAtMs`; `data-testid="constellation-tooltip"` present |

**Score:** 7/7 truths verified

---

### Required Artifacts

| Artifact | Expected | Status | Details |
|----------|----------|--------|---------|
| `apps/workbench/src/features/observatory/components/world-canvas/ConstellationRoutesLayer.tsx` | R3F component rendering constellation curves via drei Line | VERIFIED | 112 lines; exports `ConstellationRoutesLayer`; imports `Line` from `@react-three/drei`; uses `CatmullRomCurve3`; constants `CONSTELLATION_Y_BASE=40`, `CONSTELLATION_MAX_COUNT=12`; `depthWrite={false}`, `toneMapped={false}`; `lerp` for 30% spirit accent tint |
| `apps/workbench/src/features/observatory/components/world-canvas/SpiritTrailsLayer.tsx` | R3F component rendering spirit movement trail with mood/level-driven visuals | VERIFIED | 156 lines; exports `SpiritTrailsLayer`; `MAX_TRAIL_POINTS = 150`; `MOOD_CONFIG` record with all 4 moods; `levelMultiplier` formula; `useFrame` for trail sampling; `playerFocusRef` pattern; two-segment fade rendering |
| `apps/workbench/src/features/observatory/components/world-canvas/SpiritResonanceConnections.tsx` | R3F component rendering hidden dashed connections at spirit level 5 | VERIFIED | 88 lines; exports `SpiritResonanceConnections`; calls `deriveSpiritResonanceConnections`; `OBSERVATORY_STATION_POSITIONS`; `dashed={true}` Line; animated dash-offset in `useFrame` |
| `apps/workbench/src/features/observatory/components/world-canvas/observatory-world-scene-types.ts` | Extended ObservatoryWorldSceneProps with constellation + spirit props | VERIFIED | Contains `constellations?: ConstellationRoute[]`, `spiritAccentColor?: string \| null`, `spiritMood?: SpiritMood \| null`, `spiritLevel?: number` — all Phase 41 additions present |
| `apps/workbench/src/features/observatory/components/world-canvas/ObservatoryWorldScene.tsx` | All three new layers mounted in scene graph | VERIFIED | Imports all three components; mounts `ConstellationRoutesLayer` after ProbeDeltaLayer with CNST comment; mounts `SpiritTrailsLayer` with SPRT-01/03/05 comment; mounts `SpiritResonanceConnections` with SPRT-04 comment; passes `playerFocusRef` to SpiritTrailsLayer |
| `apps/workbench/src/features/observatory/components/ObservatoryWorldCanvas.tsx` | Constellation + spirit props read from stores and threaded to scene | VERIFIED | `useObservatoryStore` for `constellations`; `useSpiritStore.use.mood()` and `.use.kind()`; `useSpiritEvolutionStore` for `spiritLevel`; `spiritMood` nulled when no spirit bound; all 4 new props passed to extracted scene |
| `apps/workbench/src/features/observatory/panels/observatory-minimap-panel.tsx` | Constellation markers on minimap SVG with hover tooltip | VERIFIED | Subscribes to `state.constellations`; `constellationChartPaths` useMemo; polyline rendering block with CNST-04 comment; `tooltipConstellation` state; tooltip with `data-testid="constellation-tooltip"` |

---

### Key Link Verification

| From | To | Via | Status | Details |
|------|----|-----|--------|---------|
| `ObservatoryTab.tsx` | `ObservatoryWorldCanvas.tsx` | `constellations` prop from observatory-store | WIRED | `const constellations = useObservatoryStore((state) => state.constellations)` in ObservatoryWorldCanvas; `constellations={constellations}` prop passed to extracted scene |
| `ObservatoryWorldCanvas.tsx` | `ObservatoryWorldScene.tsx` | constellation + spirit props threading | WIRED | `constellations={constellations}`, `spiritAccentColor={spirit?.accentColor ?? null}`, `spiritMood={spiritMood}`, `spiritLevel={spiritLevel}` all passed at line ~4789 |
| `ObservatoryWorldScene.tsx` | `ConstellationRoutesLayer.tsx` | component mount with constellations prop | WIRED | `<ConstellationRoutesLayer constellations={constellations} spiritAccentColor={spiritAccentColor} />` after ProbeDeltaLayer, guarded by `constellations.length > 0` |
| `ObservatoryWorldScene.tsx` | `SpiritTrailsLayer.tsx` | component mount with spirit trail props | WIRED | `<SpiritTrailsLayer spiritAccentColor spiritMood spiritLevel playerFocusRef={playerFocusRef} />` guarded by `spiritAccentColor && spiritMood && spiritMood !== "dormant"` |
| `ObservatoryWorldScene.tsx` | `SpiritResonanceConnections.tsx` | component mount with resonance props | WIRED | `<SpiritResonanceConnections spiritLevel spiritAccentColor />` guarded by `spiritLevel >= 5` |
| `SpiritResonanceConnections.tsx` | `observatory-derivations.ts` | `deriveSpiritResonanceConnections` for level-5 pairs | WIRED | `import { deriveSpiritResonanceConnections } from "../../utils/observatory-derivations"` called in `useMemo` |
| `ObservatoryTab.tsx` | `observatory-replay-persistence.ts` | `savePersistedObservatoryReplayArtifactsV2` on constellation change | WIRED | Both `loadPersistedObservatoryReplayArtifactsV2` and `savePersistedObservatoryReplayArtifactsV2` imported and called in two separate `useEffect` hooks |
| `observatory-minimap-panel.tsx` | `observatory-store.ts` | `useObservatoryStore` constellations subscription | WIRED | `const constellations = useObservatoryStore((state) => state.constellations)` at top of component |
| `observatory-minimap-panel.tsx` | `OBSERVATORY_STATION_POSITIONS` | `worldToChart` mapping for constellation path rendering | WIRED | `constellationChartPaths` useMemo maps `stationPath` through `worldToChart(pos[0], pos[2])` |

---

### Requirements Coverage

| Requirement | Source Plan | Description | Status | Evidence |
|-------------|------------|-------------|--------|----------|
| CNST-01 | 41-01 | Completed mission route permanently traced as constellation in starfield | SATISFIED | `prevMissionStatusRef` pattern in ObservatoryTab detects completion, calls `deriveConstellationFromMission` + `addConstellation`; `ConstellationRoutesLayer` renders into R3F scene |
| CNST-02 | 41-01 | Constellation rendered as luminous curve connecting stations, positioned above world plane in star layer | SATISFIED | CatmullRomCurve3 with Y=40-60 arc, drei `<Line>` with `opacity=0.65`, `depthWrite=false`, `toneMapped=false` |
| CNST-03 | 41-01 | Constellations persist to localStorage and visible across sessions | SATISFIED | v2 persistence schema with `constellations: ConstellationRoute[]`; hydrate-on-mount effect; auto-save-on-change effect guarded by `replayArtifactsHydrated` |
| CNST-04 | 41-03 | Analyst can click constellation in star chart minimap to see name and creation date | SATISFIED | Minimap has `<polyline>` per constellation, click toggles tooltip with `name` + `toLocaleDateString(createdAtMs)` |
| CNST-05 | 41-01 | Over multiple completed missions, starfield accumulates constellations showing investigation history | SATISFIED | `addConstellation` appends with dedup; 12-cap with oldest eviction; `ConstellationRoutesLayer` renders all `constellations` from store |
| SPRT-01 | 41-02 | Bound spirit leaves luminous trails between stations as analyst navigates | SATISFIED | `SpiritTrailsLayer` accumulates player positions in `useFrame`, renders trail only when spirit is bound and not dormant |
| SPRT-02 | 41-02 | Trail color and intensity reflect spirit's current mood | SATISFIED | `MOOD_CONFIG` record: idle=dim(0.25/0.8), active=bright(0.55/1.2), alert=pulsing(0.7/1.5 + sin oscillation), dormant=suppressed |
| SPRT-03 | 41-02 | Trail intensity scales with spirit XP level (level 1=faint, level 5=vivid) | SATISFIED | `levelMultiplier = 0.3 + (spiritLevel - 1) * 0.175` gives 0.30 at L1 through 1.0 at L5; applied to both opacity and lineWidth |
| SPRT-04 | 41-02 | At spirit level 5, trails reveal hidden resonance connections between non-adjacent stations | SATISFIED | `SpiritResonanceConnections` calls `deriveSpiritResonanceConnections` (returns 3 pairs at L5); rendered as dashed lines at Y=8 with animated dash offset |
| SPRT-05 | 41-02 | Trails use fixed-capacity geometry (max 150 points) with oldest points fading out | SATISFIED | `MAX_TRAIL_POINTS = 150` ring buffer; `shift()` evicts oldest; trail split into two `<Line>` segments where oldest quarter renders at `opacity * 0.35` |

---

### Anti-Patterns Found

None. All `return null` occurrences are legitimate guard clauses for empty arrays and degenerate input (< 2 points for lines/curves). No TODO/FIXME/PLACEHOLDER comments. No unimplemented handlers. No empty API responses.

---

### Human Verification Required

#### 1. CatmullRom constellation curves render visibly in the starfield

**Test:** Open observatory, complete a mission, observe the starfield layer.
**Expected:** A soft luminous curve (soft white with slight lavender) appears at Y=40-60, connecting the stations visited during the mission.
**Why human:** R3F Three.js rendering with bloom post-processing — curve appearance and bloom glow cannot be verified programmatically.

#### 2. Spirit trail visibility and mood reactivity

**Test:** Bind a spirit, navigate between multiple stations. Change spirit mood (idle/active/alert).
**Expected:** A luminous trail accumulates behind the player. Idle=dim, active=brighter, alert=pulsing opacity.
**Why human:** `useFrame` trail accumulation and real-time opacity changes require live rendering.

#### 3. Spirit level 5 resonance connections

**Test:** Grant spirit enough XP to reach level 5, observe observatory.
**Expected:** Three dashed luminous lines appear between non-adjacent station pairs (signal-receipts, targets-case-notes, run-watch) with animated flowing dash pattern.
**Why human:** Level gating and dash animation require live rendering.

#### 4. Constellation persistence across tab close/reopen

**Test:** Complete a mission (creates a constellation), close and reopen the observatory tab.
**Expected:** The constellation is still visible in the starfield after reopen.
**Why human:** localStorage lifecycle and React effect hydration timing requires live browser testing.

#### 5. Minimap constellation tooltip interaction

**Test:** Open observatory with completed missions, open the minimap panel, click a constellation polyline.
**Expected:** Tooltip appears at bottom-center showing constellation name and creation date. Clicking again dismisses it.
**Why human:** SVG interaction and tooltip positioning requires visual confirmation in the actual browser.

---

### Gaps Summary

No gaps found. All 10 requirements (CNST-01 through CNST-05, SPRT-01 through SPRT-05) are satisfied by substantive, wired implementations.

The full prop chain from stores to R3F rendering is intact:
- Observatory store → ObservatoryWorldCanvas → ObservatoryWorldScene → ConstellationRoutesLayer
- Spirit stores → ObservatoryWorldCanvas → ObservatoryWorldScene → SpiritTrailsLayer + SpiritResonanceConnections
- Observatory store → observatory-minimap-panel (SVG polylines + tooltip)
- ObservatoryTab orchestrates mission completion detection, constellation derivation, persistence hydration, and auto-save

All 5 commits exist in git history and map to real file changes. No placeholder implementations detected.

---

_Verified: 2026-03-22_
_Verifier: Claude (gsd-verifier)_
