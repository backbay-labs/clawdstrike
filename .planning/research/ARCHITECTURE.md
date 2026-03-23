# Architecture Patterns

**Domain:** v10.0 Observatory Analyst Toolkit — 7 new features on top of existing R3F observatory
**Researched:** 2026-03-22
**Confidence:** HIGH — based on direct inspection of all relevant existing files

---

## Existing Architecture (Confirmed State)

Before mapping integrations, the established architecture must be understood precisely:

### The Orchestration Stack

```
ObservatoryTab.tsx (1054 lines)
  ├─ Reads: observatory-store, hunt-store, spirit-store, pane-store
  ├─ Derives: liveTelemetry, effectiveTelemetry, replayFrames, replayTelemetry,
  │           sceneState, effectiveSceneState, ghostTraces, weatherState,
  │           replayMarkers, probeGuidance, ghostPresentation
  ├─ Handlers: handleSelectStation, handleDispatchProbe, handleStartMission,
  │            handleReplayToggle, handleReplayCreateAnnotation, ...
  └─ Renders:
       ObservatoryWorldCanvas (full R3F scene)
       SpaceFlightHud (flight HUD overlay)
       ObservatoryLeftDrawer (panels: explainability, mission, replay, ghost)
       ObservatoryStatusStrip (footer, presets, mode toggle)
       AchievementLayer
```

```
ObservatoryWorldCanvas.tsx (~900 lines)
  ├─ Derives: derivedWorld (from sceneState), lodTiers, eruptions
  ├─ Manages: per-frame animation, probe eruptions, district arrivals
  └─ Renders (R3F Canvas):
       ObservatoryWorldScene (15+ render layers)
         ├─ ObservatoryStarfield, ObservatoryNebulaClouds, ObservatoryWeatherLayer
         ├─ ObservatoryDistrictLayer, ObservatoryTransitLayer
         ├─ GhostTraceLayer, MissionWaypointTrail, MissionObjectiveBeacons
         ├─ ThreatPresetOverlay, EvidencePresetOverlay,
         │  ReceiptsPresetOverlay, GhostPresetOverlay
         ├─ ThesisCore, OperatorProbe, HeroConsequenceLayer, ProbeDischargeVFX
         └─ WorldCameraRig, FovController, CameraShake
```

### Store Architecture

```
observatory-store.ts (Zustand)
  stations, pressureLanes, analystPresetId, seamSummary, connected,
  confidence, likelyStationId, mission, probeState,
  replay: { enabled, frameIndex, frameMs, bookmarks, annotations, markers },
  roomReceiveState, selectedStationId, flightState, dockingState,
  autopilotTargetStationId, discoveredStations, activePanel
  HudPanelId = "explainability" | "replay" | "mission" | "ghost"

spirit-store.ts (Zustand)
  kind, mood, fieldStrength, accentColor

spirit-evolution-store.ts (Zustand, persisted to localStorage)
  evolution: Record<SpiritKind, { xp: number, level: number }>
  Level thresholds: L1=0, L2=50, L3=150, L4=350, L5=700
```

### Persistence Layer

```
observatory-replay-persistence.ts
  Key: "clawdstrike:observatory:replay:v1"
  Persists: { annotations: ObservatoryReplayAnnotation[], bookmarks: ObservatoryReplayBookmark[] }
  Pattern: loadPersistedObservatoryReplayArtifacts / savePersistedObservatoryReplayArtifacts
  Load: on ObservatoryTab mount (hydrateReplayArtifacts → store)
  Save: in useEffect watching [replayAnnotations, replayBookmarks]
```

### Key Types

```
ObservatoryReplayAnnotation {
  id, frameIndex, timestampMs, districtId, authorLabel,
  body, sourceType: "manual"|"bookmark"|"spike", sourceId?
}

ObservatoryGhostTrace {
  id, stationId, route, routeLabel, sourceKind: "finding"|"receipt",
  sourceId, authorLabel, headline, detail, timestampMs, score
}

HuntStationId = "signal"|"targets"|"run"|"receipts"|"case-notes"|"watch"

OBSERVATORY_STATION_POSITIONS: Record<HuntStationId, [number,number,number]>
  (space-scale: stations at ~300-unit radius)
```

### Render Layer Pattern (Reference)

`GhostTraceLayer.tsx` is the canonical reference for adding a new R3F scene layer:
- Pure R3F functional component
- Receives typed props derived in `ObservatoryTab`
- Reads station positions from `OBSERVATORY_STATION_POSITIONS`
- Zero store reads inside the R3F tree (all data flows in as props)
- `useFrame` for animation with pre-allocated module-level vectors
- Registered in `ObservatoryWorldScene` JSX as a self-contained layer

---

## Feature Integration Maps

### Feature 1: Replay Annotation Canvas

**What it does:** Click 3D space during replay to drop pins with text notes, draw investigation trails, persist to localStorage, visible in Replay drawer.

**Existing infrastructure already in place:**
- `ObservatoryReplayAnnotation` type exists in `types.ts` (id, frameIndex, timestampMs, districtId, authorLabel, body, sourceType)
- `upsertReplayAnnotation` / `removeReplayAnnotation` actions exist in `observatory-store.ts`
- Persistence already saves/loads annotations via `observatory-replay-persistence.ts`
- `handleReplayCreateAnnotation` callback exists in `ObservatoryTab.tsx`
- `replay.annotations` already flows through to `replayMarkers`

**What is missing / needs to be built:**
- 3D pin mesh component — `ReplayAnnotationLayer.tsx` (new R3F scene layer)
  - Renders a `<mesh>` at the clicked 3D world position per annotation
  - Only visible when `replay.enabled === true`
  - Reads `replay.annotations` from store (or receives as props from `ObservatoryWorldCanvas`)
  - Click on existing pin → opens edit modal
- Freehand trail drawing — `ReplayTrailCanvas.tsx` (new R3F scene layer)
  - Intercepts pointer events on an invisible plane mesh when "draw mode" is active
  - Builds `THREE.Line` from accumulated pointer positions
  - Needs a new trail type — `ObservatoryReplayTrail` — to store point sequences in the store
- "Draw mode" toggle button in `ReplayDrawerPanel.tsx` (existing, modify)
- Annotation list view in `ReplayDrawerPanel.tsx` (existing, modify)
- `ObservatoryWorldCanvas` needs to receive `replayAnnotations` as a prop (modify interface)
- `ObservatoryWorldScene` needs `<ReplayAnnotationLayer />` added (modify)

**Store changes:**
- `ObservatoryState.replay` needs `trails?: ObservatoryReplayTrail[]` field
- New actions: `addReplayTrail`, `removeReplayTrail`
- `PersistedObservatoryReplayArtifacts` needs `trails` added
- Persistence key version bump: `"clawdstrike:observatory:replay:v2"`

**Files to modify:**
- `types.ts` — add `ObservatoryReplayTrail` interface
- `stores/observatory-store.ts` — add trail state + actions
- `utils/observatory-replay-persistence.ts` — add trail persistence
- `components/ObservatoryWorldCanvas.tsx` — add `replayAnnotations` prop, pass to scene
- `components/world-canvas/ObservatoryWorldScene.tsx` — add `<ReplayAnnotationLayer />`
- `components/hud/panels/ReplayDrawerPanel.tsx` — add draw mode toggle + annotation list
- `components/ObservatoryTab.tsx` — wire annotation click handler into canvas

**Files to create:**
- `components/ReplayAnnotationLayer.tsx` — R3F pin + trail renderer
- `world/observatory-replay-trails.ts` — trail data utilities

---

### Feature 2: Probe Delta Cards

**What it does:** Floating 3D cards near target station after probe fires showing pressure shift, explanation, and recommended next action.

**Existing infrastructure already in place:**
- `probeState: ObservatoryProbeState` in store tracks probe status ("ready" | "active" | "cooling")
- `probeTelemetryBaselineRef.current` in `ObservatoryTab` already captures pre-probe telemetry
- `probeGuidance: ObservatoryProbeGuidance | null` is already derived in `ObservatoryTab`
  - `buildObservatoryProbeGuidance` in `world/observatory-recommendations.ts` returns guidance cards
- `probeLockedTargetStationId` flows from `ObservatoryTab` to `ObservatoryWorldScene`
- `OBSERVATORY_STATION_POSITIONS` gives the 3D anchor for each station

**What is missing / needs to be built:**
- `ProbeDeltaCard.tsx` — R3F Html card component (using drei `<Html>`)
  - Positioned at station XZ + Y offset (above station mesh)
  - Shows: pressure delta (before/after), explanation text, recommended next probe target
  - Billboard orientation (faces camera)
  - Animated entry: fade + scale in on probe "cooling" state
  - Dismisses when probe resets to "ready" or station changes
- `ProbeDeltaLayer.tsx` — R3F scene layer that renders 0–1 `ProbeDeltaCard` instances
  - Receives: `probeGuidance`, `probeStatus`, `probeLockedTargetStationId`
  - Only renders when `probeStatus === "cooling"` and guidance is non-null

**ObservatoryWorldScene changes:**
- Add `probeGuidance` prop to `ObservatoryWorldSceneProps` (modify `observatory-world-scene-types.ts`)
- Add `<ProbeDeltaLayer />` to `ObservatoryWorldScene` JSX

**ObservatoryWorldCanvas changes:**
- Accept `probeGuidance` as a prop, forward to `ObservatoryWorldScene`

**ObservatoryTab changes:**
- Pass `probeGuidance` to `ObservatoryWorldCanvas`

**Files to modify:**
- `components/world-canvas/observatory-world-scene-types.ts` — add `probeGuidance` to `ObservatoryWorldSceneProps`
- `components/world-canvas/ObservatoryWorldScene.tsx` — add `<ProbeDeltaLayer />`
- `components/ObservatoryWorldCanvas.tsx` — accept + forward `probeGuidance`
- `components/ObservatoryTab.tsx` — pass `probeGuidance` to canvas

**Files to create:**
- `components/ProbeDeltaCard.tsx` — drei `<Html>` floating card
- `components/ProbeDeltaLayer.tsx` — R3F scene layer

---

### Feature 3: Split-Screen Compare Mode

**What it does:** Side-by-side "then" (replay frame) vs "now" (live) observatory worlds with diff overlay highlighting changed stations.

**Existing infrastructure already in place:**
- `replayTelemetry` (replay frame state) and `liveTelemetry` (live state) are both derived in `ObservatoryTab`
- `liveSnapshot` and `replaySnapshot` are already derived
- `effectiveSceneState` switches between live and replay scene states
- The pane system supports split views via binary tree `PaneNode`

**What is missing / needs to be built:**
- `ObservatorySplitCompareView.tsx` — new top-level wrapper
  - Uses CSS `display: grid; grid-template-columns: 1fr 1fr`
  - Left canvas: replay scene (receives `replayTelemetry`-derived state)
  - Right canvas: live scene (receives `liveTelemetry`-derived state)
  - Both render `ObservatoryWorldCanvas` with `frameloop="demand"`
  - Diff overlay: positioned absolutely across both canvases, highlights stations where pressure delta > threshold
- `deriveObservatoryCompareState` utility — pure function
  - Input: `{ liveTelemetry, replayTelemetry }`
  - Output: `{ changedStations: { stationId, pressureDelta, statusChange }[] }`
- `ObservatoryCompareDiffOverlay.tsx` — DOM overlay (not R3F)
  - Receives `changedStations`, positions highlight badges using `useHudProjection` pattern (project 3D station positions to screen space)
- Toggle in `ObservatoryStatusStrip` or `ReplayDrawerPanel`
  - Sets `compareMode: boolean` — new state, likely `ObservatoryTab` local `useState`

**Key constraint:** Two simultaneous `ObservatoryWorldCanvas` instances both instantiate full R3F `<Canvas>` contexts. This is the most expensive feature. Use `frameloop="demand"` on both. Do not duplicate the post-processing pipeline for the compare canvases — disable `ObservatoryPostFX` in compare mode.

**Files to modify:**
- `components/ObservatoryTab.tsx` — add `compareMode` state, render `ObservatorySplitCompareView` vs standard view
- `components/hud/panels/ReplayDrawerPanel.tsx` — add compare mode toggle
- `components/ObservatoryWorldCanvas.tsx` — accept `disablePostFx?: boolean` prop

**Files to create:**
- `components/ObservatorySplitCompareView.tsx` — dual-canvas layout
- `components/ObservatoryCompareDiffOverlay.tsx` — DOM diff badge overlay
- `utils/observatory-compare.ts` — `deriveObservatoryCompareState` pure function

---

### Feature 4: Constellation Routes

**What it does:** Completed missions permanently traced as named constellations in the starfield, clickable to replay that mission.

**Existing infrastructure already in place:**
- `mission.completedObjectiveIds` tracks which objectives completed
- `mission.objectives` lists station sequence for completed missions
- `OBSERVATORY_STATION_POSITIONS` gives station positions
- `ObservatoryStarfield.tsx` renders the starfield layer
- `MissionWaypointTrail.tsx` pattern: `THREE.CatmullRomCurve3` + `THREE.TubeGeometry` with `AdditiveBlending`
- `ObservatoryReplayBookmark` already tracks mission context

**What is missing / needs to be built:**
- `ConstellationRoute` data type — represents a completed mission trace
  ```ts
  interface ConstellationRoute {
    id: string;        // mission huntId + timestamp
    label: string;     // mission briefing or auto-generated name
    stationIds: HuntStationId[];  // objective station sequence
    completedAtMs: number;
    huntId: string;
  }
  ```
- Persistence: new localStorage key `"clawdstrike:observatory:constellations:v1"`
- `ConstellationRoutesLayer.tsx` — R3F scene layer
  - Uses `THREE.CatmullRomCurve3` connecting station positions
  - Renders as thin tube or `<Line>` with dim emissive material
  - `onPointerClick` → fires `observatory:replay:load` event to jump to that mission
  - Uses `<Html>` label (drei) for constellation name
  - Permanent — visible in both atlas and replay modes
- `useConstellationRoutes` hook — loads from localStorage, derives from completed missions

**Store changes:**
- `ConstellationRoute[]` can live in `observatory-store` OR a dedicated thin store
- Recommendation: add `constellations: ConstellationRoute[]` to `observatory-store`
- New actions: `addConstellation`, `hydrateConstellations`

**ObservatoryWorldScene changes:**
- Add `<ConstellationRoutesLayer />` after `ObservatoryTransitLayer`

**ObservatoryTab changes:**
- On `mission.status === "completed"`, push a `ConstellationRoute` to store
- Hydrate constellations from localStorage alongside replay artifacts

**Files to modify:**
- `types.ts` — add `ConstellationRoute` interface
- `stores/observatory-store.ts` — add `constellations` state + actions
- `components/world-canvas/ObservatoryWorldScene.tsx` — add `<ConstellationRoutesLayer />`
- `components/ObservatoryWorldCanvas.tsx` — accept + forward `constellations` prop
- `components/ObservatoryTab.tsx` — complete-mission → add constellation, hydrate on mount

**Files to create:**
- `components/ConstellationRoutesLayer.tsx` — R3F constellation renderer
- `utils/observatory-constellation-persistence.ts` — load/save from localStorage
- `world/observatory-constellations.ts` — `deriveConstellationFromMission` utility

---

### Feature 5: Threat Topology Heatmap

**What it does:** Volumetric ground-plane gradient showing pressure intensity as continuous field, pulses with telemetry updates.

**Existing infrastructure already in place:**
- `effectiveTelemetry.stations[].emphasis` (0–1) per station — the pressure scalar
- `effectiveTelemetry.pressureLanes` with `rawPressure`, `score`, `emphasis`
- `ObservatoryDistrictLayer` already uses district pressure for emissive intensity
- `ThreatPresetOverlay.tsx` — renders danger motes at high-pressure districts (same data source)
- `world/deriveObservatoryWorld.ts` — `world.districts[].emphasis`, `world.environment`

**What is missing / needs to be built:**
- `ThreatTopologyHeatmap.tsx` — R3F scene layer
  - Ground-plane mesh (XZ plane at Y = 0 or slightly below station floor level)
  - Custom shader material using fragment shader:
    - Samples station positions and pressure values as uniforms
    - Renders smooth radial gradient blobs (SDF-based Gaussian falloff) per station
    - AdditiveBlending for overlapping pressure zones
    - Pulses opacity/intensity on telemetry updates via uniform animation
  - Uses `shaderMaterial` from drei or raw `THREE.ShaderMaterial`
  - Only visible when `analystPresetId === "threat"` OR always visible at low opacity
- Station positions passed as a uniform array (max 6 stations)
- Pressure values passed as a uniform float array

**Existing shader infrastructure:**
- `apps/workbench/src/features/observatory/shaders/` already exists (check contents)
- The pattern of custom fragment shaders is established in the codebase

**Performance note:** Ground-plane heatmap is a single mesh with custom fragment shader. One `drawCall`. Zero instancing required. This is lightweight.

**ObservatoryWorldScene changes:**
- Add `<ThreatTopologyHeatmap />` after background layers, before district layer
- Pass `stations` (from `world.districts`) with pressure values

**Files to modify:**
- `components/world-canvas/ObservatoryWorldScene.tsx` — add `<ThreatTopologyHeatmap />`
- `components/world-canvas/observatory-world-scene-types.ts` — no interface change needed if derived from `world.districts`

**Files to create:**
- `components/ThreatTopologyHeatmap.tsx` — ground-plane shader mesh
- `shaders/heatmap.frag.glsl` — fragment shader for pressure gradient (or inline as template literal)

---

### Feature 6: Spirit Resonance Trails

**What it does:** Bound spirit leaves luminous trails between stations keyed to mood/XP level, level-5 reveals hidden inter-station connections.

**Existing infrastructure already in place:**
- `spirit-store.ts`: `kind`, `mood`, `accentColor`, `fieldStrength`
- `spirit-evolution-store.ts`: `evolution[kind].level` (1–5), XP thresholds
- `spirit` prop already flows from `ObservatoryTab` → `ObservatoryWorldCanvas` as `ObservatorySpiritVisual`
- `MissionWaypointTrail.tsx` pattern: animated tube with `AdditiveBlending` — directly reusable
- `ObservatoryTransitLayer.tsx` — existing route/lane rendering between stations
- Station positions and transit route structure in `world/observatory-world-template.ts`

**What is missing / needs to be built:**
- `SpiritResonanceTrails.tsx` — R3F scene layer
  - Renders animated curved tubes between stations
  - Tube count and which connections are shown gate on spirit level:
    - Level 1–4: trails only on current mission route stations
    - Level 5: reveals hidden cross-station connections (e.g., signal ↔ receipts, targets ↔ case-notes)
  - Color: `spirit.accentColor` with luminosity keyed to `fieldStrength`
  - Animation: flow direction pulse using `useFrame` + offset `shaderMaterial` or animated `THREE.Line`
  - Mood-reactive: "alert" mood → faster pulse, "calm" mood → slow drift
  - Visibility gate: only when spirit is bound (`kind !== null`)
- `deriveSpiritResonanceConnections` utility — pure function
  - Input: `{ kind, level, stations, missionStationIds }`
  - Output: `{ connections: { from: HuntStationId, to: HuntStationId, strength: number }[] }`
  - Level-5 hidden connections are per-kind constants (each spirit kind reveals different pairs)

**Spirit level read path:**
```ts
// In ObservatoryTab:
const spiritLevel = useSpiritEvolutionStore((state) =>
  kind ? state.evolution[kind].level : 1
);
// Pass as prop to ObservatoryWorldCanvas → ObservatoryWorldScene → SpiritResonanceTrails
```

**ObservatoryWorldScene changes:**
- Add `<SpiritResonanceTrails />` near transit layer
- Needs new props: `spiritLevel`, `spiritMood`, `spiritAccentColor`

**Files to modify:**
- `components/world-canvas/observatory-world-scene-types.ts` — add spirit level/mood to scene props
- `components/world-canvas/ObservatoryWorldScene.tsx` — add `<SpiritResonanceTrails />`
- `components/ObservatoryWorldCanvas.tsx` — accept + forward spirit level/mood
- `components/ObservatoryTab.tsx` — read `spiritLevel` from evolution store, pass to canvas

**Files to create:**
- `components/SpiritResonanceTrails.tsx` — R3F trail renderer
- `world/observatory-spirit-resonance.ts` — `deriveSpiritResonanceConnections` utility

---

### Feature 7: Station Interior Zones

**What it does:** Seamless camera-push transition into detailed per-station interior layouts with unique room geometry and NPC activity.

**Existing infrastructure already in place:**
- `dockingState` in `observatory-store` tracks docking proximity and state
- `WorldCameraRig` already has `arrivalDurationMs` and `arrivalLift` for camera transitions
- `OBSERVATORY_STATION_POSITIONS` gives station origins
- `ObservatoryDistrictLayer.tsx` renders the exterior station geometry
- `StationDockingRing.tsx`, `StationFresnelGlow.tsx` already exist as per-station components
- `characterControllerEnabled` (flow mode) gates player input
- NPC crew system in `world/npcCrew.tsx` — `StationNpcCrew` already renders crew per station
- `OBSERVATORY_HERO_PROP_ASSETS` — per-station prop sets

**What is missing / needs to be built:**
- Interior state tracking — new `selectedStationId` already exists; add `interiorMode: boolean`
  - Or: derive from `dockingState.status === "docked"` + camera distance < interior threshold
- `StationInteriorScene.tsx` — per-station interior geometry component
  - One component, parameterized by `stationId`
  - Interior geometry is procedural (matching exterior aesthetic) — rooms built from box/cylinder primitives
  - 6 station interior templates as static data in `world/station-interior-templates.ts`
  - Rooms: control deck, archive bay, observation window, reactor chamber (station-dependent)
  - Interior NPC activity: reuses `StationNpcCrew` at closer scale
- Camera transition system
  - `InteriorCameraController.tsx` — overrides `WorldCameraRig` when interior mode active
  - Transition: lerp camera from exterior orbital to interior first-person/close-up position
  - Exit: double-tap back key or distance trigger
- `ObservatoryInteriorLayer.tsx` — R3F scene layer
  - Mounts `StationInteriorScene` for the currently selected/docked station
  - Handles interior/exterior fade crossfade (exterior fades out, interior fades in)

**Key architectural constraint:** Station interiors must NOT break the existing scene layer composition in `ObservatoryWorldScene`. Interiors render as an additional layer only when the camera is within the interior threshold distance. Use `visible` prop or conditional render gated on `interiorMode`, not a separate R3F `<Canvas>`.

**Files to modify:**
- `types.ts` — add `interiorMode: boolean` to `ObservatoryState` (or derive it)
- `stores/observatory-store.ts` — add `interiorMode` state + `enterInterior`/`exitInterior` actions
- `components/world-canvas/ObservatoryWorldScene.tsx` — add `<ObservatoryInteriorLayer />`
- `components/world-canvas/observatory-world-scene-types.ts` — add interior props
- `components/ObservatoryWorldCanvas.tsx` — forward `interiorMode` + `selectedStationId` to scene
- `components/ObservatoryTab.tsx` — watch docking state, trigger interior mode

**Files to create:**
- `components/ObservatoryInteriorLayer.tsx` — R3F interior mounting logic + crossfade
- `components/StationInteriorScene.tsx` — parametric interior geometry
- `world/station-interior-templates.ts` — 6 station interior layout data
- `components/InteriorCameraController.tsx` — close-up camera behavior

---

## Component Boundary Summary

### New R3F Scene Layers (added to ObservatoryWorldScene)

| Layer Component | Position in Scene | Data Source |
|----------------|-------------------|-------------|
| `ReplayAnnotationLayer` | After `GhostTraceLayer` | `replay.annotations`, `replay.trails` |
| `ProbeDeltaLayer` | After `OperatorProbe` | `probeGuidance`, `probeStatus` |
| `ConstellationRoutesLayer` | After `ObservatoryTransitLayer` | `constellations` from store |
| `ThreatTopologyHeatmap` | Before `ObservatoryDistrictLayer` | `world.districts` pressure |
| `SpiritResonanceTrails` | Near `ObservatoryTransitLayer` | `spiritLevel`, `spiritMood`, `spirit.accentColor` |
| `ObservatoryInteriorLayer` | After all district layers | `interiorMode`, `selectedStationId` |

Split-Screen Compare (`ObservatorySplitCompareView`) is a layout wrapper, not a scene layer — it instantiates two complete `ObservatoryWorldCanvas` trees side-by-side.

### New DOM Overlays (added to ObservatoryTab)

| Component | Layer | Trigger |
|-----------|-------|---------|
| `ObservatoryCompareDiffOverlay` | `z-25` above canvas | `compareMode === true && replay.enabled` |

### Modified Existing Files

| File | What Changes |
|------|-------------|
| `types.ts` | + `ObservatoryReplayTrail`, `ConstellationRoute`, `interiorMode` on `ObservatoryState` |
| `stores/observatory-store.ts` | + trail/constellation/interior state + actions |
| `utils/observatory-replay-persistence.ts` | + trails, version bump to v2 |
| `components/ObservatoryWorldCanvas.tsx` | + `replayAnnotations`, `probeGuidance`, `constellations`, `spiritLevel`, `spiritMood`, `interiorMode`, `disablePostFx` props |
| `components/world-canvas/ObservatoryWorldScene.tsx` | + 6 new layer components |
| `components/world-canvas/observatory-world-scene-types.ts` | + new props for all new layers |
| `components/ObservatoryTab.tsx` | + wire all new data → canvas, + `compareMode` state, + constellation tracking |
| `components/hud/panels/ReplayDrawerPanel.tsx` | + draw mode toggle, annotation list, compare toggle |

---

## Data Flow Changes

### Annotation Canvas Data Flow

```
[User click in replay mode]
  → ReplayAnnotationLayer pointer handler
  → ObservatoryTab.handleReplayCreateAnnotation(annotation)
  → observatoryActions.upsertReplayAnnotation(annotation)
  → relay.annotations in store
  → savePersistedObservatoryReplayArtifacts (side-effect in ObservatoryTab)
  → replayAnnotations prop → ObservatoryWorldCanvas → ObservatoryWorldScene → ReplayAnnotationLayer (re-render)
```

### Probe Delta Card Data Flow

```
[Probe fires → probeState.status changes to "cooling"]
  → probeGuidance derived in ObservatoryTab (already done, uses probeTelemetryBaselineRef)
  → probeGuidance prop → ObservatoryWorldCanvas → ObservatoryWorldScene → ProbeDeltaLayer
  → ProbeDeltaCard rendered at probeLockedTargetStationId position
```

### Constellation Data Flow

```
[Mission status becomes "completed"]
  → ObservatoryTab useEffect watching mission.status
  → deriveConstellationFromMission(mission) → ConstellationRoute
  → observatoryActions.addConstellation(constellation)
  → saveConstellations to localStorage
  → constellations prop → ObservatoryWorldCanvas → ConstellationRoutesLayer (re-render)
```

### Spirit Resonance Data Flow

```
[Spirit level changes (XP granted)]
  → spirit-evolution-store.evolution[kind].level
  → ObservatoryTab reads spiritLevel via selector
  → deriveSpiritResonanceConnections({ kind, level, stations })
  → spiritLevel prop → ObservatoryWorldCanvas → SpiritResonanceTrails
  → connections rendered as animated tubes in 3D
```

### Interior Zone Data Flow

```
[Ship docks at station (dockingState.status changes)]
  → ObservatoryTab useEffect watching dockingState
  → When docked: observatoryActions.enterInterior(stationId)
  → interiorMode prop → ObservatoryWorldCanvas → ObservatoryInteriorLayer
  → InteriorCameraController overrides WorldCameraRig
  → StationInteriorScene renders procedural interior
```

---

## Suggested Build Order

Dependencies between the 7 features must drive phase ordering. Some features have zero cross-dependencies; others require store extensions that others rely on.

### Phase A: Store + Persistence Extensions (pre-req for features 1, 4, 7)

No R3F changes. Pure TypeScript.

1. Extend `types.ts` with `ObservatoryReplayTrail`, `ConstellationRoute`
2. Extend `observatory-store.ts` with trail, constellation, interior state + actions
3. Extend `observatory-replay-persistence.ts` with trail persistence (version bump)
4. Add `utils/observatory-constellation-persistence.ts`

**Why first:** Features 1, 4, and 7 all need store changes. Getting them in cleanly before any R3F work means the scene layers have stable data contracts.

### Phase B: Data Derivation Utilities (pre-req for features 2, 4, 5, 6)

Pure functions, fully testable without R3F.

5. `world/observatory-constellations.ts` — `deriveConstellationFromMission`
6. `world/observatory-spirit-resonance.ts` — `deriveSpiritResonanceConnections`
7. `utils/observatory-compare.ts` — `deriveObservatoryCompareState`
8. Add constellation tracking to `ObservatoryTab.tsx` (detect mission complete → push constellation)

**Why second:** These pure functions define the data contracts that the R3F components will consume. Writing them first enables unit testing in isolation.

### Phase C: Independent R3F Scene Layers (no cross-dependencies)

Can be parallelized if working in separate lanes.

9. `ThreatTopologyHeatmap` (Feature 5) — derives entirely from `world.districts`, no new store fields
10. `ConstellationRoutesLayer` (Feature 4) — depends on Phase A store + Phase B utility
11. `SpiritResonanceTrails` (Feature 6) — depends on Phase B utility + spiritLevel prop threading
12. `ProbeDeltaLayer` + `ProbeDeltaCard` (Feature 2) — depends only on existing `probeGuidance`

Wire each into `ObservatoryWorldScene` and `ObservatoryWorldCanvas` prop chains as they complete.

### Phase D: Interactive R3F Layers (require pointer handling)

13. `ReplayAnnotationLayer` (Feature 1) — pointer events on 3D plane, depends on Phase A store
14. `ObservatoryInteriorLayer` + `StationInteriorScene` (Feature 7) — most complex; depends on Phase A store, requires `InteriorCameraController`

### Phase E: Layout Feature (requires two-canvas coordination)

15. `ObservatorySplitCompareView` + `ObservatoryCompareDiffOverlay` (Feature 3) — build last because it wraps `ObservatoryWorldCanvas` (which has accrued new props in phases C/D) and needs the compare utility from Phase B

**Why last:** Split-screen is the highest-cost feature (two simultaneous canvases) and depends on all the prop interface changes from phases C/D being stable. Building it last avoids re-doing the dual-canvas prop wiring multiple times.

### Dependency Graph

```
Phase A (store extensions)
  ↓
Phase B (pure derivation utils)
  ↓
Phase C (independent scene layers) — can run in parallel
  ├─ ThreatTopologyHeatmap
  ├─ ConstellationRoutesLayer
  ├─ SpiritResonanceTrails
  └─ ProbeDeltaLayer
  ↓
Phase D (interactive layers)
  ├─ ReplayAnnotationLayer
  └─ StationInteriorScene / ObservatoryInteriorLayer
  ↓
Phase E (layout wrapper)
  └─ ObservatorySplitCompareView
```

---

## Critical Constraints

### No New R3F Canvas Instances (except Feature 3)

All features except Split-Screen Compare must live inside the existing single R3F `<Canvas>` in `ObservatoryWorldCanvas.tsx`. Adding scene layers inside the existing `ObservatoryWorldScene` tree is the correct pattern, not creating additional canvases.

### Prop Threading Pattern

`ObservatoryTab` is the store bridge. All new state read from stores happens there, then flows as props:

```
stores → ObservatoryTab → ObservatoryWorldCanvas → ObservatoryWorldScene → layer component
```

Scene layer components do NOT read from Zustand stores directly. They receive typed props. This is the existing pattern (confirmed in `GhostTraceLayer`, `MissionObjectiveBeacons`, `MissionWaypointTrail`).

Exception: `MissionWaypointTrail` reads `flightState` directly via `useObservatoryStore.getState()` inside `useFrame` — this is acceptable for high-frequency per-frame reads to avoid React re-render overhead. Follow this exception pattern for features that need per-frame position data.

### ObservatoryTab Complexity Budget

`ObservatoryTab.tsx` is already 1054 lines. Each feature adds ~20–50 lines of handler + derivation code. With 7 features the file could grow to ~1350–1400 lines. This is acceptable (the existing architecture document notes this is the intended orchestrator pattern) but avoid adding new `useMemo` chains with more than 5 dependencies.

### Split-Screen Performance Gate

`ObservatorySplitCompareView` must:
1. Force `disablePostFx={true}` on both canvases — two post-processing pipelines running simultaneously will degrade performance significantly on integrated GPUs
2. Use `frameloop="demand"` on both canvases
3. Only mount when `compareMode === true && replay.enabled === true` — not as a persistent mount

### Level-5 Spirit Resonance Gate

`deriveSpiritResonanceConnections` must gate hidden connection reveal behind `level === 5` strictly. This is a product-level decision already documented in `PROJECT.md`. The function should have an explicit `if (level < 5) return []` guard for the hidden connections path, making the gate testable in unit tests.

### Annotation Persistence Schema Version

Bumping `OBSERVATORY_REPLAY_PERSISTENCE_KEY` from `v1` to `v2` requires a migration strategy. Options:
1. Attempt to read v1, migrate annotations/bookmarks forward, write as v2 (best for existing users)
2. Silently drop v1 data if v2 not found (acceptable given no production users yet)

Given v10.0 is milestone development, option 2 is sufficient. The persistence utility should check version and fall back to empty state rather than crashing on schema mismatch.

---

## Anti-Patterns to Avoid

### Avoid: R3F Store Reads in Render-Path Components

**Wrong:** Adding `useObservatoryStore.use.constellations()` inside `ConstellationRoutesLayer`
**Right:** Read in `ObservatoryTab`, derive what the layer needs, pass as props

### Avoid: Two Post-Processing Pipelines in Compare Mode

**Wrong:** Letting both `ObservatorySplitCompareView` canvases load `LazyObservatoryPostFX`
**Right:** Pass `disablePostFx={true}` to both canvas instances in compare mode

### Avoid: Interior Scene as a Separate Route

**Wrong:** Creating a `/observatory-interior/:stationId` route that opens in a new pane
**Right:** Interior is a camera + geometry transition within the same R3F canvas. The pane tab stays `/observatory`. Only the camera position and visible geometry layers change.

### Avoid: Heatmap Per-Frame Rebuild

**Wrong:** Rebuilding `PlaneGeometry` or recomputing UV maps every frame for the heatmap
**Right:** Use a custom `ShaderMaterial` with uniforms updated each frame. Geometry is static (one flat plane). Pressure values flow in as `float[6]` uniform arrays — fast GPU-side update.

### Avoid: Constellation Routes in the TransitLayer

**Wrong:** Adding constellation rendering inside `ObservatoryTransitLayer.tsx`
**Right:** `ObservatoryTransitLayer` renders mission-active routes. Constellations are permanent historical traces with different visual treatment (dimmer, different color, labeled). They belong in their own `ConstellationRoutesLayer` component.

---

## Sources

- Direct inspection: `ObservatoryTab.tsx` (full 1054-line read)
- Direct inspection: `stores/observatory-store.ts` (complete)
- Direct inspection: `components/world-canvas/ObservatoryWorldScene.tsx` (complete)
- Direct inspection: `components/world-canvas/observatory-world-scene-types.ts` (complete)
- Direct inspection: `components/ObservatoryWorldCanvas.tsx` (interface + first 234 lines)
- Direct inspection: `types.ts` (complete)
- Direct inspection: `utils/observatory-replay-persistence.ts` (complete)
- Direct inspection: `components/GhostTraceLayer.tsx` (canonical layer pattern)
- Direct inspection: `components/MissionWaypointTrail.tsx` (trail pattern + store.getState() exception)
- Direct inspection: `components/MissionObjectiveBeacons.tsx` (beacon pattern)
- Direct inspection: `stores/spirit-evolution-store.ts` (level thresholds + store shape)
- Direct inspection: `stores/spirit-store.ts` (kind/mood/accentColor)
- Direct inspection: `world/stations.ts` (station IDs and positions)
- Direct inspection: `world/observatory-ghost-memory.ts` (trace type + derive pattern)
- Direct inspection: `world/missionLoop.ts` (mission types)
- Direct inspection: `components/hud/panels/ReplayDrawerPanel.tsx` (panel pattern)
- Direct inspection: `components/hud/ObservatoryLeftDrawer.tsx` (HudPanelId pattern)
- Direct inspection: `components/hud/hud-constants.ts` (HudPanelId values, PANEL_LABELS)
- Direct inspection: `.planning/PROJECT.md` (milestone context, constraints)
- Direct inspection: `docs/plans/clawdstrike/huntronomer/observatory-analyst-experience/target-architecture.md`
- Confidence: HIGH — all findings from first-party source code inspection

---
*Architecture research for: v10.0 Observatory Analyst Toolkit (7 features)*
*Researched: 2026-03-22*
