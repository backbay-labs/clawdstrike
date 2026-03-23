# Observatory Next: Feature Research

**Domain:** ClawdStrike Workbench — Observatory Enhancements
**Researched:** 2026-03-19
**Overall confidence:** HIGH (source code read directly, no speculation)

---

## Context Recap

The workbench already has a complete observatory layer:

- `ObservatoryTab` — store bridge + mode toggle + Easter-egg controller
- `ObservatoryWorldCanvas` — R3F canvas with station spheres, probe ring, camera rig, Stars, flow terrain
- `FlowModeController` — Rapier physics, lazy-loaded, character controller Easter-egg
- `observatory-store` — stations, seamSummary, connected
- `probeRuntime.ts` — probe state machine (ready → active → cooldown)
- `probeConsequences.ts` — applies probe effects to DerivedObservatoryWorld
- `grounding.ts` — traversal surface helpers for Rapier colliders
- `propAssets.ts` — 7 asset definitions, all marked `availability: "slot"` (GLBs intentionally not present)
- `deriveObservatoryWorld.ts` — full world derivation, ~650 lines, includes `ObservatoryHeroPropRecipe`

**What does NOT exist yet in workbench:**
- `missionLoop.ts` — present in huntronomer source only
- GLB files in `public/` — present in huntronomer source only
- Any minimap component
- Any replay/recording system

---

## Feature 1: GLB Hero Props

### What the source has

Seven GLBs exist in huntronomer at `apps/desktop/public/observatory-props/`:

| Asset ID | File | Size | Station | Glow Color |
|----------|------|------|---------|------------|
| `signal-dish-tower` | signal-dish-tower.glb | 6.6 MB | Horizon (signal) | `#7cc8ff` |
| `subjects-lattice-anchor` | subjects-lattice-anchor.glb | 5.6 MB | Subjects (targets) | `#9df2dd` |
| `operations-scan-rig` | operations-scan-rig.glb | 6.1 MB | Operations (run) | `#f4d982` |
| `evidence-vault-rack` | evidence-vault-rack.glb | 6.5 MB | Evidence (receipts) | `#7ee6f2` |
| `judgment-dais` | judgment-dais.glb | 6.4 MB | Judgment (case-notes) | `#f0b87b` |
| `watchfield-sentinel-beacon` | watchfield-sentinel-beacon.glb | 6.0 MB | Watchfield (watch) | `#d3b56e` |
| `operator-drone` | operator-drone.glb | 4.3 MB | Core | `#d8c895` |

Total size: ~41.5 MB raw. All created by the huntronomer project — each is a distinct industrial/sci-fi prop matching the station's semantic role.

The `propAssets.ts` in the workbench already has the full type system (`ObservatoryHeroPropAssetDefinition`, `availability: "ready" | "slot"`) and correct URL paths. The `deriveObservatoryWorld.ts` already emits `ObservatoryHeroPropRecipe` objects with position, scale, rotation, fallback kind, and `importance`/`wakeThreshold` fields. `ObservatoryWorldCanvas.tsx` already renders the fallback procedural geometry using these recipes. The infrastructure is complete — only the GLB files are missing from the workbench `public/` folder, and `propAssets.ts` marks them all `"slot"`.

### Asset pipeline

The huntronomer source uses `useGLTF` from `@react-three/drei` (already a workbench dep). The workbench `ObservatoryWorldCanvas.tsx` comment confirms hero prop loading was deliberately removed and uses fallback geometry only (see the "Removals" comment at line 1–7). The huntronomer `propAssets.ts` marks all as `availability: "ready"` and loads them via `useGLTF(asset.url)`.

**To activate GLB props:**
1. Copy the 7 GLB directories from huntronomer `public/observatory-props/` into workbench `apps/workbench/public/observatory-props/`
2. In workbench `propAssets.ts`, change all `availability: "slot"` → `"ready"`
3. Add a `HeroPropMesh` component in `ObservatoryWorldCanvas.tsx` that calls `useGLTF(recipe.assetUrl)` when `recipe.availability === "ready"`, falls back to procedural geometry otherwise

The huntronomer source's `ObservatoryWorldCanvas.tsx` has the `useGLTF` loading pattern to reference — it conditionally renders GLB vs fallback based on the `availability` flag.

### Complexity: LOW-MEDIUM

The type system, URL mappings, and recipe generation are already in place. The work is:
- File copy (7 directories, ~41.5 MB total)
- A `HeroPropMesh` component (~80 lines) that calls `useGLTF` and applies bob animation from the recipe
- Change 7 `"slot"` → `"ready"` in `propAssets.ts`

### Dependencies
- `@react-three/drei` (useGLTF) — already in workbench
- Tauri build must copy `public/observatory-props/` — standard Vite static assets, no config change needed

### Risks

**Performance:** 41.5 MB of raw GLBs. Tauri ships a WebView; GPU memory is shared. draco-compressed or meshopt-compressed GLBs (typically 70–80% reduction) would get this to ~8–12 MB total. The huntronomer source does not appear to pre-compress them — check before copying. Use `npx gltf-transform optimize` if needed.

**Load ordering:** `useGLTF` is async. The canvas renders the fallback sphere frame-perfect, then replaces it with the GLB when loaded. This is the intended behavior per the `ObservatoryHeroPropAvailability` design. No blank-flash risk.

**Scale/pivot mismatches:** GLBs may have authoring-time scales that differ from the `scale` field in `ObservatoryHeroPropRecipe`. The recipe already has a `scale: number` field for uniform scaling — use it, but visually verify each prop at startup.

---

## Feature 2: Observatory Minimap

### What the source has

No minimap exists in either the workbench or huntronomer source. This would be net-new.

`deriveObservatoryWorld` is a pure function that returns `DerivedObservatoryWorld` containing:
- `districts: ObservatoryDistrictRecipe[]` — each with `position: ObservatoryVec3`, `id`, `colorHex`, `emphasis`, `active`, `likely`
- `watchfield: ObservatoryWatchfieldRecipe` — perimeter position and ring data
- `coreRecipe: ObservatoryCoreRecipe` — center anchor

The station positions are deterministic: 5 primary stations on a circle (radius 13.8), watchfield perimeter (radius 20.5), core at origin. This is fixed geometry — the minimap can be computed from `HUNT_STATION_PLACEMENTS` alone without calling `deriveObservatoryWorld`.

### Implementation options

**Option A: SVG (recommended)**

Pure React, zero new deps. Read station positions from `HUNT_STATION_PLACEMENTS`, map from world-space (radius ~20) to a 2D viewport (e.g., 120×120 px). Render:
- Background circle (fog boundary)
- Station dots with `colorHex` from `STATION_COLORS` in `ObservatoryWorldCanvas.tsx`
- Label text via SVG `<text>` — or skip labels at small size
- Active/probe highlight ring

Pros: lightweight, no Canvas lifecycle, CSS animations work, fully testable. Cons: no depth cue (flat). Fine for a sidebar widget.

**Option B: CSS Canvas 2D**

`<canvas ref>` + `useEffect` to draw. Similar output to SVG but imperative. No advantage over SVG at this scale. Skip.

**Option C: drei `View` with tiny R3F scene**

`@react-three/drei` `View` component shares the WebGL context with `ObservatoryWorldCanvas`. Renders a secondary camera view into a DOM element. Would give a live 3D bird's-eye of the actual scene.

Pros: depth, actual scene state visible (probe ring visible in minimap). Cons: requires the minimap to live inside the same R3F `Canvas` DOM tree as `ObservatoryWorldCanvas`, which makes sidebar placement complex — the minimap DOM element must be positioned over the canvas or `View` must be used in a portal. This is architecturally tangled with the pane system.

**Verdict: SVG is the right choice.** A 120×120 px SVG widget that maps station positions to 2D and shows emphasis/artifact counts as dot size is sufficient. It reuses existing data without adding a second R3F canvas or fighting DOM topology.

### Data source

The minimap does not need `deriveObservatoryWorld`. It only needs:
- `HUNT_STATION_PLACEMENTS` (angles, radii) — static import
- `useObservatoryStore.use.stations()` — artifact counts and status
- `STATION_COLORS` from `ObservatoryWorldCanvas.tsx` (or duplicated into a shared constant)

The `observatory-store` already has `stations: ObservatoryStation[]` with `artifactCount`.

### Complexity: LOW

~100 lines. A `ObservatoryMinimap` component, SVG, placed in the observatory sidebar panel or as a floating overlay inside `ObservatoryTab`. No new stores, no new deps.

### Dependencies
- None new. Pure React + SVG.

### Risks
- Coordinate mapping: world-space uses XZ (Y is height). SVG is XY. Map world X → SVG x, world Z → SVG y with a scale factor. This is a ~5-line transform. Not complex, but must account for the elliptical Z-axis compression (the canvas uses `z * 0.82` for the orbital ellipse).
- Sidebar placement: if shown in the observatory sidebar panel, it renders even when the ObservatoryTab is not open. This is probably desirable (at-a-glance station status). If shown as an overlay inside `ObservatoryTab`, it duplicates information already visible in the main canvas. Recommend sidebar placement.

---

## Feature 3: Observatory Missions

### What the source has

`missionLoop.ts` is fully implemented in huntronomer source at `world/missionLoop.ts` and is **100% pure TypeScript** — zero React, zero Three.js, zero side effects. It is a state machine over `ObservatoryMissionLoopState`. The workbench has already ported `probeRuntime.ts` and `probeConsequences.ts` from the same directory. `missionLoop.ts` was deliberately excluded (see `ObservatoryWorldCanvas.tsx` line 1–7 comments: "Removals: mission system (missionLoop)").

**The mission system at a glance:**

```
ObservatoryMissionLoopState {
  huntId: string
  startedAtMs: number
  completedAtMs: number | null
  status: "in-progress" | "completed"
  branch: "operations-first" | "evidence-first" | null
  completedObjectiveIds: ObservatoryMissionObjectiveId[]
  progress: ObservatoryMissionLoopProgress
}
```

Five objectives in fixed sequence:
1. `acknowledge-horizon-ingress` → station: `signal` → prop: `signal-dish-tower`
2. `resolve-subject-cluster` → station: `targets` → prop: `subjects-lattice-anchor`
3. (branch) `arm-operations-scan` or `inspect-evidence-arrival`
4. (branch) the other one
5. `seal-judgment-finding` → station: `case-notes` → prop: `judgment-dais`

Branch is determined by `deriveObservatoryMissionBranch()` — reads run vs evidence station status from `HuntObservatorySceneState`. In the workbench, the sceneState is synthetic (stations come from `observatory-store`, not a live hunt session), so branch detection will always return `"operations-first"` until the store exposes real run/evidence dynamics. This is fine — the sequence still works, it just won't branch.

**Key API:**
```typescript
createObservatoryMissionLoopState(huntId, nowMs)
getCurrentObservatoryMissionObjective(mission) → ObservatoryMissionObjective | null
completeObservatoryMissionObjective(mission, assetId, nowMs) → ObservatoryMissionLoopState
isObservatoryMissionObjectiveProp(mission, assetId) → boolean
resolveObservatoryMissionProbeTargetStationId(mission, options) → HuntStationId | null
```

**Connection to `probeConsequences.ts`:** The already-ported `applyObservatoryProbeConsequences` already accepts `mission: ObservatoryMissionLoopState | null` as its third argument. It calls `getCurrentObservatoryMissionObjective(mission)` internally to augment the probe directive read with mission context. Currently the workbench passes `null` — adding missions just means passing a real state object.

### State management

Two options:

**Option A: Local state in `ObservatoryTab` (recommended for initial port)**

`missionState` sits next to `probeState` as `useState`. Mission persists for the tab's lifetime. When the user completes an objective (presses a prop in the world), call `completeObservatoryMissionObjective`. Mission resets when the tab unmounts or user triggers a command.

Pros: zero new Zustand surface, matches the probe pattern already established, pure local state. Cons: mission is lost if the tab is closed.

**Option B: Add to `observatory-store`**

Add `mission: ObservatoryMissionLoopState | null` and `actions.startMission`, `actions.completeObjective`, `actions.resetMission`. Persists across tab close/reopen. Allows sidebar panel to show mission progress.

The store is already structured for extension (`setStations`, `addArtifacts`, etc.). This is the right home if mission state should survive tab remount.

Recommend Option B when GLB props are active (Feature 1), because objective completion is triggered by interacting with the prop — and having the mission objective highlight visible in the minimap (Feature 2) requires the mission state to be in the store.

### What needs building

1. **Port `missionLoop.ts`** verbatim from huntronomer source — ~244 lines, zero deps beyond local types. Header comment to match workbench port convention.
2. **Wire into `ObservatoryTab`** — create initial mission state, pass to `applyObservatoryProbeConsequences` (already accepts it), dispatch probe to mission objective station.
3. **Mission HUD overlay** — a `ObservatoryMissionHud` component (~80 lines) showing current objective title, hint, and action label. Similar pattern to `ObservatoryProbeHud`.
4. **Objective completion trigger** — for now, dispatch a probe to the mission objective station and advance the mission on probe completion. Full GLB interaction (click prop) is Feature 1 territory.

### Complexity: MEDIUM

- `missionLoop.ts` port: LOW (direct copy, pure functions, well-tested)
- State integration: LOW (matches existing probe pattern)
- Mission HUD component: LOW-MEDIUM
- Objective completion wiring: MEDIUM (needs a clear trigger — probe completion at target station is the right first mechanism)
- Full GLB-prop click interaction (click prop → complete objective): depends on Feature 1 being done first

### Dependencies
- Feature 1 (GLB hero props): Not strictly required, but missions referencing `assetId` fields only fully resolve visually when the actual props are present. The mission HUD works without GLBs.
- `missionLoop.ts` port from huntronomer source

### Risks

**Synthetic scene state:** `deriveObservatoryMissionBranch()` reads run vs evidence station `status` fields. The workbench `ObservatoryTab` synthesizes all station status as `"idle"`. Branch will always be `"operations-first"`. Not a bug — just means the branching logic is inert until the store provides real status. Document this.

**Mission completion trigger granularity:** Without prop-click interaction (which requires GLBs + raycasting), the only trigger is probe dispatch. The natural completion condition is "probe fired at mission objective station" — but the current `ObservatoryTab` dispatches the probe to `WORKBENCH_STATION_IDS[0]` ("signal") always. The probe target needs to follow the mission objective station, not a fixed fallback. This is a one-line change in `ObservatoryTab`.

**Objective highlight conflict:** `isObservatoryMissionObjectiveProp` is used to visually highlight the active prop. This only has visual effect when GLBs are rendered. Works without GLBs but has no visual output — the mission HUD text overlay is the only user-facing signal.

---

## Feature 4: Immersive Hunt Replay

### What the source has

No replay system exists in either the workbench or huntronomer source. This is net-new. The huntronomer source has no recording infrastructure — it renders live, ephemeral scene states.

However, the huntronomer source has two relevant building blocks:

1. **`HuntObservatorySceneState`** — the snapshot type passed to `deriveObservatoryWorld`. A replay is a time-indexed array of these snapshots.
2. **Probe state machine** — `ObservatoryProbeState` has timestamps (`activeUntilMs`, `cooldownUntilMs`). A probe history is a `{stationId, firedAtMs}[]` array.

### What would need recording

A minimal replay frame:

```typescript
interface ObservatoryReplayFrame {
  timestampMs: number
  sceneState: HuntObservatorySceneState  // station status/artifactCount at this moment
  probeEvent?: { stationId: HuntStationId }  // only present when probe fires
  missionEvent?: { objectiveId: ObservatoryMissionObjectiveId }  // only when objective completes
}

interface ObservatoryReplaySession {
  huntId: string
  startedAtMs: number
  endedAtMs: number
  frames: ObservatoryReplayFrame[]
  probePath: Array<{ stationId: HuntStationId; firedAtMs: number }>
}
```

The `HuntObservatorySceneState` contains all station statuses and artifact counts. `deriveObservatoryWorld` is deterministic — given a `sceneState`, the world is fully determined. Replay needs only to replay `sceneState` snapshots and re-run `deriveObservatoryWorld` at each tick.

**Camera path:** The probe fires at a station, the camera flies to that station (bezier flight via `WorldCameraRig`). Replay camera can follow the same path by replaying probe events in sequence, which will trigger the same camera animation.

### Playback mechanism

1. `ObservatoryTab` accepts an optional `replaySession` prop
2. When `replaySession` is present, `frameloop` is forced to `"always"` and a `useRef` holds a playhead position (ms)
3. Each frame: advance playhead, binary-search `frames` for current frame, pass its `sceneState` to canvas
4. When playhead crosses a `probeEvent`, call `dispatchObservatoryProbe` to trigger camera flight + probe ring animation
5. Playback controls: a `ObservatoryReplayControls` component with play/pause, scrub, speed multiplier

### Recording mechanism

Recording is a separate concern from playback. During a live hunt session:
- On each `HuntObservatorySceneState` change, append a frame (throttled to ~250ms)
- On each probe dispatch, append a `probeEvent`
- On each mission objective completion, append a `missionEvent`

The recorded frames are serializable JSON — can be stored in Zustand, saved to Tauri filesystem, or both.

### Complexity: HIGH

This is the most complex of the four features:

| Sub-task | Complexity |
|----------|------------|
| Frame recording in `ObservatoryTab` | LOW (throttled setState append) |
| `ObservatoryReplaySession` type design | LOW |
| Replay playback in `ObservatoryTab` | MEDIUM (playhead math, frame lookup) |
| Camera path replay | MEDIUM (probe event replay triggers existing camera rig) |
| Replay controls HUD | MEDIUM |
| Save/load via Tauri FS | MEDIUM |
| Scrub with preview | HIGH |

Total: a standalone feature, probably a 2–3 day implementation if built correctly. Not a small add-on.

### Dependencies
- Feature 3 (missions) is not required but strongly correlated — replays without mission events are less interesting
- Feature 1 (GLB props): not required but replay is much more visually rich with props visible
- Tauri `fs` plugin for save/load — already available in the workbench project

### Risks

**Frame size:** A full `HuntObservatorySceneState` is ~1 KB JSON. At 4 frames/second for a 10-minute hunt = ~2.4 MB raw. Manageable but should be delta-encoded or downsampled to state-change events only (station status changes, not polling).

**Determinism:** `deriveObservatoryWorld` uses `Math.random()` for some procedural placement variation. If it is not seeded or pure, replaying the same `sceneState` may produce different world geometry each replay. The huntronomer source uses a seeded hash for district growth structures (based on `huntId` and `stationId`). Verify `deriveObservatoryWorld` in workbench is fully deterministic before building replay. If not, record the derived world instead of the input state — but that is ~10x larger.

**Time compression:** Probe animations are 5200 ms active + 3600 ms cooldown. At 2x speed, the camera flight and probe ring animations must be time-scaled too. The `WorldCameraRig` uses `lerpSpeed` and `arrivalDurationMs` — these need to be fed a speed multiplier. Non-trivial.

**No precedent in source:** Replay is net-new in every sense. No existing infrastructure to port. Full design + implementation burden falls on the workbench.

---

## Recommended Build Order

The four features have a natural dependency graph:

```
Feature 1 (GLB props)
    │
    ├── unlocks visual richness for Feature 3 (missions)
    │       │
    │       └── missions make Feature 4 (replay) more meaningful
    │
Feature 2 (minimap)  ← independent, can land anytime
    │
    └── becomes richer when Feature 3 adds mission objective station highlight
```

**Recommended sequence:**

1. **Feature 2 (minimap)** — fastest win, standalone, zero deps on other features
2. **Feature 1 (GLB props)** — moderate effort, immediately visible payoff, enables prop-click for missions
3. **Feature 3 (missions)** — port is fast (pure function copy), HUD is fast; wiring to prop-click is where time goes
4. **Feature 4 (replay)** — build last; requires good recording hooks that features 1–3 introduce; high complexity warrants its own milestone

---

## Effort Estimates

| Feature | Port / Copy | New Code | Testing | Total |
|---------|-------------|----------|---------|-------|
| GLB props | Copy 7 GLB dirs + flip 7 flags | HeroPropMesh component (~80 LOC) | Visual verify + 1 unit test | ~0.5 day |
| Minimap | None | ~100 LOC SVG component | 1–2 unit tests | ~0.5 day |
| Missions | Port `missionLoop.ts` (~244 LOC) | HUD overlay + wiring (~150 LOC) | ~8 tests (match huntronomer missionLoop.test.ts) | ~1.5 days |
| Replay | None to port | ~500–800 LOC net-new | Significant (time-based logic) | ~2.5–3 days |

---

## Confidence Assessment

| Area | Confidence | Reason |
|------|------------|--------|
| GLB asset availability | HIGH | Files confirmed on disk, sizes measured |
| propAssets.ts slot mechanism | HIGH | Source read directly, design intent clear from comments |
| missionLoop portability | HIGH | Pure TS, no React deps, well-tested in source |
| Minimap SVG approach | HIGH | Standard React pattern, data source confirmed |
| Replay complexity | HIGH | No precedent, determinism risk documented |
| deriveObservatoryWorld determinism | MEDIUM | Not verified line-by-line; huntronomer uses seeded hash for growth, but full audit needed before replay |

---

## Open Questions

1. **Are the GLBs draco/meshopt compressed?** Check with `npx gltf-transform inspect <file>`. If uncompressed, run optimizer before copying to avoid 40+ MB cold load.
2. **Is `deriveObservatoryWorld` fully deterministic?** Audit all random/Math.random calls. If any use unseeded randomness, replay recording must capture the derived world, not the input state.
3. **Probe target in missions:** `ObservatoryTab` currently fires probe to `WORKBENCH_STATION_IDS[0]` always. Should the probe target follow the active mission objective? This is a one-line change but is a user-visible behavior change — decide before adding missions.
4. **Minimap placement:** sidebar panel overlay (always visible when observatory panel open) vs floating overlay inside `ObservatoryTab` (only visible when observatory pane is focused). Sidebar is more discoverable; overlay is more immersive.
