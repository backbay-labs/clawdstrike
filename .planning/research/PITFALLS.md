# Pitfalls Research

**Domain:** R3F Observatory v10.0 — Adding Analyst Toolkit Features to a Mature 3D World
**Researched:** 2026-03-22
**Confidence:** HIGH — derived from direct codebase inspection of existing invalidation system, replay persistence, performance profile, and scene layer architecture; verified against R3F and Three.js documented behavior.

> **Note:** This file supersedes the v2.0 integration pitfalls (canvas height, context limit, tab switch stutter, useFrame/Zustand boundary, NexusStateContext isolation, OrbitControls, Html labels, glia-three context, CSS stacking, stale command closures). Those pitfalls remain valid but are not repeated here. This document covers only the new pitfalls introduced by the seven v10.0 features.

---

## Critical Pitfalls

### Pitfall 1: Split-Screen Compare Mode Creates a Second WebGL Context in a Already Context-Constrained System

**What goes wrong:**
The obvious implementation of Split-Screen Compare Mode is two `<Canvas>` elements side-by-side — one for the replay frame world, one for the live world. The existing system already uses multiple WebGL contexts (Observatory, Nexus, spirit companion). Adding a second Canvas for the compare mode can push the session over the browser WebGL context limit (Chrome: 16, WebKit: 8), causing silent context loss on existing canvases. Even below the hard limit, two full observatory scenes render simultaneously, doubling draw call and overdraw load.

**Why it happens:**
Each `<Canvas>` creates a `WebGLRenderer` with its own context. R3F does not share renderers between Canvas instances. The compare mode splits the view area so each half looks smaller, making it feel like "less work" — but each half is a full observatory world running at the original context's GPU cost, just scissored.

**How to avoid:**
Use a single Canvas with scissor rendering for both views. R3F's `<View>` component (drei) enables scissor-based sub-views inside a single Canvas. The left view tracks a `div` for the replay world; the right view tracks a `div` for the live world. Both share the single WebGL context and postprocessing pipeline.

Critically: the live world already exists as the primary scene. The "then" (replay frame) world should be a lightweight re-render of the same geometry with a separate camera and scene state override — not a second mounted scene. A `frameloop="demand"` invalidation trigger that fires when `splitScreenEnabled` toggles ensures the idle side does not burn CPU.

The diff overlay (highlighting stations that changed) should be a DOM HUD layer using the existing ref-mutation pattern, not a 3D overlay that requires another draw pass.

**Warning signs:**
- Console: `THREE.WebGLRenderer: A WebGL context could not be created.`
- Spirit companion canvas goes black when split-screen opens.
- Chrome DevTools GPU tab shows two WebGLRenderer entries while split-screen is active.
- Frame time doubles immediately when split-screen activates.

**Phase to address:**
Split-Screen Compare Mode phase (feature 3). Establish the View-based scissor architecture before writing any compare world scene code. The diff overlay DOM layer must be designed before the 3D compare layer to avoid backtracking.

---

### Pitfall 2: Heatmap Shader Overdraw Destroys Frame Rate When Existing Post-Processing Pipeline is Active

**What goes wrong:**
The Threat Topology Heatmap is a volumetric ground-plane gradient. The common approach is a full-screen quad with a fragment shader that ray-marches through a pressure field. In the existing scene, the observatory already runs a `@react-three/postprocessing` EffectComposer with bloom, vignette, SMAA, LUT, and tone mapping. A volumetric shader added as a scene object (not a postprocessing effect) renders before the composer pass, meaning the bloom and tone mapping then process the heatmap pixels — causing washed-out or over-bloomed colors that do not match design intent.

The second failure mode: the heatmap fragment shader samples a 2D texture or evaluates a multi-point pressure function per-fragment across the entire ground plane. In a 300-unit radius world, the ground plane covers a large screen area. A naive per-fragment pressure evaluation at 6 stations produces acceptable results in isolation but compounds with the existing 15+ render layers (starfield, nebula, fog, bloom, weather particles, ghost traces, beacon columns) into unacceptable overdraw.

**Why it happens:**
Overdraw accumulates multiplicatively. Each semi-transparent layer that covers the same screen pixel adds to the fragment shader execution count. Existing weather particles already introduce overdraw. The heatmap, if implemented as a large translucent plane, adds another full-coverage transparent draw on top of all existing layers.

**How to avoid:**
Implement the heatmap as a postprocessing effect (a custom `Effect` subclass from `postprocessing`) rather than a scene object. This runs once per pixel after opaque rendering, reading the depth buffer to reconstruct world position and evaluate the pressure field. Cost is one full-screen pass instead of one per-fragment scene draw.

Alternatively: bake the pressure field into a small (64x64) `DataTexture` updated on telemetry change events (not per-frame), and sample that texture in a simple translucent plane material with `blending: THREE.AdditiveBlending` and `depthWrite: false`. This is a single cheap texture sample per fragment instead of per-fragment math.

The heatmap must be gated behind the existing `ObservatoryWeatherBudget` system — at `"off"` budget, skip entirely; at `"reduced"`, use the baked texture approach; at `"full"`, use the postprocessing effect.

**Warning signs:**
- Frame time spikes when heatmap is first enabled and does not recover.
- Heatmap colors look blown-out or neon — symptom of bloom processing a bright heatmap source.
- Weather budget `"off"` mode does not disable the heatmap (it should).
- GPU profiler shows a large fragment shader execution time dominated by the ground plane draw.

**Phase to address:**
Threat Topology Heatmap phase (feature 5). Verify weather budget integration before adding the heatmap to the scene. Implement the DataTexture baking approach first; the postprocessing upgrade is a later optimization.

---

### Pitfall 3: Annotation Store Bloat from Unbounded 3D Pin Serialization into LocalStorage

**What goes wrong:**
The Replay Annotation Canvas allows operators to drop 3D pins with text during replay. If each annotation stores its 3D world position as a Vector3 (`[x, y, z]`) plus a trail geometry (serialized as a point array), the localStorage entry grows unboundedly with session use. The existing replay persistence key (`clawdstrike:observatory:replay:v1`) already stores `ObservatoryReplayAnnotation[]` without any size limits. Adding 3D positions, per-pin color, and freehand trail point arrays to each annotation entry can quickly push the payload into megabytes — localStorage has a 5–10 MB quota and throws `QuotaExceededError` synchronously when full.

**Why it happens:**
`savePersistedObservatoryReplayArtifacts` does a single `localStorage.setItem` with `JSON.stringify`. Trail paths that capture high-frequency pointer events (30fps * 2-minute trail = 3600 points per trail) bloat the JSON payload. Neither the current save function nor the validation functions in `observatory-replay-persistence.ts` enforce size caps.

**How to avoid:**
Three required constraints:
1. Cap trail point arrays at a fixed sample rate (every 200ms, not every frame) and a maximum length (150 points per trail, discarding oldest when full).
2. Limit total annotation count per hunt session. Enforce an eviction policy (e.g., keep the 50 most recent by `timestampMs`).
3. Wrap `savePersistedObservatoryReplayArtifacts` in a try/catch for `QuotaExceededError` and silently drop the oldest annotation when quota is exceeded rather than crashing.

Store 3D positions as `[number, number, number]` tuples, not `THREE.Vector3` instances. The existing `asAnnotations` validator must be extended to validate the new position and trail fields and strip oversized trails on deserialization.

The annotation store slice in `useObservatoryStore` should have a derived selector `hasAnnotations` that computes a serialized byte estimate and surfaces a warning in the Replay drawer when payload approaches 1 MB.

**Warning signs:**
- `QuotaExceededError` in the browser console during a long replay session.
- Replay drawer takes >200ms to open (deserializing a large localStorage entry).
- Annotations from previous sessions are absent — overwritten because quota exceeded and save failed silently without the try/catch guard.
- `JSON.stringify(annotations).length` logged in dev tools grows by thousands on each trail creation.

**Phase to address:**
Replay Annotation Canvas phase (feature 1). The persistence schema must be designed with size constraints from the start — retrofitting them after data is already persisted requires a migration.

---

### Pitfall 4: Invalidation System Does Not Trigger on Annotation Drop or Heatmap Pulse — Scene Stays Dark

**What goes wrong:**
The observatory uses demand-based frame invalidation (`frameloop="demand"` on the Canvas). The `ObservatoryInvalidationController` watches a `sourceKey` derived from `activeHeroInteraction`, `eruptionCount`, `flyByActive`, `missionTargetStationId`, `playerInputEnabled`, `probeStatus`, `replayFrameIndex`, `replayScrubbing`, `routeSignature`, and `selectedStationId`. New visual state introduced by v10.0 features — annotation drop positions, trail drawing progress, heatmap pulse phase, spirit resonance trail updates, constellation geometry additions, and interior zone transitions — are not in this source list. If a new feature mutates 3D scene state without also triggering `invalidate()`, the change is computed but never rendered: the scene stays frozen until the next unrelated invalidation event.

**Why it happens:**
The `ObservatoryInvalidationController` was designed incrementally; each new animation source must be explicitly added to the `sourceKey` computation. This is easy to forget when implementing a feature that seems "self-contained" (e.g., a trail that appends points to a ref rather than updating a Zustand store field).

**How to avoid:**
Every new source of scene change in v10.0 must have a corresponding entry in `ObservatoryInvalidationController.sourceKey`. The specific additions needed:

- Annotation canvas: `annotationDropCount` (increments on each pin drop)
- Heatmap: `heatmapPulseVersion` (increments on telemetry update that changes pressure)
- Spirit resonance trails: `spiritTrailSegmentCount` (increments when a new trail segment is committed)
- Constellation routes: `constellationCount` (increments when a new constellation is permanently added)
- Station interiors: `interiorTransitionPhase` (changes during camera push transition)

For animations that need continuous frames (heatmap pulse glow, spirit trail fade), the weather budget system already controls `enableWeather` — add a similar `enableHeatmap` flag to `ObservatoryPerformanceProfile` and drive `shouldKeepObservatoryRealtimeActive` to return `true` when heatmap animation is active.

**Warning signs:**
- Dropping an annotation pin appears to have no visual effect until the camera moves.
- Heatmap shows correct pressure values in the store but the ground plane doesn't update.
- Spirit trail segments appear in bursts rather than smoothly (triggered only by coincidental invalidations from other sources).
- `invalidate()` call count is zero over a 10-second interval when only heatmap/trails are changing.

**Phase to address:**
Applies to all seven features (features 1–7). The invalidation extension must be the first implementation step for each feature — before any scene geometry or shader code is written.

---

### Pitfall 5: Spirit Resonance Trail Geometry Accumulates Unboundedly and Causes GPU Memory Pressure

**What goes wrong:**
Spirit Resonance Trails draw luminous paths between stations as the spirit moves. The common approach with `@react-three/drei`'s `<Trail>` component (already used in the spirit companion canvas) maintains a rolling buffer of recent positions. However, "permanent" trails that persist between stations — especially the level-5 hidden inter-station connections — require a different approach: geometry that grows over the session as more paths are traversed. If each new connection adds a new `THREE.TubeGeometry` or `THREE.BufferGeometry` to the scene without ever disposing the old ones, GPU memory accumulates indefinitely.

The problem compounds because R3F will not automatically call `.dispose()` on geometries created inside `useEffect` or `useMemo` when a component re-renders with new props. If trail segments are created as new geometry objects on each segment update, the old geometry leaks.

**Why it happens:**
Three.js geometries are not garbage collected — they must be explicitly disposed via `geometry.dispose()`. Trail libraries that grow their buffer do not share this problem because they reuse a fixed-size buffer. Custom tube geometry created per-trail-segment does not have this protection.

**How to avoid:**
Use a fixed-capacity geometry approach: pre-allocate a `THREE.BufferGeometry` with the maximum expected point count (e.g., 256 vertices per trail arc), updating the `position` attribute buffer in-place when new points are added. The attribute count does not change; only the data does.

For permanent level-5 constellation connections, represent each arc as an `instancedMesh` of pre-computed arc segments — 6 possible inter-station pairs means at most 6 arc geometries, each created once and updated by toggling visibility or opacity.

Dispose any geometry that is created dynamically (e.g., for animated trail effects) in the `useEffect` cleanup function:
```typescript
useEffect(() => {
  const geo = new THREE.TubeGeometry(curve, 32, 0.05, 8, false);
  return () => { geo.dispose(); };
}, [curve]);
```

**Warning signs:**
- Chrome DevTools Memory panel shows steadily increasing "three.js geometries" count in the GPU memory section.
- Frame time degrades gradually over a 30-minute observatory session.
- React DevTools shows `TubeGeometry` or `BufferGeometry` objects accumulating in the component tree without corresponding disposal.
- `renderer.info.memory.geometries` value climbs monotonically in dev logging.

**Phase to address:**
Spirit Resonance Trails phase (feature 6) and Constellation Routes phase (feature 4). Both involve permanent geometry that grows with session activity. Trail geometry disposal pattern must be established in feature 6 before constellation routes adds another permanent geometry layer.

---

### Pitfall 6: Station Interior Transition Breaks the Demand-Driven Invalidation and Log-Z Depth Buffer

**What goes wrong:**
The Station Interior Zone transition pushes the camera inside a per-station interior layout. Two sub-problems:

**Sub-problem A (Invalidation):** The camera transition is an animation over ~60 frames. If invalidation is demand-driven and the transition is driven by a Zustand `interiorTransitionPhase` field, the transition renders correctly only if `invalidate()` is called on every frame of the animation. Storing phase as a `0..1` float in Zustand and relying on the React re-render to drive `invalidate()` causes the transition to stutter — React batches state updates and may skip frames.

**Sub-problem B (Log-Z depth buffer):** The existing scene uses a logarithmic depth buffer (`logarithmicDepthBuffer: true` on the WebGLRenderer) to handle the 300-unit world scale. Interior zones are small (sub-5-unit rooms) and contain close-together geometry. The log-Z depth buffer trades near-plane precision for far-plane precision. In a small interior room, this inverts the trade-off: near-plane z-fighting becomes visible between closely-spaced walls, floors, and props that are less than 1 unit apart. Interior zones will exhibit z-fighting artifacts with the same renderer settings that work fine in the outer world.

**Why it happens:**
Log-Z depth buffer is calibrated for the outer world's near/far camera clip planes (e.g., `near: 0.5, far: 2000`). Interior geometry at sub-unit spacing hits the precision limit of the log-Z formula at very small distances. Transition animation driven by Zustand state misses the "always-render-during-transition" requirement of the demand invalidation system.

**How to avoid:**
For Sub-problem A: drive the transition animation entirely in `useFrame` with a mutable ref for phase, and call `invalidate()` explicitly on every frame until the transition completes. Transition completion (phase === 1) is the only moment that writes to Zustand (to persist the `insideInterior: true` state).

For Sub-problem B: when transitioning into an interior zone, temporarily adjust the camera's `near` clip plane to a smaller value (e.g., `0.02` instead of `0.5`) and ensure interior geometry has sufficient polygon separation (minimum 0.05 unit gap between co-planar surfaces). Consider disabling the log-Z buffer for the interior camera and using a standard depth buffer configured for the interior's scale. This requires switching the renderer's `logarithmicDepthBuffer` setting on the fly — which is possible via `renderer.logarithmicDepthBuffer = false` followed by recompiling affected materials' shader programs.

**Warning signs:**
- Camera transition into interior stutters or snaps rather than animating smoothly.
- Z-fighting stripes visible on interior floors and walls while outer-world geometry is clean.
- `renderer.info.programs` count spikes when entering interior — symptom of material recompilation after renderer settings change.
- Interior transition completes instantly on first try but stalls on subsequent transitions — symptom of phase being reset to 0 by Zustand re-render before the animation finishes.

**Phase to address:**
Station Interior Zones phase (feature 7). This is the most technically isolated feature and should be implemented last. The log-Z mitigation strategy (camera near adjustment vs. renderer mode swap) should be prototyped before building the full interior geometry system.

---

### Pitfall 7: Probe Delta Cards Using `<Html>` from drei Escape the Canvas Pane Boundary and Overlap HUD Chrome

**What goes wrong:**
Probe Delta Cards are floating 3D info cards near target stations. The natural implementation is `<Html>` from drei positioned at the station's world coordinates. However, the existing `<Html>` clipping problem (documented in v2.0 PITFALLS.md as Pitfall 7) applies with greater impact here: delta cards are designed to be visually prominent and positioned near stations that may be at the edge of the camera frustum. A card near the edge can partially clip outside the pane, overlapping the HUD chrome, the glassmorphism status strip, or the cockpit drawer panels.

The second issue: `<Html>` elements in drei receive pointer events. A delta card that is "behind" a 3D station mesh (occluded) but whose DOM element is still rendered in front of the HUD will intercept mouse clicks intended for HUD panel buttons.

**Why it happens:**
drei's `<Html>` portals to a sibling div of the canvas. The portal's position is computed via `project()` from the camera's frustum — correct for the 3D position, but the DOM element is not clipped to the canvas bounding box. The HUD overlay (DOM layer) sits in the same stacking context.

**How to avoid:**
Use drei's `<Html occlude portal={{ current: canvasHostDivRef.current }}>` with the `portal` prop pointing to the canvas host div. This constrains the HTML portals to the canvas host's DOM subtree, enabling `overflow: hidden` on the host to clip them.

Additionally, use the `occlude` prop so that cards behind geometry are hidden (matching the station's actual 3D visibility). This prevents occluded cards from intercepting HUD pointer events.

For cards that need to interact with the HUD (e.g., a "View Full Delta" button that opens the Replay panel), use the HUD callback pattern: the card stores its intended action in a Zustand field (`pendingDeltaCardAction`), and the HUD DOM layer reads this field to render the action button — keeping all interactive DOM in the HUD layer, not in the drei `<Html>` portal.

**Warning signs:**
- Delta card text visible outside the pane border.
- Clicking a HUD panel button activates the delta card behind it instead.
- `occlude` not set — card visible through station mesh from camera angles where it should be hidden.
- Multiple delta cards stacking on top of each other when several stations receive probes simultaneously.

**Phase to address:**
Probe Delta Cards phase (feature 2). Establish the `portal` + `occlude` pattern in the first delta card implementation before adding more card variants.

---

### Pitfall 8: Split-Screen State Sync — Two Scene States Running Different `deriveObservatoryTelemetry` Passes Diverge Silently

**What goes wrong:**
Split-Screen Compare Mode needs two observatory worlds: the "now" state (live telemetry) and the "then" state (a frozen replay snapshot). The "then" world must derive its stations, pressure lanes, and weather from the replay frame's telemetry input — a separate `DerivedObservatoryTelemetry` computed at `snapshotMs = replayFrameMs`. If both worlds read from the same `useObservatoryStore` state, they will show the same world (the live one). If the "then" world derives from a separate computation, it must receive a `previousTelemetry: null` seed (because it has no smoothing history at that point in time), causing it to show raw pressure without the hysteresis smoothing the user saw during the actual replay — making the "then" world look different from what was actually shown at that time.

**Why it happens:**
`deriveObservatoryTelemetry` uses smoothing (EWMA with `SMOOTHING_ALPHA = 0.36`) and status hysteresis to avoid jitter. The replay timeline snapshots were computed with smoothing applied at each step. A retrospective single-frame computation at `snapshotMs` without a smoothing chain produces different emphasis and status values than the originally-displayed scene — the "then" view shows different pressure values than the operator actually saw, undermining the analytical value of the comparison.

**How to avoid:**
The "then" world for split-screen must read its scene state from the already-computed `ObservatoryReplaySnapshot` stored in the replay timeline — specifically `replayTimeline.snapshots[selectedFrameIndex]`. This snapshot contains emphasis, status, and artifactCount values that were already smoothed during the original timeline build. The compare world reconstructs its `ObservatoryStation[]` array from the snapshot's `districts` array, not by re-running `deriveObservatoryTelemetry`.

Add a utility function `buildStationsFromReplaySnapshot(snapshot: ObservatoryReplaySnapshot): ObservatoryStation[]` that maps the snapshot's district data back to the station shape expected by the scene rendering code. This ensures the "then" world shows exactly what was computed when the timeline was built.

**Warning signs:**
- The "then" world shows different pressure intensities than the operator remembers from that time point.
- Diff overlay highlights stations as "changed" when the analyst believes they were the same.
- Both worlds show the live state when split-screen opens — symptom of both reading `useObservatoryStore.stations` without branching.
- Toggling between replay frames while in split-screen causes the "then" world to briefly flash the live state.

**Phase to address:**
Split-Screen Compare Mode phase (feature 3). The `buildStationsFromReplaySnapshot` utility must be implemented and tested before the split-screen visual is rendered.

---

### Pitfall 9: Constellation Route Geometry Added to the Starfield Scene Layer Conflicts with Logarithmic Depth Precision at Large Distances

**What goes wrong:**
Constellation Routes trace permanent starfield paths between station world positions. Stations are at world-space positions within the 300-unit radius world. A tube or line geometry connecting two station positions (e.g., `signal` at [50, 10, 30] to `targets` at [-60, 8, -40]) passes through large world-space distances. At the far end of the log-Z depth buffer's range, depth precision degrades: constellation lines may z-fight with nebula planes, starfield geometry, or each other when viewed from the observatory's center.

A second problem: the route geometry is "permanent" — it should survive replay mode, atlas mode, and weather changes. If it is added as a child of a group that is conditionally rendered (e.g., inside the weather layer group or the starfield group that is toggled for performance), it may disappear when those groups are hidden.

**Why it happens:**
The log-Z buffer provides good precision for the near/mid range (<100 units) but degrades for geometry that passes through both near and far zones in a single mesh. The line from station to station covers the full radius of the world. Additionally, constellation geometry added to the wrong scene group inherits that group's visibility toggle.

**How to avoid:**
Render constellation routes as a top-level scene group with `renderOrder = -1` (behind most geometry) and `depthWrite = false` combined with `depthTest = true`. Setting `depthWrite: false` prevents constellation lines from occluding other geometry while still being occluded themselves by stations and ships.

For the log-Z depth precision problem, use `THREE.Line2` (from `three/addons/lines/Line2`) with `vertexColors = true` instead of `THREE.Line`. `Line2` handles depth correctly at large scales and supports variable line width.

Constellation routes must be a child of the root scene group (not weather, not starfield, not NPC crew groups) so that visibility is independent of those systems.

**Warning signs:**
- Constellation lines appear to flicker or z-fight against the starfield when viewed from center.
- Lines disappear when weather is disabled or when replay mode changes.
- `depthWrite: true` on a constellation material causes stations to be "hidden behind" constellation geometry from certain angles.
- `THREE.Line` (not Line2) used for routes — visible as fixed 1px lines regardless of distance, which looks flat and has known depth precision issues.

**Phase to address:**
Constellation Routes phase (feature 4). The `Line2` + `depthWrite: false` approach must be decided before route geometry is built. Verify depth behavior by testing from the center of the world with multiple routes active.

---

## Technical Debt Patterns

| Shortcut | Immediate Benefit | Long-term Cost | When Acceptable |
|----------|-------------------|----------------|-----------------|
| Two full `<Canvas>` elements for split-screen | Simple implementation, no scissor setup | Second context; doubles GPU load; exceeds context limit in Tauri/WebKit | Never — use View-based scissor |
| Heatmap as scene mesh with per-fragment pressure math | Easy to prototype | Massive overdraw on 300-unit ground plane; compounds with existing 15+ transparent layers | Acceptable for a non-ship prototype; unacceptable in production |
| Storing trail point arrays without size caps in localStorage | All points preserved | `QuotaExceededError` after long sessions; data loss if not caught | Never — always cap at 150 points per trail |
| Creating new `TubeGeometry` per trail segment without disposal | Simplest geometry update approach | GPU memory leak; frame time degrades over 30-minute session | Acceptable in a test harness; never in production |
| Driving interior transition phase via Zustand state updates | Fits existing state patterns | React batching skips frames; transition stutters | Never for multi-frame animations — use `useFrame` + ref |
| Using `<Html>` without `occlude` and `portal` for delta cards | Default drei usage, no extra setup | Cards escape pane boundary; occluded cards intercept HUD clicks | Never when cards are in a scene with overlapping HUD DOM elements |
| Re-computing "then" world telemetry from raw events at `snapshotMs` | No separate snapshot storage needed | Produces different pressure values than originally shown; undermines comparison validity | Never — always read from stored `ObservatoryReplaySnapshot.districts` |

---

## Integration Gotchas

| Integration Point | Common Mistake | Correct Approach |
|-------------------|----------------|------------------|
| `ObservatoryInvalidationController` + new features | Adding new scene state without adding it to `sourceKey` | For each new visual source (annotation count, heatmap pulse, trail count, constellation count, interior phase), add a corresponding field to `sourceKey` |
| `deriveObservatoryWeatherState` + heatmap | Heatmap always visible regardless of weather budget | Gate heatmap behind `weatherBudget` check; disable at `"off"`, use baked texture at `"reduced"` |
| Replay persistence + 3D annotation positions | Storing `THREE.Vector3` objects in the annotation record | Store as `[number, number, number]` tuple; validate shape in `asAnnotations()` |
| Split-screen + existing replay store | Both worlds reading `useObservatoryStore.stations` | "Then" world reads `buildStationsFromReplaySnapshot(replayTimeline.snapshots[frameIndex])` |
| Trail geometry lifecycle | Geometry created in `useMemo` without cleanup | All dynamic geometry created with `new THREE` must have a `useEffect(() => { return () => geo.dispose(); }, [...])` pattern |
| Station interiors + log-Z depth buffer | Interior z-fighting with same camera near/far settings as outer world | Decrease camera `near` to `0.02` on interior entry; restore on exit |
| Constellation routes + scene layer group | Routes added inside weather or starfield conditional group | Constellation route group must be a direct child of the root scene; independent visibility |
| `<Html>` delta cards + HUD chrome | Interactive buttons inside `<Html>` compete with HUD events | HUD actions stored in Zustand as `pendingAction`; all interactive DOM lives in the HUD DOM layer |

---

## Performance Traps

| Trap | Symptoms | Prevention | When It Breaks |
|------|----------|------------|----------------|
| Two full Canvas elements for compare mode | Frame time doubles; context lost on spirit canvas | Single Canvas + View scissor architecture | Immediately on open in WebKit (8-context limit) |
| Heatmap volumetric shader on large ground plane | Frame time spikes >16ms when heatmap first enabled | Baked DataTexture updated on telemetry events, not per-frame shader evaluation | Visible at any display resolution on scenes with 15+ existing transparent layers |
| Unbounded trail point array in localStorage | `QuotaExceededError` in console; silent annotation data loss | 150-point cap per trail; 50-annotation eviction; try/catch around localStorage.setItem | After ~20 trail annotations in a session |
| Trail geometry not disposed on segment update | `renderer.info.memory.geometries` grows monotonically | `useEffect` cleanup calls `geometry.dispose()` on each trail segment object | Subtle degradation starting after ~10 minutes of active trail drawing |
| Zustand state driving interior transition phase | Transition stutters or snaps | `useFrame` + mutable ref for phase; Zustand written only at transition end | Every transition attempt when state batching occurs |
| Heatmap continuously triggering invalidation when idle | CPU/GPU burns when observatory is open but no probe activity | Heatmap animation frames only when `budget === "full"` AND telemetry changed since last render; otherwise static texture | Any time the observatory is left open in background |
| Constellation route geometry inside weather group | Routes disappear when weather disabled | Constellation group independent from weather group; `renderOrder = -1`, `depthWrite = false` | Every time weather is toggled off (including on reduced-motion devices) |

---

## UX Pitfalls

| Pitfall | User Impact | Better Approach |
|---------|-------------|-----------------|
| 3D annotation pin requires pixel-precise click to place in a 300-unit world | Operator misses intended location by several units; pins land on wrong stations | Snap pin placement to the nearest station's world position when within 10 units; show a preview ghost pin before click-confirm |
| Interior transition lacks orientation anchor — operator loses sense of which station they entered | After transition, operator cannot tell which station's interior they are in | Show the station name and icon in the HUD during the interior camera push; fade it out after 3 seconds |
| Freehand trail drawing during replay conflicts with camera pan (both use click-drag) | Operator accidentally pans camera while trying to draw a trail | Trail draw mode requires an explicit toggle (e.g., a pencil button in the Replay HUD panel); default click-drag remains camera pan |
| Delta cards for multiple simultaneous probe results overlap in 3D space near the same station | Cards stack on top of each other; only the topmost is readable | Use a fan layout: offset cards angularly around the station's position; each card gets its own angular slot |
| Spirit resonance trail at level 5 reveals "hidden" connections as prominent glowing arcs | Operators mistake the hidden-connection visualization for live threat data | Add a "connection origin: spirit resonance" label to these arcs; use a visually distinct style (dashed or dotted) vs. regular trails |
| Constellation route click-to-replay triggers immediately on first click | Accidental clicks on bright constellation lines trigger full mission replays | Require a two-step confirm: first click selects the constellation (highlights it); second click within 3 seconds triggers replay |

---

## "Looks Done But Isn't" Checklist

- [ ] **Annotation invalidation:** Drop a pin during replay with no camera movement — verify the pin appears without needing to move the camera. If it doesn't appear, `annotationDropCount` is not in the `sourceKey`.
- [ ] **Trail size cap:** Create 200 rapid freehand trail points in a single drawing session — verify localStorage entry stays under 100 KB. If it grows uncapped, the 150-point limit was not enforced.
- [ ] **Heatmap weather budget:** Set reduced-motion in OS settings — verify heatmap is not rendered. If it renders, it is not gated behind `weatherBudget`.
- [ ] **Split-screen context count:** Open split-screen mode while spirit companion is active — verify the spirit companion canvas does not go black. If it does, two Canvas elements were created.
- [ ] **Trail geometry disposal:** Draw 20 trail segments over 5 minutes, then check `renderer.info.memory.geometries` in dev — verify it does not exceed the initial geometry count by more than the expected fixed amount. If it grows unboundedly, `dispose()` is missing.
- [ ] **Interior transition smoothness:** Trigger an interior entry 5 times in a row — verify each transition animates smoothly without stuttering or snapping. If it stutters, phase is being driven by Zustand instead of `useFrame`.
- [ ] **Interior depth z-fighting:** Enter any station interior and look at floor/wall junctions — verify no z-fighting stripes. If they appear, camera `near` was not adjusted for interior scale.
- [ ] **Constellation independence from weather:** Disable weather via `reducedMotion = true` in the performance profile — verify constellation routes remain visible. If they disappear, they are inside the weather scene group.
- [ ] **Delta card HUD occlusion:** Position a delta card between the camera and a HUD panel button — verify the button still responds to clicks. If the card intercepts the click, `occlude` and `portal` are not set.
- [ ] **Split-screen "then" accuracy:** Select a replay frame where one station had `status: "active"` — verify the "then" world shows that station as active, not at its current live status. If it shows live status, the world is reading from `useObservatoryStore` instead of the snapshot.

---

## Recovery Strategies

| Pitfall | Recovery Cost | Recovery Steps |
|---------|---------------|----------------|
| Split-screen creates second Canvas context | MEDIUM | Introduce `<View>` scissor architecture; move compare world to a View portal tracked by a div in the split layout |
| Heatmap overdraw kills frame rate | LOW | Move heatmap to a postprocessing Effect or switch to baked DataTexture updated on telemetry change events |
| localStorage quota exceeded from trail data | LOW | Add try/catch + eviction policy to `savePersistedObservatoryReplayArtifacts`; trim trail points to 150 on next save |
| Trail geometry GPU leak | MEDIUM | Add `useEffect(() => { return () => geo.dispose(); }, [geo])` to all trail segment components; accept one GC pass to clear accumulated garbage |
| Interior transition stutter | LOW | Move `interiorTransitionPhase` from Zustand to `useRef`; drive via `useFrame`; write to Zustand only on completion |
| Constellation routes disappear with weather | LOW | Move constellation route group out of weather group; render as independent scene sibling |
| Delta cards intercept HUD clicks | LOW | Add `occlude` and `portal` props to all `<Html>` in delta card components; move interactive buttons to HUD DOM layer |
| "Then" world shows live data | MEDIUM | Implement `buildStationsFromReplaySnapshot` utility; replace `useObservatoryStore.stations` read in the compare world with snapshot-derived stations |
| Invalidation not triggering for new features | LOW | Audit `ObservatoryInvalidationController.sourceKey` against each new visual state source; add missing fields |

---

## Pitfall-to-Phase Mapping

| Pitfall | Prevention Phase | Verification |
|---------|------------------|--------------|
| Split-screen second Canvas context | Feature 3: Split-Screen Compare Mode | Open split-screen; spirit companion remains active; no "Context Lost" warning |
| Heatmap shader overdraw | Feature 5: Threat Topology Heatmap | `renderer.info.render.calls` does not spike when heatmap is enabled |
| Annotation store localStorage bloat | Feature 1: Replay Annotation Canvas | 200 rapid trail points stay under 100 KB in localStorage |
| Invalidation missing for new features | All features (1–7), first implementation step | Each new feature's visual change is visible without camera movement |
| Trail geometry GPU leak | Feature 6: Spirit Resonance Trails | `renderer.info.memory.geometries` stays stable after 20-minute session |
| Station interior log-Z z-fighting | Feature 7: Station Interior Zones | Interior floor/wall junctions show no depth artifacts |
| Interior transition Zustand stutter | Feature 7: Station Interior Zones | 5 consecutive transitions animate smoothly |
| Probe delta card HUD occlusion | Feature 2: Probe Delta Cards | Delta cards clip to pane boundary; HUD buttons respond through cards |
| Split-screen "then" world accuracy | Feature 3: Split-Screen Compare Mode | "Then" world station states match stored snapshot, not live state |
| Constellation depth z-fighting | Feature 4: Constellation Routes | Constellation lines stable when viewed from world center with all routes active |
| Constellation visibility independence | Feature 4: Constellation Routes | Routes visible with `reducedMotion = true` and weather budget `"off"` |

---

## Sources

- Direct codebase inspection: `ObservatoryInvalidationController.tsx`, `observatory-performance.ts`, `observatory-replay-persistence.ts`, `observatory-telemetry.ts`, `observatory-weather.ts`, `spirit-companion-canvas.tsx`, `FlowModeController.tsx`, `NexusCanvas.tsx`, `observatory-replay-diff.ts` — HIGH confidence
- [R3F Performance Pitfalls — demand rendering and invalidation](https://r3f.docs.pmnd.rs/advanced/pitfalls) — HIGH confidence
- [drei `<Html>` occlude and portal props](https://drei.docs.pmnd.rs/misc/html) — HIGH confidence
- [drei `<View>` scissor rendering](https://drei.docs.pmnd.rs/portals/view) — HIGH confidence
- [Three.js BufferGeometry dispose() — memory management](https://threejs.org/docs/#api/en/core/BufferGeometry.dispose) — HIGH confidence
- [Three.js logarithmicDepthBuffer — precision tradeoffs](https://threejs.org/docs/#api/en/renderers/WebGLRenderer) — HIGH confidence
- [Three.js Line2 from three/addons for large-scale lines](https://threejs.org/examples/#webgl_lines_fat) — MEDIUM confidence (example-based, not formal API doc)
- [WebGL context limit per tab — MDN and Chromium behavior](https://developer.mozilla.org/en-US/docs/Web/API/WebGLRenderingContext) — HIGH confidence
- [localStorage quota limits and QuotaExceededError — MDN](https://developer.mozilla.org/en-US/docs/Web/API/Storage/setItem) — HIGH confidence

---

*Pitfalls research for: R3F Observatory v10.0 Analyst Toolkit (7 new features on existing mature scene)*
*Researched: 2026-03-22*
