# Feature Landscape

**Domain:** 3D observatory analyst toolkit — immersive features added to an existing R3F security observatory
**Researched:** 2026-03-22
**Milestone:** v10.0 Observatory Analyst Toolkit

---

## Context

This document covers the 7 new features for v10.0. The observatory already has a full 3D world (6 stations, NPC crews, mission loop, replay system with frame capture + spike detection + bookmarks, ghost traces, beacons, analyst preset overlays, weather, glassmorphism HUD, left drawer panels). The question for each feature is: what do users expect based on analogues in other tools, what would genuinely differentiate, and what traps to avoid.

**Existing building blocks the new features build on:**
- Replay system: `ObservatoryReplayState`, `ObservatoryReplayFrame[]`, `ObservatoryReplayAnnotation` type already defined, `savePersistedObservatoryReplayArtifacts()` already wired
- Station positions: `OBSERVATORY_STATION_POSITIONS` record (6 stations) with `[x,y,z]` tuples
- Material pattern: `MeshBasicMaterial` + `AdditiveBlending` + `toneMapped:false` is the established convention for all emissive overlay geometry
- Trail pattern: `MissionWaypointTrail` demonstrates CatmullRomCurve3 + TubeGeometry with throttled geometry rebuild
- Weather pattern: `ObservatoryWeatherLayer` demonstrates fog mutation + Sparkles overlay driven by store state
- Ghost trace pattern: `GhostTraceLayer` demonstrates per-station grouped rendering with `useFrame` opacity animation
- Probe consequence pattern: `probeConsequences.ts` demonstrates post-probe narrative text and affected station list
- Drei Html: available in `@react-three/drei` for world-space DOM overlays
- Drei View: scissor-based multi-viewport on a single canvas (requires drei 10)
- R3F events: `onClick` with `event.point` gives world-space click position directly

---

## Feature 1: Replay Annotation Canvas

**What it is:** During replay playback, operators click 3D world space to drop named pins and drag-draw investigation trails. Pins persist to localStorage. Visible in the Replay drawer and as 3D markers in the scene.

### Table Stakes

| Behavior | Why Expected | Complexity | Dependency |
|----------|--------------|------------|------------|
| Click in 3D space to place a pin | Every 3D annotation tool (Blender grease pencil, Miro, Figma FigJam, Google Earth) lets you point-click to mark locations. An annotation system without click-to-place feels broken. | LOW | R3F `onClick` on an invisible ground plane mesh. `event.point` is the world position. No raycasting code needed — R3F handles it. |
| Text label input after pin placement | Users expect to name what they found. A nameless pin is a breadcrumb with no information. Analogues: Miro sticky notes, GitHub inline comments. | LOW | `drei Html` component rendered at pin world position with a small input box. Or a modal HUD dialog driven by store state. |
| Pins persist across sessions (localStorage) | Replay annotations are investigation artifacts. Losing them on refresh = losing work. The existing `savePersistedObservatoryReplayArtifacts()` already handles this — `ObservatoryReplayAnnotation[]` is already the persistence type. | LOW | Already architected. `upsertReplayAnnotation` + `savePersistedObservatoryReplayArtifacts` already exist in the store. The 3D rendering is the missing piece. |
| Annotations appear in Replay drawer panel | The Replay panel already shows bookmarks. Users expect annotations alongside bookmarks in the same list. | LOW | `ReplayDrawerPanel` already reads `replay.bookmarks`. Extend it to also render `replay.annotations`. |
| Annotation markers visible in 3D scene during replay | Ghost trace markers (GhostTraceLayer) show how per-station 3D markers work. Annotation pins should follow the same pattern: markers at world positions, emissive material, pulse animation. | LOW | New `AnnotationPinLayer` component following `GhostTraceLayer` pattern exactly. |

### Differentiators

| Behavior | Value Proposition | Complexity | Notes |
|----------|-------------------|------------|-------|
| Freehand investigation trail drawing | Blender grease pencil lets analysts draw paths through 3D space. An analyst marking a lateral movement path across stations would draw a glowing arc connecting signal→targets→run. No security tool does this. | MEDIUM | Pointer-down + pointer-move captures sequence of world positions. Build a `LineSegments` or thin `TubeGeometry` from the captured points. Commit to annotation store on pointer-up. Existing `CatmullRomCurve3` pattern from `MissionWaypointTrail` applies directly. |
| Pin color keyed to annotation category | Blender annotations use stroke color to categorize. Pins colored by: threat (red), evidence (gold), path (cyan), question (violet) let analysts visually scan across sessions. | LOW | Add `category` field to `ObservatoryReplayAnnotation`. Map category → emissive color. Reuses the existing `sourceKind` → color pattern from `GhostTraceLayer` (receipt=gold, finding=violet). |
| "Annotation mode" toggle (so clicks don't navigate) | Unity Editor, Blender, and Google Earth all use an explicit mode switch before annotations can be placed — otherwise normal navigation clicks create accidental pins. Without a mode gate, clicking to fly to a station creates a pin instead. | LOW | `annotationModeActive: boolean` in observatory-store. When active: suppress station-select on click, route clicks to pin placement. HUD button in status strip to toggle. |
| Frame-linked pins (pin only shows on relevant replay frames) | FigJam comments on timeline frames. Pins placed at replay frame 42 should only appear when scrubber is near frame 42 — not cluttering every frame. | MEDIUM | Store `frameIndex` on each annotation (already in `ObservatoryReplayAnnotation`). In `AnnotationPinLayer`, filter visible pins by `Math.abs(pin.frameIndex - currentFrame) < WINDOW`. |

### Anti-Features

| Anti-Feature | Why Avoid | Alternative |
|--------------|-----------|-------------|
| Freehand drawing that allocates geometry every pointer-move event | Pointer-move fires at 60fps. Building new TubeGeometry on every event creates GC pressure and frame drops. | Accumulate points in a ref. Rebuild geometry only on pointer-up (commit) or throttled every 8 frames during draw. Pattern already proven in `MissionWaypointTrail`'s rebuild throttle. |
| Annotations that block normal orbit controls | If annotation canvas captures all pointer events, the operator can't orbit the camera while annotation mode is off. | Mode gate: annotation capture only active when `annotationModeActive=true`. Normal OrbitControls events pass through otherwise. |
| Full undo/redo stack | Tempting to add full undo history. Over-engineering for an annotation tool that already has delete. | Delete button on each annotation is sufficient. Undo is a v11 concern. |
| Cross-session annotation sharing / sync | Would require a backend. Annotations are local investigation artifacts. | localStorage is correct. Export-to-JSON as a future enhancement, not a v10 requirement. |

### Complexity Assessment: MEDIUM overall
- Pin placement + text label + 3D render: LOW (infrastructure already exists)
- Freehand trail drawing with throttled geometry: MEDIUM (new but uses proven patterns)
- Frame-visibility windowing: MEDIUM (filtering logic in AnnotationPinLayer)

### Dependencies on Existing Systems
- `ObservatoryReplayAnnotation` type: already defined in `types.ts`
- `upsertReplayAnnotation`, `removeReplayAnnotation`: already in observatory-store actions
- `savePersistedObservatoryReplayArtifacts`: already implemented
- `OBSERVATORY_STATION_POSITIONS`: provides world positions for spatial context
- `replay.frameIndex`: already tracked in store for frame-linked visibility

---

## Feature 2: Probe Delta Cards

**What it is:** After a probe fires at a station, a floating 3D info card appears near that station showing: pressure shift (before/after delta), explanation text, and recommended next action.

### Table Stakes

| Behavior | Why Expected | Complexity | Dependency |
|----------|--------------|------------|------------|
| Card appears near the target station after probe | Unity Gizmo handles, Blender annotations, and every HUD tooltip in games place context information near the object being examined. Probe fires → card appears at station = natural cause-and-effect. | LOW | Positioned using `OBSERVATORY_STATION_POSITIONS[stationId]` + Y offset. `drei Html` or a small R3F mesh with `Html` child. |
| Pressure delta (before minus after) with directional indicator | Security analysts need to know if the probe changed anything. Splunk dashboards and Datadog metric cards all show delta with a directional arrow. | LOW | `probeConsequences.ts` already derives `intensity` and `affectedStationIds`. Add `pressureBefore` / `pressureAfter` to `ObservatoryProbeWorldDirective` or read from station pressure lanes. |
| Explanation text from probe consequence | `probeConsequences.ts` already has `missionRead` and `crewDirective` narrative text per station. The card just needs to surface this. | LOW | Direct read from existing `ObservatoryProbeWorldDirective`. |
| Recommended next action | Analyst tools (Splunk, Elastic SIEM, Chronicle Security) all have "next step" recommendations in alert cards. | LOW | `observatory-recommendations.ts` already exists. Wire its output into the card. |
| Card auto-dismisses after probe cooldown expires | Blinking/lingering UI that never clears is a known UX anti-pattern. Probe has a `ready→active→cooldown→ready` cycle. Card should vanish when probe returns to `ready`. | LOW | Visibility gated by `probeState.status !== "ready"` in the card component. |

### Differentiators

| Behavior | Value Proposition | Complexity | Notes |
|----------|-------------------|------------|-------|
| Card face-camera billboard always | Unity HUD labels and AR annotations always face the camera. A card that you can only read from one angle is frustrating to use in a 3D environment you're orbiting. | LOW | `Billboard` component from `@react-three/drei` wraps the card group. Zero custom code. |
| Visual connection line from card to station | Aerospace telemetry dashboards and game quest markers draw a thin line from the floating label to its target. Makes clear which station the card is about when the camera is far away. | LOW | `lineSegments` from station position to card position. `LineBasicMaterial` with existing emissive color convention. |
| Card pulses in sync with probe active window | The `StationBeacon` component already does a breathing pulse animation. The delta card could share this visual rhythm — pulsing while the probe is active, dimming during cooldown. | LOW | `useFrame` animation on card opacity/scale using same sinusoidal pattern as `StationBeacon`. |
| Multiple station cards simultaneously (compound missions) | Compound missions can target multiple stations. A card per affected station (from `affectedStationIds`) turns the probe into a multi-point analysis tool. | MEDIUM | Map over `affectedStationIds` array. Each station gets a smaller secondary card. Budget: max 3 cards at once (primary + 2 affected). |

### Anti-Features

| Anti-Feature | Why Avoid | Alternative |
|--------------|-----------|-------------|
| `drei Html` for the card if it needs occlusion | `drei Html` occlusion with `occlude` prop has known performance issues when many elements are visible. For a card visible from most angles, occlusion adds overhead with minimal benefit. | Use `Html` without `occlude` — the card should always be visible since it's delivering critical probe results. If the station is off-screen, the card is off-screen too. |
| Rich interactive card (charts, sliders, expandable) | Tempting to make it a full data panel. But this is a floating 3D object in a 3D world — the user can open the full Explainability panel for rich data. The card should be glanceable. | Max 4 data fields: station name, delta value, explanation (1 line), next action (1 line). Anything more belongs in the left drawer panels. |

### Complexity Assessment: LOW-MEDIUM overall
- Basic card + position + billboard: LOW
- Pressure delta computation from existing store data: LOW
- Multi-station cards for compound missions: MEDIUM

### Dependencies on Existing Systems
- `probeConsequences.ts`: `ObservatoryProbeWorldDirective` with `missionRead`, `crewDirective`, `affectedStationIds`
- `observatory-recommendations.ts`: recommended next actions
- `probeState.status`: probe lifecycle gating card visibility
- `OBSERVATORY_STATION_POSITIONS`: card positioning
- `drei Billboard`: from existing `@react-three/drei` dep

---

## Feature 3: Split-Screen Compare Mode

**What it is:** Side-by-side "then" (frozen replay frame) vs "now" (live telemetry) observatory worlds. A diff overlay highlights which stations changed pressure between the two frames.

### Table Stakes

| Behavior | Why Expected | Complexity | Dependency |
|----------|--------------|------------|------------|
| Two simultaneous viewport renders of the same scene type | VS Code diff editor, Meld, DiffMerge, and every map comparison tool uses side-by-side. Operators have been trained by IDEs to expect this pattern for before/after analysis. | MEDIUM | `drei View` component uses `gl.scissor` to split a single canvas into two viewports. Each view gets its own camera and scene content. Single WebGL context — no performance penalty from multiple canvases. |
| "THEN" label on left / "NOW" label on right | VS Code diff labels each side. Without labels, operators don't know which side is historical. | LOW | DOM overlay (CSS position:absolute) over the canvas split. No R3F needed. |
| Diff overlay highlighting changed stations | VS Code highlights changed lines in red/green. The spatial equivalent: stations with significant pressure delta get a visual emphasis overlay (glow ring color shift, intensity change). Security analysts need to spot what moved. | MEDIUM | Compute per-station delta between frozen replay snapshot and current `pressureLanes`. Pass deltas as props to each station's district rendering. Changed stations get an additional emissive ring in red/green. |
| Shared star background (single canvas) | The scissored approach renders both views on one canvas. Stars and nebulae in the background can either be duplicated or rendered once. | LOW | `ObservatoryStarfield` and `ObservatoryNebulaClouds` can be shared across both views since they tile the full background. Each view gets its own camera + district layer. |
| Replay scrubber still controls the "then" side | Compare mode triggered from replay panel — the existing `frameIndex` controls which frozen frame appears on the left. | LOW | The "then" world reads from `ObservatoryReplaySnapshot` at `replay.frameIndex`. The "now" world reads from live store state. No new state needed. |

### Differentiators

| Behavior | Value Proposition | Complexity | Notes |
|----------|-------------------|------------|-------|
| Synchronized camera rotation between both views | Three.js documentation and Blender's split view sync camera movements in both panes when in "linked" mode. Pressing orbit on one side orbits both — disorienting to orbit one side and leave the other static. | MEDIUM | Shared `orbitRef` with camera state mirrored from the active view to the passive view. Or: use a single `PerspectiveCamera` ref and derive both view cameras from it. |
| Camera de-sync toggle ("lock/unlock" icon) | After observing synchronization, analysts often want to orbit one side independently to examine a specific station. VS Code split view allows independent scrolling. | LOW | Toggle `cameraSynced: boolean` in observatory-store. When false, views use independent OrbitControls. Icon in HUD strip. |
| "Swap sides" button | Analysts may want to put "now" on the left and "then" on the right (habitual from reading left-to-right timelines). | LOW | `swapSides: boolean` in state flips which world data goes to which scissor viewport. One boolean. |
| Delta magnitude badge per station | Map tools (Datawrapper, Kepler.gl) show numerical delta on comparison layers. A small numeric badge (+23% / -11%) on changed stations surfaces the quantitative shift without requiring full panel open. | LOW | Read `pressureLanes[stationId].score` delta. Render as `Html` label near each changed district. |

### Anti-Features

| Anti-Feature | Why Avoid | Alternative |
|--------------|-----------|-------------|
| Two separate R3F Canvas instances | Multiple WebGL contexts hit a browser limit (~8). Two canvases also can't share geometry/material instances. The three.js manual explicitly warns against this. | `drei View` with scissor on a single canvas. Already confirmed by three.js docs and `react-three-scissor` package (also pmndrs). |
| Full post-processing (EffectComposer) on both views | The existing `ObservatoryPostFX` runs EffectComposer (bloom, vignette, SMAA, DOF). Running two EffectComposers on scissored views has documented incompatibilities with the render pass system. | Disable post-processing in split mode. The scene is readable without bloom. Add a status strip indicator "Post-FX disabled in compare mode." |
| Pixel-perfect alignment expectations | Zed's blog about split diffs calls out VS Code's alignment drift during editing. In a 3D context, alignment is meaningless — stations orbit a core at different angles. Don't try to align the two views geometrically. | Independent cameras. No alignment constraint. The "diff" is conveyed by color overlays, not spatial alignment. |
| Compare mode as default or on startup | Splunk dashboards do not default to comparison mode. It's an explicit analytical action. | Gated behind the ReplayDrawerPanel "Compare" toggle that already exists as a UI element in `ReplayDrawerPanel` ("Compare toggle (now vs then)" is already in the panel comment). |

### Complexity Assessment: HIGH overall
- Scissor-based dual viewport (drei View): MEDIUM (well-supported, documented)
- Diff overlay computation: MEDIUM
- Synchronized cameras: MEDIUM
- Post-FX compatibility issue in split mode: HIGH (needs investigation, likely requires disabling EffectComposer)

### Dependencies on Existing Systems
- `ObservatoryReplaySnapshot`: frozen frame data for "then" side
- `pressureLanes`: live station pressure data for "now" side
- `ObservatoryPostFX`: must be disabled or bypassed in split mode
- `ReplayDrawerPanel`: compare toggle UI already exists (need to wire it)
- `drei View`: from existing `@react-three/drei` dep (drei 10 confirmed in stack)

---

## Feature 4: Constellation Routes

**What it is:** Completed missions permanently traced as named constellations in the starfield — glowing inter-station paths that persist in the background. Each constellation is clickable to replay that mission.

### Table Stakes

| Behavior | Why Expected | Complexity | Dependency |
|----------|--------------|------------|------------|
| Completed mission path rendered as a persistent line between visited stations | Space games (No Man's Sky hyperlane routes, Star Citizen jump lanes) and flight simulators trace completed routes. An observatory that tracks missions but leaves no trace of them feels stateless. Analysts expect their completed investigations to leave a mark on the world. | LOW | Line from each station in mission objective order. `THREE.Line` with `LineBasicMaterial`, `AdditiveBlending`, low opacity (0.3–0.5). Persisted in localStorage keyed by mission ID. Pattern is simpler than `MissionWaypointTrail`. |
| Mission name label at the constellation midpoint | Every nautical chart and star atlas labels route lines. Without a label, the constellation is decorative only. | LOW | `drei Html` at midpoint of the route path. Small monospace label matching glassmorphism design tokens. |
| Click on constellation → jump to that mission's replay | Splunk saved searches, Chronicle Security saved queries, and game journal entries are all clickable to reload context. A constellation that can't be revisited is just decoration. | LOW | `onClick` handler on the line mesh. Opens replay at the mission's saved frameIndex range. `setReplayState` + `openPanel("replay")` from observatory-store actions. |
| Constellations survive session refresh | localStorage persistence. Annotations already use this pattern — constellations follow the same contract. | LOW | New `saveConstellationRoutes()` / `loadConstellationRoutes()` following exact same pattern as `savePersistedObservatoryReplayArtifacts`. |

### Differentiators

| Behavior | Value Proposition | Complexity | Notes |
|----------|-------------------|------------|-------|
| Star-connect visual style (dots at station nodes + lines between) | Actual star constellation maps connect named stars with lines. Adding bright point markers at each station node in the constellation (beyond the normal station glow) creates recognizable constellation aesthetics distinct from the mission waypoint trail. | LOW | Small `Points` geometry or `SphereGeometry` at each station position in the route. Same `AdditiveBlending` convention. Different color per constellation (derive from mission ID hash for consistency across sessions). |
| "Nebula name" generated per constellation | Star names like "Orion" or "Perseus" for completed investigations create a poetic audit trail. Generate a two-word code name from mission ID (e.g., "Iron Witness", "Crimson Lattice"). | LOW | Deterministic name from mission ID hash. Pre-defined word list (30 adjectives × 30 nouns = 900 unique names). No randomness — same mission always = same name. |
| Constellation brightness reflects mission severity | Maps that use graduated symbol sizes to convey magnitude — more severe/complex missions produce brighter/thicker constellations. Gives the accumulated starfield semantic meaning. | LOW | Map `mission.pressureHighWaterMark` to constellation `opacity` and tube `radius`. Values already tracked in mission loop state. |
| Fade in animation on first creation | Elite Dangerous hyperspace routes fade in when charted. Immediate appearance is jarring. A 1–2s fade-in from opacity 0 → final opacity creates the sense of charting new territory. | LOW | `useEffect` with an opacity animation ref. Standard `useFrame` interpolation toward target opacity. |

### Anti-Features

| Anti-Feature | Why Avoid | Alternative |
|--------------|-----------|-------------|
| Hundreds of constellations accumulating over months | If every completed mission creates a persistent constellation, the observatory starfield eventually becomes illegible. A security tool used daily for months would generate dozens per week. | Cap at most recent N constellations (e.g., 20). Oldest are pruned when cap is exceeded. Display count in HUD status strip. Configurable via settings. |
| Dynamic tube geometry that rebuilds every frame | The constellation lines are static — they connect fixed station positions. No need for `useFrame` geometry rebuild like `MissionWaypointTrail`. | Build geometry once on mount. No `useFrame` rebuilds. Dispose on unmount. |
| Constellation interactivity that competes with station interactivity | If the constellation line overlaps a station's click target, the line intercepts the click instead of the station. | `raycast={() => null}` or `raycast={emptyRaycast}` on constellation lines when not in annotation mode. Clicks pass through to stations. |

### Complexity Assessment: LOW overall
- Persistence + rendering: LOW (direct extension of existing patterns)
- Deterministic naming: LOW
- Brightness-from-severity: LOW

### Dependencies on Existing Systems
- `ObservatoryMissionLoopState`: mission objective station sequence (already tracks which stations were visited)
- `OBSERVATORY_STATION_POSITIONS`: connection point positions
- `AdditiveBlending` + `MeshBasicMaterial` convention: established
- localStorage persistence pattern: established via `savePersistedObservatoryReplayArtifacts`

---

## Feature 5: Threat Topology Heatmap

**What it is:** A volumetric ground-plane gradient showing station pressure intensity as a continuous field — like a temperature map of threat activity. Pulses with telemetry updates.

### Table Stakes

| Behavior | Why Expected | Complexity | Dependency |
|----------|--------------|------------|------------|
| Ground-plane heatmap tinted by station pressure intensity | Security operations centers universally use heatmaps (MITRE ATT&CK heat maps, Splunk heat matrix, Chronicle Security geographic maps). An analyst observatory that doesn't show spatial pressure distribution misses the most fundamental SOC visualization pattern. | MEDIUM | Large horizontal `PlaneGeometry` (covers the station ring footprint). Custom `ShaderMaterial` with per-station pressure values as uniforms. Fragment shader samples distance to each station position and blends a `hot/cold` color ramp. ~50 lines of GLSL. |
| Color ramp from cool (low pressure) to hot (high pressure) | Industry standard: blue/teal = calm, yellow/orange = elevated, red = critical. Every SIEM heatmap uses this convention. Deviation from it confuses trained analysts. | LOW | GLSL mix() across a `cool→warm→hot` color ramp. Map `pressure.score` (0–1) to color index. |
| Visibility tied to THREAT preset | The existing `ThreatPresetOverlay` already modulates scene mood when the THREAT preset is active. The heatmap should appear/intensify in THREAT mode and dim or hide in other modes. | LOW | `analystPresetId === "threat"` gates the heatmap or modulates a global opacity uniform. Pattern: same as `ghostOpacityScale` prop in `ObservatoryWorldScene`. |
| Heatmap updates when telemetry changes | `pressureLanes` in observatory-store updates when new events arrive via `setSceneTelemetry`. The heatmap shader uniforms must update to reflect live pressure shifts. | LOW | Update uniform values in a `useEffect` or `useFrame` that reads from `pressureLanes`. `THREE.Uniform` objects mutate without triggering re-renders. |

### Differentiators

| Behavior | Value Proposition | Complexity | Notes |
|----------|-------------------|------------|-------|
| Pulse animation tied to telemetry events | Kibana dashboard tiles pulse when new alerts arrive. The heatmap could pulse (brief opacity flare) whenever `telemetrySnapshotMs` updates. Creates a live "heartbeat" sensation. | LOW | `useFrame` animation tracking `telemetrySnapshotMs` changes. When it changes, trigger a short (500ms) opacity pulse via an animated uniform. |
| Gaussian smoothing between station positions | Crude heatmaps show discrete blobs per station. Smooth Gaussian kernels (KDE) blend station pressure into a continuous field — exactly like the Kepler.gl heatmap layer and actual geographic heat maps. | MEDIUM | GLSL: for each fragment, sum `pressure[i] * gaussian(dist(frag, station[i]), sigma)` across all 6 stations. Sigma controls spread. Pre-calculate in vertex shader to reduce per-fragment cost. |
| Ground plane height responds to peak pressure | Topographic maps and terrain visualizations use Z-height to encode value — not just color. The heatmap plane could have mild vertex displacement (Y axis) to form a low-relief pressure terrain. | MEDIUM | Vertex shader displaces Y by `pressure_blend * maxDisplacement`. `PlaneGeometry` needs enough subdivisions (e.g., 64x64) to show smooth hills. Adds visual depth without affecting gameplay. |
| Heatmap fades at depth-fog boundary | The weather layer already uses `FogExp2`. The heatmap should respect fog — fading toward the outer ring where fog thickens. Avoids an abrupt cut-off at the fog boundary. | LOW | Standard fog integration in the ShaderMaterial: include `THREE.ShaderChunk.fog_frag` or replicate fog formula in the custom shader. |

### Anti-Features

| Anti-Feature | Why Avoid | Alternative |
|--------------|-----------|-------------|
| Solid/opaque heatmap plane | An opaque heat map would cover the ground geometry, NPC crew positions, and space lane decorations beneath it. | `depthWrite: false`, `transparent: true`, opacity 0.3–0.5. Same convention as all other overlay layers in the scene. |
| CPU-side heatmap texture rebuild every frame | Using `Canvas2D` API to repaint a texture and `texture.needsUpdate = true` every frame is the "Projecting Dynamic Textures" approach from 2016. At 60fps this creates GC pressure from canvas ImageData operations. | All computation in GLSL shader uniforms. Zero CPU-side texture rebuilds. Pressure values are 6 floats — trivially cheap as uniforms. |
| Always-on at full opacity | A bright heatmap visible in every mode would compete visually with all other overlays (ghost traces, beacons, weather). | Default opacity: 0 (hidden). Fade in when THREAT preset is active. Operator can pin it via HUD toggle. |
| Heatmap that obscures station meshes | If the plane sits at Y=0 and stations also have base elements at Y=0, Z-fighting artifacts appear. | Offset the heatmap plane slightly below station base level (Y = -1.0 or clamp above ground). |

### Complexity Assessment: MEDIUM overall
- Basic shader heatmap: MEDIUM (GLSL required, but straightforward)
- Gaussian smoothing + vertex displacement: MEDIUM
- Telemetry update wiring: LOW

### Dependencies on Existing Systems
- `pressureLanes`: per-station pressure scores (the data source)
- `analystPresetId`: gates visibility in THREAT mode
- `telemetrySnapshotMs`: pulse animation trigger
- `OBSERVATORY_STATION_POSITIONS`: station positions passed as shader uniforms
- `ObservatoryPostFX` (bloom): the heatmap's emissive contribution will bloom — desired effect
- Fog (`FogExp2`): shader must account for fog density

---

## Feature 6: Spirit Resonance Trails

**What it is:** The bound spirit leaves luminous trails between stations reflecting its movement history, keyed to mood and XP level. Level 5 reveals hidden inter-station connections not visible at lower levels.

### Table Stakes

| Behavior | Why Expected | Complexity | Dependency |
|----------|--------------|------------|------------|
| Visible trail connecting recently visited stations | Every space game (No Man's Sky, Elite Dangerous), map app (Google Maps "your path"), and exploration RPG shows where the player has been. Spirit-driven movement leaving a trace is the natural expectation for an entity that "lives" in the observatory. | LOW | Per-station pair history (station A → station B) drives a glowing arc between those stations. `CatmullRomCurve3` with midpoint lift (same as `MissionWaypointTrail`). Spirit-color tint from the spirit's `accentColor`. |
| Trail opacity fades with time (recent = bright, old = dim) | Motion blur trails in games, particle trails in visual tools — all fade with age to avoid infinite accumulation. Analysts need to see "recent path" not "all paths ever". | LOW | Track `trailSegments: Array<{from, to, createdAtMs}>`. In `useFrame`, opacity = `1 - (now - createdAtMs) / FADE_DURATION`. Remove expired segments. |
| Level-gated intensity (higher XP level = more visible trail) | The spirit evolution system is already level-gated (level-gated geometry layers are a shipped v3.0 feature). Trail intensity following the same gating is consistent with the established progression model. | LOW | Read `spiritLevel` from spirit-store. Map level 1–5 to trail opacity scale: `[0.15, 0.3, 0.45, 0.65, 1.0]`. Below level 2 = barely visible. Level 5 = full brightness. |
| Trail color reflects spirit mood | The spirit `accentColor` already drives CSS custom properties and the `ObservatoryPostFX` LUT selection. Trail using the same color creates visual coherence — the trail is recognizably "this spirit's" work. | LOW | Trail material color = `spirit.accentColor`. Same `AdditiveBlending` convention. |

### Differentiators

| Behavior | Value Proposition | Complexity | Notes |
|----------|-------------------|------------|-------|
| Level-5 hidden inter-station connections | Journey (the game) reveals hidden connections between areas as the player progresses. At spirit level 5, the observatory reveals hidden "resonance paths" — connections between stations that aren't in the normal `HUNT_STATION_ORDER` graph. These represent cross-cutting analytical relationships (e.g., signal → case-notes shortcut, receipts → watch direct path) that experienced analysts discover. | MEDIUM | Define `HIDDEN_RESONANCE_CONNECTIONS: [HuntStationId, HuntStationId][]` (3–4 pairs). Render as additional arcs in `SpiritResonanceLayer` only when `spiritLevel >= 5`. Use a distinctive visual style: thinner, animated dashes, different hue (e.g., magenta vs spirit-color). |
| Trail "breathing" animation (thickness pulse) | GPGPU particle trail implementations and the Matrix Sentinels TSL demo use position history buffers to animate trail thickness. The trail tube's radius modulated by a sine wave gives the trail a living, organic quality. | LOW | `useFrame` drives a `radiusScale` uniform or rebuilds tube geometry with modulated radius. Keep rebuild throttled (> 1s interval). Given static station-to-station paths, geometry rebuild is cheap. |
| Trail particles along the arc | TSL trail implementations emit particles along trail curves. Small emissive points drifting along the arc (from source station toward destination) reinforce directionality — the spirit is moving, not just marking. | MEDIUM | `THREE.Points` geometry along the arc curve. `useFrame` advances each particle's `t` parameter along the curve. 10–20 particles per active segment. Reuse `ObservatoryVFXPools` pooling pattern. |
| Mood-reactive trail style changes | Spirit in `alert` mood = jittery/fragmented trail. Spirit in `calm` mood = smooth wide arc. Spirit in `focused` mood = narrow, precise, high-opacity. Mood is already tracked in spirit-store via motion envelope. | LOW | Map `spiritMood` to trail `fragmentationAmount`, `opacity`, `radius`. Fragmentation: add noise to CatmullRom control points. |

### Anti-Features

| Anti-Feature | Why Avoid | Alternative |
|--------------|-----------|-------------|
| Persistent trail for every station-to-station transition ever made | After a long session, every station-pair would be lit up equally, destroying the signal. The trail should show recent movement, not all-time movement. | Time-based decay (already in table stakes). Cap at last N transitions (e.g., last 10). Decay window: ~5 minutes. |
| High-resolution tube geometry with frequent rebuilds | The spirit trail connects 6 fixed station positions. Static geometry is fine — only rebuild when the set of active segments changes. | Segment-based model: each segment is a cached TubeGeometry rebuilt only when that segment's opacity crosses the visibility threshold. Zero `useFrame` rebuilds. |
| Making the hidden resonance paths a feature-flag unlock tied to account tier | This is an internal IDE tool, not a SaaS with tiers. Gating by spirit XP level is the correct mechanism — it's already the established progression model. | XP level gate only. No account-tier logic. |

### Complexity Assessment: MEDIUM overall
- Trail rendering with decay: LOW
- Level-5 hidden connections: MEDIUM (requires design of which hidden connections make sense)
- Trail particle animation: MEDIUM

### Dependencies on Existing Systems
- `spiritLevel`, `spiritMood`, `accentColor` from spirit-store
- Spirit XP evolution system (level-gated geometry layers): established v3.0 pattern
- `OBSERVATORY_STATION_POSITIONS`: arc endpoints
- `ObservatoryVFXPools`: pooling pattern for trail particles
- `CatmullRomCurve3` + tube pattern: established in `MissionWaypointTrail`

---

## Feature 7: Station Interior Zones

**What it is:** Seamless camera-push transition into detailed per-station interior layouts when the operator navigates "into" a station. Each station has unique room geometry and NPC activity appropriate to its domain.

### Table Stakes

| Behavior | Why Expected | Complexity | Dependency |
|----------|--------------|------------|------------|
| Camera transition from exterior to interior | Mass Effect, Star Citizen, Elite Dangerous, and every AAA space game with station interiors uses a seamless push-in camera transition rather than a screen-cut or loading screen. The existing docking system already guides the ship to the station — interior entry is the natural next step after docking. | HIGH | Camera lerps from docked exterior position into the station's interior "entry point" position. `drei CameraControls` or manual `useFrame` lerp of camera position+target. Key challenge: exterior and interior geometry must coexist in the same scene without Z-fighting. |
| Each station has distinct interior geometry | All 6 stations have distinct purposes (Horizon/signal, Subjects/targets, Operations/run, Evidence/receipts, Judgment/case-notes, Watchfield/watch). An interior that's the same for all stations feels like a copy-paste environment. Analogues: Firewatch's different cabin rooms, Elite Dangerous station types. | HIGH | Per-station `InteriorGeometry` components with procedural primitives (Three.js geometry + materials). Same approach as `ObservatoryDistrictLayer` using primitive building blocks, not GLTF models. Unique features per station: Evidence = archive shelves + data terminals; Horizon = antenna arrays + dish consoles; Watchfield = elevated command deck + monitoring screens. |
| NPC crew visible inside the interior | `npcCrew.tsx` already defines 24 NPCs distributed across stations. Interiors should show 2–4 of the station's assigned NPCs doing station-appropriate activities. | MEDIUM | Filter `npcCrew` by `stationId`. Inside the interior camera zone, NPCs render at their interior positions (new `interiorPositions` field per crew member type). |
| Exit transition back to exterior | Users must be able to leave the interior. Analogues: Firewatch, The Witness — all have an explicit exit that transitions back to the world camera. | MEDIUM | "Exit" interaction (E key or button) triggers reverse camera lerp from interior back to docked exterior position. |

### Differentiators

| Behavior | Value Proposition | Complexity | Notes |
|----------|-------------------|------------|-------|
| Interior activates station-specific data context | When inside Evidence station, the ambient data display shows actual receipt content. When inside Judgment, it shows investigation findings. When inside Horizon, it shows live signal telemetry. The interior isn't just decoration — it contextualizes investigation data spatially. | HIGH | Per-station interior mounts a `drei Html` data panel at the "wall display" position showing relevant store data (receipts, investigations, events). Connects the 3D interior to real workbench data. |
| Interior LOD (only loaded when camera is near) | `StationLodWrapper` already uses distance-based LOD for exterior station geometry. Interiors should only load when the camera is within the docking zone (< 60 units) to avoid loading all 6 interiors at once. | MEDIUM | Existing LOD system extended: interior geometry mounts only when `dockingState.zone === "docked"` and `dockingState.targetStationId === stationId`. Unmounts when camera exits. |
| "Holographic brief" on entry | Destiny 2 and Mass Effect play a brief ambient animation when entering a location — establishing the space before full control is given. On entering a station interior, a semi-transparent holographic overlay (like the `ThreatPresetOverlay` but station-specific) plays a 2s fade-in animation. | MEDIUM | Fade-in `MeshBasicMaterial` plane with station-specific data glyph. Resolves after 2s. Same technique as analyst preset overlays but time-limited. |
| Interior "heartbeat" ambient sound cues (visual only — no audio) | Note: audio was explicitly rejected as an anti-feature in previous research. However, ambient visual rhythm (pulsing console lights, blinking readouts) can create the sense of a "living" station without sound. | LOW | Each interior has 2–4 `useFrame`-animated emissive mesh elements (blinking at different rates) to create ambient activity sensation. Budget: < 100 extra vertices per station. |

### Anti-Features

| Anti-Feature | Why Avoid | Alternative |
|--------------|-----------|-------------|
| Full GLTF/GLB interior models | The project explicitly deferred real GLTF station models to v7.0 polish. Interiors following the same pattern (procedural primitives) is consistent and avoids asset pipeline complexity. | Procedural geometry only. `BoxGeometry`, `CylinderGeometry`, `PlaneGeometry` compositions. Matches existing `ObservatoryDistrictLayer` approach. |
| Interior in a separate R3F scene/canvas | Using a separate canvas for interiors would hit the WebGL context limit and prevent resource sharing with the main scene. | Same scene, same canvas. Interior geometry is a child group that appears/disappears based on camera proximity. Scale: interiors are small (~20x20 unit rooms) vs the 300-unit exterior world. |
| Teleport/snap camera into interior | A snap/cut transition is jarring. Every modern space game with interiors uses a dolly push. The user needs to feel the spatial relationship between outside and inside. | Lerp-based camera push over 0.8–1.2s. Easing: ease-in-out cubic. Camera target moves from station exterior to interior entry point. |
| Interior that blocks the space flight HUD | The SpaceFlightHud DOM overlay is always visible. Inside an interior, the flight HUD (speed indicator, compass) is contextually wrong. | Suppress `SpaceFlightHud` and `OffScreenArrows` when in interior mode. Show a simplified interior HUD (station name, exit prompt). |
| Loading all 6 interiors on observatory mount | 6 interior geometry sets multiplied by NPCs, terminals, and ambient elements could be significant startup overhead. | Lazy mount per station: only load the interior of the station you're docked at. Existing LOD infrastructure supports this. |
| Post-processing interactions inside interiors | The DOF effect in `ObservatoryPostFX` blurs background objects by distance. Inside a small interior (< 20 units), DOF would blur everything. | Disable or reduce DOF focal distance when in interior mode. Pass `interiorActive: boolean` prop to `ObservatoryPostFX`. |

### Complexity Assessment: HIGH overall
- Camera transition system: HIGH (most complex new system — requires state machine for enter/exit/interior modes)
- Per-station interior geometry (6 sets): HIGH (design and implementation work per station)
- Interior-specific data panels: HIGH (requires connecting 3D interior to store data per station type)
- LOD integration: MEDIUM

### Dependencies on Existing Systems
- `dockingState.zone` + `dockingState.targetStationId`: determines which interior to enter and when
- `StationLodWrapper`: existing LOD system to extend for interior lazy loading
- `npcCrew.tsx`: crew members need interior positions per station
- `ObservatoryPostFX`: DOF must be suppressed in interior mode
- `SpaceFlightHud`: must be hidden in interior mode, replaced with interior HUD
- `HUNT_STATION_LABELS` + station domain knowledge: drives interior thematic design

---

## Feature Dependencies

```
Replay Annotation Canvas
  └──builds-on──> ObservatoryReplayAnnotation type (already in types.ts)
  └──builds-on──> upsertReplayAnnotation action (already in observatory-store)
  └──builds-on──> savePersistedObservatoryReplayArtifacts (already implemented)
  └──builds-on──> R3F onClick event.point (built-in R3F API)
  └──enhanced-by──> replay.frameIndex (already tracked for frame-linked visibility)

Probe Delta Cards
  └──builds-on──> probeConsequences.ts (missionRead, crewDirective, affectedStationIds)
  └──builds-on──> probeState.status (probe lifecycle gating)
  └──builds-on──> observatory-recommendations.ts
  └──builds-on──> drei Billboard (from existing dep)
  └──requires-no-new-infrastructure

Split-Screen Compare Mode
  └──builds-on──> ObservatoryReplaySnapshot (frozen frame data)
  └──builds-on──> pressureLanes (live station data)
  └──requires──> drei View (scissor viewports — from existing dep)
  └──conflicts-with──> ObservatoryPostFX (must disable EffectComposer in split mode)
  └──surfaces-in──> ReplayDrawerPanel "compare" toggle (UI already exists)

Constellation Routes
  └──builds-on──> ObservatoryMissionLoopState (station visit sequence)
  └──builds-on──> localStorage pattern from savePersistedObservatoryReplayArtifacts
  └──builds-on──> CatmullRomCurve3 + tube geometry pattern (MissionWaypointTrail)
  └──clickable-to──> setReplayState + openPanel("replay") (replay navigation)

Threat Topology Heatmap
  └──reads-from──> pressureLanes (per-station pressure scores)
  └──gated-by──> analystPresetId === "threat"
  └──triggered-by──> telemetrySnapshotMs (pulse animation)
  └──requires──> custom ShaderMaterial (GLSL — new capability)
  └──affected-by──> ObservatoryPostFX bloom (desired)
  └──requires-fog-integration──> scene.fog (FogExp2 already present)

Spirit Resonance Trails
  └──reads-from──> spiritLevel, spiritMood, accentColor (spirit-store)
  └──gated-by──> spiritLevel >= 2 (level 1 barely visible)
  └──unlocks-at-5──> hidden resonance connections (level-5 exclusive)
  └──builds-on──> CatmullRomCurve3 pattern (MissionWaypointTrail)
  └──pools-particles-via──> ObservatoryVFXPools

Station Interior Zones
  └──gated-by──> dockingState.zone === "docked"
  └──reads-from──> dockingState.targetStationId (which interior to show)
  └──extends──> StationLodWrapper (lazy mount interior geometry)
  └──suppresses──> SpaceFlightHud (replaced by interior HUD)
  └──modifies──> ObservatoryPostFX (DOF disabled in interior)
  └──most-complex──> requires enter/exit state machine (new to observatory-store)
```

---

## MVP Recommendation

Given the complexity spread, the recommended sequencing prioritizes features that deliver immediate analytical value and build on the most infrastructure already in place:

**Phase 1 — Analyst Workflow Enhancement (LOW complexity, HIGH value)**
1. Probe Delta Cards — zero new infrastructure, direct wiring of existing probe consequence data to 3D card rendering
2. Constellation Routes — localStorage + tube geometry, fully additive to existing scene
3. Replay Annotation Canvas (pins only, no freehand) — persistence already built, 3D pin layer is the new piece

**Phase 2 — Advanced Visualization (MEDIUM complexity)**
4. Threat Topology Heatmap — requires GLSL shader but table stakes behavior is achievable in one component
5. Spirit Resonance Trails — direct extension of spirit level-gating pattern
6. Replay Annotation Canvas (freehand trail drawing) — completes annotation feature

**Phase 3 — Structural Features (HIGH complexity)**
7. Split-Screen Compare Mode — post-processing compatibility is the hard part
8. Station Interior Zones — full state machine + 6 interior geometry sets; most implementation work

**Defer from MVP:**
- Constellation deterministic naming (low priority, decorative)
- Hidden resonance connections (level-5 gated, needs design work on which connections are "hidden")
- Interior data panels with live store data (Phase 3+ enhancement after basic interiors ship)

---

## Sources

- Direct source analysis: observatory `types.ts`, `observatory-replay-persistence.ts`, `observatory-replay-markers.ts`, `probeConsequences.ts`, `observatory-recommendations.ts`, `missionLoop.ts`, `stations.ts`
- Direct source analysis: `GhostTraceLayer.tsx`, `ObservatoryWeatherLayer.tsx`, `MissionWaypointTrail.tsx`, `ObservatoryWorldScene.tsx` — established rendering patterns
- Direct source analysis: `ReplayDrawerPanel.tsx` — existing compare toggle UI
- drei documentation: [View/scissor viewports](https://drei.docs.pmnd.rs/portals/view) — confirmed scissor-based multi-viewport approach
- drei documentation: [Html component](https://drei.docs.pmnd.rs/misc/html) — world-space DOM overlay, occlusion performance notes
- Three.js forum: [multiple scenes/viewports](https://discourse.threejs.org/t/how-to-create-multiple-viewport-scenes-using-only-three-js/73116) — confirmed single-canvas scissor recommendation
- Three.js forum: [heatmap over 3D model](https://discourse.threejs.org/t/how-to-creating-heatmap-over-3d-model/52744) — GLSL-based approach confirmed
- Codrops: [Matrix Sentinels TSL particle trails](https://tympanus.net/codrops/2025/05/05/matrix-sentinels-building-dynamic-particle-trails-with-tsl/) — position history buffer pattern for trail particles
- Huntsman Security: [MITRE ATT&CK threat heatmap](https://huntsmansecurity.com/products/siem-enterprise/siem-features/explore-mitre-attck-threat-heatmap/) — SOC heatmap domain conventions
- Xcitium: [heat map in cybersecurity](https://www.xcitium.com/blog/news/what-is-a-heat-map/) — color ramp conventions (cool=low, hot=high) as industry standard
- Zed blog: [split diffs](https://zed.dev/blog/split-diffs) — split view alignment non-expectation in live-update scenarios
- Project context: `.planning/PROJECT.md` — milestone goals, constraints, existing shipped features

---
*Feature research for: v10.0 Observatory Analyst Toolkit (7 new observatory features)*
*Researched: 2026-03-22*
