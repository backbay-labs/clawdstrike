# Project Research Summary

**Project:** ClawdStrike Workbench — v10.0 Observatory Analyst Toolkit
**Domain:** 3D immersive security analyst toolkit built on an existing R3F observatory world
**Researched:** 2026-03-22
**Confidence:** HIGH

## Executive Summary

The v10.0 Observatory Analyst Toolkit adds 7 new features to a mature, fully-functioning R3F observatory: Replay Annotation Canvas, Probe Delta Cards, Split-Screen Compare Mode, Constellation Routes, Threat Topology Heatmap, Spirit Resonance Trails, and Station Interior Zones. The codebase is already at high maturity — the entire Three.js/R3F/Zustand stack is installed and validated, most data infrastructure is already in place, and clear rendering layer patterns are established. The expert pattern for this type of extension is additive scene layers following the `GhostTraceLayer` canonical pattern (pure R3F component, receives typed props from `ObservatoryTab`, no direct store reads inside the R3F tree), with data derivation utilities written first and tested independently.

The recommended approach follows a dependency-driven build order: extend TypeScript store and persistence contracts first (no visual work), then build pure derivation utilities, then wire independent R3F scene layers, then tackle interactive and complex features last. This order is dictated by the prop-threading architecture where `ObservatoryTab` is the single store bridge — all new state must be plumbed through before scene layers can use it. Zero new npm packages are required; every capability needed is in the installed `@react-three/drei ^10.7.7` and `three ^0.171.0` stack, including first-use APIs like `<RenderTexture>`, `<CameraControls>`, and `THREE.DataTexture`.

The primary risk is the WebGL context budget: the Split-Screen Compare Mode must not create a second `<Canvas>` element. The existing system already has multiple contexts (observatory, Nexus, spirit companion), and WebKit enforces an 8-context hard limit. Use `drei <View>` scissor rendering within the single existing canvas. Secondary risks are the demand-driven invalidation system (every new visual state source must be explicitly registered in `ObservatoryInvalidationController`) and geometry lifecycle management (Three.js geometries require explicit `dispose()` — failing to do so causes measurable GPU memory accumulation over long sessions). Both risks have clear, low-effort prevention strategies documented in research.

---

## Key Findings

### Recommended Stack

The installed stack is sufficient for all 7 features without any new dependencies. The only "new" work is first-time use of drei APIs already installed: `<RenderTexture>` (Feature 3: Split-Screen), `<CameraControls>` (Feature 7: Station Interiors), and `THREE.DataTexture` (Feature 5: Heatmap). Custom GLSL via `THREE.ShaderMaterial` uses the same `/* glsl */` tagged template literal pattern already established in `StationFresnelGlow.tsx`. No new packages — zero install step.

Full stack analysis: `.planning/research/STACK.md`

**Core technologies:**
- `@react-three/fiber ^9.0.0`: scene graph, event handling, `useFrame` animation — already validated and in active use
- `@react-three/drei ^10.7.7`: `<Html>`, `<Line>`, `<Trail>`, `<Billboard>`, `<CameraControls>` (first use), `<RenderTexture>` (first use) — all available, no install required
- `three ^0.171.0`: `ShaderMaterial`, `CatmullRomCurve3`, `AdditiveBlending`, `DataTexture` (first use) — all available
- Zustand (observatory-store, spirit-store, spirit-evolution-store): store contracts already defined; only additive changes needed
- `observatory-replay-persistence.ts`: localStorage persistence pattern established; needs schema version bump from v1 to v2

**Explicit "do not add" from research:** no second `<Canvas>` for split-screen, no `simpleheat` or other heatmap library, no `@theatre/r3f` for camera animation, no `react-three-scissor` package (conflicts with pane architecture).

### Expected Features

Full feature analysis: `.planning/research/FEATURES.md`

**Must have (table stakes):**
- Probe Delta Cards — probe fires → floating 3D card near station showing pressure delta, explanation, next action; auto-dismisses on probe cooldown
- Constellation Routes — completed missions traced as named permanent starfield lines; persist to localStorage; clickable to replay
- Replay Annotation Canvas (pins) — click 3D space during replay to drop named pins with text; visible in Replay drawer and 3D scene
- Threat Topology Heatmap — ground-plane shader gradient showing station pressure intensity; gated to THREAT analyst preset; pulses on telemetry update
- Spirit Resonance Trails — spirit leaves luminous trails between stations; level-gated intensity; level-5 reveals hidden inter-station connections
- Replay Annotation Canvas (freehand trails) — pointer-draw investigation paths in 3D space during replay; throttled geometry (not per-frame)

**Should have (competitive differentiators):**
- Split-Screen Compare Mode — side-by-side "then" vs "now" observatory worlds with diff overlay on changed stations
- Station Interior Zones — seamless camera-push transition into per-station interior layouts with unique room geometry and NPC activity

**Defer (v2+):**
- Constellation deterministic naming (decorative, low analytical value for v10)
- Interior data panels with live store data (add after basic interiors ship)
- Hidden resonance connections design for level-5 (requires inter-station domain design decisions)
- Annotation cross-session sharing/sync (requires backend; localStorage is correct scope)

### Architecture Approach

The architecture is additive and prop-threaded: `ObservatoryTab` (1054 lines, the store bridge) derives all state from stores, then passes typed props down through `ObservatoryWorldCanvas` → `ObservatoryWorldScene` → individual layer components. No new scene layer reads Zustand directly (one documented exception: per-frame access via `store.getState()` for high-frequency reads to avoid React re-render overhead). The 7 features each map to a new R3F scene layer component registered in `ObservatoryWorldScene` JSX, plus corresponding store additions and derivation utilities.

Full component boundary and data flow maps: `.planning/research/ARCHITECTURE.md`

**Major components to build:**
1. **Store + Persistence Extensions** — `ObservatoryReplayTrail`, `ConstellationRoute` types; trail/constellation/interior state in `observatory-store`; persistence key version bump to v2
2. **Data Derivation Utilities** — `deriveConstellationFromMission`, `deriveSpiritResonanceConnections`, `deriveObservatoryCompareState`, `buildStationsFromReplaySnapshot` — pure functions, testable without R3F
3. **Independent Scene Layers** — `ThreatTopologyHeatmap`, `ConstellationRoutesLayer`, `SpiritResonanceTrails`, `ProbeDeltaLayer` — each a self-contained R3F component added to `ObservatoryWorldScene`
4. **Interactive Layers** — `ReplayAnnotationLayer` (pointer events), `ObservatoryInteriorLayer` + `StationInteriorScene` (camera state machine)
5. **Layout Wrapper** — `ObservatorySplitCompareView` + `ObservatoryCompareDiffOverlay` — built last, after Phase C/D prop interfaces are stable

### Critical Pitfalls

Full pitfall analysis with recovery strategies: `.planning/research/PITFALLS.md`

1. **Split-screen second WebGL context** — never use two `<Canvas>` elements for the compare mode. Use `drei <View>` scissor within the existing single canvas. WebKit (Tauri target) enforces an 8-context hard limit; the existing system already consumes multiple contexts. Warning sign: spirit companion canvas goes black when split-screen opens.

2. **Invalidation controller not updated for new visual sources** — `ObservatoryInvalidationController.sourceKey` must be extended with new entries before any visual code per feature: `annotationDropCount`, `heatmapPulseVersion`, `spiritTrailSegmentCount`, `constellationCount`, `interiorTransitionPhase`. Missing entries cause scene changes to never render until an unrelated camera event fires. Applies to all 7 features; must be the first implementation step per feature.

3. **Heatmap shader overdraw** — a full-coverage GLSL heatmap on a 300-unit ground plane compounds with the existing 15+ transparent render layers. Implement as a baked `DataTexture` updated on telemetry change events (not per-frame GLSL evaluation). Gate behind `weatherBudget` — at `"off"`, skip entirely.

4. **Trail geometry GPU leak** — Three.js geometries require explicit `dispose()`. Custom `TubeGeometry` or `BufferGeometry` created per trail segment without cleanup causes monotonically growing `renderer.info.memory.geometries` over long sessions. Use fixed-capacity buffer geometry or `useEffect` cleanup disposals.

5. **Annotation localStorage bloat** — trail point arrays at 60fps produce thousands of points. Cap at 150 points per trail, enforce 50-annotation eviction policy, and wrap `localStorage.setItem` in try/catch for `QuotaExceededError`. Bump persistence key from v1 to v2.

6. **Interior transition stutter from Zustand state** — camera push transition must be driven via `useFrame` + mutable ref, not Zustand state updates. React batching skips animation frames. Only write to Zustand on transition completion.

7. **Split-screen "then" world accuracy** — both canvases reading `useObservatoryStore.stations` shows the same live data. The "then" world must use `buildStationsFromReplaySnapshot(replayTimeline.snapshots[frameIndex])` to reconstruct station states with original EWMA smoothing applied — not a fresh re-derivation from raw events at that timestamp.

---

## Implications for Roadmap

The architecture's dependency graph drives a 5-phase build order with no ambiguity. Phases A and B are pure TypeScript; Phases C and D are R3F; Phase E is the structural layout feature that wraps all prior work.

### Phase A: Store and Persistence Foundations
**Rationale:** Features 1 (Annotation Canvas), 4 (Constellation Routes), and 7 (Station Interiors) all require store additions before any R3F work can begin. Getting these contracts correct first prevents prop-interface rework when multiple features are added simultaneously. Pure TypeScript with no visual work — easiest phase to test.
**Delivers:** Extended `types.ts` (`ObservatoryReplayTrail`, `ConstellationRoute`); extended `observatory-store.ts` (trail, constellation, interior state + actions); persistence key v2 with migration stub; `observatory-constellation-persistence.ts`
**Addresses:** Annotation Canvas data model, Constellation Routes data model, Interior Zone state machine entry point
**Avoids:** Prop-interface churn when multiple features are added simultaneously

### Phase B: Data Derivation Utilities
**Rationale:** Pure functions define the data contracts that all R3F scene layers consume. Writing them before R3F code enables isolated unit testing and prevents schema mismatches — especially `buildStationsFromReplaySnapshot`, which is a prerequisite for split-screen correctness. Derivation utilities written here also gate whether Phase C layers can be built correctly.
**Delivers:** `deriveConstellationFromMission`, `deriveSpiritResonanceConnections`, `deriveObservatoryCompareState`, `buildStationsFromReplaySnapshot`; constellation tracking wired into `ObservatoryTab` mission-complete handler
**Addresses:** Split-Screen Compare accuracy (Pitfall 8), Spirit Resonance level-gate design
**Avoids:** Re-running `deriveObservatoryTelemetry` on stale single-frame snapshot (produces wrong pressure values)

### Phase C: Independent Scene Layers
**Rationale:** These 4 features have no cross-dependencies on each other and build directly on Phase A/B contracts. Each follows the canonical `GhostTraceLayer` pattern exactly — pure R3F layer, props from `ObservatoryTab`, wired into `ObservatoryWorldScene`. Lowest-risk features with highest analyst value per implementation cost.
**Delivers:** `ThreatTopologyHeatmap` (GLSL heatmap shader), `ConstellationRoutesLayer` (permanent mission traces), `SpiritResonanceTrails` (level-gated luminous trails), `ProbeDeltaLayer` + `ProbeDeltaCard` (floating probe result cards)
**Uses:** `THREE.DataTexture` (heatmap baking), `drei <Trail>` (spirit trails), `drei <Html transform sprite>` (delta cards), `THREE.CatmullRomCurve3` (constellation geometry), `drei <Billboard>` (card facing)
**Avoids:** Heatmap overdraw (DataTexture bake approach, not per-frame GLSL), delta card HUD occlusion (`portal` + `occlude` props on `<Html>`), geometry GPU leak (dispose pattern in `useEffect` cleanup)

### Phase D: Interactive Layers
**Rationale:** Both features require pointer event handling in 3D space (annotations) or a multi-state camera controller (interiors) — more complex than Phase C. Station Interiors is the most technically demanding feature, requiring a 3-state camera state machine and log-Z depth buffer mitigation for interior scale. Phase C must be complete first so the `ObservatoryWorldScene` prop interface is stable.
**Delivers:** `ReplayAnnotationLayer` (3D pin drops + freehand trail drawing with throttled geometry), `ObservatoryInteriorLayer` + `StationInteriorScene` (6 procedural station interiors) + `InteriorCameraController`
**Uses:** `drei <CameraControls>` (replaces `<OrbitControls>` for interior `fitToBox()` transitions); `useFrame` + `useRef` for transition animation (not Zustand state — avoids batching stutter)
**Avoids:** Interior transition stutter (Pitfall 6 — `useFrame` ref pattern, not Zustand), log-Z z-fighting (camera `near` drops to `0.02` on interior entry), annotation localStorage bloat (150-point cap per trail)

### Phase E: Split-Screen Compare
**Rationale:** Highest architectural cost because it wraps `ObservatoryWorldCanvas`, which has accrued all new props from Phases C and D. Building it last means the dual-view prop wiring is done once on a stable interface. Also requires Phase B's `buildStationsFromReplaySnapshot` utility. The `<View>`-based scissor architecture must be designed before any compare world scene code is written.
**Delivers:** `ObservatorySplitCompareView` (dual scissor layout via `drei <View>`), `ObservatoryCompareDiffOverlay` (DOM diff badge overlay), compare mode toggle wired into `ReplayDrawerPanel` and `ObservatoryTab`
**Uses:** `drei <View>` scissor (not a second `<Canvas>`); `disablePostFx={true}` on both views; `frameloop="demand"` on both views
**Avoids:** Second WebGL context (Pitfall 1 — single canvas with View scissor), "then" world showing live data (Pitfall 8 — `buildStationsFromReplaySnapshot`)

### Phase Ordering Rationale

- Phase A precedes all others: the store contracts must exist before any component reads from them via props
- Phase B before C/D/E: derivation utilities are the data contracts for scene layers; writing them first enables unit testing in isolation
- Phase C before D: `ObservatoryWorldScene` prop interface should be stable from simpler additions before the complex interactive features add more
- Phase E last: wraps the full `ObservatoryWorldCanvas` — only one pass of dual-view prop wiring needed after all prior prop additions
- `ObservatoryInvalidationController.sourceKey` must be updated as the very first implementation step per feature, before any scene geometry or shader code

### Research Flags

Phases likely needing deeper research during planning:
- **Phase D (Station Interior Zones):** The log-Z depth buffer mitigation strategy has two candidate approaches — camera `near` adjustment vs. renderer mode swap with material recompile. The renderer mode swap causes `renderer.info.programs` spike (material recompilation). Prototype both before building 6 interior geometry sets to pick the correct approach.
- **Phase E (Split-Screen: `<View>` vs `<RenderTexture>`):** STACK.md recommends `<RenderTexture>` for its composability inside the existing Canvas without structural changes; ARCHITECTURE.md and PITFALLS.md recommend `<View>` scissor. This disagreement needs resolution before Phase E begins. `<View>` is likely correct for full-scene rendering; `<RenderTexture>` is better for embedded sub-scenes (e.g., a minimap). Confirm with a prototype.

Phases with standard patterns (skip research-phase):
- **Phase A (Store/Persistence):** Pure TypeScript extension of existing Zustand patterns — well-established in this codebase, zero ambiguity
- **Phase B (Derivation Utilities):** Pure functions mirroring existing `deriveObservatoryWorld`, `deriveObservatoryWeatherState` patterns
- **Phase C (Independent Scene Layers):** Each follows `GhostTraceLayer` canonical pattern exactly; all APIs confirmed in STACK.md
- **Phase C: Probe Delta Cards specifically:** All infrastructure already exists (`probeGuidance`, `probeState`, `observatory-recommendations.ts`); this is the most "wiring" feature in the milestone

---

## Confidence Assessment

| Area | Confidence | Notes |
|------|------------|-------|
| Stack | HIGH | All findings from direct `package.json` + source file inspection; versions confirmed; "no new packages" conclusion verified against drei 10.7.7 and three 0.171.0 API surface |
| Features | HIGH | Directly sourced from codebase analysis of existing infrastructure, existing types, and existing pattern files; complexity assessments grounded in actual code |
| Architecture | HIGH | All integration maps from direct source inspection of `ObservatoryTab.tsx` (1054 lines), `ObservatoryWorldCanvas.tsx`, `ObservatoryWorldScene.tsx`, `observatory-store.ts`, `types.ts`, and all referenced layer components |
| Pitfalls | HIGH | Derived from direct inspection of `ObservatoryInvalidationController.tsx`, `observatory-replay-persistence.ts`, `observatory-telemetry.ts`; verified against R3F, drei, Three.js, and MDN official docs |

**Overall confidence:** HIGH

### Gaps to Address

- **`<View>` vs `<RenderTexture>` for Split-Screen:** STACK.md and ARCHITECTURE.md/PITFALLS.md give different recommendations. Resolve by prototyping both in Phase E planning — `<View>` scissor is the safer choice for full observatory scene rendering, `<RenderTexture>` is better for embedded sub-scene portals.
- **Level-5 hidden resonance connection design:** Which inter-station connections are "hidden" at level 5 is a product design decision not fully specified in research. FEATURES.md suggests 3-4 pairs but leaves selection to implementation. This needs explicit design decisions before `deriveSpiritResonanceConnections` can be written in Phase B.
- **Interior geometry design:** FEATURES.md specifies procedural primitive-based interiors with unique features per station, but the 6 interior layout templates (`world/station-interior-templates.ts`) are a design task that should precede Phase D implementation.
- **`weatherBudget` integration for heatmap:** PITFALLS.md specifies gating heatmap behind `ObservatoryWeatherBudget` (`"off"` / `"reduced"` / `"full"` levels) but ARCHITECTURE.md does not detail this integration. Verify `ObservatoryPerformanceProfile` exposes the right hook before implementing heatmap in Phase C.

---

## Sources

### Primary (HIGH confidence)
- `apps/workbench/src/features/observatory/` — direct inspection of all observatory source files: `ObservatoryTab.tsx`, `ObservatoryWorldCanvas.tsx`, `ObservatoryWorldScene.tsx`, `observatory-store.ts`, `types.ts`, `observatory-replay-persistence.ts`, `GhostTraceLayer.tsx`, `MissionWaypointTrail.tsx`, `spirit-companion-canvas.tsx`, `StationFresnelGlow.tsx`, `ObservatoryInvalidationController.tsx`
- `apps/workbench/package.json` — confirmed installed versions (`@react-three/drei ^10.7.7`, `three ^0.171.0`)
- drei official docs (`drei.docs.pmnd.rs`) — `<Html>`, `<Trail>`, `<CameraControls>`, `<RenderTexture>`, `<View>`, `<Billboard>`, `<Line>`
- Three.js official docs — `BufferGeometry.dispose()`, `logarithmicDepthBuffer`, `DataTexture`, `WebGLRenderer`
- MDN Web Docs — WebGL context limits, localStorage `QuotaExceededError`
- R3F official docs — demand rendering, `frameloop="demand"`, `invalidate()`, performance pitfalls

### Secondary (MEDIUM confidence)
- Drei community discussions — `<Html>` `distanceFactor` stutter during fast camera transitions; `<View>` z-index issues in pane context
- Three.js forum — multiple scenes/viewports single-canvas recommendation; heatmap GLSL approach
- Three.js examples — `Line2` from `three/addons` for large-scale lines with correct depth behavior

### Tertiary (LOW confidence)
- Codrops: Matrix Sentinels TSL particle trails — position history buffer pattern (TSL-specific; adapted to Three.js patterns)
- Zed blog: split diffs — alignment non-expectation in live-update comparison scenarios

---
*Research completed: 2026-03-22*
*Ready for roadmap: yes*
