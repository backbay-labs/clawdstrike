# Feature Research

**Domain:** 3D/immersive features embedded in a VS Code-like security IDE workbench
**Researched:** 2026-03-18
**Confidence:** HIGH (based on direct source code analysis of both apps)

## Context

This research covers the Huntronomer Integration milestone: porting 3D spirit companion, observatory world, and cyber nexus features from `apps/desktop/` (huntronomer shell) into `apps/workbench/` (the IDE workbench). The source features are all implemented and testable; the question is what to carry over, how, and in what order.

The core tension in embedding 3D/immersive features into a productivity tool is **ambient vs. intrusive**. IDE users need focus. Features that demand attention (full-screen takeovers, physics simulations, blocking animations) break flow. Features that enhance without demanding attention (subtle ambient glow, status indicators, optional deeper views) survive long-term use.

---

## Feature Landscape

### Table Stakes (Users Expect These)

Features that must exist for the integration to feel complete — not polished, but present.

| Feature | Why Expected | Complexity | Notes |
|---------|--------------|------------|-------|
| Spirit field CSS stain on panel backgrounds | Spirit is bound — users expect the environment to reflect that. A bound spirit with zero visual feedback feels broken. | LOW | Pure CSS computed gradients; `buildSpiritFieldStainStyle()` already exists with all 5 kind variants (tracker, lantern, forge, loom, ledger). Drop in `background` style on sidebar and main pane container. |
| Spirit accent color on hunt-related UI | When spirit kind drives accentColor, that color should bleed into buttons, badges, borders within hunt views. Zero color = feature feels dead. | LOW | Read `accentColor` from spirit meta; pass as CSS custom property `--spirit-accent`. All hunt UI honors it via Tailwind arbitrary values or direct style prop. |
| Activity bar badges powered by observatory seam | Operators expect sidebar badges to reflect live state. If artifact counts come from somewhere other than the observable model, they drift. | LOW | `HuntStationState.artifactCount` and `hasUnread` are already computed in `deriveObservatorySceneState`. Map stationId → activity bar icon count. |
| Route bridge: station click → pane-store.openApp() | Observatory station clicks navigate. Without the bridge, clicking a station silently fails. The observatory becomes read-only decoration. | LOW | Thin event handler: `onStationSelect(id)` → `paneStore.openApp(STATION_TO_ROUTE[id])`. Map is already partially defined in `NexusCanvas.tsx` as `STRIKECELL_BY_STATION`. |
| spirit-store.ts Zustand store | All spirit state currently lives in workbench-level context from the old app. The IDE has 11 Zustand stores; spirit needs to be one of them. Without it, nothing reads spirit state correctly. | LOW | New store: `{ spirit: HuntSpiritState \| null, bind, release, reconfigure }`. Replaces the old `useWorkbench()` spirit slice. |
| observatory-store.ts Zustand store | Observatory scene state (`deriveObservatorySceneState`) needs a stable home. Without it, every consumer re-derives independently, causing stale reads. | LOW | New store: `{ sceneState, mode, probeState, setMode, dispatchProbe }`. Wraps `deriveObservatorySceneState`. |
| Commands: spirit.bind, spirit.release, observatory.open, nexus.open | The command palette has 80+ commands. Spirit/observatory actions need to be there. Operators expect keyboard-first access to every major feature. | LOW | Register 5 commands in the existing command registry. No new infrastructure needed. |

### Differentiators (Competitive Advantage)

Features that make this security workbench uniquely expressive — things no other policy IDE has.

| Feature | Value Proposition | Complexity | Notes |
|---------|-------------------|------------|-------|
| Animated spirit orb in ActivityBar | When a spirit is bound, the spirit icon in the activity bar animates (pulse, tilt, arousal from the motion envelope). No other security tool has a living indicator in the app chrome. This is the "spiritual health indicator" of the hunt. | MEDIUM | Uses `HuntSpiritMotionEnvelope` (arousal, valence, pulse) from `deriveHuntSpiritRuntimeState`. CSS animation values driven by derived numbers. R3F not needed — CSS keyframes suffice. |
| Spirit chamber as full pane tab | Bind/reconfigure spirit from a dedicated editor tab with the full `SpiritCreationChamber` atmosphere + `SpiritManifestationCanvas`. This is the ritual experience — no competitor has anything like it. Operators get a ceremony for setting hunting intent. | MEDIUM | Port `SpiritChamberTab` from the old app. Mounts `SpiritBindSheet` inside a pane route `/spirit-chamber/:huntId`. Zustand store replaces old `useWorkbench` dispatch. |
| Mini spirit companion R3F canvas in right sidebar | A small 3D canvas (100-200px) in the right sidebar showing the spirit's 3D geometry (contour) animated by its motion envelope. Gives the operator a living presence in the IDE without a full tab. | MEDIUM | Subset of `sceneVisuals.tsx` + `renderSpiritContourGeometry()`. Needs R3F Canvas with `preserveDrawingBuffer: false`, fixed pixel size, transparent background. Spirit geometry + emissive material + rotation driven by `arousal` and `pulse`. |
| Observatory world as full editor pane (atlas mode default) | A 3D overhead view of the hunt topology — stations orbiting the hunt core, run flows as animated arcs, receipts as glow nodes. Unique to this product. Security teams get spatial understanding of hunt state. | HIGH | Port `ObservatoryWorldCanvas` minus character controller. `deriveObservatoryWorld` survives intact. Mounts at route `/observatory/:huntId`. Atlas mode (overhead orbit controls) is default. |
| Forensics river "Tape" tab in bottom pane | The live 3D river of tool calls and policy outcomes flowing as `RiverAction` particles. Placed in the bottom pane as a "Tape" tab alongside Terminal/Problems/Output. Provides ambient live feed without demanding full-screen attention. | HIGH | Depends on `@backbay/glia-three/three` `RiverView`. Port `ForensicsRiverView` but strip the full-screen observatory and nexus chrome — just the river canvas. Bottom pane has fixed height; river must adapt. |
| Cyber nexus as Hunt Deck pane tab | Full 3D security domain graph: strikecells as nodes with R3F terrain, sentinels, and spirit overlays. The operational "god view" of all security domains. No other policy editor offers this. | HIGH | Port `CyberNexusView`. Retains its own layout modes (radial, typed-lanes, force-directed) and operation modes (observe, trace, contain, execute). Mounts at route `/hunt-deck`. |
| Spirit orb in observatory scene (SpiritFieldActor) | The spirit is rendered directly in the 3D observatory world as a `SpiritFieldActor` — its stance and emphasis positions affect the scene. Connects the spirit companion to the spatial hunt view. | MEDIUM | Already handled inside `ObservatoryWorldCanvas` via the `spirit` prop (`ObservatorySpiritVisual`). Wire `spirit-store` → `observatory pane` spirit prop. |
| observatory.probe command | Operators fire a probe from the command palette to scan a station. The probe has a 5.2s active window and 3.6s cooldown. Interactive but not disruptive. | LOW | `dispatchObservatoryProbe()` already exists. Command calls `observatory-store.dispatchProbe(stationId)`. |

### Anti-Features (Deliberately NOT Building)

Features to explicitly exclude from this milestone because they cause harm disproportionate to value in an IDE context.

| Feature | Why Requested | Why Problematic | Alternative |
|---------|---------------|-----------------|-------------|
| Character controller (WASD walk-around) in observatory | It exists in the source and it's impressive — first-person exploration of the hunt world. | Full physics + character controller (Rapier + capsule collider + animation state machine) adds ~80KB to the scene graph and turns an ambient data view into a game. Operators don't want to WASD through receipts. Breaks flow entirely. Tab focus captured by controller input steals keyboard from IDE. | Easter-egg opt-in via `flow mode` toggle inside the observatory pane. Only activates if operator explicitly enables it. Never default. PROJECT.md already calls this out as "Easter-egg opt-in". |
| VRM avatar rendering in sidebar | Spirit companion feels more alive with a humanoid avatar. | VRM loaders are 2-3MB of bundle. Full avatar animation in a 150px sidebar widget creates constant GPU load and eats battery. The sidebar is resizable to very small widths — avatar breaks at any size below 200px. | Spirit contour geometry (icosahedron, octahedron, etc.) driven by the motion envelope is the correct abstraction: recognizable spirit personality without humanoid weight. |
| Full Rapier physics simulation in nexus | Physics-driven node layout looks spectacular and is already partially built in the source. | Physics simulation at 60fps for 50+ nodes in a background tab creates background CPU/GPU pressure that makes the policy editor feel laggy. Rapier WASM is 500KB+ of initialization cost. | Use the existing force-directed layout from `@xyflow/react` (already a dep) for static-ish graphs. Reserve Rapier for the observatory's simplified scene only (it's already there and scoped). |
| Full-screen intro animation / spirit awakening sequence | The creation chamber has a beautiful multi-second manifestation choreography that would be tempting to play on first bind. | Modal full-screen animations in an IDE feel deeply wrong. After the first time, they become an obstacle. Operators will find ways to skip them or avoid binding spirits entirely to dodge the sequence. | Play the manifestation canvas at the bottom of `SpiritChamberTab` as a non-blocking card animation. The `SpiritReleaseChoreography` already handles this within the tab's own space — keep it there. |
| Ambient sound / audio feedback for spirit state | Spirit mood changes could trigger audio cues (a common immersive-tool pattern). | Audio in a work environment is aggressive. Security operators often work in open plans or on calls. Even opt-in audio creates a surface that feels inappropriate for a CLI-adjacent tool. | Visual-only: motion envelope drives animation parameters, color, and field stain opacity. No audio. |
| Real-time 3D receipt previews in editor tabs | Ed25519 receipts rendered as 3D objects inside editor panes. | Policy editors that are the primary use case already have CodeMirror occupying the tab. Injecting a WebGL canvas alongside a code editor creates sizing/layout conflicts and constant GPU pressure when editing. | The observatory renders receipts as glow nodes already. That's the correct spatial view. Editor tabs show receipt JSON/YAML in CodeMirror, not WebGL. |

---

## Feature Dependencies

```
spirit-store.ts
    └──required-by──> Spirit field CSS stain
    └──required-by──> Spirit accent color on hunt UI
    └──required-by──> Animated spirit orb in ActivityBar
    └──required-by──> Spirit chamber pane tab
    └──required-by──> Mini spirit companion R3F canvas
    └──required-by──> Spirit orb in observatory scene

observatory-store.ts
    └──required-by──> Activity bar badges (observatory seam)
    └──required-by──> Observatory world pane tab
    └──required-by──> observatory.probe command
    └──required-by──> Spirit orb in observatory scene (scene state)

Route bridge (station → openApp)
    └──required-by──> Observatory world pane tab (station selection triggers nav)
    └──required-by──> Cyber nexus Hunt Deck tab (station clicks from nexus)

Spirit commands (spirit.bind, spirit.release)
    └──required-by──> Spirit chamber pane tab (commands open it)

Observatory world pane tab (atlas mode)
    └──enhanced-by──> Spirit orb in observatory scene
    └──enhanced-by──> observatory.probe command
    └──optional-enhancement──> Character controller (flow mode opt-in, DEFERRED)

Mini spirit R3F canvas in right sidebar
    └──requires──> spirit-store.ts
    └──requires──> sceneVisuals.tsx port (renderSpiritContourGeometry)

Forensics river Tape tab
    └──requires──> @backbay/glia-three RiverView (already a dep in source)
    └──enhanced-by──> spirit-store.ts (spirit overlay in river)
    └──independent-of──> Observatory world pane (river is its own view)

Cyber nexus Hunt Deck pane tab
    └──requires──> observatory-store.ts (nexus embeds observatory canvas)
    └──requires──> spirit-store.ts (NexusSpiritCompanion)
    └──requires──> route bridge (station click → nav)
    └──independent-of──> Observatory world pane (they are alternative views)
```

### Dependency Notes

- **spirit-store is the foundation:** Every visual feature that reacts to spirit state reads from this store. Must be in the first phase.
- **observatory-store is the second foundation:** Observatory seam badges, probe state, and the observatory pane all share this store. Phase 1 alongside spirit-store.
- **CSS/state drop-ins unblock visually early:** Field stain, accent color, and badge wiring require only the two stores — no R3F at all. These deliver visible progress in Phase 1.
- **R3F embeds are independent of each other:** Mini companion in sidebar, forensics river, observatory world, and nexus Hunt Deck all use R3F but don't share canvas instances. They can be phased independently.
- **Cyber nexus is the most entangled:** It imports `ObservatoryWorldCanvas`, `NexusAppRail`, `NexusCanvas`, spirit overlay, strikecell adapter, and observatory bridge. It should be last.
- **Character controller must be gated:** The Rapier physics + animation state machine must not be imported eagerly — lazy load behind the flow mode toggle to avoid startup cost.

---

## MVP Definition

This is a subsequent milestone on an existing mature workbench. "MVP" here means the integration that delivers the spirit system without breaking the IDE.

### Launch With (Tier 1 — State + CSS drop-ins)

- [ ] spirit-store.ts — foundation for everything
- [ ] observatory-store.ts — foundation for observatory features
- [ ] Spirit field CSS stain on sidebar and main pane backgrounds — immediate "spirit is alive" signal
- [ ] Spirit accent color on hunt UI elements — `--spirit-accent` CSS custom property
- [ ] Activity bar badges from observatory seam (artifactCount, hasUnread) — live data in the chrome
- [ ] Route bridge: station click → pane-store.openApp() — makes the system navigable
- [ ] Commands: spirit.bind, spirit.release, observatory.open, observatory.probe, nexus.open — palette-accessible

### Add in Tier 2 (Targeted R3F embeds)

- [ ] Animated spirit orb in ActivityBar — first R3F surface; scoped and small
- [ ] Mini spirit companion R3F canvas in right sidebar — second R3F surface; motion envelope driven
- [ ] Spirit chamber as pane tab (/spirit-chamber/:huntId) — the bind/reconfigure ritual in the IDE
- [ ] Forensics river Tape tab in bottom pane — ambient live telemetry view

### Add in Tier 3 (Full immersive pane tabs)

- [ ] Observatory world as full editor pane (/observatory/:huntId, atlas mode default) — spatial hunt view
- [ ] Cyber nexus as Hunt Deck pane tab (/hunt-deck) — full operational graph
- [ ] Spirit creation chamber (/spirit-creation/:huntId) — full atmosphere + manifestation canvas
- [ ] Character controller as flow mode Easter-egg — opt-in, lazy-loaded, never default

---

## Feature Prioritization Matrix

| Feature | User Value | Implementation Cost | Priority |
|---------|------------|---------------------|----------|
| spirit-store.ts | HIGH | LOW | P1 |
| observatory-store.ts | HIGH | LOW | P1 |
| Spirit field CSS stain | HIGH | LOW | P1 |
| Spirit accent color | MEDIUM | LOW | P1 |
| Activity bar badges | HIGH | LOW | P1 |
| Route bridge | HIGH | LOW | P1 |
| Commands (5) | MEDIUM | LOW | P1 |
| Animated spirit orb | HIGH | MEDIUM | P2 |
| Mini spirit R3F canvas | HIGH | MEDIUM | P2 |
| Spirit chamber pane tab | HIGH | MEDIUM | P2 |
| Forensics river Tape tab | MEDIUM | HIGH | P2 |
| Observatory world pane | HIGH | HIGH | P3 |
| Cyber nexus Hunt Deck | HIGH | HIGH | P3 |
| Spirit creation chamber | MEDIUM | MEDIUM | P3 |
| Character controller (flow mode) | LOW | HIGH | P3 |

**Priority key:**
- P1: Must have — unblocks all other features, delivers visible integration signal early
- P2: Should have — the interactive R3F surfaces that make the integration feel alive
- P3: Full immersive views — the destination, but not required for the integration to feel real

---

## How 3D/Immersive Features Work in Productivity Tools

Based on direct source analysis (not generic research), here is the pattern this codebase uses and why it works:

**The Ambient Principle:** 3D features in the source app are layered. The CSS field stain is the outermost layer — present always, zero GPU cost. The activity bar orb animation is the second layer — small, scoped, informative. The mini companion canvas is the third layer — present as long as right sidebar is open, but small. The observatory and nexus are the deepest layer — full pane tabs the user deliberately opens. The forensics river occupies the bottom pane — a liminal space between ambient and intentional.

This layering model is exactly how successful IDEs embed non-code features: VSCode's extension host starts tiny (status bar items) and expands to full panes only when asked. Cursor's AI features live in the sidebar until you open a composer. The spirit system follows this same pattern naturally.

**The IDE Contract:** In an IDE, any feature that captures keyboard focus without user intent is hostile. The character controller is the only feature in the spirit/observatory system that would capture keyboard focus. This is why it must be opt-in and never default. Everything else in the system is either CSS-only, click-triggered, or renders to a canvas that doesn't capture keyboard events.

**Performance budget for embedded R3F:** A single low-poly R3F canvas (< 2000 vertices, no textures, no shadows) running at 60fps costs ~2-4ms GPU time on a modern laptop. The workbench can safely host 2-3 such canvases simultaneously (mini companion + observatory or nexus, but not all three at once). The forensics river's `RiverView` is more expensive because it animates particles — it should be suspended when the bottom pane is collapsed.

---

## Sources

- Direct source analysis: `huntronomer-workspace-orch/apps/desktop/src/features/hunt-observatory/` — observatory types, world, probe system
- Direct source analysis: `huntronomer-workspace-orch/apps/desktop/src/features/cyber-nexus/` — nexus types, canvas, components
- Direct source analysis: `huntronomer-workspace-orch/apps/desktop/src/shell/workbench/spirit/` — spirit types, field stain, scene math, visuals
- Direct source analysis: `huntronomer-workspace-orch/apps/desktop/src/shell/workbench/spirit-ritual/` — creation chamber, manifestation canvas, release choreography
- Direct source analysis: `huntronomer-workspace-orch/apps/desktop/src/features/forensics/ForensicsRiverView.tsx` — forensics river integration pattern
- Project context: `.planning/PROJECT.md` — milestone goals, constraints, out-of-scope decisions

---
*Feature research for: 3D spirit/observatory/nexus integration into security IDE workbench*
*Researched: 2026-03-18*
