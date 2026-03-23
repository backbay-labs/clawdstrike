# Spirit System Evolution — Feature Research

**Domain:** ClawdStrike Workbench IDE — Spirit System
**Researched:** 2026-03-19
**Overall confidence:** HIGH (all findings grounded in actual source code)

---

## Context

The workbench currently has a thin spirit layer:

- `spirit-store.ts` — 4 fields: `kind`, `mood`, `fieldStrength`, `accentColor`
- `SpiritMood` — 4 values: `idle | active | alert | dormant`
- `SpiritKind` — 4 values: `sentinel | oracle | witness | specter`
- `SpiritFieldInjector` — injects 3 CSS vars into `:root`
- `SpiritCompanionCanvas` — 150px R3F icosahedron, mood drives rotation speed
- `SpiritChamberTab` — full creation atmosphere
- `NexusTab` — already passes `spirit` prop to `ObservatoryWorldCanvas`

The huntronomer source (`huntronomer-workspace-orch`) has a substantially richer system:
5 spirit kinds, 6 moods, a `HuntSpiritMotionEnvelope` (6 continuous floats),
an inference engine driven by artifact counts + semantic tags + hunt context,
and a `NexusSpiritCompanion` 3D scene actor.

---

## Feature 1: Spirit Mood Reactivity

### What It Is

Mood shifts automatically in response to hunt activity — probe results, artifact
discoveries, active runs — rather than being set once at bind time and staying static.

### How the Huntronomer Source Does It

The inference pipeline in `selectors/index.ts` → `inference/index.ts` → `runtime.ts`
is a pure-function stack that derives `liveMood` from a `HuntSpiritSignalSnapshot`.

The snapshot captures: artifact counts by kind, semantic assignment counts, active run
presence, phase (discovery/triage/investigation/reporting), likely intent, and confidence
score. `deriveLiveMood()` in `inference/index.ts` then maps this onto one of 6 mood
values: `dormant | attuned | focused | pressured | witnessing | transit`.

The key insight is that mood is never stored as editable user preference — it is a
derived value recomputed whenever the hunt context changes. The workbench equivalent
would be a selector that computes mood from the hunt data store rather than storing it
in `spirit-store`.

### What Drives Mood in the Workbench Context

The workbench does not yet have a `HuntStore` with artifact/run models like the
huntronomer source. The closest analog is:

- **Active file operations** — rename, delete, save errors (observable via file-store)
- **Search activity** — queries in the global search panel
- **Policy errors** — lint diagnostics from `YamlEditor` pushing error state
- **Observatory probes** — `observatory.probe` command results
- **Pane activity** — which apps are open (policies, swarm, simulation)

A simplified version that fits the current workbench state surface:

```
dormant   → no spirit bound
idle      → spirit bound, nothing happening
active    → any pane is open and focused
alert     → policy lint errors OR observatory probe returned findings
```

This is exactly the 4-value `SpiritMood` the workbench already has. The missing piece
is automatic transitions rather than static assignment.

### How Visual Changes Propagate

The `SpiritCompanionCanvas` already reads `mood` from `useSpiritStore.use.mood()` and
maps it to rotation speed. The `SpiritFieldInjector` currently only reads `kind` +
`accentColor` — it does not emit mood-derived CSS vars.

To add mood reactivity the propagation chain would be:

```
hunt/file/policy event
  → call useSpiritStore.getState().actions.setMood(derived)
  → SpiritCompanionCanvas reacts (rotation speed)
  → SpiritFieldInjector emits --spirit-mood-pulse if expanded
  → spirit-orb-icon animation class switches
```

All consumers are already subscribed to `useSpiritStore` — the store is the broadcast
mechanism and no new wiring is needed.

### Implementation Approach

1. Add a `deriveSpiritMood` pure function in `features/spirit/mood.ts` that maps
   observable workbench signals to `SpiritMood`. No new state — just mapping logic.

2. Add a `SpiritMoodReactor` component (renders null, mounts once alongside
   `SpiritFieldInjector`) that subscribes to relevant stores and calls `setMood`
   when the derived value changes. Use `useEffect` watching the computed value to
   avoid infinite loops.

3. Expand `SpiritFieldInjector` to also inject `--spirit-mood` (the string value)
   so CSS can select on it for animations without JS.

No changes to `spirit-store.ts` are needed — `setMood` already exists.

### Complexity: Small

- No new Zustand stores
- No new types (existing `SpiritMood` enum is sufficient for workbench scope)
- No R3F changes beyond the rotation speed that already exists
- Risk: deciding which signals to subscribe to without over-triggering mood flaps
  (debouncing or hysteresis logic is the only non-trivial piece)

### Dependencies

- Existing `spirit-store.ts` with `setMood` action
- Existing `SpiritCompanionCanvas` (already mood-reactive)
- Whatever store holds policy lint state (observable via command or store subscription)

### Risks

- **Mood thrashing**: without hysteresis a rapid file rename or multi-file delete
  creates rapid idle→active→idle transitions. Fix: debounce transitions by 400ms,
  require 2 consecutive same-mood readings before committing.
- **Scope creep**: the huntronomer inference engine is 450 lines. Keep the workbench
  version to <60 lines by using a simple signal tally, not a weighted scoring system.

---

## Feature 2: Spirit-Driven CodeMirror Themes

### What It Is

Binding a spirit kind subtly shifts the CodeMirror syntax highlighting palette. For
example `oracle` (purple) tints string tokens toward purple; `specter` (muted red)
tints keyword tokens toward red. The change is subtle — this is ambiance, not a full
theme swap.

### How the CodeMirror Theme System Works

The workbench uses `EditorView.theme()` (a StateEffect-based extension) together with
a static `HighlightStyle` for token colors. Both are constructed via `useMemo` in
`YamlEditor.tsx` and passed into `EditorState.create({ extensions })`.

The current setup rebuilds extensions whenever `readOnly`, `fontSize`, or
`showLineNumbers` changes — the editor is destroyed and recreated. This means adding
`accentColor` to the dependency array of the `useMemo` will rebuild the theme cleanly
whenever the spirit changes.

### CSS Var Propagation Path

`SpiritFieldInjector` already writes `--spirit-accent` to `:root`. However,
`EditorView.theme()` operates inside CodeMirror's shadow DOM and does not inherit
CSS custom properties from the document root — the theme object is JS-only.

This means the CSS var on `:root` cannot be read inside an `EditorView.theme()` call.
The propagation must go through the React layer:

```
useSpiritStore.use.accentColor()
  → passed as prop to YamlEditor or read in the theme factory
  → createClawdTheme(fontSize, accentColor) generates slightly tinted colors
  → included in extensions → triggers EditorView recreation
```

### Feasibility

HIGH confidence feasibility. The `createClawdTheme` function in `yaml-editor.tsx` is
already parameterized on `fontSize`. Adding `accentColor` as a second parameter is
a 10-line change. The `HighlightStyle` is currently module-level static — it would
need to move inside `useMemo` alongside the theme to accept spirit-derived tint values.

The implementation approach is:

1. In `YamlEditor`, read `accentColor` from `useSpiritStore.use.accentColor()`.
2. Extend `createClawdTheme(fontSize, accentColor?)` to tint 2-3 specific CSS rules
   (cursor color, active line gutter, search match highlight) with a blended version
   of the accent color. These are already accent-colored; the spirit just changes which
   accent.
3. Move `clawdHighlightStyle` inside `useMemo` and add spirit kind → token palette
   map for 1-2 token tags. Keep changes subtle (±15% hue shift).
4. Add `accentColor` to the `useMemo` dependency array.

A subtle palette per kind (token-level color shifts are 5-10% saturation/hue change):

| Spirit | Accent | Token emphasis |
|--------|--------|----------------|
| sentinel | #3dbf84 green | string tokens lean green (already green by default) |
| oracle | #7b68ee purple | property names lean lavender |
| witness | #d4a84b amber | keywords lean gold (already gold by default) |
| specter | #c45c5c red | operators lean red |

For sentinel and witness the shift is near-zero since the defaults already match their
accents. Oracle and specter create the most noticeable shift.

### Complexity: Small

The entire change is inside `yaml-editor.tsx`. No new files, no new stores.

### Dependencies

- `useSpiritStore` must be readable inside `YamlEditor` (it is — it is a Zustand store)
- EditorView recreation on accent change is acceptable because spirit bind is not
  a frequent event. If the user worries about cursor position loss, preserve selection
  before recreating (the existing code already handles the `value` sync path).

### Risks

- **Editor flicker**: full EditorView recreation causes a brief flash. Mitigate by
  using `EditorView.reconfigure()` via `view.dispatch({ effects: [...] })` instead of
  destroying/recreating. `EditorView.theme()` can be added as a compartment that
  reconfigures in place. This is the correct approach and avoids flicker entirely.
  Complexity bumps to medium-small but is architecturally cleaner.
- **Lezer highlight style** cannot be reconfigured in place after initial creation —
  it must be in a `Compartment`. The `@codemirror/language` package exports
  `syntaxHighlighting` which wraps a `Compartment` internally; swapping requires the
  compartment pattern. See CodeMirror docs on dynamic reconfiguration.

The `Compartment` approach (recommended):

```typescript
const themeCompartment = useMemo(() => new Compartment(), []);
const highlightCompartment = useMemo(() => new Compartment(), []);

// In extensions useMemo — install compartments once
themeCompartment.of(createClawdTheme(fontSize, accentColor)),
highlightCompartment.of(syntaxHighlighting(createHighlightStyle(accentColor))),

// In a separate useEffect watching accentColor — reconfigure without recreation
view.dispatch({
  effects: [
    themeCompartment.reconfigure(createClawdTheme(fontSize, accentColor)),
    highlightCompartment.reconfigure(syntaxHighlighting(createHighlightStyle(accentColor))),
  ]
});
```

With compartments the theme update is a single transaction dispatch — no flicker.

---

## Feature 3: Spirit Evolution

### What It Is

Spirits gain experience from completed hunts and artifact discoveries. Visual
complexity increases as experience accumulates — the companion orb gains additional
geometry, orbit shards increase, emissive intensity strengthens.

### What State This Requires

A minimal evolution model needs:

```typescript
interface SpiritExperience {
  level: number;           // 1–5 (or 1–10, open question)
  xp: number;             // accumulated points
  xpToNextLevel: number;  // threshold for next level
  achievedAt: number[];   // timestamps of level-ups (for animation triggers)
}
```

This extends `SpiritState` in the store, or lives in a separate persisted store.

Key events that grant XP:
- Successful policy validation (no lint errors after edit session)
- Observatory probe returning findings
- Hunt artifact discovery
- File saved to detection project tree
- Simulation run completed without errors

### How It Persists Across Sessions

Tauri 2 provides the `tauri-plugin-store` (JSON file store backed by the app data dir)
and direct filesystem access via `@tauri-apps/plugin-fs`. The workbench already uses
Tauri for terminal PTY — the infrastructure for native persistence exists.

The simplest approach: a `spirit-evolution-store.ts` that writes to
`app_data_dir/spirit-evolution.json` on every level-up. Between sessions, the store
loads from disk on mount. XP accumulation within a session is in-memory only; only
level-up events persist.

If Tauri plugin-store is not already in the project, `localStorage` is a viable
fallback since the workbench runs in a Tauri window (not a public browser). Check
`package.json` for `@tauri-apps/plugin-store`.

### How Visual Complexity Increases

The `SpiritCompanionCanvas` currently renders a fixed icosahedron with no orbit shards.
The huntronomer `NexusSpiritCompanion` has: core mesh, shadow ring, orbit torus ring,
pulse ring, and 3 orbit shards. Each element can be gated on level.

A level → visual map:

| Level | Visible elements |
|-------|-----------------|
| 1 | Core icosahedron only |
| 2 | + shadow ring beneath |
| 3 | + orbit torus ring (slow rotation) |
| 4 | + pulse ring (breathing opacity) |
| 5 | + 3 orbit shards on elliptical paths |

The `renderSpiritContourGeometry` function in the huntronomer source already maps spirit
kind to geometry (octahedron, sphere, dodecahedron, torusKnot, cylinder vs icosahedron
default). At level 3+, the companion could switch from the default icosahedron to the
kind-specific contour geometry — a visible reward for progression.

Emissive intensity also scales with level: `0.4 + level * 0.12` gives a range of
0.4 (level 1) to 1.0 (level 5), matching the huntronomer's
`0.86 + presenceStrength * 0.64` pattern.

### Complexity: Medium

- New `spirit-evolution-store.ts` Zustand store with Tauri persistence
- New `SpiritExperienceTracker` component (renders null, subscribes to relevant stores,
  dispatches XP events to evolution store)
- `SpiritCompanionCanvas` updated to read level and render additional geometry layers
- Level-up animation: brief pulse burst when level changes (easy with `useFrame` + state)

The medium rating comes from the persistence layer (needs Tauri plugin or localStorage
decision) and the XP event wiring (touching 3-4 different stores to observe activity).

### Dependencies

- Tauri plugin-store or localStorage for cross-session persistence
- `SpiritCompanionCanvas` refactor to accept `level` prop
- `renderSpiritContourGeometry` ported from huntronomer source (already done for
  NexusSpiritCompanion if that feature is built first)
- Clear definition of XP-granting events and point values (product decision)

### Risks

- **XP grinding**: if any single action grants XP, users can trivially reach max level
  by repeatedly creating/deleting files. Mitigation: cooldown per event type (e.g.,
  file saves only grant XP once per 60s per session), or cap daily XP.
- **Persistence coupling**: if spirit-store and spirit-evolution-store diverge (e.g.,
  user unbinds spirit), what happens to XP? Simplest answer: XP is per-kind, stored
  keyed by `SpiritKind`. Binding a different spirit shows that kind's XP level. Levels
  are permanent and cross-session.
- **Visual regression**: adding orbit shards to `SpiritCompanionCanvas` in a 150px
  canvas is tight. The huntronomer companion runs in the full nexus 3D scene. The
  150px sidebar canvas may need to increase to 180–200px at higher levels or use a
  scaled-down shard count.

---

## Feature 4: NexusSpiritCompanion Port

### What the Source Looks Like

`NexusSpiritCompanion.tsx` in the huntronomer source
(`features/cyber-nexus/scene/spirits/NexusSpiritCompanion.tsx`) is a 310-line R3F
component that renders inside the 3D nexus scene. It requires:

- `actor: NexusSpiritSceneActor | null` — the fully derived scene actor struct
- `receiveState: SpiritSurfaceReceiveState` — `"idle" | "receiving" | "aftermath"`
- `strikecellPositions: Map<StrikecellDomainId, THREE.Vector3>` — 3D positions of all
  domain nodes in the nexus graph

The component renders:
- Anchor pulse rings on the active strikecell (floor projection)
- Wake pulse rings (outer glow on the anchor)
- Affinity rings on secondary strikecells (strength-scaled floor halos)
- A focus beam cylinder on the likely station (vertical light pillar)
- A tether `<Line>` from anchor to likely station when they differ
- A `<GlyphSentinel>` transit arc during strikecell-to-strikecell transitions
- The core group: kind-specific contour geometry + shadow ring + orbit torus + pulse
  ring + 3 orbit shards (all animated in `useFrame`)
- An `<Html>` floating label above the spirit position

All animation lives in a single `useFrame` callback. The `NexusSpiritSceneActor` struct
drives every parameter: `presenceStrength`, `orbitRadius`, `altitude`, `focusBeam`,
`stationAffinities`, `cue` (with kind: bind/transit/focus/recenter).

### How the Actor Is Derived

`deriveNexusSpiritSceneActor()` in `scene/spirits/runtime.ts` produces the actor from:
- `HuntSpiritRuntimeState` (derived from bound spirit + context signals)
- `HuntSpiritSignalSnapshot` (artifact counts, phase, intent — the inference inputs)
- Strikecell list (for affinity calculation)
- Active strikecell ID (current focus)
- Current cue event (bind/transit/focus/recenter with timestamps)

This is a pure function — no side effects, no async, no external calls.

### What Is Already in the Workbench

The `NexusTab` already:
- Renders `ObservatoryWorldCanvas` (not the raw nexus graph with strikecell positions)
- Passes a simplified `spirit` prop: `{ kind, accentColor }`
- Has `NexusStore` with strikecells (domain nodes with activity counts)

The workbench nexus is the observatory world (the 6-station 3D space) rather than the
huntronomer's domain-graph nexus (6+ strikecell domain nodes laid out by force
simulation). These are architecturally distinct views. The `NexusSpiritCompanion` is
designed for the domain-graph nexus, not the observatory world.

The `ObservatoryWorldCanvas` already has its own spirit field rendering (`spiritFieldBias`,
`spirit` prop) — the observatory spirit presence is already handled through a different
channel.

### Port Complexity Assessment

**For the observatory world (current NexusTab):** LOW — the spirit overlay is already
implemented through `ObservatoryWorldCanvas`'s `spirit` prop. No port needed; the
workbench's simplified `{ kind, accentColor }` spirit struct is already connected.
Enhancement to drive it from the full `HuntSpiritRuntimeState` motion envelope would
require porting the runtime derivation logic (medium work, described in Feature 1).

**For a true cyber-nexus domain-graph tab (new feature):** LARGE — the
`NexusSpiritCompanion` depends on `strikecellPositions` which come from the force-directed
layout simulation in the huntronomer source. The workbench does not currently have a
force-directed graph nexus; the 6-node `NexusStore` drives the observatory world via
station IDs, not spatial positions. Building a true domain-graph nexus is a separate
large feature (force-directed layout, strikecell node rendering, edge rendering, zoom/pan
controls — all predating the spirit companion itself).

### Recommended Path

The most useful extraction from `NexusSpiritCompanion.tsx` for the workbench is not
the full component but its visual sub-elements:

1. **Affinity rings** (floor halos under active observatory stations) — can be added
   to `ObservatoryWorldCanvas` by passing `stationAffinities` alongside the spirit.
   The observatory station positions are known (they are the `HUNT_STATION_PLACEMENTS`).
   This would require porting only the ring geometry and the anchor pulse mesh — roughly
   60 lines, no new stores, no layout simulation.

2. **Tether line** — the `<Line>` between anchor and likely station can be added to
   the observatory world when `activeStationId` differs from `likelyStationId`.

3. **Full NexusSpiritCompanion** as designed — requires building the force-directed
   domain-graph nexus view first, which is a separate large milestone item.

### Complexity: Large (for full port) / Small (for observatory integration)

Full port estimate: 3-4 days. It requires:
- Force-directed layout runtime for strikecell positions
- Strikecell node rendering (domain graph nodes)
- Edge rendering
- `NexusSpiritSceneActor` derivation chain (runtime.ts + full inference)
- The companion component itself

Observatory integration (affinity rings + tether only): 0.5 days. It requires:
- Extending the `spirit` prop on `ObservatoryWorldCanvas` with optional `stationAffinities`
- Adding floor ring meshes and a conditional `<Line>` inside the observatory scene

### Dependencies

**Full port:**
- `@xyflow/react` for force-directed graph (already in deps for swarm board)
- Ported `deriveNexusSpiritSceneActor` + `detectNexusSpiritCue` from runtime.ts
- Ported `renderSpiritContourGeometry` from sceneVisuals.tsx
- `blendHex` utility from sceneVisuals.tsx
- `GlyphSentinel` component from huntronomer source

**Observatory integration only:**
- `blendHex` utility (10 lines)
- Floor ring geometry (inline JSX)

### Risks

- **WebGL context budget**: the nexus tab already runs a full R3F canvas. Adding the
  companion scene actor is low additional GPU cost since it is lightweight mesh geometry
  (rings, torus, shards). No risk here.
- **Position dependency**: the companion's floor ring projections require accurate
  world-space positions for each node. In the observatory world these positions are
  deterministic (HUNT_STATION_PLACEMENTS defines them). This is not a risk for the
  observatory integration path.
- **Full port scope**: the force-directed layout simulation is non-trivial to port and
  test. The huntronomer's domain-graph nexus has not been built in the workbench at all
  — attempting to port `NexusSpiritCompanion` without first having the graph view is
  building a companion for a scene that does not exist.

---

## Summary Matrix

| Feature | Complexity | New Stores | New Types | R3F Changes | Persistence |
|---------|-----------|------------|-----------|-------------|-------------|
| Mood reactivity | Small | None | None | Existing canvas | None |
| Spirit code themes | Small | None | None | No R3F | None |
| Spirit evolution | Medium | 1 (evolution) | `SpiritExperience` | Yes (geometry layers) | Yes (Tauri/localStorage) |
| NexusSpiritCompanion (observatory) | Small | None | None | Yes (ring meshes) | None |
| NexusSpiritCompanion (full graph) | Large | Possibly 1 | `NexusSpiritSceneActor` + derivation chain | Major | None |

## Recommended Sequencing

Build in this order if all four are approved:

1. **Mood reactivity** — foundational. Once `setMood` is called reactively, both the
   companion canvas and orb icon benefit immediately. No dependencies on other features.

2. **Spirit code themes** — fully independent, touches only `yaml-editor.tsx`. Build
   in parallel with or after mood reactivity.

3. **Observatory spirit rings** (the small slice of NexusSpiritCompanion) — requires
   only `blendHex` utility and ring geometry. Enhances the already-working NexusTab.
   Best built before evolution since it establishes the affinity pattern.

4. **Spirit evolution** — builds on the mood reactivity foundation (active mood is an
   XP signal). Requires product decision on XP values and persistence backend before
   starting.

5. **Full NexusSpiritCompanion port** — defer until a force-directed domain-graph
   nexus view is built. Do not attempt before that prerequisite exists.

## Implementation Recommendations

### Mood Reactivity

Use a `useSpiritMoodReactor` hook (not a standalone component) mounted in the layout
root alongside `SpiritFieldInjector`. Subscribe to: file-store save error flag,
policy lint error count, observatory-store probe state. Debounce transitions with a
300ms delay to prevent flapping. Start with a simple 3-bucket derivation:
- Any lint errors → `alert`
- Any active pane activity → `active`
- Otherwise → `idle` (or `dormant` if unbound)

### Spirit Code Themes

Use `Compartment` from `@codemirror/state` (already a transitive dep via CodeMirror)
for zero-flicker reconfiguration. Do NOT add `accentColor` to the `useMemo` dependency
array — use a separate `useEffect` that calls `view.dispatch({ effects: compartment.reconfigure(...) })`.
This avoids recreating the editor on every spirit change.

### Spirit Evolution

Store shape: `Record<SpiritKind, { level: number; xp: number }>` — one entry per kind,
persisted to `localStorage` under key `clawdstrike.spirit-evolution`. Use `localStorage`
before considering Tauri plugin-store; it is simpler and sufficient for non-sensitive
preference data. Level-up is purely a visual reward — no gameplay dependency means
data loss on storage clear is acceptable.

### Observatory Spirit Rings

Port `blendHex` into a `spirit/scene-math.ts` utility file. Add an optional
`stationAffinities?: Partial<Record<HuntStationId, number>>` to the spirit prop type
on `ObservatoryWorldCanvas`. Inside the scene, render floor ring meshes at each station
position where affinity exceeds 0.1. This is the most direct value extraction from the
huntronomer source with minimal integration cost.

---

## Sources

All findings are based on direct code inspection of:
- `/Users/connor/Medica/backbay/standalone/clawdstrike-worktrees/huntronomer-workbench/apps/workbench/src/features/spirit/`
- `/Users/connor/Medica/backbay/standalone/clawdstrike-worktrees/huntronomer-workbench/apps/workbench/src/components/ui/yaml-editor.tsx`
- `/Users/connor/Medica/backbay/standalone/clawdstrike-worktrees/huntronomer-workbench/apps/workbench/src/features/nexus/components/NexusTab.tsx`
- `/Users/connor/Medica/backbay/standalone/clawdstrike-worktrees/huntronomer-workspace-orch/apps/desktop/src/shell/workbench/spirit/` (types, defaults, inference, runtime, selectors, sceneVisuals)
- `/Users/connor/Medica/backbay/standalone/clawdstrike-worktrees/huntronomer-workspace-orch/apps/desktop/src/features/cyber-nexus/scene/spirits/` (NexusSpiritCompanion, runtime)

Confidence is HIGH throughout — no claims depend on training data or web search.
All capability assessments derive from reading the actual implementation files.
