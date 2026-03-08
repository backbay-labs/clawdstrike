# Hunt Spirits In The 3D Workspace

> **Status:** Proposed | **Date:** 2026-03-08
> **Audience:** Product, design, desktop, and 3D-scene implementers
> **Scope:** Define how hunt spirits should live in Nexus, Forensics River, and station-aware 3D space

## Why This Exists

The current hunt-spirit idea is correct, but still too flat if it only lands as better dock icons.

Huntronomer already has:

- a 3D Nexus scene
- a 3D Forensics River
- station-oriented navigation and scene modes
- a growing anticipation system that already predicts where the operator is likely to go next

If hunt spirit is real, it should not stop at the sidebar or dock.

It should become:

> the hunt’s operative presence in the 3D realm

That means the hunt is no longer just a row, pill, or badge.
It becomes a spatial investigative posture that the workspace can visibly react to.

## Current-State Read

### Hunts are still mostly 2D identity records

The current hunt model only carries:

- title
- status
- artifact IDs
- run IDs
- case link
- color
- icon
- semantic assignments

See `apps/desktop/src/shell/workbench/huntTypes.ts`.

That is enough for state but not enough for a durable spatial identity.

### Nexus is a strikecell graph, not yet a hunt space

The Cyber Nexus scene is built around strikecells, layouts, and connection lines.

- Strikecells are rendered as emissive dodecahedrons in `apps/desktop/src/features/cyber-nexus/components/NexusCanvas.tsx`
- Focus changes produce a transient `GlyphSentinel` streak
- Layouts are radial burst, typed lanes, or force-directed

This is already a strong 3D command space, but hunts are not first-class entities in it yet.

### Forensics River already has the richer behavioral grammar

Forensics is further along as a living scene:

- it renders actions, signals, incidents, detectors, policies, and causal links
- it already imports `RiverView` from `@backbay/glia-three/three`
- it already has agent organisms and HUD overlays

See:

- `apps/desktop/src/features/forensics/ForensicsRiverView.tsx`
- `apps/desktop/src/features/forensics/components/AgentGlyphOverlay.tsx`
- `apps/desktop/src/features/forensics/hooks/useAgentCognitionState.ts`

This is the best near-term precedent for what a hunt spirit should feel like.

## Core Thesis

A hunt spirit should be a **first-class spatial object** that expresses:

1. what the hunt is about
2. what phase it is in
3. what it is currently pulling attention toward
4. how confident the system is about that pull

The spirit is not:

- a mascot
- a floating pet
- a fantasy creature
- an ungrounded VFX layer

The spirit is:

- the 3D embodiment of hunt identity
- the spatial manifestation of intent gravity
- the cross-surface continuity object that links dock, sidebar, tabs, stations, and flows

## Mental Model

Use a two-layer model.

### 1. Core Form

Stable identity derived from:

- artifact mix
- semantic assignments
- run/case posture
- hunt thesis

This is the durable spirit archetype.

### 2. Live Stance

Dynamic modulation derived from:

- current shell/lens
- active run
- active station
- recent pivots
- dragged object kind
- anticipation confidence

This is how the spirit leans, wakes, travels, or witnesses.

## North Star

The operator should feel:

> the hunt is already in the room with me, already leaning toward the next relevant station, and visibly catching proof as the investigation unfolds

## What “Spirit Lives In 3D” Means

It means the hunt is rendered as a spatial field object with its own:

- silhouette
- orbit / halo / ring system
- stance transitions
- anchor station
- flow affinities
- proof-collection behavior

Not every hunt needs to be visually loud.
Dormant hunts can remain quiet beacons.
But the active hunt should have a visible, readable presence.

## Recommended 3D Behavior Grammar

### Idle

- spirit is anchored near its home station or current hunt locus
- low-motion field presence only
- readable silhouette even with effects disabled

### Attune

- medium-confidence anticipation rotates or opens the spirit toward a relevant station, lane, or receipt orbit
- no full movement yet

### Transit

- high-confidence station change or explicit focus change sends the spirit through the scene using a sentinel-like streak or tether
- should feel like relocation, not teleport

### Witness

- when a receipt or proof artifact becomes attached to the hunt, the spirit briefly seals, crystallizes, or catches it
- this is the “that proof belongs to this hunt now” motion

### Absorb

- when files, entities, or evidence are attached, the spirit pulls them into its field
- should be short and directional

### Focus

- at high confidence, the spirit sharpens a lane, station, or flow surface before the user acts
- this is spatial anticipation, not autonomous behavior

## How It Should Behave Across Surfaces

### Hunt Dock

The dock pill becomes the 2D handle of a 3D being.

- pill glyph is the compressed identity token
- hover/flyout explains spirit, stance, and current pull
- selecting a hunt should wake or focus its 3D spirit

### Sidebar / Smart Bucket

The sidebar is not the spirit itself.
It is the spirit’s semantic console.

- promoted sections should align with the spirit’s current stance
- ghost peeks should speak in the spirit’s operational bias
- smart bucket should show spirit identity and current semantic preference

### Nexus

In Nexus, the spirit should become a companion object to strikecells.

Recommended model:

- one foreground active-hunt spirit
- anchored to the active strikecell or a derived locus
- can bias local connection glow and station emphasis
- can transit between strikecells when the active locus changes

Do not make it replace strikecells.
Strikecells remain topology.
The spirit expresses hunt posture relative to topology.

### Forensics River

Forensics is the strongest home for spirits in the near term.

Recommended model:

- spirit hovers above or alongside the hunt’s active flow lane
- reacts to receipts, causal threads, incidents, and policy rails
- acts as the umbrella field for the hunt, while agent organisms remain individual actors

This means:

- agents are workers
- receipts are proof objects
- stations are destinations
- the spirit is the hunt’s continuous field presence

### Stations

Stations should become spirit-aware.

Not by changing every station’s identity, but by allowing the spirit to bias:

- which station glows as likely next
- which station receives transit motion
- which station gets explanation copy

This keeps the 3D world legible without making it noisy.

## Where Glia-Agent Fits

`glia-agent` is relevant, but not in the most obvious way.

It should not become the hunt-spirit brain.

It should become the **motion and posture bridge** between hunt semantics and 3D rendering.

### What Glia-Agent Already Gives Us

The package contains two distinct layers:

#### Emotion

This is the most reusable layer for hunt spirits.

It gives:

- `AVO` dimensions: `arousal`, `valence`, `openness`
- anchor states
- transitions
- micro-expressions
- visual-state mapping for hue, pulse, particles, tilt, aura, and intensity

This is useful because it is mostly generic math and renderer-facing behavior.

#### Cognition

This is only partially reusable.

It gives:

- coarse cognitive modes
- normalized signals like `attention`, `workload`, `risk`, `uncertainty`, `confidence`, `errorStress`
- a bridge from cognition into emotion targets

But it is clearly agent-shaped.

It talks about things like:

- `focusRunId`
- `personaAnchor`
- `personaDriftRisk`
- `ui.input_received`
- `run.started`

That makes it a poor direct model for hunt identity.

### Current Relevance In This App

This is not hypothetical.

The desktop app already uses `CognitionController` in:

- `apps/desktop/src/features/forensics/hooks/useAgentCognitionState.ts`

And that state already drives the forensics organism overlay rendered in:

- `apps/desktop/src/features/forensics/components/AgentGlyphOverlay.tsx`

So `glia-agent` is already part of the existing 3D behavior vocabulary.

### Recommended Relationship

Use this stack:

`hunt + anticipation -> hunt spirit state -> glia-agent emotion adapter -> 3D render`

Do **not** use this stack:

`hunt -> CognitionController pretending to be an agent`

### Practical Rule

Huntronomer should own a native `HuntSpiritState`.

That state should then be mapped into a narrow `glia-agent` bridge:

- spirit stance -> emotion anchor
- spirit pressure/confidence -> AVO
- spirit intensity -> visual-state modulation

Example:

- `tracking` -> `focused`
- `attuning` -> `attentive`
- `witnessing-proof` -> `responding`
- `under-conflict` -> `concerned`
- `recovering` -> `recovering`

This gives us motion continuity with the existing agent organisms without claiming that hunts are literally emotional agents.

### Guardrail

If `glia-agent` starts shaping hunt semantics instead of hunt rendering, we are using it wrong.

## What Glia-Three Already Gives Us

Do not think of `glia-three` as “some 3D code to copy.”
Think of it as a library of primitives and patterns.

### Most Relevant Primitives

#### Glyph

`GlyphObject` already behaves like a spirit renderer:

- breathing
- tilt
- emissive mood
- particles
- abstract emotion/state mapping

Best use:

- hunt spirit core renderer or renderer inspiration

Relevant files:

- `/Users/connor/Medica/backbay/standalone/backbay-sdk/packages/glia-three/src/three/Glyph/GlyphObject.tsx`
- `/Users/connor/Medica/backbay/standalone/backbay-sdk/packages/glia-three/src/three/Glyph/types.ts`
- `/Users/connor/Medica/backbay/standalone/backbay-sdk/packages/glia-three/src/three/Glyph/useGlyphEmotion.ts`

#### RiverView / ActionNode

`ActionNode` already turns domain state into visual posture:

- risk
- novelty
- blast radius
- policy status

mapped to:

- hue
- emissive intensity
- breathing
- ring speed
- aura expansion

Best use:

- pattern for turning hunt semantics into spirit stance

Relevant files:

- `/Users/connor/Medica/backbay/standalone/backbay-sdk/packages/glia-three/src/three/RiverView/ActionNode.tsx`
- `/Users/connor/Medica/backbay/standalone/backbay-sdk/packages/glia-three/src/three/RiverView/RiverView.tsx`
- `/Users/connor/Medica/backbay/standalone/backbay-sdk/packages/glia-three/src/three/RiverView/types.ts`

#### Sentinel

`SentinelOrb` already solves:

- docked state
- summoned state
- orbital state
- tethering / throw / reposition patterns

Best use:

- lifecycle grammar, not full subsystem adoption

Relevant files:

- `/Users/connor/Medica/backbay/standalone/backbay-sdk/packages/glia-three/src/three/Sentinel/SentinelOrb.tsx`
- `/Users/connor/Medica/backbay/standalone/backbay-sdk/packages/glia-three/src/three/Sentinel/types.ts`

#### QuantumField

`QuantumField` already solves proximity and intention substrate:

- probe
- etch
- burst
- latch
- hover promotion after about `120ms`

Best use:

- ambient wake substrate around a spirit’s local area or around station lanes

Relevant files:

- `/Users/connor/Medica/backbay/standalone/backbay-sdk/packages/glia-three/src/three/QuantumField/FieldProvider.tsx`
- `/Users/connor/Medica/backbay/standalone/backbay-sdk/packages/glia-three/src/three/QuantumField/FieldLayer.tsx`
- `/Users/connor/Medica/backbay/standalone/backbay-sdk/packages/glia-three/src/three/QuantumField/types.ts`

#### SpatialWorkspace

`SpatialWorkspace` is the clearest pattern for a unified 3D workroom with:

- orbiting objects
- topology slices
- trust rings
- selection/hover orchestration

Best use:

- conceptual reference and possible future substrate for a broader hunt room

Relevant files:

- `/Users/connor/Medica/backbay/standalone/backbay-sdk/packages/glia-three/src/three/SpatialWorkspace/SpatialWorkspace.tsx`
- `/Users/connor/Medica/backbay/standalone/backbay-sdk/packages/glia-three/src/three/SpatialWorkspace/types.ts`

## Package Strategy

Do **not** copy the `glia-three` source tree into this repo.

That would create needless duplication and runtime risk around React/Three/R3F ownership.

Also, `apps/desktop` already depends on the published package and already uses it in places like:

- `apps/desktop/src/features/forensics/ForensicsRiverView.tsx`

Recommendation:

1. keep using published `@backbay/glia-three` for stable generic primitives
2. translate selected patterns into local Huntronomer components when they need shell state, routing, anticipation, or hunt semantics
3. avoid vendoring unless a very small isolated utility absolutely needs to be forked

Apply the same rule to `glia-agent`:

1. reuse the published package for generic emotion/cognition primitives already proven in the app
2. build Huntronomer-owned adapters for hunt-spirit semantics
3. do not let hunt identity depend directly on agent-persona concepts

## Recommended Architecture

Introduce a new local concept:

```ts
type HuntSpiritArchetype = "tracker" | "lantern" | "forge" | "loom" | "ledger";

type HuntSpiritStance =
  | "idle"
  | "attuning"
  | "transit"
  | "witnessing"
  | "absorbing"
  | "focused";

type HuntSpiritSpatialState = {
  huntId: string;
  archetype: HuntSpiritArchetype;
  stance: HuntSpiritStance;
  confidence: "low" | "medium" | "high";
  anchorStationId: string | null;
  highlightedStationIds: string[];
  emphasizedFlowKinds: Array<"signals" | "causal-links" | "policy-rails" | "receipts">;
  reason: string | null;
};
```

Then:

- derive it inside the existing anticipation pipeline
- render it through a local 3D adapter layer
- surface it in 2D through dock/sidebar/tab affordances

## Implementation Shape

### Phase 1

Make spirits real in state before making them fancy in rendering.

- add `HuntSpiritState` and `HuntSpiritSpatialState`
- derive spirit from current hunt semantics + anticipation
- show spirit in dock/sidebar/tab metadata

### Phase 2

Add spirit to Forensics first.

- render one active-hunt spirit above the river scene
- attach receipt-witness and focus behaviors
- keep the spirit as a sibling to agent glyphs, not a replacement

### Phase 3

Add spirit to Nexus as a companion to strikecells.

- anchor to active strikecell
- bias station emphasis and focus transitions
- add station-aware transit motion

### Phase 4

Add ambient field coupling.

- field substrate around spirit/station surfaces
- stronger spatial anticipation under confidence gates
- performance and reduced-motion fallbacks

## Guardrails

1. Spirit must encode real hunt state.
   No random spectacle.
2. Spirit must not compete with agents, receipts, or strikecells for meaning.
3. One active foreground spirit at a time.
   Other hunts stay dormant.
4. Motion only on meaningful state changes.
5. Spirit should be legible with reduced effects.
6. Spirit is allowed to bias attention, never to act autonomously.

## Strong Recommendation

Do not start by building “a cool 3D spirit object.”

Start by deciding:

1. what the spirit is trying to communicate
2. where it anchors in the scene
3. which scene events it reacts to
4. how it inherits anticipation reasons

If those are right, the rendering can become beautiful.
If those are wrong, the rendering will only make the product feel more confused.

## North Star

The 3D workspace should eventually feel like:

> stations, flows, receipts, and agents are the world; the hunt spirit is the living investigative posture moving through that world with the operator

That is the level of sophistication this should aim for.
