# Hunt Spirits Concept

> **Status:** Proposed | **Date:** 2026-03-08
> **Audience:** Product, design, desktop, and anticipation-system implementers
> **Scope:** Give hunts a durable sense of intention and identity without fragmenting Huntronomer

## Why This Exists

The current hunt representation is structurally useful but emotionally flat.

- Hunts carry `color` and `icon` in the model at `apps/desktop/src/shell/workbench/huntTypes.ts`.
- The dock renders those as compact static glyphs in `apps/desktop/src/shell/workbench/HuntDock.tsx`.
- The anticipation layer already knows how to predict actions, semantic targets, and lens promotion, but hunts themselves still feel like generic containers rather than purposeful investigative instruments.

The goal is not to make hunts more ornamental.

The goal is to make each hunt feel like it has:

1. a stable identity
2. a clear investigative posture
3. a visible pull on the surrounding UI

## Current-State Read

Today a hunt is defined mostly as:

- title
- status
- artifacts
- runs
- case link
- color
- icon

That is enough for basic state, but not enough for felt identity.

Baia provides a useful contrast. A sigil there feels alive because it is a stable identity bundle with:

- intention
- seed
- style
- palette
- geometry
- traits
- rarity
- provenance

See:

- `/Users/connor/Medica/backbay/origin/platform/client/web/src/lib/sigil/types.ts`
- `/Users/connor/Medica/backbay/origin/platform/client/web/src/components/apps/Baia/useSigilGenerator.ts`
- `/Users/connor/Medica/backbay/origin/platform/client/web/src/components/apps/Baia/SigilCanvas.tsx`
- `/Users/connor/Medica/backbay/origin/platform/client/web/src/components/apps/Baia/SigilCube/SigilCubeWidget.tsx`

The transferable lesson is not “make hunts mystical.” It is:

> identity should be a stable object that shapes visuals, motion, and interaction bias across surfaces

## Core Thesis

Every hunt should have a **spirit**.

Spirit is the hunt’s operative stance: what kind of work the hunt is currently trying to pull the operator toward.

Spirit is not:

- a mascot
- a fantasy character
- a separate prediction engine
- a decorative theme pack

Spirit is:

- a stable identity layer for the hunt
- a visual grammar for how that hunt appears
- a behavioral bias used by the existing anticipation system
- a compact explanation of what the hunt is “about” right now

## The Right Model

Use a two-layer model:

### 1. Base Spirit

The durable posture of the hunt.

This changes rarely and is inferred from:

- artifact mix
- semantic assignments
- run history
- case linkage
- the hunt’s declared thesis or purpose

### 2. Live Mood

The current operational modulation of the spirit.

This changes live based on:

- active run
- active lens
- current drag object
- recent action chain
- confidence tier
- phase

Base spirit gives continuity.
Live mood gives responsiveness.

## Suggested Spirit Set

Start with a small, operational set.

### Tracker

- best for target-led hunts
- favors entities, watchlists, and pursuit
- ideal when the hunt is pulling toward attribution or follow-the-actor work

### Lantern

- best for proof-building hunts
- favors evidence, receipts, notes, and citations
- ideal when the hunt is trying to illuminate and document

### Forge

- best for execution-led hunts
- favors files, mounts, sandboxes, and run input
- ideal when the hunt is actively testing, replaying, or mounting artifacts

### Loom

- best for relational hunts
- favors graph pivots, scopes, and history
- ideal when the operator is weaving connections and working laterally

### Ledger

- best for case-ready hunts
- favors notes, citations, compare, and export-adjacent surfaces
- ideal when the hunt is assembling durable narrative and proof

## Default Spirit At Hunt Creation

This should be a real feature, but with restraint.

For the concrete user-facing flow, see [Hunt Spirit Creation Flow](./hunt-spirit-creation-flow.md).

When a hunt is created, the system should attach a default spirit immediately.

The follow-on user flow should do three things:

1. show the default spirit that was attached at creation
2. explain why that spirit fits
3. allow the operator to affirm, retune, or pin it at any time

The operator should never be forced to write lore or name a mascot.

The interaction should look more like:

- `Suggested spirit: Forge`
- `Because this hunt is run-heavy and file-led`
- `Focuses Files, Mounts, and Run Input`

Optional operator controls:

- accept current spirit
- choose another spirit
- pin current spirit so inference no longer changes the base spirit
- add a short hunt thesis line that sharpens spirit inference

## Visual System

Spirit should replace the generic icon model with a richer but still restrained identity system.

Each spirit gets:

- a canonical glyph family
- a contour grammar
- a palette tendency
- a motion tendency
- a copy tendency

### Example Visual Grammar

Tracker:

- reticle / forward vector / pursuit marks
- slightly directional motion
- warmer entity-target emphasis

Lantern:

- aperture / reveal beam / opening ring
- soft shimmer and reveal motion
- stronger proof/evidence emphasis

Forge:

- bracket / chamber / mount rail / seated lines
- short compress-and-lock motion
- stronger files/run-input emphasis

Loom:

- thread arcs / links / woven geometry
- linked handoff motion
- stronger scope/history/entity relation emphasis

Ledger:

- stacked bars / proof marks / citation ticks
- stable lock-in motion
- stronger notes/citations/export emphasis

What should transfer from Baia:

- stable generated or derived glyph logic
- orb-like active states
- multi-surface embodiment
- small aura/motion cues

What should not transfer from Baia:

- rarity as spectacle
- mystical copy
- ritual-for-ritual’s-sake
- full custom theming per spirit

## Interaction Model

Spirit should shape the same anticipation surfaces that already exist.

### Hunt Dock

Hunt pills become spirit pills.

Instead of a generic icon path, the pill should show:

- spirit glyph
- hunt color
- live mood through subtle halo/motion

Hover should show:

- spirit name
- one-line hunt thesis or rationale
- current bias

Example:

- `Forge`
- `Run-heavy hunt with active file inputs`
- `Biasing mounts and sandbox surfaces`

### Smart Bucket

The smart bucket should show spirit identity inline beside the hunt title.

That lets semantic drop zones feel like they belong to a specific hunt character instead of a generic drop header.

Example:

- `Hunt 21 · Forge`
- `Prefers Run Input and Mount`

### Sidebar Wake / Ghost Peek

Spirit should influence:

- predicted copy
- lens tie-breaks
- promoted section styling
- explanation strings

Example:

- Tracker: `Attach to active hunt` with `entity-led hunt is active`
- Lantern: `Cite in current note` with `proof-building hunt is active`
- Forge: `Mount to active run` with `run-heavy hunt is active`

### Orb / Lens Rotor

The orb remains a lens controller.
It should not become a spirit selector.

Spirit should only bias:

- which lenses warm first
- which wake reasons appear
- which lens the director spring-loads under high confidence

### Tabs / Headers

Hunt tabs and headers should show a compact spirit chip or glyph so the identity persists beyond the dock.

## Behavior Rules

Spirit must be computed inside the existing anticipation model, not beside it.

It should:

- bias ranking
- bias section promotion
- bias semantic-drop default ordering
- bias lens preference
- shape explanation copy

It must not:

- own a separate confidence model
- create autonomous actions
- override explicit user input
- cause layout thrash

## Proposed State Model

```ts
type HuntSpiritId = "tracker" | "lantern" | "forge" | "loom" | "ledger";

type HuntSpiritMood = "watchful" | "active" | "proving" | "settling";

type HuntSpiritState = {
  id: HuntSpiritId;
  mood: HuntSpiritMood;
  pinned: boolean;
  thesis: string | null;
  reasons: string[];
  lensAffinities: LensId[];
  semanticAffinities: SemanticAttachment[];
};
```

And at the hunt-model layer:

```ts
type Hunt = {
  ...
  spirit: HuntSpiritState | null;
};
```

## Code Touchpoints

These are the natural integration points in the current desktop app:

- `apps/desktop/src/shell/workbench/huntTypes.ts`
  - extend the hunt model with spirit state
- `apps/desktop/src/shell/workbench/HuntDock.tsx`
  - replace static icon rendering with spirit glyph rendering and spirit-aware hover copy
- `apps/desktop/src/shell/workbench/anticipation/SmartBucketHeader.tsx`
  - surface spirit identity and spirit-biased semantic defaults
- `apps/desktop/src/shell/workbench/anticipation/useAnticipation.ts`
  - compute spirit-aware biases inside the fused anticipation context
- `apps/desktop/src/shell/workbench/anticipation/useSidebarDirector.ts`
  - use spirit as a tie-breaker for promoted sections and lens switching
- `apps/desktop/src/shell/workbench/anticipation/useSidebarWakeController.ts`
  - let spirit shape wake copy and emphasis
- `apps/desktop/src/shell/workbench/OrbLensRotor.tsx`
  - warm likely spirit-affined lenses without changing orb ownership

## Guardrails

1. Spirit must stay operational.
   It explains work posture, not lore.
2. Spirit must be stable.
   Base spirit should not thrash as the user pivots.
3. Spirit must be explainable.
   Every spirit-driven bias should carry a visible why-line.
4. Spirit must reuse existing intent gravity.
   No second predictor, no parallel theme engine.
5. Spirit must improve action clarity.
   If it makes the UI harder to read, it is failing.

## Strong Recommendation

Do not start with full procedural sigil generation for hunts.

Start with:

1. a fixed spirit taxonomy
2. a derived spirit state on each hunt
3. a compact glyph system per spirit
4. spirit-aware dock/sidebar/wake copy
5. a `Configure spirit` flow that lets the operator accept, retune, or pin the inferred spirit

If that lands well, then a later phase can explore richer generated glyph variants or spirit-specific orb treatment.

## North Star

The operator should feel:

> this hunt has a character, that character matches the kind of work I’m doing, and the sidebar/dock/orb are all leaning in the same direction

That is the right version of “spirit” for Huntronomer.
