# Hunt Observatory Concept

> **Status:** Draft
> **Date:** 2026-03-09
> **Audience:** Product, design, desktop, and 3D/runtime implementers
> **Goal:** Define what a usable 3D Hunt Observatory in Huntronomer should be, what it should
> replace, and which repo-backed ideas are worth carrying forward.

## Executive Summary

Huntronomer should not become a generic cyber dashboard with decorative 3D effects, and it should
not become a free-roam game scene.

The right target is a **3D Hunt Observatory**:

- a stable spatial arena for one active hunt
- a small set of semantic stations around that arena
- visible connective tissue between hunt, run, evidence, stations, and receipts
- restrained diegetic readouts near objects
- dense textual detail pushed back into intentional rails or editor tabs

The observatory should help an operator answer four questions quickly:

1. What is happening in this hunt right now?
2. Where is the hunt pulling attention next?
3. What evidence, receipts, or stations matter most?
4. What action should I take without losing the overall field?

That means the 3D scene is not a hero background. It is the spatial operating surface for the
hunt.

## What Exists Today

The current Huntronomer implementation has enough strong material to avoid a rewrite, but the
pieces are still framed as separate surfaces rather than one observatory.

### Strong Substrates

- [ForensicsRiverView.tsx](../../../../apps/desktop/src/features/forensics/ForensicsRiverView.tsx)
  is the strongest current substrate. It already carries flow lanes, policies, detectors,
  incidents, agents, and room-level spirit cues.
- [CyberNexusView.tsx](../../../../apps/desktop/src/features/cyber-nexus/CyberNexusView.tsx) and
  [NexusCanvas.tsx](../../../../apps/desktop/src/features/cyber-nexus/components/NexusCanvas.tsx)
  already contain a real strikecell scene, camera logic, and spirit/station embodiment hooks.
- [HuntDock.tsx](../../../../apps/desktop/src/shell/workbench/HuntDock.tsx) already gives hunts a
  persistent entrypoint, spirit access, drag affordances, and live state.
- [SmartBucketHeader.tsx](../../../../apps/desktop/src/shell/workbench/anticipation/SmartBucketHeader.tsx)
  is already close to becoming a compact hunt HUD instead of a generic sidebar header.

### Current Problems

- Hunt state is still too often explained with copy blocks instead of spatial consequence.
- Nexus and Forensics still behave like adjacent views rather than two camera modes on one hunt
  world.
- The Hunt Dock still carries too much chrome and too much product-state narration.
- The 3D layer sometimes looks impressive without being decisively more useful.
- Dense sidebar and bottom-panel surfaces still compete with the main room too often.

## What To Steal From The Reference Code

### From `realm`

The best Realm idea is not fantasy styling. It is the **stable arena with semantic stations**.

Important source files:

- `/Users/connor/Medica/backbay/origin/platform/client/desktop/src/features/realm/RealmView.tsx`
- `/Users/connor/Medica/backbay/origin/platform/client/desktop/src/features/realm/RealmContext.tsx`
- `/Users/connor/Medica/backbay/origin/platform/client/desktop/src/features/realm/types.ts`
- `/Users/connor/Medica/backbay/origin/platform/client/desktop/src/features/realm/components/monuments/ProviderMonument.tsx`
- `/Users/connor/Medica/backbay/origin/platform/client/desktop/src/features/realm/components/dispatch/DispatchTether.tsx`
- `/Users/connor/Medica/backbay/origin/platform/client/desktop/src/features/realm/components/dispatch/WorkProjection.tsx`
- `/Users/connor/Medica/backbay/origin/platform/client/desktop/src/features/realm/components/dispatch/StructureManifestor.tsx`

Transferable principles:

- the room has a stable center and stable edge
- stations live at memorable positions
- work is shown as tethers, projections, and manifested structures
- readable detail uses hybrid 3D + HTML projection instead of forcing dense text into mesh space

Do not import:

- fantasy-world framing
- avatar-driven movement as the core interaction
- provider-themed monument lore

### From `glia-three`

The best `glia-three` material is the **operational scene grammar**, not the packaged full scenes.

Important source files:

- `/Users/connor/Medica/backbay/standalone/backbay-sdk/packages/glia-three/src/three/RiverView/RiverView.tsx`
- `/Users/connor/Medica/backbay/standalone/backbay-sdk/packages/glia-three/src/three/RiverView/riverHelpers.ts`
- `/Users/connor/Medica/backbay/standalone/backbay-sdk/packages/glia-three/src/three/RiverView/InspectorPanel.tsx`
- `/Users/connor/Medica/backbay/standalone/backbay-sdk/packages/glia-three/src/three/CrystallineOrganism/CrystallineOrganism.tsx`
- `/Users/connor/Medica/backbay/standalone/backbay-sdk/packages/glia-three/src/three/AmbientField/FieldProvider.tsx`
- `/Users/connor/Medica/backbay/standalone/backbay-sdk/packages/glia-three/src/three/AmbientField/BackbayFieldBus.ts`
- `/Users/connor/Medica/backbay/standalone/backbay-sdk/packages/glia-three/src/three/QuantumField/domMapping.ts`
- `/Users/connor/Medica/backbay/standalone/backbay-sdk/packages/glia-three/src/three/ThreeErrorBoundary/ThreeErrorBoundary.tsx`

Transferable principles:

- one clear scene grammar for flows, links, rails, and anchors
- scene primitives should be reused inside Huntronomer scenes, not mounted wholesale
- atmosphere should be event-driven and low-information
- heavy scenes need hard performance constraints and explicit failure boundaries

Do not import:

- canned cinematic starfield theater
- SOC dashboard spectacle as a product language
- ornamental radar motifs without operational meaning

### From `Console`

The best Console ideas are about **overview/detail balance** and **diegetic navigation**.

Important source files:

- `/Users/connor/Medica/backbay/origin/platform/client/web/src/components/apps/Console/index.tsx`
- `/Users/connor/Medica/backbay/origin/platform/client/web/src/components/apps/Console/NexusCanvas.tsx`
- `/Users/connor/Medica/backbay/origin/platform/client/web/src/components/apps/Console/ClusterCarousel.tsx`
- `/Users/connor/Medica/backbay/origin/platform/client/web/src/components/apps/Console/NexusDiegeticPanel.tsx`
- `/Users/connor/Medica/backbay/origin/platform/client/web/src/components/apps/Console/DetailPanel.tsx`
- `/Users/connor/Medica/backbay/origin/platform/client/web/src/components/apps/Console/NexusClusterDock.tsx`
- `/Users/connor/Medica/backbay/origin/platform/client/web/src/components/apps/Console/NexusClusterFieldAnchors.tsx`
- `/Users/connor/Medica/backbay/origin/platform/client/web/src/components/apps/Console/CameraRelativeShelf.tsx`

Transferable principles:

- the room can have anchored world UI without becoming unreadable
- navigation should attach to the field, not just screen corners
- detail should open intentionally beside the scene, not be baked permanently into it
- the room should visibly acknowledge focus changes and state changes

Do not import:

- autopilot / explorer game-mode complexity
- full-screen mode takeover
- overuse of 3D text panels

## Coherent Target Picture

Huntronomer should converge on one observatory made of five layers.

### 1. Hunt Arena

The arena is the always-present spatial substrate for the active hunt.

It should provide:

- one stable center of gravity
- one readable floor / field / horizon reference
- one dominant motion grammar for live work
- one bounded camera model

This should feel closer to an instrument table or field observatory than a map or game world.

### 2. Semantic Stations

Stations should be fixed spatial anchors around the hunt arena, not floating menu items.

The first station set should be semantic, not product-marketing driven:

- `Signal`
- `Targets`
- `Run`
- `Receipts`
- `Case / Notes`
- `Watch`

Each station should:

- have a distinct silhouette
- receive compatible work
- glow or bias when likely next
- expose only a small diegetic readout nearby

### 3. Live Connective Tissue

Most of the observatory’s meaning should come from connective effects, not cards.

Those connections should show:

- what station is active
- which run or receipt stream is hot
- what evidence is attached to what
- where the spirit is biasing the hunt
- where the next likely action lives

This is where Forensics River is the best existing base.

### 4. Intentional Detail Surfaces

The scene should not try to carry dense detail itself.

Text-heavy detail belongs in:

- editor/workbench tabs
- right-side detail rails opened intentionally
- bottom proof/replay surfaces opened intentionally

The observatory should supply spatial context, not replace document-grade reading.

### 5. Quiet Hunt Identity

Spirit should remain part of hunt identity, but it should not dominate the room with copy.

In the observatory, spirit should show up as:

- contour bias
- station affinity
- subtle field stain
- receive/aftermath behavior
- station emphasis or suggested line of travel

Spirit should behave like weather or posture, not like a mascot.

## What The Observatory Is Used For

The observatory should support four primary operator loops.

### Loop 1: Triage A Hunt

The operator needs to see:

- what the hunt currently contains
- where fresh signals are entering
- which station is under pressure
- whether the hunt is still exploratory or already proving something

The room should answer this without forcing the user into sidebars immediately.

### Loop 2: Follow A Live Run

The operator needs to see:

- the run path through stations
- what inputs fed it
- where policies shaped or blocked it
- which outputs are becoming receipts or evidence

This is primarily a flow/river use case.

### Loop 3: Inspect Proof Without Losing The Field

The operator needs to open a receipt, note, or case reference without losing the active hunt
geometry.

That means the room stays visible while detail opens beside it, not instead of it.

### Loop 4: Retask Or Recompose

The operator needs to drag a target, artifact, or file into the hunt and understand where it lands
before dropping.

This is where the observatory should connect back to the anticipation work:

- target station warms
- hunt lane sharpens
- likely meaning appears
- drop consequence is visible in-room

## Nexus And Forensics Should Become Two Modes Of One Observatory

Today they are still too separate.

The better mental model is:

- **Forensics / Flow mode**: emphasize lanes, policies, receipts, runtime flow, and action chains
- **Nexus / Observatory mode**: emphasize stations, topology, hunt posture, and strikecell affinity

They should share:

- the same active-hunt identity
- the same station model
- the same spirit runtime
- the same receive/aftermath language
- the same surrounding shell rules

That lets the operator change viewpoint without feeling like they left the hunt.

## Design Rules

1. The room must lead; the HUD must support.
2. Every visible 3D element must encode operational meaning.
3. Dense prose should move out of the room unless intentionally requested.
4. Hunt identity should bias the field quietly, not dominate the screen.
5. One active hunt should feel like one world, even across different camera modes.
6. A station should be more memorable than a sidebar section.
7. The observatory should reduce path length, not add spectacle tax.

## What Not To Build

Do not build:

- a free-roam cyber game
- a generic graph toy with glowing nodes
- a 3D scene with all the real detail still trapped in side cards
- a spirit theater that overwhelms the hunt itself
- separate “Nexus” and “Forensics” products that happen to share branding

## Practical Direction For The Next Design/Architecture Pass

The next pass should focus on defining a first-class observatory contract rather than adding more
visual effects.

Specifically:

1. define the station model
2. define shared scene actor types for hunt, run, receipt, and station cues
3. collapse Nexus and Forensics into one observatory vocabulary
4. demote Hunt Dock from “mini control panel” into “hunt selector + state pulse”
5. define when detail belongs in-room vs in the editor/rail

That is the path from “cool 3D security UI” to a genuinely useful hunt observatory.
