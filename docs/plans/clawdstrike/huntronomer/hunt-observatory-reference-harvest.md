# Hunt Observatory Reference Harvest

> **Status:** Draft
> **Date:** 2026-03-09
> **Audience:** Desktop, design, 3D scene, and product architecture implementers
> **Scope:** What to borrow from `trident`, `three-maps`, and `Console` for the next hunt-observatory world pass

## Why This Exists

The current observatory is now conceptually pointed in the right direction, but its world is still
too handcrafted and too thin. We need a better authoring model for:

- stable districts that can grow over time
- a shared world representation for `flow` and `atlas`
- camera travel and in-room navigation that stays in one scene
- procedural or semi-procedural scene expansion without turning the room into hard-coded JSX

This note reviews three internal references and answers one question:

> What scene and world-building systems are worth stealing for Huntronomer?

Reviewed sources:

- `/Users/connor/Medica/backbay/standalone/trident`
- `/Users/connor/Medica/backbay/standalone/three-maps`
- `/Users/connor/Medica/backbay/origin/platform/client/web/src/components/apps/Console`

## Current Observatory Gap

The current observatory world in
[ObservatoryWorldCanvas.tsx](../../../../../apps/desktop/src/features/hunt-observatory/world/ObservatoryWorldCanvas.tsx)
is still mostly direct JSX scene authoring:

- station positions are hard-coded
- district content is handwritten
- there is no derived world-document layer
- there is no recipe system for district growth
- there is no cacheable world build step

That is enough for early composition work, but not enough for a room that evolves as hunts gain
signals, operations, evidence, and judgment.

## Reference 1: Trident

### What It Is

`trident` is the cleanest example of **document -> derived render scene** separation.

Relevant files:

- [ARCHITECTURE.md](/Users/connor/Medica/backbay/standalone/trident/ARCHITECTURE.md)
- [derived-scene.ts](/Users/connor/Medica/backbay/standalone/trident/packages/render-pipeline/src/scene/derived-scene.ts)
- [ViewportCanvas.tsx](/Users/connor/Medica/backbay/standalone/trident/apps/editor/src/viewport/ViewportCanvas.tsx)

### What To Borrow

#### 1. Derived scene pipeline

`trident` explicitly separates authoring state from render state. The key move is:

- source document is authoritative
- render scene is derived
- view code consumes the derived scene, not raw authoring state

That is exactly what the observatory needs next.

Huntronomer equivalent:

```ts
ObservatoryDocument
  -> deriveObservatoryWorld()
  -> DerivedObservatoryScene
  -> ObservatoryWorldCanvas
```

This lets us stop hand-threading scene behavior directly into React components.

#### 2. Viewport/interaction separation

[ViewportCanvas.tsx](/Users/connor/Medica/backbay/standalone/trident/apps/editor/src/viewport/ViewportCanvas.tsx)
shows a useful pattern:

- camera rig
- grid / base world
- overlays
- tool interaction
- scene preview

For Huntronomer, the analog is:

- world canvas
- station navigation rig
- diegetic overlays
- room consequence / spirit weather
- detail-surface seams

The point is not to copy the editor UX. The point is to stop mixing everything into one scene file.

### What Not To Borrow

- brush/mesh authoring kernel
- editor-shell layout
- transform gizmo workflow
- file-oriented scene editing model

Huntronomer needs the render derivation pattern, not the level-editor product.

## Reference 2: Three Maps

### What It Is

`three-maps` is the strongest reference for **parameterized world state** and **procedural surface
generation**.

Relevant files:

- [IMPLEMENTATION.md](/Users/connor/Medica/backbay/standalone/three-maps/docs/IMPLEMENTATION.md)
- [world-store.ts](/Users/connor/Medica/backbay/standalone/three-maps/src/stores/world-store.ts)
- [generate.ts](/Users/connor/Medica/backbay/standalone/three-maps/src/utils/terrain/generate.ts)
- [viewport-store.ts](/Users/connor/Medica/backbay/standalone/three-maps/src/stores/viewport-store.ts)

### What To Borrow

#### 1. Separate world render settings from scene/object state

[world-store.ts](/Users/connor/Medica/backbay/standalone/three-maps/src/stores/world-store.ts)
separates environment, bloom, fog, renderer, and depth-of-field from the rest of the scene.

Huntronomer should do the same:

- observatory weather
- field exposure
- fog / atmosphere
- receive-state lighting
- station-specific ambient presets

This should not stay buried in one JSX file.

#### 2. Recipe-driven generation

[generate.ts](/Users/connor/Medica/backbay/standalone/three-maps/src/utils/terrain/generate.ts)
is valuable because it treats world generation as:

- a graph of inputs
- a stable signature
- a bake/evaluate step

Huntronomer does not need heightmaps, but it does need the same architecture for district growth:

```ts
DistrictRecipeGraph
  -> compute signature
  -> derive/bake district scaffolds
  -> cache result
```

That becomes the basis for:

- dormant infrastructure waking up
- transit networks thickening
- evidence districts accreting objects
- judgment districts formalizing into stronger structures

#### 3. Viewport state as first-class state

[viewport-store.ts](/Users/connor/Medica/backbay/standalone/three-maps/src/stores/viewport-store.ts)
keeps camera target, framing, and navigation settings explicit.

Huntronomer should similarly promote:

- active station focus
- previous station focus
- travel intent
- travel phase
- idle drift orbit
- hunt-scale framing

into a real observatory camera state instead of ad hoc camera math.

### What Not To Borrow

- whole editor/store stack
- geometry editing workflow
- properties panel architecture
- terrain authoring UX

What is useful is the generation model and world-parameter separation, not the whole application.

## Reference 3: Console

### What It Is

`Console` is the best reference for **spatial information arrangement** and **diegetic control
layering**.

Relevant files:

- [NexusCanvas.tsx](/Users/connor/Medica/backbay/origin/platform/client/web/src/components/apps/Console/NexusCanvas.tsx)
- [layouts/index.ts](/Users/connor/Medica/backbay/origin/platform/client/web/src/components/apps/Console/layouts/index.ts)
- [typedLanes.ts](/Users/connor/Medica/backbay/origin/platform/client/web/src/components/apps/Console/layouts/typedLanes.ts)
- [NexusClusterFieldAnchors.tsx](/Users/connor/Medica/backbay/origin/platform/client/web/src/components/apps/Console/NexusClusterFieldAnchors.tsx)
- [CameraRelativeShelf.tsx](/Users/connor/Medica/backbay/origin/platform/client/web/src/components/apps/Console/CameraRelativeShelf.tsx)
- [NexusSpatialWorkspace.tsx](/Users/connor/Medica/backbay/origin/platform/client/web/src/components/apps/Console/NexusSpatialWorkspace.tsx)

### What To Borrow

#### 1. Layout engines as interchangeable strategies

[layouts/index.ts](/Users/connor/Medica/backbay/origin/platform/client/web/src/components/apps/Console/layouts/index.ts)
is the most directly reusable conceptual piece.

It treats layout as a mode-driven, pluggable system:

- grid
- force-directed
- typed lanes
- radial

Huntronomer needs the same idea, but with observatory semantics:

- district overview layout
- transit-heavy flow layout
- evidence constellation layout
- judgment scaffold layout
- watchfield perimeter layout

This should become a local `observatory-layouts/` system.

#### 2. Field anchor pattern

[NexusClusterFieldAnchors.tsx](/Users/connor/Medica/backbay/origin/platform/client/web/src/components/apps/Console/NexusClusterFieldAnchors.tsx)
is valuable because it bridges scene objects into a field system without making the field own the
objects.

That pattern maps well to Huntronomer:

- station district emits field anchors
- spirit bias emits field anchors
- evidence clusters emit field anchors
- room consequence consumes them

This is stronger than painting one giant overlay over the room.

#### 3. Camera-relative diegetic UI

[CameraRelativeShelf.tsx](/Users/connor/Medica/backbay/origin/platform/client/web/src/components/apps/Console/CameraRelativeShelf.tsx)
shows a good pattern for controls that feel spatial without being world geometry.

Huntronomer can use that for:

- compact station readouts
- travel hints
- local operator prompts

without dropping back into flat screen-chrome panels.

### What Not To Borrow

- old cluster/item taxonomy
- existing object shapes
- sprawling debug-heavy overlays
- full `Console` app framing

The useful part is the spatial layout grammar, not the old product model.

## Synthesis

The right next architecture is:

```ts
ObservatoryDocument
  stations
  core
  worldWeather
  detailLinks
  spiritBias
  eventPressure

-> deriveObservatorySceneState()

-> deriveObservatoryDistrictRecipes()

-> bakeObservatoryWorld()

-> DerivedObservatoryScene
  cameraState
  districtStructures
  transitRoutes
  hypothesisScaffolds
  fieldAnchors
  roomEffects

-> ObservatoryWorldCanvas
```

That combines:

- `trident` style derived render scene
- `three-maps` style recipe/bake system
- `Console` style layout engines and field anchors

## Recommendation

### Do Not

- import `trident` wholesale
- import `three-maps` wholesale
- move the current observatory into either app’s runtime or store system

### Do

- keep the observatory implementation local to `apps/desktop`
- introduce a local derived scene layer for the observatory
- introduce a local district-recipe/bake step
- introduce local observatory layout strategies inspired by `Console`
- keep generic rendering primitives in `@backbay/glia-three` only when they are clearly reusable

## Concrete Next Step

The best next implementation slice is:

1. create `apps/desktop/src/features/hunt-observatory/world/deriveObservatoryWorld.ts`
2. define `DistrictRecipe`, `TransitRouteRecipe`, and `HypothesisScaffoldRecipe`
3. move district geometry decisions out of `ObservatoryWorldCanvas.tsx`
4. keep `ObservatoryWorldCanvas.tsx` as a renderer for the derived world, not the authoring brain

That is the point where the observatory stops being a handcrafted demo and starts becoming a real
world system.
