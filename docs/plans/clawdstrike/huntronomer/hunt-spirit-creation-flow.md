# Hunt Spirit Creation Flow

> **Status:** Proposed | **Date:** 2026-03-08
> **Audience:** Product, design, desktop, anticipation, and 3D-scene implementers
> **Scope:** Define how an operator should create, review, and bind a spirit to a hunt

## Why This Exists

The hunt-spirit idea is correct, but the missing piece is the user-facing creation act.

Right now Huntronomer has:

- a bare hunt creation path
- a growing anticipation system
- a strong 3D workspace grammar
- concept docs for hunt identity and 3D embodiment

What it does not have yet is a concrete answer to:

> how a user actually creates a spirit

This doc answers that.

## Current-State Read

### Huntronomer hunt creation is still a thin action

The current creation path is immediate and minimal:

- the `+` control in `apps/desktop/src/shell/workbench/HuntDock.tsx` dispatches `HUNT_CREATE`
- `apps/desktop/src/shell/workbench/huntReducer.ts` creates a hunt with a generated title, empty artifact/run lists, and palette-assigned `color` and `icon`
- the `Hunt` model in `apps/desktop/src/shell/workbench/huntTypes.ts` has nowhere to store spirit posture, thesis, anchors, or bind history

That means hunt creation is currently:

`make empty hunt -> assign icon/color -> set active`

That is fast, but it gives the operator no way to establish what the hunt is trying to become.

### Baia has the right ritual structure

Baia is relevant because its creation flow is not a settings form.

At `origin/platform/client/web/src/components/apps/Baia/Baia.tsx` and
`origin/platform/client/web/src/components/apps/Baia/useSigilGenerator.ts`, the user:

1. chooses a creation mode
2. supplies raw intention or material
3. gets system suggestions back
4. manifests a candidate artifact
5. inspects that artifact in place
6. explicitly releases it into the desktop world

The transferable lesson is structural:

`gather intent -> infer -> manifest -> inspect -> release`

Huntronomer should borrow that structure, not Baia's mysticism, rarity, or art-toy behavior.

## Core Product Decision

The operator should create the hunt first and bind the spirit second.

Do **not** turn spirit into a blocking pre-create wizard.

The right default sequence is:

1. user creates a hunt instantly
2. Huntronomer opens a lightweight `Bind Spirit` surface for that new active hunt
3. the system suggests a spirit from whatever context exists
4. the operator accepts, changes, pins, or skips
5. the spirit is released into dock, sidebar, and 3D space

This preserves the speed of the current `HUNT_CREATE` path while giving the hunt a real identity layer.

## The Right Mental Model

Creating a spirit is not "customizing an icon."

Creating a spirit is:

> binding an operative posture to a hunt

The system should help the operator answer three questions:

1. What is this hunt trying to reveal or prove?
2. What material already defines its center of gravity?
3. What posture should the workspace take around it?

The user is not naming a mascot.
The user is authoring or confirming the hunt's stance.

## Entry Points

There should be three creation moments.

### 1. First creation: immediate bind prompt

After `HUNT_CREATE`, open a small `Bind Spirit` sheet anchored to the newly active hunt.

This is the primary path.

Requirements:

- non-blocking
- dismissible
- one clear suggestion if confidence is high
- able to complete in one click

If the operator dismisses it, the hunt stays usable.

### 2. Mature hunt: add spirit later

If a hunt is already accumulating artifacts, semantic assignments, or run history and still has no spirit, surface:

`Add spirit`

Good surfaces:

- hunt dock hover flyout
- smart bucket header
- empty-state card inside the hunt lens

This path should feel quieter than first creation because the hunt already exists.

### 3. Rebind / repin

If the hunt changes shape materially, allow:

- `Rebind spirit`
- `Pin current spirit`
- `Unpin and infer again`

This should be available from hunt settings or the spirit detail card, not from every hover surface.

## Input Modes

Baia uses `generate`, `draw`, `hybrid`, and `upload`.
Huntronomer should adapt that into operational modes.

### Quick Bind

Default mode.

The system infers from:

- hunt title
- current shell/lens
- first artifacts
- semantic assignments
- run activity
- case linkage

The operator sees:

- suggested spirit
- one reason line
- predicted focus surfaces

This should be the fastest path and the default for most hunts.

### Thesis

One authored sentence.

Prompt:

`What are you chasing?`

Examples:

- `Trace lateral movement through the sandbox execution chain`
- `Build proof for policy bypass and export path`
- `Map operator-linked entities behind this receipt cluster`

This is the closest Huntronomer analog to Baia's intention field.

### Anchor Artifacts

Let the operator choose up to three artifacts that define the hunt's center.

Good anchors:

- files
- receipts
- entities
- notes
- signals

The system then explains the suggestion in relation to those anchors.

Example:

- `Suggested spirit: Lantern`
- `Because these anchors are receipt-led and citation-heavy`

This is the operational analog to Baia's upload or sketch-derived generation.

### Manual Spirit

Allow direct selection from the v1 spirit set:

- Tracker
- Lantern
- Forge
- Loom
- Ledger

This is an override path, not the primary path.

It exists because experienced operators will often know the posture immediately.

### Explicit Non-Goal: freehand drawing in v1

Do not bring Baia's draw canvas directly into hunt spirit creation yet.

That would add ceremony before the operational model is stable.

If visual authoring ever appears, it should be a later refinement layer over a stable hunt-native spirit model.

## Authored vs Inferred

The flow only works if the user can tell what the system decided versus what they decided.

### Authored by the operator

- thesis line
- selected spirit override
- selected anchor artifacts
- pinned/unpinned base spirit

### Inferred by the system

- candidate spirit
- rationale line
- glyph family
- palette tendency
- motion tendency
- likely focus surfaces
- likely 3D stance

The UI must always label the reason for the inference.

Examples:

- `Suggested because this hunt is run-heavy and file-led`
- `Suggested because recent work is receipt and citation heavy`
- `Suggested because the selected anchors are entity-forward`

## Flow Anatomy

The flow should be short, legible, and staged.

### Step 1. Gather

Show the active hunt plus one of:

- inferred context
- thesis input
- anchor selectors
- manual spirit chooser

Do not show all modes as a complex wizard.
Use a compact mode switch with `Quick Bind` selected by default.

### Step 2. Infer

The system proposes:

- one primary spirit
- up to two alternates
- one reason line
- one "this will bias" line

Example:

- `Forge`
- `Suggested because this hunt already centers file mounts and active run inputs`
- `Biases Files, Mounts, and sandbox surfaces`

### Step 3. Manifest

Show one live preview card with synchronized embodiments:

- hunt dock pill preview
- smart bucket/sidebar wake preview
- 3D workspace preview

The preview should not be decorative.
It should answer:

- what will this hunt look like in the dock
- what language will the sidebar use
- how will the spirit appear in Nexus or Forensics

### Step 4. Inspect

Let the operator make one of a few high-value adjustments:

- `Accept suggestion`
- `Choose another spirit`
- `Pin spirit`
- `Change thesis`
- `Swap anchors`

Do not create an endless reroll surface.

### Step 5. Bind

The final action is:

`Bind Spirit`

Alternative copy:

`Crystallize`

`Bind Spirit` is better for v1 because it is clearer and more operational.

## Commit And Release

Baia's best pattern is that generation and release are separate acts.
Huntronomer should keep that separation.

The candidate spirit exists in preview first.
It only becomes part of the live hunt when the operator binds it.

On bind:

- the hunt record stores the spirit state
- the hunt dock pill updates immediately
- the smart bucket updates immediately
- the sidebar wake copy updates immediately
- the active 3D workspace gets a short bind pulse or draw-in motion

The confirmation should last roughly `500-800ms`.
It should feel like the spirit entered the hunt, not like a settings dialog saved.

## Surface Behavior After Binding

Once bound, the spirit should immediately change three surfaces.

### Hunt Dock

The generic icon should be replaced by the spirit's compressed identity token.

Hover should explain:

- spirit name
- thesis or rationale
- current bias

### Sidebar / Smart Bucket

The smart bucket becomes the semantic console for the spirit.

It should show:

- spirit name or glyph
- rationale line
- current bias
- promoted semantic targets based on stance

### 3D Workspace

The spirit should appear as a restrained preview-presence in the active 3D scene.

For v1:

- if the operator is in Forensics, bind there first
- if the operator is in Nexus, show the lighter locus form there

The important thing is continuity:
the thing the operator just bound should now visibly inhabit the workspace.

## First-Run And Repeat Paths

### First-time path

The first spirit bind can be slightly more guided.

Target duration:

- `20-30s` if the operator reads and chooses intentionally
- `1 click` if the default suggestion is already correct

### Repeat path

For experienced operators, the flow should collapse to:

1. create hunt
2. see suggestion
3. click `Bind Spirit`

That is the bar.

## Guardrails

- Never block hunt creation on spirit creation.
- Never require drawing, uploading, or decorative customization.
- Never hide why a spirit was suggested.
- Never let spirit override explicit operator actions.
- Never turn spirit creation into lore writing.
- Never add rarity, lootbox rerolls, or mystical spectacle.
- Never let the ceremony take longer than the investigative value it adds.

## Data And Implementation Implications

This flow implies changes to the current hunt model and creation path.

### Hunt model additions

`apps/desktop/src/shell/workbench/huntTypes.ts` should eventually add a spirit payload with fields like:

- `baseSpirit`
- `liveMood`
- `thesis`
- `anchorArtifactIds`
- `bindSource`
- `bindReason`
- `isSpiritPinned`
- `spiritVersion`

### Reducer and action changes

`apps/desktop/src/shell/workbench/huntReducer.ts` should keep instant hunt creation, but support a second action family such as:

- `HUNT_BIND_SPIRIT`
- `HUNT_REBIND_SPIRIT`
- `HUNT_PIN_SPIRIT`

`HUNT_CREATE` should remain fast and thin.
Spirit binding should layer on top of it.

### Surface consumers

Spirit bind results should propagate into:

- `apps/desktop/src/shell/workbench/HuntDock.tsx`
- `apps/desktop/src/shell/workbench/anticipation/SmartBucketHeader.tsx`
- `apps/desktop/src/shell/workbench/anticipation/useAnticipation.ts`
- `apps/desktop/src/features/forensics/ForensicsRiverView.tsx`
- `apps/desktop/src/features/cyber-nexus/components/NexusCanvas.tsx`

## Recommended V1

If this ships in phases, v1 should be:

1. instant hunt creation stays as-is
2. `Bind Spirit` sheet appears for new hunts
3. support `Quick Bind`, `Thesis`, and `Manual Spirit`
4. show preview in dock + sidebar + lightweight 3D card
5. commit with `Bind Spirit`
6. add `Add spirit` for existing hunts later

That is enough to prove the model without overbuilding.

## Reading Order

- [Hunt Spirits Concept](./hunt-spirits-concept.md)
- [Hunt Spirits In The 3D Workspace](./hunt-spirits-3d-workspace-concept.md)
- [Intent Gravity Implementation](./intent-gravity-implementation.md)
