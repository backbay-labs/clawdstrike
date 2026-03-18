# Spirit Chamber Fourth Pass Plan

> **Status:** Proposed | **Date:** 2026-03-09
> **Audience:** Product, design, desktop, motion, scene, and swarm implementers
> **Scope:** Fourth-pass execution plan for moving the spirit chamber from tasteful and coherent to authored, beautiful, and spatially consequential

## Why This Exists

The third pass fixed the chamber architecture and the immediate release aftermath.

What it did not fully solve is the aesthetic bar.

Using the latest live artifacts:

- `output/playwright/huntronomer-smoke/20260309T052801Z/spirit-chamber.png`
- `output/playwright/huntronomer-smoke/20260309T052801Z/spirit-release.png`

the current state is:

- competent
- coherent
- premium

but still not fully artistic.

The chamber now feels like a strong product surface with ritual styling.
It does not yet feel like a living chamber that changes the room.

## Current Gap

The remaining issues are now taste and authorship issues:

1. the chamber stage is elegant but still too flat and too quiet
2. the right rail still reads like software UI instead of chamber instrumentation
3. the orbit stations still feel like placed controls, not field-bound stations
4. the release aftermath works, but the room still does not feel meaningfully changed

## Product Thesis

Fourth pass is about **authored presence**.

The chamber should:

- feel like a scene, not a form
- make each spirit body feel more singular and alive
- reduce product-copy density even further
- make release change the room, not just the sidebar

It should not:

- add more cards
- add more tiny labels
- add more explanatory prose to compensate for weak motion

## Shared Ownership

`ORCH` owns:

- `apps/desktop/src/shell/workbench/spirit-bind/index.ts`
- `apps/desktop/src/shell/workbench/spirit-bind/types.ts`
- `apps/desktop/src/shell/workbench/spirit/index.ts`
- `apps/desktop/src/shell/workbench/spirit/runtime.ts`
- `docs/plans/clawdstrike/huntronomer/spirit-ritual/**`
- `docs/plans/clawdstrike/huntronomer/README.md`
- `.codex/swarm/lanes.tsv`
- `.codex/swarm/waves.tsv`

Workers must not edit those files.

## Lane Map

## `FP1` Chamber Authorship / Reduction

### Goal

Reduce the chamber back down to a stronger composition with fewer software-looking reads.

### Owned Paths

- `apps/desktop/src/shell/workbench/spirit-ritual/SpiritCreationChamber.tsx`
- `apps/desktop/src/shell/workbench/spirit-ritual/SpiritCreationChamber.test.tsx`
- `apps/desktop/src/shell/workbench/spirit-ritual/IntentionSuggestions.tsx`
- `apps/desktop/src/shell/workbench/spirit-ritual/IntentionSuggestions.test.tsx`
- `apps/desktop/src/shell/workbench/spirit-ritual/controls/**`

### Responsibilities

- remove one full informational read from the chamber
- make the right rail feel quieter and more essential
- make the station/orbit controls feel more embedded in the scene
- turn the stabilizer into a quieter, chamber-native control instead of a visible app switch

### Concrete Targets

- keep only:
  - spirit name
  - one reason line
  - one live tuning control
- reduce `READ`, `STABILIZER`, and similar software-language emphasis
- attach station captions more tightly to the chamber edge
- make mode changes shift composition, not only highlighted labels

### Verification

- `npm --prefix apps/desktop test -- --run src/shell/workbench/spirit-ritual/SpiritCreationChamber.test.tsx src/shell/workbench/spirit-ritual/IntentionSuggestions.test.tsx`
- `npm --prefix apps/desktop run typecheck`

## `FP2` Vessel Emergence / Stage Tension

### Goal

Make the vessel feel more alive, tense, and authored without getting noisy.

### Owned Paths

- `apps/desktop/src/shell/workbench/spirit-ritual/canvas/**`
- `apps/desktop/src/shell/workbench/spirit-ritual/atmosphere/**`

### Responsibilities

- strengthen emergence and internal tension in the stage
- give each spirit stronger silhouette and energy distinction
- make the chamber center carry more meaning so the rails can say less
- keep quick mode calm, but not dead

### Concrete Targets

- stronger spirit-specific emergence behaviors:
  - `Forge`: compressed heat and harder ignition
  - `Loom`: woven field tension and strand pull
  - `Lantern`: projection and witness casting
  - `Tracker`: pursuit drift and directional acquisition
  - `Ledger`: measured strata and exact pulse
- more stage-led meaning, fewer floating labels
- more visible tension before release

### Verification

- `npm --prefix apps/desktop test -- --run src/shell/workbench/spirit-ritual/canvas/model.test.ts src/shell/workbench/spirit-ritual/atmosphere/SpiritAtmosphereLayer.test.tsx`
- `npm --prefix apps/desktop run typecheck`

## `FP3` Room Consequence

### Goal

Make the room feel changed after release, not just the sidebar surfaces.

### Owned Paths

- `apps/desktop/src/shell/workbench/spirit-ritual/release/**`
- `apps/desktop/src/shell/workbench/HuntDock.tsx`
- `apps/desktop/src/shell/workbench/anticipation/SmartBucketHeader.tsx`
- `apps/desktop/src/features/forensics/components/hunt-spirit/**`
- `apps/desktop/src/features/forensics/ForensicsRiverView.tsx`
- `apps/desktop/src/features/cyber-nexus/components/NexusCanvas.tsx`
- `apps/desktop/src/features/cyber-nexus/scene/spirits/**`
- `apps/desktop/docs/huntronomer-dogfooding.md`
- `scripts/huntronomer-playwright-smoke.sh`

### Responsibilities

- shift more consequence into the main room and 3D field
- reduce sidebar dominance in the post-release beat
- make the world hold a short field stain after release

### Concrete Targets

- deck / room:
  - subtle ambient change near the active hunt lane
  - calmer sidebar copy
  - less emphasis on `released spirit` style state headings
- Nexus / Forensics:
  - one clearer receive ripple
  - temporary field stain or residue in the main scene
- smoke:
  - capture the room-change moment, not only the rail afterglow

### Verification

- `npm --prefix apps/desktop test -- --run src/shell/workbench/spirit-ritual/release/SpiritReleaseChoreography.test.tsx src/shell/workbench/anticipation/SmartBucketHeader.test.tsx src/features/forensics/components/hunt-spirit/runtime.test.ts src/features/cyber-nexus/scene/spirits/runtime.test.ts`
- `scripts/huntronomer-playwright-smoke.sh`
- `npm --prefix apps/desktop run typecheck`

## Wave Plan

### `wave6`

Lanes:

- `fp1`
- `fp2`

Why:

- the chamber itself still needs one more authorship pass before another room-consequence pass should tune around it

### `wave7`

Lanes:

- `fp3`

Why:

- room consequence should target the final chamber composition and final vessel behavior instead of chasing moving internals

## Merge Order

1. `FP1` and `FP2` land first in either order after review.
2. `ORCH` integrates and visually reviews the chamber again.
3. `FP3` lands on top of the stabilized chamber.
4. `ORCH` reruns live smoke and final aesthetic review against the room-level aftermath.
