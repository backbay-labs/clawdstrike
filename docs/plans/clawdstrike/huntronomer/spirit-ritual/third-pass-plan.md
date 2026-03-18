# Spirit Chamber Third Pass Plan

> **Status:** Proposed | **Date:** 2026-03-09
> **Audience:** Product, design, desktop, motion, scene, and swarm implementers
> **Scope:** Third-pass execution plan for moving the spirit chamber from structurally correct to authored, distinct, and consequential

## Why This Exists

The chamber is no longer blocked by engineering fundamentals.

It now:

- opens from the public `SpiritBindSheet` seam
- uses the shared manifestation stage
- releases into dock/sidebar/runtime
- passes focused ritual verification and live browser smoke

The remaining gap is no longer "does it work."
It is:

> does it feel authored, distinct, beautiful, and alive enough to justify the ritual?

The current chamber is now a good system.
The next pass needs to make it a better experience.

## Current Gap

Using the latest live chamber artifact:

- `output/playwright/huntronomer-smoke/20260309T035629Z/spirit-chamber.png`

the remaining issues are:

1. spirits still share too much of one generic vessel grammar
2. the orbit/mode controls still read like a refined menu, not chamber stations
3. release is visible, but the aftermath in dock/sidebar/3D still feels operational instead of charged

This plan addresses exactly those three gaps with three bounded lanes.

## Product Thesis

Third pass is about **authorship**.

The chamber should:

- feel different when the spirit is `Forge` versus `Loom`
- feel like the operator is tuning an instrument field, not clicking a menu
- leave a temporary field consequence in the workspace after release

It should not:

- add more boxes
- add more explainer copy
- become more cluttered while trying to feel richer

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

## `TP1` Spirit-Specific Visual Grammars

### Goal

Make each spirit feel like a different being, not a relabeled instance of the same vessel.

### Owned Paths

- `apps/desktop/src/shell/workbench/spirit-ritual/canvas/**`
- `apps/desktop/src/shell/workbench/spirit-ritual/atmosphere/**`

### Responsibilities

- introduce per-spirit stage grammars for `Tracker`, `Lantern`, `Forge`, `Loom`, and `Ledger`
- differentiate:
  - vessel silhouette
  - contour emphasis
  - ring behavior
  - halo/floor glow profile
  - tether character
  - ghost behavior
  - exit seam character
- make quick mode especially calm and non-chatty
- move more meaning into the stage so less text is needed elsewhere

### Concrete Targets

- `Forge`
  - hotter, denser core
  - sharper arcs and harder compression
  - more directional release seam
- `Loom`
  - thread lattice and distributed linework
  - softer structural weaving
  - relation-driven tension
- `Lantern`
  - projected witness beam
  - halo-forward silhouette
  - less central mass, more field casting
- `Tracker`
  - reticle drift and directional pursuit
  - narrow forward pull
  - tighter rings
- `Ledger`
  - measured strata
  - stacked, stable geometry
  - low-drama but high-clarity pulse

### Deliverables

- spirit grammar map in the canvas model
- distinct per-kind manifestation visuals
- tests proving per-kind stage differences exist and are stable

### Verification

- `npm --prefix apps/desktop test -- --run src/shell/workbench/spirit-ritual/canvas/model.test.ts src/shell/workbench/spirit-ritual/atmosphere/SpiritAtmosphereLayer.test.tsx`
- `npm --prefix apps/desktop run typecheck`

## `TP2` Orbit / Station Control Redesign

### Goal

Turn the mode/control system into chamber instruments instead of a polished vertical menu.

### Owned Paths

- `apps/desktop/src/shell/workbench/spirit-ritual/SpiritCreationChamber.tsx`
- `apps/desktop/src/shell/workbench/spirit-ritual/SpiritCreationChamber.test.tsx`
- `apps/desktop/src/shell/workbench/spirit-ritual/IntentionSuggestions.tsx`
- `apps/desktop/src/shell/workbench/spirit-ritual/IntentionSuggestions.test.tsx`
- `apps/desktop/src/shell/workbench/spirit-ritual/controls/**`

### Responsibilities

- redesign the left mode rail into orbit/station controls attached to the vessel field
- reduce caption text further and use stateful affordances instead of explanation blocks
- make `Quick`, `Thesis`, `Anchors`, and `Manual` feel like different stations around the chamber
- keep the right rail minimal:
  - one read
  - one reason
  - one active tuning control
- push alternate readings into `Manual` instead of always showing them

### Concrete Targets

- replace stacked cards with:
  - orbit nodes
  - radial or arc-attached toggles
  - chamber-edge stations
- mode changes should visibly move the chamber composition, not only switch text
- `Intensity` should appear only when relevant
- `Pin spirit` should feel like a quiet stabilizer, not a prominent panel

### Deliverables

- orbit/station control composition
- reduced rail and control copy
- updated keyboard behavior for new instrument layout

### Verification

- `npm --prefix apps/desktop test -- --run src/shell/workbench/spirit-ritual/SpiritCreationChamber.test.tsx src/shell/workbench/spirit-ritual/IntentionSuggestions.test.tsx`
- `npm --prefix apps/desktop run typecheck`

## `TP3` Release Aftermath Across Dock / Sidebar / 3D

### Goal

Make release feel consequential for a few seconds after the chamber closes.

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

- extend release from a visible transit into a visible aftermath
- make dock/sidebar/3D acknowledge receipt as one coordinated event
- keep the aftermath restrained and time-bounded
- update smoke and dogfood artifacts so the after-effect is actually captured

### Concrete Targets

- dock
  - lingering receive pulse
  - spirit-specific afterimage
  - stronger temporary identity handoff
- smart bucket
  - short field-shift state
  - less admin wording after release
- Forensics / Nexus
  - one immediate receive ripple or field residue
  - subtle spirit-specific wake around the active hunt presence
- smoke path
  - capture post-release state after the receive beat, not too early

### Deliverables

- extended release choreography
- temporary multi-surface aftermath state
- updated smoke script and dogfood note for the new timing

### Verification

- `npm --prefix apps/desktop test -- --run src/shell/workbench/spirit-ritual/release/SpiritReleaseChoreography.test.tsx src/shell/workbench/anticipation/SmartBucketHeader.test.tsx src/features/forensics/components/hunt-spirit/runtime.test.ts src/features/cyber-nexus/scene/spirits/runtime.test.ts`
- `scripts/huntronomer-playwright-smoke.sh`
- `npm --prefix apps/desktop run typecheck`

## Wave Plan

### `wave4`

Lanes:

- `tp1`
- `tp2`

Why:

- the chamber itself needs to be finalized before the aftermath lane can tune the external receive surfaces against it

### `wave5`

Lanes:

- `tp3`

Why:

- release aftermath should target the final spirit grammars and final control composition rather than chasing moving chamber internals

`ORCH` remains active through both waves for integration and acceptance.

## Merge Order

1. `TP1` and `TP2` land first in either order after review.
2. `ORCH` integrates their chamber seam and verifies the chamber visually.
3. `TP3` lands on top of the stabilized chamber.
4. `ORCH` runs full ritual smoke and final screenshot review.

## Acceptance Criteria

Third pass is complete when:

1. a screenshot of `Forge` and a screenshot of `Loom` no longer look like the same chamber with different labels
2. mode controls read as chamber instruments, not a settings rail
3. the right rail can be understood in one glance
4. release leaves a visible, short-lived consequence in dock, sidebar, and one 3D surface
5. live dogfood artifacts show both a non-black deck state and a materially improved chamber state

## Launch Briefs

### `TP1` brief

Own spirit-specific stage grammar only.
Do not edit chamber shell, release surfaces, or docs.

### `TP2` brief

Own orbit/station control composition only.
Do not edit canvas/atmosphere internals or release surfaces.

### `TP3` brief

Own aftermath and dogfood capture only.
Do not rework the chamber shell or per-spirit stage grammar.

## Verification Gate

At the end of the full third pass, `ORCH` must run:

- `npm --prefix apps/desktop run typecheck`
- `npm --prefix apps/desktop test -- --run`
- `scripts/huntronomer-playwright-smoke.sh`

Optional but recommended:

- native `tauri:dev` dogfood plus screenshots once the chamber visuals settle
