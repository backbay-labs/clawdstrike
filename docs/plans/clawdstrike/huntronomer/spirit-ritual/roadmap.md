# Spirit Ritual Roadmap

> **Status:** Proposed | **Date:** 2026-03-08
> **Audience:** Product, design, desktop, motion, and 3D-scene implementers
> **Scope:** Rewrite hunt spirit creation into a Baia-inspired artistic ritual without losing the current hunt-state and anticipation spine

## Why This Exists

The current spirit work solved the data model, but not the experience.

The current implementation in:

- `apps/desktop/src/shell/workbench/spirit-bind/**`
- `apps/desktop/src/shell/workbench/HuntDock.tsx`
- `apps/desktop/src/shell/workbench/spirit/**`

still presents spirit creation as an efficient configuration surface.

That is not the product bar anymore.

The new bar is:

- artistic
- embodied
- suggestive
- ritualized
- released into the world

Baia is the right structural reference because its creation flow is not a form.
It is a staged act:

1. choose a mode
2. provide raw intention or material
3. receive interpretive suggestions
4. watch a form emerge
5. inspect it
6. release it into the environment

Huntronomer should translate that structure into hunt-native, operator-safe language.

## Product Principles

- Keep `HUNT_CREATE` instant.
- Every hunt still gets a default spirit seed immediately.
- The rewrite replaces the **creation ritual**, not the requirement that hunts already have a spirit.
- The ritual should feel like entering a chamber, not opening settings.
- The spirit is a living investigative posture, not an icon pack.
- Suggestions must feel collaborative, not authoritarian.
- Release into dock/sidebar/3D must be visible and satisfying.
- Baia's occult language, rarity, and collectible framing remain out of scope.

## Current-State Read

### What exists

- `HUNT_CREATE` now attaches a default spirit in `apps/desktop/src/shell/workbench/huntReducer.ts`
- dock launch wiring exists in `apps/desktop/src/shell/workbench/HuntDock.tsx`
- a working but operational `SpiritBindSheet` exists in `apps/desktop/src/shell/workbench/spirit-bind/SpiritBindSheet.tsx`
- spirit domain, inference, and runtime consumers exist in `apps/desktop/src/shell/workbench/spirit/**`
- 3D spirit actors already exist in Forensics and Nexus

### What is wrong

- the current sheet is text-first, not manifestation-first
- there is no draw / upload / hybrid ritual
- there is no artistic chamber layout or atmosphere
- there is no meaningful release animation equivalent to Baia's burn/release sequence
- the flow feels like configuration of an already-known answer rather than creation of a living posture

## Rewrite Direction

Replace the current `spirit-bind` experience with a new `spirit-ritual` chamber.

The chamber should be built from Baia-style components translated into hunt language:

- mode rail
- intention field
- suggestion chips
- draw canvas
- artifact upload / anchor ingest
- live spirit manifestation canvas
- atmosphere and motion controls
- explicit release action

The spirit seed from `HUNT_CREATE` still exists, but the chamber lets the operator:

- shape it
- replace it
- hybridize it with sketch or artifacts
- pin it
- release it into the live hunt surfaces

## Delivery Phases

| Phase | Goal | Exit Criteria |
| --- | --- | --- |
| `SR-P0` | Contract alignment | Current state and docs stop treating the operational sheet as the target end state |
| `SR-P1` | Ritual chamber shell | A new Baia-inspired chamber exists and replaces the current sheet shell |
| `SR-P2` | Multimodal creation | Intention, draw, hybrid, and upload/anchor modes all feed one draft model |
| `SR-P3` | Manifestation and release | The chamber has living preview, atmosphere, and explicit release choreography |
| `SR-P4` | Surface propagation | Dock, smart bucket, and related hunt surfaces reflect the new ritual output coherently |
| `SR-P5` | 3D handoff | Releasing a spirit visibly hands it into Forensics and Nexus |
| `SR-P6` | Hardening | Tests, dogfood flows, accessibility, and build verification are green |

## Ticket Breakdown

## Phase SR-P0: Contract Alignment

### `SR-P0-01` Ritual initiative docs

- Publish a dedicated `spirit-ritual` initiative separate from the current operational roadmap.
- Make it explicit that the old `SpiritBindSheet` is transitional, not the final UX target.

Primary paths:

- `docs/plans/clawdstrike/huntronomer/spirit-ritual/**`
- `docs/plans/clawdstrike/huntronomer/README.md`

### `SR-P0-02` Shared runtime preservation

- Keep the new reducer/state contract intact:
  - default spirit on `HUNT_CREATE`
  - reconfigure and pin support
- Treat the rewrite as a new front-end ritual over the existing spirit state spine.

Primary paths:

- `apps/desktop/src/shell/workbench/huntReducer.ts`
- `apps/desktop/src/shell/workbench/huntTypes.ts`
- `apps/desktop/src/shell/workbench/WorkbenchStateProvider.tsx`

## Phase SR-P1: Ritual Chamber Shell

### `SR-P1-01` Replace the sheet with a chamber

- Replace `SpiritBindSheet` with a full ritual chamber component.
- Use a split layout closer to Baia:
  - manifestation canvas
  - mode rail
  - interpretation / controls panel
- The chamber must feel immersive and artistic without becoming occult.

Primary paths:

- `apps/desktop/src/shell/workbench/spirit-ritual/**` (new)
- `apps/desktop/src/shell/workbench/spirit-bind/index.ts`

### `SR-P1-02` Ritual control vocabulary

- Replace plain tabs/buttons with tactile selectors inspired by Baia controls.
- Translate:
  - orb selector
  - slider/toggle patterns
  - intention suggestions

Primary paths:

- `apps/desktop/src/shell/workbench/spirit-ritual/controls/**`
- `apps/desktop/src/shell/workbench/spirit-ritual/IntentionSuggestions.tsx`

## Phase SR-P2: Multimodal Creation

### `SR-P2-01` Intention mode

- Rework the current quick-configure mode into a stronger intention-first flow.
- Suggestions should emerge around the operator’s wording, not just show a single static rationale line.

Primary paths:

- `apps/desktop/src/shell/workbench/spirit-ritual/modes/intention/**`
- `apps/desktop/src/shell/workbench/spirit/inference/**`

### `SR-P2-02` Draw mode

- Introduce a sketch-based input path inspired by Baia’s draw canvas.
- Translate freehand drawing into hunt-spirit posture cues instead of sigil geometry.

Primary paths:

- `apps/desktop/src/shell/workbench/spirit-ritual/draw/**`

### `SR-P2-03` Upload / anchor mode

- Introduce artifact ingestion with file/receipt/note/entity anchor previews.
- Make upload/anchor analysis feel interpretive rather than form-like.

Primary paths:

- `apps/desktop/src/shell/workbench/spirit-ritual/upload/**`
- `apps/desktop/src/shell/workbench/spirit/inference/**`

### `SR-P2-04` Hybrid mode

- Allow operator intention plus sketch or anchors to co-shape the ritual draft.
- Keep one shared draft state model across all modes.

Primary paths:

- `apps/desktop/src/shell/workbench/spirit-ritual/state/**`
- `apps/desktop/src/shell/workbench/spirit-ritual/modes/**`

## Phase SR-P3: Manifestation And Release

### `SR-P3-01` Live manifestation canvas

- Add a spirit manifestation surface that feels alive while the operator edits the ritual.
- This should not be a static preview card.

Primary paths:

- `apps/desktop/src/shell/workbench/spirit-ritual/canvas/**`

### `SR-P3-02` Atmosphere layer

- Add controlled atmospheric layers inspired by Baia:
  - particle field
  - glow/breathing environment
  - optional audio-ready hooks if later desired
- Keep everything click-through and operationally restrained.

Primary paths:

- `apps/desktop/src/shell/workbench/spirit-ritual/atmosphere/**`

### `SR-P3-03` Release choreography

- Add an explicit release sequence that hands the chosen spirit into the hunt.
- This is the Baia burn/release equivalent, translated into Huntronomer.

Primary paths:

- `apps/desktop/src/shell/workbench/spirit-ritual/release/**`
- `apps/desktop/src/shell/workbench/HuntDock.tsx`

## Phase SR-P4: Surface Propagation

### `SR-P4-01` Dock and smart bucket adoption

- Make dock, flyouts, and smart bucket reflect the new ritual language and visual grammar.
- Replace leftover “sheet” energy with “released spirit” continuity.

Primary paths:

- `apps/desktop/src/shell/workbench/HuntDock.tsx`
- `apps/desktop/src/shell/workbench/anticipation/SmartBucketHeader.tsx`
- `apps/desktop/src/shell/workbench/spirit/components/**`

### `SR-P4-02` Chamber reopen / retune flow

- Make retuning feel like re-entering the chamber, not editing a settings card.
- Preserve state continuity between first release and later re-entry.

Primary paths:

- `apps/desktop/src/shell/workbench/HuntDock.tsx`
- `apps/desktop/src/shell/workbench/spirit-ritual/**`

## Phase SR-P5: 3D Handoff

### `SR-P5-01` Forensics release receive

- When the spirit is released, Forensics should visibly receive it.
- Keep the actor distinct from agents and receipts.

Primary paths:

- `apps/desktop/src/features/forensics/ForensicsRiverView.tsx`
- `apps/desktop/src/features/forensics/components/hunt-spirit/**`

### `SR-P5-02` Nexus release receive

- Nexus should receive the same release event as a spatial posture change, not a separate representation.

Primary paths:

- `apps/desktop/src/features/cyber-nexus/components/NexusCanvas.tsx`
- `apps/desktop/src/features/cyber-nexus/scene/spirits/**`

## Phase SR-P6: Hardening

### `SR-P6-01` Ritual flow tests

- Add tests for mode switching, ritual draft preservation, release, and retune continuity.

Primary paths:

- `apps/desktop/src/shell/workbench/**/*.test.ts*`

### `SR-P6-02` Dogfood and smoke

- Add a ritual-specific desktop smoke:
  - create hunt
  - chamber opens
  - shape spirit
  - release spirit
  - verify dock + smart bucket + 3D receive

Primary paths:

- `scripts/**`
- `apps/desktop/docs/**`

## Acceptance Gate

The rewrite is done only when:

- `HUNT_CREATE` still stays instant
- the first spirit experience feels like entering an artistic chamber, not editing settings
- intention, draw, upload/anchor, and hybrid creation all work
- release into dock/sidebar/3D is visible and satisfying
- retuning reopens the same ritual language later
- verification passes from one clean run

