# Spirit Chamber Redesign Spec

> **Status:** Proposed | **Date:** 2026-03-08
> **Audience:** Product, design, desktop, motion, and scene implementers
> **Scope:** Replace the current three-column ritual sheet with a Baia-caliber chamber that feels artistic, embodied, and consequential

## Why This Exists

The current ritual stack is structurally correct and visually disciplined, but the live dogfood pass
shows the chamber is still the wrong interaction genre.

It reads as:

- a premium settings modal
- a dense operational control panel
- an illustration surrounded by forms

It does **not** read as:

- a chamber
- an act of manifestation
- a spirit entering the world

The screenshot-backed critique is simple:

> the current chamber is elegant enterprise UI with ceremonial styling, not an artistic creation experience

This spec turns that critique into the next concrete target.

## Source Evidence

This redesign is grounded in the live chamber flow captured at:

- `output/playwright/huntronomer-smoke/20260309T023544Z/spirit-chamber.png`
- `output/playwright/huntronomer-smoke/20260309T023544Z/spirit-release.png`

and in the current implementation seam:

- `apps/desktop/src/shell/workbench/spirit-ritual/SpiritCreationChamber.tsx`
- `apps/desktop/src/shell/workbench/spirit-bind/SpiritBindSheet.tsx`

The current problems are:

1. the chamber is composed like a `left nav + center preview + right controls` modal
2. nearly every idea is boxed, so nothing feels singular
3. the manifestation is too inert and illustration-like
4. the copy is over-labeled and over-explained
5. release collapses immediately into sidebar summary language instead of a world transfer

## Product Rule

The chamber is not a form for configuring a spirit.

The chamber is:

> a staged act where the operator gathers intent, shapes a living posture, and releases it into the hunt field

That means:

- the center must dominate
- interpretation must feel collaborative
- controls must feel instrumental, not administrative
- release must visibly transit into the workspace

## Non-Goals

- Do not import Baia's occult framing, rarity logic, or collectible energy.
- Do not turn the chamber into a blocking wizard.
- Do not reduce the chamber to pure art with weak operational legibility.
- Do not add ambient layers that block pointer ownership or keyboard reachability.

## Layout Spec

## Layout Thesis

The chamber must stop being a balanced three-column sheet.

The new spatial hierarchy is:

1. **Manifestation Stage** - dominant, living, central
2. **Ritual Ring** - mode and tuning instruments attached to the stage
3. **Interpretation Rail** - a narrow, quiet reading of what the chamber currently believes
4. **Threshold Actions** - keep / dismiss / release at the edge of the scene, not as a header toolbar

The stage should visually own about `65-72%` of the chamber width.

## Canonical Composition

### 1. Threshold band

Replace the current dense header with a thin threshold band.

Contents:

- hunt title
- current spirit seed state: `first release` or `retuning`
- one short line of chamber framing
- quiet `Dismiss` / `Keep current spirit`

Rules:

- no long explanatory paragraph
- no primary CTA here
- this band should feel like crossing a threshold, not reading a panel intro

### 2. Manifestation stage

This is the chamber.

It should contain:

- a deep field backdrop
- one central vessel / orb / contour body
- live atmosphere layers around it
- emerging traces from the active mode
- interpretive labels anchored near the form, not in separate cards

Rules:

- the spirit body should occupy real area, not a small object centered in lots of empty panel chrome
- the stage must support draw, anchors, and thesis overlays without becoming cluttered
- orbit lines, particles, and contour traces should feel like a field reacting to input, not a screensaver

### 3. Ritual ring

The current left mode stack becomes a ring or arc of tools attached to the stage, not a side menu.

Modes:

- `Quick`
- `Thesis`
- `Anchors`
- `Manual`

Rules:

- mode selectors should feel like instruments or stations around the vessel
- the active mode should reshape the stage, not only highlight a button
- secondary affordances should stay hidden until the mode is active

### 4. Interpretation rail

The right column survives, but it becomes much narrower and much quieter.

It should carry only:

- current read: spirit + mood + confidence
- one reason line
- one alternate path
- one active tuning control at a time

Rules:

- no stack of equal-weight bordered cards
- no repeated labels for the same idea
- predicted surfaces should appear as a concise consequence line, not a standalone module

### 5. Threshold actions

The primary action cluster sits low and close to the stage edge.

Actions:

- `Release Spirit`
- `Keep current spirit`
- `Dismiss`

Rules:

- release should feel like opening a gate, not submitting a form
- release must visually tether to the stage and to the dock/workspace destination

## Density Rules

- Maximum of `2` strong bordered regions visible at once.
- Support details should prefer floating labels, inscriptions, or anchored chips over full cards.
- The chamber should use negative space as ceremony, not fill every region with framed content.

## Motion Grammar

## Motion Thesis

The chamber should feel like matter gathering, stabilizing, and discharging.

It should not feel like tabs switching, cards fading, and modals closing.

## Motion States

### 1. Threshold entry

Trigger:

- `New hunt`
- `Configure spirit`

Behavior:

- background field dims
- dock spirit seed pulls toward center
- chamber aperture opens from the hunt source, not from screen center
- the stage appears first
- support controls phase in second

Timing:

- aperture open: `220ms`
- field settle: `320ms`
- support fade/slide: `160ms`, delayed `90ms`

### 2. Idle chamber

Behavior:

- vessel breathes subtly
- field grains drift slowly
- one or two faint interpretive traces orbit

Rules:

- no constant dramatic shimmer
- the chamber must feel alive even when the operator pauses

### 3. Mode shift

Behavior by mode:

- `Quick`: vessel stabilizes, minimal disturbance
- `Thesis`: inscription line threads into the field and bends the contour
- `Anchors`: selected artifacts tether into the vessel with visible pull lines
- `Manual`: neighboring spirit echoes appear as alternate presences, not pills

Timing:

- mode focus shift: `140ms`
- stage reaction: `260ms`
- interpretation update: `120ms`

### 4. Suggestion emergence

Behavior:

- suggestion chips or alternate spirits emerge from the field edge nearest the active mode
- rationale line sharpens only after the visual suggestion is legible

Rule:

- visual suggestion first, explanation second

### 5. Release

Behavior:

- release button press compresses the vessel briefly
- spirit contour brightens and tightens
- a tether line or particulate stream exits toward the destination surfaces
- dock, sidebar, and 3D target acknowledge receipt
- the chamber recedes only after transfer is visible

Timing:

- compress: `90ms`
- discharge: `260ms`
- destination acknowledgement: `180ms`
- chamber dissolve: `220ms`, after discharge completes

### 6. Post-release afterimage

Behavior:

- a faint residual ring remains for one beat in the chamber origin
- destination surfaces show a short receive pulse

Rule:

- do not hard-cut from `Release Spirit` to a static sidebar card

## Motion Rules

- Motion should always originate from the spirit body or the hunt source surface.
- Never animate every region equally; center first, supports second.
- Hover motion stays local. Release motion crosses surfaces.
- Use depth, tethering, and focus shifts more than simple opacity fades.

## Copy Cuts

## Copy Thesis

The current copy explains the machinery too literally.

The chamber needs less taxonomy and more charged clarity.

Copy should sound:

- deliberate
- investigative
- alive

It should not sound:

- like admin labels
- like UX placeholder language
- like a dashboard tutorial

## Vocabulary Rules

- Prefer verbs, readings, and consequences.
- Cut repeated nouns like `posture`, `destination`, `current`, `predicted`, `sidebar wake`.
- Let one reason line do the interpretive work.
- Use microcopy to support the image, not compete with it.

## Current To Target Copy Map

| Current | Replace With |
| --- | --- |
| `Configure Spirit` | `Spirit Chamber` |
| `Current posture` | `Current read` |
| `Predicted surfaces` | `Pulls toward` |
| `Try alternate spirits` | `Other readings` |
| `Field strength` | `Intensity` |
| `Sidebar wake` | `Wake` |
| `Release destination` | remove; implied by release line |
| `Keep current spirit` | `Keep seed` or `Stay with current read` |
| `Dismiss` | `Leave chamber` |

## Copy Shape By Region

### Threshold band

Use:

- `First release`
- `Retuning`
- `Enter the chamber and shape the hunt's pull`

Avoid:

- multi-sentence intros
- implementation language like `bind payload` or `local field`

### Manifestation stage

Use short anchored lines:

- `Loom`
- `Attuned`
- `Following relational pressure`

Avoid:

- full paragraph cards floating over the stage

### Interpretation rail

Use:

- one reason line
- one consequence line
- one alternate line

Example:

- `Suggested because this hunt is synthesis-heavy and relationship-led.`
- `Pulls toward Scopes, History, and Entities.`
- `Ledger is the stricter read.`

### Release action

Use:

- `Release Spirit`
- `Release Loom into Hunt 4`

Avoid:

- generic submit wording
- duplicate explanation next to the button

## Composition Plan

## North Star

The chamber should feel like a hybrid of:

- observatory
- darkroom
- instrument deck
- manifestation theater

It should not feel like:

- settings
- inspector
- wizard
- modal dashboard

## Visual Layers

### Layer 1. Field

Deep blue-black with subtle tonal drift and sparse grains.

Purpose:

- creates depth
- holds the scene together
- gives the vessel somewhere to live

### Layer 2. Vessel

The spirit body.

It should be:

- large
- luminous
- slightly imperfect
- contour-driven rather than icon-driven

The spirit should look partially discovered, not fully rendered.

### Layer 3. Inputs as traces

Each mode should write into the field differently:

- `Quick`: pressure rings and calm contour tighten
- `Thesis`: inscription arcs or language threads
- `Anchors`: tether lines from artifact tokens
- `Manual`: neighboring echoes, comparative silhouettes

### Layer 4. Chamber instruments

Controls should feel embedded:

- arc toggles
- orbit handles
- discreet switches
- anchored chips

The eye should read them as part of the chamber, not as sidecar UI.

### Layer 5. Release seam

The chamber must include a visible seam where the spirit exits into the hunt world.

That seam can aim toward:

- the hunt dock
- the smart bucket
- the active 3D scene

Without this seam, release has no drama.

## Surface-Specific Composition Notes

### First release

- more darkness
- more empty field
- clearer sense of something not yet stabilized
- stronger threshold copy

### Retuning

- chamber opens already carrying the current spirit residue
- alternates appear more quickly
- the vessel starts closer to stable form

### Manual spirit mode

- use comparison ghosts around the main vessel
- never present alternates as plain pills alone

### Anchor mode

- selected artifacts should visibly hang around the stage and pull the form off-center

## Accessibility And Restraint Rules

- All instruments remain real buttons, sliders, switches, and text inputs.
- Atmosphere stays click-through.
- Motion must degrade gracefully under reduced-motion preferences.
- The chamber must remain readable at laptop sizes without collapsing back into a card grid.

## Implementation Direction

## Replace

- `SpiritCreationChamber.tsx` overall composition
- current card-heavy right rail
- current left stacked mode menu
- current static manifestation layout

## Keep But Recast

- shared draft state under `spirit-ritual/state/**`
- spirit inference and preview model
- release plumbing and reducer contract
- existing dock/sidebar/3D spirit runtime

## New Implementation Slices

### `SCR-01` Stage-first chamber shell

- make the stage visually dominant
- reduce support regions to threshold band + interpretation rail

### `SCR-02` Embedded ritual instruments

- replace left stack with arc/ring-attached mode controls
- move active control affordances into the stage perimeter

### `SCR-03` Manifestation language per mode

- thesis inscription overlays
- anchor tether overlays
- alternate spirit ghost forms

### `SCR-04` Release seam choreography

- visible transit from chamber to hunt surfaces
- destination acknowledgement in dock/sidebar/3D

### `SCR-05` Copy rewrite

- cut panel-language taxonomy
- rewrite chamber into short, charged, operational language

## Acceptance Criteria

The redesign is ready when:

1. the chamber no longer reads as a settings modal in static screenshots
2. the manifestation stage is the unquestioned focal point
3. mode changes visibly reshape the stage
4. release visibly transfers the spirit into the hunt world
5. the amount of framed card chrome is materially reduced
6. the post-release state feels like a consequence, not a collapse back into admin UI

## Reading Order

- [Spirit Ritual Rewrite](./README.md)
- [Spirit Ritual Roadmap](./roadmap.md)
- [Baia Concept Harvest](../baia-concept-harvest.md)
- [Hunt Spirit Creation Flow](../hunt-spirit-creation-flow.md)
