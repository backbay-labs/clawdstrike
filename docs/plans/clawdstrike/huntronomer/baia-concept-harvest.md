# Baia Concept Harvest

> **Status:** Proposed | **Date:** 2026-03-08
> **Audience:** Product, design, desktop, anticipation, and 3D-scene implementers
> **Scope:** Distill the Baia app into concrete decisions for Huntronomer hunt spirits and adaptive workspace behavior

## Why This Exists

Baia contains a lot of genuinely strong product ideas, but they should not be imported wholesale.

Huntronomer needs a tighter translation layer:

1. what to steal directly
2. what to translate into Huntronomer's operational language
3. what not to import at all

This doc is that filter.

## Source Sweep

This harvest is based on a full read of `origin/platform/client/web/src/components/apps/Baia/**`, including:

- creation flow and generator state
- suggestions and controls
- draw and upload subsystems
- atmosphere and embodiment
- memory/progression surfaces
- tests and interaction styles

Key files:

- `origin/platform/client/web/src/components/apps/Baia/Baia.tsx`
- `origin/platform/client/web/src/components/apps/Baia/useSigilGenerator.ts`
- `origin/platform/client/web/src/components/apps/Baia/useGrimoire.ts`
- `origin/platform/client/web/src/components/apps/Baia/SigilCanvas.tsx`
- `origin/platform/client/web/src/components/apps/Baia/SigilCube/SigilCube.tsx`
- `origin/platform/client/web/src/components/apps/Baia/SigilCube/SigilCubeWidget.tsx`
- `origin/platform/client/web/src/components/apps/Baia/BurnAnimation.tsx`
- `origin/platform/client/web/src/components/apps/Baia/DrawCanvas/**`
- `origin/platform/client/web/src/components/apps/Baia/FileUpload/**`
- `origin/platform/client/web/src/components/apps/Baia/controls/**`
- `origin/platform/client/web/src/components/apps/Baia/atmosphere/**`

## Harvest Matrix

| Concept | Steal Directly | Translate for Huntronomer | Do Not Import |
| --- | --- | --- | --- |
| Creation lifecycle | Separate `create` from `activate`. A thing is drafted first, then explicitly released into the world. | `Create hunt -> Bind Spirit -> release into dock/sidebar/3D workspace`. | Do not collapse this into a one-click icon picker or a long wizard. |
| Multimodal input | One shared state model can accept different input modes. | Support `Quick Bind`, `Thesis`, `Anchor Artifacts`, and later a light spatial mode if needed. | Do not copy Baia's exact `generate/draw/hybrid/upload` taxonomy just because it exists. |
| Suggestion behavior | Suggestions should collaborate with the operator, not override them. | Use rationale lines like `Suggested because this hunt is run-heavy and file-led`; let suggestions enrich thesis and anchors. | Do not make spirit inference opaque or fully automatic. |
| Pre-commit preview | Show ghost structure before the action is finalized. | Preview spirit posture in dock, sidebar wake, and 3D before `Bind Spirit`; preview semantic drop meaning before release. | Do not wait until after bind or drop to reveal what the system thought was happening. |
| Selected-state design | Active controls should feel inhabited, not merely checked. | Spirit selectors, lens selectors, and station targets should glow, pulse, and carry presence when active. | Do not settle for plain radio-button behavior dressed up with a single color change. |
| Constraint discipline | Apply snap and guidance selectively, not globally. | Use confidence-gated spring loading, semantic snapping, and proximity wake only when context is strong. | Do not make the whole workspace constantly predictive or sticky. |
| Embodiment | A created object should have a vessel, not just a flat icon. | Hunt spirits need a stable form that survives across dock pill, smart bucket, Nexus, and Forensics. | Do not make spirits floating decals or disconnected glyph stickers. |
| World release | The created thing should visibly enter the world. | `Bind Spirit` should culminate in a short draw-in, pulse, or transit into the active workspace scene. | Do not reduce binding to a toast or silent state write. |
| Object continuity | The same identity should survive across compact, detail, and 3D views. | One hunt spirit grammar should drive dock iconography, sidebar language, and 3D posture. | Do not invent a different spirit representation per surface. |
| Ambient field | Environment can react around the object, not only inside it. | Let confidence, receipts, active run pressure, and station focus modulate nearby rails, lanes, or local fields. | Do not import audio-reactive spectacle or full-screen ambience as the default workspace mode. |
| Input grammar | Keep a consistent gesture grammar underneath different tools or modes. | Reuse one interaction grammar for drag intent, wake peeks, semantic drop roles, and spirit binding previews. | Do not create one-off behaviors for every surface that require relearning basic motion. |
| Thresholded actions | Primary actions can stay dormant until there is enough signal. | Only light up `Bind Spirit`, `Start Hunt from Staging`, or promoted semantic targets when the operator has provided enough context. | Do not surface advanced anticipatory actions at full strength from an empty state. |
| Interpretation of uploads/material | Raw material should be analyzed into usable meaning, not merely attached. | Artifact clusters, receipts, notes, files, and signals can become spirit anchors or sidebar suggestions. | Do not treat uploaded or dragged artifacts as only decorative input to a spirit. |
| Memory model | Record activated objects, not every draft. | Persist bound spirits and major rebinding events as hunt history; drafts can remain ephemeral. | Do not copy Baia's localStorage grimoire or collectible inventory semantics. |
| Progression context | Temporal or phase context can shape the atmosphere around creation. | Use hunt phase, station context, and case maturity as operational context around the spirit, not as fantasy lore. | Do not import epoch mythology, lunar framing, or calendar mysticism. |
| Control polish | Rich controls can still be accessible and keyboard-correct. | Keep spirit and sidebar controls as real radiogroups, buttons, sliders, and toggles with strong focus behavior and roving tab index where needed. | Do not sacrifice keyboard/accessibility because the control looks “magical.” |
| Ambient layers | Decorative layers must never block interaction. | Any spirit wake field, station aura, or atmospheric layer in Huntronomer must stay click-through and low-interference. | Do not let background particles or overlay effects steal pointer ownership. |
| Reselection semantics | Re-clicking the active option can still be meaningful. | Allow reselection to retrigger preview, rehearse bind reasoning, or re-center a spirit on its active station. | Do not assume active means inert. |
| Density modes | The same object can have compact and expanded embodiments. | Spirits should have compressed dock/sidebar forms and richer 3D/detail forms without losing identity. | Do not require the full 3D treatment everywhere. |
| Micro-motion | Small motion cues can carry hierarchy and feedback. | Use restrained lift, settle, pulse, contour sharpening, and tether motion for anticipation and spirit presence. | Do not import collectible-style constant glow, endless shimmer, or overly theatrical spawn behavior. |
| Audio cues | Layered feedback can deepen state transitions. | If used at all, keep sound sparse and operational: bind chime, receipt catch, station transfer cue. | Do not import rarity-driven audio layering or make sound central to understanding the system. |
| Theming | A strong token system can make immersive chrome coherent. | Keep spirit-aware tokens for dock, wake cards, smart buckets, and local scene accents. | Do not inherit Baia's gold-occult theme or purple epoch palette as product identity. |
| Product fantasy | Strong metaphor can unify behavior, visuals, and copy. | Recast the underlying move as investigative posture, proof gravity, station presence, and semantic roles. | Do not import occult language, sigil mysticism, rarity theater, or collectible framing. |

## Strongest Takeaways

### Steal directly

- lifecycle separation between creation and release
- pre-commit preview
- collaborative suggestions
- embodied object continuity across surfaces
- thresholded primary actions
- accessible, tactile controls

### Translate for Huntronomer

- ritual becomes operational ceremony
- sigil intention becomes hunt thesis
- upload/sketch material becomes artifact anchors
- cube/world release becomes spirit bind into dock/sidebar/3D
- epoch context becomes hunt phase and station context

### Do not import

- occult copy
- rarity systems
- collectible-object framing
- audio-reactive spectacle
- decorative ambient excess
- lore-heavy progression semantics

## Product Rule

The rule for Huntronomer should be:

> steal Baia's lifecycle and embodiment logic, translate its interpretation model into investigation semantics, and reject its fantasy-layer assumptions.

If a Baia concept makes the hunt feel:

- more legible
- more alive
- more native to the workspace
- more predictive without being opaque

then it is a good candidate.

If it makes the product feel:

- mystical
- gamified
- collectible
- ornamental first

then it should stay in Baia.

## Reading Order

- [Hunt Spirits Concept](./hunt-spirits-concept.md)
- [Hunt Spirit Creation Flow](./hunt-spirit-creation-flow.md)
- [Hunt Spirits In The 3D Workspace](./hunt-spirits-3d-workspace-concept.md)
