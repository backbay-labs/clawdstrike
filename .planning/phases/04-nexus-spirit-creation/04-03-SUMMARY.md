---
phase: 04-nexus-spirit-creation
plan: "03"
subsystem: spirit-ritual
tags: [spirit, canvas, atmosphere, creation-chamber, css-animation, port]
dependency_graph:
  requires:
    - "04-01: nexus types + store"
    - "02-01: spirit store + types"
  provides:
    - spirit-ritual/canvas/model.ts (buildSpiritManifestationModel)
    - SpiritManifestationCanvas (pure CSS/SVG)
    - SpiritAtmosphereLayer (pure CSS particles)
    - SpiritChamberTab (full creation chamber)
  affects:
    - /spirit-chamber route (immersive creation chamber replaces Phase 2 form)
tech_stack:
  added: []
  patterns:
    - port-with-inline-stubs (huntronomer dependencies replaced with inline types + stubs)
    - synthetic-context (SpiritBindContext built at call site, no huntronomer Hunt/Artifact imports)
    - tdd-red-green (RED commit then GREEN commit)
key_files:
  created:
    - apps/workbench/src/features/spirit/components/spirit-ritual/canvas/model.ts
    - apps/workbench/src/features/spirit/components/spirit-ritual/canvas/SpiritManifestationCanvas.tsx
    - apps/workbench/src/features/spirit/components/spirit-ritual/atmosphere/SpiritAtmosphereLayer.tsx
  modified:
    - apps/workbench/src/features/spirit/components/spirit-chamber-tab.tsx
    - apps/workbench/src/features/spirit/__tests__/spirit-chamber-tab.test.tsx
decisions:
  - "HuntSpiritKind/RuntimeState/Meta inlined into model.ts rather than importing from huntronomer"
  - "createHuntSpiritState + deriveHuntSpiritRuntimeState stubbed inline; motion envelope derived from fieldStrength with stable defaults"
  - "SpiritBindContext/Candidate defined as workbench-local synthetic types — no Hunt/Artifact imports from huntronomer"
  - "SPIRIT_KIND_TO_HUNT_KIND: sentinel=tracker, oracle=lantern, witness=ledger, specter=forge (established in 03-01)"
  - "SPIRIT_ACCENT_MAP duplicated locally in spirit-chamber-tab.tsx to avoid import coupling with spirit-store internals"
metrics:
  duration: "~11 min"
  completed_date: "2026-03-18"
  tasks_completed: 2
  files_created: 3
  files_modified: 2
---

# Phase 04 Plan 03: Spirit Creation Chamber Summary

Pure CSS/SVG spirit creation chamber ported from huntronomer — SpiritManifestationCanvas + SpiritAtmosphereLayer + buildSpiritManifestationModel with inline stubs replacing huntronomer spirit/ imports — replacing Phase 2 SpiritChamberTab plain form at /spirit-chamber.

## Objective

Port the spirit creation chamber from huntronomer: manifestation canvas (vessel rings, tethers, ghost forms, inscription traces), atmosphere layer (particle grains, sweep rings, ambient glow), and model builder with synthetic context. Replace Phase 2 SpiritChamberTab form.

## Tasks Completed

| Task | Name | Commit | Files |
|------|------|--------|-------|
| 1 | Port spirit-ritual canvas model + SpiritManifestationCanvas + SpiritAtmosphereLayer | 7d6b4e385 | canvas/model.ts, SpiritManifestationCanvas.tsx, SpiritAtmosphereLayer.tsx |
| TDD-RED | Add failing tests for creation chamber | 0b33078a8 | spirit-chamber-tab.test.tsx |
| 2 | Replace SpiritChamberTab with full creation chamber | 5ef26bc14 | spirit-chamber-tab.tsx |

## What Was Built

### canvas/model.ts
- `buildSpiritManifestationModel(context, candidate)` — ported verbatim from huntronomer, 1000+ lines
- Inline types: `HuntSpiritKind`, `HuntSpiritStance`, `HuntSpiritMood`, `HuntSpiritRuntimeState`, `HuntSpiritMotionEnvelope`
- Inline meta table: `HUNT_SPIRIT_META` for tracker/lantern/ledger/forge/loom (accentColor, label, contour, defaultBiases)
- Inline stubs: `createHuntSpiritState`, `deriveHuntSpiritRuntimeState` — produce stable motion envelopes from confidenceScore
- Local `SpiritBindContext` / `SpiritBindCandidate` types — no huntronomer Hunt/Artifact imports
- All 5 kind stage grammars, trace/tether/ghost layout tables verbatim

### SpiritManifestationCanvas.tsx
- Pure CSS/SVG — vessel rings, beam, halo, floor glow, contour SVG, ghost forms, tether SVG paths, inscription traces
- Zero R3F imports verified
- `data-testid="spirit-manifestation-canvas"` for test identification

### SpiritAtmosphereLayer.tsx
- Pure CSS particle grain float + sweep ring atmosphere
- Zero R3F imports verified
- `data-testid="spirit-atmosphere-layer"` for test identification

### SpiritChamberTab (full replacement)
- `SpiritAtmosphereLayer` at `absolute inset-0 z-[2]`
- `SpiritManifestationCanvas` at `absolute inset-0 z-[3]` centered
- Controls overlay at `absolute inset-x-0 bottom-8 z-[10]`
- 4 kind pill buttons (sentinel/oracle/witness/specter) with accent color border on selected
- Bind button (when no spirit bound) / Unbind button (when spirit is bound)
- No HTML `<select>` / combobox — completely removed

## Test Results

- 5 new tests written and passing: renders canvas, renders atmosphere, bind calls bindSpirit, unbind calls unbindSpirit, kind pill updates canvas model
- Pre-existing test failures (nexus-tab, App.test, desktop-layout): 18 tests — unchanged before/after this plan, not caused by these changes
- TypeScript: zero errors in spirit-ritual/ and spirit-chamber-tab.tsx

## Deviations from Plan

None — plan executed exactly as written.

## Self-Check: PASSED
