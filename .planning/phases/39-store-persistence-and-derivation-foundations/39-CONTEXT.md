# Phase 39: Store, Persistence, and Derivation Foundations - Context

**Gathered:** 2026-03-22
**Status:** Ready for planning

<domain>
## Phase Boundary

Pure TypeScript infrastructure phase — lock data contracts, store slices, persistence schema v2, derivation utilities, and invalidation controller extensions for all 5 v10.0 visual systems (heatmap, delta cards, constellations, spirit trails, annotations, interiors). No R3F components.

</domain>

<decisions>
## Implementation Decisions

### Claude's Discretion
All implementation choices are at Claude's discretion — pure infrastructure phase.

</decisions>

<code_context>
## Existing Code Insights

### Reusable Assets
- `observatory-replay-persistence.ts` — existing localStorage save/load for replay bookmarks and annotations
- `ObservatoryInvalidationController.tsx` — existing sourceKey computation for demand-based frame invalidation
- `observatory-store.ts` — Zustand store with 24+ actions, replay slice already has annotations array
- `types.ts` — observatory types barrel export
- `deriveObservatoryWorld.ts` — established pattern for pure derivation functions
- `buildSpiritLut.ts` — existing spirit color lookup utility

### Established Patterns
- Zustand + createSelectors for all stores
- Pure derivation functions (no side effects) returning typed recipe objects
- localStorage persistence with versioned schemas
- sourceKey string concatenation for invalidation detection

### Integration Points
- `ObservatoryTab.tsx` — orchestrator that calls derivation functions and threads props to canvas
- `ObservatoryWorldCanvas.tsx` → `ObservatoryWorldScene.tsx` — prop threading chain
- `spirit-evolution-store.ts` — source of spirit level for resonance trail gating

</code_context>

<specifics>
## Specific Ideas

No specific requirements — infrastructure phase.

</specifics>

<deferred>
## Deferred Ideas

None — discussion stayed within phase scope.

</deferred>
