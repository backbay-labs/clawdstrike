---
phase: 10-post-processing-foundation
plan: "03"
subsystem: observatory-postfx
tags: [postprocessing, lut, color-grading, spirit-kind, three-data3dtexture]
dependency_graph:
  requires: [10-01, 10-02]
  provides: [spirit-kind-lut-grading]
  affects: [ObservatoryPostFX, ObservatoryWorldCanvas]
tech_stack:
  added: []
  patterns:
    - "Programmatic 3D LUT via THREE.Data3DTexture (17×17×17 RGBA)"
    - "useMemo keyed on spirit.kind for LUT lifecycle management"
    - "Module-scope reverse-map constant for observatory→spirit kind translation"
key_files:
  created:
    - apps/workbench/src/features/observatory/utils/buildSpiritLut.ts
  modified:
    - apps/workbench/src/features/observatory/components/ObservatoryPostFX.tsx
    - apps/workbench/src/features/observatory/components/ObservatoryWorldCanvas.tsx
decisions:
  - "Programmatic LUT (not .cube files): 17^3*4 = 19,652 bytes; CPU-generated, no file I/O"
  - "THREE.Data3DTexture over 2D-encoded DataTexture: native 3D LUT support in three 0.170"
  - "OBSERVATORY_KIND_TO_SPIRIT_KIND at module scope: avoids recreation per render"
  - "Placed before Vignette: LUT grades scene, then vignette darkens edges on top"
  - "tetrahedralInterpolation=true: higher quality at negligible cost"
  - "spirit.kind='loom' maps to undefined → null LUT (identity pass-through)"
metrics:
  duration: "~10 minutes"
  completed: "2026-03-19"
  tasks_completed: 2
  files_changed: 3
---

# Phase 10 Plan 03: Spirit LUT Color Grading Summary

**One-liner:** Programmatic 3D LUT color grading per spirit kind via THREE.Data3DTexture — sentinel=cool teal, oracle=warm violet, witness=warm gold, specter=deep red shadow crush.

## What Was Built

### buildSpiritLut.ts (new utility)

`apps/workbench/src/features/observatory/utils/buildSpiritLut.ts`

Generates a `THREE.Data3DTexture` (17×17×17×RGBA = 19,652 bytes) encoding a full color-transform LUT for each of the 4 spirit kinds. The texture is uploaded to GPU once and reused across frames via `useMemo`.

**Color transform approach:** Linear matrix + offset transforms per spirit kind. Each entry maps input RGB → output RGB through a cross-channel color matrix, producing visible color palette shifts across the entire scene.

**Per-kind transforms:**

| Kind | Observable Effect | Technique |
|------|------------------|-----------|
| sentinel | Cool teal — blues boosted, reds pulled back | R channel: 0.72 multiplier; B channel: 1.08x + 0.14 green spill |
| oracle | Warm violet — reds+blues lifted, greens suppressed | R+B: +0.04 lift offset; G: 0.76x reduction |
| witness | Warm gold / amber — reds+greens boosted, blues compressed | B: 0.72x; 0.03 shadow lift on R+G |
| specter | Deep red + shadow crush — luma-based contrast crush, red dominant | `Math.pow(luma, 1.4)` crushFactor; G+B channels desaturated to 0.68/0.58 |

### ObservatoryPostFX.tsx (updated)

- Added `LUT` to imports from `@react-three/postprocessing`
- Updated `spiritLut` prop type: `THREE.Texture | null` → `THREE.Data3DTexture | null`
- Inserted `<LUT key="lut" lut={spiritLut} tetrahedralInterpolation />` conditionally between DOF and Vignette in the imperative effect array

### ObservatoryWorldCanvas.tsx (updated)

- Added `buildSpiritLut` import and `SpiritKind` type import
- Added `OBSERVATORY_KIND_TO_SPIRIT_KIND` reverse-map at module scope
- Added `spiritLut = useMemo(() => ..., [spirit?.kind])` hook after `activeHeroPropPosition` memo
- Updated `<ObservatoryPostFX>` to pass `spiritLut={spiritLut}`

## Spirit.kind → SpiritKind Reverse-Map

The `ObservatorySpiritVisual.kind` uses observatory-specific names distinct from `SpiritKind`. The mapping used:

```typescript
const OBSERVATORY_KIND_TO_SPIRIT_KIND: Record<string, SpiritKind> = {
  tracker: "sentinel",  // tracker → cool teal LUT
  lantern: "oracle",    // lantern → warm violet LUT
  ledger:  "witness",   // ledger  → warm gold LUT
  forge:   "specter",   // forge   → deep red shadow crush LUT
};
```

`"loom"` is a valid `ObservatorySpiritVisual.kind` but not in `SpiritKind` — returns `undefined`, spiritLut stays `null`, no LUT applied (identity pass-through).

This matches the mapping confirmed in `ObservatoryTab.tsx` `SPIRIT_KIND_MAP`.

## TypeScript Notes

- `THREE.Data3DTexture` extends `THREE.Texture` — assignment to the updated `spiritLut?: THREE.Data3DTexture | null` prop is type-safe
- `@react-three/postprocessing` `LUT` component accepts `THREE.Texture` (base class) — `Data3DTexture` satisfies this
- Pre-existing unrelated TypeScript error in `sidebar-icons.tsx` (TS2783 duplicate props) not touched per scope boundary rules
- No errors in any changed files after TypeScript check

## Deviations from Plan

### Auto-applied adjustment: imperative array pattern preserved

The plan showed JSX ternary syntax for conditional LUT rendering. The existing `ObservatoryPostFX` uses an imperative `JSX.Element[]` array (established in Plan 02 to avoid `null` in `EffectComposer.children`). The LUT was inserted using the same `if (spiritLut) { effects.push(...) }` pattern — functionally identical, consistent with existing code structure.

No other deviations. Plan executed exactly as specified.

## Deferred Items

- Hand-crafted `.cube` files (future milestone): the programmatic LUT gives visible color shifts immediately. Fine-tuned aesthetic `.cube` files are noted in STATE.md blockers.
- `"loom"` spirit visual kind has no SpiritKind equivalent — if a fifth spirit kind is added in the future, the reverse-map needs updating.

## Self-Check: PASSED

| Item | Status |
|------|--------|
| buildSpiritLut.ts created | FOUND |
| ObservatoryPostFX.tsx modified | FOUND |
| ObservatoryWorldCanvas.tsx modified | FOUND |
| Commit a6293c9e7 (Task 1) | FOUND |
| Commit a299608c5 (Task 2) | FOUND |
