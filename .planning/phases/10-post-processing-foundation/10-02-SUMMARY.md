---
phase: 10-post-processing-foundation
plan: "02"
subsystem: observatory-postfx
tags: [bloom, dof, autofocus, emissive, three, r3f, postprocessing]
dependency_graph:
  requires: [10-01]
  provides: [emissive-bloom-targets, autofocus-dof-interaction]
  affects: [ObservatoryPostFX, ObservatoryWorldCanvas]
tech_stack:
  added: []
  patterns:
    - "toneMapped={false} + emissiveIntensity > 1 for bloom-eligible materials"
    - "EffectComposer children built as JSX.Element[] array (avoids null type error)"
    - "Autofocus conditionally pushed into effects array when activeHeroPropPosition non-null"
    - "useMemo resolves hero prop world position from world.heroProps + activeHeroInteraction.assetId"
key_files:
  created: []
  modified:
    - apps/workbench/src/features/observatory/components/ObservatoryWorldCanvas.tsx
    - apps/workbench/src/features/observatory/components/ObservatoryPostFX.tsx
decisions:
  - "EffectComposer children typed as JSX.Element | JSX.Element[] (no null): built effects as JSX.Element[] array with conditional push instead of JSX conditional expression returning null"
  - "Autofocus uses focalLength=0.02, bokehScale=3, smoothTime=0.35, mouse=false — unmounted when inactive to save GPU"
  - "Hero prop cylinder active emissiveIntensity boosted from 0.22 to 1.8 (active state) for visible bloom on interaction"
metrics:
  duration_minutes: 6
  completed_date: "2026-03-19"
  tasks_completed: 2
  tasks_total: 2
  files_modified: 2
---

# Phase 10 Plan 02: Emissive Bloom Targets + Autofocus DOF Summary

Upgraded four materials in ObservatoryWorldCanvas.tsx to emit above the bloom luminance threshold, and wired Autofocus DOF to the hero prop interaction state already tracked in the canvas component.

## Tasks Completed

| # | Task | Commit | Files |
|---|------|--------|-------|
| 1 | Upgrade emissive materials for bloom targeting | 161c796d3 | ObservatoryWorldCanvas.tsx |
| 2 | Autofocus DOF wired to hero prop interaction state | 56ac5f073 | ObservatoryPostFX.tsx, ObservatoryWorldCanvas.tsx |

## Material Changes (Task 1)

All four materials now carry `toneMapped={false}` — required so Three.js does not clamp the HDR emissive value before the bloom luminance pass reads it.

**Spirit shell — ThesisCore icosahedron (~line 3859):**
- `emissiveIntensity`: `0.48` → `2.2`
- Added: `toneMapped={false}`
- Effect: shell blooms with golden halo around the core at all times

**Torus — ThesisCore ring (~line 3848):**
- `emissiveIntensity`: `core.torusEmissiveIntensity` (0.3–0.8 range) → `Math.max(1.8, core.torusEmissiveIntensity * 2.5)`
- Added: `toneMapped={false}`
- Effect: always blooms (floor 1.8), preserves recipe-driven intensity variation (max ~2.0)

**Eruption convoy pods — ObservatoryTransitConvoyMesh (~line 1980):**
- `emissiveIntensity`: `0.48 + route.intensity * 0.42` (max 0.90) → `1.2 + route.intensity * 1.8` (max 3.0)
- Added: `toneMapped={false}`
- Effect: pods always bloom (floor 1.2), peak eruption at intensity=1 reaches 3.0 for dramatic glow

**Hero prop cylinder platform — ObservatoryHeroProp (~line 565):**
- `emissiveIntensity` active value: `0.22` → `1.8`; missionTarget: `0.14` → `0.5`; interactable: `0.1` → `0.3`
- Added: `toneMapped={false}`
- Effect: active hero props bloom visibly to draw player attention during interaction

## Autofocus DOF Integration (Task 2)

**ObservatoryPostFX.tsx:**

The `EffectComposer` component has strict children typing (`JSX.Element | JSX.Element[]`) — it does not accept `null`. Using a JSX conditional expression `{condition ? <X /> : null}` causes a TypeScript error. The fix: build the effects list as a `JSX.Element[]` array and conditionally push `<Autofocus>` using an `if` block.

Effect order preserved:
1. `<Bloom>` — always on
2. `<Autofocus>` — conditionally pushed when `activeHeroPropPosition` is non-null
3. (Plan 03 placeholder: LUT)
4. `<Vignette>` — always on
5. `<ToneMapping mode={ACES_FILMIC}>` — always on
6. `<SMAA>` — always on

Autofocus props: `target={activeHeroPropPosition}`, `smoothTime={0.35}`, `mouse={false}`, `focalLength={0.02}`, `bokehScale={3}`

**ObservatoryWorldCanvas.tsx:**

Added `activeHeroPropPosition` memo after `operatorDroneProp` (~line 4416):

```tsx
const activeHeroPropPosition = useMemo((): [number, number, number] | null => {
  if (!activeHeroInteraction) return null;
  const prop = world.heroProps.find((p) => p.assetId === activeHeroInteraction.assetId);
  return prop?.position ?? null;
}, [activeHeroInteraction, world.heroProps]);
```

Updated `<ObservatoryPostFX />` to `<ObservatoryPostFX activeHeroPropPosition={activeHeroPropPosition} />` (~line 4824).

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 1 - Bug] EffectComposer strict children type rejects null**
- **Found during:** Task 2
- **Issue:** `EffectComposer` children typed as `JSX.Element | JSX.Element[]` — returning `null` from a JSX conditional expression causes TS error `Type 'null' is not assignable to type 'Element'`. Same issue with JSX comment blocks near effect elements.
- **Fix:** Replaced JSX tree with imperative `effects: JSX.Element[]` array. Autofocus conditionally pushed with `if (activeHeroPropPosition) { effects.push(<Autofocus .../>) }`. Array passed as `{effects}` child.
- **Files modified:** ObservatoryPostFX.tsx
- **Commit:** 56ac5f073

## Pre-existing Out-of-Scope Issues

`apps/workbench/src/components/desktop/sidebar-icons.tsx` has 5 pre-existing TS2783 errors (duplicate SVG props). These were present before this plan and are unrelated to post-processing work. Logged to `deferred-items.md` (or will be addressed in a future cleanup plan).

## TypeScript Status

Clean (no new errors introduced). Pre-existing `sidebar-icons.tsx` errors unchanged.

## Self-Check: PASSED

- [x] `ObservatoryWorldCanvas.tsx` has 4 instances of `toneMapped={false}`
- [x] `ObservatoryPostFX.tsx` imports and conditionally renders `Autofocus`
- [x] `ObservatoryWorldCanvas.tsx` has `activeHeroPropPosition` useMemo and prop pass
- [x] Commits 161c796d3 and 56ac5f073 exist in git log
- [x] TypeScript compiles clean (no new errors)
