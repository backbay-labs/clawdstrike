---
phase: 12-particle-effects
plan: "04"
subsystem: observatory-vfx
tags: [particles, wawa-vfx, character-vfx, landing-dust, thruster-exhaust, r3f]
dependency_graph:
  requires:
    - plan: "12-01"
      provides: ObservatoryVFXPools component + wawa-vfx installed
    - plan: "12-03"
      provides: ObservatoryWorldCanvas edits (ProbeDischargeVFX, Sparkles)
  provides: [PFX-01, PFX-05]
  affects:
    - apps/workbench/src/features/observatory/vfx/CharacterVFX.tsx (new)
    - apps/workbench/src/features/observatory/components/ObservatoryWorldCanvas.tsx (CharacterVFX mount + ObservatoryVFXPools mount)
tech_stack:
  added: []
  patterns:
    - VFXEmitter forwarded ref with emitAtPos() for imperative burst emission
    - VFXEmitter startEmitting/stopEmitting for continuous thruster toggle
    - Pre-allocated THREE.Vector3 at module scope to avoid GC in useFrame
    - prevGroundedRef pattern for exact one-shot burst on airborne→grounded transition
key_files:
  created:
    - apps/workbench/src/features/observatory/vfx/CharacterVFX.tsx
  modified:
    - apps/workbench/src/features/observatory/components/ObservatoryWorldCanvas.tsx
key-decisions:
  - "wawa-vfx has no useVFX hook — VFXEmitter forwarded ref + emitAtPos() is the correct burst API"
  - "VFXEmitterSettings.speed is [number, number] tuple not [number] — both landing-dust and thruster use [min, max] range"
  - "thruster-exhaust uses startEmitting/stopEmitting to toggle continuous emission; position sync via ref.current.position.copy()"
  - "facingRadians is present in ObservatoryPlayerControllerStateLike — used directly from runtime.state"
  - "5 pre-existing sidebar-icons.tsx TS2783 errors are out of scope (documented in 12-01)"
metrics:
  duration: "283 seconds (~5 min)"
  completed_date: "2026-03-19"
  tasks_completed: 3
  tasks_total: 3
  files_created: 1
  files_modified: 1
---

# Phase 12 Plan 04: CharacterVFX + ObservatoryVFXPools Wiring Summary

CharacterVFX component with VFXEmitter ref-based landing dust burst and continuous thruster exhaust, both wired into ObservatoryWorldCanvas alongside ObservatoryVFXPools.

## What Was Built

### Task 1 — CharacterVFX component (new file)

`apps/workbench/src/features/observatory/vfx/CharacterVFX.tsx`

New component implementing PFX-01 (landing dust) + PFX-05 (thruster exhaust):
- Two `<VFXEmitter>` components rendered (landing-dust, thruster-exhaust), refs captured via `useRef`
- `prevGroundedRef` tracks previous grounded state; emits landing dust burst exactly once on `false → true` transition
- `wasThrustingRef` tracks previous thruster state; calls `startEmitting(true)` on thrust start, `stopEmitting()` on thrust end
- `_backpackWorldPos` and `_groundContactPos` pre-allocated as module-level `THREE.Vector3` — no GC in useFrame
- Backpack world position computed from character pos + avatar offsets (`positionOffset=[0,-0.8,0]`, `scale=1.48`, backpack local `[0,1.16,-0.28]`) → world Y offset +0.917, XZ offset 0.414 behind facing direction

### Task 2 — ObservatoryWorldCanvas wiring

Two import lines added (after ProbeDischargeVFX import at line 80):
```tsx
import { CharacterVFX } from "../vfx/CharacterVFX";
import { ObservatoryVFXPools } from "../vfx/ObservatoryVFXPools";
```

**CharacterVFX mount** inside `ObservatoryPlayerRig` return — third child after `<ObservatoryPlayerAvatar>`:
```tsx
<CharacterVFX
  position={runtime.state.position}
  grounded={runtime.state.grounded}
  sprinting={runtime.state.sprinting}
  activeAction={runtime.state.activeAction}
  facingRadians={runtime.state.facingRadians}
/>
```

**ObservatoryVFXPools mount** after `<ObservatoryPostFX>`, still inside `<Suspense>`:
```tsx
<ObservatoryVFXPools />
```

### Task 3 — TypeScript final verification

Zero errors in plan-modified files. 5 pre-existing `sidebar-icons.tsx` TS2783 errors out of scope.

## Actual API Details

**facingRadians field:** Present in `ObservatoryPlayerControllerStateLike` (confirmed in `moveSet.ts`). Used directly from `runtime.state.facingRadians`.

**wawa-vfx emit API:** `useVFX()` hook does not exist in `wawa-vfx@1.2.10`. The correct imperative API is:
- `VFXEmitter` forwarded ref exposes `emitAtPos(position: THREE.Vector3 | null, reset?: boolean)`
- `startEmitting(reset?: boolean)` and `stopEmitting()` for continuous emitters
- The plan's `emit("landing-dust", { position: [...] })` pattern is from documentation/research but not in the actual library

**VFXEmitterSettings.speed:** Type is `[number, number]` (min/max range tuple), not `[number]`. Used `[1.5, 1.5]` for landing dust and `[2.0, 2.0]` for thruster exhaust.

## Commits

| Task | Hash | Description |
|------|------|-------------|
| Task 1 | 348c51297 | feat(12-04): add CharacterVFX component (landing dust + thruster exhaust) |
| Task 2+3 | 3f4a4fe78 | feat(12-04): mount CharacterVFX and ObservatoryVFXPools in ObservatoryWorldCanvas |

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 1 - Bug] `useVFX` hook does not exist in wawa-vfx — replaced with VFXEmitter ref API**
- **Found during:** Task 1 TypeScript check
- **Issue:** Plan specified `import { useVFX } from "wawa-vfx"` and `const { emit } = useVFX()` — this hook is not exported by `wawa-vfx@1.2.10`. The library exports `VFXParticles`, `VFXEmitter`, `RenderMode`, `vfxStore` only.
- **Fix:** Replaced with `VFXEmitter` component refs and `emitAtPos()` / `startEmitting()` / `stopEmitting()` imperative API. `VFXEmitter` components are mounted in CharacterVFX's return; position is updated via `ref.current.position.copy()` in useFrame.
- **Files modified:** `CharacterVFX.tsx`
- **Commit:** 3f4a4fe78

**2. [Rule 1 - Bug] `VFXEmitterSettings.speed` is `[number, number]` not `[number]`**
- **Found during:** Task 2/3 TypeScript check
- **Issue:** Plan inferred `speed: [1.5]` (single-element tuple). Actual type is `[number, number]` (min/max range).
- **Fix:** Changed to `speed: [1.5, 1.5]` and `speed: [2.0, 2.0]`
- **Files modified:** `CharacterVFX.tsx`
- **Commit:** 3f4a4fe78

## Issues Encountered

- Pre-existing TypeScript TS2783 errors in `sidebar-icons.tsx` (5 errors) — out of scope, documented in 12-01 deferred-items.

## Self-Check: PASSED

- [x] `apps/workbench/src/features/observatory/vfx/CharacterVFX.tsx` — exists
- [x] `apps/workbench/src/features/observatory/vfx/ObservatoryVFXPools.tsx` — exists
- [x] `apps/workbench/src/features/observatory/vfx/ProbeDischargeVFX.tsx` — exists
- [x] CharacterVFX at line 2096 of ObservatoryWorldCanvas.tsx — exists
- [x] ObservatoryVFXPools at line 5099 of ObservatoryWorldCanvas.tsx — exists
- [x] commit 348c51297 — CharacterVFX component
- [x] commit 3f4a4fe78 — ObservatoryWorldCanvas wiring + fixes
- [x] Zero TypeScript errors in plan-modified files

---
*Phase: 12-particle-effects*
*Completed: 2026-03-19*
