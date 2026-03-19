---
phase: 12-particle-effects
plan: "01"
subsystem: ui
tags: [r3f, three.js, particles, wawa-vfx, observatory, vfx]

requires:
  - phase: 10-post-processing-foundation
    provides: ObservatoryWorldCanvas with R3F Canvas and EffectComposer
  - phase: 11-camera-cinematics-shake
    provides: Observatory scene infrastructure

provides:
  - wawa-vfx@1.2.10 installed as production dependency
  - leva@0.10.1 installed as devDependency (wawa-vfx debug panel)
  - ObservatoryVFXPools component with landing-dust (200, Billboard) and thruster-exhaust (300, StretchBillboard) pool declarations

affects:
  - 12-02-PLAN.md (landing dust emitter — uses landing-dust pool)
  - 12-03-PLAN.md (thruster exhaust emitter — uses thruster-exhaust pool)
  - 12-04-PLAN.md (mounts ObservatoryVFXPools inside ObservatoryWorldCanvas)

tech-stack:
  added:
    - wawa-vfx@1.2.10 (R3F particle system, pool-based InstancedMesh)
    - leva@0.10.1 (devDep, wawa-vfx optional debug controls)
  patterns:
    - VFXParticles pool declarations separate from emitter placement
    - RenderMode enum import required (not string literals) for TypeScript safety
    - VFXParticlesSettings is pool-level only; per-particle settings go on VFXEmitter

key-files:
  created:
    - apps/workbench/src/features/observatory/vfx/ObservatoryVFXPools.tsx
  modified:
    - apps/workbench/package.json (added wawa-vfx + leva)
    - bun.lockb

key-decisions:
  - "wawa-vfx VFXParticlesSettings does not accept startLifeTime/startSize/startColor — these are VFXEmitterSettings fields set at emit time"
  - "RenderMode enum must be imported and used for TypeScript; string literals rejected by tsc"
  - "landing-dust: 200 particles, RenderMode.Billboard, gravity [0,-4,0], fadeAlpha [0.0,0.1]"
  - "thruster-exhaust: 300 particles, RenderMode.StretchBillboard, gravity [0,1.5,0], fadeAlpha [0.0,0.15]"

patterns-established:
  - "VFXParticles pool component lives in features/observatory/vfx/ — separate from emitters"
  - "Import RenderMode enum from wawa-vfx directly (re-exported from wawa-vfx-vanilla)"

requirements-completed: [PFX-01, PFX-05]

duration: 4min
completed: "2026-03-19"
---

# Phase 12 Plan 01: Install wawa-vfx and Create ObservatoryVFXPools Summary

**wawa-vfx@1.2.10 installed and ObservatoryVFXPools component created with landing-dust (200 particles, Billboard) and thruster-exhaust (300 particles, StretchBillboard) pool declarations**

## Performance

- **Duration:** 4 min
- **Started:** 2026-03-19T18:27:59Z
- **Completed:** 2026-03-19T18:32:00Z
- **Tasks:** 3
- **Files modified:** 3 (package.json, bun.lockb, ObservatoryVFXPools.tsx)

## Accomplishments

- Installed wawa-vfx@1.2.10 (production dep) and leva@0.10.1 (devDep) via bun
- Created `ObservatoryVFXPools` component at `apps/workbench/src/features/observatory/vfx/`
- Verified TypeScript compiles cleanly for the new file (zero errors in ObservatoryVFXPools.tsx)

## Task Commits

Each task was committed atomically:

1. **Task 1: Install wawa-vfx and leva devdependency** - `502f36af9` (chore)
2. **Task 2: Create ObservatoryVFXPools component** - `e3626fb5e` (feat)
3. **Task 3: TypeScript compile check + RenderMode fix** - `1488d3e5d` (fix)

## Files Created/Modified

- `apps/workbench/src/features/observatory/vfx/ObservatoryVFXPools.tsx` — New file; declares landing-dust and thruster-exhaust VFXParticles pools
- `apps/workbench/package.json` — wawa-vfx added to dependencies, leva to devDependencies
- `bun.lockb` — Updated lockfile

## Decisions Made

- **VFXParticlesSettings scope:** After inspecting `wawa-vfx-vanilla/dist/index.d.ts`, confirmed that `VFXParticlesSettings` only accepts pool-level fields (`nbParticles`, `renderMode`, `gravity`, `fadeAlpha`, `blendingMode`, etc.). The plan's proposed `startLifeTime`, `startSize`, `startColor`, `startOpacity`, `endOpacity` are `VFXEmitterSettings` fields — they belong on the `VFXEmitter` component in Plans 02/03.
- **RenderMode enum:** TypeScript rejects string literals `"billboard"` and `"stretchBillboard"` for the `renderMode` field. Must import and use `RenderMode.Billboard` / `RenderMode.StretchBillboard` enum values.
- **No THREE.Color import needed:** Color constants from the plan were removed since `VFXParticlesSettings` has no `startColor` field — colors are emitter-time settings.

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 1 - Bug] Removed invalid VFXParticlesSettings fields; replaced with actual API**
- **Found during:** Task 2 (Create ObservatoryVFXPools component)
- **Issue:** Plan specified `startLifeTime`, `startSize`, `startColor`, `startOpacity`, `endOpacity` on `VFXParticles settings`. These fields do not exist in `VFXParticlesSettings` — they belong to `VFXEmitterSettings`.
- **Fix:** Removed color constants and invalid fields. Used only fields present in the actual type: `nbParticles`, `renderMode`, `gravity`, `fadeAlpha`.
- **Files modified:** `ObservatoryVFXPools.tsx`
- **Verification:** TypeScript reports 0 errors for this file
- **Committed in:** `e3626fb5e` (Task 2 commit)

**2. [Rule 1 - Bug] Imported RenderMode enum to fix TypeScript type mismatch**
- **Found during:** Task 3 (TypeScript compile check)
- **Issue:** String literals `"billboard"` and `"stretchBillboard"` are not assignable to `RenderMode | undefined`
- **Fix:** Added `RenderMode` to the import, used `RenderMode.Billboard` and `RenderMode.StretchBillboard`
- **Files modified:** `ObservatoryVFXPools.tsx`
- **Verification:** TypeScript reports 0 errors for ObservatoryVFXPools.tsx
- **Committed in:** `1488d3e5d` (Task 3 fix commit)

---

**Total deviations:** 2 auto-fixed (2x Rule 1 — API mismatch between plan spec and actual wawa-vfx types)
**Impact on plan:** Both fixes necessary for correctness. Core intent preserved: same pool names, particle counts, renderModes, gravity vectors.

## Issues Encountered

- Pre-existing TypeScript errors in `sidebar-icons.tsx` (duplicate SVG props, TS2783) exist before Phase 12 — deferred to `.planning/phases/12-particle-effects/deferred-items.md`. Not caused by this plan.

## User Setup Required

None — no external service configuration required.

## Next Phase Readiness

- `ObservatoryVFXPools` is ready to be mounted in ObservatoryWorldCanvas (Plan 04's job)
- Plans 02 and 03 can proceed: they reference `"landing-dust"` and `"thruster-exhaust"` by name via `useVFX().emit()`
- Per-particle settings (`colorStart`, `colorEnd`, `particlesLifetime`, `size`, `speed`) go on `VFXEmitter` settings in Plans 02/03, not on the pools

---
*Phase: 12-particle-effects*
*Completed: 2026-03-19*
