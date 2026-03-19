---
phase: 10-post-processing-foundation
plan: "01"
subsystem: ui
tags: [react-three-fiber, postprocessing, three, bloom, vignette, smaa, tone-mapping, observatory]

# Dependency graph
requires: []
provides:
  - "ObservatoryPostFX component with EffectComposer (Bloom, Vignette, ToneMapping ACES_FILMIC, SMAA)"
  - "@react-three/postprocessing@3.0.4 and postprocessing@6.38.3 installed"
  - "Canvas hardware MSAA disabled (gl.antialias=false) in ObservatoryWorldCanvas"
  - "HDR post-processing pipeline with HalfFloatType framebuffer"
affects: [10-02, 10-03, phase-11, phase-12]

# Tech tracking
tech-stack:
  added:
    - "@react-three/postprocessing@3.0.4"
    - "postprocessing@6.38.3"
  patterns:
    - "EffectComposer with multisampling=0 + gl.antialias=false (SMAA replaces hardware MSAA)"
    - "HalfFloatType framebuffer required for HDR bloom (emissiveIntensity > 1 values not clamped)"
    - "Effect order is mandatory: Bloom -> Vignette -> ToneMapping -> SMAA"
    - "ObservatoryPostFX placed as last child inside <Suspense>, after </Physics>"

key-files:
  created:
    - "apps/workbench/src/features/observatory/components/ObservatoryPostFX.tsx"
  modified:
    - "apps/workbench/package.json"
    - "apps/workbench/bun.lock"
    - "apps/workbench/src/features/observatory/components/ObservatoryWorldCanvas.tsx"

key-decisions:
  - "gl.antialias=false on Canvas: SMAA replaces hardware MSAA to avoid double AA (over-blurring artifacts)"
  - "frameBufferType=THREE.HalfFloatType: required so emissiveIntensity > 1 HDR values are not clamped before bloom"
  - "ToneMapping MUST be second-to-last (before SMAA only): if placed before Bloom, bloom appears blown out"
  - "luminanceThreshold=0.85 means only materials with emissiveIntensity > 1 AND toneMapped=false will bloom"
  - "Forward-compat props activeHeroPropPosition and spiritLut stubbed for Plans 02 and 03"

patterns-established:
  - "Post-processing effects are encapsulated in ObservatoryPostFX, not scattered in ObservatoryWorldCanvas"
  - "Effect insertion slots documented in comments: Plan 02 inserts Autofocus between Bloom and Vignette; Plan 03 inserts LUT between Vignette and ToneMapping"

requirements-completed: [PP-01, PP-02]

# Metrics
duration: 3min
completed: 2026-03-19
---

# Phase 10 Plan 01: Post-Processing Foundation Summary

**EffectComposer with HDR Bloom (HalfFloatType, luminanceThreshold=0.85), ACES Filmic ToneMapping, Vignette, and SMAA wired into ObservatoryWorldCanvas with hardware MSAA disabled**

## Performance

- **Duration:** ~3 min
- **Started:** 2026-03-19T17:34:10Z
- **Completed:** 2026-03-19T17:36:31Z
- **Tasks:** 3
- **Files modified:** 4 (package.json, bun.lock, ObservatoryPostFX.tsx created, ObservatoryWorldCanvas.tsx)

## Accomplishments
- Installed @react-three/postprocessing@3.0.4 and postprocessing@6.38.3 via bun add
- Created ObservatoryPostFX.tsx encapsulating the full EffectComposer stack with exact AAA-quality values
- Wired ObservatoryPostFX into ObservatoryWorldCanvas: disabled hardware MSAA, added component inside Suspense after Physics

## Task Commits

Each task was committed atomically:

1. **Task 1: Install @react-three/postprocessing and postprocessing packages** - `123fda75c` (chore)
2. **Task 2: Create ObservatoryPostFX component** - `089d9d070` (feat)
3. **Task 3: Wire ObservatoryPostFX into ObservatoryWorldCanvas** - `5ae902d2a` (feat)

## Files Created/Modified
- `apps/workbench/src/features/observatory/components/ObservatoryPostFX.tsx` - New EffectComposer component with Bloom(intensity=1.5, luminanceThreshold=0.85, mipmapBlur, radius=0.35), Vignette(offset=0.3, darkness=0.6), ToneMapping(ACES_FILMIC), SMAA; forward-compat props for Plans 02 and 03
- `apps/workbench/package.json` - Added @react-three/postprocessing and postprocessing dependencies
- `apps/workbench/src/features/observatory/components/ObservatoryWorldCanvas.tsx` - Import ObservatoryPostFX, gl.antialias false, <ObservatoryPostFX /> as last Suspense child

## Decisions Made
- **HalfFloatType framebuffer:** Required for HDR bloom to function. Without it, emissiveIntensity > 1 values are clamped to [0,1] before reaching Bloom, so the glow effect cannot activate.
- **gl.antialias: false:** SMAA replaces hardware MSAA. Running both causes over-blurring / double AA work per research pitfall #4.
- **multisampling={0} on EffectComposer:** Pairs with gl.antialias:false to ensure no redundant AA pass.
- **Effect order:** Bloom must be first (operates on HDR values before tone mapping). ToneMapping second-to-last (if before Bloom, bloom appears blown out). SMAA always last.
- **ObservatoryPostFX placement:** Inside Suspense, after Physics closing tag — R3F hooks require Canvas context; scene geometry must render before compositor runs.

## Deviations from Plan

None - plan executed exactly as written.

## Issues Encountered
- Pre-existing TypeScript errors in `sidebar-icons.tsx` (5x TS2783 "specified more than once") are unrelated to this plan and were not introduced by these changes. Logged to deferred-items.

## Next Phase Readiness
- Post-processing infrastructure is live. Plans 02 and 03 can now insert DOF (Autofocus between Bloom and Vignette) and LUT (between Vignette and ToneMapping) using the documented insertion slots in ObservatoryPostFX.tsx comments.
- Forward-compat props `activeHeroPropPosition` and `spiritLut` are stubbed and ready for Plans 02 and 03 to implement.

---
*Phase: 10-post-processing-foundation*
*Completed: 2026-03-19*
