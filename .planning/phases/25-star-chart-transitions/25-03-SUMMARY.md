---
phase: 25-star-chart-transitions
plan: 03
subsystem: ui
tags: [three.js, r3f, vfx, animation, instanced-mesh, zustand, post-processing]

requires:
  - phase: 25-star-chart-transitions
    provides: "Star chart, station transitions, SpeedTier types and flightState in observatory store"
  - phase: 21-ship-flight
    provides: "FlightState, SpeedTier, boostActivatedAtMs, DEFAULT_FLIGHT_CONFIG (boostDurationMs: 2000)"
  - phase: 12-particle-effects
    provides: "wawa-vfx (VFXParticles, VFXEmitter) installed and patterned"

provides:
  - "FovController with boost phase FSM: 60→90 over 0.3s (ease-in) + 90→60 over 0.8s (ease-out)"
  - "Bloom luminanceThreshold spike: 0.85→0.5 for 0.8s then eases back over 0.5s on boost"
  - "WarpSpeedLines: 40 instanced cylinder streaks from camera during boost, toneMapped=false (bloom-visible)"
  - "warp-speed-lines VFX pool (80 particles, StretchBillboard) in ObservatoryVFXPools"

affects:
  - 25-star-chart-transitions
  - observatory visual effects
  - post-processing bloom behavior

tech-stack:
  added: []
  patterns:
    - "Boost phase FSM via refs (boostFovPhaseRef + boostFovTimerRef): idle/ramp-up/sustain/ramp-down"
    - "ObservatoryWorldScene subscribes to flightState.speedTier for local boost-derived state"
    - "seededRandom(seed) for stable per-instance values in InstancedMesh (avoids per-frame allocation)"
    - "setTimeout-based bloom spike in outer React component (rare event, acceptable setState)"

key-files:
  created:
    - apps/workbench/src/features/observatory/vfx/WarpSpeedLines.tsx
  modified:
    - apps/workbench/src/features/observatory/components/ObservatoryWorldCanvas.tsx
    - apps/workbench/src/features/observatory/components/ObservatoryPostFX.tsx
    - apps/workbench/src/features/observatory/vfx/ObservatoryVFXPools.tsx

key-decisions:
  - "InstancedMesh over wawa-vfx VFXEmitter for WarpSpeedLines: cylindrical streaks don't need particle lifetime/color/spawn API; InstancedMesh matrix updates in useFrame are cheaper and more predictable for this use case"
  - "seededRandom per instance index: per-frame stable streak positions without per-frame allocation; streaks rotate slowly with camera orientation changes giving organic feel"
  - "setTimeout bloom spike in outer component: boost fires at most every 6s (boostDurationMs+cooldown), so 2 setTimeouts per boost is acceptable; avoids complexity of a separate useFrame loop or shared ref"
  - "speedTier subscription in ObservatoryWorldScene (zustand selector): fires only on boost start/end (~once per 6s), not 60fps; separate from boostActive prop which is derived from this subscription"
  - "bloomLuminanceOverride as nullable prop on ObservatoryPostFX: null = default 0.85, number = active override; clean separation of responsibilities between post-FX component and outer controller"

patterns-established:
  - "Boost VFX pattern: subscribe to speedTier in scene component, derive boostActive boolean, pass to sub-components as bool prop"
  - "InstancedMesh streaks pattern: zero all scales on deactivation frame rather than unmounting"

requirements-completed: [TRN-01, TRN-02, TRN-04]

duration: 7min
completed: 2026-03-20
---

# Phase 25 Plan 03: Boost Transition VFX Summary

**FOV punch (60→90→60), instanced warp speed line streaks, and bloom spike all fire simultaneously on boost activation using refs-only animation in useFrame**

## Performance

- **Duration:** ~7 min
- **Started:** 2026-03-20T19:31:16Z
- **Completed:** 2026-03-20T19:38:25Z
- **Tasks:** 2
- **Files modified:** 4 (3 modified, 1 created)

## Accomplishments
- Boost FOV punch: phase state machine (ramp-up 0.3s ease-in, sustain, ramp-down 0.8s ease-out) using refs only — zero setState in 60fps frame loop
- Bloom spike: luminanceThreshold drops from 0.85 → 0.5 on boost, eases back over 0.5s via setTimeout in outer component
- WarpSpeedLines: 40 instanced thin cylinder streaks in cone pattern around camera forward, all bloom-visible via toneMapped=false

## Task Commits

Each task was committed atomically:

1. **Task 1: Boost FOV punch + bloom spike** - `fdfa0f2a2` (feat)
2. **Task 2: Warp speed line particles** - `1f3fdfad2` (feat)

## Files Created/Modified
- `apps/workbench/src/features/observatory/vfx/WarpSpeedLines.tsx` - New: 40 instanced cylinder streaks, InstancedMesh with seededRandom per-instance positions in cone around camera forward
- `apps/workbench/src/features/observatory/components/ObservatoryWorldCanvas.tsx` - FovController boost phase FSM, speedTier subscription, bloom spike state, WarpSpeedLines mount
- `apps/workbench/src/features/observatory/components/ObservatoryPostFX.tsx` - bloomLuminanceOverride optional prop, Bloom element uses override ?? 0.85
- `apps/workbench/src/features/observatory/vfx/ObservatoryVFXPools.tsx` - Added "warp-speed-lines" pool (80 particles, StretchBillboard, no gravity)

## Decisions Made
- Used InstancedMesh over wawa-vfx for WarpSpeedLines: cylindrical streaks need matrix control not particle lifetime/spawn API
- seededRandom(i*7+n) per instance: stable positions each frame without GC allocation
- setTimeout for bloom spike: fires once per boost (~6s), acceptable React setState; simpler than a shared ref + separate useFrame
- speedTier subscription at ObservatoryWorldScene level (not inner FovController): allows both FovController and WarpSpeedLines to share the same derived boolean

## Deviations from Plan

None - plan executed exactly as written.

## Issues Encountered
None.

## User Setup Required
None - no external service configuration required.

## Next Phase Readiness
- All three boost effects (FOV + lines + bloom) fire simultaneously on boost activation
- Effects are time-bounded and resolve before 6s boost+cooldown cycle ends
- Ready for any additional transition work in phase 25 plans 04+

---
*Phase: 25-star-chart-transitions*
*Completed: 2026-03-20*
