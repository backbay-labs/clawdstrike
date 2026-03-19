---
phase: 13-character-polish
plan: "02"
subsystem: observatory-character-animation
tags:
  - animation
  - locomotion-blending
  - breathing
  - sprint-lean
  - footstep-events
dependency_graph:
  requires:
    - 13-01
  provides:
    - CHR-01
    - CHR-03
    - CHR-04
    - CHR-06
  affects:
    - CharacterVFX (receives observatory:footstrike events)
    - ObservatoryPlayerAnimation (consumes hip bone for lean)
tech_stack:
  added: []
  patterns:
    - Weight-based AnimationAction blending (setEffectiveWeight + all actions playing simultaneously)
    - ExpLerp smoothing for lean (1 - exp(-8*delta))
    - Cycle sign-flip zero-crossing for footstep detection
    - Additive post-mixer Y offset for idle breathing
key_files:
  created: []
  modified:
    - apps/workbench/src/features/observatory/character/animation/useObservatoryPlayerAnimation.ts
    - apps/workbench/src/features/observatory/character/animation/moveSet.ts
decisions:
  - "Export WALK_SPEED_THRESHOLD (0.3) and RUN_SPEED_THRESHOLD (2.2) from moveSet.ts instead of inlining magic numbers in useObservatoryPlayerAnimation.ts"
  - "assetClipName snapshot: for locomotion use entries.get(resolved.action)?.clipName; for one-shots use activeClipNameRef — avoids out-of-scope clipEntry reference"
  - "Sprint lean resets in cleanup return to null (hipsBoneRef.current = null) to prevent stale bone reference after model change"
  - "Footstep speedFactor clamp range uses same bounds as sampleWalkPose/sampleRunPose (0.45-0.88 walk, 0.8-1.2 run) for physical consistency"
metrics:
  duration_seconds: 268
  completed_date: "2026-03-19"
  tasks_completed: 2
  files_modified: 2
---

# Phase 13 Plan 02: Animation Polish Layers Summary

Weight-based locomotion blending (idle/walk/run three-way weight lerp), idle breathing Y oscillation, sprint hip lean with expLerp smoothing, and footstep CustomEvent dispatch via cycle sign-flip detection — all additive post-mixer changes to useObservatoryPlayerAnimation.ts.

## Tasks Completed

| Task | Name | Commit | Files |
|------|------|--------|-------|
| 1 | Weight-based locomotion blending (CHR-01) | 6d66a127b | useObservatoryPlayerAnimation.ts, moveSet.ts |
| 2 | Breathing layer + Sprint lean + Footstep events (CHR-03, CHR-04, CHR-06) | f4f67bb87 | useObservatoryPlayerAnimation.ts |

## What Was Built

### CHR-01: Weight-based Locomotion Blending

The hook now starts `idle`, `walk`, and `run` AnimationActions playing at weight 0 in `useEffect`, keeping all three time-synchronized. The new `updateLocomotionWeights` helper computes a three-way blend:

- `horizontalSpeed < 0.3` (WALK_SPEED_THRESHOLD): idleW=1, walkW=0, runW=0
- `0.3 <= speed < 2.2` (RUN_SPEED_THRESHOLD): linear blend idle→walk
- `speed >= 2.2`: linear blend walk→run (saturates at speed=4.2)

One-shot actions (jump, land, front-flip, back-flip) continue to hard-switch via the existing `playClipEntry`/`fadeOutClipByName` path; locomotion weights are zeroed during one-shots.

### CHR-03: Idle Breathing

Post-`applyRootPose`, a sinusoidal Y offset is added: `sin(breathElapsed * 1.8) * 0.018 * idleWeight`. The `idleWeight` is `max(0, 1 - horizontalSpeed / WALK_SPEED_THRESHOLD)`, meaning breathing is fully visible at rest and fades completely at walking speed.

### CHR-04: Sprint Lean

Hip bone is discovered once in `useEffect` by searching `["Hips", "mixamorigHips", "Root", "Pelvis"]` on `modelScene`. Each frame post-mixer, a lean target is computed as `min(speed / RUN_SPEED_THRESHOLD, 1.0) * 0.18` radians (~10 degrees max). ExpLerp at rate 8/s smooths transitions. The lean is applied as `hipsBoneRef.current.rotation.x -= smoothedLean` (degrades gracefully if bone not found).

### CHR-06: Footstep Events

During grounded walk/run, cycle value is computed using the identical formula as `sampleWalkPose`/`sampleRunPose`. Sign-flip detection on `prevCycleSignRef` fires `window.dispatchEvent(new CustomEvent('observatory:footstrike', { detail: { foot, position } }))`. The `foot` property is `"right"` when sign flips to negative, `"left"` when positive. Sign resets to 0 on airborne/non-locomotion to prevent spurious events on re-entry.

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 1 - Bug] Out-of-scope `clipEntry` reference in snapshot**
- **Found during:** Task 1 — after refactoring the clip-switching block, `clipEntry` was only in scope inside the one-shot `else` branch, but the snapshot update at the end of `useFrame` referenced it
- **Fix:** Replaced `clipEntry?.clipName ?? null` with a conditional: for locomotion, lookup `clipEntriesRef.current.get(resolved.action)?.clipName`; for one-shots, use `activeClipNameRef.current`
- **Files modified:** useObservatoryPlayerAnimation.ts
- **Commit:** 6d66a127b

## Self-Check

- [x] `useObservatoryPlayerAnimation.ts` modified with all 4 behaviors
- [x] `moveSet.ts` exports `WALK_SPEED_THRESHOLD` and `RUN_SPEED_THRESHOLD`
- [x] Commits 6d66a127b and f4f67bb87 exist
- [x] All `moveSet.test.ts` tests pass (22/22)
- [x] TypeScript build: 0 `error TS` lines
- [x] Pre-existing test count unchanged: 265 failed / 2108 passed (same as before changes)
