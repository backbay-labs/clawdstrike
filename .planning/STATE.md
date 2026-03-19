---
gsd_state_version: 1.0
milestone: v4.0
milestone_name: AAA Observatory Experience
status: planning
stopped_at: Completed 11-camera-cinematics-shake-03-PLAN.md
last_updated: "2026-03-19T18:24:14Z"
last_activity: 2026-03-19 — completed CAM-04 mission focus pull with dwellRef suppression
progress:
  total_phases: 5
  completed_phases: 1
  total_plans: 10
  completed_plans: 6
  percent: 0
---

# Project State

## Project Reference

See: .planning/PROJECT.md (updated 2026-03-19)

**Core value:** AAA-quality immersive observatory — post-processing, particles, cinematic camera, polished character, world detail, NPCs
**Current focus:** Phase 10 — Post-Processing Foundation (ready to plan)

## Current Position

Phase: 11 of 14 (Camera Cinematics Shake)
Plan: 03 of 03 (complete)
Status: Phase 11 complete — all CAM requirements addressed
Last activity: 2026-03-19 — completed CAM-04 mission focus pull (plan 11-03)

Progress: [░░░░░░░░░░] 0%

## Performance Metrics

**Velocity:**
- Total plans completed (v4.0): 0
- Average duration: —
- Total execution time: —

*Updated after each plan completion*

## Accumulated Context

### Decisions

- Phase 10: Install `@react-three/postprocessing` + `postprocessing` via `bun add` in apps/workbench; ESM-only, Vite handles transparently
- Phase 10: `EffectComposer` needs `frameBufferType={THREE.HalfFloatType}` for HDR bloom; `multisampling={0}` + `gl={{ antialias: false }}` on Canvas
- Phase 10: Effect order is mandatory — Bloom → DOF/Autofocus → Vignette → ChromaticAberration → LUT → ToneMapping → SMAA
- Phase 10: LUT files need sourcing/creation per spirit kind (.cube format, 17x17x17 or 32x32x32)
- Phase 11: `OrbitControls` needs `makeDefault` added for `CameraShake` to track controls correctly
- Phase 11: Fly-by uses existing WorldCameraRig Bezier machinery; letterbox bars are CSS overlay (not R3F)
- Phase 12: Install `wawa-vfx` (+ `leva` as devDep); `three.quarks` blocked by three@0.170 version constraint
- Phase 12: Probe discharge is custom InstancedMesh (expanding shell); ambient motes use drei Sparkles; spirit trail uses drei Trail
- Phase 13: Weight-based locomotion blending (all three actions playing, setEffectiveWeight); NOT crossfade, NOT drei useAnimations
- Phase 13: Footstep events via cycle-zero-crossing detection (Approach A — procedural, not bone monitoring)
- Phase 14: NPCs via drei Instances + Instance (declarative instancedMesh); no pathing library needed
- Phase 14: Waypoint beacons via Billboard + Text (NOT Html — perf trap at scale)
- Phase 14: Achievement popups via Framer Motion AnimatePresence outside Canvas
- [Phase 10-post-processing-foundation]: gl.antialias:false on Canvas; SMAA replaces hardware MSAA to avoid double AA artifacts
- [Phase 10-post-processing-foundation]: frameBufferType=THREE.HalfFloatType required for HDR bloom; emissiveIntensity > 1 values would be clamped without it
- [Phase 10-post-processing-foundation]: Effect order is mandatory: Bloom -> Vignette -> ToneMapping (ACES_FILMIC) -> SMAA
- [Phase 10-post-processing-foundation]: EffectComposer children typed as JSX.Element|JSX.Element[] (no null): use imperative JSX.Element[] array with conditional push for Autofocus instead of null-returning JSX ternary
- [Phase 10-post-processing-foundation]: Bloom targets require both emissiveIntensity > 1 AND toneMapped={false}: 4 materials updated — spirit shell (2.2), torus (max(1.8, recipe*2.5)), convoy pods (1.2 + intensity*1.8), active hero prop cylinder (1.8 active)
- [Phase 10-post-processing-foundation]: Plan 03: Programmatic 17x17x17 Data3DTexture LUTs (not .cube files) for spirit color grading — sentinel=cool teal, oracle=warm violet, witness=warm gold, specter=deep red shadow crush
- [Phase 11-camera-cinematics-shake]: FovController lerps camera.fov using lerpAlpha(5.0); targets: sprint=52, probe=35, rest=42; safeDelta cap prevents spiral on frame drops
- [Phase 11-camera-cinematics-shake]: CameraShake mounted with intensity=0 (dormant); shakeRef.setIntensity called imperatively on observatory:shake CustomEvent; probe=0.45, landing=0.7
- [Phase 11-camera-cinematics-shake]: OrbitControls makeDefault added — required for CameraShake to track controls correctly via R3F state.controls
- [Phase 11-camera-cinematics-shake]: Fly-by uses existing WorldCameraRig Bezier machinery (bezierPoint + smoothstep01) reused for waypoint sequencing — no new animation system needed
- [Phase 11-camera-cinematics-shake]: frameloop prop threaded through ObservatoryWorldCanvas to Canvas (option a) — simpler than useThree approach from inside Canvas
- [Phase 11-camera-cinematics-shake]: missionFocusDwellMs required (non-optional) on ObservatoryCameraRecipe; deriveCameraRecipe returns 1800ms for atlas+focusStation, 0 otherwise
- [Phase 11-camera-cinematics-shake]: dwellRef pattern: useRef<{expiresAt:number}|null> suppresses new goal-change flights for 1.8s after flight completes; isDwelling uses slow lerp (lerpSpeed*0.4) for soft hold
- [Phase 11-camera-cinematics-shake]: flyByActive guard on activeStationId prevents mission focus flight racing with opening cinematic fly-by

### Blockers/Concerns

- Per-spirit LUT .cube files need creation before Phase 10 is fully shippable (design decision on color aesthetics per spirit kind)
- HDR skybox file needs sourcing (CC0 from Poly Haven recommended; download at 1K resolution)
- Avatar bone names need verification for thruster particle attachment (Phase 12) and sprint lean (Phase 13)

## Session Continuity

Last session: 2026-03-19T18:24:14Z
Stopped at: Completed 11-camera-cinematics-shake-03-PLAN.md
Resume file: None
