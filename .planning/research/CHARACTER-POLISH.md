# Character Animation Polish Research

**Domain:** Three.js AnimationMixer + procedural animation layering for R3F character controller
**Researched:** 2026-03-19
**Overall confidence:** HIGH (all findings backed by Three.js official docs + community verification)

---

## Current System Audit

Read all four character files before researching. Key facts that shape every recommendation:

**What the system already does:**
- `useObservatoryPlayerAnimation.ts` — already creates a `new AnimationMixer(modelScene)` directly. It registers all visual actions (idle, walk, run, jump, land, front-flip, back-flip) into a `Map<VisualAction, ClipEntry>`, handles `fadeIn`/`fadeOut` with `crossFadeTo` semantics via reset+fadeIn, and calls `mixer.update(delta)` each frame.
- After `mixer.update(delta)`, it calls `applyRootPose` and `applyFallbackPose` — these write directly to `animatedRoot.position.y`, `animatedRoot.rotation.x`, `animatedRoot.scale`, and all fallback rig group rotations.
- `moveSet.ts` — contains `sampleObservatoryPlayerPose()` which returns a full `ObservatoryPlayerPose` struct with rootOffsetY, rootScale, bodySpinX, and per-bone pitch/roll values. The land action (`sampleLandPose`) already implements squash-stretch via `rootScale` ([1.04, 0.88, 1.04] at impact → [1.04, 1.0, 1.04] at progress=1) and a `rootOffsetY` compression.
- The flip uses `easeInOutCubic` for spin — not elastic.
- Landing detection happens in `resolveObservatoryPlayerAction` via `previousGrounded === false && state.grounded` transition, setting `landTimerSeconds = LAND_HOLD_SECONDS (0.18s)`.
- The GLB avatar is loaded via `useAvatarAsset`; `modelClips` are passed into `useObservatoryPlayerAnimation`. The asset has 3 clips (idle, walk, run). Flip/land/jump use fallbacks (`selectClipEntry` maps them to jump→idle).

**Stack versions:**
- `three: ^0.170.0`
- `@react-three/drei: ^10.7.7`
- `@react-three/fiber: ^9.0.0`
- `@react-three/rapier: ^2.2.0`

---

## 1. AnimationMixer Blending — Crossfade idle↔walk↔run

### Current state
`playClipEntry` uses `action.reset() + action.fadeIn(0.14) + prevAction.fadeOut(0.12)`. This is a hard crossfade — the previous action fades out while the new one fades in over 0.12–0.14 seconds. It works correctly for one-shot transitions (jump, land, flip) but for locomotion (idle↔walk↔run) it produces a snap whenever the speed crosses thresholds.

### Recommended approach: weight-based simultaneous blending

Do NOT use `crossFadeTo()` for the locomotion layer. Instead, keep all three locomotion actions playing simultaneously and drive their `setEffectiveWeight` each frame based on velocity. This is the standard pattern used in Three.js `webgl_animation_skinning_blending` example (HIGH confidence, from official Three.js examples).

```typescript
// All three playing at all times, weights sum to 1
idleAction.play();
walkAction.play();
runAction.play();

// In useFrame, after resolving horizontalSpeed:
function updateLocomotionWeights(
  idleAction: AnimationAction,
  walkAction: AnimationAction,
  runAction: AnimationAction,
  horizontalSpeed: number,
) {
  const WALK_MIN = 0.3;   // matches moveSet.ts WALK_SPEED_THRESHOLD
  const RUN_MIN  = 2.2;   // matches moveSet.ts RUN_SPEED_THRESHOLD

  let idleW = 0, walkW = 0, runW = 0;

  if (horizontalSpeed < WALK_MIN) {
    idleW = 1;
  } else if (horizontalSpeed < RUN_MIN) {
    const t = (horizontalSpeed - WALK_MIN) / (RUN_MIN - WALK_MIN);
    idleW = 1 - t;
    walkW = t;
  } else {
    const t = Math.min((horizontalSpeed - RUN_MIN) / 2.0, 1); // blend out of walk fully at +2 m/s
    walkW = 1 - t;
    runW  = t;
  }

  idleAction.setEffectiveWeight(idleW);
  walkAction.setEffectiveWeight(walkW);
  runAction.setEffectiveWeight(runW);
}
```

**Key detail:** `setEffectiveWeight` requires the action to already be playing. If an action has weight 0 it contributes nothing to the pose but stays time-synchronized. This prevents the "snap to T-pose" issue seen in drei 9.81.2 when switching actions.

**Time-scale sync:** Walk and run cycle at different speeds. To prevent foot-sliding, sync playback time:

```typescript
// Lock walk time to idle time when blending out
if (horizontalSpeed < WALK_MIN) {
  walkAction.syncWith(idleAction);
} else {
  walkAction.syncWith(null as unknown as AnimationAction); // unsync
}
```

### Should you use `drei useAnimations`?

No. The system already has a hand-rolled `AnimationMixer` with full control. `useAnimations` is a thin wrapper that returns `{ mixer, actions, names, clips, ref }` — useful for simple cases but you would lose the `clipEntriesRef` map, the one-shot vs loop distinction, and the fallback chain logic. Keep the existing mixer. The drei hook has a known T-pose flash bug on action switch (issue #2340, present as of drei 9.81.x). Your current approach avoids this.

### Integration point in existing code

Replace the `clipEntry`/`playClipEntry`/`fadeOutClipByName` block in `useFrame` with a locomotion weight function for idle/walk/run only. Keep the hard-switch logic for one-shot actions (land, front-flip, back-flip, jump) since they need `reset()` + `LoopOnce`.

---

## 2. Landing Squash-Stretch

### Current state

Already implemented in `sampleLandPose()`:
- `rootScale`: [1.04, 0.88, 1.04] at impact decaying to [1.04, 1.0, 1.04] over `progress`
- `rootOffsetY`: negative compression (`-compression`) decaying to 0
- Timer: 0.18s hold (`LAND_HOLD_SECONDS`)

The foundation is correct. It is currently applied via `applyRootPose` → `animatedRoot.scale.set(...)` which works for the fallback rig. For GLB avatars, `animatedRoot` is the `<group ref={animatedRootRef}>` wrapping `<primitive object={modelScene} />` — scaling this group squashes the entire model including skinned mesh, which is correct.

### Improvements to the current values

The current compress value (Y=0.88) is workable but feels gentle. For "AAA feel" the industry standard is:

- **Compress:** Y = 0.72–0.78 (strong hit read)
- **Overshoot:** Y = 1.08–1.12 (body springs back past neutral)
- **Settle:** Y = 1.0

The current `sampleLandPose` uses a single linear decay from compressed to 1.0. It has no overshoot pass. To add overshoot, extend the land pose duration and use a two-phase easing:

```typescript
// In sampleLandPose — replace current rootScale Y calculation
const COMPRESS_Y = 0.74;
const OVERSHOOT_Y = 1.1;
const COMPRESS_PHASE = 0.35; // first 35% of duration = compress

let scaleY: number;
if (progress < COMPRESS_PHASE) {
  // 0→COMPRESS_Y
  const t = progress / COMPRESS_PHASE;
  scaleY = 1 + (COMPRESS_Y - 1) * easeOutQuad(t);
} else {
  // COMPRESS_Y → OVERSHOOT_Y → 1.0 via elastic
  const t = (progress - COMPRESS_PHASE) / (1 - COMPRESS_PHASE);
  const overshootT = easeOutBack(t); // defined below
  scaleY = COMPRESS_Y + (1 - COMPRESS_Y) * overshootT;
}
```

Also extend `LAND_HOLD_SECONDS` from 0.18 to 0.28–0.32 seconds to give the overshoot phase room to breathe.

### Landing detection in Rapier

The system already detects landing correctly in `runtime.ts`: `!previous.grounded && grounded` triggers `landUntilMs = nowMs + config.landLockMs`. The `landLockMs` default is 120ms. This is the right place to also compute impact velocity for variable-strength squash:

```typescript
// In stepObservatoryPlayerState, when landing is detected:
if (!previous.grounded && grounded) {
  const impactVelocityY = Math.abs(body.velocity[1]); // m/s at moment of contact
  // Store on state for animation consumption
  landImpactVelocity: impactVelocityY,
}
```

Pass `impactVelocityY` into `sampleLandPose` so a hard fall (velocity > 8 m/s) compresses more (Y=0.68) than a soft hop (velocity < 3 m/s, Y=0.88). This creates proportional squash that reads as weight.

---

## 3. Idle Breathing — Layered on Top of AnimationMixer

### The problem

The GLB idle clip will play its baked breathing motion. The existing `sampleIdlePose` already does a sin-wave oscillation on `rootOffsetY` and `torsoRoll`. If the GLB idle clip is playing, writing to the same bones via `applyRootPose` will conflict with whatever the mixer wrote.

### Correct pattern: modify bones AFTER mixer.update()

The `useObservatoryPlayerAnimation` `useFrame` already does this correctly — `mixer.update(delta)` is called first, then `applyRootPose` and `applyFallbackPose` write over the pose. For the GLB case, `applyRootPose` only writes to the `animatedRootRef` group (the wrapper), not to the skinned mesh bones directly. This is safe — the group transform stacks on top of the mixer-driven bone positions.

For breathing layered on GLB clips, the recommended approach is to apply breathing as a small additive delta to `animatedRoot.position.y` (not the mesh bones) AFTER `mixer.update`:

```typescript
// After mixer.update(delta) in useFrame:
const breathOffset = Math.sin(elapsedSeconds * 1.8) * 0.018 * idleWeight;
animatedRoot.position.y = pose.rootOffsetY + breathOffset;
```

This stacks on top of whatever the mixer put on the skeleton's root.

### If you want to drive a specific bone (e.g., spine/torso) additively

You must find the bone by name from the skinned mesh skeleton AFTER `mixer.update()`:

```typescript
// Once on scene load, cache the bone ref:
const spineBone = modelScene.getObjectByName("Spine") as Bone | undefined;

// In useFrame, after mixer.update(delta):
if (spineBone && idleWeight > 0) {
  spineBone.rotation.x += Math.sin(elapsedSeconds * 1.8) * 0.015 * idleWeight;
  // Do NOT call updateMatrixWorld here — R3F does a full scene update each frame
}
```

**Important:** Do NOT use `AnimationUtils.makeClipAdditive` for breathing unless you bake the breath motion into a separate GLB clip. The makeClipAdditive approach requires the base pose reference frame to be correct and is more fragile than a simple post-mixer rotation delta for this use case (MEDIUM confidence — based on Three.js forum patterns).

---

## 4. Sprint Lean — Root Bone Rotation Additively

### Recommended approach

The `torsoPitch` in `sampleRunPose` already pushes the torso to -0.22 rad (forward lean) for the fallback rig. For GLB avatars, extend this by finding the hip/root bone and adding a pitch proportional to `horizontalSpeed`:

```typescript
// In useFrame, after mixer.update(delta):
const MAX_LEAN_RADIANS = 0.18; // ~10 degrees
const leanFactor = Math.min(horizontalSpeed / RUN_SPEED_THRESHOLD, 1.0) * sprintModifier;
const leanAmount = leanFactor * MAX_LEAN_RADIANS;

if (hipsBone) {
  hipsBone.rotation.x -= leanAmount; // negative X = lean forward in standard skeleton
}
```

**Smoothing:** Don't snap lean. Use an exponential lerp on `leanAmount` with speed ~8:

```typescript
const smoothedLean = expLerp(smoothedLeanRef.current, leanAmount, 8, delta);
smoothedLeanRef.current = smoothedLean;
```

The `expLerp` function already exists in `runtime.ts` — copy it into the animation hook.

**Bone name fallback:** GLB skeletons use inconsistent naming. Search for: `"Hips"`, `"mixamorigHips"`, `"Root"`, `"Pelvis"` in that order. Cache the found bone ref in a `useRef` on scene load.

---

## 5. Flip Easing — Elastic Overshoot + Settle

### Current state

`sampleFlipPose` uses `easeInOutCubic` for `bodySpinX`. This produces a smooth but physically inert spin — it decelerates evenly to a stop with no character. The `easeInOutCubic` function is defined at the bottom of `moveSet.ts`.

### Recommended: easeOutBack for the deceleration phase

Replace the single easing with a two-phase approach:

```typescript
// Phase 1 (0→0.6): accelerate with easeInCubic
// Phase 2 (0.6→1.0): decelerate with easeOutBack (overshoot + settle)

function easeFlipProgress(t: number): number {
  if (t < 0.6) {
    // ease in
    const t2 = t / 0.6;
    return 0.6 * (t2 * t2 * t2);
  }
  // ease out back in the remaining 40%
  const t2 = (t - 0.6) / 0.4;
  return 0.6 + 0.4 * easeOutBack(t2);
}

// easeOutBack formula (c1=1.70158, c3=c1+1):
function easeOutBack(x: number): number {
  const c1 = 1.70158;
  const c3 = c1 + 1;
  return 1 + c3 * Math.pow(x - 1, 3) + c1 * Math.pow(x - 1, 2);
}
```

This makes the flip snap to upright with a slight over-rotation (~3–5 degrees) then bounce back to neutral — exactly the "planted" feel of a game-quality flip.

**Dial the overshoot:** `c1 = 1.70158` is the standard Back overshoot. Reduce to `c1 = 0.8` for subtle, increase to `c1 = 2.5` for theatrical. For a grounded astronaut-operator, `c1 = 1.2` reads well.

**Also add a settle on tuck:** `tuck` in `sampleFlipPose` currently uses a symmetric triangle (tuck up from 0 to 0.5, tuck down from 0.5 to 1.0). Apply `easeOutBack` to the tuck-release phase so limbs snap back to extended position with a micro-bounce:

```typescript
const tuckRelease = progress > 0.5 ? easeOutBack((progress - 0.5) / 0.5) : 0;
const tuck = progress < 0.5
  ? (progress / 0.5) * tuckStrength
  : tuckStrength * (1 - tuckRelease);
```

---

## 6. Footstep Events — Detecting Foot-Strike Moments

### Two approaches; use approach A for this system

**Approach A: Procedural cycle time detection (correct for this architecture)**

The walk/run procedural poses in `moveSet.ts` already drive foot position via `Math.sin(cycle)`. The foot-strike moment is when a foot transitions from forward swing to backward push — i.e., when `Math.sin(cycle)` crosses zero from positive to negative (right foot hits) or negative to positive (left foot hits).

Track the previous cycle sign and fire an event on sign change:

```typescript
// In useFrame, after sampleObservatoryPlayerPose:
const cycle = actionElapsedRef.current * (5.8 + strideFactor * 1.4); // matches sampleWalkPose
const cycleSign = Math.sign(Math.sin(cycle));

if (prevCycleSignRef.current !== 0 && cycleSign !== prevCycleSignRef.current) {
  const isRightFoot = cycleSign < 0; // right foot strikes when sin goes negative
  onFootstrike?.({ foot: isRightFoot ? "right" : "left", position: controllerState.position });
}
prevCycleSignRef.current = cycleSign;
```

Only fire when action is "walk" or "run" AND `grounded === true`.

**Approach B: Bone Y-position monitoring (for GLB clips only)**

Monitor the Y world position of the foot bone AFTER `mixer.update()`. If position.Y drops below a threshold (≈ 0.05 above ground) and was above it last frame, that is a foot-strike. This is the most accurate method for baked clips.

```typescript
// Cache on scene load:
const leftFootBone = modelScene.getObjectByName("LeftFoot") as Object3D | undefined;

// In useFrame, after mixer.update(delta):
if (leftFootBone && grounded) {
  const worldPos = new Vector3();
  leftFootBone.getWorldPosition(worldPos);
  const isContact = worldPos.y < GROUND_Y + 0.08;
  if (isContact && !prevLeftFootContactRef.current) {
    onFootstrike?.({ foot: "left", position: controllerState.position });
  }
  prevLeftFootContactRef.current = isContact;
}
```

**Recommendation:** Use Approach A for the current system. The `sampleWalkPose`/`sampleRunPose` functions own the cycle math already — this avoids the bone-naming fragility of Approach B and works identically for both the fallback rig and GLB avatars. Approach B is the upgrade path if you later ship with verified bone-named GLBs.

---

## Implementation Order

These six improvements are roughly independent but have a natural ordering:

1. **Flip easing** (5) — isolated change to `sampleFlipPose` in `moveSet.ts`. No new refs, no new hooks. ~20 LOC.

2. **Landing squash-stretch enhancement** (2) — modify `sampleLandPose` in `moveSet.ts` + extend `LAND_HOLD_SECONDS`. Optional: add `landImpactVelocity` to state. ~30 LOC.

3. **Idle breathing layer** (3) — add a `breathingRef` elapsed tracker in `useObservatoryPlayerAnimation`, apply delta to `animatedRoot.position.y` after `mixer.update`. ~15 LOC.

4. **Sprint lean** (4) — add `smoothedLeanRef` and hip bone cache in `useObservatoryPlayerAnimation`, apply post-mixer. ~25 LOC.

5. **Footstep events** (6) — add `prevCycleSignRef` and optional callback prop on `useObservatoryPlayerAnimation`. ~20 LOC.

6. **AnimationMixer weight blending** (1) — largest change; refactor `playClipEntry`/`fadeOutClipByName` into a weight function. ~60 LOC. Do last since it touches the core mixer logic.

---

## Pitfalls to Avoid

### Bone modification ordering
Always modify bones AFTER `mixer.update(delta)`. Writing to the same bone before mixer.update causes the mixer to overwrite your changes. The current `useFrame` already has the right order — `mixer.update(delta)` then `applyRootPose`. Preserve this invariant.

### Simultaneous weight blending requires all actions playing
For weight-based locomotion blending, all three actions (idle, walk, run) must be `.play()`-ed even if their weight is 0. A weight-0 action contributes nothing to the pose but must be active. Initialize all three on scene load.

### T-pose flash in drei useAnimations
If you ever switch to `useAnimations`, be aware of issue #2340 (T-pose flash on action switch in drei ^9.81.2). The current hand-rolled mixer approach is immune to this.

### Scale conservation in squash-stretch
When squashing Y, XZ must expand proportionally to conserve apparent volume: if scaleY = 0.74, set scaleX = scaleZ = `1 / Math.sqrt(0.74)` ≈ 1.16. The current `moveSet.ts` land spec uses [1.04, 0.88, 1.04] which is conservative (not volume-conserving). For juicier feel, push to [1.16, 0.74, 1.16].

### Footstep cycle phase varies between walk and run
Walk cycle rate: `5.8 + strideFactor * 1.4` (from `sampleWalkPose`). Run cycle rate: `8.6 + strideFactor * 2.4` (from `sampleRunPose`). The footstep detection must use the correct formula for the current action.

### Flip spin and model clip interference
`bodySpinX` writes to `animatedRoot.rotation.x`. If the flip GLB clip also drives root rotation (unlikely given only 3 clips: idle/walk/run), there will be a conflict. The `suppressSpin` flag in `applyRootPose` prevents spin when a specific clip is playing — this logic is already correct.

---

## Confidence Assessment

| Area | Confidence | Notes |
|------|------------|-------|
| AnimationMixer weight blending | HIGH | Documented in official Three.js `webgl_animation_skinning_blending` example |
| Post-mixer bone override ordering | HIGH | Confirmed in three.js forum thread #69909, aligns with Unity LateUpdate pattern |
| drei useAnimations T-pose bug | HIGH | Verified in pmndrs/drei issue #2340 |
| Landing detection via grounded transition | HIGH | Already implemented correctly in runtime.ts |
| easeOutBack formula | HIGH | From easings.net source, standard Robert Penner formula |
| Squash-stretch values (0.74/1.1) | MEDIUM | Industry guidance; specific values need tuning in your scene |
| Footstep cycle-zero-crossing approach | MEDIUM | Logical from the procedural math; not a documented Three.js pattern |
| Bone name discovery ("Hips", "mixamorigHips") | MEDIUM | Common Mixamo convention; verify against your specific GLB |

---

## Sources

- [Three.js AnimationMixer docs](https://threejs.org/docs/#api/en/animation/AnimationMixer)
- [Three.js Animation System manual](https://threejs.org/manual/en/animation-system.html)
- [Three.js webgl_animation_skinning_blending example](https://github.com/mrdoob/three.js/blob/dev/examples/webgl_animation_skinning_blending.html)
- [Three.js webgl_animation_skinning_additive_blending example](https://github.com/mrdoob/three.js/blob/master/examples/webgl_animation_skinning_additive_blending.html)
- [drei useAnimations docs](https://drei.docs.pmnd.rs/abstractions/use-animations)
- [drei issue #2340 — T-pose flash on action switch](https://github.com/pmndrs/drei/issues/2340)
- [Three.js forum — bone override flickering](https://discourse.threejs.org/t/overriding-an-animation-by-modifying-a-bone-causes-flickering/69909)
- [Three.js forum — footstep sound approaches](https://discourse.threejs.org/t/how-i-can-put-footstep-sound/39292)
- [easings.net — easeOutBack / easeOutElastic formulas](https://github.com/ai/easings.net/blob/master/src/easings/easingsFunctions.ts)
