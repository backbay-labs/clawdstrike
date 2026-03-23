# Camera Cinematics Research

**Domain:** R3F camera systems for Observatory (hunt-observatory world)
**Researched:** 2026-03-19
**Overall confidence:** HIGH — source code read directly; all findings are from the live workbench and deps

---

## Context: What Exists Today

The workbench `ObservatoryWorldCanvas.tsx` has a sophisticated camera system already. Understanding its internals is the prerequisite for all six cinematic features below.

### WorldCameraRig (the existing system)

Location: `apps/workbench/src/features/observatory/components/ObservatoryWorldCanvas.tsx` — inline component starting at line 196.

**Architecture:**

```
Canvas camera={{ position: initialPosition, fov: 42 }}
  OrbitControls ref={controlsRef}  ← user interaction only; rotate+pan disabled, zoom only
  WorldCameraRig                   ← drives controlsRef.object.position + controlsRef.target each frame
```

`WorldCameraRig` is a headless `useFrame` component that owns all camera motion. It works by
writing directly to `controlsRef.current.object.position` and `controlsRef.current.target`, then
calling `controlsRef.current.update()`. It does not use CameraControls in atlas mode.

**Three internal states:**

1. **Uninitialized:** On first frame, snaps camera to `camera.initialPosition` (atlas: `[0, 20.4, 36.8]`, flow: `[0, 16.4, 31.5]`). Marks `initializedRef.current = true`.

2. **In-flight (flightRef.current != null):** Bezier sweep from current position/target to goal position/target over `camera.arrivalDurationMs` ms (atlas: 1220–1300ms, flow: 980–1100ms). Uses quadratic Bezier with a lateral deviation point computed from the travel axis. In the final 26% of the flight (`eased > 0.74`), adds a small orbital arc (`settleRadius` * decaying orbit angle) for a film-like "settling" effect.

3. **Tracking:** Lerp toward goal using `lerpAlpha(camera.lerpSpeed, delta)` — exponential smoothing, not linear. `lerpSpeed` is 3.1–4.2 depending on mode and whether a station is focused.

**Player-follow blending (flow mode):**

`playerFocusRef` carries `{ position, moveVector, facingRadians, sprinting, airborne, moving }`. When non-null, the WorldCameraRig blends the orbit goal with a chase camera. Follow strength: 0.28 (idle) → 0.82 (moving) → 0.88 (airborne). Sprint widens the chase distance from 4.8 to 5.8 units behind the heading. This already produces a rudimentary FOV-widening effect via the larger chase offset.

**Key recipt fields from `ObservatoryCameraRecipe`:**

```typescript
interface ObservatoryCameraRecipe {
  desiredPosition: [x, y, z]   // orbital goal position
  desiredTarget: [x, y, z]     // look-at goal
  initialPosition: [x, y, z]   // snap-on-mount
  fov: number                  // static; set at Canvas level, not changed per-frame
  arrivalDurationMs: number    // flight animation duration
  arrivalLift: number          // how high the via-point is pushed above the travel arc
  settleRadius: number         // orbital arc amplitude at flight end
  lerpSpeed: number            // exponential smoothing rate in tracking state
  dampingFactor: number        // passed to OrbitControls (0.08)
  minDistance / maxDistance    // zoom limits for OrbitControls
}
```

**Critical constraint:** `fov` is set at the `<Canvas camera={{ fov }}>` level and is static. The WorldCameraRig does not touch FOV at all. Animated FOV requires direct imperatiave writes to `camera.fov` + `camera.updateProjectionMatrix()` inside `useFrame`.

---

## Feature 1: Spawn Fly-by

### What it is

An automated camera path that sweeps the world when the observatory tab first opens, before the user takes control. Typically 3–5 seconds, visiting 2–3 positions, then landing at the default atlas position.

### How to sequence with the existing WorldCameraRig

The WorldCameraRig's in-flight state (`flightRef`) is already a Bezier sweep system. The cleanest approach is to gate WorldCameraRig itself: add a `cinematic` prop that, when truthy, suppresses the normal goal tracking and instead runs a predefined waypoint sequence.

**Pattern:**

```typescript
// In ObservatoryWorldCanvas or ObservatoryTab:
const [flyByComplete, setFlyByComplete] = useState(false);

// Pass flyByComplete to WorldCameraRig
// WorldCameraRig: if (!flyByComplete) run waypoint sequence, else normal tracking
```

Inside WorldCameraRig, a fly-by is a chain of Bezier flights. One `flightRef`-compatible structure handles one leg. Chain multiple legs by listening for `progress >= 1` on the current leg and advancing to the next waypoint index.

**Waypoint definition:**

```typescript
const FLY_BY_WAYPOINTS: Array<{
  position: THREE.Vector3;
  target: THREE.Vector3;
  durationMs: number;
}> = [
  // Start: low sweep from south, looking across the ring
  { position: new THREE.Vector3(28, 8, 28),  target: new THREE.Vector3(0, 2, 0),   durationMs: 1800 },
  // Arc: pull up to the west side
  { position: new THREE.Vector3(-22, 14, 20), target: new THREE.Vector3(0, 3, 0),  durationMs: 1600 },
  // Land: settle into atlas default
  { position: new THREE.Vector3(0, 20.4, 36.8), target: new THREE.Vector3(0, 1.2, 0), durationMs: 1400 },
];
```

Each leg reuses the existing `bezierPoint` + `smoothstep01` machinery. The via-point for each leg is computed with the same lateral-deviation formula already in the rig.

**Hand-off to user control:**

When the final waypoint completes (`waypointIndex === FLY_BY_WAYPOINTS.length - 1` and `progress >= 1`), call `onFlyByComplete()` which sets `flyByComplete = true`. From that frame forward, WorldCameraRig enters normal tracking. OrbitControls zoom is already active throughout; the fly-by does not need to disable user zoom since it writes directly to `controlsRef.object.position`.

**Keyframe path vs Bezier curve:**

Use Bezier (the existing `bezierPoint` function). Keyframe splines (CatmullRom) require a minimum of 4 control points and a different sampling strategy. For 3 waypoints with smooth arc interpolation, quadratic Bezier per leg is simpler and already tested.

**FOV during fly-by:**

Optionally narrow FOV to ~36 during fly-by for a cinematic telephoto feel, widening to 42 at hand-off. This requires animating `camera.fov` — see Feature 2.

**Trigger condition:**

A `hasShownFlyBy` ref (or observatory-store flag) prevents the fly-by from replaying when the tab remounts. Initialize to `false`; set to `true` after first fly-by completes. Use a ref (not state) so it survives re-renders without triggering them.

**frameloop during fly-by:**

`ObservatoryTab` already manages `frameloop: "demand" | "always"`. During fly-by, force `frameloop="always"`. Revert to `"demand"` after hand-off when no probe is active.

---

## Feature 2: Dynamic FOV

### How R3F handles FOV

The `<Canvas camera={{ fov }}>` prop sets the initial FOV. R3F exposes the Three.js camera via the `useThree` hook: `useThree(s => s.camera)`. After mutating `camera.fov`, Three.js requires `camera.updateProjectionMatrix()` to apply the change.

**Pattern inside a `useFrame` component:**

```typescript
useFrame(({ camera }, delta) => {
  const target = isSprinting ? 52 : isScanMode ? 35 : 42;
  const current = (camera as THREE.PerspectiveCamera).fov;
  const next = current + (target - current) * lerpAlpha(4.0, delta);
  (camera as THREE.PerspectiveCamera).fov = next;
  (camera as THREE.PerspectiveCamera).updateProjectionMatrix();
});
```

**Where to put it:**

Add a `FovController` component rendered inside the Canvas alongside WorldCameraRig. It receives `sprinting: boolean` and `probeScan: boolean` props from `playerFocusRef` and `probeState`.

```typescript
function FovController({
  playerFocusRef,
  probeActive,
}: {
  playerFocusRef: RefObject<ObservatoryPlayerFocusState | null>;
  probeActive: boolean;
}) {
  useFrame(({ camera }, delta) => {
    const pCam = camera as THREE.PerspectiveCamera;
    const sprinting = playerFocusRef.current?.sprinting ?? false;
    const targetFov = probeActive ? 35 : sprinting ? 52 : 42;
    pCam.fov += (targetFov - pCam.fov) * lerpAlpha(5.0, delta);
    pCam.updateProjectionMatrix();
  });
  return null;
}
```

**Lerprate:** `lerpAlpha(5.0, delta)` gives roughly a 0.2-second 63% approach — snappy but not instant. Probe scan is a deliberate action so can be slower (`lerpAlpha(3.5, delta)`).

**Interaction with OrbitControls:** OrbitControls does not touch FOV. No conflict.

**Interaction with WorldCameraRig:** WorldCameraRig writes to `position` and `target` only. No conflict with FOV changes.

**Caveat:** `useThree(s => s.camera)` returns the scene's current camera. R3F does not re-create the camera between frames so mutating `fov` is safe and persists. However, if a `<PerspectiveCamera makeDefault>` component is mounted, it will re-apply its `fov` prop and fight the `FovController`. The current code uses `<Canvas camera={{ fov: 42 }}>` without a separate PerspectiveCamera component — no conflict.

---

## Feature 3: Orbit-to-First-Person Transition (Atlas → Flow Mode)

### Current mode toggle

`ObservatoryTab` switches `mode` between `"atlas"` and `"flow"` via a button click. This re-runs `deriveCameraRecipe`, which changes `desiredPosition`, `desiredTarget`, `arrivalDurationMs`, and `lerpSpeed`. The `WorldCameraRig` detects the goal change via `previousGoalRef` and launches a Bezier flight to the new position.

**What this already gives you:** When clicking ATLAS→FLOW, the camera already does a smooth Bezier flight from the atlas vantage (`[0, 20.4, 36.8]`) to the flow vantage (`[0, 16.4, 31.5]`). This is the orbit→chase transition. It is already smooth because `goalChanged` detects the position delta (`distanceToSquared > 0.25`).

**What is missing:** The flight uses the same lateral-deviation arc as a station focus change. For a mode transition, the ideal arc is more dramatic — descend through space rather than arc around the equator. The via-point formula computes lateral as `(-axis.z, 0, axis.x)` which for a front-to-front flight (both positions on the Z axis) produces minimal lateral. The `arrivalLift` in flow mode (3.4) is lower than atlas (4.8), so the arc naturally descends.

**Enhancement if desired:**

For a cinematic descent feel, override the via-point for mode transitions: instead of a horizontal lateral arc, force the midpoint to arc above and toward the core (target the center of the station ring). This is a conditional in WorldCameraRig:

```typescript
if (isModeTransition) {
  // Arc upward through the zenith on ATLAS→FLOW
  viaPosition = fromPosition.clone().lerp(followedPosition, 0.5).setY(fromPosition.y + 8);
  viaTarget = fromTarget.clone().lerp(followedTarget, 0.5);
}
```

Detecting `isModeTransition` requires passing the current mode to WorldCameraRig so it can compare against the previous mode in `previousGoalRef`.

**Orbit vs first-person distinction:**

In atlas mode, `OrbitControls` (zoom only, no rotate/pan) is the user-facing control. In flow mode, `WorldCameraRig` switches to player-follow chase using `playerFocusRef`. There is no separate "first-person" CameraControls — the existing architecture uses OrbitControls in both modes, with WorldCameraRig overriding its position. This is correct and should be preserved.

**If a true first-person view is wanted (inside character head):**

That would require disabling player-follow blend and instead offsetting the camera to `playerFocus.position + [0, 1.62, 0]` (eye height) with no distance. This is a simple addition to WorldCameraRig's tracking state: if `followStrength === 1.0` and a new `firstPerson: boolean` prop is true, set `chasePosition` to the player's eye position. Not currently needed for the workbench Easter-egg scope.

---

## Feature 4: Focus Pull to Mission Objective

### What this is

When a new mission objective becomes active, the camera smoothly pans to the target station's position and holds briefly before returning to tracking behavior.

### How it maps to the existing system

`WorldCameraRig` already does exactly this via the `cameraResetToken` + `desiredPosition/desiredTarget` mechanism. When `deriveObservatoryWorld` returns a new station-focused `ObservatoryCameraRecipe`, `WorldCameraRig` detects `goalChanged` and launches a Bezier flight. The mission system in `ObservatoryTab` already calls `focusCurrentObjective` (via the `observatory:mission:start` window event pattern).

**The existing pattern works without modification:**

1. Mission becomes active → `focusStationId` changes in `deriveCameraRecipe`
2. New `ObservatoryCameraRecipe.desiredPosition` = station-relative position
3. `WorldCameraRig.goalChanged` = true → Bezier flight to station
4. After `arrivalDurationMs`, flight completes → camera lerp-tracks the station goal
5. When objective is completed / focus is cleared → `focusStationId` returns null → flight back to overview

**Enhancement: Cinematic hold:**

Add a `missionFocusDwellMs` (e.g., 1800ms) during which the camera holds on the objective station before returning to tracking. Implement as a `dwellRef: { stationId, expiresAt }` in WorldCameraRig — while `clock.elapsedTime < dwell.expiresAt`, suppress goal change detection even if `desiredPosition` has moved away.

**Integration point:**

`ObservatoryTab` already increments `cameraResetToken` on station selection. The mission wiring is: when `getCurrentObservatoryMissionObjective(mission)` changes, update `activeStationId` prop (or emit a new `cameraResetToken`) to trigger the focus flight.

---

## Feature 5: Screen Shake

### drei CameraShake

`@react-three/drei` v10.7.7 (installed) exports `CameraShake` from `@react-three/drei/core/CameraShake`. The component is:

```typescript
// From node_modules/@react-three/drei/core/CameraShake.js
const CameraShake = React.forwardRef(({
  intensity = 1, decay, decayRate = 0.65,
  maxYaw = 0.1, maxPitch = 0.1, maxRoll = 0.1,
  yawFrequency = 0.1, pitchFrequency = 0.1, rollFrequency = 0.1,
}, ref) => {
  // ...uses SimplexNoise from three-stdlib
  // applies rotation offsets to camera.rotation
  // listens to defaultControls 'change' event to reset initialRotation
});
```

It exposes a `ShakeController` imperative handle: `{ getIntensity, setIntensity }`.

**Key implementation detail:** CameraShake listens to `defaultControls.addEventListener('change', ...)` to keep `initialRotation` updated when controls move the camera. This means it automatically respects OrbitControls movements — the shake is always relative to the controls' current orientation.

**How to trigger probe dispatch shake:**

```typescript
const shakeRef = useRef<ShakeController>(null);

// In ObservatoryTab, on probe dispatch:
const handleProbeDispatch = useCallback(() => {
  dispatchProbe();
  // Signal shake via ref or window event
  window.dispatchEvent(new CustomEvent("observatory:shake", { detail: { intensity: 0.4 } }));
}, [dispatchProbe]);

// Inside Canvas, in a ShakeController component:
useEffect(() => {
  const handler = (e: CustomEvent) => {
    if (shakeRef.current) {
      shakeRef.current.setIntensity(e.detail.intensity);
    }
  };
  window.addEventListener("observatory:shake", handler);
  return () => window.removeEventListener("observatory:shake", handler);
}, []);
```

**Parameters for subtle probe dispatch shake:**

```tsx
<CameraShake
  ref={shakeRef}
  intensity={0}       // starts at 0; set via shakeRef.current.setIntensity()
  decay={true}
  decayRate={0.85}    // fast decay: ~0.3 seconds until negligible
  maxYaw={0.018}
  maxPitch={0.012}
  maxRoll={0.008}
  yawFrequency={0.6}
  pitchFrequency={0.5}
  rollFrequency={0.4}
/>
```

**Parameters for probe landing:**

```tsx
// heavier, slower shake:
maxYaw={0.03}, maxPitch={0.02}, maxRoll={0.015}, decayRate={0.65}
```

**Interaction with OrbitControls:**

CameraShake uses `useThree(state => state.controls)` to get `defaultControls`. OrbitControls is not `makeDefault` in the current code — `controlsRef` is passed manually, not via `makeDefault`. This means `CameraShake` will find `state.controls === null` and will not subscribe to change events, so `initialRotation` will be stale.

**Fix:** Add `makeDefault` to OrbitControls:

```tsx
<OrbitControls
  ref={controlsRef as never}
  makeDefault            // ← add this
  enableRotate={false}
  ...
/>
```

With `makeDefault`, R3F stores the OrbitControls instance in `state.controls`, and CameraShake picks it up automatically.

**Alternative (no makeDefault needed):**

Implement shake manually inside WorldCameraRig using `SimplexNoise` from `three-stdlib` (already a transitive dep via drei). A `shakeIntensityRef` passed from outside; WorldCameraRig adds the noise offset to the final position before `controls.object.position.copy()`. This avoids any interaction issues with OrbitControls' change event subscription.

```typescript
// Inside WorldCameraRig useFrame, at the end of each code path:
if (shakeIntensityRef.current > 0.001) {
  const shake = shakeIntensityRef.current ** 2;
  controls.object.position.x += yawNoise.noise(clock.elapsedTime * 0.6, 1) * 0.03 * shake;
  controls.object.position.y += pitchNoise.noise(clock.elapsedTime * 0.5, 1) * 0.02 * shake;
  shakeIntensityRef.current *= Math.exp(-8 * delta); // exponential decay
}
```

**Recommendation:** Use drei CameraShake with `makeDefault` on OrbitControls. This is the cleaner solution — fewer lines, declarative API, already in the dep tree. The `makeDefault` change is safe because OrbitControls is the only controls component in the scene.

---

## Feature 6: Letterbox Bars

### CSS overlay vs R3F

**CSS overlay is the correct choice.** Letterbox bars are a DOM-layer concern — they do not need to be part of the 3D scene. The `ObservatoryTab` already has a `relative` container with absolute-positioned overlays (`ObservatoryProbeHud`, `ObservatoryMissionHud`, the mode toggle button).

**Pattern:**

```tsx
// In ObservatoryTab, during fly-by:
{flyByActive && (
  <>
    <div
      className="absolute top-0 left-0 right-0 z-20 pointer-events-none transition-all duration-500"
      style={{ height: letterboxHeight, background: "#000" }}
    />
    <div
      className="absolute bottom-0 left-0 right-0 z-20 pointer-events-none transition-all duration-500"
      style={{ height: letterboxHeight, background: "#000" }}
    />
  </>
)}
```

Where `letterboxHeight` transitions from `0px` → `48px` (on fly-by start) → `0px` (on hand-off). CSS `transition-all duration-500` handles the animation.

**Tailwind alternative:**

```tsx
<div className={cn(
  "absolute top-0 left-0 right-0 z-20 pointer-events-none bg-black transition-all duration-700",
  flyByActive ? "h-12" : "h-0",
)} />
```

**R3F alternative (not recommended):**

A letterbox effect in R3F would require a full-screen quad with black material and a scissor/viewport trick, or a post-processing pass via `@react-three/postprocessing`. This is significantly more complex for zero visual benefit — the CSS version looks identical and has better browser support.

**Timing:**

- Fly-by starts → `flyByActive = true` → bars animate in (500ms CSS transition)
- Fly-by ends (hand-off to user control) → `flyByActive = false` → bars animate out (500ms)
- Optional: add a `cinematicText` string that appears in the bottom bar during fly-by (e.g., "CLAWDSTRIKE WORKBENCH — SECURITY OBSERVATORY"). Same CSS overlay, `opacity: flyByActive ? 1 : 0` transition.

---

## Integration Architecture

### What to add to ObservatoryCameraRecipe

```typescript
// Addition to ObservatoryCameraRecipe (deriveObservatoryWorld.ts):
interface ObservatoryCameraRecipe {
  // existing fields...
  flyByEnabled?: boolean;      // true on first mount only
  missionFocusDwellMs?: number; // how long to dwell on objective before returning
}
```

### New components inside the Canvas

| Component | Props | Purpose |
|-----------|-------|---------|
| `FovController` | `playerFocusRef`, `probeActive` | Sprint/scan FOV animation |
| `CameraShake` (drei) | `ref={shakeRef}`, `intensity={0}`, `decay` | Probe shake |

Both render `null` and exist purely for `useFrame` effects.

### State changes in ObservatoryTab

```typescript
// Add:
const [flyByActive, setFlyByActive] = useState(true);  // true = bars shown
const flyByDoneRef = useRef(false);                      // prevents replay on remount
const shakeRef = useRef<ShakeController>(null);

// In handleProbeDispatch:
shakeRef.current?.setIntensity(0.4);  // dispatch shake

// WorldCameraRig callback:
const handleFlyByComplete = useCallback(() => {
  flyByDoneRef.current = true;
  setFlyByActive(false);       // bars animate out
  setFrameloop("demand");      // revert to demand rendering
}, []);
```

### Props flow

```
ObservatoryTab
  ↓ flyByActive → CSS letterbox bars (DOM layer)
  ↓ shakeRef → passed into WorldScene → CameraShake
  ↓ flyByDoneRef → passed into WorldCameraRig as flyByComplete
  ↓ probeActive → passed into FovController
  ↓ playerFocusRef → passed into FovController + WorldCameraRig (already wired)
```

---

## Implementation Order

These six features are mostly independent. Recommended build order by value/effort ratio:

1. **Dynamic FOV (Feature 2)** — ~30 lines, pure `useFrame`, high visual impact for sprint + probe scan. No architectural changes.

2. **Screen Shake (Feature 5)** — add `makeDefault` to OrbitControls + mount `CameraShake` + wire probe dispatch. ~50 lines. Immediate tactile feedback.

3. **Letterbox bars (Feature 6)** — ~25 lines CSS + state flag. Zero risk, ships standalone.

4. **Spawn fly-by (Feature 1)** — requires adding waypoint sequencing to WorldCameraRig. ~100 lines. Depends on letterbox bars being done (they frame the fly-by visually).

5. **Focus pull to mission objective (Feature 4)** — mostly free because the Bezier system already handles it. Add `missionFocusDwellMs` dwell logic (~40 lines) and connect to the `missionLoop.ts` port from OBSERVATORY-NEXT.md Feature 3.

6. **Orbit-to-first-person transition (Feature 3)** — detect mode transition in WorldCameraRig and override the via-point for a more dramatic descent arc (~25 lines). Ship last as a polish pass.

---

## Pitfalls

### FOV mutation without updateProjectionMatrix

**What goes wrong:** `camera.fov = 52` has no visual effect until `camera.updateProjectionMatrix()` is called. The frame will render with the old FOV.

**Prevention:** Always pair the assignment:
```typescript
pCam.fov = next;
pCam.updateProjectionMatrix();
```

### CameraShake + OrbitControls without makeDefault

**What goes wrong:** `CameraShake` sources `initialRotation` from a `defaultControls.addEventListener('change', ...)` subscription. If OrbitControls is not `makeDefault`, `state.controls` is null, the subscription never fires, and `initialRotation` is set once on mount and never updated. When OrbitControls moves the camera (zoom), the shake rotation offset is computed against a stale base rotation, causing visible snapping or drift.

**Prevention:** Add `makeDefault` to the single `<OrbitControls>` component in `ObservatoryWorldCanvas`. This is safe because there is only one controls component in the scene.

### Fly-by replaying on tab remount

**What goes wrong:** `flyByActive` is `useState(true)` — if the tab unmounts and remounts (user switches panes), the fly-by fires again.

**Prevention:** Gate on `flyByDoneRef.current`. Initialize `flyByDoneRef` in `ObservatoryTab` (not in WorldCameraRig), and check it before launching the fly-by sequence. A `useRef` persists across renders but resets on unmount — if survival across unmount is desired, move `flyByDone` to `observatory-store`.

### Bezier via-point NaN on zero-travel legs

**What goes wrong:** When `travelDistance ≈ 0` (camera is already at the goal), the `axis.normalize()` call produces `NaN` components, corrupting the via-point, causing the camera to jump to `(NaN, NaN, NaN)`.

**Prevention:** Guard with `if (travelDistance < 0.1) { skip flight, just snap to goal }`. The existing WorldCameraRig code already checks `distanceToSquared > 0.25` before launching a flight, but explicit fly-by waypoints should include the same guard.

### FOV lerp overshooting

**What goes wrong:** If `lerpAlpha` is too high (lerpSpeed > 10), the exponential decay overshoots on high-delta frames (e.g., first frame after tab focus). This produces a momentary FOV flicker.

**Prevention:** Clamp `delta` to a max of `1/20` seconds before feeding it to `lerpAlpha`:
```typescript
const safeDelta = Math.min(delta, 1 / 20);
```
This pattern is already used in three.js-based character controllers for the same reason.

### Letterbox bars occluding HUD elements

**What goes wrong:** The probe HUD, mission HUD, and mode toggle button are `z-10` in the current layout. Letterbox bars at `z-20` will cover them during fly-by.

**Prevention:** Either keep bars at a lower z-index than HUD overlays, or hide HUD elements during fly-by (simplest: `{!flyByActive && <ObservatoryMissionHud ... />}`).

---

## Confidence Assessment

| Feature | Confidence | Reason |
|---------|------------|--------|
| Dynamic FOV | HIGH | `camera.fov + updateProjectionMatrix()` is standard Three.js; no R3F surprises |
| Screen shake | HIGH | Read drei CameraShake source; makeDefault interaction confirmed in source |
| Letterbox bars | HIGH | Pure CSS overlay; no R3F involvement |
| Spawn fly-by | HIGH | Bezier system already in WorldCameraRig; sequencing is additive |
| Mode transition arc | HIGH | WorldCameraRig goalChanged path is well-understood; via-point override is simple |
| Focus pull | HIGH | Already works via existing Bezier + station focus; dwell is additive |

---

## Open Questions

1. **Should `flyByDone` survive tab close/reopen?** If yes, move to `observatory-store`. If no, keep as `useRef` in `ObservatoryTab`. The "observatory feels fresh each session" argument favors a store flag; "don't repeat the intro" favors tab lifetime only.

2. **Probe dispatch vs probe landing shake timing.** The probe state machine in `ObservatoryTab` has `probeState.status: "ready" | "active" | "cooldown"`. Dispatch shake should fire when `status` transitions to `"active"`. Landing shake should fire on `"active" → "cooldown"` transition. Both can be detected in a `useEffect([probeState.status])` in `ObservatoryTab` using the previous-status pattern.

3. **FOV during fly-by.** Should the fly-by start at a narrower FOV (e.g., 36) and widen to 42 at hand-off, or stay at 42 throughout? Narrowing → widening adds cinematic feel but requires `FovController` to also handle a `flyByActive` prop.

4. **Sprint FOV in atlas mode.** `playerFocusRef.current` is only non-null when the character controller Easter-egg is active (`characterControllerEnabled = true`). In atlas mode with no player, `sprinting` is always false. The FOV controller correctly handles this — `sprinting = playerFocusRef.current?.sprinting ?? false` defaults to no sprint. No action needed.
