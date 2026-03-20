# Phase 21: Flight Controller - Context

**Gathered:** 2026-03-20
**Status:** Ready for planning

<domain>
## Phase Boundary

Replace the ground-based Rapier walking controller with a velocity+quaternion space flight controller. Ship mesh replaces capsule avatar. WASD+mouse input, damping, three speed tiers (cruise/boost/dock), chase camera with lerp lag, thruster particle VFX. Atlas mode (OrbitControls) remains for overview analysis — flight activates in flow mode.

</domain>

<decisions>
## Implementation Decisions

### Ship Mesh Design
- Geometric low-poly ship built from Three.js primitives (no GLB) — matches station geometry style
- Ship ~3 units long (stations are 4-8 unit radius) — visible but not oversized relative to stations
- 2-4 cone+cylinder thruster nozzles on the rear — give VFX anchor points for exhaust
- Spirit accent color tint on hull with white/gray base — ties ship visually to bound spirit
- Ship mesh component: `ShipMesh` in a new file `observatory/character/ship/ShipMesh.tsx`

### Flight Model Parameters
- Pure velocity-based (no Rapier, no gravity) — position += velocity * delta each frame
- Quaternion rotation for pitch/yaw — avoids gimbal lock for full 3D orientation
- Damping factor: 1.5 (velocity *= (1 - damping * delta)) — "space submarine" feel, responsive but not twitchy
- Cruise speed cap: 40 units/s — crosses the 300-unit station gap in ~7.5s, purposeful pace
- Boost: 3x speed (120 units/s) for 2s duration, 4s cooldown before next boost — dramatic but not spammable
- Dock approach: speed auto-caps to 8 units/s within 50 units of any station — precision approach
- Thrust acceleration: ~60 units/s² — reaches cruise speed in ~0.7s, feels snappy
- Flight controller state: new Zustand slice or store for velocity, quaternion, speed tier, boost cooldown

### Input Mapping
- PointerLockControls on canvas click — mouse controls pitch/yaw while locked, ESC to release
- W = forward thrust along ship's local forward vector
- S = brake (reverse thrust if already stopped)
- A/D = strafe left/right (not yaw — yaw is mouse)
- Space = vertical thrust up
- Shift = vertical thrust down
- Boost = double-tap W within 300ms window — feels like a lunge, no extra key needed
- E = interact (dock when in dock zone) — reuses existing interact binding
- Keyboard input only active when observatory pane is focused (existing pitfall 5 pattern)

### Activation & Mode Switching
- FlowModeController.tsx is REPLACED by SpaceFlightController.tsx — Rapier walking is removed
- Atlas mode (OrbitControls) remains for overview analysis — no ship visible in atlas
- Flow mode = flight mode — ship appears, chase camera activates, WASD+mouse active
- Mode toggle: same double-click mechanism as current FlowModeController
- Transition: smooth camera lerp from orbit position to chase camera offset on mode switch (~0.8s)
- Default on observatory open: atlas mode (preserves current analyst workflow)

### Chase Camera
- Offset: (0, 4, 14) in ship's local space — behind and above
- Lerp follow factor: 0.07 — smooth lag, ship leads camera
- Look-at target: ship position + slight forward offset — camera anticipates where ship is heading
- FOV: 60 default, 90 during boost (existing FovController pattern can be extended)

### Thruster VFX
- wawa-vfx stretchBillboard particles from thruster nozzle positions
- Idle: no exhaust
- Cruise thrust: 4-8 particles per cycle, orange/blue color matching spirit accent
- Boost: 20+ particles, stretched longer, brighter, wider spread
- Particle lifetime: 0.3-0.6s — short trails, not persistent

### Claude's Discretion
- Exact ship geometry dimensions and proportions
- Quaternion rotation speed (pitch/yaw sensitivity)
- Exact lerp formulas for camera smoothing
- How to handle edge cases (ship at world boundary, boost while docking)
- Whether to add roll (Q/E or auto-roll during turns)

</decisions>

<canonical_refs>
## Canonical References

**Downstream agents MUST read these before planning or implementing.**

### Existing flight/character system (being replaced)
- `apps/workbench/src/features/observatory/components/FlowModeController.tsx` — Current Rapier-based controller (being replaced with SpaceFlightController)
- `apps/workbench/src/features/observatory/character/input/useObservatoryPlayerInput.ts` — Existing WASD input hook (extend for mouse/flight)
- `apps/workbench/src/features/observatory/character/types.ts` — PlayerIntent, PlayerKeyState, bindings, spawn constants
- `apps/workbench/src/features/observatory/character/controller/useObservatoryPlayerRuntime.ts` — Existing runtime step loop (reference pattern, will be replaced)

### Canvas and scene integration
- `apps/workbench/src/features/observatory/components/ObservatoryWorldCanvas.tsx` — Main canvas, imports FlowModeController lazily, FovController, chase camera integration point
- `apps/workbench/src/features/observatory/components/ObservatoryTab.tsx` — characterControllerEnabled state, mode toggle, pane focus gating

### VFX system
- `apps/workbench/src/features/observatory/vfx/ProbeDischargeVFX.tsx` — Existing wawa-vfx pattern (VFXEmitter usage)
- `apps/workbench/src/features/observatory/components/world-canvas/ObservatoryWorldScene.tsx` — Where VFX pools are mounted

### World scale (from Phase 20)
- `apps/workbench/src/features/observatory/world/stations.ts` — WORLD_RADIUS=300, station positions, elevationY values
- `apps/workbench/src/features/observatory/world/observatory-world-template.ts` — stationPosition() for dock approach distance checks

</canonical_refs>

<code_context>
## Existing Code Insights

### Reusable Assets
- `useObservatoryPlayerInput` — WASD key handling, enabled/disabled gating, intent derivation. Extend with mouse delta for pitch/yaw.
- `FovController` in ObservatoryWorldCanvas — already lerps FOV based on sprint/probe state. Extend with boost FOV.
- `wawa-vfx` VFXEmitter/VFXParticles — already used for probe discharge and character VFX. Reuse for thruster exhaust.
- `lerpAlpha()` utility — already used for smooth interpolation in camera and FOV code.
- `getObservatoryNowMs()` — timestamp utility for cooldown tracking.

### Established Patterns
- Lazy-loaded components via React.lazy (FlowModeController pattern) — SpaceFlightController should follow same pattern
- `useFrame` with ref-based mutation (no setState) — all flight loop code must follow this
- `useRef` for all per-frame state (position, velocity, quaternion) — never React state
- characterControllerEnabled boolean gating in ObservatoryWorldCanvas — reuse for flight controller

### Integration Points
- ObservatoryWorldCanvas renders `<LazyObservatoryFlowRuntimeScene>` when characterControllerEnabled=true — swap to `<LazySpaceFlightController>`
- ObservatoryTab manages characterControllerEnabled state + double-click toggle
- FovController reads playerFocusRef — flight controller should write to same ref pattern
- ObservatoryPlayerAvatar in character/avatar/ — replace with ShipMesh

</code_context>

<specifics>
## Specific Ideas

- Flight should feel like Elite Dangerous with "flight assist on" — damping makes it controllable, not floaty
- The ship should be immediately recognizable as "yours" — spirit accent color makes it personal
- Boost should feel dramatic — FOV punch + particle burst + speed rush, like NOS in a racing game
- The transition from atlas to flight mode should be cinematic — smooth camera sweep, not a hard cut

</specifics>

<deferred>
## Deferred Ideas

- Docking mechanics (approach/magnet/dock) — Phase 23 (DCK-01 through DCK-04)
- Ship HUD elements (speed bar, heading) — Phase 24 (HUD-01 through HUD-06)
- Warp speed lines during boost — Phase 25 (TRN-02)
- Autopilot navigation — Phase 25 (MAP-03)
- Ship customization / spirit appearance changes — v7.0 (SHIP-01, SHIP-02)

</deferred>

---

*Phase: 21-flight-controller*
*Context gathered: 2026-03-20 via smart discuss (auto mode)*
