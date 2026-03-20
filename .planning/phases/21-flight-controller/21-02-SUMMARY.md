---
phase: 21-flight-controller
plan: "02"
subsystem: ui
tags: [react-three-fiber, three-js, quaternion, pointer-lock, useFrame, flight-controller, space-flight]

# Dependency graph
requires:
  - phase: 21-01
    provides: "FlightConfig/FlightState/FlightIntent types, DEFAULT_FLIGHT_CONFIG, ShipMesh, observatory store flight slice"
provides:
  - "useFlightInput hook: keyboard+mouse → FlightIntent ref (no re-renders)"
  - "useFlightLoop hook: velocity+quaternion physics with damping each frame"
  - "SpaceFlightController component: ShipMesh + flight loop + playerFocusRef bridge"
  - "ObservatoryFlowRuntimeScene: Rapier bootstrap replaced with SpaceFlightController"
  - "FovController: FOV 60 at rest, 90 during boost (per CONTEXT.md)"
affects: [22-camera-system, 23-speed-tiers, 24-thruster-vfx, 25-hud-overlay]

# Tech tracking
tech-stack:
  added: []
  patterns:
    - "Flight input uses ref-only mutation (no setState) — intentRef consumed by useFrame with zero GC pressure"
    - "Module-level scratch THREE objects pre-allocated once, reused every frame"
    - "Pointer lock: document.body.requestPointerLock() on canvas click via gl.domElement listener"
    - "Store snapshot throttled to 100ms to avoid per-frame setState calls"
    - "ObservatoryFlowRuntimeScene acts as lazy-load boundary — Rapier never imported in main bundle"

key-files:
  created:
    - apps/workbench/src/features/observatory/character/ship/useFlightInput.ts
    - apps/workbench/src/features/observatory/character/ship/useFlightLoop.ts
    - apps/workbench/src/features/observatory/character/ship/SpaceFlightController.tsx
  modified:
    - apps/workbench/src/features/observatory/components/ObservatoryFlowRuntimeScene.tsx
    - apps/workbench/src/features/observatory/components/ObservatoryTab.tsx
    - apps/workbench/src/features/observatory/components/ObservatoryWorldCanvas.tsx
    - apps/workbench/src/features/observatory/__tests__/observatory-flow-runtime-scene.test.tsx
    - apps/workbench/src/features/observatory/__tests__/observatory-world-canvas.performance.test.tsx

key-decisions:
  - "useFlightInput uses a Set<string> ref for pressed keys (not state) to avoid re-renders on every keydown/keyup"
  - "Yaw applies via quaternion.premultiply (world-Y), pitch via quaternion.multiply (local-X) — no gimbal lock"
  - "Velocity damping: v *= max(0, 1 - dampingFactor * dt) gives smooth coast-to-stop; dampingFactor=1.5"
  - "Thrust normalizes the combined axis vector before scaling by thrustAcceleration to prevent diagonal speed boost"
  - "Delta clamped to 1/20s to prevent huge jumps after tab-unfocus"
  - "ObservatoryFlowRuntimeScene preserves original props interface — WorldCanvas call site unchanged"
  - "Tests updated: mocked SpaceFlightController instead of ObservatoryFlowPhysicsBootstrap; assertions updated from enableCharacterVfx to inputEnabled"

patterns-established:
  - "Flight hooks: useFlightInput for input accumulation, useFlightLoop for physics — separate concerns"
  - "playerFocusRef bridging: SpaceFlightController translates FlightState to ObservatoryPlayerFocusState so existing camera/FOV systems work without changes"
  - "Lazy module boundary: ObservatoryFlowRuntimeScene is the import wall — Rapier and SpaceFlightController are both lazy"

requirements-completed: [FLT-02, FLT-03]

# Metrics
duration: 7min
completed: 2026-03-20
---

# Phase 21 Plan 02: Flight Controller Core Summary

**Keyboard+mouse flight controller with quaternion rotation, velocity damping, and pointer lock — replaces Rapier walking controller with pure velocity-based space flight**

## Performance

- **Duration:** ~7 min
- **Started:** 2026-03-20T17:08:27Z
- **Completed:** 2026-03-20T17:15:26Z
- **Tasks:** 2
- **Files modified:** 8

## Accomplishments

- `useFlightInput.ts`: WASD/arrows/Space/Shift/E keyboard input + pointer-locked mouse delta → `FlightIntent` ref (zero re-renders in the frame loop)
- `useFlightLoop.ts`: useFrame physics loop applying quaternion yaw+pitch rotation, thrust in ship-local axes, velocity damping, and speed cap with 100ms throttled store snapshots
- `SpaceFlightController.tsx`: Renders `ShipMesh`, wires input+physics hooks, bridges `FlightState` → `ObservatoryPlayerFocusState` for existing camera/FOV systems, acquires pointer lock on canvas click
- `ObservatoryFlowRuntimeScene.tsx`: Rapier `ObservatoryFlowPhysicsBootstrap` replaced with lazy `SpaceFlightController`; existing call site in WorldCanvas unchanged
- `FovController`: Updated to FOV 60 (rest) / 90 (boost) per CONTEXT.md chase camera spec
- All 209 observatory tests pass

## Task Commits

Each task was committed atomically:

1. **Task 1: useFlightInput hook + useFlightLoop physics** - `6261fb56a` (feat)
2. **Task 2: SpaceFlightController + scene integration** - `7b4b8bc70` (feat)

## Files Created/Modified

- `apps/workbench/src/features/observatory/character/ship/useFlightInput.ts` - Keyboard+mouse input hook producing FlightIntent ref; boost double-tap detection; pointer lock tracking
- `apps/workbench/src/features/observatory/character/ship/useFlightLoop.ts` - useFrame physics loop with quaternion rotation, thrust acceleration, damping, speed cap
- `apps/workbench/src/features/observatory/character/ship/SpaceFlightController.tsx` - Component bridging input+physics hooks to ShipMesh; playerFocusRef bridge for FovController
- `apps/workbench/src/features/observatory/components/ObservatoryFlowRuntimeScene.tsx` - Rewired to lazy-load SpaceFlightController; Rapier dependency removed
- `apps/workbench/src/features/observatory/components/ObservatoryTab.tsx` - Notification text: "Flight controls activated/deactivated"
- `apps/workbench/src/features/observatory/components/ObservatoryWorldCanvas.tsx` - FovController FOV: probe=35, boost=90, rest=60
- `apps/workbench/src/features/observatory/__tests__/observatory-flow-runtime-scene.test.tsx` - Updated to mock SpaceFlightController
- `apps/workbench/src/features/observatory/__tests__/observatory-world-canvas.performance.test.tsx` - Updated mock path and prop assertions

## Decisions Made

- Input uses `useRef` not `useState` — keyboard events fire 60Hz+, state updates would trigger cascading re-renders in the R3F tree
- Yaw uses `quaternion.premultiply` (world-Y rotation applied before current orientation), pitch uses `quaternion.multiply` (local-X rotation applied after) — this gives standard FPS-style feel with no gimbal lock
- Velocity damping guard: `Math.max(0, 1 - dampingFactor * dt)` prevents negative multiplier at low framerates
- Thrust direction normalize only runs if `thrustLength > 0.0001` (guards zero-vector normalize that would produce NaN)
- `ObservatoryFlowRuntimeScene` accepts the full `ObservatoryFlowRuntimeSceneProps` but only forwards `inputEnabled` and `playerFocusRef` to `SpaceFlightController` — extra props discarded silently (world, heroProps not needed for flight)

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 1 - Bug] Test suite updated after Rapier bootstrap replaced**
- **Found during:** Task 2 (SpaceFlightController integration)
- **Issue:** `observatory-flow-runtime-scene.test.tsx` mocked `ObservatoryFlowPhysicsBootstrap` and expected `data-testid="flow-physics-bootstrap"`. `observatory-world-canvas.performance.test.tsx` checked `enableCharacterVfx` prop. Both tests were testing old Rapier behavior that no longer exists.
- **Fix:** Updated mocks to target `SpaceFlightController`; replaced `enableCharacterVfx` assertions with `inputEnabled` assertions; replaced `flow-physics-bootstrap` testid with `space-flight-controller`
- **Files modified:** `observatory-flow-runtime-scene.test.tsx`, `observatory-world-canvas.performance.test.tsx`
- **Verification:** All 209 observatory tests pass
- **Committed in:** `7b4b8bc70` (Task 2 commit)

---

**Total deviations:** 1 auto-fixed (Rule 1 — test sync)
**Impact on plan:** Necessary — tests were asserting Rapier behavior that no longer exists. Updated assertions now correctly describe the SpaceFlightController interface.

## Issues Encountered

- Import path in `SpaceFlightController.tsx` initially used `../../../features/observatory/...` (wrong relative depth). Caught by first TypeScript check and fixed immediately.

## Next Phase Readiness

- Flight core is live: analyst can double-click canvas to enable, click to lock pointer, fly with WASD+mouse
- Plan 03 can layer speed tier logic (boost double-tap → `boostTriggered` already in `FlightIntent`)
- Plan 04 camera (chase/cockpit modes) can read `playerFocusRef.current` which is now populated by `SpaceFlightController`
- `SHIP_THRUSTER_LAYOUT` nozzle positions are in `flight-types.ts` ready for Plan 06 thruster VFX

---
*Phase: 21-flight-controller*
*Completed: 2026-03-20*

## Self-Check: PASSED

- useFlightInput.ts: FOUND
- useFlightLoop.ts: FOUND
- SpaceFlightController.tsx: FOUND
- 21-02-SUMMARY.md: FOUND
- commit 6261fb56a: FOUND
- commit 7b4b8bc70: FOUND
