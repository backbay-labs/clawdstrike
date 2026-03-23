---
phase: 42-replay-annotation-canvas
plan: 01
subsystem: ui
tags: [r3f, three.js, drei, observatory, replay, annotations, 3d]

requires:
  - phase: 39-store-persistence-derivation
    provides: annotationPins store slice with addAnnotationPin/removeAnnotationPin actions
  - phase: 41-constellation-routes-spirit-trails
    provides: prop threading pattern through ObservatoryWorldCanvas -> ObservatoryWorldScene

provides:
  - ReplayAnnotationLayer R3F component with diamond pin geometry, ground-plane click-to-drop, drei Html glassmorphism edit overlay, and drei Text labels
  - ObservatoryWorldSceneProps extended with annotationPins / replayEnabled / replayFrameIndex / replayFrameMs / onAnnotationDrop
  - Full prop chain: store -> ObservatoryWorldCanvas -> ObservatoryWorldScene -> ReplayAnnotationLayer
  - handleAnnotationDrop callback constructing ObservatoryAnnotationPin from replay state

affects:
  - 42-replay-annotation-canvas (later plans in this phase build on this layer)
  - ObservatoryWorldScene prop interface consumers

tech-stack:
  added: []
  patterns:
    - "TDD RED/GREEN: test file committed before implementation, verified failing then passing"
    - "Remove+add pattern for note update (no upsert action exists in store)"
    - "Invisible PlaneGeometry(200,200) ground plane for click-to-drop with replayEnabled guard on onPointerDown"
    - "Diamond pin = two ConeGeometry(0.25, 0.5, 6) meshes tip-to-tip in a group"
    - "Glassmorphism edit overlay via drei Html with CSS variable references (--hud-bg, --hud-border, --hud-blur)"

key-files:
  created:
    - apps/workbench/src/features/observatory/components/world-canvas/ReplayAnnotationLayer.tsx
    - apps/workbench/src/features/observatory/__tests__/replay-annotation-layer.test.tsx
  modified:
    - apps/workbench/src/features/observatory/components/world-canvas/observatory-world-scene-types.ts
    - apps/workbench/src/features/observatory/components/world-canvas/ObservatoryWorldScene.tsx
    - apps/workbench/src/features/observatory/components/ObservatoryWorldCanvas.tsx

key-decisions:
  - "depthTest is not a valid prop on drei Text — removed; labels rely on natural draw order instead"
  - "vi.mock factory must use locally-declared vi.fn() instead of top-level variables (hoisting restriction)"
  - "Three mock needs class-style constructor for MeshBasicMaterial (not plain object) to pass `new` operator"
  - "SpiritResonanceConnections.tsx type error is pre-existing (confirmed via git stash) — deferred per out-of-scope rule"

patterns-established:
  - "R3F scene layers accept annotationPins prop array + onDropPin callback; parent constructs full pin object and calls store"
  - "Edit overlay local state (editingPinId) lives in ReplayAnnotationLayer — no store state needed for transient UI"

requirements-completed: [ANNO-01, ANNO-02, ANNO-06]

duration: 5min42s
completed: 2026-03-22
---

# Phase 42 Plan 01: Replay Annotation Canvas Summary

**R3F ReplayAnnotationLayer with diamond pin geometry, glassmorphism Html edit overlay, and full prop chain from observatory store through ObservatoryWorldCanvas to scene**

## Performance

- **Duration:** 5 min 42s
- **Started:** 2026-03-22T23:25:13Z
- **Completed:** 2026-03-22T23:30:55Z
- **Tasks:** 2 (TDD: 3 commits for Task 1)
- **Files modified:** 5

## Accomplishments

- Created `ReplayAnnotationLayer.tsx` with diamond pins (two ConeGeometry tip-to-tip), invisible 200×200 ground plane for click-to-drop, drei Html glassmorphism overlay for editing/delete, and drei Text floating labels
- Extended `ObservatoryWorldSceneProps` with 5 new annotation props and mounted the layer after `SpiritResonanceConnections`
- Threaded annotationPins from store through `ObservatoryWorldCanvas` → `ObservatoryWorldScene` → `ReplayAnnotationLayer` with `handleAnnotationDrop` callback that constructs full `ObservatoryAnnotationPin` objects

## Task Commits

Each task was committed atomically:

1. **Task 1 RED: Failing tests** - `69d546e07` (test)
2. **Task 1 GREEN: ReplayAnnotationLayer implementation** - `8dfc95598` (feat)
3. **Task 2: Prop threading and scene mount** - `27ec73b25` (feat)

_Note: TDD RED phase committed before implementation (test → feat pattern)_

## Files Created/Modified

- `apps/workbench/src/features/observatory/components/world-canvas/ReplayAnnotationLayer.tsx` — R3F layer component: diamond pins, ground plane, Html overlay, Text labels
- `apps/workbench/src/features/observatory/__tests__/replay-annotation-layer.test.tsx` — 5 tests covering render, pin count, ConeGeometry, replayEnabled guard, store wiring
- `apps/workbench/src/features/observatory/components/world-canvas/observatory-world-scene-types.ts` — Added 5 annotation props + ObservatoryAnnotationPin import
- `apps/workbench/src/features/observatory/components/world-canvas/ObservatoryWorldScene.tsx` — Destructures new props, imports and mounts ReplayAnnotationLayer
- `apps/workbench/src/features/observatory/components/ObservatoryWorldCanvas.tsx` — Selects annotationPins + replayState from store, adds handleAnnotationDrop, passes to scene

## Decisions Made

- `depthTest` is not a valid prop on drei `Text` (it's a mesh prop, not a text prop) — removed from the label element; labels remain readable via natural draw order
- Three.js mock in tests must use a class constructor for `MeshBasicMaterial` not a plain object, since the component does `new THREE.MeshBasicMaterial(...)`
- `vi.mock` factory functions are hoisted before variable declarations; store mock must declare its own `vi.fn()` instances internally

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 1 - Bug] Fixed vi.mock hoisting: moved mock functions inside factory**
- **Found during:** Task 1 (TDD RED → GREEN)
- **Issue:** `vi.mock` factories are hoisted to top of file, but `mockAddAnnotationPin` was declared as a top-level variable — caused "Cannot access before initialization" error
- **Fix:** Declared `addAnnotationPin` and `removeAnnotationPin` as `vi.fn()` inside the factory closure
- **Files modified:** replay-annotation-layer.test.tsx
- **Verification:** Test suite passes (5/5)
- **Committed in:** 8dfc95598 (Task 1 GREEN commit)

**2. [Rule 1 - Bug] Fixed Three mock: MeshBasicMaterial needs class constructor**
- **Found during:** Task 1 (TDD GREEN)
- **Issue:** `MeshBasicMaterial: vi.fn(() => mockMaterial)` returns a plain object, but `new THREE.MeshBasicMaterial()` requires a real constructor — threw "not a constructor" TypeError
- **Fix:** Changed to `class MeshBasicMaterial { constructor(_opts?) { ... } }`
- **Files modified:** replay-annotation-layer.test.tsx
- **Verification:** Test suite passes (5/5)
- **Committed in:** 8dfc95598 (part of fix iteration)

**3. [Rule 1 - Bug] Removed `depthTest` prop from drei Text**
- **Found during:** Task 2 (TypeScript verification)
- **Issue:** `depthTest` is not a valid prop on `@react-three/drei` `<Text>` — type error from tsc
- **Fix:** Removed `depthTest={false}` from Text element; labels remain visible via draw order
- **Files modified:** ReplayAnnotationLayer.tsx
- **Verification:** `npx tsc --noEmit` passes for our new files
- **Committed in:** 27ec73b25

---

**Total deviations:** 3 auto-fixed (all Rule 1 bugs)
**Impact on plan:** All auto-fixes required for correctness or TypeScript compilation. No scope creep.

## Issues Encountered

- Pre-existing TypeScript error in `SpiritResonanceConnections.tsx` (Ref type mismatch) — confirmed pre-existing via `git stash` test, logged to deferred issues per scope boundary rule. Does not affect our new code.

## Next Phase Readiness

- `ReplayAnnotationLayer` is fully mounted and wired; analysts can drop, edit, and delete pins during replay
- Phase 42 Plan 02 can build on this foundation to add pin persistence, timeline integration, and export

---
*Phase: 42-replay-annotation-canvas*
*Completed: 2026-03-22*
