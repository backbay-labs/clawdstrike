---
phase: 42-replay-annotation-canvas
plan: "02"
subsystem: ui
tags: [react, zustand, three.js, r3f, localStorage, observatory, replay, annotations]

requires:
  - phase: 42-01
    provides: ObservatoryAnnotationPin type + store actions (addAnnotationPin, removeAnnotationPin, clearAnnotationPins) + ReplayAnnotationLayer 3D scene component

provides:
  - Annotations section in ReplayDrawerPanel with scrollable pin list (sorted by frameIndex), diamond icon, note text, frame label, and delete button
  - Jump-to-frame + camera focus on pin row click (dispatches observatory:camera-focus custom event)
  - Annotation pin persistence via localStorage v2 (hydrate on mount, auto-save on change)
  - Camera focus event listener in ObservatoryWorldScene snaps OrbitControls target to pin worldPosition

affects:
  - 42-03 (if any): downstream annotation features
  - Phase 43: station interior geometry

tech-stack:
  added: []
  patterns:
    - observatory:camera-focus CustomEvent dispatch from drawer → scene event listener pattern
    - v2 localStorage save/hydrate follows constellation precedent (spread-and-override approach)

key-files:
  created:
    - apps/workbench/src/features/observatory/__tests__/replay-drawer-annotations.test.tsx
  modified:
    - apps/workbench/src/features/observatory/components/hud/panels/ReplayDrawerPanel.tsx
    - apps/workbench/src/features/observatory/components/ObservatoryTab.tsx
    - apps/workbench/src/features/observatory/components/world-canvas/ObservatoryWorldScene.tsx

key-decisions:
  - "Drawer dispatches window CustomEvent (observatory:camera-focus) for camera focus — decoupled from R3F scene tree"
  - "OrbitControls dampingFactor provides natural smooth camera transition when target snaps — no manual lerp needed"
  - "Camera focus listener lives in ObservatoryWorldScene (owns controlsRef) not ObservatoryWorldCanvas"
  - "Annotation pin hydration added to existing v2 mount effect alongside constellation hydration"

patterns-established:
  - "Cross-boundary R3F camera control: drawer dispatches CustomEvent, scene component listens and mutates controlsRef.target"

requirements-completed: [ANNO-03, ANNO-04, ANNO-05]

duration: 5min
completed: 2026-03-23
---

# Phase 42 Plan 02: Replay Annotation Canvas Summary

**Replay drawer Annotations section with sorted pin list, jump-to-frame + camera focus, delete, and localStorage v2 persistence completing the ANNO-03/04/05 analyst workflow loop**

## Performance

- **Duration:** ~5 min
- **Started:** 2026-03-23T03:33:48Z
- **Completed:** 2026-03-23T03:38:21Z
- **Tasks:** 2
- **Files modified:** 4 (1 created test file + 3 modified components)

## Accomplishments

- ReplayDrawerPanel now shows an Annotations section below Bookmarks with sorted pin rows (diamond icon, truncated note, F{frameIndex} label, delete button) and "No pins yet" empty state
- Clicking a pin row jumps the replay timeline to that pin's frameIndex and dispatches `observatory:camera-focus` event that snaps OrbitControls target to the pin's worldPosition with natural damping feel
- Annotation pins hydrate from localStorage v2 on mount and auto-save on every change — pins survive tab close/reopen

## Task Commits

1. **Task 1: Add Annotations section to ReplayDrawerPanel** - `471dde0b8` (feat, TDD RED+GREEN)
2. **Task 2: Hydrate pins from localStorage v2 + camera focus event handler** - `1ec15c6d3` (feat)

## Files Created/Modified

- `apps/workbench/src/features/observatory/components/hud/panels/ReplayDrawerPanel.tsx` - Added annotationPins selector, sortedPins, handlePinClick, handlePinDelete, Annotations section JSX, ObservatoryAnnotationPin import
- `apps/workbench/src/features/observatory/components/ObservatoryTab.tsx` - Added annotationPins selector, hydration loop in v2 mount effect, auto-save useEffect
- `apps/workbench/src/features/observatory/components/world-canvas/ObservatoryWorldScene.tsx` - Added useEffect import, observatory:camera-focus event listener with OrbitControls target snap
- `apps/workbench/src/features/observatory/__tests__/replay-drawer-annotations.test.tsx` - 6 vitest tests covering all ANNO-04/05 behaviors

## Decisions Made

- Drawer dispatches `window.CustomEvent("observatory:camera-focus")` for camera focus rather than a store action — keeps R3F scene internals decoupled from the HUD layer
- Camera focus event listener lives in `ObservatoryWorldScene` (not `ObservatoryWorldCanvas`) because it owns `controlsRef`
- OrbitControls `dampingFactor` already set to `world.camera.dampingFactor` handles smooth animation naturally — no manual lerp needed
- Annotation pin hydration added inside the existing v2 mount effect alongside constellation hydration (single atomic `loadPersistedObservatoryReplayArtifactsV2()` call)

## Deviations from Plan

None — plan executed exactly as written.

## Issues Encountered

Pre-existing TypeScript error in `SpiritResonanceConnections.tsx` (`Line2 vs LineSegments` ref type mismatch) unrelated to this plan's changes — zero new TypeScript errors introduced.

## User Setup Required

None — no external service configuration required.

## Next Phase Readiness

- ANNO-03/04/05 complete — analyst workflow loop fully closed: pins created in 3D (Plan 01), visible/manageable/persistent in drawer (Plan 02)
- Phase 43 (station interiors) can proceed independently

## Self-Check: PASSED

- FOUND: `apps/workbench/src/features/observatory/components/hud/panels/ReplayDrawerPanel.tsx`
- FOUND: `apps/workbench/src/features/observatory/__tests__/replay-drawer-annotations.test.tsx`
- FOUND: `.planning/phases/42-replay-annotation-canvas/42-02-SUMMARY.md`
- FOUND commit: `471dde0b8` (Task 1 — Annotations section in ReplayDrawerPanel)
- FOUND commit: `1ec15c6d3` (Task 2 — persistence + camera focus)
