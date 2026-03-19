---
phase: 11-camera-cinematics-shake
plan: "02"
subsystem: observatory-camera
tags: [camera, cinematics, fly-by, letterbox, R3F, CAM-01]
dependency_graph:
  requires: [11-01]
  provides: [CAM-01-fly-by, letterbox-bars, fly-by-skip]
  affects: [ObservatoryWorldCanvas, ObservatoryTab, WorldCameraRig]
tech_stack:
  added: []
  patterns:
    - "Waypoint sequencer reusing existing bezierPoint + smoothstep01 Bezier machinery"
    - "flyByActive prop gates useFrame execution path in WorldCameraRig"
    - "CSS letterbox bars (absolute positioned divs) animated via Tailwind h-12/h-0 transition"
    - "frameloop prop threaded from ObservatoryTab -> ObservatoryWorldCanvas -> Canvas"
key_files:
  created: []
  modified:
    - apps/workbench/src/features/observatory/components/ObservatoryWorldCanvas.tsx
    - apps/workbench/src/features/observatory/components/ObservatoryTab.tsx
    - apps/workbench/src/features/observatory/__tests__/observatory-tab.test.tsx
decisions:
  - "Fly-by uses existing WorldCameraRig Bezier machinery (bezierPoint + smoothstep01) — no new animation system"
  - "flyByActive prop gates normal tracking; fly-by branch runs first in useFrame before station tracking"
  - "flyByCompleteCalledRef prevents double-calling onFlyByComplete if state updates cause re-renders"
  - "flyByDoneRef in ObservatoryTab prevents replay if component re-mounts mid-session"
  - "frameloop prop threaded through ObservatoryWorldCanvas to Canvas (option a) — simpler than useThree approach"
  - "HUDs hidden during fly-by (conditional render) — cleaner UX than z-index stacking"
  - "Hook ordering fix: flyByActive + flyByDoneRef state declared before callbacks that reference them"
metrics:
  duration: 294s
  completed: "2026-03-19"
  tasks_completed: 2
  files_modified: 3
---

# Phase 11 Plan 02: Spawn Fly-By Sequence + CSS Letterbox Bars Summary

**One-liner:** 4.8s opening camera sweep across the station ring (3-leg Bezier waypoints) with CSS letterbox bars framing the sequence and Escape/click skip support.

## What Was Built

### Task 1: FLY_BY_WAYPOINTS + fly-by sequencing in WorldCameraRig + prop threading

Added to `ObservatoryWorldCanvas.tsx`:

- `FLY_BY_WAYPOINTS` constant (3 legs: SE low [28,8,28] -> W elevated [-22,14,20] -> atlas default [0,20.4,36.8], 1600ms each)
- Extended `WorldCameraRig` props: `flyByActive: boolean` + `onFlyByComplete: () => void`
- Added `waypointIndexRef` + `flyByCompleteCalledRef` inside `WorldCameraRig`
- Fly-by branch at top of `useFrame`: first frame places camera at waypoint 0; subsequent frames launch Bezier flights leg-by-leg; after last leg calls `onFlyByComplete()`; near-zero travel legs (<0.5 units) are skipped automatically
- Extended `ObservatoryWorldScene` with `flyByActive` + `onFlyByComplete` (threaded to `WorldCameraRig`)
- Extended `ObservatoryWorldCanvasProps` with `frameloop`, `flyByActive`, `onFlyByComplete`
- `Canvas` now receives `frameloop={frameloop ?? "demand"}`

**Commit:** `2a920475a`

### Task 2: flyByActive state + letterbox bars + skip handler + frameloop-always in ObservatoryTab

Added to `ObservatoryTab.tsx`:

- `flyByActive` state (starts `true`) + `flyByDoneRef` to prevent replay on re-mount
- `handleFlyByComplete`: sets `flyByActive=false`, sets `frameloop="demand"`
- `handleSkipFlyBy`: guards on `flyByActive`, calls `handleFlyByComplete`
- `useEffect` forces `frameloop="always"` when `flyByActive=true`
- `useEffect` registers/unregisters Escape key listener based on `flyByActive`
- `onClick={flyByActive ? handleSkipFlyBy : undefined}` on outer container
- CSS letterbox bars: top + bottom `absolute` divs, `bg-black`, `z-20`, `h-12` during fly-by / `h-0` after, 500ms transition
- Bottom bar shows "CLAWDSTRIKE WORKBENCH — SECURITY OBSERVATORY · ESC to skip" hint text
- `ProbeHud` and `MissionHud` hidden while `flyByActive=true`
- New props threaded to `ObservatoryWorldCanvas`: `flyByActive`, `frameloop`, `onFlyByComplete`

Added to `observatory-tab.test.tsx` (4 new tests):
- `shows letterbox bars (h-12) on initial render`
- `letterbox bars hide (h-0) after Escape key press skips fly-by`
- `registers keydown listener for Escape skip on mount`
- `renders without crash with flyByActive=true on mount`

**Commit:** `791ba25db`

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 1 - Bug] React hook ordering: flyByActive referenced before declaration**

- **Found during:** Task 2 — first test run
- **Issue:** `handleFlyByComplete` and `handleSkipFlyBy` callbacks were inserted before the `flyByActive` state declaration, causing "Cannot access 'flyByActive' before initialization" at runtime
- **Fix:** Moved all fly-by state declarations (`frameloop`, `flyByActive`, `flyByDoneRef`) to before the callbacks that reference them, maintaining correct React hook call order
- **Files modified:** `ObservatoryTab.tsx`
- **Commit:** included in `791ba25db`

None of the other plan steps required deviation. Plan executed as specified.

## Verification Results

- `grep -c "FLY_BY_WAYPOINTS" ObservatoryWorldCanvas.tsx` = 4 (>= 2 required)
- `grep -c "waypointIndexRef" ObservatoryWorldCanvas.tsx` = 5 (>= 2 required)
- `grep -c "flyByActive" ObservatoryWorldCanvas.tsx` = 11 (>= 4 required)
- `grep -c "onFlyByComplete" ObservatoryWorldCanvas.tsx` = 9 (>= 3 required)
- `grep -c "frameloop" ObservatoryWorldCanvas.tsx` = 4 (>= 2 required)
- `grep -c "flyByActive" ObservatoryTab.tsx` = 14 (>= 6 required)
- `grep -c "handleFlyByComplete" ObservatoryTab.tsx` = 4 (>= 3 required)
- TypeScript: 0 new errors (only pre-existing sidebar-icons.tsx TS2783 duplicate props)
- Vitest: 64 pass / 1 pre-existing fail (r3f-canvas jsdom/useThree issue, not introduced by this plan)

## Self-Check: PASSED

- ObservatoryWorldCanvas.tsx: FOUND
- ObservatoryTab.tsx: FOUND
- Commit 2a920475a: FOUND
- Commit 791ba25db: FOUND
