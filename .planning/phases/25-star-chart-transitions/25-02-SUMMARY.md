---
phase: 25-star-chart-transitions
plan: "02"
subsystem: observatory/minimap
tags: [autopilot, flight-trail, star-chart, navigation, svg, r3f]
dependency_graph:
  requires: ["25-01"]
  provides: ["MAP-02", "MAP-03"]
  affects: ["observatory-minimap-panel", "useFlightLoop", "observatory-store"]
tech_stack:
  added: []
  patterns: ["circular-trail-buffer", "quaternion-slerp-autopilot", "raf-svg-mutation"]
key_files:
  created: []
  modified:
    - apps/workbench/src/features/observatory/character/ship/flight-types.ts
    - apps/workbench/src/features/observatory/character/ship/useFlightLoop.ts
    - apps/workbench/src/features/observatory/stores/observatory-store.ts
    - apps/workbench/src/features/observatory/types.ts
    - apps/workbench/src/features/observatory/panels/observatory-minimap-panel.tsx
    - apps/workbench/src/features/observatory/__tests__/observatory-minimap.test.tsx
decisions:
  - "[Phase 25-02]: autopilotTargetStationId kept as top-level store field (not inside flightState) — user intent, not physics state"
  - "[Phase 25-02]: Autopilot slerp 0.03/frame toward target quaternion; cruise thrust applied when forward dot > 0.95"
  - "[Phase 25-02]: Mouse rotation block when autopilotActive=true (autopilotTargetId non-null and no manual input)"
  - "[Phase 25-02]: Trail buffer circular (max 50, shift oldest); sampled every 500ms via Date.now() in rAF — no re-renders"
  - "[Phase 25-02]: Trail polyline + autopilot dashed line driven imperatively via refs in rAF — zero React re-renders"
  - "[Phase 25-02]: Dock proximity cancel: autopilot fires onAutopilotCancel when distToTarget <= dockProximityRadius (50)"
metrics:
  duration: "~4min"
  completed: "2026-03-20"
  tasks: 2
  files: 6
---

# Phase 25 Plan 02: Flight Trail + Click-to-Autopilot Summary

One-liner: Quaternion-slerp autopilot in flight loop + rAF-driven SVG trail polyline and dashed indicator on star chart, wired to station dot clicks.

## Tasks Completed

| Task | Name | Commit | Files |
|------|------|--------|-------|
| 1 | Autopilot state + flight loop integration | 559fb383b | flight-types.ts, useFlightLoop.ts, observatory-store.ts, types.ts |
| 2 | Flight path trail + click-to-autopilot on star chart | bba0bbc95 | observatory-minimap-panel.tsx, observatory-minimap.test.tsx |

## What Was Built

**Task 1 — Autopilot state + flight loop (559fb383b):**
- `autopilotTargetStationId: HuntStationId | null` added to `FlightState` and `DEFAULT_FLIGHT_STATE`
- Top-level `autopilotTargetStationId` field added to `ObservatoryState` (separate from flightState — user intent vs physics)
- `setAutopilotTarget(stationId)` and `clearAutopilot()` actions added to observatory store
- `UseFlightLoopOptions` gains `autopilotRef` and `onAutopilotCancel` options
- Pre-allocated module-level scratch objects `_targetPos`, `_toTarget`, `_targetQuat` for zero-GC autopilot math
- When autopilot active: quaternion slerps at 0.03/frame toward target; cruise thrust fires when alignment dot > 0.95
- Manual WASD/mouse input immediately fires `onAutopilotCancel` callback
- Dock proximity (<=50 units) fires `onAutopilotCancel` callback
- `autopilotTargetStationId` included in throttled FlightState snapshot

**Task 2 — Flight trail + click-to-autopilot (bba0bbc95):**
- Module-level circular trail buffer (max 50 `{x, z}` entries, sample interval 500ms)
- Trail buffer driven in rAF loop via `Date.now()` comparison — no React state
- SVG `<polyline>` ref updated imperatively in rAF: `points` attribute set each frame when trail has >=2 entries
- SVG `<line>` ref for autopilot dashed indicator: `x1/y1/x2/y2` updated in rAF from player → target chart positions
- Autopilot line: stroke `#e0e6ef`, `strokeDasharray="4 3"`, opacity 0.6; hidden when `autopilotTargetStationId` is null
- Station dot onClick now calls `useObservatoryStore.getState().actions.setAutopilotTarget(id)` in addition to route open
- Tests: 2 new tests verify `setAutopilotTarget` called with correct station id on click; mock updated with `setAutopilotTarget`

## Decisions Made

- `autopilotTargetStationId` is a top-level store field (not inside `flightState`) because it's user intent driving the autopilot, not a physics output. This keeps the physics snapshot clean.
- Autopilot slerp happens INSTEAD of mouse rotation (checked via `autopilotActive = autopilotTargetId !== null && !hasManualInput`), not in addition to it.
- Trail polyline uses single stroke `rgba(255,255,255,0.5)` rather than per-segment opacity gradient — simpler SVG, sufficient visual fidelity for a minimap.
- `stationChartPositions` (from `useMemo`) passed as rAF dependency to ensure stable chart coordinate access for the autopilot line.

## Verification

- All acceptance criteria pass (grep checks on all 6 criteria for both tasks)
- 29 tests pass: 25 minimap tests + 4 store tests
- `npx vitest run src/features/observatory/__tests__/observatory-minimap.test.tsx src/features/observatory/__tests__/observatory-store.test.ts` — 2 test files, 29 tests passed

## Deviations from Plan

None — plan executed exactly as written.

## Self-Check: PASSED

All 6 modified files exist on disk. Both task commits verified in git log (559fb383b, bba0bbc95).
