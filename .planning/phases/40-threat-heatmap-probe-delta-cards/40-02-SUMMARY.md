---
phase: 40-threat-heatmap-probe-delta-cards
plan: 02
subsystem: ui
tags: [react, r3f, drei, vitest, glassmorphism, observatory, probe, lifecycle]

requires:
  - phase: 40-threat-heatmap-probe-delta-cards
    provides: ObservatoryProbeGuidance and observatory-recommendations module (plan 01 context)
  - phase: 28-observatory-hud
    provides: Glassmorphism CSS variables (--hud-bg, --hud-border, --hud-blur, etc.)
  - phase: 39-store-persistence-derivation-foundations
    provides: Observatory store and probe state management foundations

provides:
  - ProbeDeltaCard: Floating glassmorphism DOM card with shift arrow, delta summary, why-it-matters, action button
  - ProbeDeltaLayer: Lifecycle manager that mounts card 8 units above station via drei Html, auto-dismisses after 8s

affects: [40-03-plan, Observatory scene wiring, ObservatoryWorldCanvas integration]

tech-stack:
  added: []
  patterns:
    - "drei Html with transform+sprite for DOM overlays in 3D space"
    - "CSS opacity transition (0.5s) driven by React state for fade-out"
    - "useRef-based timer management to prevent stale closure leaks"
    - "React.createElement in .ts test files to avoid JSX parsing issues"

key-files:
  created:
    - apps/workbench/src/features/observatory/components/world-canvas/ProbeDeltaCard.tsx
    - apps/workbench/src/features/observatory/components/world-canvas/ProbeDeltaLayer.tsx
    - apps/workbench/src/features/observatory/__tests__/probe-delta-layer.test.ts
  modified: []

key-decisions:
  - "ProbeDeltaCard already existed in the repo (committed in 40-01 test commit a82ee65fa) — file was created correctly, no re-write needed"
  - "Test file kept as .ts extension (per plan spec) — uses React.createElement instead of JSX to avoid esbuild transform errors"
  - "Auto-dismiss split into two timers: 7500ms fade-start + 8000ms full removal — matches plan's 7.5s fade + 8s dismiss spec"
  - "distanceFactor={80} on drei Html for readable card scale at typical orbit camera distance"
  - "dismiss() uses useRef timers (not closure state) to avoid stale closure issues across re-renders"

patterns-established:
  - "ProbeDeltaCard: glassmorphism DOM card using --hud-bg/--hud-border/--hud-blur CSS variables with inline styles"
  - "ProbeDeltaLayer: zwei-timer pattern (fade at T-500ms, remove at T) for smooth auto-dismiss"
  - "R3F component tests in .ts files use React.createElement instead of JSX"

requirements-completed: [PRBI-01, PRBI-02, PRBI-03, PRBI-04, PRBI-05]

duration: 7min
completed: 2026-03-23
---

# Phase 40 Plan 02: ProbeDeltaCard + ProbeDeltaLayer Summary

**Floating glassmorphism delta cards with 8-second auto-dismiss, keypress dismiss, and replace mode — rendered via drei Html 8 units above target stations after probe discharge**

## Performance

- **Duration:** 7 min
- **Started:** 2026-03-23T01:41:57Z
- **Completed:** 2026-03-23T01:49:30Z
- **Tasks:** 2
- **Files modified:** 3 (2 created new, 1 existing from prior plan)

## Accomplishments
- Created `ProbeDeltaCard.tsx`: Glassmorphism card with station label, pressure shift arrow (↑ red for lane-up/pressure-shift, → amber for cause-shift, — blue for steady), delta summary, why-it-matters sentence, and one-click action button with stopPropagation
- Created `ProbeDeltaLayer.tsx`: Lifecycle manager using drei Html with transform+sprite, mounts 8 units above target station, 7.5s fade + 8s full dismiss timers, keydown dismiss, and replace mode for new guidance
- Created `probe-delta-layer.test.ts`: 5 passing tests covering null guard, show-on-guidance, 8s auto-dismiss (fake timers), and replace mode

## Task Commits

1. **Task 1: ProbeDeltaCard DOM overlay component** - `a82ee65fa` (committed in prior 40-01 plan test commit)
2. **Task 2: ProbeDeltaLayer lifecycle manager and tests** - `67ab4e571` (feat)

## Files Created/Modified
- `apps/workbench/src/features/observatory/components/world-canvas/ProbeDeltaCard.tsx` - Glassmorphism card overlay using HUD CSS variables, imports openObservatoryRecommendationRoute
- `apps/workbench/src/features/observatory/components/world-canvas/ProbeDeltaLayer.tsx` - Lifecycle manager with drei Html, auto-dismiss timers, keydown handler, replace mode
- `apps/workbench/src/features/observatory/__tests__/probe-delta-layer.test.ts` - 5 unit tests (all passing)

## Decisions Made
- ProbeDeltaCard was already committed in the 40-01 test commit — no re-write needed, file content matched plan spec exactly
- Test file uses `.ts` extension (per plan spec) with `React.createElement` instead of JSX to avoid esbuild transform errors in non-tsx test files
- Two-timer approach: separate `setTimeout` at 7500ms (begin fade) and 8000ms (remove) gives smooth 500ms fade-out before card removal
- `useRef` for timer handles avoids stale closure issues; `clearTimers()` called on each new guidance installation

## Deviations from Plan

None — plan executed exactly as written.

The only unexpected discovery was that `ProbeDeltaCard.tsx` had already been scaffolded in the 40-01 plan's test commit. The content was identical to what the plan specifies, so no re-work was required.

## Issues Encountered
- Initial test file failed with esbuild error because JSX was written in a `.ts` file — resolved by switching mock lambda to use `children` pass-through and render calls to `React.createElement`
- Vitest must be run from `apps/workbench/` directory (not repo root) for `@` alias resolution to work correctly

## Next Phase Readiness
- `ProbeDeltaCard` and `ProbeDeltaLayer` are standalone components ready to be wired into `ObservatoryWorldCanvas` in Plan 03
- Both components accept `ObservatoryProbeGuidance` and station positions as props — no store coupling, clean prop threading
- All 5 unit tests pass

---
*Phase: 40-threat-heatmap-probe-delta-cards*
*Completed: 2026-03-23*
