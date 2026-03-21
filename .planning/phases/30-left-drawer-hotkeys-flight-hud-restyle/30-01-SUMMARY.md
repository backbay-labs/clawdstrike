---
phase: 30-left-drawer-hotkeys-flight-hud-restyle
plan: "01"
subsystem: ui
tags: [react, glassmorphism, css-transitions, zustand, hud, observatory]

# Dependency graph
requires:
  - phase: 29-status-strip-panel-registry
    provides: activePanel field in observatory store, HUD_STATUS_STRIP_HEIGHT constant, glassmorphism CSS tokens in observatory-hud.css

provides:
  - ObservatoryLeftDrawer.tsx: 360px glassmorphism panel sliding from left edge when activePanel is non-null
  - HUD_LEFT_DRAWER_WIDTH = 360 constant in hud-constants.ts
  - 5 unit tests covering drawer visibility, transitions, placeholder content, and panel switching

affects: [31-left-drawer-panels, future-hud-phases]

# Tech tracking
tech-stack:
  added: []
  patterns:
    - Always-mounted drawer pattern (like SpaceFlightHud) — visibility via CSS transform, not conditional render
    - CSS slide + content fade combo: translateX 250ms ease-out, then opacity 200ms with 100ms delay
    - React subscription for panel open/close — appropriate for rare user actions (not per-frame rAF)

key-files:
  created:
    - apps/workbench/src/features/observatory/components/hud/ObservatoryLeftDrawer.tsx
    - apps/workbench/src/features/observatory/__tests__/observatory-left-drawer.test.tsx
  modified:
    - apps/workbench/src/features/observatory/components/hud/hud-constants.ts
    - apps/workbench/src/features/observatory/components/ObservatoryTab.tsx

key-decisions:
  - "Always-mounted drawer (not conditional render) — CSS translateX drives visibility; avoids unmount/remount on open"
  - "pointerEvents: none when hidden — prevents invisible drawer from intercepting canvas clicks"
  - "Content fade starts with 100ms delay so text fades in after drawer is partially visible"
  - "z-index 18: above SpaceFlightHud (z:15), below StatusStrip (z:20)"
  - "Phase 30 placeholder shows panel name in uppercase monospace; Phase 31 will replace with real content"

patterns-established:
  - "Always-mounted HUD overlay pattern: component is always in DOM, CSS transitions control visibility"
  - "Two-part transition: outer container slides (250ms ease-out), inner content fades (200ms with 100ms delay)"

requirements-completed: [HUD-13, VIS-03]

# Metrics
duration: 8min
completed: 2026-03-21
---

# Phase 30 Plan 01: Left Drawer Container Summary

**360px glassmorphism left drawer sliding in from the canvas edge with CSS transitions when activePanel is non-null, backed by 5 unit tests**

## Performance

- **Duration:** ~8 min
- **Started:** 2026-03-21T13:48:00Z
- **Completed:** 2026-03-21T13:56:29Z
- **Tasks:** 2
- **Files modified:** 4

## Accomplishments

- Created ObservatoryLeftDrawer.tsx with full glassmorphism shell using var(--hud-bg), var(--hud-blur), var(--hud-border), var(--hud-shadow) CSS tokens
- CSS slide transition (250ms ease-out) + content fade-in (200ms, 100ms delay) satisfying VIS-03
- Added HUD_LEFT_DRAWER_WIDTH = 360 constant to hud-constants.ts (HUD-13: 300-400px range)
- Mounted drawer in ObservatoryTab.tsx between SpaceFlightHud and ObservatoryStatusStrip
- 5 unit tests all passing: render, hidden state, visible state, placeholder text, panel switching

## Task Commits

Each task was committed atomically:

1. **Task 1: Add HUD_LEFT_DRAWER_WIDTH constant + Create ObservatoryLeftDrawer component** - `d2e44310d` (feat)
2. **Task 2: Mount ObservatoryLeftDrawer in ObservatoryTab + unit tests** - `fa5045b8c` (feat)

## Files Created/Modified

- `apps/workbench/src/features/observatory/components/hud/ObservatoryLeftDrawer.tsx` - Left drawer container with glassmorphism shell, slide+fade transitions, placeholder panel name
- `apps/workbench/src/features/observatory/__tests__/observatory-left-drawer.test.tsx` - 5 unit tests covering all drawer states
- `apps/workbench/src/features/observatory/components/hud/hud-constants.ts` - Added HUD_LEFT_DRAWER_WIDTH = 360
- `apps/workbench/src/features/observatory/components/ObservatoryTab.tsx` - Import + mount ObservatoryLeftDrawer between SpaceFlightHud and StatusStrip

## Decisions Made

- Always-mounted pattern (not conditional render): translateX drives visibility so there is no unmount/remount cost on open, consistent with SpaceFlightHud pattern
- pointerEvents: none when hidden ensures the invisible drawer doesn't intercept canvas mouse events
- Content fade uses 100ms delay so placeholder text appears after the drawer is partially slid in, which feels more polished
- z-index 18 fits the existing z-index stack: SpaceFlightHud (15), drawer (18), StatusStrip (20)

## Deviations from Plan

None — plan executed exactly as written.

## Issues Encountered

- Running `npx vitest run` from the workspace root failed to resolve `@/lib/create-selectors` (the `@` alias not active outside of `apps/workbench/`). Fixed by running tests from `apps/workbench/` directory, which picks up `vitest.config.ts` with the correct alias. No code change required.

## Next Phase Readiness

- ObservatoryLeftDrawer container is mounted and slides correctly — Phase 31 can fill it with real panel content (explainability, replay, mission, ghost) by rendering inside the drawer's content area
- The placeholder `data-testid="observatory-left-drawer-panel-name"` span will be replaced with real content in Phase 31

---
*Phase: 30-left-drawer-hotkeys-flight-hud-restyle*
*Completed: 2026-03-21*
