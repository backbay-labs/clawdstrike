---
phase: 28-design-tokens-panel-audit
plan: 02
subsystem: ui
tags: [css, design-tokens, glassmorphism, observatory, hud]

# Dependency graph
requires: []
provides:
  - "observatory-hud.css with 8 glassmorphism CSS custom properties"
  - "Import chain from globals.css to observatory-hud.css"
  - "--hud-bg, --hud-border, --hud-shadow, --hud-text, --hud-text-muted, --hud-accent, --hud-blur, --hud-radius"
affects:
  - phase-29-observatory-status-strip
  - phase-30-observatory-left-drawer
  - phase-31-observatory-panels-rebuild

# Tech tracking
tech-stack:
  added: []
  patterns:
    - "CSS custom properties defined once in a dedicated feature CSS file, imported via globals.css"
    - "--hud-accent uses var(--spirit-accent, #4af) — spirit-driven theming with safe fallback"

key-files:
  created:
    - apps/workbench/src/features/observatory/observatory-hud.css
  modified:
    - apps/workbench/src/globals.css

key-decisions:
  - "Glassmorphism tokens isolated to observatory-hud.css — not polluting globals.css :root with HUD-specific values"
  - "--hud-accent references --spirit-accent with #4af fallback, making the entire HUD spirit-aware without hard dependency"

patterns-established:
  - "Feature-scoped CSS files imported via globals.css for token isolation"
  - "Spirit-driven accent pattern: var(--spirit-accent, <safe-fallback>)"

requirements-completed: [VIS-01]

# Metrics
duration: 4min
completed: 2026-03-21
---

# Phase 28 Plan 02: Design Tokens Summary

**8 glassmorphism CSS custom properties in observatory-hud.css, imported globally, enabling spirit-driven theming with --hud-accent: var(--spirit-accent, #4af)**

## Performance

- **Duration:** 4 min
- **Started:** 2026-03-21T00:00:00Z
- **Completed:** 2026-03-21T00:04:00Z
- **Tasks:** 1
- **Files modified:** 2

## Accomplishments
- Created `observatory-hud.css` with all 8 required CSS custom properties at exact specified values
- Wired import into `globals.css` immediately after `@custom-variant dark` declaration
- `--hud-accent` references `--spirit-accent` with `#4af` fallback — HUD inherits spirit color if bound

## Task Commits

Each task was committed atomically:

1. **Task 1: Create observatory HUD design tokens CSS file** - `231d8192d` (feat)

**Plan metadata:** (see final commit below)

## Files Created/Modified
- `apps/workbench/src/features/observatory/observatory-hud.css` - 8 glassmorphism design token CSS custom properties in :root
- `apps/workbench/src/globals.css` - Added `@import "./features/observatory/observatory-hud.css"` after `@custom-variant dark`

## Decisions Made
- Tokens isolated in feature-scoped CSS file (not embedded in globals.css) to keep HUD-specific properties out of the main token namespace
- `--hud-accent: var(--spirit-accent, #4af)` makes HUD spirit-aware without requiring a spirit to be bound

## Deviations from Plan

None - plan executed exactly as written.

## Issues Encountered
None

## User Setup Required
None - no external service configuration required.

## Next Phase Readiness
- Design tokens are live and available to any component in the app
- Phase 29 (status strip), Phase 30 (left drawer), and Phase 31 (panel rebuilds) can consume `var(--hud-bg)`, `var(--hud-border)`, etc. immediately

---
*Phase: 28-design-tokens-panel-audit*
*Completed: 2026-03-21*
