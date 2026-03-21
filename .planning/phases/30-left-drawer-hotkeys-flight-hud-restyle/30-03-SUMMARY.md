---
phase: 30-left-drawer-hotkeys-flight-hud-restyle
plan: "03"
subsystem: ui
tags: [observatory, hud, glassmorphism, css-custom-properties, flight-hud]

# Dependency graph
requires:
  - phase: 28-design-tokens-panel-audit
    provides: observatory-hud.css glassmorphism tokens (--hud-bg, --hud-blur, --hud-border, --hud-radius, --hud-text, --hud-text-muted)
  - phase: 29-status-strip-panel-registry
    provides: HUD_STATUS_STRIP_HEIGHT=28 constant for bottom offset calculation
provides:
  - SpaceFlightHud root uses var(--hud-text) for text color
  - SpeedIndicator repositioned to bottom 108px (80+28) clearing status strip
  - SpeedIndicator track uses var(--hud-bg) and var(--hud-border)
  - SpeedIndicator readout uses var(--hud-text) and var(--hud-text-muted)
  - HeadingCompass full glassmorphism: var(--hud-bg), var(--hud-blur), var(--hud-border), var(--hud-radius)
  - HeadingCompass tick marks use var(--hud-text-muted) for visibility
affects:
  - flight-hud visual consistency
  - HUD_COLORS deprecation path (no more usages in SpeedIndicator or HeadingCompass)

# Tech tracking
tech-stack:
  added: []
  patterns:
    - "CSS custom properties with original values as fallbacks: var(--hud-token, #original)"
    - "HUD_COLORS constant replaced by CSS var references — components now theme via CSS not JS"
    - "Speed indicator offset = base + HUD_STATUS_STRIP_HEIGHT ensures clearance over status strip"

key-files:
  created: []
  modified:
    - apps/workbench/src/features/observatory/components/hud/SpaceFlightHud.tsx
    - apps/workbench/src/features/observatory/components/hud/SpeedIndicator.tsx
    - apps/workbench/src/features/observatory/components/hud/HeadingCompass.tsx

key-decisions:
  - "Use CSS var fallback syntax (var(--token, #original)) — runtime safe if hud.css not loaded"
  - "HeadingCompass uses background (shorthand) not backgroundColor — CSS var may contain full shorthand value"
  - "Tick marks upgraded from hudBorder color to --hud-text-muted for visibility on glassmorphism bg"
  - "HUD_COLORS import removed from both SpeedIndicator and HeadingCompass after last usage replaced"

patterns-established:
  - "Flight HUD color token migration: replace hard-coded HUD_COLORS.* with var(--hud-*, fallback)"
  - "Bottom position clearance: base_offset + HUD_STATUS_STRIP_HEIGHT for status strip awareness"

requirements-completed: [CLN-02]

# Metrics
duration: 2min
completed: 2026-03-21
---

# Phase 30 Plan 03: Flight HUD Glassmorphism Restyle Summary

**SpaceFlightHud speed indicator and heading compass restyled with --hud-* CSS custom property tokens, speed bar repositioned 28px higher to clear the status strip, compass upgraded to blur(12px) glassmorphism with border radius**

## Performance

- **Duration:** 2 min
- **Started:** 2026-03-21T13:53:52Z
- **Completed:** 2026-03-21T13:55:56Z
- **Tasks:** 2
- **Files modified:** 3

## Accomplishments
- SpaceFlightHud root color token migrated from hard-coded `#c8d2e0` to `var(--hud-text, #c8d2e0)`
- SpeedIndicator bottom offset increased by `HUD_STATUS_STRIP_HEIGHT` (80 -> 108) so the speed bar no longer overlaps the 28px status strip
- SpeedIndicator track bg/border/text colors all migrated to `--hud-bg`, `--hud-border`, `--hud-text`, `--hud-text-muted`
- HeadingCompass gets full glassmorphism treatment: semi-transparent bg, 12px blur (was 4px), border, and 8px radius
- HeadingCompass tick marks changed from `hudBorder` (invisible on dark glass) to `--hud-text-muted` (visible)
- `HUD_COLORS` import removed from both SpeedIndicator and HeadingCompass (no longer used)

## Task Commits

Each task was committed atomically:

1. **Task 1: Restyle SpaceFlightHud root + SpeedIndicator with glassmorphism tokens and status strip clearance** - `bbebe2a0b` (feat)
2. **Task 2: Restyle HeadingCompass with glassmorphism tokens** - `839d7a19b` (feat)

## Files Created/Modified
- `apps/workbench/src/features/observatory/components/hud/SpaceFlightHud.tsx` - Root text color: var(--hud-text, #c8d2e0)
- `apps/workbench/src/features/observatory/components/hud/SpeedIndicator.tsx` - Bottom clearance + 4 CSS var token replacements, HUD_COLORS removed
- `apps/workbench/src/features/observatory/components/hud/HeadingCompass.tsx` - Full glassmorphism (bg, blur, border, radius), tick mark fix, HUD_COLORS removed

## Decisions Made
- Used `background` (shorthand property) instead of `backgroundColor` for the HeadingCompass container because `var(--hud-bg)` contains `rgba(...)` which is a valid background shorthand value — using `backgroundColor` with a CSS var that contains a value like `rgba(8,12,24,0.75)` works, but `background` is semantically more flexible if the var ever expands to include gradients
- Tick marks changed from `HUD_COLORS.hudBorder` (`#202531`, near-black) to `var(--hud-text-muted, #6f7f9a)` because the border color is nearly invisible against the glassmorphism backdrop; text-muted provides sufficient contrast

## Deviations from Plan

None - plan executed exactly as written.

## Issues Encountered
None

## User Setup Required

None - no external service configuration required.

## Next Phase Readiness
- Flight HUD chrome now visually matches the status strip and left drawer established in Phases 28/29
- All three HUD component files compile cleanly with TypeScript
- `HUD_COLORS` constant is now unused in SpeedIndicator and HeadingCompass; only `SPEED_TIER_COLORS` and layout constants remain in active use

## Self-Check: PASSED

- FOUND: apps/workbench/src/features/observatory/components/hud/SpaceFlightHud.tsx
- FOUND: apps/workbench/src/features/observatory/components/hud/SpeedIndicator.tsx
- FOUND: apps/workbench/src/features/observatory/components/hud/HeadingCompass.tsx
- FOUND: .planning/phases/30-left-drawer-hotkeys-flight-hud-restyle/30-03-SUMMARY.md
- FOUND commit: bbebe2a0b (feat(30-03): restyle SpaceFlightHud + SpeedIndicator)
- FOUND commit: 839d7a19b (feat(30-03): restyle HeadingCompass)

---
*Phase: 30-left-drawer-hotkeys-flight-hud-restyle*
*Completed: 2026-03-21*
