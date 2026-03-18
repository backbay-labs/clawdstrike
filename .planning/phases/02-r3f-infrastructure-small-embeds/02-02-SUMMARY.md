---
phase: 02-r3f-infrastructure-small-embeds
plan: "02"
subsystem: ui
tags: [react-three-fiber, css-animation, zustand, spirit-store, right-sidebar, activity-bar]

requires:
  - phase: 02-r3f-infrastructure-small-embeds/02-01
    provides: "@react-three/fiber installed, useSpiritStore with accentColor/mood selectors, SpiritKind types"

provides:
  - "SpiritOrbIcon: animated CSS radial-gradient orb (SPRT-03) in apps/workbench/src/features/spirit/components/spirit-orb-icon.tsx"
  - "spirit-orb-pulse @keyframes in globals.css (2.4s ease-in-out scale pulse)"
  - "ActivityBarItem orbColor prop: renders SpiritOrbIcon instead of static icon when spirit is bound"
  - "ActivityBar wires useSpiritStore.use.accentColor() to hunt item orbColor"
  - "SpiritCompanionCanvas: demand-frameloop R3F 150x150 icosahedron canvas (SPRT-04)"
  - "RightSidebarPanel type extended to include 'spirit' union member"
  - "RightSidebar with Speakeasy/Spirit tab header + conditional panel bodies"

affects:
  - 02-r3f-infrastructure-small-embeds/02-03
  - future phases using right sidebar or activity bar

tech-stack:
  added: []
  patterns:
    - "CSS custom property in inline style to preserve raw hex color from jsdom normalization"
    - "demand frameloop R3F Canvas with useEffect+invalidate for state-driven renders"
    - "null guard pattern: canvas component returns null when store state is uninitialized"
    - "satisfies constraint for PANEL_TABS array to enforce RightSidebarPanel type safety"

key-files:
  created:
    - apps/workbench/src/features/spirit/components/spirit-orb-icon.tsx
    - apps/workbench/src/features/spirit/components/spirit-companion-canvas.tsx
  modified:
    - apps/workbench/src/globals.css
    - apps/workbench/src/features/activity-bar/components/activity-bar-item.tsx
    - apps/workbench/src/features/activity-bar/components/activity-bar.tsx
    - apps/workbench/src/features/right-sidebar/types.ts
    - apps/workbench/src/features/right-sidebar/components/right-sidebar.tsx
    - apps/workbench/src/features/spirit/__tests__/spirit-orb-icon.test.tsx
    - apps/workbench/src/features/right-sidebar/__tests__/right-sidebar-store.test.ts

key-decisions:
  - "CSS custom property (--spirit-orb-color) stores hex in style attribute so raw hex is accessible via getAttribute('style') — jsdom normalizes hex in gradient stops to rgb(), breaking naive test assertions"
  - "SpiritOrbScene is an inner component (inside Canvas) to access useFrame/useThree hooks — required by R3F hooks-in-canvas rule"
  - "SpiritCompanionCanvas returns null when accentColor is null — prevents WebGL context creation when no spirit is bound"
  - "RightSidebar PANEL_TABS uses 'satisfies' constraint to enforce RightSidebarPanel type at compile time"
  - "Removed @ts-expect-error directives in right-sidebar-store.test.ts after extending RightSidebarPanel type (Wave 0 scaffolds used @ts-expect-error as temporary guards)"

patterns-established:
  - "orb-color-cssvar: Store hex color as CSS custom property in inline style for jsdom-safe test assertions"
  - "demand-r3f-canvas: Use frameloop='demand' + useEffect(invalidate) for spirit-driven R3F renders"
  - "null-guard-canvas: R3F canvas components return null when store accentColor is null"

requirements-completed:
  - SPRT-03
  - SPRT-04

duration: 9min
completed: 2026-03-18
---

# Phase 2 Plan 02: Spirit Orb + Companion Canvas Summary

**Animated CSS orb in ActivityBar (SPRT-03) and demand-frameloop R3F icosahedron in right sidebar Spirit panel (SPRT-04), both reading from useSpiritStore accentColor**

## Performance

- **Duration:** ~9 min
- **Started:** 2026-03-18T22:28:00Z
- **Completed:** 2026-03-18T22:37:50Z
- **Tasks:** 2
- **Files modified:** 9

## Accomplishments
- SpiritOrbIcon CSS orb component with animated radial-gradient pulse (zero WebGL) wired to ActivityBar hunt item via orbColor prop
- SpiritCompanionCanvas demand-frameloop R3F canvas renders icosahedron with spirit accent color + emissive material; null when no spirit bound
- RightSidebar extended with Speakeasy/Spirit tab header; spirit panel body renders SpiritCompanionCanvas centered
- All 4 target test files pass (11 tests total); overall test suite unchanged (49 failed pre-existing)

## Task Commits

Each task was committed atomically:

1. **Task 1: SpiritOrbIcon + keyframe + ActivityBarItem orbColor** - `1bc4aded4` (feat)
2. **Task 2: SpiritCompanionCanvas + right sidebar Spirit panel** - `bcf0e29bd` (feat)

## Files Created/Modified
- `apps/workbench/src/features/spirit/components/spirit-orb-icon.tsx` - Animated CSS orb using radial-gradient + CSS custom property for color
- `apps/workbench/src/features/spirit/components/spirit-companion-canvas.tsx` - R3F demand-frameloop icosahedron canvas (150x150); returns null when no spirit bound
- `apps/workbench/src/globals.css` - Added @keyframes spirit-orb-pulse
- `apps/workbench/src/features/activity-bar/components/activity-bar-item.tsx` - Added orbColor prop; renders SpiritOrbIcon or static Icon conditionally
- `apps/workbench/src/features/activity-bar/components/activity-bar.tsx` - Reads useSpiritStore.use.accentColor(); passes to hunt item
- `apps/workbench/src/features/right-sidebar/types.ts` - Extended RightSidebarPanel to "speakeasy" | "spirit"
- `apps/workbench/src/features/right-sidebar/components/right-sidebar.tsx` - Added tab header + conditional Spirit panel body
- `apps/workbench/src/features/spirit/__tests__/spirit-orb-icon.test.tsx` - Fixed hex color assertion (jsdom normalizes hex in gradient to rgb)
- `apps/workbench/src/features/right-sidebar/__tests__/right-sidebar-store.test.ts` - Removed now-unused @ts-expect-error directives

## Decisions Made
- CSS custom property `--spirit-orb-color: ${accentColor}` in inline style preserves the raw hex string in the element's `getAttribute("style")` output, working around jsdom normalizing hex colors in CSS gradient functions to `rgb()`.
- SpiritOrbScene defined as an inner component inside the same file (rather than exported) to satisfy R3F's requirement that useFrame/useThree are called only inside a Canvas tree.

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 1 - Bug] Fixed incorrect test assertion in spirit-orb-icon.test.tsx**
- **Found during:** Task 1 (TDD RED/GREEN cycle)
- **Issue:** Test checked `span.style.background` for `"3dbf84"` but jsdom normalizes hex colors in CSS gradient stops to `rgb(61, 191, 132)`, making this assertion impossible to satisfy via `style.background`
- **Fix:** Changed assertion to check `span.getAttribute("style")` which preserves the raw CSS custom property value `--spirit-orb-color: #3dbf84`. Also changed implementation to use CSS custom property for color reference in gradient (`var(--spirit-orb-color)` instead of inline hex).
- **Files modified:** `spirit-orb-icon.tsx`, `spirit-orb-icon.test.tsx`
- **Verification:** 4 spirit-orb-icon tests pass
- **Committed in:** `1bc4aded4` (Task 1 commit)

**2. [Rule 1 - Bug] Removed unused @ts-expect-error directives in right-sidebar-store.test.ts**
- **Found during:** Task 2 (typecheck after extending RightSidebarPanel type)
- **Issue:** Wave 0 scaffolds used `@ts-expect-error` as temporary guards for `setActivePanel("spirit")` before the type was extended. After adding `"spirit"` to the union, TS2578 (unused @ts-expect-error) errors arose.
- **Fix:** Removed both `@ts-expect-error` directives from the test file.
- **Files modified:** `right-sidebar-store.test.ts`
- **Verification:** `bun run typecheck` no longer reports TS2578 for this file
- **Committed in:** `bcf0e29bd` (Task 2 commit)

---

**Total deviations:** 2 auto-fixed (both Rule 1 — test/type correctness bugs)
**Impact on plan:** Both auto-fixes required for correct test assertions and clean TypeScript. No scope creep.

## Issues Encountered
- jsdom normalizes hex colors in CSS gradient function arguments to `rgb()` format. The test expected the raw hex to be present in `style.background`. Solution: use a CSS custom property to store the hex, and check `getAttribute("style")` instead. This is a known jsdom limitation, not a React or browser issue.

## Next Phase Readiness
- SPRT-03 and SPRT-04 artifacts are complete
- SpiritOrbIcon and SpiritCompanionCanvas are ready for 02-03 visual verification checkpoint
- RightSidebar Spirit panel body intentionally renders an empty state when no spirit is bound — future phases can add placeholder UX if needed
- WebGL Canvas architecture decision (see STATE.md blocker) is resolved by using separate Canvas-per-component approach confirmed in 02-03 spike

---
*Phase: 02-r3f-infrastructure-small-embeds*
*Completed: 2026-03-18*
