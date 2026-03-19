---
phase: 12-particle-effects
plan: 02
subsystem: ui
tags: [react-three-fiber, drei, Trail, spirit, particles, r3f]

# Dependency graph
requires:
  - phase: 12-particle-effects
    provides: wawa-vfx installed; SpiritCompanionCanvas with orb mesh; drei already installed

provides:
  - drei Trail wrapping spirit orb mesh in SpiritCompanionCanvas
  - Accent-colored fading trail (quadratic attenuation) following orb rotation

affects: [spirit-companion-canvas, PFX-04]

# Tech tracking
tech-stack:
  added: []
  patterns:
    - "Trail wraps inner mesh child — meshRef stays on mesh, Trail reads first child Object3D position automatically"
    - "frameloop=demand preserved: Trail updates inside existing useFrame tick without forcing continuous rendering"
    - "Test mock pattern: vi.mock('@react-three/drei', ...) with Trail as React.Fragment passthrough avoids useThree call from real drei"

key-files:
  created: []
  modified:
    - apps/workbench/src/features/spirit/components/spirit-companion-canvas.tsx
    - apps/workbench/src/features/spirit/__tests__/spirit-companion-canvas.test.tsx

key-decisions:
  - "Trail wraps mesh (not group) so it reads world position of the rotating icosahedron directly"
  - "attenuation=(t)=>t*t provides quadratic fade — fully opaque at head, zero at tail; decay=2 shortens visible history"
  - "interval=2 samples every 2 frames reducing segment density on fast rotation (mood=alert runs at 1.8 rad/s)"
  - "local=false samples world-space positions (correct for object rotating in place)"
  - "Trail mock in test is React.Fragment passthrough — renders children transparently so level-gate tests remain valid"

patterns-established:
  - "When drei components use useThree internally: add vi.mock('@react-three/drei', ...) in test file with passthrough shims"

requirements-completed: [PFX-04]

# Metrics
duration: 8min
completed: 2026-03-19
---

# Phase 12 Plan 02: Spirit Companion Trail Summary

**drei Trail wrapping spirit orb in SpiritCompanionCanvas — accent-colored quadratic-fade trail following orb rotation with frameloop=demand preserved**

## Performance

- **Duration:** 8 min
- **Started:** 2026-03-19T14:25:00Z
- **Completed:** 2026-03-19T14:33:00Z
- **Tasks:** 2
- **Files modified:** 2

## Accomplishments
- Added `Trail` import from `@react-three/drei` to spirit-companion-canvas.tsx
- Wrapped orb mesh in `<Trail width=0.15 color={color} length=8 decay=2 local=false interval=2 attenuation={(t)=>t*t}>` inside SpiritOrbScene
- meshRef remains on inner mesh — useFrame rotation logic unchanged
- frameloop="demand" preserved — Trail's mesh-line updates inside existing useFrame tick
- Added `@react-three/drei` mock (Trail as passthrough) to test file — all 8 tests pass

## Task Commits

Each task was committed atomically:

1. **Tasks 1+2: Add Trail import, wrap orb mesh, fix test mock** - `6cf3ea733` (feat)

**Plan metadata:** (docs commit — see below)

## Files Created/Modified
- `apps/workbench/src/features/spirit/components/spirit-companion-canvas.tsx` - Added drei Trail import; wrapped orb mesh in Trail component with quadratic attenuation
- `apps/workbench/src/features/spirit/__tests__/spirit-companion-canvas.test.tsx` - Added @react-three/drei mock with Trail as React.Fragment passthrough

## Decisions Made
- `attenuation={(t) => t * t}` — plan's recommended quadratic curve retained (confirmed prop exists in installed drei version)
- `local={false}` — world-space sampling is correct for an object rotating in-place
- `interval={2}` — samples every 2 frames to avoid dense segment buildup during fast (alert) rotation at 1.8 rad/s
- Test mock is a React passthrough (`<>{children}</>`) rather than `null` so level-gate geometry tests that query child test-ids still pass

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 2 - Missing Critical] Added @react-three/drei mock to test file**
- **Found during:** Task 2 (TypeScript and test verification)
- **Issue:** Trail calls useThree() internally in real drei code — test environment had no Canvas context, causing "R3F: Hooks can only be used within the Canvas component" error for all 7 tests that rendered a bound spirit
- **Fix:** Added `vi.mock("@react-three/drei", () => ({ Trail: ({ children }) => <>{children}</> }))` to the test file. Plan explicitly anticipated this and specified this exact fix.
- **Files modified:** apps/workbench/src/features/spirit/__tests__/spirit-companion-canvas.test.tsx
- **Verification:** All 8 tests pass after mock added
- **Committed in:** 6cf3ea733 (combined task commit)

---

**Total deviations:** 1 auto-fixed (Rule 2 — missing critical test mock)
**Impact on plan:** Plan anticipated this exact scenario and provided the fix specification. No scope creep.

## Issues Encountered
- Pre-existing TypeScript errors in `sidebar-icons.tsx` (TS2783 duplicate SVG props) and `ObservatoryVFXPools.tsx` (TS2322 RenderMode type) — out of scope, not caused by Trail changes
- `bun test` runs without jsdom environment; must use `bunx vitest run` from within `apps/workbench/` for correct test environment

## Next Phase Readiness
- PFX-04 complete — spirit companion orb now leaves accent-colored fading trail
- Ready for 12-03 (next particle effects plan) if any
- Trail is visible only when accentColor is non-null (spirit bound) — SpiritCompanionCanvas null guard at line 203 handles this

---
*Phase: 12-particle-effects*
*Completed: 2026-03-19*
