---
phase: 07-spirit-evolution-persistence
plan: "02"
subsystem: ui
tags: [react, three.js, r3f, zustand, vitest, animation, spirit, evolution]

# Dependency graph
requires:
  - phase: 07-01
    provides: useSpiritEvolutionStore with grantXp + per-kind level/xp records persisted in localStorage

provides:
  - SpiritCompanionCanvas reads bound spirit's level from useSpiritEvolutionStore and renders 4 level-gated geometry layers
  - ShadowRing (L2), OrbitTorus (L3), PulseRing (L4), OrbitShards (L5) with useFrame animations
  - Level-up burst: orb scales 1.5x over 0.6s via burstRef state machine in useFrame
  - emissiveIntensity scales with level (0.4 + (level-1)*0.12) giving progressive glow
  - 9 tests total (3 existing preserved, 6 new level-gated tests)

affects: [08-spirit-chamber-display, spirit-reactivity, companion-sidebar]

# Tech tracking
tech-stack:
  added: []
  patterns:
    - "Level-gated R3F geometry: conditional render with {level >= N && <Component />} pattern inside Canvas scene"
    - "Level-up burst via useRef state machine: burstRef.current = {active, t}, levelRef tracks prev level for change detection"
    - "Fixed-count refs array: declare ref0/ref1/ref2 individually (not in loop) to satisfy React Rules of Hooks"
    - "emissiveIntensity scales with level for progressive visual intensity"

key-files:
  created: []
  modified:
    - apps/workbench/src/features/spirit/components/spirit-companion-canvas.tsx
    - apps/workbench/src/features/spirit/__tests__/spirit-companion-canvas.test.tsx

key-decisions:
  - "OrbitShards refs use ref0/ref1/ref2 individual declarations (not useRef in array loop) to comply with React Rules of Hooks"
  - "burstRef state machine in SpiritOrbScene: levelRef tracks previous level, burstRef.current.t tracks animation progress; no additional re-render triggered"
  - "All geometry sub-components (ShadowRing, OrbitTorus, PulseRing, OrbitShards) are file-internal, not exported"

patterns-established:
  - "Level-gated R3F geometry: {level >= N && <Component />} inside Canvas scene"
  - "useRef state machine for fire-and-forget animations (burstRef pattern)"

requirements-completed: [SPRT-12, SPRT-13]

# Metrics
duration: 2min
completed: 2026-03-19
---

# Phase 7 Plan 02: Spirit Evolution Persistence — Level-Gated Geometry Summary

**SpiritCompanionCanvas extended with 4 level-gated geometry layers (ShadowRing L2, OrbitTorus L3, PulseRing L4, OrbitShards L5) and a 0.6s level-up burst animation driven by useFrame state machine**

## Performance

- **Duration:** 2 min
- **Started:** 2026-03-19T13:30:10Z
- **Completed:** 2026-03-19T13:32:25Z
- **Tasks:** 1 (TDD: RED → GREEN)
- **Files modified:** 2

## Accomplishments

- SpiritCompanionCanvas now reads `level` from `useSpiritEvolutionStore.use.evolution()[kind]?.level` and passes it to SpiritOrbScene
- Four level-gated geometry components added: ShadowRing (flat ring beneath orb at L2), OrbitTorus (rotating torus around orb at L3), PulseRing (breathing opacity ring at L4), OrbitShards (3 orbiting octahedra at L5)
- Level-up burst state machine fires when `level > levelRef.current`: scales orb from 1.0 to 1.5x and back over 0.6s with `Math.sin(progress * Math.PI)` envelope
- emissiveIntensity scales progressively with level: `0.4 + (level-1)*0.12` (L1=0.40, L5=0.88)
- All 9 tests pass (3 pre-existing regression + 6 new level-gated assertions)

## Task Commits

Each task was committed atomically:

1. **Task 1: Level-gated geometry layers + level-up burst in SpiritOrbScene** - `802606c93` (feat)

**Plan metadata:** (docs commit follows)

_Note: TDD task — RED (failing tests written first), GREEN (implementation added)_

## Files Created/Modified

- `apps/workbench/src/features/spirit/components/spirit-companion-canvas.tsx` - Added ShadowRing, OrbitTorus, PulseRing, OrbitShards components + level-up burst state machine + evolution store integration
- `apps/workbench/src/features/spirit/__tests__/spirit-companion-canvas.test.tsx` - Extended with 6 level-gated tests covering L1-L5 geometry gating

## Decisions Made

- **OrbitShards refs:** Declared as `ref0`, `ref1`, `ref2` individually (not in a loop) to satisfy React Rules of Hooks — hooks must be called unconditionally at component level
- **Burst state machine in SpiritOrbScene:** Uses `burstRef.current` (object with `active` + `t`) and `levelRef.current` (previous level) — both mutable refs updated in useFrame without triggering re-renders
- **Geometry components are file-internal:** ShadowRing/OrbitTorus/PulseRing/OrbitShards not exported — they only make sense within the R3F Canvas context

## Deviations from Plan

None - plan executed exactly as written.

## Issues Encountered

None. The R3F `useFrame` mock (`vi.fn()`) means animation callbacks don't run in tests, but `data-testid` attributes on `<group>` elements are visible in jsdom via React's HTML rendering of unrecognized tags — this is the documented test pattern for R3F.

## User Setup Required

None - no external service configuration required.

## Next Phase Readiness

- Level-gated geometry is live in the companion canvas — visual evolution feedback is complete
- The spirit evolution loop is now closed: XP accumulates via SpiritXpTracker (07-01) → level advances → canvas displays richer geometry
- Ready for any phase that displays or configures spirit evolution (spirit chamber enhancements, level badges, XP progress bars)

---
*Phase: 07-spirit-evolution-persistence*
*Completed: 2026-03-19*
