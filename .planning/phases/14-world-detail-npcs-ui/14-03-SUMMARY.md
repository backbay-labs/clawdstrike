---
phase: 14-world-detail-npcs-ui
plan: "03"
subsystem: ui
tags: [react-three-fiber, drei, framer-motion, zustand, observatory, r3f, svg, billboard]

# Dependency graph
requires:
  - phase: 14-world-detail-npcs-ui
    provides: ObservatoryWorldCanvas scene structure, ObservatoryProbeHud, ObservatoryTab overlay system, mission store
  - phase: 12-particle-effects
    provides: wawa-vfx patterns, ObservatoryHeroProp interactable prop system
provides:
  - 3D Billboard waypoint beacons (MissionObjectiveBeacon) pulsing above active mission objective stations
  - Circular SVG probe charge ring (ProbeChargeRingsvg) replacing flat text bar in ProbeHud during cooldown
  - Html occlude tooltips on interactable hero props (InteractablePropTooltip — one at a time)
  - Framer Motion AnimatePresence achievement popups outside Canvas on mission objective completion
  - Zustand achievement queue store (useAchievementStore) with pushAchievement/popAchievement actions
affects: [future-observatory-phases, huntronomer-tier1-integration]

# Tech tracking
tech-stack:
  added: []
  patterns:
    - "Achievement queue: Zustand store with push/pop pattern; AchievementToast auto-dismisses via setTimeout(onDone, 3200)"
    - "Waypoint beacon: Billboard + Text (drei) for screen-aligned 3D label + pulsing ringGeometry, NOT Html (perf)"
    - "Charge ring: SVG arc via strokeDasharray/strokeDashoffset on circle element; --spirit-accent CSS var for consistent theming"
    - "Prop tooltip: Html occlude (drei) only on interactable=true prop; one-at-a-time guaranteed by game state"
    - "AchievementLayer outside Canvas: sibling div with absolute bottom-6 right-4 z-30; AnimatePresence mode=popLayout"

key-files:
  created:
    - apps/workbench/src/features/observatory/stores/achievement-store.ts
  modified:
    - apps/workbench/src/features/observatory/components/ObservatoryWorldCanvas.tsx
    - apps/workbench/src/features/observatory/components/ObservatoryProbeHud.tsx
    - apps/workbench/src/features/observatory/components/ObservatoryTab.tsx

key-decisions:
  - "Waypoint beacons use Billboard + Text (drei), NOT Html — avoids per-frame DOM measurement perf trap at scale"
  - "Achievement popups placed outside Canvas (screen-space overlay) — Framer Motion AnimatePresence cannot run inside R3F Canvas"
  - "ProbeChargeRing is pure SVG in DOM, not R3F mesh — HUD is screen-space UI, no 3D needed"
  - "--spirit-accent CSS var reused for charge ring color — consistent with existing SpiritFieldInjector theming"
  - "One-at-a-time tooltip guarantee comes from game state: only one prop can have interactable=true simultaneously"

patterns-established:
  - "Achievement queue pattern: Zustand push/pop with auto-dismiss timer in AchievementToast component"
  - "SVG circular arc pattern: strokeDasharray=circumference, strokeDashoffset=circumference*(1-fill), rotate(-90) for top-start"
  - "AchievementToast spring slide: initial x:60 opacity:0 -> animate x:0 opacity:1 -> exit x:60 opacity:0 (stiffness:380 damping:28)"

requirements-completed: [UIP-01, UIP-02, UIP-03, UIP-04]

# Metrics
duration: ~45min
completed: 2026-03-19
---

# Phase 14 Plan 03: World Detail NPCs UI — Polish Elements Summary

**3D Billboard waypoint beacons, SVG probe charge ring, Html occlude prop tooltips, and Framer Motion achievement popups bring the Observatory HUD to AAA quality**

## Performance

- **Duration:** ~45 min
- **Started:** 2026-03-19
- **Completed:** 2026-03-19
- **Tasks:** 2 auto tasks + 1 human-verify checkpoint (all complete)
- **Files modified:** 4

## Accomplishments

- Created `achievement-store.ts` Zustand store with `pushAchievement`/`popAchievement` queue actions and `createSelectors` pattern
- Added `MissionObjectiveBeacon` (Billboard + Text + pulsing ringGeometry via useFrame) in ObservatoryWorldCanvas, mounted above active mission target station
- Added `InteractablePropTooltip` via drei `Html occlude` inside `ObservatoryHeroProp` — shows asset name label when `interactable=true`
- Replaced flat text charge bar in `ObservatoryProbeHud` with `ProbeChargeRingsvg` SVG circular arc (strokeDashoffset-driven, `--spirit-accent` color)
- Added `AchievementLayer` + `AchievementToast` in `ObservatoryTab` outside Canvas: AnimatePresence spring slide-in from right, auto-dismisses after 3.2s
- Wired mission `completedObjectiveIds` length change to `pushAchievement` via `useEffect` + `prevCompletedCountRef`
- All four UIP requirements (UIP-01 through UIP-04) verified in running workbench by user

## Task Commits

Each task was committed atomically:

1. **Task 1: Achievement store + waypoint beacons + prop tooltips** - `650a36de7` (feat)
2. **Task 2: ProbeChargeRing + AchievementLayer** - `ca203eb2e` (feat)
3. **Task 3: Human verify checkpoint** - approved by user (no code commit)

## Files Created/Modified

- `apps/workbench/src/features/observatory/stores/achievement-store.ts` — Zustand achievement queue store (created)
- `apps/workbench/src/features/observatory/components/ObservatoryWorldCanvas.tsx` — MissionObjectiveBeacon + InteractablePropTooltip (modified)
- `apps/workbench/src/features/observatory/components/ObservatoryProbeHud.tsx` — ProbeChargeRingsvg SVG arc replacing flat charge bar (modified)
- `apps/workbench/src/features/observatory/components/ObservatoryTab.tsx` — AchievementLayer + AchievementToast with AnimatePresence + mission wiring (modified)

## Decisions Made

- Waypoint beacons use Billboard + Text (drei), NOT Html elements — Html has per-frame DOM measurement cost that hurts performance at scale. Billboard is a pure R3F mesh approach.
- Achievement popups placed as screen-space DOM overlay outside Canvas — Framer Motion AnimatePresence cannot run inside the R3F Canvas tree; this is the architecturally correct plane for animated overlays.
- ProbeChargeRing implemented as pure SVG in DOM (not R3F mesh) since the HUD is already screen-space UI; no 3D scene involvement needed.
- `--spirit-accent` CSS variable reused for the charge ring accent color, maintaining visual consistency with the SpiritFieldInjector theming system.
- The "one tooltip visible at a time" constraint is enforced by game state (only one prop has `interactable=true` at a time), requiring no explicit deduplication logic.

## Deviations from Plan

None - plan executed exactly as written.

## Issues Encountered

None.

## User Setup Required

None - no external service configuration required.

## Next Phase Readiness

- All four UIP polish elements are live and verified
- Phase 14 (World Detail, NPCs, UI) is now complete — all three plans (14-01, 14-02, 14-03) shipped
- Observatory experience has reached AAA polish tier: post-processing, particles, cinematic camera, character polish, world detail, NPC crew, and contextual UI feedback all implemented
- No blockers for future phases

---
*Phase: 14-world-detail-npcs-ui*
*Completed: 2026-03-19*
