---
phase: 41-constellation-routes-spirit-trails
plan: 02
subsystem: ui
tags: [react-three-fiber, drei, three.js, spirit, observatory, animation]

# Dependency graph
requires:
  - phase: 41-constellation-routes-spirit-trails
    provides: "41-01: ConstellationRoutesLayer + spiritAccentColor prop threading to ObservatoryWorldScene"
  - phase: 39-store-persistence-and-derivation-foundations
    provides: "deriveSpiritResonanceConnections, SpiritEvolutionStore, useSpiritEvolutionStore"
provides:
  - "SpiritTrailsLayer: R3F component tracking player movement with 150-point trail buffer, mood/level-driven visuals"
  - "SpiritResonanceConnections: R3F component rendering 3 dashed cross-ring connections at spirit level 5"
  - "spiritMood + spiritLevel props threaded from spirit stores through ObservatoryWorldCanvas -> ObservatoryWorldScene"
affects:
  - 42-probe-telemetry-minimap
  - 43-station-interiors

# Tech tracking
tech-stack:
  added: []
  patterns:
    - "playerFocusRef-in-useFrame: pass RefObject into R3F child; read .current inside useFrame to avoid re-renders"
    - "trail-split-segments: render oldest quarter at 35% opacity as a second Line component for fade effect"
    - "alert-pulse-via-sin: oscillate opacity using sin(clock.elapsedTime * 4) * 0.5 + 0.5 for alert mood"

key-files:
  created:
    - apps/workbench/src/features/observatory/components/world-canvas/SpiritTrailsLayer.tsx
    - apps/workbench/src/features/observatory/components/world-canvas/SpiritResonanceConnections.tsx
  modified:
    - apps/workbench/src/features/observatory/components/world-canvas/observatory-world-scene-types.ts
    - apps/workbench/src/features/observatory/components/world-canvas/ObservatoryWorldScene.tsx
    - apps/workbench/src/features/observatory/components/ObservatoryWorldCanvas.tsx

key-decisions:
  - "SpiritTrailsLayer uses playerFocusRef (RefObject) not playerPosition (prop) to read position inside useFrame — avoids re-renders each frame"
  - "Trail rendering suppressed when spiritMood=dormant or no spirit bound — prevents ghost trails from unbound state"
  - "Trail split into two Line segments: newest 75% at full opacity, oldest 25% at 35% — no per-vertex alpha, cleaner approach"
  - "spiritMood + spiritLevel read via useSpiritStore/useSpiritEvolutionStore directly in ObservatoryWorldCanvas (not passed as ObservatorySpiritVisual fields)"
  - "Resonance connections at Y=8 (above station level, below star layer) with dashed=true, dashSize=3, gapSize=2"

patterns-established:
  - "MOOD_CONFIG lookup pattern: Record<SpiritMood, {opacityBase, widthBase, pulse}> for mood-driven visual parameters"
  - "levelMultiplier = 0.3 + (spiritLevel - 1) * 0.175: linear scale from 0.3 (level 1) to 1.0 (level 5)"

requirements-completed: [SPRT-01, SPRT-02, SPRT-03, SPRT-04, SPRT-05]

# Metrics
duration: 8min
completed: 2026-03-23
---

# Phase 41 Plan 02: Constellation Routes Spirit Trails Summary

**Spirit movement trails in observatory: 150-point luminous polyline with mood/level-driven opacity, dashed cross-ring resonance connections unlocked at level 5**

## Performance

- **Duration:** 8 min
- **Started:** 2026-03-23T02:54:35Z
- **Completed:** 2026-03-23T03:02:34Z
- **Tasks:** 2
- **Files modified:** 5 (2 created, 3 modified)

## Accomplishments

- SpiritTrailsLayer accumulates player movement points (sampled every 8 world units) into a 150-point fixed-capacity ring buffer, rendering as zwei `<Line>` components: newest 75% at full opacity + oldest 25% at 35% for trailing fade effect
- Mood-driven visuals: idle=dim (opacityBase=0.25, width=0.8), active=bright (0.55, 1.2), alert=pulsing (0.7, 1.5 with sin oscillation), dormant=hidden (trail suppressed entirely)
- Level multiplier (0.3 + (level-1)*0.175) scales intensity from faint wisps at level 1 to vivid ribbons at level 5
- SpiritResonanceConnections renders 3 dashed cross-ring station pairs (signal-receipts, targets-case-notes, run-watch) at spirit level 5, animated dash-offset flow
- spiritMood and spiritLevel prop threaded from useSpiritStore/useSpiritEvolutionStore through ObservatoryWorldCanvas into ObservatoryWorldScene

## Task Commits

1. **Task 1: Create SpiritTrailsLayer and SpiritResonanceConnections R3F components** - `d52daf0bc` (feat)
2. **Task 2: Wire spirit trail props through scene graph from stores** - `1d001ce4f` (feat)

## Files Created/Modified

- `apps/workbench/src/features/observatory/components/world-canvas/SpiritTrailsLayer.tsx` - R3F component: 150-point trail buffer, mood config, level multiplier, two-segment fade rendering
- `apps/workbench/src/features/observatory/components/world-canvas/SpiritResonanceConnections.tsx` - R3F component: dashed cross-ring lines from deriveSpiritResonanceConnections at level 5
- `apps/workbench/src/features/observatory/components/world-canvas/observatory-world-scene-types.ts` - Added spiritMood (SpiritMood|null) and spiritLevel (number) props to ObservatoryWorldSceneProps
- `apps/workbench/src/features/observatory/components/world-canvas/ObservatoryWorldScene.tsx` - Mounted SpiritTrailsLayer and SpiritResonanceConnections with SPRT comment markers
- `apps/workbench/src/features/observatory/components/ObservatoryWorldCanvas.tsx` - Added useSpiritStore + useSpiritEvolutionStore reads, pass spiritMood/spiritLevel downstream

## Decisions Made

- SpiritTrailsLayer accepts `playerFocusRef: RefObject<ObservatoryPlayerFocusState | null>` rather than a position prop — reads focus.position inside useFrame to avoid triggering React re-renders on every frame tick
- Trail dormant guard: `spiritMood !== "dormant"` in the conditional prevents the trail component from mounting when spirit is dormant (trails don't make sense for a sleeping spirit)
- Two-segment fade rather than per-vertex alpha — drei `<Line>` does not natively support per-vertex alpha with the `vertexColors` path reliably; two overlapping Line components is cleaner and well-tested in the codebase
- spiritMood/spiritLevel read from stores in ObservatoryWorldCanvas (not in ObservatoryTab) to keep the canvas self-contained and not require prop changes at ObservatoryTab level

## Deviations from Plan

None - plan executed exactly as written.

## Issues Encountered

None.

## Next Phase Readiness

- Spirit trail infrastructure complete; SPRT-01 through SPRT-05 requirements fulfilled
- Phase 42 (probe telemetry minimap) can proceed — no dependencies on this plan's output
- Phase 43 (station interiors) may want to suppress trails while in interior view (future consideration)

---
*Phase: 41-constellation-routes-spirit-trails*
*Completed: 2026-03-23*
