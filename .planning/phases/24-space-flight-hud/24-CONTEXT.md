# Phase 24: Space Flight HUD - Context

**Gathered:** 2026-03-20
**Status:** Ready for planning

<domain>
## Phase Boundary

DOM-based flight HUD overlay updating at 60fps via ref mutation — speed indicator bar, heading compass strip, target brackets on in-frustum stations, off-screen directional arrows, and distance readouts. All HTML/CSS positioned over the R3F Canvas. Zero setState calls in the update loop.

</domain>

<decisions>
## Implementation Decisions

### Speed Indicator (HUD-01)
- Vertical bar on the left edge of the viewport, 120px tall, 12px wide
- Fill from bottom — height percentage = currentSpeed / activeSpeedTierCap
- Color changes by speed tier: white=cruise, orange=boost, blue=dock approach
- Numeric readout below the bar: current speed in u/s, rounded to integer
- Ref-based: bar height and color set via ref.current.style in useFrame

### Heading Compass (HUD-02)
- Horizontal strip, top center, 400px visible window, ~1200px inner strip
- Cardinal directions (N/E/S/W) at 90° intervals + station labels at their angleDeg positions
- Ship heading extracted from quaternion → yaw angle → translateX on inner strip
- CSS overflow hidden on outer container, inner strip slides left/right
- Station labels colored with station colorHex
- Ref-based: inner strip transform.translateX set via ref in useFrame

### Target Brackets (HUD-03)
- Selected station gets 4 corner L-shapes (CSS borders, 2px solid, 10x10px corners)
- Scale inversely with distance: bracket size = clamp(800 / distance, 24, 80)px
- Color-coded: green=unvisited, gold=selected/active, red=mission target
- Positioned via Vector3.project(camera) → screen coords, set via ref.current.style.transform
- Only visible when station is in camera frustum (projected.z < 1)

### Off-Screen Arrows (HUD-04)
- Triangle arrow (CSS border-based or SVG) clamped to screen edge with 40px margin
- Arrow rotation: Math.atan2(centeredY, centeredX) pointing toward station
- Station name (8px, uppercase) + distance (10px, bold) labels beside arrow
- Behind-camera handling: flip projected coords when projected.z > 1
- Arrow color matches station colorHex
- Ref-based: transform + rotation set in useFrame

### Distance Readouts (HUD-05)
- Numeric distance below target bracket or off-screen arrow
- Format: `{distance}m` (integers, since 1 unit ≈ 1 meter)
- Fade opacity: 0 at 500+ units, 1.0 at 100 units (linear interpolation)
- Ref-based: textContent + opacity set in useFrame

### Performance Architecture (HUD-06)
- Single `SpaceFlightHud` React component wrapping all HUD elements
- Positioned absolute over the Canvas, pointer-events: none
- One `useFlightHud` hook that runs in useFrame:
  1. Read ship position, quaternion, speed from flight store (getState, not selector)
  2. Project all 6 station positions to screen coords once
  3. Classify each: in-frustum (bracket) vs off-screen (arrow) vs behind (flip+arrow)
  4. Write to all DOM refs in a single pass
- All DOM elements pre-rendered (not conditionally mounted) — use opacity/visibility for show/hide
- No useState, no useSelector subscriptions — pure ref mutation at 60fps

### Claude's Discretion
- Exact CSS styling (font family, opacity, shadows, gradients)
- Whether to add a subtle background blur/darken behind compass strip
- Exact corner bracket geometry (radius, gap between corners)
- Whether arrows should have a subtle glow/shadow for visibility against bright scenes
- HUD visibility toggle (show/hide all HUD elements)

</decisions>

<canonical_refs>
## Canonical References

### Flight state (data source)
- `apps/workbench/src/features/observatory/character/ship/flight-types.ts` — FlightState, SpeedTier, FlightConfig
- `apps/workbench/src/features/observatory/stores/observatory-store.ts` — flightState slice, dockingState slice
- `apps/workbench/src/features/observatory/character/ship/useFlightLoop.ts` — Ship position/velocity/quaternion refs

### Station positions
- `apps/workbench/src/features/observatory/world/stations.ts` — HUNT_STATION_PLACEMENTS, HUNT_STATION_LABELS
- `apps/workbench/src/features/observatory/world/observatory-world-template.ts` — stationPosition()

### Scene integration
- `apps/workbench/src/features/observatory/components/ObservatoryWorldCanvas.tsx` — Canvas wrapper (HUD overlay goes as sibling)
- `apps/workbench/src/features/observatory/components/ObservatoryTab.tsx` — Tab container (HUD mounts here alongside Canvas)

### Existing HUD patterns
- `apps/workbench/src/features/observatory/components/ObservatoryProbeHud.tsx` — Existing probe HUD (DOM overlay pattern reference)
- `apps/workbench/src/features/observatory/components/ObservatoryMissionHud.tsx` — Existing mission HUD

</canonical_refs>

<code_context>
## Existing Code Insights

### Reusable Assets
- `stationPosition(stationId)` — returns world Vec3 per station, project to screen for brackets/arrows
- `HUNT_STATION_PLACEMENTS` — angleDeg values for compass strip positioning
- `HUNT_STATION_LABELS` — station display names for compass and arrow labels
- `ObservatoryProbeHud` / `ObservatoryMissionHud` — existing DOM overlay HUD pattern (positioned absolute, pointer-events none)

### Established Patterns
- DOM overlays positioned absolute outside Canvas (ProbeHud, MissionHud, CinematicOverlay)
- `useFrame` with `getState()` for non-reactive store reads (established in flight controller)
- `useThree()` for camera access inside Canvas — but HUD is OUTSIDE Canvas so needs camera ref passed down or useThree via a bridge

### Integration Points
- ObservatoryTab renders Canvas + ProbeHud + MissionHud — add SpaceFlightHud alongside
- Camera ref needed outside Canvas for projections — either pass via ref from Canvas internals or use a Zustand store snapshot of camera matrices
- Flight store `flightState` provides speed, speedTier — read via getState() in animation frame

</code_context>

<specifics>
## Specific Ideas

- HUD should feel like Elite Dangerous — functional, not decorative. Orange/white monochrome with accent colors for stations
- Compass strip should feel like a real instrument — smooth sliding, station labels appear and slide through the window
- Target brackets should pulse subtly when the station is the mission target
- The whole HUD should be invisible in atlas mode — only appears in flight mode

</specifics>

<deferred>
## Deferred Ideas

- Ship health/shield bar — not applicable (no combat)
- Radar/3D minimap — Phase 25 (MAP-01)
- Boost cooldown indicator — could be part of speed bar, Claude's discretion
- Threat level indicator — future milestone

</deferred>

---

*Phase: 24-space-flight-hud*
*Context gathered: 2026-03-20 via smart discuss (auto mode)*
