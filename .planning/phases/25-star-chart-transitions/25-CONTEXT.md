# Phase 25: Star Chart + Transitions - Context

**Gathered:** 2026-03-20
**Status:** Ready for planning

<domain>
## Phase Boundary

Replace the SVG ring minimap with a star chart showing station positions/status/player location, add click-to-autopilot navigation, implement boost transition effects (FOV punch + speed lines + bloom spike), station arrival name cards, and proximity-based detail fade. Two capability clusters: navigation (MAP) and cinematics (TRN).

</domain>

<decisions>
## Implementation Decisions

### Star Chart Minimap (MAP-01, MAP-04)
- SVG overlay replacing existing observatory-minimap-panel.tsx
- Top-down orthographic projection: station XZ positions mapped to SVG viewBox (ignore Y elevation for 2D chart)
- Player arrow at current XZ position, rotated to match ship heading (yaw from quaternion)
- Station dots colored by station colorHex, sized by importance/activity
- Status icons per station: filled circle=visited, ring=unvisited, star=mission target, diamond=docked
- Lane connections as SVG lines between connected stations (reuse transit route topology)
- Panel fits in existing sidebar minimap slot (observatory-minimap-panel)
- Update via requestAnimationFrame + getState() (same pattern as HUD)

### Flight Path Trail (MAP-02)
- SVG polyline of last 50 ship XZ positions, sampled every 0.5s
- Fading opacity along the trail (newest=1.0, oldest=0.1)
- Trail color: white with 50% opacity
- Circular buffer in a ref (push new, shift old when > 50)
- Clears on tab switch or mode change

### Click-to-Autopilot (MAP-03)
- Click a station dot on the star chart SVG → set autopilot target in flight store
- Autopilot logic in useFlightLoop:
  1. Compute direction from ship to target station
  2. Quaternion slerp ship rotation toward target (slerp factor 0.03 per frame for smooth turn)
  3. Apply cruise thrust along ship forward once roughly aligned (dot product > 0.95)
  4. Auto-cancel at magnet-pull zone (50 units) — docking system takes over
- Any WASD/mouse input immediately cancels autopilot (set autopilotTarget=null)
- Visual indicator on chart: dashed line from player to target station while autopilot active
- Store field: `autopilotTargetStationId: HuntStationId | null` in flight store

### Boost FOV Punch (TRN-01)
- Triggered when speed tier transitions to "boost"
- FOV curve: 60→90 over 0.3s (ease-in), hold at 90 for boost duration (~1.5s remaining), ease back 90→60 over 0.8s (ease-out)
- Extend existing FovController to handle boost FOV (already has sprint=52 and probe=35 targets)
- Target FOV during boost: 90 (already set in Phase 21 FovController)
- The ease-back happens when boost expires and tier returns to cruise

### Warp Speed Lines (TRN-02)
- 40 instanced thin CylinderGeometry (radius 0.02, length 3-6) arranged in a cone around the camera forward vector
- stretchBillboard via wawa-vfx (reuse existing VFX pool pattern)
- Triggered on boost activation, 0.5s particle lifetime, continuous emission for boost duration
- Positioned relative to camera (not world) — particles move with camera
- White/blue tint, toneMapped=false for bloom visibility
- VFX pool: "warp-speed-lines" in ObservatoryVFXPools (40 particles, StretchBillboard)

### Station Arrival Name Card (TRN-03)
- Triggered when ship enters approach zone (<180 units) for first time per station visit
- Uses existing ObservatoryCinematicOverlay letterbox pattern
- Sequence: letterbox bars slide in (0.3s) → station name fades in center-screen (0.3s) → hold 1.2s → fade out (0.3s) → bars retract (0.3s)
- Station name styled: uppercase, station colorHex, large font (32px)
- Subtitle: station label (e.g., "Horizon" for signal station)
- Only triggers once per station per session (track in a Set)

### Bloom Spike (TRN-04)
- During boost: temporarily reduce bloom luminanceThreshold from 0.85 to 0.5 for 0.8s
- Effect: everything in the scene glows brighter during the boost rush
- Ease back to 0.85 over 0.5s after spike ends
- Controlled by a ref in ObservatoryPostFX, toggled by a custom event or store flag

### Proximity Detail Fade (TRN-05)
- Station sub-elements fade in as ship approaches:
  - 180 units: station label appears (already handled by LOD far tier)
  - 120 units: NPC crew becomes visible (adjust LOD or opacity)
  - 80 units: docking ring guide lights start pulsing (already in Phase 23)
  - 60 units: full detail LOD tier activates (already in Phase 23 Detailed)
- Existing LOD system (drei Detailed at [0,60,180,500]) already handles most of this
- Additional: artifact count badge on station appears at 120 units (opacity fade via distance)

### Claude's Discretion
- Star chart SVG styling (background, grid lines, border)
- Speed line particle exact colors and sizes
- Letterbox bar height and animation easing
- Whether autopilot shows a HUD indicator ("AUTOPILOT" text)
- Exact proximity fade distance thresholds (can tune the LOD tiers)

</decisions>

<canonical_refs>
## Canonical References

### Existing minimap (being replaced)
- `apps/workbench/src/features/observatory/panels/observatory-minimap-panel.tsx` — Current SVG ring minimap (replace with star chart)

### Flight state
- `apps/workbench/src/features/observatory/character/ship/flight-types.ts` — FlightState, SpeedTier
- `apps/workbench/src/features/observatory/character/ship/useFlightLoop.ts` — Flight physics loop (extend with autopilot)
- `apps/workbench/src/features/observatory/stores/observatory-store.ts` — flightState, dockingState

### Cinematics
- `apps/workbench/src/features/observatory/components/ObservatoryCinematicOverlay.tsx` — Existing letterbox pattern
- `apps/workbench/src/features/observatory/components/ObservatoryPostFX.tsx` — Bloom pipeline (luminanceThreshold)
- `apps/workbench/src/features/observatory/components/ObservatoryWorldCanvas.tsx` — FovController

### VFX
- `apps/workbench/src/features/observatory/vfx/ObservatoryVFXPools.tsx` — VFX pool declarations

### Station data
- `apps/workbench/src/features/observatory/world/stations.ts` — HUNT_STATION_PLACEMENTS, stationPosition
- `apps/workbench/src/features/observatory/world/observatory-world-template.ts` — Transit route topology

</canonical_refs>

<code_context>
## Existing Code Insights

### Reusable Assets
- `observatory-minimap-panel.tsx` — existing SVG minimap with station dot rendering, replace contents but keep the panel integration
- `ObservatoryCinematicOverlay` — letterbox bars with fade-in/out, reuse for arrival name cards
- `FovController` — already handles sprint FOV=52, probe=35, boost=90; the FOV punch is already partially wired
- `wawa-vfx` VFXPools — add speed line pool alongside existing pools
- `HudCameraBridge` camera-bridge.ts — can provide camera data for star chart player heading

### Established Patterns
- rAF+getState() for 60fps DOM updates (from Phase 24 HUD)
- wawa-vfx VFXEmitter burst/continuous patterns
- Custom events for cross-component communication (observatory:shake, observatory:footstrike)
- Zustand store slices for new state fields

### Integration Points
- observatory-minimap-panel.tsx renders in sidebar — star chart replaces its content
- ObservatoryPostFX has bloom luminanceThreshold — needs a ref/prop to allow dynamic override
- useFlightLoop — extend with autopilot quaternion slerp logic
- ObservatoryCinematicOverlay — trigger arrival name card via store or custom event

</code_context>

<specifics>
## Specific Ideas

- Star chart should feel like a tactical map — clean, functional, not decorative
- Autopilot should feel hands-off — click and watch the ship fly itself, satisfying
- Boost should be the most dramatic moment in the flight experience — FOV+lines+bloom all at once
- Arrival name card should feel like entering a new zone in a AAA game — brief, impactful, doesn't interrupt gameplay

</specifics>

<deferred>
## Deferred Ideas

- 3D R3F View minimap — too complex for v6.0, SVG is sufficient
- Warp tunnel effect (full tube geometry) — v7.0 polish
- Radial blur during boost — postprocessing cost concern, defer
- Autopilot voice/text callouts — v7.0 with audio system

</deferred>

---

*Phase: 25-star-chart-transitions*
*Context gathered: 2026-03-20 via smart discuss (auto mode)*
