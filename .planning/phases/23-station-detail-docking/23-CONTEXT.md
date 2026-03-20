# Phase 23: Station Detail + Docking - Context

**Gathered:** 2026-03-20
**Status:** Ready for planning

<domain>
## Phase Boundary

Add visual depth to stations (4-tier LOD, beacon lights, Fresnel rim glow, docking rings) and implement the three-zone docking system (approach → magnet-pull → dock lock) with automated docking and undocking sequences. Depends on Phase 20 (station geometry) and Phase 21 (flight controller for docking zones).

</domain>

<decisions>
## Implementation Decisions

### Station LOD Tiers (STN-02)
- drei `<Detailed>` component with distances [0, 60, 180, 500]
- **Near (0-60):** Full SpaceStationMesh geometry (~5K tris) + Fresnel rim glow + docking ring
- **Mid (60-180):** Simplified — torus ring + cylinder hub only, drop panels/bay/antennae (~500 tris)
- **Far (180-500):** drei Billboard + Text label showing station name, tinted with station colorHex
- **Beacon (500+):** Single Sprite with AdditiveBlending glow texture + PointLight
- Wrap existing SpaceStationMesh in `<Detailed>` — near tier uses existing component as-is

### Beacon Lights (STN-03)
- Sprite with procedural radial gradient texture (reuse pattern from ObservatoryNebulaClouds Canvas2D approach)
- AdditiveBlending, toneMapped=false for bloom visibility
- PointLight per station (intensity 3.0, distance 100) — visible through fog at extreme range
- Pulsing intensity via useFrame: `intensity = 2.5 + Math.sin(time * 1.5) * 0.5`
- Station colorHex tints both sprite and light

### Fresnel Rim Glow (STN-04)
- Custom ShaderMaterial on a scaled-up (1.3x) clone of the station bounding sphere
- Fragment shader: `float fresnel = pow(1.0 - dot(normal, viewDir), 4.0); gl_FragColor = vec4(color, fresnel * 0.6);`
- Transparent, AdditiveBlending, depthWrite false
- Station colorHex drives glow color
- Only renders at near LOD tier (inside Detailed distance 0-60)

### Docking Ring Geometry (STN-05)
- TorusGeometry (radius 6, tube 0.15, radialSegments 16, tubularSegments 48)
- Positioned at station center, oriented to face outward (toward approaching ships)
- 4 PointLights (small, intensity 1.5, distance 8) as guide lights at cardinal positions on the ring
- Slow Y rotation: 0.3 rad/s via useFrame
- Guide lights pulse (sin oscillation) when ship is in approach zone (<50 units)
- MeshBasicMaterial, station colorHex, toneMapped=false — visible through bloom

### Docking Zone Detection (DCK-01)
- useFrame distance check: `shipPosition.distanceTo(stationPosition)` per station each frame
- Three zones defined by distance:
  - **Approach** (50-180 units): Station label fades in, guide lights start pulsing
  - **Magnet-pull** (15-50 units): Ship velocity gently lerped toward dock point
  - **Dock lock** (<15 units): Automated docking sequence triggers
- `findNearestStation()` from useFlightLoop already computes distances — extend to return zone info
- Store current zone state in flight store: `dockingState: { stationId, zone: 'approach' | 'magnet' | 'dock' | null }`

### Magnet-Pull Behavior (DCK-02)
- When ship is 15-50 units from station dock point:
  - Compute direction from ship to dock point
  - Lerp ship velocity toward dock direction: `pullStrength = mapLinear(dist, 50, 15, 0, 0.3)`
  - Applied as a velocity bias in useFlightLoop, not overriding player input
  - Ship can still thrust away — magnet is a gentle suggestion, not a lock

### Dock Lock Sequence (DCK-03)
- Triggered when ship enters <15 units AND speed < 12 units/s (prevents slamming)
- Sequence:
  1. Disable flight input (set flightInputEnabled=false in store)
  2. Lerp ship position to dock point over 0.8s
  3. Camera lerps from chase to front-facing station view over 1.0s (offset: station position + (0, 5, 25) in station-facing direction)
  4. Set `dockingState.zone = 'dock'` and `dockingState.stationId` in store
  5. Existing ObservatoryTab can react to docked state for UI changes

### Undock (DCK-04)
- Triggered by E key press while docked, or `observatory.undock` command
- Sequence:
  1. Push ship 20 units away from station along dock axis at 15 units/s initial velocity
  2. Camera lerps back to chase offset over 0.6s
  3. Re-enable flight input
  4. Set `dockingState.zone = null`
  5. Brief 0.5s input grace period before full controls resume (prevents accidental re-dock)

### Claude's Discretion
- Exact Fresnel shader parameters (power exponent, opacity)
- Mid-LOD geometry simplification details
- Beacon sprite texture size and gradient falloff
- Dock point position relative to station center (offset toward docking ring)
- Camera angle during docked view

</decisions>

<canonical_refs>
## Canonical References

### Station geometry (from Phase 20)
- `apps/workbench/src/features/observatory/world/districtGeometry.tsx` — SpaceStationMesh (being wrapped in Detailed)
- `apps/workbench/src/features/observatory/world/districtGeometryResources.ts` — createSpaceStationLayout, mulberry32
- `apps/workbench/src/features/observatory/world/stations.ts` — WORLD_RADIUS, HUNT_STATION_PLACEMENTS, stationPosition

### Flight controller (from Phase 21)
- `apps/workbench/src/features/observatory/character/ship/useFlightLoop.ts` — findNearestStation(), velocity application (extend for magnet-pull)
- `apps/workbench/src/features/observatory/character/ship/flight-types.ts` — FlightState, FlightConfig, SpeedTier
- `apps/workbench/src/features/observatory/character/ship/SpaceFlightController.tsx` — Flight controller scene component
- `apps/workbench/src/features/observatory/stores/observatory-store.ts` — flightState slice (extend with dockingState)

### Scene rendering
- `apps/workbench/src/features/observatory/components/world-canvas/ObservatoryWorldScene.tsx` — Where station rendering happens
- `apps/workbench/src/features/observatory/components/ObservatoryWorldCanvas.tsx` — District layer rendering
- `apps/workbench/src/features/observatory/components/ObservatoryPostFX.tsx` — Bloom pipeline

</canonical_refs>

<code_context>
## Existing Code Insights

### Reusable Assets
- `SpaceStationMesh` — existing composable station geometry, becomes the near-LOD tier
- `ObservatoryNebulaClouds` procedural Canvas2D texture pattern — reuse for beacon sprite texture
- `findNearestStation()` in useFlightLoop — already computes ship-to-station distances each frame
- `lerpAlpha()` utility — smooth interpolation for dock sequence cameras
- `FovController` — already handles FOV transitions, can be extended for dock view

### Established Patterns
- `toneMapped={false}` + emissiveIntensity > 1 for bloom (beacons, ring)
- `useFrame` with ref-based mutation for animations (pulsing, rotation)
- drei `Billboard` + `Text` for world-space labels (used in waypoint beacons)
- Zustand store slices for state management (flight slice pattern)

### Integration Points
- `ObservatoryDistrictLayer` or `ObservatoryWorldScene` renders per-station geometry — wrap in `<Detailed>`
- `useFlightLoop` computes distances already — extend return value with zone info
- Observatory store `flightState` — add `dockingState` field
- `ObservatoryTab` can react to docked state for UI mode switching

</code_context>

<specifics>
## Specific Ideas

- Beacons should be the first thing you see when flying toward a station — bright, pulsing, unmistakable
- The magnet-pull should feel like a gentle tractor beam, not a hard snap — you can still fly away if you want
- Docking should feel satisfying — smooth camera transition, like Elite Dangerous auto-dock
- The Fresnel glow should make stations look alive — subtle atmospheric halo, not a force field

</specifics>

<deferred>
## Deferred Ideas

- Station approach UI with distance readouts — Phase 24 (HUD-05)
- Station arrival name card — Phase 25 (TRN-03)
- Proximity-based detail fade — Phase 25 (TRN-05)
- Station interiors — v7.0 (ENV-03)

</deferred>

---

*Phase: 23-station-detail-docking*
*Context gathered: 2026-03-20 via smart discuss (auto mode)*
