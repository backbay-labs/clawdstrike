# Requirements: ClawdStrike Workbench v6.0 Observatory Space Flight

**Defined:** 2026-03-20
**Core Value:** Analysts fly a ship through an immersive space environment to reach floating stations — the journey between stations is as engaging as the destination

## Constraints

- **Renderer**: Bump three to 0.171+, swap Canvas gl prop to async WebGPURenderer (one-liner — automatic WebGL2 fallback). Existing MeshStandardMaterial and postprocessing work as-is.
- **Shaders**: New shaders (starfield, nebula, lanes) should use TSL for WebGPU/WebGL dual compilation. Not a hard gate — raw GLSL still works via WebGL fallback.
- **Testing**: All existing observatory tests must pass after renderer swap and scale change.

## v6.0 Requirements

### Space World

- [x] **SPC-01**: Stations positioned at 200-500 unit radius with varied elevations (Y -15 to +60), logarithmic depth buffer enabled, replacing the flat Y=0 ring
- [x] **SPC-02**: 3-layer starfield — procedural Star Nest shader (far background sphere), InstancedMesh mid-field stars (15K, dual-hemisphere), drei Sparkles near-dust (<2K particles)
- [x] **SPC-03**: Billboard nebula cloud patches near stations — plane geometry with cloud texture, colored point lights, visible through bloom
- [x] **SPC-04**: Void space between stations with depth fog scaled to new world radius
- [x] **SPC-05**: Space lanes rendered as emissive CatmullRomCurve3 TubeGeometry between connected stations with animated dash-offset energy flow
- [x] **SPC-06**: Space lane particle streams — instanced particles flowing along lane curves via wawa-vfx stretchBillboard

### Flight Controller

- [x] **FLT-01**: Ship mesh replaces capsule avatar — visible ship model with thruster geometry
- [x] **FLT-02**: Velocity-based flight controller with quaternion rotation (no gravity, no Rapier) — WASD for thrust/strafe, mouse for pitch/yaw
- [x] **FLT-03**: Velocity damping for "flight assist" feel (configurable damping factor ~1.0-2.0)
- [x] **FLT-04**: Three speed tiers — cruise (normal cap), boost (3x with cooldown + FOV punch), dock approach (reduced cap near stations)
- [x] **FLT-05**: Chase camera following ship with lerp lag (offset in ship's local space, smooth follow factor ~0.05-0.1)
- [x] **FLT-06**: Ship thruster particle effects — exhaust trails scaling with thrust intensity via wawa-vfx

### Station Design

- [x] **STN-01**: Floating space station geometry replacing ground-level buildings — composable primitives (torus habitat ring, cylinder hub, plane solar panels, box docking bay) driven by per-station seed
- [x] **STN-02**: 4-tier LOD via drei Detailed — near (full geometry ~5K tris), mid (simplified hub+ring ~500 tris), far (billboard sprite + Html label), beacon (single sprite + point light)
- [x] **STN-03**: Station beacon lights visible at extreme distance — emissive bloom sprites with additive blending, pulsing intensity
- [x] **STN-04**: Fresnel rim-glow shader on near-LOD stations for atmospheric halo effect
- [x] **STN-05**: Docking ring geometry around each station — visual landing approach guide with flanking guide lights

### Docking System

- [x] **DCK-01**: Three-zone approach system — approach (>50 units: beacon + label), magnet-pull (15-50 units: gentle lerp toward dock axis), dock lock (<15 units: automated sequence)
- [x] **DCK-02**: Magnet-pull zone lerps ship toward docking point with distance-proportional strength
- [x] **DCK-03**: Dock lock triggers automated camera transition (1s), disables flight controls, transitions to docked station view
- [x] **DCK-04**: Undock action restores flight controls and pushes ship away from station with launch velocity

### HUD & UI

- [x] **HUD-01**: Speed indicator — vertical bar showing current velocity relative to speed tier cap
- [x] **HUD-02**: Heading compass strip — horizontal bar at top with cardinal directions and station labels at angular positions
- [x] **HUD-03**: Target brackets — diamond/L-corner shapes around selected station, scale inversely with distance, color-coded by status
- [x] **HUD-04**: Off-screen station arrows — directional arrows at screen edges for stations not in view, with station name + distance
- [x] **HUD-05**: Distance readouts — numeric distance count attached to station markers, fading in during approach
- [x] **HUD-06**: All HUD elements use DOM ref-based useFrame mutation (never setState) for 60fps updates

### Star Chart

- [x] **MAP-01**: Star chart minimap replacing SVG ring map — shows all station positions, player location with facing indicator, and pressure lane connections
- [x] **MAP-02**: Flight path trail — player's recent trajectory drawn as a fading line on the chart
- [x] **MAP-03**: Click-to-autopilot — click a station on the chart to engage auto-navigation toward it
- [x] **MAP-04**: Station status icons on chart — mission active, artifacts pending, docked, unvisited indicators

### Transitions & Cinematics

- [x] **TRN-01**: Boost/warp FOV punch — camera FOV animates 60→90→60 over 1.1s during boost activation
- [x] **TRN-02**: Warp speed lines — instanced tube particles radiating from screen center during boost, visible through bloom
- [x] **TRN-03**: Station arrival name card — letterbox bars + station name slide-in (1.2s hold) via ObservatoryCinematicOverlay
- [x] **TRN-04**: Bloom spike during warp — temporary increase in bloom intensity and luminance during boost transition
- [x] **TRN-05**: Proximity-based detail fade — station sub-elements (artifact counts, threat level, NPC visibility) fade in as camera approaches, marker fades out

### Discovery & Missions

- [x] **DSC-01**: Progressive station reveal — first visit shows only hub + 2 nearest stations; others appear as dim "uncharted" markers
- [x] **DSC-02**: Station discovery animation — lights power on, structures unfold when player first approaches an uncharted station
- [x] **DSC-03**: Mission waypoint path — glowing trail from player to mission objective station, visible in flight
- [x] **DSC-04**: Mission-guided flight flow — mission objectives direct player between stations ("Signal detected at Horizon, investigate" → fly there)

## v7.0 Requirements (Deferred)

### Audio
- **AUD-01**: Thruster engine audio with intensity-based pitch/volume
- **AUD-02**: Ambient space music with station proximity crossfade
- **AUD-03**: Docking sequence audio cues

### Multiplayer
- **MP-01**: Other analyst ships visible in the space (NATS presence)
- **MP-02**: Shared mission markers and cooperative waypoints

### Ship Customization
- **SHIP-01**: Spirit companion changes ship appearance (color, trail, thruster style)
- **SHIP-02**: Ship model selection (3-4 variants)

### Advanced Environment
- **ENV-01**: Asteroid/debris fields between stations with collision avoidance
- **ENV-02**: Anomaly encounters — floating data fragments in void space tied to mission system
- **ENV-03**: Station interiors (docked interior detail view)

## Out of Scope

| Feature | Reason |
|---------|--------|
| Full Newtonian physics | Arcade flight feel is better for an analyst tool — damping provides "flight assist" |
| Rapier physics for flight | Velocity-based is simpler, more controllable, and Rapier adds overhead for zero-G |
| Combat/weapons | Observatory is investigation, not combat |
| Procedural planet generation | Stations are the destination, not planets |
| VR/XR support | Desktop-first; VR deferred indefinitely |
| Real GLTF station models in v6.0 | Procedural primitives first; Meshy/Kenney GLBs are v7.0 polish |
| Multiple camera modes (cockpit/external) | Chase camera only for v6.0; cockpit view deferred |

## Traceability

| Requirement | Phase | Status |
|-------------|-------|--------|
| SPC-01 | Phase 20 | Complete |
| SPC-02 | Phase 22 | Complete |
| SPC-03 | Phase 22 | Complete |
| SPC-04 | Phase 22 | Complete |
| SPC-05 | Phase 22 | Pending |
| SPC-06 | Phase 22 | Pending |
| FLT-01 | Phase 21 | Complete |
| FLT-02 | Phase 21 | Complete |
| FLT-03 | Phase 21 | Complete |
| FLT-04 | Phase 21 | Complete |
| FLT-05 | Phase 21 | Complete |
| FLT-06 | Phase 21 | Complete |
| STN-01 | Phase 20 | Complete |
| STN-02 | Phase 23 | Complete |
| STN-03 | Phase 23 | Complete |
| STN-04 | Phase 23 | Complete |
| STN-05 | Phase 23 | Complete |
| DCK-01 | Phase 23 | Complete |
| DCK-02 | Phase 23 | Complete |
| DCK-03 | Phase 23 | Complete |
| DCK-04 | Phase 23 | Complete |
| HUD-01 | Phase 24 | Complete |
| HUD-02 | Phase 24 | Complete |
| HUD-03 | Phase 24 | Complete |
| HUD-04 | Phase 24 | Complete |
| HUD-05 | Phase 24 | Complete |
| HUD-06 | Phase 24 | Complete |
| MAP-01 | Phase 25 | Complete |
| MAP-02 | Phase 25 | Complete |
| MAP-03 | Phase 25 | Complete |
| MAP-04 | Phase 25 | Complete |
| TRN-01 | Phase 25 | Complete |
| TRN-02 | Phase 25 | Complete |
| TRN-03 | Phase 25 | Complete |
| TRN-04 | Phase 25 | Complete |
| TRN-05 | Phase 25 | Complete |
| DSC-01 | Phase 26 | Complete |
| DSC-02 | Phase 26 | Complete |
| DSC-03 | Phase 26 | Complete |
| DSC-04 | Phase 26 | Complete |

**Coverage:**
- v6.0 requirements: 40 total
- Mapped to phases: 40
- Unmapped: 0 ✓

---
*Requirements defined: 2026-03-20*
*Last updated: 2026-03-20 after roadmap creation (v6.0 Phases 20-26)*
