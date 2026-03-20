# Phase 22: Space Environment Art - Context

**Gathered:** 2026-03-20
**Status:** Ready for planning

<domain>
## Phase Boundary

Fill the void between stations with deep space atmosphere — 3-layer starfield (procedural shader + instanced stars + near dust), billboard nebula cloud patches near stations, depth fog scaled to the 300-unit world, emissive tube lanes connecting stations with animated energy flow, and particle streams flowing along those lanes. All visual — no gameplay mechanics.

</domain>

<decisions>
## Implementation Decisions

### Starfield Layers
- **Far background:** Port the "Star Nest" shader from Shadertoy (XlfGRj) to a GLSL ShaderMaterial on a large SphereGeometry (radius ~2000) with `side: THREE.BackSide`, `depthWrite: false`. Uniforms: `time` (animated), `resolution`. ~65 lines GLSL — volumetric fractal producing stars + nebula color naturally.
- **Mid-field stars:** 15K stars via InstancedMesh using dual-hemisphere technique (2x 7500 hemispheres). Pre-calculate rotation matrices at init time (not per-frame). Vertex shader twinkling via sin(time + instanceId). No perspective distortion.
- **Near dust:** drei `<Sparkles>` with count < 2000, size 0.3-0.8, speed 0.1. Parallaxes naturally during flight.
- Shader language: GLSL ShaderMaterial (not TSL) — pragmatic, Shadertoy port is straightforward. TSL port is optional future polish.

### Nebula Cloud Patches
- Billboard PlaneGeometry (8x8 units) with a cloud/smoke PNG texture, randomly rotated around Z axis
- 2-3 patches per station, positioned at station world position with ±20 unit random offsets
- PointLight per patch cluster colored by station `colorHex`, intensity 2.0, toneMapped=false — glows through bloom
- Opacity 0.4-0.6, AdditiveBlending for ethereal look
- Frustum-culled naturally by Three.js — no custom LOD needed at this scale

### Space Lane Rendering
- Reuse existing `transitRoutes` topology from `deriveObservatoryWorld` — lanes connect adjacent stations
- CatmullRomCurve3 from station A position to station B position (with a midpoint lifted Y+15 for arc)
- TubeGeometry(curve, 64, 0.3, 8) — thin glowing tubes
- MeshBasicMaterial with emissive color (#4488ff), toneMapped=false, emissiveIntensity 2.0 — visible through bloom
- Animated `dashOffset` via useFrame for energy-flow effect: material.dashSize=2, gapSize=4, offset += delta * 3
- Lane particle streams: wawa-vfx stretchBillboard, 150 particles per lane, distributed along curve via `curve.getPointAt(t)`, speed ~20 units/s, lifetime 2s, accent blue color

### Fog & Atmosphere
- FogExp2 with density 0.0008 — stations visible at ~500 units, geometry fades to void at ~800+
- Fog color: match environment recipe backgroundColor (dark navy, ~#060a14)
- Replace current linear fog with exponential — better depth cueing for vast spaces
- Stars background sphere is exempt (rendered behind fog via depthWrite:false)

### Claude's Discretion
- Exact Star Nest shader parameters (volsteps, iterations, brightness, saturation)
- Cloud texture source (can generate a simple radial gradient PNG or use a free asset)
- Exact sparkle colors and opacity
- Whether to add slow rotation to nebula patches
- Particle color gradient along lane (start vs end tint)

</decisions>

<canonical_refs>
## Canonical References

**Downstream agents MUST read these before planning or implementing.**

### World geometry and environment
- `apps/workbench/src/features/observatory/world/deriveObservatoryWorld.ts` — ObservatoryEnvironmentRecipe (fog, stars, background), ObservatoryTransitRouteRecipe (lane topology)
- `apps/workbench/src/features/observatory/world/observatory-world-template.ts` — OBSERVATORY_WORLD_TEMPLATE (environment defaults, transit route generation), stationPosition()
- `apps/workbench/src/features/observatory/world/stations.ts` — WORLD_RADIUS=300, station positions with elevationY

### Scene rendering
- `apps/workbench/src/features/observatory/components/world-canvas/ObservatoryWorldScene.tsx` — Where environment elements (stars, fog, lights) are rendered
- `apps/workbench/src/features/observatory/components/ObservatoryWorldCanvas.tsx` — Main canvas, transit route layer, environment setup
- `apps/workbench/src/features/observatory/components/ObservatoryPostFX.tsx` — Bloom pipeline (luminanceThreshold, mipmapBlur) — lanes and nebula must glow through this

### VFX system
- `apps/workbench/src/features/observatory/vfx/ObservatoryVFXPools.tsx` — Existing VFX pool declarations, add lane particle pool here

### Existing transit routes
- `apps/workbench/src/features/observatory/world/deriveObservatoryWorld.ts` — `ObservatoryTransitRouteRecipe` with `lanePoints` arrays connecting stations

</canonical_refs>

<code_context>
## Existing Code Insights

### Reusable Assets
- `ObservatoryTransitRouteRecipe.lanePoints` — pre-computed lane points between stations, can be used as CatmullRom control points
- `ObservatoryEnvironmentRecipe` — already has fogColor, fogNear, fogFar, starsRadius, backgroundColor — extend or override for new environment
- `wawa-vfx` VFXEmitter/VFXParticles — already used for probe discharge and thruster exhaust, reuse for lane particles
- drei `<Sparkles>` — already imported in the project (used for station motes)

### Established Patterns
- Environment elements rendered in ObservatoryWorldScene.tsx (stars, ambientLight, directionalLight, fog)
- `toneMapped={false}` + emissiveIntensity > 1 for bloom-visible materials (established in Phase 10)
- Lazy-loaded components for heavy scene elements
- `useFrame` with ref-based mutation for animations

### Integration Points
- ObservatoryWorldScene renders the environment layer — starfield and fog go here
- Transit route layer in ObservatoryWorldCanvas renders lane geometry — replace/enhance existing line rendering
- VFX pools mounted in ObservatoryWorldScene — add lane particle pool

</code_context>

<specifics>
## Specific Ideas

- The Star Nest shader should produce a subtle, not overwhelming, background — stars + faint nebula color, not a psychedelic fractal
- Nebula patches should feel like station "auras" — color-coded to the station, visible during approach
- Lanes should feel like energy highways — the flow direction should match lane orientation (A→B)
- The overall atmosphere should evoke Elite Dangerous crossed with No Man's Sky — not photorealistic, but cinematic and moody

</specifics>

<deferred>
## Deferred Ideas

- God rays from bright stars/stations — v7.0 polish (ENV post-processing)
- Lens flare on station beacons — Phase 23 (STN-03) or v7.0
- Asteroid/debris fields — v7.0 (ENV-01)
- Volumetric raymarched nebula — too expensive for v6.0, billboard approach sufficient

</deferred>

---

*Phase: 22-space-environment-art*
*Context gathered: 2026-03-20 via smart discuss (auto mode)*
