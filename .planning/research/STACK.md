# Technology Stack

**Project:** ClawdStrike Workbench — v10.0 Observatory Analyst Toolkit
**Researched:** 2026-03-22
**Scope:** Stack additions for 7 new features ONLY — existing R3F/drei/three/Zustand/wawa-vfx/Rapier stack is validated and unchanged.

---

## Situation Summary

The workbench already has a fully validated 3D stack: `@react-three/fiber ^9.0.0`, `@react-three/drei ^10.7.7`, `three ^0.171.0`, `@react-three/postprocessing ^3.0.4`, `wawa-vfx ^1.2.10`, `@react-three/rapier ^2.2.0`, and `@types/three ^0.183.1`. All are installed and in active use.

**The 7 new features require zero new npm packages.** Every capability needed is already in the installed stack or addressable with Three.js primitives + custom GLSL. The decisions below are about which existing APIs to use for each feature, not what to add.

---

## Recommended Stack by Feature

### Feature 1: Replay Annotation Canvas (3D pin drops + freehand trails)

**Approach: R3F event raycasting + drei `Html` + `Line` + `localStorage`**

R3F transparently handles pointer events via raycasting on any mesh with `onClick`/`onPointerDown` props. Pin drops are: `onClick` on an invisible ground plane mesh → capture `THREE.Vector3` world hit point → store annotation in existing `localStorage` persistence layer (`observatory-replay-persistence.ts` already exists).

Pin visualization: `drei <Html>` with `distanceFactor` and `occlude` props renders the annotation card at the 3D position. For freehand trails, accumulate pointer-move world positions while mouse is held, then render with `drei <Line>` (already imported in `ObservatoryWorldCanvas.tsx`).

| Component | Source | Status |
|-----------|--------|--------|
| `onClick` / `onPointerDown` on mesh | `@react-three/fiber` | Already in use — `ObservatoryWorldCanvas.tsx` uses `ThreeEvent` |
| `<Html distanceFactor occlude>` | `@react-three/drei` | Already imported in `ObservatoryWorldCanvas.tsx` |
| `<Line>` | `@react-three/drei` | Already imported |
| `localStorage` persistence | Existing `observatory-replay-persistence.ts` | Already built — extend `PersistedObservatoryReplayArtifacts` with a `pins` field |

**No new packages.** The `ObservatoryReplayAnnotation` type already exists in `types.ts` with `districtId`, `body`, `frameIndex` — add `worldPosition: [number, number, number]` field to store pin coordinates.

**Raycasting pattern for ground plane:**

```typescript
// Invisible ground mesh receives clicks for pin placement
<mesh
  rotation={[-Math.PI / 2, 0, 0]}
  visible={false}
  onClick={(e: ThreeEvent<MouseEvent>) => {
    e.stopPropagation();
    onPinDrop(e.point); // THREE.Vector3 world coordinate
  }}
>
  <planeGeometry args={[400, 400]} />
</mesh>
```

**Caveat:** `drei <Html>` `distanceFactor` scaling can stutter during fast camera transitions (known issue in drei discussions). Compensate by using `occlude={false}` or clamping the distanceFactor range.

---

### Feature 2: Probe Delta Cards (floating 3D info cards)

**Approach: `drei <Html>` with `transform` + `Billboard`**

After a probe fires, a card floats near the target station. The card is a DOM element (glassmorphism CSS, shadcn primitives) positioned in 3D space.

`<Html transform sprite distanceFactor={8}>` renders the card as a billboard that scales with camera distance and always faces the camera. `transform` mode enables matrix3d positioning that tracks the 3D point correctly in non-fullscreen canvas contexts (the observatory tab is a pane, not fullscreen — `transform` mode is required for correct behavior).

| Component | Source | Status |
|-----------|--------|--------|
| `<Html transform sprite distanceFactor>` | `@react-three/drei` | Already imported in `ObservatoryWorldCanvas.tsx` |
| `<Billboard>` | `@react-three/drei` | Already imported in `ObservatoryWorldCanvas.tsx` |
| Station positions | `OBSERVATORY_STATION_POSITIONS` | Already in `observatory-world-template.ts` |
| Probe state | `observatory-store.ts` | Already exists |

**No new packages.** The probe delta content (pressure shift, explanation, recommended action) comes from existing `probeConsequences.ts` + `ObservatoryStationExplanation` type.

**Critical note on `<Html>` in non-fullscreen canvas:** Do NOT use `center` prop or custom CSS positioning — use `transform` mode only. The `center` prop is ignored in `transform` mode, and non-transform mode misaligns in pane context. This is a known gotcha documented in drei discussions.

```typescript
<Html
  position={[stationX, stationY + 4, stationZ]}
  distanceFactor={8}
  transform
  sprite
  style={{ pointerEvents: "none", width: "220px" }}
>
  <ProbeDeltaCard diff={probeDiff} />
</Html>
```

---

### Feature 3: Split-Screen Compare Mode (then vs now, two observatory worlds)

**Approach: `drei <RenderTexture>` for the secondary "then" world + portal**

This is the most architecturally novel feature. The pattern: one primary R3F Canvas renders the live ("now") world normally. The "then" (replay frame) world renders into a `<RenderTexture>` portal and is displayed as a texture on a screen-filling plane mesh positioned at the side of the primary viewport.

`drei <RenderTexture>` creates an isolated rendering context (a `WebGLRenderTarget` under the hood). Its children form an independent scene with their own camera, lights, and meshes. Crucially, it shares the same GL context as the parent canvas, so there is no second WebGL context and no context budget impact.

The diff overlay (highlighting changed stations) is a second pass: after both scenes render, use a `drei <Line>` + emissive material on changed-station positions in the primary scene where `emphasisDelta > threshold` from `compareObservatoryReplaySnapshots()` (already exists in `observatory-replay-diff.ts`).

| Component | Source | Status |
|-----------|--------|--------|
| `<RenderTexture>` | `@react-three/drei ^10.7.7` | Installed, NOT yet imported — first use in project |
| `compareObservatoryReplaySnapshots()` | `observatory-replay-diff.ts` | Already built |
| Station diff types `ObservatoryReplayDistrictDiff` | `observatory-replay-diff.ts` | Already built |
| Replay snapshot types | `observatory-telemetry.ts` | Already built |

**No new packages.** `<RenderTexture>` is exported from `@react-three/drei` which is already at `^10.7.7`.

**Implementation shape:**

```typescript
// Split screen: "now" renders normally, "then" renders into RenderTexture
// The texture is applied to a plane mesh offset to the left half of the viewport

<mesh position={[-viewport.width / 4, 0, -1]}>
  <planeGeometry args={[viewport.width / 2, viewport.height]} />
  <meshBasicMaterial>
    <RenderTexture attach="map" frames={Infinity}>
      <ReplayWorldScene snapshot={replaySnapshot} />
    </RenderTexture>
  </meshBasicMaterial>
</mesh>
```

**Why not two separate Canvas elements:** A second Canvas opens a second WebGL context. Context budgets are ~8-16 per page. The observatory is already one context; adding another would work but is wasteful and causes context loss risk. `<RenderTexture>` shares the context and is the correct approach for same-canvas split.

**Why not `drei <View>` (scissor):** `<View>` requires a persistent parent Canvas that wraps both views as siblings, conflicting with the existing pane architecture where the Canvas mounts inside a pane tab. `<RenderTexture>` is composable inside the existing Canvas without structural changes.

---

### Feature 4: Constellation Routes (starfield traces from completed missions)

**Approach: `drei <Line>` + `drei <Stars>` + `THREE.CatmullRomCurve3`**

Completed mission routes are permanent CatmullRom curves drawn between visited station positions at high altitude (Y = ~40 units above the world plane, above station structures). Each constellation is a `<Line>` with `lineWidth={1.5}` and `AdditiveBlending` so it glows against the starfield.

Station name labels at constellation nodes: `drei <Text>` (already imported) or `drei <Html>` at node positions. Click handlers use R3F's built-in `onClick` on an invisible `SphereGeometry` at each node.

| Component | Source | Status |
|-----------|--------|--------|
| `<Line>` (CatmullRom points) | `@react-three/drei` | Already imported |
| `<Text>` | `@react-three/drei` | Already imported in `ObservatoryWorldCanvas.tsx` |
| `THREE.CatmullRomCurve3.getPoints()` | `three ^0.171.0` | Already in use in `MissionWaypointTrail.tsx` |
| `AdditiveBlending` | `three ^0.171.0` | Already in use in `GhostTraceLayer.tsx` |
| Completed mission state | `observatory-store.ts` | Extend with `completedConstellations` array |

**No new packages.** Constellation geometry is the same tube/line approach already used in `MissionWaypointTrail.tsx` and `ObservatorySpaceLanes.tsx`.

**Persistence:** Completed constellation data (station sequence + mission ID + label) persists to `localStorage` using the same `observatory-replay-persistence.ts` pattern — add a `constellations` field to `PersistedObservatoryReplayArtifacts`.

---

### Feature 5: Threat Topology Heatmap (volumetric ground-plane pressure gradient)

**Approach: Custom `THREE.ShaderMaterial` on a wide transparent plane + `THREE.DataTexture`**

The heatmap is a transparent plane mesh (Y = -0.5, covers the world floor radius ~200 units) with a custom ShaderMaterial that reads a `DataTexture` mapping station positions to pressure intensities. The fragment shader samples the texture, computes distance-weighted radial falloff per station, and outputs a color gradient (cool → hot: `#0044ff` → `#ff2200`) with `AdditiveBlending`.

The `DataTexture` is a small `Float32Array` (8 stations × 4 channels = 32 floats) updated when telemetry changes via `texture.needsUpdate = true`. This avoids rebuilding geometry on each telemetry tick.

The codebase already has `THREE.ShaderMaterial` patterns established in `StationFresnelGlow.tsx` and `ObservatorySpaceLanes.tsx` (custom GLSL with uniforms). The heatmap shader follows the same `/* glsl */` tagged template literal convention.

| Component | Source | Status |
|-----------|--------|--------|
| `THREE.ShaderMaterial` | `three ^0.171.0` | Already used in `StationFresnelGlow.tsx` |
| `THREE.DataTexture` | `three ^0.171.0` | Built-in, not yet used — first use in project |
| `THREE.AdditiveBlending` | `three ^0.171.0` | Already used in `GhostTraceLayer.tsx` |
| Station pressure values | `observatory-store.ts` — `emphasisByStation` | Already computed in telemetry |
| Station world positions | `OBSERVATORY_STATION_POSITIONS` | Already in `observatory-world-template.ts` |

**No new packages.** `THREE.DataTexture` is part of Three.js core at `^0.171.0`.

**Shader approach:** Each station contributes a radial pressure dome to the fragment shader. With 8 stations, this is 8 distance calculations per fragment — trivially fast on GPU. The uniform block passes station positions as `vec3[8]` and intensities as `float[8]`.

```glsl
// Fragment shader core — pressure heatmap
uniform vec3 uStationPositions[8];
uniform float uPressureValues[8];
uniform float uTime;

void main() {
  float totalPressure = 0.0;
  for (int i = 0; i < 8; i++) {
    float dist = length(vWorldPos.xz - uStationPositions[i].xz);
    float falloff = max(0.0, 1.0 - dist / 40.0);
    totalPressure += uPressureValues[i] * falloff * falloff;
  }
  // Pulse with telemetry time
  float pulse = 0.85 + 0.15 * sin(uTime * 2.5);
  totalPressure *= pulse;
  // Cool → hot colormap
  vec3 cool = vec3(0.0, 0.27, 1.0);
  vec3 hot = vec3(1.0, 0.13, 0.0);
  vec3 color = mix(cool, hot, clamp(totalPressure, 0.0, 1.0));
  gl_FragColor = vec4(color, clamp(totalPressure * 0.55, 0.0, 0.45));
}
```

**Performance note:** Update pressure uniforms (not DataTexture) on telemetry change via `meshRef.current.material.uniforms.uPressureValues.value = pressureArray`. `needsUpdate` is only required when changing texture data, not float uniforms.

---

### Feature 6: Spirit Resonance Trails (luminous trails between stations, level-gated)

**Approach: `drei <Trail>` (already imported in spirit companion) + `THREE.CatmullRomCurve3` path animation**

`Trail` is already imported and used in `spirit-companion-canvas.tsx`. The resonance trails follow the spirit entity's position as it moves between stations along predefined `CatmullRomCurve3` paths (the same curves used by `MissionWaypointTrail.tsx`). The spirit object moves along the path via `getPointAt(t)` in `useFrame`, and `<Trail>` automatically records its world-space positions.

For level-5 hidden inter-station connections: these are additional `<Line>` components (the "resonance web") rendered with `opacity={0}` until XP level === 5, then faded in via `motion` (already a dep) driving a CSS variable or a ref-mutated material opacity.

| Component | Source | Status |
|-----------|--------|--------|
| `<Trail width color length decay attenuation>` | `@react-three/drei` | Already imported and used in `spirit-companion-canvas.tsx` |
| `THREE.CatmullRomCurve3.getPointAt()` | `three ^0.171.0` | Already used in `MissionWaypointTrail.tsx` |
| Spirit XP level | `spirit-evolution-store.ts` | Already exists |
| Spirit accent color | `spirit-store.ts` | Already exists |
| Level gate logic | `spirit-evolution-store.ts` | Already exists (level-gated geometry in companion canvas) |

**No new packages.** `Trail` uses `meshline` internally — meshline is a transitive dep of drei (not a direct dep you add). The `Trail` component handles its own geometry lifecycle.

**Trail configuration for resonance:**

```typescript
<Trail
  width={0.3}
  color={spiritAccentColor}
  length={12}
  decay={1.5}
  local={false}
  attenuation={(w) => w * w}  // quadratic fade for luminous tip
>
  <mesh ref={spiritPathRef} visible={false}>
    <sphereGeometry args={[0.01]} />
  </mesh>
</Trail>
```

The invisible mesh acts as the target — `Trail` follows it automatically (first child as target). The spirit's visual mesh is separate and can lag behind the path mesh for visual looseness.

---

### Feature 7: Station Interior Zones (seamless camera-push into per-station interiors)

**Approach: `drei <CameraControls>` with `fitToBox()` / `setLookAt()` + conditional interior `<group>` visibility**

The transition is a camera animation pushing from the exterior world view into a bounding box surrounding the station's interior geometry. `drei <CameraControls>` (part of `@react-three/drei ^10.7.7`) wraps the `camera-controls` library which exposes `fitToBox(object, enableTransition)` — a smooth camera glide to frame an object over ~0.6s.

Interior geometry is a standard Three.js `<group>` positioned at the station's world coordinates, invisible by default (`visible={false}`), swapped to visible before the camera transition begins. The interior contains room geometry (walls, floor, ceiling using `BoxGeometry` primitives), NPC crew (already built in `npcCrew.tsx`), and emissive accent elements.

| Component | Source | Status |
|-----------|--------|--------|
| `<CameraControls>` | `@react-three/drei ^10.7.7` | Installed, NOT yet imported — first use in project |
| `cameraControlsRef.current.fitToBox(target, true)` | `camera-controls v3` (bundled with drei 10.5+) | Available via drei |
| `cameraControlsRef.current.setLookAt(x,y,z, tx,ty,tz, true)` | `camera-controls v3` | Available via drei |
| `StationNpcCrew` | `world/npcCrew.tsx` | Already built |
| `<OrbitControls>` (current) | `@react-three/drei` | Must be REPLACED by `<CameraControls>` in interior mode, or disabled |

**No new packages.** `<CameraControls>` is already bundled in `@react-three/drei ^10.7.7`. The underlying `camera-controls` package is a transitive dep — not added directly.

**Critical: CameraControls vs OrbitControls.** The observatory currently uses `<OrbitControls>` (imported in `ObservatoryWorldCanvas.tsx`). For interior transitions, `<CameraControls>` is needed because OrbitControls has no programmatic `fitToBox()` API. The approach: replace `<OrbitControls>` with `<CameraControls makeDefault>` globally. `CameraControls` is a drop-in superset — all OrbitControls-like user interaction continues to work. The `makeDefault` prop registers it with the R3F camera system.

**Drei v10 migration note:** Drei 10.5+ bundles `camera-controls v3`. In v3, `setLookAt` no longer auto-normalizes azimuth. Call `normalizeRotations()` before `setLookAt` when transitioning from free orbit (unknown azimuth) to a fixed interior view angle:

```typescript
cameraControlsRef.current
  .normalizeRotations()
  .setLookAt(
    interiorPos.x + 8, interiorPos.y + 6, interiorPos.z + 8,
    interiorPos.x, interiorPos.y, interiorPos.z,
    true // enableTransition
  );
```

**Exit transition:** Call `cameraControlsRef.current.reset(true)` to smoothly return to the saved default exterior view.

---

## Consolidated "New to This Milestone" APIs

These are already-installed packages with APIs that have NOT been used in the codebase yet. They require first-import but no installation:

| API | Package | First Use Feature | Import Pattern |
|-----|---------|-------------------|----------------|
| `<RenderTexture>` | `@react-three/drei` | Split-Screen Compare Mode | `import { RenderTexture } from '@react-three/drei'` |
| `<CameraControls>` | `@react-three/drei` | Station Interior Zones | `import { CameraControls } from '@react-three/drei'` |
| `THREE.DataTexture` | `three` | Threat Topology Heatmap | `import * as THREE from 'three'` (already imported) |
| Custom GLSL heatmap shader | `three` ShaderMaterial | Threat Topology Heatmap | Inline `/* glsl */` tagged template, same as `StationFresnelGlow.tsx` |

---

## What NOT to Add

| Avoid | Why | Use Instead |
|-------|-----|-------------|
| `simpleheat` or any heatmap library | External heatmap libs render to canvas2D then copy to texture — adds copy overhead and doesn't support GLSL additive blending. Custom ShaderMaterial is 10 lines of GLSL. | Custom `THREE.ShaderMaterial` + uniform array |
| `@react-three/xr` | VR/XR explicitly out of scope per PROJECT.md | N/A |
| `react-three-scissor` | Scissoring requires a persistent parent Canvas outside pane system. `<RenderTexture>` is composable inside existing Canvas. | `drei <RenderTexture>` |
| `meshline` (direct dep) | `drei <Trail>` and `drei <Line>` already pull in meshline as a transitive dep. Adding it directly creates version conflict risk. | Use via `drei <Trail>` |
| `@theatre/r3f` | Theatre.js for keyframe camera animation is engineering overkill for a single camera transition. `camera-controls.fitToBox()` is 1 line. | `<CameraControls>` via drei |
| Second `<Canvas>` for split-screen | Opens a second WebGL context. Context budget is ~8-16 total across the page. The observatory already uses one. | `drei <RenderTexture>` (shares context) |
| `drei <Float>` for card hover | Float adds continuous `useFrame` jitter to delta cards. These are analyst info cards — stability is more readable than floating. | Static position, `motion` CSS for subtle entrance animation |
| `drei <Decal>` for ground annotations | Decal projects onto mesh surfaces, requires polygon offset setup, and is designed for model surface marks. Heatmap on a separate transparent plane is simpler and more controllable. | Custom plane + ShaderMaterial |

---

## Alternatives Considered

| Category | Recommended | Alternative | Why Not |
|----------|-------------|-------------|---------|
| Split-screen two worlds | `drei <RenderTexture>` | Two separate `<Canvas>` | Second canvas = second GL context; context budget waste; RenderTexture shares context cleanly |
| Split-screen two worlds | `drei <RenderTexture>` | `drei <View>` scissor | View requires persistent parent Canvas outside pane structure; z-index conflicts with pane system dialogs (known issue) |
| Interior camera transition | `drei <CameraControls>` with `fitToBox` | Manual lerp in `useFrame` | Manual lerp doesn't handle collision with orbit damping; CameraControls handles all edge cases |
| Heatmap | Custom ShaderMaterial | `simpleheat` → CanvasTexture | Canvas2D copy to WebGL adds CPU overhead; can't do additive blending; less flexible on GPU |
| Spirit trails | `drei <Trail>` | Custom `BufferGeometry` history trail | Trail component handles all lifecycle, GC, and meshline thickness correctly; custom rebuild is ~200 extra LOC for no gain |
| Probe delta cards | `drei <Html transform sprite>` | `drei <Billboard>` + custom mesh card | Html allows actual shadcn/UI components with click handlers; full DOM in 3D space; Billboard is geometry-only |
| Annotation pin storage | Extend existing `observatory-replay-persistence.ts` | New store/IndexedDB | Annotations are lightweight (<10KB per session); localStorage is simpler and already in use for bookmarks |

---

## Integration Points with Existing Stack

### CameraControls Replaces OrbitControls

`ObservatoryWorldCanvas.tsx` currently imports `OrbitControls` from drei. For Station Interior Zones, `<CameraControls makeDefault>` replaces it. `CameraControls` is a superset — identical user interaction model, adds programmatic API. The `<OrbitControls>` import line becomes `<CameraControls>`.

**Impact:** None on existing behavior. All `dampingFactor`, `minDistance`, `maxDistance` props map directly to `CameraControls` equivalents.

### RenderTexture and Existing postprocessing

`ObservatoryPostFX.tsx` uses `@react-three/postprocessing` for bloom/SMAA on the primary scene. The secondary world inside `<RenderTexture>` does NOT inherit these post-effects (it renders to a separate FBO). This is correct — the "then" world should look slightly different (less bloom, more muted) to visually distinguish past from present. No action needed.

### Trail and Spirit Evolution Level Gate

`<Trail>` is already used in `spirit-companion-canvas.tsx`. For resonance trails in the observatory world, the level-5 gate reads from `spirit-evolution-store.ts` using the existing `useEvolutionLevel()` selector. No new store surface required.

### DataTexture Uniform Updates

The heatmap `DataTexture` is created in `useMemo` and never recreated — pressure values are updated via direct uniform mutation (`uniforms.uPressureValues.value = ...`), not texture replacement. Subscribe to `observatory-store.ts` telemetry changes in `useFrame` or a `useEffect` to push updated pressure values.

### localStorage Annotation Keys

The existing `OBSERVATORY_REPLAY_PERSISTENCE_KEY = "clawdstrike:observatory:replay:v1"` key in `observatory-replay-persistence.ts` should be versioned up to `v2` when adding `pins` and `constellations` fields to `PersistedObservatoryReplayArtifacts` to avoid parsing errors against old persisted data.

---

## No-Install Summary

**Zero new npm packages are required for v10.0.** Every feature uses already-installed APIs:

| Feature | Key APIs | Already Installed? |
|---------|----------|-------------------|
| Replay Annotation Canvas | R3F `onClick`, `drei <Html>`, `drei <Line>` | YES |
| Probe Delta Cards | `drei <Html transform sprite>`, `drei <Billboard>` | YES |
| Split-Screen Compare | `drei <RenderTexture>` (first use) | YES (^10.7.7) |
| Constellation Routes | `drei <Line>`, `THREE.CatmullRomCurve3` | YES |
| Threat Topology Heatmap | `THREE.ShaderMaterial`, uniform arrays | YES |
| Spirit Resonance Trails | `drei <Trail>` (expand existing usage) | YES |
| Station Interior Zones | `drei <CameraControls>` (first use) | YES (^10.7.7) |

---

## Sources

- `apps/workbench/package.json` — confirmed installed versions (`@react-three/drei ^10.7.7`, `three ^0.171.0`) — HIGH confidence
- Direct source audit: `ObservatoryWorldCanvas.tsx` — confirmed `Html`, `Billboard`, `Line`, `OrbitControls`, `Trail` imports — HIGH confidence
- Direct source audit: `StationFresnelGlow.tsx` — confirmed custom `ShaderMaterial` pattern established — HIGH confidence
- Direct source audit: `MissionWaypointTrail.tsx` — confirmed `CatmullRomCurve3` path animation pattern established — HIGH confidence
- Direct source audit: `spirit-companion-canvas.tsx` — confirmed `Trail` already in use — HIGH confidence
- Direct source audit: `observatory-replay-persistence.ts` — confirmed `localStorage` persistence pattern established — HIGH confidence
- Drei official docs `drei.docs.pmnd.rs/portals/render-texture` — `RenderTexture` is a portal-based FBO component sharing GL context — HIGH confidence
- Drei official docs `drei.docs.pmnd.rs/controls/camera-controls` — `CameraControls` bundles `camera-controls v3` in drei 10.5+; v3 migration note re: `normalizeRotations()` — HIGH confidence
- Drei official docs `drei.docs.pmnd.rs/abstractions/trail` — `Trail` uses `meshline` internally; `target` defaults to first child Object3D — HIGH confidence
- Drei official docs `drei.docs.pmnd.rs/misc/html` — `transform` mode required for correct positioning in non-fullscreen canvas — HIGH confidence
- WebSearch: drei View z-index issues in pane context (known issue), multiple discussions — MEDIUM confidence
- WebSearch: Three.js DataTexture + uniform update pattern vs needsUpdate — MEDIUM confidence

---
*Stack research for: ClawdStrike Workbench v10.0 Observatory Analyst Toolkit*
*Researched: 2026-03-22*
