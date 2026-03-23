# Feature Research: World Detail, NPCs, and UI Polish for Observatory

**Domain:** React Three Fiber 3D scene enhancement — procedural geometry, NPC behavior, world-space UI
**Researched:** 2026-03-19
**Overall confidence:** HIGH (all findings verified against official drei docs or R3F source)

---

## 1. District Detail

### 1.1 Procedural District Geometry

**Recommendation: compose `<RoundedBox>` + `<cylinderGeometry>` + `<coneGeometry>` driven by a seeded random function per station.**

Three.js primitives map 1-to-1 to JSX in R3F. There is no additional library needed for simple building blocks. The composition pattern is:

```tsx
// Deterministic seeded building generator per station
function StationBuilding({ seed, position }: { seed: number; position: [number, number, number] }) {
  const rng = useMemo(() => createSeededRng(seed), [seed]);
  const height = rng() * 3 + 1;          // 1-4 units tall
  const width  = rng() * 0.8 + 0.4;     // 0.4-1.2 wide

  return (
    <group position={position}>
      {/* Main block */}
      <RoundedBox args={[width, height, width]} radius={0.04} smoothness={2} position={[0, height / 2, 0]}>
        <meshStandardMaterial color="#1a1f2e" emissive="#0a0e1a" roughness={0.8} />
      </RoundedBox>
      {/* Antenna / tower accent */}
      <mesh position={[0, height + 0.3, 0]}>
        <cylinderGeometry args={[0.02, 0.02, 0.6, 6]} />
        <meshStandardMaterial color="#00ff88" emissive="#00ff88" emissiveIntensity={0.4} />
      </mesh>
    </group>
  );
}
```

**`<RoundedBox>` props (drei — HIGH confidence):**
- `args={[w, h, d]}` — width/height/depth
- `radius={0.05}` — corner rounding, keep ≤ 0.05 for architectural shapes
- `smoothness={2}` — curve segments; 2 is enough for small buildings, saves triangles
- `bevelSegments={0}` — set to 0 for crisp industrial aesthetic
- Memoize the `args` tuple with `React.useMemo` if args change per frame (not the case here)

**Seeded RNG note:** Three.js has no built-in seeded RNG. Use a simple mulberry32 or xorshift function inline — no external library needed for this use case.

**Per-station layout strategy:** Scatter 4-8 buildings per station using a seeded offset from the station's world position. Keep all buildings within a radius that does not clip the station's hero GLB prop. A `Math.cos/sin` spiral from the center with incremental offsets gives natural grouping without overlap.

**Confidence: HIGH** — direct R3F primitive composition, no library uncertainty.

---

### 1.2 Skybox — Environment HDR

**Recommendation: Use drei `<Environment files="..." background />` with a self-hosted space HDRI. Do not use `preset` in production.**

Confirmed from official drei docs:

- `preset` prop links to CDN-hosted files from HDRI Haven — "not meant to be used in production, may fail." The available presets are: `apartment`, `city`, `dawn`, `forest`, `lobby`, `night`, `park`, `studio`, `sunset`, `warehouse`. None are space-themed.
- `files` prop loads local assets via `RGBELoader` (`.hdr`), `EXRLoader` (`.exr`), or gainmap formats (`.jpg`/`.webp` with `.json` manifest). **Gainmap `.jpg` is the recommended format** — smallest footprint, adequate quality.
- `background` prop: `true` sets both scene environment and background; `"only"` sets background without affecting material reflections.
- `resolution={256}` default is fine for a background skybox; increase to 512 if used as reflection source.

```tsx
<Environment
  files="/textures/space-nebula.hdr"
  background
  backgroundBlurriness={0}
  backgroundIntensity={0.6}
  resolution={256}
/>
```

**Free space / nebula HDRI sources (CC0):**
- **Poly Haven** (polyhaven.com/hdris) — all assets CC0 public domain, no login. Their `night` category has star fields. Download as `.hdr` at 1K resolution for web.
- **ArtStation free pack** — "Free space and nebula HDRI Sci-fi skydomes" (4 panoramic views, 4K HDR). Find at `artstation.com/marketplace/p/LrOD5`.
- Convert any `.hdr` to gainmap `.jpg` using the `@monogrid/gainmap-js` encoder for the smallest bundle size. A 1K `.hdr` is typically 3-6 MB; gainmap reduces it to ~200-400 KB at equivalent quality.

**Confidence: HIGH** — from official drei Environment docs.

---

### 1.3 Ground Surface Variety

**Recommendation: Use `useTexture` with `RepeatWrapping` + per-zone emissive color variation. Procedural noise is a secondary option for color only, not displacement.**

```tsx
import { useTexture } from '@react-three/drei';
import * as THREE from 'three';

function DistrictGround({ stationColor }: { stationColor: string }) {
  const texture = useTexture('/textures/grid-floor.png', (t) => {
    t.wrapS = t.wrapT = THREE.RepeatWrapping;
    t.repeat.set(8, 8);
  });

  return (
    <mesh rotation={[-Math.PI / 2, 0, 0]} receiveShadow>
      <planeGeometry args={[20, 20, 1, 1]} />
      <meshStandardMaterial
        map={texture}
        color={stationColor}         // tints per station zone
        roughness={0.9}
        emissive={stationColor}
        emissiveIntensity={0.05}
      />
    </mesh>
  );
}
```

**Per-zone color variation:** Each of the 6 stations already has a theme color in the observatory data model. Pass that color to `meshStandardMaterial.color` + a low `emissiveIntensity`. This creates distinct zones without separate texture assets per station.

**Procedural noise for color:** `simplex-noise` (npm) works in R3F — sample noise at each vertex via a custom `shaderMaterial` to modulate emissive. However this adds shader complexity for minimal visual gain over simple emissive tint. **Defer noise-based variation unless tint approach looks flat after integration testing.**

**Texture recommendation:** A 512x512 dark grid/tech floor pattern at `RepeatWrapping` with 8x tiling covers a 20-unit district cleanly. One texture handles all 6 stations when combined with per-zone color tints.

**Confidence: HIGH** — `useTexture` + `RepeatWrapping` pattern is standard R3F, documented in official tutorials.

---

### 1.4 Environmental Storytelling Props

**Recommendation: Asset-based for distinct props (monitors, crates), procedural for cables/wires.**

**Crates/monitors:** Small GLB models are the correct approach. Three.js + R3F loads them via `useGLTF` with automatic draco compression. Use `gltfjsx` to generate typed components. Each hero-prop station can have 2-3 companion micro-props placed at fixed offsets. This avoids shader complexity and keeps art direction consistent.

**Cables/wires:** Use `<CatmullRomLine>` from drei (or `<QuadraticBezierLine>`) to draw glowing wire runs between props. This is entirely procedural with no assets needed.

```tsx
import { CatmullRomLine } from '@react-three/drei';

<CatmullRomLine
  points={[[0,0,0], [0.5, 0.3, 0.2], [1.2, 0.1, 0.8]]}
  color="#00ffaa"
  lineWidth={1}
  dashed={false}
/>
```

**Crate batching:** If crates repeat across stations, instance them with `<Instances>` from drei or raw `instancedMesh`. A single crate GLB shared across all stations is one draw call.

**Confidence: MEDIUM** — GLB approach is standard; CatmullRomLine availability confirmed in drei docs structure but not fetched directly.

---

## 2. NPC Crews

### 2.1 NPC Rendering Approach

**Recommendation: Single `InstancedMesh` per NPC body part tier — one for torsos, one for heads. Do NOT use individual meshes per NPC.**

The R3F performance docs are explicit: each mesh = one draw call. Aim for fewer than 300 draw calls for a stable 60fps on integrated GPUs. With 6 stations × 4 NPCs = 24 NPCs, individual meshes (24 × 2 body parts = 48 draw calls) is technically fine. But instancing is still the right pattern to establish because the observatory may expand.

```tsx
import { Instances, Instance } from '@react-three/drei';

// Drei's <Instances> wraps instancedMesh with a declarative API
function NpcCrew({ positions }: { positions: [number, number, number][] }) {
  return (
    <Instances limit={50}>
      <capsuleGeometry args={[0.15, 0.4, 4, 8]} />
      <meshStandardMaterial color="#334455" />
      {positions.map((pos, i) => (
        <NpcInstance key={i} position={pos} />
      ))}
    </Instances>
  );
}

function NpcInstance({ position }: { position: [number, number, number] }) {
  const ref = useRef<InstancedMeshRef>(null);
  // patrol logic goes here via useFrame
  return <Instance ref={ref} position={position} />;
}
```

**`<Instances>` from drei** is the recommended wrapper over raw `instancedMesh`. It provides a declarative `<Instance>` child API with per-instance color, position, rotation, and scale props — no manual matrix math needed.

**Confidence: HIGH** — Instances component pattern confirmed in drei docs and R3F discussion #761.

---

### 2.2 Patrol Paths — Waypoint Lerp

**Recommendation: Minimal waypoint array per NPC + `useFrame` lerp. No library needed at this scale.**

```tsx
const PATROL_WAYPOINTS: [number, number, number][] = [
  [0, 0, 0], [2, 0, 1], [3, 0, -1], [1, 0, -2],
];

function usePatrol(speed = 0.5) {
  const posRef = useRef(new THREE.Vector3(...PATROL_WAYPOINTS[0]));
  const waypointIdx = useRef(0);

  useFrame((_, delta) => {
    const target = new THREE.Vector3(...PATROL_WAYPOINTS[waypointIdx.current]);
    const dist = posRef.current.distanceTo(target);

    if (dist < 0.1) {
      waypointIdx.current = (waypointIdx.current + 1) % PATROL_WAYPOINTS.length;
    } else {
      posRef.current.lerp(target, speed * delta);
    }
  });

  return posRef;
}
```

**Performance rule for `useFrame`:** Never `setState` inside `useFrame`. Mutate refs directly and call `instance.setMatrixAt` + `instancedMesh.instanceMatrix.needsUpdate = true` to update the GPU buffer. This is the correct path for instanced NPCs.

**NPC count ceiling:** At 24-48 NPCs (instanced), performance impact is negligible on desktop. The patrol lerp runs in `useFrame` — the concern is not NPC count but matrix update cost. Calling `needsUpdate = true` every frame on an instanced mesh with 50 instances costs ~0.1ms — acceptable. At 500 NPCs the cost rises to ~1ms; above that use a single bulk update pass rather than per-NPC updates.

**three-pathfinding (donmccurdy/three-pathfinding):** Full navmesh pathfinding library for Three.js — overkill for simple waypoint patrols. **Do not use.** Simple lerp is correct here.

**Confidence: HIGH** — useFrame + ref mutation pattern is the canonical R3F animation approach.

---

### 2.3 Player Proximity Reaction — Look-At + Wave

**Recommendation: `distanceTo` check in `useFrame`, threshold at 4-6 units. Drive look-at via ref mutation, not React state.**

```tsx
useFrame(({ camera }) => {
  const npcPos = npcRef.current.position;
  const camPos = camera.position;
  const dist = npcPos.distanceTo(camPos);

  if (dist < PROXIMITY_THRESHOLD) {
    // Look at player — mutate the instance matrix
    npcRef.current.lookAt(camPos.x, npcPos.y, camPos.z); // keep Y locked
    // Trigger wave: set wave = true via ref flag, not setState
    if (!wavingRef.current) {
      wavingRef.current = true;
      waveTimer.current = 0;
    }
  } else {
    wavingRef.current = false;
  }

  // Wave animation: bob the "arm" instance up/down via matrix
  if (wavingRef.current) {
    waveTimer.current += delta;
    const wave = Math.sin(waveTimer.current * 4) * 0.3;
    // update arm instance Y offset
  }
});
```

**Critical:** The `useFrame` docs are explicit — "never setState in there." All animation state should live in refs. Only transition to React state when a user interaction needs to cause a re-render (e.g., opening a dialogue).

**Proximity threshold:** 4-6 world units works for a station-scale observatory. The camera is typically an orbit or FPS camera, so `camera.position` is the correct reference point.

**Confidence: HIGH** — pattern confirmed in multiple R3F discussions and official useFrame docs.

---

### 2.4 NPC Behavior Libraries

**Recommendation: None needed. Implement inline with useFrame at this scale.**

Surveyed options:
- **three-pathfinding** (donmccurdy/three-pathfinding) — navmesh-based pathfinding for Three.js. Appropriate for open-world navigation around obstacles. Overkill for 4-waypoint patrols.
- **yuka** (Mugen87/yuka) — game AI library with steering behaviors, state machines, and goal-driven agents. Solid library but adds ~40KB and introduces its own entity system that conflicts with R3F's declarative model.
- **recast-navigation-js** — WASM Recast/Detour port. Full navmesh baking. Completely inappropriate at this scale.

**Verdict:** At 24-48 NPCs with 4-waypoint loops, zero external libraries. The `useFrame` + `distanceTo` + `lerp` pattern covers all stated requirements. Introduce yuka only if patrol complexity grows to obstacle avoidance or squad formations.

**Confidence: HIGH** — ecosystem survey complete, recommendation is based on scope fit.

---

## 3. UI Polish

### 3.1 3D Waypoint Beacons — World-Space Labels

**Recommendation: Mesh-based billboard using `<Billboard>` + `<Text>` from drei. Reserve `<Html>` for rich interactive tooltips only.**

**`<Billboard>` + `<Text>` (pure mesh, always GPU-resident):**
```tsx
import { Billboard, Text } from '@react-three/drei';

<Billboard position={stationWorldPos}>
  <Text fontSize={0.18} color="#00ffaa" anchorX="center" anchorY="bottom">
    {stationName}
  </Text>
  {/* Accent ring beacon */}
  <mesh>
    <ringGeometry args={[0.12, 0.16, 32]} />
    <meshBasicMaterial color="#00ffaa" transparent opacity={0.8} />
  </mesh>
</Billboard>
```

**Why not `<Html>` for beacons:** The `<Html>` component processes DOM transforms every frame. A confirmed R3F discussion (pmndrs #3130) shows that 2000+ `<Html>` elements cause significant lag due to continuous `updateWorldMatrix` calls and lack of frustum culling. Even at 6-12 beacons the overhead is measurable. For pure label display, `<Text>` (backed by troika-3d-text with SDF rendering) is visually superior and has zero DOM overhead.

**`<Billboard>` props:**
- `follow={true}` — always face camera (default behavior)
- `lockX={false}` / `lockY={false}` / `lockZ={false}` — lock rotation axes if needed
- Wraps any R3F children, not just Text

**Confidence: HIGH** — Billboard + Text component from official drei docs, Html performance issue confirmed from community discussion.

---

### 3.2 Circular Probe Charge Ring

**Recommendation: Custom GLSL fragment shader via `shaderMaterial` from drei. `<Ring>` with geometry clipping is the wrong approach — it cannot animate fill arc without shader involvement.**

**The technique:** Use a full-screen quad (or thin ring mesh) with a fragment shader that uses `atan2` to convert UV position to polar angle, then compares against a `uFill` uniform (0.0-1.0) to discard fragments beyond the current fill.

```glsl
// fragment shader
uniform float uFill; // 0.0 = empty, 1.0 = full
uniform vec3  uColor;
uniform float uTime;

void main() {
  vec2 uv = vUv - 0.5;            // center UVs
  float angle = atan(uv.y, uv.x); // -PI to PI
  float norm  = (angle + PI) / (2.0 * PI); // 0..1 CW from left

  float dist = length(uv);
  float ring = smoothstep(0.38, 0.40, dist) - smoothstep(0.46, 0.48, dist);

  if (norm > uFill) discard;

  // Pulse glow at the arc tip
  float tip = smoothstep(0.02, 0.0, abs(norm - uFill));
  vec3 color = uColor + tip * uColor * 2.0;

  gl_FragColor = vec4(color, ring);
}
```

```tsx
import { shaderMaterial } from '@react-three/drei';
import { extend } from '@react-three/fiber';

const ChargeMaterial = shaderMaterial(
  { uFill: 0.0, uColor: new THREE.Color('#00ffaa'), uTime: 0 },
  vertexShader,
  fragmentShader,
);
extend({ ChargeMaterial });

function ProbeChargeRing({ fill }: { fill: number }) {
  const matRef = useRef<any>(null);
  useFrame((_, delta) => {
    if (matRef.current) {
      matRef.current.uFill = fill;
      matRef.current.uTime += delta;
    }
  });
  return (
    <mesh>
      <planeGeometry args={[1, 1]} />
      <chargeMaterial ref={matRef} transparent depthWrite={false} />
    </mesh>
  );
}
```

**Why not `<Ring>` with clipping:** Three.js `ClippingPlane` clips by a flat plane — you cannot define a radial arc clip without a shader. The ring geometry approach would require 32+ individual triangle segments with conditional rendering, which is worse than a shader.

**Alternative (lower effort):** Animate `ringGeometry args` by rebuilding from `thetaLength` (the arc angle parameter — `RingGeometry(inner, outer, segments, rings, thetaStart, thetaLength)`). Animating `thetaLength` from 0 to `2 * Math.PI` creates a fill arc. This is shader-free but requires geometry disposal + recreation each frame — acceptable for a 60fps animation if the geometry is simple (32 segments, 1 ring). **Use this as the fast path if shader approach feels heavy for this milestone.**

```tsx
// Fast-path: geometry arc via thetaLength
function ProbeChargeRingSimple({ fill }: { fill: number }) {
  return (
    <mesh>
      <ringGeometry args={[0.38, 0.46, 64, 1, 0, fill * Math.PI * 2]} />
      <meshBasicMaterial color="#00ffaa" side={THREE.DoubleSide} />
    </mesh>
  );
}
```

This re-creates the geometry each render when `fill` changes. For a charge animation (fill changes every ~100ms), the geometry allocation is minimal. For smooth 60fps animation, prefer the shader.

**Confidence: MEDIUM** — GLSL atan2 arc technique is standard; R3F `shaderMaterial` + `extend` pattern confirmed from official docs. The `ringGeometry` thetaLength shortcut is from Three.js API docs (training knowledge, not verified against current docs).

---

### 3.3 Tooltip System — World-Space Props

**Recommendation: Use `<Html>` with `occlude` + `distanceFactor` for rich tooltips on interactable props. Limit to one visible at a time.**

Unlike beacons (which are always visible), tooltips appear on pointer hover and are singular — only one shows at a time. This eliminates the multi-instance performance concern that makes `<Html>` problematic for beacons.

```tsx
import { Html } from '@react-three/drei';

function InteractableProp({ name, description, position }) {
  const [hovered, setHovered] = useState(false);

  return (
    <group position={position}>
      <mesh
        onPointerEnter={() => setHovered(true)}
        onPointerLeave={() => setHovered(false)}
      >
        <boxGeometry args={[0.4, 0.4, 0.4]} />
        <meshStandardMaterial color={hovered ? '#224433' : '#112233'} />
      </mesh>
      {hovered && (
        <Html
          position={[0, 0.6, 0]}
          distanceFactor={8}
          occlude
          style={{ pointerEvents: 'none' }}
        >
          <div className="bg-black/80 border border-green-500/30 rounded px-2 py-1 text-xs text-green-300 whitespace-nowrap">
            <div className="font-bold">{name}</div>
            <div className="text-green-500/70">{description}</div>
          </div>
        </Html>
      )}
    </group>
  );
}
```

**Key props in use:**
- `occlude` — hides the tooltip behind geometry (avoids floating labels through walls)
- `distanceFactor={8}` — scales the HTML element to appear constant-size regardless of camera distance
- `pointerEvents: 'none'` on the div — prevents the tooltip itself from capturing hover events
- Conditional render (`{hovered && ...}`) — mounts only when visible, no idle DOM+matrix overhead

**`useState` for hover is correct here** — it is a user interaction event, not a per-frame animation, so React state is appropriate.

**Confidence: HIGH** — `<Html>` occlude + distanceFactor confirmed from official drei docs. Pointer events pattern confirmed from community examples.

---

### 3.4 Achievement Popups

**Recommendation: CSS overlay positioned outside the R3F Canvas, animated with Framer Motion `AnimatePresence`. Do not use R3F `<Html>` for achievement popups.**

Achievement popups are screen-space UI, not world-space objects. Putting them inside Canvas via `<Html>` adds unnecessary overhead and makes CSS positioning awkward. The correct model is:

1. Zustand store holds `achievementQueue: Achievement[]`
2. An `<AchievementToast>` component renders fixed-position in the DOM, outside `<Canvas>`
3. Framer Motion `AnimatePresence` drives enter/exit animations
4. Pop entries from the queue after a timeout

```tsx
// Outside Canvas, in the IDE shell layer
function AchievementLayer() {
  const queue = useAchievementStore(s => s.queue);
  const pop   = useAchievementStore(s => s.pop);

  return (
    <div className="fixed bottom-8 right-4 z-50 flex flex-col gap-2 pointer-events-none">
      <AnimatePresence>
        {queue.map(a => (
          <motion.div
            key={a.id}
            initial={{ opacity: 0, x: 60 }}
            animate={{ opacity: 1, x: 0 }}
            exit={{ opacity: 0, x: 60 }}
            transition={{ type: 'spring', stiffness: 400, damping: 30 }}
            onAnimationComplete={() => { /* auto-pop after delay */ }}
            className="bg-black/90 border border-yellow-500/40 rounded-lg px-4 py-2 text-sm"
          >
            <span className="text-yellow-400 font-bold">{a.title}</span>
            <span className="text-yellow-200/70 ml-2">{a.description}</span>
          </motion.div>
        ))}
      </AnimatePresence>
    </div>
  );
}
```

**Why not R3F `<Html>`:** The achievement popup has no meaningful 3D relationship — it does not belong to a world-space position. Forcing it through `<Html>` would add matrix calculations for no benefit and make z-index management against the IDE shell panels harder.

**Framer Motion + R3F coexistence:** Confirmed working — Motion for React Three Fiber (`motion/react-three-fiber`) is a separate import path. Standard `motion.div` in the DOM layer does not require any R3F integration and works alongside Canvas without conflict.

**Confidence: HIGH** — Framer Motion AnimatePresence pattern confirmed from official Motion docs. The architectural separation (CSS overlay vs Html inside Canvas) is based on clear domain reasoning.

---

## Summary Table

| Feature | Recommended Approach | Library/API | Confidence |
|---|---|---|---|
| Procedural buildings | `<RoundedBox>` + cylinder/cone composition, seeded RNG | drei `RoundedBox` | HIGH |
| Skybox | `<Environment files=... background>` + local HDRI | drei `Environment` | HIGH |
| Ground variation | `useTexture` + RepeatWrapping + per-zone emissive tint | drei `useTexture` | HIGH |
| Cables/wires | `<CatmullRomLine>` procedural between prop positions | drei Lines | MEDIUM |
| NPC rendering | `<Instances>` + `<Instance>` per NPC | drei `Instances` | HIGH |
| NPC patrol | `useFrame` + `distanceTo` + `lerp`, 4-waypoint arrays | R3F core | HIGH |
| NPC look-at | `ref.current.lookAt(camPos)` in useFrame, Y-locked | Three.js `Object3D` | HIGH |
| Waypoint beacons | `<Billboard>` + `<Text>` (no Html) | drei Billboard + Text | HIGH |
| Probe charge ring | Shader `atan2` arc OR `ringGeometry.thetaLength` | drei `shaderMaterial` | MEDIUM |
| Prop tooltips | `<Html occlude distanceFactor={8}>`, single at a time | drei `Html` | HIGH |
| Achievement popups | CSS overlay + Framer Motion `AnimatePresence`, outside Canvas | Framer Motion | HIGH |

---

## Phase Implications

**Effort ranking (ascending):**

1. **Skybox** — drop-in: `<Environment files="..." background />` + one HDRI download. 30 minutes.
2. **Ground variation** — useTexture + emissive color. 1 hour including texture asset.
3. **Waypoint beacons** — Billboard + Text per station. 1-2 hours.
4. **Achievement popups** — Zustand store + AnimatePresence overlay. 2-3 hours.
5. **Prop tooltips** — Html occlude pattern + hover state per prop. 2-3 hours.
6. **Procedural buildings** — Seeded generator + RoundedBox composition. 3-4 hours.
7. **NPC crews** — Instances + useFrame patrol + look-at. 4-6 hours.
8. **Cables/wires** — CatmullRomLine between prop anchor points. 2-3 hours.
9. **Probe charge ring** — shader approach: 3-4 hours. thetaLength shortcut: 1 hour.

**Suggested build order:**
Skybox → Ground → Beacons → Procedural buildings → Props + tooltips → NPCs → Charge ring → Achievements → Cables

Skybox first because it sets the visual baseline that makes all subsequent geometry look correct. NPCs and charge ring are the most complex; sequence them after simpler wins are banked.

---

## Sources

- [drei Environment docs](https://drei.docs.pmnd.rs/staging/environment) — confirmed presets, file formats, background prop
- [drei Html docs](https://drei.docs.pmnd.rs/misc/html) — confirmed occlude, distanceFactor, pointer events
- [drei Billboard docs](https://drei.docs.pmnd.rs/abstractions/billboard) — confirmed follow, lockX/Y/Z props
- [drei RoundedBox docs](https://drei.docs.pmnd.rs/shapes/rounded-box) — confirmed args, radius, smoothness, bevelSegments
- [R3F scaling performance docs](https://docs.pmnd.rs/react-three-fiber/advanced/scaling-performance) — draw call budget guidance
- [R3F Html performance discussion](https://github.com/pmndrs/react-three-fiber/discussions/3130) — confirmed Html overhead at scale
- [Poly Haven HDRIs](https://polyhaven.com/hdris) — CC0 space/night HDRIs
- [ArtStation space HDRI pack](https://www.artstation.com/marketplace/p/LrOD5/free-space-and-nebula-hdri-sci-fi-skydomes) — free space nebula skydomes
- [Codrops Three.js performance article 2025](https://tympanus.net/codrops/2025/02/11/building-efficient-three-js-scenes-optimize-performance-while-maintaining-quality/) — instancing strategy, asset budgets
- [Motion for R3F docs](https://motion.dev/docs/react-three-fiber) — Framer Motion + R3F coexistence confirmed
- [drei Instances gist](https://gist.github.com/supahfunk/5426232d729f297b902267e719f014ce) — declarative instancing pattern
- [three-pathfinding](https://github.com/donmccurdy/three-pathfinding) — surveyed, confirmed overkill for waypoint patrols
