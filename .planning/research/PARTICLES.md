# Particle Systems for Observatory (R3F Instanced Particles)

**Domain:** R3F particle effects in a productivity IDE (Tauri 2 + React 19)
**Researched:** 2026-03-19
**Overall Confidence:** HIGH for library choice and architecture; MEDIUM for performance ceilings

---

## Executive Summary

The project already has `@react-three/fiber ^9.0.0`, `@react-three/drei ^10.0.0`, and `three ^0.170.0`. This constrains library choice significantly.

**Recommended library: `wawa-vfx@1.2.10`** — the only purpose-built R3F particle engine that explicitly targets R3F 9 + React 19 + Three ≥ 0.159. It is zero-dependency for the particle logic itself (Zustand and leva are peerDeps, both already in the project), uses instanced rendering natively, and exposes a `useVFX` hook with an `emit()` function that maps cleanly onto the state-machine trigger points already identified (jump/land, probe cooldown, etc.).

**Drei `<Sparkles>` and `<Trail>`** are kept for ambient motes and the spirit orb trail respectively. They are already in `@react-three/drei@10` and require no additional installation.

**three.quarks is not viable** at this stack version: `three.quarks@0.17.0` requires `three >= 0.182.0` (confirmed via `npm info`), but the project pins `three ^0.170.0`. Upgrading Three would ripple through all huntronomer source files and is out of scope for a particle milestone.

**Custom `InstancedMesh` particles** are reserved for the probe energy discharge shell — a case where animation math (expanding sphere) is simpler to express directly than via an emitter API.

---

## 1. Library Choice

### Candidates Evaluated

| Library | Version | Three Peer | R3F 9 compat | Status |
|---------|---------|------------|--------------|--------|
| `wawa-vfx` | 1.2.10 | ≥ 0.159 | YES (explicit peerDep `^9.0.0`) | **RECOMMENDED** |
| `@react-three/drei` Sparkles | bundled in drei 10 | ≥ 0.159 | YES | **USE for ambient** |
| `@react-three/drei` Trail | bundled in drei 10 | ≥ 0.159 | YES | **USE for spirit trail** |
| `three.quarks` | 0.17.0 | **>= 0.182.0** | BLOCKED by Three version | EXCLUDED |
| Custom InstancedMesh | — | any | YES | **USE for probe shell** |
| `r3f-particle-system` | 0.x | not specified | UNKNOWN (no npm maintenance signal) | AVOID |

**Source verification:**
- `npm info wawa-vfx` returns `peerDependencies: { '@react-three/fiber': '^9.0.0', react: '^19', three: '>=0.159', zustand: '^5.0.0' }` — perfect match.
- `npm info three.quarks` returns `peerDependencies: { three: '>=0.182.0' }` — incompatible with `three@0.170.0`.
- `@react-three/drei@10.7.7` peerDeps: `{ '@react-three/fiber': '^9.0.0', react: '^19', three: '>=0.159' }` — already installed.
- Confidence: HIGH (directly verified from npm registry).

### wawa-vfx API Pattern

```tsx
// One pool per effect type (single InstancedMesh draw call each)
<VFXParticles
  name="landing-dust"
  settings={{
    nbParticles: 200,
    renderMode: "billboard",
    gravity: [0, -4, 0],
  }}
/>

// Emitter placed at emission point (follows a ref via position prop)
<VFXEmitter
  emitter="landing-dust"
  settings={{
    spawnMode: "burst",
    nbParticles: 40,
    duration: 0.3,
    startLifeTime: [0.4, 0.8],
    startSize: [0.05, 0.15],
    startColor: [new THREE.Color(0.6, 0.5, 0.3), new THREE.Color(0.8, 0.7, 0.5)],
  }}
/>

// Programmatic from any component, including character state listeners
const { emit } = useVFX();
emit("landing-dust", { position: groundContactPoint });
```

The `useVFX()` hook's `emit()` call is the key integration point: it fires a burst at an arbitrary world-space position without requiring the emitter JSX to be mounted at that position. This is the correct pattern for state-machine-driven effects.

---

## 2. Landing Dust (character controller ground contact)

**Approach:** `wawa-vfx` burst via `useVFX().emit()` called from a `useEffect` that watches the character's jump/land state.

**Trigger source:** `ecctrl` exposes a `characterRef` (RigidBody ref) and animation state. The landing state fires when the character transitions from airborne to grounded. In the huntronomer source, the observatory's character controller tracks `isOnGround` via a Zustand store. Watch that store value transition `false → true` to trigger the burst.

```tsx
// Inside ObservatoryWorld or a sibling CharacterVFX component
const { emit } = useVFX();
const isOnGround = useObservatoryStore(s => s.characterIsOnGround);
const prevOnGround = useRef(isOnGround);

useFrame(() => {
  if (!prevOnGround.current && isOnGround) {
    const pos = characterRef.current?.translation(); // Rapier Vector
    emit("landing-dust", {
      position: pos ? [pos.x, pos.y, pos.z] : [0, 0, 0],
    });
  }
  prevOnGround.current = isOnGround;
});
```

**Geometry:** Billboarded quads (wawa-vfx `renderMode: "billboard"`). Spheres add unnecessary vert count — quads are correct for dust that faces the camera. Use a semi-transparent disc texture or a simple circular alpha in the material.

**Budget:** 40 particles per landing burst, lifetime 0.5–0.8s. Pool of 200 covers rapid repeated landings without reallocation.

**Confidence:** HIGH on approach; MEDIUM on exact parameter tuning (requires visual iteration).

---

## 3. Probe Energy Discharge (expanding shell)

**Approach:** Custom `InstancedMesh` with a shader-driven expansion rather than a velocity-based emitter. The probe discharge is a single expanding shell of particles, not a spray — this is better expressed as a timed UV animation on an `InstancedMesh`.

**Trigger:** The `probeRuntime` state machine has `dispatch → active → cooldown` states exposed via `observatory-store`. Watch `probeState === 'active'` to start the expansion.

```tsx
// ProbeDischargeVFX.tsx
const probeState = useObservatoryStore(s => s.probeState);
const meshRef = useRef<THREE.InstancedMesh>(null!);
const startTime = useRef<number | null>(null);
const PARTICLE_COUNT = 128;

useEffect(() => {
  if (probeState === 'active') startTime.current = performance.now() / 1000;
}, [probeState]);

useFrame(({ clock }) => {
  if (!startTime.current || !meshRef.current) return;
  const t = clock.elapsedTime - startTime.current;
  if (t > 1.2) { startTime.current = null; return; } // reset

  const radius = t * 3.0; // expand outward at 3 units/sec
  const opacity = 1.0 - t / 1.2;

  for (let i = 0; i < PARTICLE_COUNT; i++) {
    // Fibonacci sphere point
    dummy.position.set(/* fibonacci sphere */ ...);
    dummy.position.multiplyScalar(radius);
    dummy.scale.setScalar(opacity * 0.1);
    dummy.updateMatrix();
    meshRef.current.setMatrixAt(i, dummy.matrix);
  }
  meshRef.current.instanceMatrix.needsUpdate = true;
});

return (
  <instancedMesh ref={meshRef} args={[undefined, undefined, PARTICLE_COUNT]}>
    <sphereGeometry args={[1, 4, 4]} />
    <meshBasicMaterial color="#00ff88" transparent opacity={0.7} />
  </instancedMesh>
);
```

**Why not wawa-vfx here:** wawa-vfx's emitter model is radial spray from a point. An expanding shell requires all particles to start at the probe center and travel outward on a sphere surface simultaneously — this is a custom math pattern that fits InstancedMesh + useFrame better than an emitter.

**Budget:** 128 particles, single draw call, ≤ 1.2s lifetime. No continuous emission.

**Confidence:** HIGH on pattern; MEDIUM on visual tuning.

---

## 4. Station Ambient Motes (floating particles around hero props)

**Approach:** `<Sparkles>` from `@react-three/drei`. Already available, no new dependency. Placed as a child of each station's hero prop group.

```tsx
// Inside StationHeroProp.tsx
<group ref={stationGroupRef}>
  <HeroGeometry />
  <Sparkles
    count={30}
    scale={2.5}
    size={0.6}
    speed={0.3}
    opacity={0.4}
    color={stationAccentColor}
    noise={0.8}
  />
</group>
```

**Lazy / view-culling:** Three.js frustum culling is automatic on `instancedMesh` geometries when the bounding sphere is set correctly. Sparkles uses `THREE.Points` internally. Set `frustumCulled={true}` (default) on the parent `<group>` and Three.js will not issue the draw call when the station is out of the camera frustum. No additional effort required.

For stations that are far away (atlas view, distant ring position), add a distance check via `useFrame` + `camera.position.distanceTo(stationGroupRef.current.position)` and set `visible={false}` beyond 40 units. This eliminates shader execution entirely.

**Budget:** 30 particles per station, 5 stations max visible at once = 150 particles total. Negligible GPU cost.

**Confidence:** HIGH — Sparkles is a first-party drei component confirmed working with drei 10 / R3F 9.

---

## 5. Spirit Trail (companion orb particles)

**Approach:** `<Trail>` from `@react-three/drei`. This component wraps a target object and samples its world position every N frames to draw a fading mesh-line trail.

```tsx
// Inside SpiritCompanion.tsx  (or the spirit orb R3F scene)
<Trail
  width={0.15}
  color={spiritColor}
  length={8}
  decay={2}
  local={false}
  stride={0}
  interval={2}
  attenuation={(t) => t * t}
>
  <mesh ref={orbMeshRef}>
    <sphereGeometry args={[0.12, 12, 12]} />
    <meshStandardMaterial
      color={spiritColor}
      emissive={spiritColor}
      emissiveIntensity={1.5}
    />
  </mesh>
</Trail>
```

**Reading orb position:** `<Trail>` uses the first child Object3D's world position directly via Three.js scene graph traversal on each frame — no ref passing required. Just ensure the target mesh is the direct child.

**For the ActivityBar spirit orb** (tiny 2D canvas, not a full R3F scene): the Trail component requires an R3F Canvas. The ActivityBar orb uses a small `<Canvas>` element (already planned as a mini-canvas embed). Trail fits naturally there.

**meshline dependency note:** `drei@10` bundles `meshline` as a direct dependency (not peerDep). The older Issue #1177 was resolved by drei switching from `three.meshline` to the pmndrs fork `meshline`. Current drei 10 is unaffected. Confidence: MEDIUM (confirmed via issue resolution thread; no direct package.json check of bundled meshline version).

**Budget:** 1 trail instance, 8 history points. Cost is proportional to `length` (line segments). At `length=8`, interval=2, this is 4 segments per frame — trivial.

**Confidence:** HIGH on approach; MEDIUM on meshline bundling in current drei 10.

---

## 6. Thruster Exhaust (avatar backpack during sprint/jump)

**Approach:** `wawa-vfx` continuous emitter attached via a `useFrame` position sync from a bone ref.

**Bone extraction pattern:**
```tsx
const { nodes } = useGLTF('/avatar.glb');
const backpackBoneRef = useRef<THREE.Bone>(null!);
const emitterRef = useRef<THREE.Group>(null!);
const { emit } = useVFX();

// On mount, locate the bone
useEffect(() => {
  const bone = (nodes.AvatarMesh as THREE.SkinnedMesh)
    .skeleton.bones.find(b => b.name === 'spine_upper');
  if (bone) backpackBoneRef.current = bone as unknown as THREE.Bone;
}, [nodes]);

// Sync emitter world position to bone world position every frame
const boneWorldPos = new THREE.Vector3(); // allocate outside useFrame
useFrame(() => {
  if (!backpackBoneRef.current || !emitterRef.current) return;
  backpackBoneRef.current.getWorldPosition(boneWorldPos);
  emitterRef.current.position.copy(boneWorldPos);
  emitterRef.current.position.y -= 0.1; // offset below backpack
});
```

**CRITICAL:** `getWorldPosition()` must be called in `useFrame`, not `useEffect`. The bone's world matrix is only valid after the skeletal animation updates in the render loop. Calling it in `useEffect` returns `(0,0,0)`.

**State-conditional emission:** Only emit during sprint/jump states. Watch the observatory store's `characterAnimationState`:

```tsx
const charState = useObservatoryStore(s => s.characterAnimationState);

useFrame(() => {
  // position sync always...
  if (charState === 'sprint' || charState === 'jump') {
    emit("thruster-exhaust", { position: boneWorldPos.toArray() });
  }
});
```

**Emitter settings:**
```tsx
<VFXParticles
  name="thruster-exhaust"
  settings={{
    nbParticles: 300,
    renderMode: "stretchBillboard",
    gravity: [0, 2, 0], // slight upward drift
  }}
/>
```

`stretchBillboard` renders particles stretched along their velocity vector — correct for exhaust. Use `nbParticles: 300` pool; at sprint continuous emission of ~20 particles/frame at 60fps and 0.25s lifetime, steady state is ≈ 300 active particles.

**Budget:** 300 pool, 1 draw call, only active during sprint/jump (<10% of observatory time for an IDE user). Confidence: HIGH on pattern; MEDIUM on bone name (depends on actual GLTF skeleton rig).

---

## 7. Performance Budget

### Context: Productivity IDE, Not a Game

The observatory is an optional pane tab. Most users have other panes open simultaneously (policy editor, simulation results). The R3F canvas competes with Tauri webview rendering, CodeMirror, xyflow graph, and CodeMirror. Aggressive particle budgets are appropriate.

### Budget Table

| Effect | Particle Pool | Draw Calls | Active Time | GPU Cost |
|--------|--------------|------------|-------------|---------|
| Landing dust | 200 | 1 | <1s on land | Negligible |
| Probe shell | 128 (InstancedMesh) | 1 | 1.2s on probe | Negligible |
| Station motes | 30 × 5 = 150 (Sparkles) | 5 (one per station) | Always in atlas view | Low |
| Spirit trail | ~8 line segments (Trail) | 1 | When spirit bound | Negligible |
| Thruster exhaust | 300 | 1 | Sprint/jump only | Low |
| **Total peak** | **~780** | **~9** | Observatory flow mode sprint | **Low** |

### Key Performance Rules

**1. Keep draw calls under 10 for the particle layer.** The general Three.js guidance is <1000 draw calls for the full scene; particle effects should consume no more than ~10 of that budget. The plan above uses 9 at peak.

**2. Use `frameloop="always"` only for the observatory Canvas.** The mini-canvas embeds (spirit orb in ActivityBar, mini R3F in Inspector) should be separate `<Canvas>` elements with `frameloop="demand"` and `invalidate()` calls wired to the relevant Zustand store subscriptions. Particles in those contexts are static/slow-moving — no wasted frames.

**3. `frustumCulled={true}` on all particle groups.** This is the default. Do not disable it. Stations off-screen generate zero draw calls automatically.

**4. Distance-based visibility gate for station motes.** Beyond 40 units in flow mode, set `visible={false}` on the Sparkles group. Below 40 units the atlas camera is close enough for motes to be legible.

**5. No GPGPU / FBO particles.** FBO particle systems (position simulation on GPU) are for >10K particles in full-screen experiences. For a productivity IDE with <1000 particles total, FBO adds complexity with no benefit.

**6. One `VFXParticles` pool per effect type, shared across all instances.** `wawa-vfx` is pool-based — a single `<VFXParticles name="landing-dust">` handles all landing events regardless of where on the map they occur.

**7. Object pool the Three.js Vector3 used in useFrame.** Allocate `new THREE.Vector3()` outside the `useFrame` callback. Creating new Vector3 inside useFrame triggers GC pressure at 60fps.

### Verified Performance Ceiling

`InstancedMesh` can handle 100K+ instances in a single draw call on modern hardware. For the IDE context, 780 particles at 9 draw calls is firmly in the "CPU-limited by other workbench activity" regime, not GPU-limited. The bottleneck is far more likely to be the CodeMirror + xyflow DOM layer than the particle layer.

**Confidence:** HIGH for draw-call analysis; MEDIUM for exact frame budget numbers without profiling on target hardware.

---

## 8. R3F Version Compatibility Summary

All recommended approaches verified against the project's pinned versions:
- `@react-three/fiber ^9.0.0` ✓
- `@react-three/drei ^10.7.7` ✓
- `three ^0.170.0` ✓
- `react ^19.0.0` ✓
- `zustand ^5.0.0` ✓ (already in project, wawa-vfx peerDep)

`wawa-vfx@1.2.10` peerDeps: `R3F ^9`, `React ^19`, `three >=0.159`, `zustand ^5`, `leva ^0.10.0`.
`leva` is the only new installation required. It is a debug panel library; used by wawa-vfx optionally for runtime VFX parameter tuning. It can be installed as a devDependency or excluded — wawa-vfx works without Leva controls in production builds.

---

## 9. Installation

```bash
# From apps/workbench/
bun add wawa-vfx
bun add -d leva  # optional, enables wawa-vfx debug controls in development
```

No other new packages required. `<Sparkles>` and `<Trail>` are already in `@react-three/drei@10`.

---

## 10. Effect-to-Component Map

| Effect | Component | Location | Trigger | Library |
|--------|-----------|----------|---------|---------|
| Landing dust | `CharacterVFX` | ObservatoryWorld child | `isOnGround` store `false→true` | wawa-vfx `emit()` |
| Probe discharge | `ProbeDischargeVFX` | ObservatoryWorld child | `probeState === 'active'` | Custom InstancedMesh |
| Station motes | `StationHeroProp` child | Station component | Always (frustum-culled) | drei Sparkles |
| Spirit trail | Inside `SpiritCompanion` | R3F Canvas wrapping orb | When spirit is bound | drei Trail |
| Thruster exhaust | `CharacterVFX` | ObservatoryWorld child | `characterAnimationState` sprint/jump | wawa-vfx `emit()` |

All five effects live in or under `ObservatoryWorld` / the observatory canvas. They are loaded lazily when the observatory tab is opened (React.lazy + Suspense). Zero particle cost when the observatory pane is not mounted.

---

## Sources

- wawa-vfx npm info (verified): `npm info wawa-vfx version peerDependencies` — v1.2.10, R3F ^9.0.0, React ^19
- three.quarks npm info (verified): `npm info three.quarks version peerDependencies` — v0.17.0, Three >=0.182.0 (BLOCKER)
- drei npm info (verified): `npm info @react-three/drei version peerDependencies` — v10.7.7, R3F ^9.0.0
- [wawa-vfx GitHub](https://github.com/wass08/wawa-vfx) — architecture, API
- [wawa-vfx blog post](https://wawasensei.dev/blog/wawa-vfx-open-source-particle-system-for-react-three-fiber-projects) — VFXParticles/VFXEmitter component docs
- [drei Trail docs](http://drei.docs.pmnd.rs/abstractions/trail) — props confirmed: width, color, length, decay, local, stride, interval, target, attenuation
- [drei Sparkles docs](https://drei.docs.pmnd.rs/staging/sparkles) — props confirmed: count, speed, opacity, color, size, scale, noise
- [R3F Scaling Performance](https://r3f.docs.pmnd.rs/advanced/scaling-performance) — frameloop="demand", invalidate(), draw call limits
- [drei Issue #1177](https://github.com/pmndrs/drei/issues/1177) — meshline breaking change (resolved in current drei)
- [drei Discussion #2213](https://github.com/pmndrs/drei/discussions/2213) — R3F v9 + React 19 compatibility confirmed
- [Three.js forum: bone position in useFrame](https://discourse.threejs.org/t/how-to-get-bone-position-in-gltf-model/48914) — getWorldPosition() must run in useFrame
- [Wawa Sensei: Three.js tips](https://www.utsubo.com/blog/threejs-best-practices-100-tips) — instancing, draw call guidance
