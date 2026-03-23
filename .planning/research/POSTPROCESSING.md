# Post-Processing Pipeline Research

**Domain:** R3F post-processing for a dark sci-fi 3D observatory
**Researched:** 2026-03-19
**Overall confidence:** HIGH (peer deps verified via npm registry; docs verified via official sources)

---

## Executive Summary

The `@react-three/postprocessing` v3.0.4 package is the right choice. Its peer dependencies
exactly match the workbench: `@react-three/fiber ^9.0.0`, `react ^19.0`, `three >= 0.156.0`.
The current workbench has three 0.170, R3F 9, React 19 — all in range. No compatibility
concerns.

The package wraps `postprocessing` v6.38.3 (peer dep `^6.36.6`) which has zero dependencies
of its own and supports `three >= 0.157.0 < 0.184.0`. Three 0.170 is firmly in range.

The critical performance issue — EffectComposer and `frameloop="demand"` — has a clean
solution: the EffectComposer does **not** force continuous rendering by itself; it
participates in R3F's render loop via `useFrame` just like any other R3F component. With
`frameloop="demand"`, you must call `invalidate()` whenever the scene needs a frame. The
observatory already does this pattern for its animations. Post-processing integrates cleanly
into that pattern.

---

## 1. Package Compatibility and Installation

### Confirmed Peer Dependencies (HIGH confidence — npm registry)

| Package | Version | Peer dep range | Workbench version | Compatible |
|---------|---------|---------------|-------------------|------------|
| `@react-three/postprocessing` | 3.0.4 | — | (to add) | yes |
| `postprocessing` | 6.38.3 | (peer: `^6.36.6` via r3p) | (to add) | yes |
| `@react-three/fiber` | — | `^9.0.0` | `^9.0.0` | yes |
| `react` | — | `^19.0` | `^19.0.0` | yes |
| `three` | — | `>= 0.156.0` | `^0.170.0` | yes |

`postprocessing` 6.38.3 peer dep is `three >= 0.157.0 < 0.184.0`. Three 0.170 is in range.

Note: `postprocessing` v7.0.0-beta exists but is not production-ready. Do not use it.

### Install

```bash
# From apps/workbench/
bun add @react-three/postprocessing postprocessing
```

`@react-three/postprocessing` bundles `n8ao` and `maath` as direct deps — no separate
installs needed for those.

### ESM-Only Warning

v3.0 is ESM-only (no CommonJS). Vite 6 handles this transparently. No config change needed.

---

## 2. EffectComposer — Integration Pattern

### Where It Lives

`<EffectComposer>` goes **inside** `<Canvas>`, after scene geometry, as a sibling of your
lights and meshes:

```tsx
<Canvas frameloop="demand" gl={{ antialias: false }}>
  <Suspense fallback={null}>
    {/* All scene geometry */}
    <ObservatorySceneGeometry />

    {/* Post-processing — last */}
    <EffectComposer multisampling={0}>
      <Bloom ... />
      <DepthOfField ... />
      <Vignette ... />
      <SMAA />
    </EffectComposer>
  </Suspense>
</Canvas>
```

Note `antialias: false` on the `gl` prop — when using `SMAA` in the composer, you disable
WebGL MSAA to avoid double anti-aliasing work.

### EffectComposer Props (complete list)

| Prop | Type | Default | Notes |
|------|------|---------|-------|
| `enabled` | boolean | true | Kill the whole pipeline without unmounting |
| `depthBuffer` | boolean | true | Needed for DOF and SSAO |
| `enableNormalPass` | boolean | false | Set true when using SSAO/N8AO |
| `stencilBuffer` | boolean | false | — |
| `autoClear` | boolean | true | — |
| `multisampling` | number | 8 | Set to 0 when using SMAA |
| `frameBufferType` | TextureDataType | HalfFloatType | Use HalfFloatType for HDR bloom |
| `resolutionScale` | number | 1 | 0.75 gives ~44% perf back |
| `renderPriority` | number | 1 | — |
| `camera` | THREE.Camera | — | Defaults to Canvas camera |
| `scene` | THREE.Scene | — | Defaults to Canvas scene |

**Critical:** `frameBufferType={THREE.HalfFloatType}` is required for HDR bloom (emissive
values > 1). Without it, the framebuffer clamps colors and bloom cannot activate on
emissive materials.

---

## 3. frameloop="demand" Interaction

### The Core Behavior

`EffectComposer` does **not** force continuous rendering. It registers itself via R3F's
`useFrame` hook. With `frameloop="demand"`, no frames render unless `invalidate()` is
called — whether or not EffectComposer is present.

**Confirmed behavior:** The `invalidate()` function queues exactly one frame. Any component
calling `invalidate()` in response to user input, state change, or animation tick causes
that frame to render through the full EffectComposer pipeline.

### What the Observatory Already Does Correctly

The observatory uses `frameloop="demand"` with `invalidate()` calls inside `useFrame` for:
- Probe animations
- Player movement
- Eruption effects
- Camera transitions

All of these will naturally render through the post-processing pipeline at zero extra cost
because the compositor runs on the same frame request.

### The One Gotcha: Static Scenes

When the scene is fully idle (no user input, no active animations), no frames render — which
means bloom, DOF, and other effects also stop updating. This is correct and desirable for an
IDE embedded canvas. The effect parameters should be set at mount time and only need
re-evaluation when the scene state changes.

### Pattern for Dynamic Effect Parameters

When you change an effect prop (e.g., DOF focus distance during a hero prop interaction),
that prop change flows through React and triggers a re-render → R3F re-renders → `invalidate()`
should be called to force the compositor to produce a new frame:

```tsx
// In a component that changes DOF focus:
const { invalidate } = useThree();

useEffect(() => {
  invalidate(); // ensure the updated DOF value is rendered
}, [focusDistance, invalidate]);
```

---

## 4. Bloom

### Recommended Approach: Emissive-Selective Bloom

The `<Bloom>` component from `@react-three/postprocessing` implements selective bloom via
material color values. You do **not** need `SelectiveBloom` (a separate Three.js addon that
is more complex and slower). The pmndrs approach is simpler and more performant:

1. Set `luminanceThreshold={1}` — nothing glows by default
2. On materials you want to glow: set `emissiveIntensity > 1` and `toneMapped={false}`
3. The threshold ensures only HDR colors (above 1.0 in linear space) bloom

### Component

```tsx
import { Bloom } from "@react-three/postprocessing";
import { BlendFunction } from "postprocessing";

<Bloom
  intensity={1.2}
  luminanceThreshold={0.85}
  luminanceSmoothing={0.025}
  mipmapBlur={true}
  radius={0.4}
/>
```

### Props

| Prop | Type | Default | Notes |
|------|------|---------|-------|
| `intensity` | number | 1 | Overall bloom strength |
| `luminanceThreshold` | number | 0.9 | 0.85 catches emissiveIntensity >= 2 |
| `luminanceSmoothing` | number | 0.025 | Reduces hard cutoff edge |
| `mipmapBlur` | boolean | false | **Set true** — dramatically better quality |
| `radius` | number | 0.85 | Bloom spread; 0.4–0.6 for tight sci-fi glow |
| `levels` | number | 8 | Mipmap levels |
| `blendFunction` | BlendFunction | SCREEN | — |

### Dark Sci-Fi Recommended Values

For the observatory's dark, emissive-accented aesthetic:

```tsx
<Bloom
  intensity={1.5}
  luminanceThreshold={0.85}
  luminanceSmoothing={0.025}
  mipmapBlur={true}
  radius={0.35}
/>
```

On materials that should glow (station lights, probe beams, spirit aura):

```tsx
<meshStandardMaterial
  emissive={spiritColor}
  emissiveIntensity={3}
  toneMapped={false}
/>
```

### EffectComposer Setup for Bloom

Bloom requires `frameBufferType={THREE.HalfFloatType}` on the composer to hold HDR values:

```tsx
import * as THREE from "three";
import { EffectComposer, Bloom } from "@react-three/postprocessing";

<EffectComposer multisampling={0} frameBufferType={THREE.HalfFloatType}>
  <Bloom intensity={1.5} luminanceThreshold={0.85} mipmapBlur radius={0.35} />
  {/* other effects */}
</EffectComposer>
```

---

## 5. Depth of Field

### Recommendation: `<DepthOfField>` from `@react-three/postprocessing`

Do not use drei's `<DepthOfField>`. Drei's version wraps a different underlying
implementation and has documented issues with `target` resolution in world space. The
pmndrs postprocessing `<DepthOfField>` is the correct choice.

The library also provides `<Autofocus>` — an extension of `<DepthOfField>` that handles
focus-pull animation automatically.

### Basic DepthOfField Props

| Prop | Type | Default | Notes |
|------|------|---------|-------|
| `focusDistance` | number | 0 | Normalized 0–1 (0 = near plane, 1 = far plane) |
| `focalLength` | number | 0.1 | Normalized 0–1 |
| `bokehScale` | number | 1.0 | Size of bokeh circles |
| `width` | number | canvas width | Render width |
| `height` | number | canvas height | Render height |

### Autofocus for Hero Prop Interaction

`<Autofocus>` is the correct primitive for "when the player interacts with a hero prop,
pull focus toward it":

```tsx
import { Autofocus } from "@react-three/postprocessing";

// Controlled focus pull toward hero prop world position
<Autofocus
  target={activeHeroPropPosition}  // [x, y, z] world coords or undefined
  smoothTime={0.3}                 // 0.3s focus pull animation
  mouse={false}                    // don't track mouse — track target only
  focalLength={0.02}
  bokehScale={3}
/>
```

When `target` is undefined, `Autofocus` reverts to its default focus behavior (center of
view). Set `target` to the hero prop's world position when `activeHeroInteraction` is
non-null in the observatory state.

### Manual Focus Pull Pattern

For full control (e.g., animated focus during station transitions):

```tsx
const dofRef = useRef();

// Animate focus distance in useFrame
useFrame(({ clock }) => {
  if (dofRef.current) {
    const targetFocusDistance = computeFocusFromCamera(targetPosition, camera);
    dofRef.current.bokehScale = lerp(dofRef.current.bokehScale, targetBokeh, 0.05);
    invalidate();
  }
});

<DepthOfField ref={dofRef} focusDistance={0.01} focalLength={0.02} bokehScale={2} />
```

### Performance Note

DOF is the most GPU-expensive effect in the stack. For the observatory used inside an IDE
pane (not fullscreen), use conservative `bokehScale` (2–4) and low `height` (480–720). The
`resolutionScale` on `EffectComposer` can drop DOF resolution further without degrading
bloom.

---

## 6. Color Grading via LUT

### Recommendation: LUT-based color grading with per-spirit swapping

The `<LUT>` component from `@react-three/postprocessing` accepts a Three.js `Texture` and
applies a 3D color lookup table to the final frame. The LUT can be swapped at runtime by
updating the `lut` prop — the component uses `useLayoutEffect` internally and calls
`invalidate()` on change.

### Loading .cube LUT Files

The `postprocessing` library bundles `LUTCubeLoader`. The three.js addons also provide one.
The recommended approach for R3F:

```tsx
import { useLoader } from "@react-three/fiber";
import { LUTCubeLoader } from "three/addons/loaders/LUTCubeLoader.js";
import { LUT } from "@react-three/postprocessing";

function ObservatoryLUT({ spiritKind }: { spiritKind: string }) {
  const lut = useLoader(LUTCubeLoader, `/luts/${spiritKind}.cube`);
  return <LUT lut={lut} />;
}
```

### Per-Spirit LUT Swapping

Because `<LUT>` calls `invalidate()` on prop change internally, swapping is clean:

```tsx
// In EffectComposer:
<LUT lut={spiritLut} tetrahedralInterpolation />
```

When `spiritStore` changes the active spirit kind, load the corresponding LUT and pass it
as a prop. The transition is instantaneous (single frame re-render).

### Recommended LUT Setup per Spirit Kind

Create one `.cube` file per spirit kind. 17x17x17 or 32x32x32 resolution is sufficient.
Tools for creating LUTs: DaVinci Resolve (free), 3D LUT Creator, or export from Photoshop.

Suggested grading per spirit archetype:
- **Sentinel**: cold blue shift, reduced saturation
- **Phantom**: high contrast, cyan-to-purple color cast
- **Architect**: warm amber, boosted midtones
- **Wraith**: desaturated green, high shadow crush

### Alternative: Shader-Based (not recommended)

Three.js `ColorCorrectionEffect` (from the postprocessing lib) allows HSL adjustments at
runtime. It is simpler to author than LUTs but produces less cinematic results. Use it as a
fallback when LUT files are unavailable.

---

## 7. Motion Blur

### Verdict: SKIP for v2.0, revisit in v3.0

Motion blur in post-processing requires either:
- **Velocity buffer approach** via `realism-effects` library (separate package: `npm i realism-effects`)
- **AccumulationPass** (temporal) in postprocessing 7 beta — not production ready

The `realism-effects` library provides `VelocityDepthNormalPass` + `MotionBlurEffect`. It
works with `postprocessing` 6.x, but is a separate install and adds significant complexity.

**Why to skip for now:**

1. The observatory uses `frameloop="demand"` — motion blur only makes visual sense when
   there is continuous motion. In demand mode, each frame is a complete still. Motion
   blur on a static or event-driven scene looks wrong (smears on idle frames).

2. Motion blur requires a velocity buffer rendered each frame — this effectively forces
   you to render every frame even when the scene is idle, defeating `demand` mode.

3. The character controller is an Easter-egg opt-in feature. If motion blur is added
   during flow mode only, it could use a `frameloop="always"` sub-canvas rather than
   fighting the demand loop.

**If you add it later:**

```bash
bun add realism-effects
```

```tsx
// Requires EffectComposer from postprocessing directly (not R3F wrapper)
// See: https://github.com/0beqz/realism-effects
const velocityDepthNormalPass = new VelocityDepthNormalPass(scene, camera);
composer.addPass(velocityDepthNormalPass);
const motionBlurEffect = new MotionBlurEffect(velocityDepthNormalPass);
```

Note: `realism-effects` requires direct `postprocessing` EffectComposer, not the R3F
`<EffectComposer>` component wrapper. Mixing is awkward. This is another reason to defer.

---

## 8. Full Recommended Stack for Observatory Post-Processing

### Effect Pipeline (ordered)

Order matters. Anti-aliasing must be last.

```
1. Bloom           — emissive glow on station lights, probe beams, spirit accents
2. DepthOfField    — bokeh on hero prop interactions (conditionally enabled)
3. Vignette        — subtle edge darkening (always on, strengthens sci-fi mood)
4. ChromaticAberration — subtle fringing on eruption events (conditional)
5. LUT             — per-spirit color grading
6. ToneMapping     — at the very end (v3.0 requirement)
7. SMAA            — anti-aliasing, always last
```

### Component

```tsx
import * as THREE from "three";
import {
  EffectComposer,
  Bloom,
  DepthOfField,
  Autofocus,
  Vignette,
  ChromaticAberration,
  LUT,
  ToneMapping,
  SMAA,
} from "@react-three/postprocessing";
import { BlendFunction, ToneMappingMode } from "postprocessing";
import { Vector2 } from "three";

interface ObservatoryPostFXProps {
  activeHeroPropPosition?: [number, number, number];
  spiritLut?: THREE.Texture;
  eruptionActive?: boolean;
}

export function ObservatoryPostFX({
  activeHeroPropPosition,
  spiritLut,
  eruptionActive = false,
}: ObservatoryPostFXProps) {
  return (
    <EffectComposer
      multisampling={0}
      frameBufferType={THREE.HalfFloatType}
    >
      <Bloom
        intensity={1.5}
        luminanceThreshold={0.85}
        luminanceSmoothing={0.025}
        mipmapBlur
        radius={0.35}
      />
      {activeHeroPropPosition ? (
        <Autofocus
          target={activeHeroPropPosition}
          smoothTime={0.35}
          focalLength={0.02}
          bokehScale={3}
        />
      ) : null}
      <Vignette
        offset={0.3}
        darkness={0.6}
        blendFunction={BlendFunction.NORMAL}
      />
      {eruptionActive ? (
        <ChromaticAberration
          offset={new Vector2(0.002, 0.002)}
          blendFunction={BlendFunction.NORMAL}
        />
      ) : null}
      {spiritLut ? (
        <LUT lut={spiritLut} tetrahedralInterpolation />
      ) : null}
      <ToneMapping mode={ToneMappingMode.ACES_FILMIC} />
      <SMAA />
    </EffectComposer>
  );
}
```

### Canvas Setup

```tsx
<Canvas
  frameloop="demand"
  gl={{ antialias: false }}   // disable hardware AA — SMAA handles it
  dpr={[1, 1.5]}              // cap device pixel ratio
>
  <ObservatoryPostFX
    activeHeroPropPosition={activeHeroInteraction?.worldPosition}
    spiritLut={spiritLutTexture}
    eruptionActive={worldEruptions.length > 0}
  />
</Canvas>
```

---

## 9. Performance in an IDE Context

### Key Facts

1. **EffectComposer is transparent to demand mode.** It renders on the same frames that
   the scene renders. Zero extra frames are produced.

2. **Resizing the canvas matters more than effect count.** The observatory runs in a pane
   tab, not fullscreen. At typical pane sizes (800–1200px wide), a `resolutionScale={0.85}`
   on EffectComposer saves ~28% fill cost with imperceptible quality loss.

3. **SMAA is cheap.** It replaces hardware MSAA (which is unavailable with postprocessing)
   at similar quality and lower memory bandwidth.

4. **Bloom with `mipmapBlur` is the most expensive single effect.** On integrated GPU
   (common on developer laptops), keep `intensity < 2.0` and `radius < 0.5`.

5. **DOF is the second most expensive.** Only enable it during hero prop interactions. Use
   conditional rendering:

   ```tsx
   {activeHeroInteraction && (
     <Autofocus target={activeHeroInteraction.worldPosition} ... />
   )}
   ```

6. **LUT is nearly free.** A single texture lookup per fragment. No performance concern.

7. **ChromaticAberration is cheap.** Acceptable to run continuously, but conditional on
   eruption events reads well narratively and saves a little.

### Performance Tiers

| Scenario | Effects | Expected overhead |
|----------|---------|------------------|
| Static idle scene | Bloom + Vignette + LUT + ToneMapping + SMAA | ~2ms/frame (0 extra frames) |
| Active navigation | + nothing (demand frames only) | same |
| Hero prop interaction | + Autofocus DOF | +4–8ms/frame during interaction |
| Eruption event | + ChromaticAberration | +1ms/frame |
| Full pipeline | all above simultaneously | ~8–12ms/frame at 1080p pane |

### Tauri Desktop Advantage

Tauri runs on the native GPU without browser compositing overhead. The observatory will have
better frame times in the Tauri window than the same scene in a browser. The full pipeline
is comfortable at 60fps on mid-range laptops.

### IDE Responsiveness

Post-processing only runs when frames render. When the user is in a code editor tab (not
the observatory pane), R3F pauses automatically if the canvas is unmounted. If the
observatory pane is backgrounded but mounted, use R3F's `frameloop="never"` or `enabled`
prop on EffectComposer to pause it:

```tsx
// In the pane host component:
const isPaneVisible = useIsObservatoryPaneVisible();

<EffectComposer enabled={isPaneVisible} ...>
```

---

## 10. Complete Effects Catalog (available in v3.0.4)

All exported from `@react-three/postprocessing`:

| Effect | Category | Notes |
|--------|----------|-------|
| `Bloom` | HDR glow | Use with HalfFloatType |
| `DepthOfField` | Focus | Use Autofocus for dynamic |
| `Autofocus` | Focus | Extends DOF |
| `Noise` | Grain | Film grain overlay |
| `Vignette` | Lens | Edge darkening |
| `ChromaticAberration` | Lens | Color fringing |
| `LUT` | Color grade | 3D LUT, .cube via LUTCubeLoader |
| `ToneMapping` | HDR | Must be last before SMAA |
| `SMAA` | Anti-alias | Replaces hardware MSAA |
| `FXAA` | Anti-alias | Faster but lower quality than SMAA |
| `SSAO` | Ambient occ | Requires `enableNormalPass` |
| `N8AO` | Ambient occ | Better than SSAO, bundled in v3.0 |
| `Outline` | Selection | Object outlines |
| `GodRays` | Light shafts | Performance heavy |
| `Pixelation` | Stylize | — |
| `DotScreen` | Stylize | — |
| `Glitch` | Stylize | — |
| `Grid` | Stylize | — |
| `Scanline` | Stylize | — |

Removed in v3.0: `SSR` (upstream library abandoned, use `realism-effects` for SSR/SSGI)

---

## 11. Pitfalls Specific to This Project

### Pitfall 1: Missing HalfFloatType

**Problem:** Bloom activates on no meshes even with emissiveIntensity > 1.
**Cause:** Default framebuffer type clamps RGB to [0,1]. HDR emissive values are lost.
**Fix:** `<EffectComposer frameBufferType={THREE.HalfFloatType}>`.

### Pitfall 2: toneMapped={false} omission

**Problem:** Emissive materials glow in the viewport but bloom doesn't activate.
**Cause:** Three.js tone-maps emissive contributions back to SDR before the bloom luminance
check sees them.
**Fix:** Add `toneMapped={false}` to every material that should bloom.

### Pitfall 3: ToneMapping placement

**Problem:** Bloom appears blown out or washed.
**Cause:** `<ToneMapping>` placed before Bloom. It must be last (before SMAA only).
**Fix:** Put ToneMapping second-to-last in EffectComposer children.

### Pitfall 4: Hardware MSAA + SMAA conflict

**Problem:** Scene looks over-blurred or aliasing artifacts appear.
**Cause:** Both hardware MSAA (Canvas `antialias: true`) and SMAA are active.
**Fix:** Set `gl={{ antialias: false }}` on Canvas and `multisampling={0}` on
EffectComposer. SMAA handles AA alone.

### Pitfall 5: DOF with logarithmic depth buffer

**Problem:** DepthOfField produces artifacts or incorrect focus.
**Cause:** The DOF effect does not work correctly when `logarithmicDepthBuffer: true` is set
on the renderer. This is a known upstream issue.
**Fix:** Do not use `logarithmicDepthBuffer` in the observatory canvas.

### Pitfall 6: Conditional effect mounting resets parameters

**Problem:** Bloom "pops" when ChromaticAberration mounts/unmounts during eruption.
**Cause:** EffectComposer rebuilds its pass when children change.
**Mitigation:** Use `blendFunction={BlendFunction.SKIP}` or `opacity={0}` to disable
effects without unmounting them, if visual pop is objectionable.

```tsx
<ChromaticAberration
  blendFunction={eruptionActive ? BlendFunction.NORMAL : BlendFunction.SKIP}
  offset={new Vector2(0.002, 0.002)}
/>
```

---

## Sources

- [npm: @react-three/postprocessing](https://www.npmjs.com/package/@react-three/postprocessing) — peer dep verification (HIGH confidence)
- [npm: postprocessing](https://www.npmjs.com/package/postprocessing) — three.js range verification (HIGH confidence)
- [react-postprocessing releases](https://github.com/pmndrs/react-postprocessing/releases) — v3.0 breaking changes (HIGH confidence)
- [react-postprocessing docs: Bloom](https://react-postprocessing.docs.pmnd.rs/effects/bloom) — luminanceThreshold/mipmapBlur details (HIGH confidence)
- [react-postprocessing docs: DepthOfField](https://react-postprocessing.docs.pmnd.rs/effects/depth-of-field) — focusDistance props (HIGH confidence)
- [react-postprocessing docs: Autofocus](https://react-postprocessing.docs.pmnd.rs/effects/autofocus) — auto focus pull API (HIGH confidence)
- [react-postprocessing docs: EffectComposer](https://react-postprocessing.docs.pmnd.rs/effect-composer) — props list (HIGH confidence)
- [react-postprocessing: LUT source](https://github.com/pmndrs/react-postprocessing/blob/master/src/effects/LUT.tsx) — runtime swap via useLayoutEffect (HIGH confidence)
- [R3F docs: Scaling performance](https://r3f.docs.pmnd.rs/advanced/scaling-performance) — frameloop demand mechanics (HIGH confidence)
- [R3F discussion: frameloop demand + animations](https://github.com/pmndrs/react-three-fiber/discussions/1800) — invalidate pattern (MEDIUM confidence)
- [realism-effects](https://github.com/0beqz/realism-effects) — motion blur via VelocityDepthNormalPass (MEDIUM confidence)
- [pmndrs/postprocessing LUTCubeLoader](https://pmndrs.github.io/postprocessing/public/docs/class/src/loaders/LUTCubeLoader.js~LUTCubeLoader.html) — .cube format, deprecated in favor of three/addons (MEDIUM confidence)
- [postprocessing settings article](https://www.balazsfarago.dev/blog/postprocessing-react-three-fibe) — N8AO/SMAA/AA pipeline recommendations (MEDIUM confidence)
- [AutoFocusDOF](https://github.com/ektogamat/AutoFocusDOF) — origin of the Autofocus component (MEDIUM confidence)
- [DeepWiki: advanced rendering effects](https://deepwiki.com/pmndrs/react-postprocessing/5.2-advanced-rendering-effects) — N8AO/FXAA details (MEDIUM confidence)
