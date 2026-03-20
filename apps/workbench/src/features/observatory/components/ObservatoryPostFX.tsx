import * as THREE from "three";
import type { JSX } from "react";
import {
  EffectComposer,
  Bloom,
  Autofocus,
  Vignette,
  LUT,
  ToneMapping,
  SMAA,
} from "@react-three/postprocessing";
import { BlendFunction, ToneMappingMode } from "postprocessing";
import type { ObservatoryPerformanceProfile } from "../utils/observatory-performance";

export interface ObservatoryPostFXProps {
  /**
   * World position of the active hero prop for DOF focus pull.
   * When non-null, Autofocus pulls focus toward this world position
   * with smoothTime=0.35s and bokehScale=3.
   * When null/undefined, DOF is not rendered (saves GPU on idle scene).
   */
  activeHeroPropPosition?: [number, number, number] | null;
  /**
   * THREE.Data3DTexture LUT for per-spirit color grading.
   * Built by buildSpiritLut(kind) in buildSpiritLut.ts.
   * When null/undefined, no LUT is applied (identity response).
   */
  spiritLut?: THREE.Data3DTexture | null;
  profile: Pick<
    ObservatoryPerformanceProfile,
    | "enableAutofocus"
    | "enableBloom"
    | "enableLut"
    | "enableSmaa"
    | "enableToneMapping"
    | "enableVignette"
  >;
  /**
   * TRN-04: Bloom spike override — replaces the default luminanceThreshold (0.85)
   * during boost activation. Parent drives a spike from 0.85 → 0.5 → 0.85 over ~1.3s.
   * When null/undefined, uses the default threshold of 0.85.
   */
  bloomLuminanceOverride?: number | null;
}

/**
 * ObservatoryPostFX — EffectComposer for the observatory Canvas.
 *
 * Effect order (mandatory):
 *   Bloom → [Autofocus DOF] → [LUT color grade] → Vignette → ToneMapping → SMAA
 */
export function ObservatoryPostFX({
  activeHeroPropPosition,
  spiritLut,
  profile,
  bloomLuminanceOverride,
}: ObservatoryPostFXProps) {
  // EffectComposer.children is typed as JSX.Element | JSX.Element[] — it does not accept null.
  // Build the effect list imperatively so TypeScript sees a JSX.Element[].
  const effects: JSX.Element[] = [];

  if (profile.enableBloom) {
    // TRN-04: bloomLuminanceOverride allows the bloom threshold to be driven externally
    // (e.g. during boost activation where it drops from 0.85 → 0.5 → 0.85 over ~1.3s).
    const luminanceThreshold = bloomLuminanceOverride ?? 0.85;
    effects.push(
      // PP-01: Bloom — emissive surfaces glow.
      // Only materials with emissiveIntensity > 1 AND toneMapped={false} bloom.
      <Bloom
        key="bloom"
        intensity={1.5}
        luminanceThreshold={luminanceThreshold}
        luminanceSmoothing={0.025}
        mipmapBlur
        radius={0.35}
      />,
    );
  }

  // PP-03: Autofocus DOF — conditionally mounted on hero prop interaction.
  // Unmounted (not just disabled) when inactive to save GPU.
  if (profile.enableAutofocus && activeHeroPropPosition) {
    effects.push(
      <Autofocus
        key="autofocus"
        target={activeHeroPropPosition}
        smoothTime={0.35}
        mouse={false}
        focalLength={0.02}
        bokehScale={3}
      />,
    );
  }

  // PP-04: LUT color grading — per-spirit kind, swapped at runtime.
  // Positioned before Vignette so the vignette darkening happens after grading.
  // tetrahedralInterpolation gives higher quality at negligible cost.
  if (profile.enableLut && spiritLut) {
    effects.push(
      <LUT key="lut" lut={spiritLut} tetrahedralInterpolation />,
    );
  }

  if (profile.enableVignette) {
    effects.push(
      // PP-02: Vignette — subtle edge darkening, always on
      <Vignette
        key="vignette"
        offset={0.3}
        darkness={0.6}
        blendFunction={BlendFunction.NORMAL}
      />,
    );
  }

  if (profile.enableToneMapping) {
    effects.push(
      // PP-02: ToneMapping — ACES filmic, must be second-to-last
      <ToneMapping key="tonemapping" mode={ToneMappingMode.ACES_FILMIC} />,
    );
  }

  if (profile.enableSmaa) {
    effects.push(
      // PP-02: SMAA — anti-aliasing replacement, always last
      <SMAA key="smaa" />,
    );
  }

  return (
    <EffectComposer
      multisampling={0}
      frameBufferType={THREE.HalfFloatType}
    >
      {effects}
    </EffectComposer>
  );
}
