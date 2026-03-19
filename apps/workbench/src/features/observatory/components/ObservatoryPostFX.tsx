import * as THREE from "three";
import type { JSX } from "react";
import {
  EffectComposer,
  Bloom,
  Autofocus,
  Vignette,
  ToneMapping,
  SMAA,
} from "@react-three/postprocessing";
import { BlendFunction, ToneMappingMode } from "postprocessing";

export interface ObservatoryPostFXProps {
  /**
   * World position of the active hero prop for DOF focus pull.
   * When non-null, Autofocus pulls focus toward this world position
   * with smoothTime=0.35s and bokehScale=3.
   * When null/undefined, DOF is not rendered (saves GPU on idle scene).
   */
  activeHeroPropPosition?: [number, number, number] | null;
  /**
   * THREE.Texture LUT for per-spirit color grading.
   * Plan 03 will implement this prop — placeholder for forward compat.
   */
  spiritLut?: THREE.Texture | null;
}

/**
 * ObservatoryPostFX — EffectComposer for the observatory Canvas.
 *
 * Effect order (mandatory):
 *   Bloom → [Autofocus DOF when hero active] → Vignette → [LUT - Plan 03] → ToneMapping → SMAA
 */
export function ObservatoryPostFX({
  activeHeroPropPosition,
  spiritLut: _spiritLut,
}: ObservatoryPostFXProps) {
  // EffectComposer.children is typed as JSX.Element | JSX.Element[] — it does not accept null.
  // Build the effect list imperatively so TypeScript sees a JSX.Element[].
  const effects: JSX.Element[] = [
    // PP-01: Bloom — emissive surfaces glow.
    // Only materials with emissiveIntensity > 1 AND toneMapped={false} bloom.
    <Bloom
      key="bloom"
      intensity={1.5}
      luminanceThreshold={0.85}
      luminanceSmoothing={0.025}
      mipmapBlur
      radius={0.35}
    />,
  ];

  // PP-03: Autofocus DOF — conditionally mounted on hero prop interaction.
  // Unmounted (not just disabled) when inactive to save GPU.
  if (activeHeroPropPosition) {
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

  // PP-04: LUT color grading — inserted by Plan 03

  effects.push(
    // PP-02: Vignette — subtle edge darkening, always on
    <Vignette
      key="vignette"
      offset={0.3}
      darkness={0.6}
      blendFunction={BlendFunction.NORMAL}
    />,
    // PP-02: ToneMapping — ACES filmic, must be second-to-last
    <ToneMapping key="tonemapping" mode={ToneMappingMode.ACES_FILMIC} />,
    // PP-02: SMAA — anti-aliasing replacement, always last
    <SMAA key="smaa" />,
  );

  return (
    <EffectComposer
      multisampling={0}
      frameBufferType={THREE.HalfFloatType}
    >
      {effects}
    </EffectComposer>
  );
}
