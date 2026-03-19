import * as THREE from "three";
import {
  EffectComposer,
  Bloom,
  Vignette,
  ToneMapping,
  SMAA,
} from "@react-three/postprocessing";
import { BlendFunction, ToneMappingMode } from "postprocessing";

export interface ObservatoryPostFXProps {
  /**
   * World position of the active hero prop for DOF focus pull.
   * Plan 02 will add <Autofocus> here. Placeholder prop kept for
   * forward compatibility — not used in this plan.
   */
  activeHeroPropPosition?: [number, number, number] | null;
  /**
   * THREE.Texture LUT for per-spirit color grading.
   * Plan 03 will add <LUT> here. Placeholder prop kept for
   * forward compatibility — not used in this plan.
   */
  spiritLut?: THREE.Texture | null;
}

/**
 * ObservatoryPostFX — EffectComposer for the observatory Canvas.
 *
 * Effect order (mandatory — do not reorder):
 *   Bloom → Vignette → ToneMapping → SMAA
 *
 * Plan 02 inserts: Autofocus (between Bloom and Vignette)
 * Plan 03 inserts: LUT (between Vignette and ToneMapping)
 *
 * Canvas requirements (enforced in ObservatoryWorldCanvas):
 *   gl={{ antialias: false }}   — SMAA replaces hardware MSAA
 *   multisampling={0}           — no double AA work
 *   frameBufferType={THREE.HalfFloatType} — required for HDR bloom
 */
export function ObservatoryPostFX({
  activeHeroPropPosition: _activeHeroPropPosition,
  spiritLut: _spiritLut,
}: ObservatoryPostFXProps) {
  return (
    <EffectComposer
      multisampling={0}
      frameBufferType={THREE.HalfFloatType}
    >
      {/* PP-01: Bloom — emissive surfaces glow (luminanceThreshold=0.85 means
          only materials with emissiveIntensity > 1 AND toneMapped={false} bloom) */}
      <Bloom
        intensity={1.5}
        luminanceThreshold={0.85}
        luminanceSmoothing={0.025}
        mipmapBlur
        radius={0.35}
      />
      {/* PP-03: Autofocus DOF — inserted by Plan 02 */}
      {/* PP-04: LUT color grading — inserted by Plan 03 */}
      {/* PP-02: Vignette — subtle edge darkening, always on */}
      <Vignette
        offset={0.3}
        darkness={0.6}
        blendFunction={BlendFunction.NORMAL}
      />
      {/* PP-02: ToneMapping — ACES filmic, must be second-to-last */}
      <ToneMapping mode={ToneMappingMode.ACES_FILMIC} />
      {/* PP-02: SMAA — anti-aliasing replacement, always last */}
      <SMAA />
    </EffectComposer>
  );
}
