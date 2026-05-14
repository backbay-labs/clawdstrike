/** GhostPresetOverlay.tsx — Phase 37, Plan 02 (APR-04) */
import type { ReactElement } from "react";

/**
 * Reduces ambient intensity by 40% for the GHOST analyst preset.
 * Returns baseIntensity * 0.6 — the caller replaces the normal ambientLight
 * with GhostPresetOverlay when analystPresetId === "ghost".
 */
export function getGhostAmbientIntensity(baseIntensity: number): number {
  return baseIntensity * 0.6;
}

export interface GhostPresetOverlayProps {
  baseIntensity: number;
  baseColor: string;
}

/**
 * R3F component: replaces the default ambientLight in ObservatoryWorldScene
 * when the GHOST analyst preset is active. Renders two additive lights:
 * 1. Main ambient at 40% reduced intensity (desaturated, same hue as base).
 * 2. Cool dark-blue tint at 15% of base intensity — slight desaturation effect.
 *
 * The caller must NOT also render the normal ambientLight — see ObservatoryWorldScene.
 */
export function GhostPresetOverlay({ baseIntensity, baseColor }: GhostPresetOverlayProps): ReactElement {
  return (
    <>
      <ambientLight intensity={getGhostAmbientIntensity(baseIntensity)} color={baseColor} />
      <ambientLight intensity={baseIntensity * 0.15} color="#1a1a2e" />
    </>
  );
}
