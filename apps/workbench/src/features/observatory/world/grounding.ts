// Ported verbatim from huntronomer apps/desktop/src/features/hunt-observatory/world/grounding.ts
// Terrain half-extents helpers for physics traversal surfaces.

import type { ObservatoryTraversalSurfaceRecipe } from "./deriveObservatoryWorld";

const RAMP_SUPPORT_INSET_X = 0.18;
const RAMP_SUPPORT_INSET_Z = 0.06;
const PLAYER_GROUND_ADHESION_GAP = 0.08;
const PLAYER_GROUND_ADHESION_MAX_VERTICAL_VELOCITY = 1.2;

export function resolveObservatoryTraversalHalfExtents(
  surface: ObservatoryTraversalSurfaceRecipe,
): [number, number, number] {
  const halfExtents: [number, number, number] = [
    surface.scale[0] * 0.5,
    surface.scale[1] * 0.5,
    surface.scale[2] * 0.5,
  ];

  if (surface.kind !== "ramp") {
    return halfExtents;
  }

  return [
    Math.max(0.24, halfExtents[0] - RAMP_SUPPORT_INSET_X),
    halfExtents[1],
    Math.max(0.18, halfExtents[2] - RAMP_SUPPORT_INSET_Z),
  ];
}

export function shouldAdhereObservatoryPlayerToGround({
  activeFlip,
  hoverGap,
  jumpQueued,
  verticalVelocityY,
}: {
  activeFlip: boolean;
  hoverGap: number;
  jumpQueued: boolean;
  verticalVelocityY: number;
}): boolean {
  return (
    hoverGap > 0
    && hoverGap <= PLAYER_GROUND_ADHESION_GAP
    && verticalVelocityY <= PLAYER_GROUND_ADHESION_MAX_VERTICAL_VELOCITY
    && !jumpQueued
    && !activeFlip
  );
}
