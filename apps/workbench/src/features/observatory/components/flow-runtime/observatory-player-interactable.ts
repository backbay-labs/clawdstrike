import type { ObservatoryHeroPropRecipe } from "../../world/deriveObservatoryWorld";
import { PLAYER_INTERACT_DISTANCE } from "./observatory-player-constants";

export function resolveNearestInteractableHeroProp(
  heroProps: readonly ObservatoryHeroPropRecipe[],
  position: [number, number, number],
): ObservatoryHeroPropRecipe | null {
  let bestProp: ObservatoryHeroPropRecipe | null = null;
  let bestDistance = PLAYER_INTERACT_DISTANCE * PLAYER_INTERACT_DISTANCE;

  for (const prop of heroProps) {
    if (prop.stationId === "core") continue;
    const dx = prop.position[0] - position[0];
    const dy = prop.position[1] + 0.8 - position[1];
    const dz = prop.position[2] - position[2];
    const distance = dx * dx + dy * dy + dz * dz;
    if (distance < bestDistance) {
      bestDistance = distance;
      bestProp = prop;
    }
  }

  return bestProp;
}
