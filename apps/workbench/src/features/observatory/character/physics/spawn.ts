// Ported verbatim from huntronomer apps/desktop/src/features/hunt-observatory/character/physics/spawn.ts
// Import remapped: ../../types → ../../world/types, ../types → ../types

import type { HuntStationId, HuntStationPlacement } from "../../world/types";
import {
  buildStationSpawnPoint,
  DEFAULT_OBSERVATORY_PLAYER_SPAWN,
  type ObservatoryPlayerSpawnPoint,
  type ObservatorySpawnResolutionOptions,
} from "../types";

export function createObservatorySpawnPoint(
  id: string,
  label: string,
  position: [number, number, number],
  facingRadians = 0,
  stationId: HuntStationId | null = null,
): ObservatoryPlayerSpawnPoint {
  return {
    id,
    label,
    position,
    facingRadians,
    stationId,
  };
}

export function resolveObservatorySpawnPoint(
  placements: HuntStationPlacement[],
  preferredStationId?: HuntStationId | null,
  options: ObservatorySpawnResolutionOptions = {},
): ObservatoryPlayerSpawnPoint {
  if (!preferredStationId) {
    return {
      ...DEFAULT_OBSERVATORY_PLAYER_SPAWN,
      position: [
        DEFAULT_OBSERVATORY_PLAYER_SPAWN.position[0],
        options.baseHeight ?? DEFAULT_OBSERVATORY_PLAYER_SPAWN.position[1],
        DEFAULT_OBSERVATORY_PLAYER_SPAWN.position[2],
      ],
    };
  }

  const placement = placements.find((candidate) => candidate.id === preferredStationId);
  if (!placement) {
    return resolveObservatorySpawnPoint(placements, null, options);
  }
  return buildStationSpawnPoint(placement, options);
}

export function createObservatoryStationSpawnPoints(
  placements: HuntStationPlacement[],
  options: ObservatorySpawnResolutionOptions = {},
): ObservatoryPlayerSpawnPoint[] {
  return placements.map((placement) => buildStationSpawnPoint(placement, options));
}
