// Ported verbatim from huntronomer apps/desktop/src/features/hunt-observatory/character/physics/colliders.ts
// Import remapped: ../../types → ../../world/types, ../types → ../types
// Added: createStationPlateSpecs alias for createObservatoryStationPlateColliders

import type { HuntStationPlacement } from "../../world/types";
import type {
  ObservatoryBoundaryColliderOptions,
  ObservatoryColliderSpec,
  ObservatoryPlayerSpawnPoint,
  ObservatoryStationPlateOptions,
} from "../types";

export function createObservatoryFloorCollider(
  radius = 42,
  floorThickness = 0.5,
): ObservatoryColliderSpec {
  return {
    id: "observatory-floor",
    translation: [0, -floorThickness, 0],
    friction: 0.92,
    restitution: 0,
    shape: {
      kind: "box",
      halfExtents: [radius, floorThickness, radius],
    },
  };
}

export function createObservatoryBoundaryColliders(
  options: ObservatoryBoundaryColliderOptions = {},
): ObservatoryColliderSpec[] {
  const arenaRadius = options.arenaRadius ?? 46;
  const wallHeight = options.wallHeight ?? 6;
  const wallThickness = options.wallThickness ?? 0.8;
  const halfExtents: [number, number, number] = [arenaRadius, wallHeight, wallThickness];

  return [
    {
      id: "observatory-wall-north",
      translation: [0, wallHeight - 0.2, arenaRadius],
      shape: { kind: "box", halfExtents },
    },
    {
      id: "observatory-wall-south",
      translation: [0, wallHeight - 0.2, -arenaRadius],
      shape: { kind: "box", halfExtents },
    },
    {
      id: "observatory-wall-east",
      translation: [arenaRadius, wallHeight - 0.2, 0],
      rotationEuler: [0, Math.PI / 2, 0],
      shape: { kind: "box", halfExtents },
    },
    {
      id: "observatory-wall-west",
      translation: [-arenaRadius, wallHeight - 0.2, 0],
      rotationEuler: [0, Math.PI / 2, 0],
      shape: { kind: "box", halfExtents },
    },
    createObservatoryFloorCollider(arenaRadius, options.floorThickness ?? 0.5),
  ];
}

export function createObservatoryStationPlateColliders(
  placements: HuntStationPlacement[],
  options: ObservatoryStationPlateOptions = {},
): ObservatoryColliderSpec[] {
  const radius = options.radius ?? 4.6;
  const halfHeight = options.halfHeight ?? 0.24;
  const y = options.y ?? 0;

  return placements.map((placement) => {
    const angleRadians = (placement.angleDeg * Math.PI) / 180;
    const x = Math.cos(angleRadians) * placement.radius;
    const z = Math.sin(angleRadians) * placement.radius;
    return {
      id: `station-plate:${placement.id}`,
      translation: [x, y, z],
      userData: {
        stationId: placement.id,
        label: placement.label,
      },
      friction: 0.95,
      restitution: 0,
      shape: {
        kind: "cylinder",
        halfHeight,
        radius,
      },
    };
  });
}

// Alias for createObservatoryStationPlateColliders (used in FlowModeController)
export const createStationPlateSpecs = createObservatoryStationPlateColliders;

export function createObservatoryPlayerCapsuleCollider(
  spawn: ObservatoryPlayerSpawnPoint,
  halfHeight = 0.46,
  radius = 0.34,
): ObservatoryColliderSpec {
  return {
    id: `player-capsule:${spawn.id}`,
    translation: [...spawn.position],
    friction: 0,
    restitution: 0,
    userData: {
      stationId: spawn.stationId,
      spawnId: spawn.id,
    },
    shape: {
      kind: "capsule",
      halfHeight,
      radius,
    },
  };
}
