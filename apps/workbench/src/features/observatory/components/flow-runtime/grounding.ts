import * as THREE from "three";
import type {
  ObservatoryColliderSpec,
  ObservatoryPlayerSpawnPoint,
} from "../../character/types";
import type {
  DerivedObservatoryWorld,
  ObservatoryHeroPropRecipe,
  ObservatoryTraversalSurfaceRecipe,
} from "../../world/deriveObservatoryWorld";
import type { HuntStationId } from "../../world/types";
import { resolveObservatoryTraversalHalfExtents } from "../../world/grounding";

export const PLAYER_COLLIDER_HALF_HEIGHT = 0.46;
export const PLAYER_COLLIDER_RADIUS = 0.34;
export const PLAYER_STAND_HEIGHT = PLAYER_COLLIDER_HALF_HEIGHT + PLAYER_COLLIDER_RADIUS;
export const PLAYER_GROUNDED_EPSILON = 0.12;
export const PLAYER_INTERACT_DISTANCE = 2.2;

export interface ObservatoryPlayerFocusState {
  action: string | null;
  airborne: boolean;
  facingRadians: number;
  moving: boolean;
  moveVector: [number, number];
  position: [number, number, number];
  sprinting: boolean;
  stationId?: HuntStationId | null;
}

export interface ObservatoryPlayerWorldState {
  interactableAssetId: ObservatoryHeroPropRecipe["assetId"] | null;
  stationId: HuntStationId | null;
}

export interface MissionInteractionSource {
  source: "click" | "player";
}

export interface ObservatoryGroundQuery {
  districts: PrecomputedGroundDistrict[];
  watchfieldX: number;
  watchfieldZ: number;
}

export interface ObservatoryGroundScratch {
  localPoint: THREE.Vector3;
  topPoint: THREE.Vector3;
}

export function createObservatoryGroundScratch(): ObservatoryGroundScratch {
  return {
    localPoint: new THREE.Vector3(),
    topPoint: new THREE.Vector3(),
  };
}

type PrecomputedGroundSurface =
  | {
      kind: "cylinder";
      centerX: number;
      centerY: number;
      centerZ: number;
      jumpBoost: number | null;
      radius: number;
      topY: number;
    }
  | {
      kind: "box";
      centerX: number;
      centerY: number;
      centerZ: number;
      halfExtents: [number, number, number];
      inverseQuaternion: THREE.Quaternion;
      jumpBoost: number | null;
      quaternion: THREE.Quaternion;
    };

interface PrecomputedGroundDistrict {
  id: HuntStationId;
  plateRadius: number;
  surfaces: PrecomputedGroundSurface[];
  x: number;
  z: number;
}

function compareTraversalSurfacePriority(
  left: ObservatoryTraversalSurfaceRecipe,
  right: ObservatoryTraversalSurfaceRecipe,
): number {
  const rank = (kind: ObservatoryTraversalSurfaceRecipe["kind"]): number => {
    switch (kind) {
      case "observation-platform":
        return 0;
      case "control-deck":
        return 1;
      case "platform":
        return 2;
      case "ledge":
        return 3;
      case "bridge":
        return 4;
      case "catwalk":
        return 5;
      case "hanging-platform":
        return 6;
      case "ramp":
        return 7;
      case "jump-pad":
        return 8;
    }
  };

  const rankDelta = rank(left.kind) - rank(right.kind);
  if (rankDelta !== 0) return rankDelta;
  return right.scale[1] - left.scale[1];
}

export function resolveObservatoryWorldSpawn(
  world: DerivedObservatoryWorld,
  preferredStationId: HuntStationId | null,
): ObservatoryPlayerSpawnPoint {
  const stationDistrict =
    world.districts.find((district) => district.id === preferredStationId)
    ?? world.districts.find((district) => district.active)
    ?? world.districts.find((district) => district.likely)
    ?? null;

  if (stationDistrict) {
    const preferredSurface = [...stationDistrict.traversalSurfaces].sort(compareTraversalSurfacePriority)[0] ?? null;
    const towardCoreX = -stationDistrict.position[0];
    const towardCoreZ = -stationDistrict.position[2];

    if (preferredSurface) {
      const surfaceCenterX = stationDistrict.position[0] + preferredSurface.position[0];
      const surfaceCenterY = stationDistrict.position[1] + preferredSurface.position[1];
      const surfaceCenterZ = stationDistrict.position[2] + preferredSurface.position[2];
      const topY = surfaceCenterY + preferredSurface.scale[1] * 0.5;

      return {
        id: `district:${stationDistrict.id}:${preferredSurface.key}`,
        label: `${stationDistrict.label} Arrival`,
        position: [surfaceCenterX, topY + PLAYER_STAND_HEIGHT + 0.05, surfaceCenterZ],
        facingRadians: Math.atan2(towardCoreX, towardCoreZ),
        stationId: stationDistrict.id,
      };
    }

    return {
      id: `district:${stationDistrict.id}`,
      label: stationDistrict.label,
      position: [stationDistrict.position[0], 0.24 + PLAYER_STAND_HEIGHT, stationDistrict.position[2]],
      facingRadians: Math.atan2(towardCoreX, towardCoreZ),
      stationId: stationDistrict.id,
    };
  }

  return {
    id: "thesis-core",
    label: "Thesis Core",
    position: [0, PLAYER_STAND_HEIGHT, 6.6],
    facingRadians: Math.PI,
    stationId: null,
  };
}

export function createObservatoryGroundQuery(world: DerivedObservatoryWorld): ObservatoryGroundQuery {
  return {
    districts: world.districts.map((district) => ({
      id: district.id,
      plateRadius: Math.max(2.8, district.baseDiscRadius * 0.82),
      surfaces: district.traversalSurfaces.map((surface) => {
        const centerX = district.position[0] + surface.position[0];
        const centerY = district.position[1] + surface.position[1];
        const centerZ = district.position[2] + surface.position[2];
        const jumpBoost = surface.kind === "jump-pad" ? surface.jumpBoost ?? null : null;

        if (surface.colliderKind === "cylinder") {
          return {
            kind: "cylinder",
            centerX,
            centerY,
            centerZ,
            jumpBoost,
            radius: surface.scale[0] * 0.5,
            topY: centerY + surface.scale[1] * 0.5,
          } satisfies PrecomputedGroundSurface;
        }

        const quaternion = new THREE.Quaternion().setFromEuler(new THREE.Euler(...surface.rotation));

        return {
          kind: "box",
          centerX,
          centerY,
          centerZ,
          halfExtents: resolveObservatoryTraversalHalfExtents(surface),
          inverseQuaternion: quaternion.clone().invert(),
          jumpBoost,
          quaternion,
        } satisfies PrecomputedGroundSurface;
      }),
      x: district.position[0],
      z: district.position[2],
    })),
    watchfieldX: world.watchfield.position[0],
    watchfieldZ: world.watchfield.position[2],
  };
}

export function resolveGroundHeightFromQuery(
  query: ObservatoryGroundQuery,
  position: [number, number, number],
  scratch: ObservatoryGroundScratch,
): number {
  let resolvedHeight = 0;

  for (const district of query.districts) {
    const dx = position[0] - district.x;
    const dz = position[2] - district.z;
    if (Math.hypot(dx, dz) <= district.plateRadius) {
      resolvedHeight = Math.max(resolvedHeight, 0.24);
    }

    for (const surface of district.surfaces) {
      if (surface.kind === "cylinder") {
        if (Math.hypot(position[0] - surface.centerX, position[2] - surface.centerZ) <= surface.radius) {
          resolvedHeight = Math.max(resolvedHeight, surface.topY);
        }
        continue;
      }

      scratch.localPoint
        .set(position[0] - surface.centerX, position[1] - surface.centerY, position[2] - surface.centerZ)
        .applyQuaternion(surface.inverseQuaternion);

      if (
        Math.abs(scratch.localPoint.x) <= surface.halfExtents[0]
        && Math.abs(scratch.localPoint.z) <= surface.halfExtents[2]
      ) {
        scratch.topPoint.set(scratch.localPoint.x, surface.halfExtents[1], scratch.localPoint.z).applyQuaternion(surface.quaternion);
        resolvedHeight = Math.max(resolvedHeight, scratch.topPoint.y + surface.centerY);
      }
    }
  }

  if (Math.hypot(position[0] - query.watchfieldX, position[2] - query.watchfieldZ) <= 1.8) {
    resolvedHeight = Math.max(resolvedHeight, 0.24);
  }

  return resolvedHeight;
}

export function resolveNearestDistrictIdFromQuery(
  query: ObservatoryGroundQuery,
  position: [number, number, number],
): HuntStationId | null {
  let nearestId: HuntStationId | null = null;
  let nearestDistance = Number.POSITIVE_INFINITY;

  for (const district of query.districts) {
    const distance = Math.hypot(position[0] - district.x, position[2] - district.z);
    if (distance < nearestDistance) {
      nearestDistance = distance;
      nearestId = district.id;
    }
  }

  return nearestDistance <= 12 ? nearestId : null;
}

export function resolveJumpPadBoostFromQuery(
  query: ObservatoryGroundQuery,
  position: [number, number, number],
): number | null {
  for (const district of query.districts) {
    for (const surface of district.surfaces) {
      if (surface.jumpBoost == null) {
        continue;
      }

      if (
        Math.hypot(position[0] - surface.centerX, position[2] - surface.centerZ)
        <= (surface.kind === "cylinder" ? surface.radius : surface.halfExtents[0])
      ) {
        return surface.jumpBoost;
      }
    }
  }

  return null;
}

export function createStationPlateSpecs(world: DerivedObservatoryWorld): ObservatoryColliderSpec[] {
  return world.districts.flatMap((district) => {
    const districtSpecs: ObservatoryColliderSpec[] = [
      {
        id: `station-plate:${district.id}`,
        translation: [district.position[0], 0, district.position[2]],
        friction: 0.96,
        restitution: 0,
        userData: { stationId: district.id, label: district.label },
        shape: {
          kind: "cylinder",
          halfHeight: 0.24,
          radius: Math.max(2.8, district.baseDiscRadius * 0.82),
        },
      },
    ];

    for (const surface of district.traversalSurfaces) {
      districtSpecs.push({
        id: `traversal:${district.id}:${surface.key}`,
        translation: [
          district.position[0] + surface.position[0],
          district.position[1] + surface.position[1],
          district.position[2] + surface.position[2],
        ],
        friction: surface.kind === "jump-pad" ? 0.84 : 0.96,
        restitution: surface.kind === "jump-pad" ? 0.08 : 0,
        rotationEuler: surface.rotation,
        userData: { stationId: district.id, surfaceKind: surface.kind },
        shape:
          surface.colliderKind === "cylinder"
            ? {
                kind: "cylinder",
                halfHeight: surface.scale[1] * 0.5,
                radius: surface.scale[0] * 0.5,
              }
            : {
                kind: "box",
                halfExtents: resolveObservatoryTraversalHalfExtents(surface),
              },
      });
    }

    return districtSpecs;
  });
}
