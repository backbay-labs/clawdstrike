import { useMemo } from "react";
import { CapsuleCollider, CuboidCollider, CylinderCollider } from "@react-three/rapier";
import { createObservatoryBoundaryColliders } from "../../character/physics/colliders";
import type { DerivedObservatoryWorld } from "../../world/deriveObservatoryWorld";
import type { ObservatoryColliderSpec } from "../../character/types";
import { createStationPlateSpecs } from "./grounding";

function ColliderFromSpec({ spec }: { spec: ObservatoryColliderSpec }) {
  const rotation = spec.rotationEuler ?? [0, 0, 0];
  switch (spec.shape.kind) {
    case "box":
      return (
        <CuboidCollider
          args={spec.shape.halfExtents}
          friction={spec.friction}
          position={spec.translation}
          restitution={spec.restitution}
          rotation={rotation}
          sensor={spec.sensor}
        />
      );
    case "capsule":
      return (
        <CapsuleCollider
          args={[spec.shape.halfHeight, spec.shape.radius]}
          friction={spec.friction}
          position={spec.translation}
          restitution={spec.restitution}
          rotation={rotation}
          sensor={spec.sensor}
        />
      );
    case "cylinder":
      return (
        <CylinderCollider
          args={[spec.shape.halfHeight, spec.shape.radius]}
          friction={spec.friction}
          position={spec.translation}
          restitution={spec.restitution}
          rotation={rotation}
          sensor={spec.sensor}
        />
      );
    default:
      return null;
  }
}

export function ObservatoryFlowColliders({ world }: { world: DerivedObservatoryWorld }) {
  const specs = useMemo(() => {
    const arenaRadius = Math.max(46, world.environment.floorRadius * 0.9);
    return [
      ...createObservatoryBoundaryColliders({
        arenaRadius,
        floorThickness: 0.4,
        wallHeight: 7,
        wallThickness: 0.8,
      }),
      ...createStationPlateSpecs(world),
    ];
  }, [world]);

  return (
    <>
      {specs.map((spec) => (
        <ColliderFromSpec key={spec.id} spec={spec} />
      ))}
    </>
  );
}
