import { useRef } from "react";
import { useFrame } from "@react-three/fiber";
import { useVFX } from "wawa-vfx";
import * as THREE from "three";

// Pre-allocated vector — never re-created inside useFrame
const _backpackWorldPos = new THREE.Vector3();

export interface CharacterVFXProps {
  /** Character world position from runtime.state.position */
  position: [number, number, number];
  /** Whether character is grounded (true = on ground) */
  grounded: boolean;
  /** Whether character is sprinting */
  sprinting: boolean | undefined;
  /** Active animation action — used to detect jump state */
  activeAction: string | null | undefined;
  /** Character facing direction in radians (used to offset backpack position) */
  facingRadians: number;
}

/**
 * CharacterVFX — PFX-01 (landing dust) + PFX-05 (thruster exhaust)
 *
 * Rendered as a sibling to ObservatoryPlayerAvatar inside ObservatoryPlayerRig.
 * Reads character state via props (passed from runtime.state in ObservatoryPlayerRig).
 *
 * Landing dust (PFX-01):
 *   Emits one burst on the frame when grounded transitions from false → true.
 *   Burst position = character position at near ground level (y = position.y - 0.05).
 *
 * Thruster exhaust (PFX-05):
 *   Emits continuously every frame during sprint or jump states.
 *   Emitter position derived from character position + backpack offset.
 *   Backpack world offset: avatar rendered at positionOffset=[0,-0.8,0] and scale=1.48.
 *   Fallback rig backpack group: torso at y=1.12, backpack at y=1.12+0.04=1.16, z=-0.28.
 *   World Y offset: -0.8 + 1.16 * 1.48 ≈ +0.917
 *   World XZ offset: 0.28 * 1.48 ≈ 0.414 behind the facing direction
 */
export function CharacterVFX({
  position,
  grounded,
  sprinting,
  activeAction,
  facingRadians,
}: CharacterVFXProps) {
  const { emit } = useVFX();
  const prevGroundedRef = useRef<boolean>(grounded);

  useFrame(() => {
    const wasGrounded = prevGroundedRef.current;

    // PFX-01: Landing dust — exactly one burst on touchdown (airborne → grounded)
    if (!wasGrounded && grounded) {
      emit("landing-dust", {
        position: [
          position[0],
          position[1] - 0.05, // slight below character origin = ground contact point
          position[2],
        ],
      });
    }
    prevGroundedRef.current = grounded;

    // PFX-05: Thruster exhaust — continuous during sprint or jump states
    const isThrusting =
      sprinting === true
      || activeAction === "jump"
      || activeAction === "flip-front"
      || activeAction === "flip-back";

    if (isThrusting) {
      // Backpack world position derived from character state + known avatar offsets:
      // Avatar rendered at scale=1.48, positionOffset=[0,-0.8,0]
      // Fallback rig backpack local pos: torso=[0,1.12,0], backpack=[0,0.04,-0.28] relative to torso
      // World Y: position.y + (-0.8 + 1.16 * 1.48) = position.y + 0.917
      // World XZ: 0.28 * 1.48 = 0.414 offset behind the facing direction
      const backpackOffsetY = -0.8 + 1.16 * 1.48; // ≈ 0.917
      const backpackOffsetXZ = 0.28 * 1.48; // ≈ 0.414

      _backpackWorldPos.set(
        position[0] - Math.sin(facingRadians) * backpackOffsetXZ,
        position[1] + backpackOffsetY,
        position[2] - Math.cos(facingRadians) * backpackOffsetXZ,
      );

      emit("thruster-exhaust", {
        position: _backpackWorldPos.toArray() as [number, number, number],
      });
    }
  });

  // CharacterVFX renders no geometry — it is a pure behavior component
  return null;
}
