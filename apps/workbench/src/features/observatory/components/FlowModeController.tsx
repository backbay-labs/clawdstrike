// FlowModeController — OBS-06 Easter-egg character controller wrapper.
// Lazy-loaded Rapier Physics + player capsule collider + WASD input hook.
// Renders null when characterControllerEnabled=false — this is the common case.
// Rapier (@react-three/rapier) is imported here: this file is the lazy module boundary.
// Physics wrapper only active when characterControllerEnabled=true (pitfall 1: no always-on overhead).

import { Physics, RigidBody, CapsuleCollider } from "@react-three/rapier";
import { useRef } from "react";
import { useFrame } from "@react-three/fiber";
import { useObservatoryPlayerInput } from "../character/input/useObservatoryPlayerInput";
import { useObservatoryPlayerRuntime } from "../character/controller/useObservatoryPlayerRuntime";
import { DEFAULT_OBSERVATORY_PLAYER_SPAWN } from "../character/types";
import { createObservatoryBoundaryColliders } from "../character/physics/colliders";
import type { RapierRigidBody } from "@react-three/rapier";

export interface FlowModeControllerProps {
  /** Whether the character controller Easter-egg is active */
  characterControllerEnabled: boolean;
  /** Called when the controller should be toggled (double-click) */
  onEnable: () => void;
  /** Whether the observatory pane is currently the active pane (gates keyboard input) */
  paneIsActive?: boolean;
}

// ─── ObservatoryPlayerAvatar ─────────────────────────────────────────────────
// Simple capsule mesh — no GLB avatar in workbench (Phase 3 constraint).
function ObservatoryPlayerAvatar() {
  return (
    <mesh position={[0, 0.5, 0]}>
      <capsuleGeometry args={[0.3, 1.0, 8, 16]} />
      <meshStandardMaterial color="#3dbf84" roughness={0.5} metalness={0.2} />
    </mesh>
  );
}

// ─── BoundaryColliders ────────────────────────────────────────────────────────
// Static colliders defining arena walls and floor. Pure data → Rapier colliders.
function BoundaryColliders() {
  const specs = createObservatoryBoundaryColliders();
  return (
    <>
      {specs.map((spec) => {
        if (spec.shape.kind === "box") {
          const { halfExtents } = spec.shape;
          return (
            <RigidBody
              key={spec.id}
              type="fixed"
              position={spec.translation}
              rotation={spec.rotationEuler}
              friction={spec.friction ?? 0.5}
              restitution={spec.restitution ?? 0}
            >
              <CapsuleCollider args={[halfExtents[1], halfExtents[0]]} />
            </RigidBody>
          );
        }
        return null;
      })}
    </>
  );
}

// ─── PlayerController ────────────────────────────────────────────────────────
// Drives RigidBody position each frame via useFrame + player runtime.
function PlayerController({ paneIsActive }: { paneIsActive: boolean }) {
  const rigidBodyRef = useRef<RapierRigidBody | null>(null);

  const runtime = useObservatoryPlayerRuntime({
    spawn: DEFAULT_OBSERVATORY_PLAYER_SPAWN,
  });

  // Keyboard input — only active when pane is focused (pitfall 5: keyboard scope)
  const { intent, consumeTransientActions } = useObservatoryPlayerInput({
    enabled: paneIsActive,
  });

  useFrame((_, delta) => {
    if (!rigidBodyRef.current) return;

    const nowMs = performance.now();
    const result = runtime.step(intent, {
      deltaSeconds: delta,
      nowMs,
      body: {
        position: [
          rigidBodyRef.current.translation().x,
          rigidBodyRef.current.translation().y,
          rigidBodyRef.current.translation().z,
        ],
        velocity: [
          rigidBodyRef.current.linvel().x,
          rigidBodyRef.current.linvel().y,
          rigidBodyRef.current.linvel().z,
        ],
        grounded: true, // simplified: assume grounded (no contact detection in Phase 3)
      },
    });

    consumeTransientActions();

    // Apply velocity from runtime command
    rigidBodyRef.current.setLinvel(
      {
        x: result.command.linearVelocity[0],
        y: result.command.linearVelocity[1],
        z: result.command.linearVelocity[2],
      },
      true,
    );
  });

  return (
    <RigidBody
      ref={rigidBodyRef}
      type="dynamic"
      position={DEFAULT_OBSERVATORY_PLAYER_SPAWN.position}
      enabledRotations={[false, false, false]}
      lockRotations
      colliders={false}
    >
      <CapsuleCollider args={[0.46, 0.34]} friction={0} restitution={0} />
      <ObservatoryPlayerAvatar />
    </RigidBody>
  );
}

// ─── FlowModeController ──────────────────────────────────────────────────────
// Lazy module boundary — @react-three/rapier imported here, never in main bundle.
// Renders null when characterControllerEnabled=false (most common case).
// Physics overhead: zero when disabled (no RigidBody ticks).
export function FlowModeController({
  characterControllerEnabled,
  paneIsActive = false,
}: FlowModeControllerProps) {
  if (!characterControllerEnabled) return null;

  return (
    <Physics gravity={[0, -18, 0]}>
      <BoundaryColliders />
      <PlayerController paneIsActive={paneIsActive} />
    </Physics>
  );
}
