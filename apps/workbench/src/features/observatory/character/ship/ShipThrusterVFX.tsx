/**
 * ShipThrusterVFX.tsx — Phase 21 FLT-06
 *
 * Ship thruster particle exhaust using wawa-vfx VFXEmitter.
 * One emitter per nozzle (4 total), anchored to SHIP_THRUSTER_LAYOUT positions.
 *
 * Behavior:
 *   - idle (thrustIntensity < 0.01): no particles emitted
 *   - cruise thrust: 6 blue particles/frame per nozzle, 0.2-0.4s lifetime
 *   - boost thrust: 24 bright orange particles/frame per nozzle, 0.3-0.6s lifetime
 *
 * VFX pool: "ship-thruster-exhaust" (StretchBillboard, registered in ObservatoryVFXPools)
 *
 * Pattern follows CharacterVFX.tsx exactly:
 *   useFrame reads state → calls startEmitting/stopEmitting/position.copy imperatively
 */

import { useRef } from "react";
import { useFrame } from "@react-three/fiber";
import { VFXEmitter, type VFXEmitterSettings } from "wawa-vfx";
import * as THREE from "three";
import { SHIP_THRUSTER_LAYOUT } from "./flight-types";

// ---------------------------------------------------------------------------
// Module-level pre-allocated vector
// ---------------------------------------------------------------------------

const _nozzleWorldPos = new THREE.Vector3();

// ---------------------------------------------------------------------------
// VFXEmitter settings
// ---------------------------------------------------------------------------

/** Cruise thrust — blue, short trails, moderate particle count */
const CRUISE_THRUST_SETTINGS: VFXEmitterSettings = {
  spawnMode: "time",
  nbParticles: 6,
  duration: 0.08,
  loop: true,
  particlesLifetime: [0.2, 0.4],
  size: [0.04, 0.08],
  colorStart: ["#88ccff", "#aaddff"],
  colorEnd: ["#3388cc", "#226699"],
  directionMin: [-0.1, -0.1, 0.8],
  directionMax: [0.1, 0.1, 1.0],
  speed: [3.0, 5.0],
};

/** Boost thrust — bright orange, longer trails, high particle count */
const BOOST_THRUST_SETTINGS: VFXEmitterSettings = {
  spawnMode: "time",
  nbParticles: 24,
  duration: 0.06,
  loop: true,
  particlesLifetime: [0.3, 0.6],
  size: [0.06, 0.14],
  colorStart: ["#ffffff", "#ffdd88"],
  colorEnd: ["#ff8844", "#ff6622"],
  directionMin: [-0.2, -0.2, 0.6],
  directionMax: [0.2, 0.2, 1.0],
  speed: [6.0, 10.0],
};

// ---------------------------------------------------------------------------
// VFXEmitter ref type (matches CharacterVFX.tsx pattern)
// ---------------------------------------------------------------------------

interface VFXEmitterRef extends THREE.Object3D {
  startEmitting: (reset?: boolean) => void;
  stopEmitting: () => void;
  emitAtPos: (position: THREE.Vector3 | null, reset?: boolean) => void;
}

// ---------------------------------------------------------------------------
// Props
// ---------------------------------------------------------------------------

export interface ShipThrusterVFXProps {
  /** Ship group ref — nozzle positions in ship-local space, transformed to world each frame */
  shipRef: React.RefObject<THREE.Group | null>;
  /** Current thrust intensity 0-1 (0 = idle, 1 = full cruise, >1 not clamped here) */
  thrustIntensity: number;
  /** Whether currently boosting — switches to BOOST_THRUST_SETTINGS */
  boosting: boolean;
  /** Spirit accent color for optional particle tint (currently informational) */
  accentColor?: string;
}

// ---------------------------------------------------------------------------
// Component
// ---------------------------------------------------------------------------

export function ShipThrusterVFX({
  shipRef,
  thrustIntensity,
  boosting,
}: ShipThrusterVFXProps) {
  // One ref slot per nozzle
  const emitterRefs = useRef<(VFXEmitterRef | null)[]>([null, null, null, null]);

  // Track whether we were thrusting last frame to detect start/stop transitions
  const wasThrustingRef = useRef(false);

  useFrame(() => {
    const ship = shipRef.current;

    if (thrustIntensity < 0.01) {
      // Idle: stop all emitters if we were just thrusting
      if (wasThrustingRef.current) {
        emitterRefs.current.forEach((e) => e?.stopEmitting());
        wasThrustingRef.current = false;
      }
      return;
    }

    if (!ship) return;

    // Thrusting — update each nozzle's world position and start if newly thrusting
    const nozzlePositions = SHIP_THRUSTER_LAYOUT.nozzlePositions;
    for (let i = 0; i < nozzlePositions.length; i++) {
      const emitter = emitterRefs.current[i];
      if (!emitter) continue;

      // Transform nozzle local position to world space via ship matrixWorld
      const [nx, ny, nz] = nozzlePositions[i];
      _nozzleWorldPos.set(nx, ny, nz).applyMatrix4(ship.matrixWorld);
      emitter.position.copy(_nozzleWorldPos);
    }

    // Start emitting on transition from idle → thrusting
    if (!wasThrustingRef.current) {
      emitterRefs.current.forEach((e) => e?.startEmitting(true));
    }

    wasThrustingRef.current = true;
  });

  return (
    <group>
      {SHIP_THRUSTER_LAYOUT.nozzlePositions.map((_, index) => (
        <VFXEmitter
          key={index}
          ref={(el: VFXEmitterRef | null) => {
            emitterRefs.current[index] = el;
          }}
          emitter="ship-thruster-exhaust"
          settings={boosting ? BOOST_THRUST_SETTINGS : CRUISE_THRUST_SETTINGS}
          autoStart={false}
        />
      ))}
    </group>
  );
}
