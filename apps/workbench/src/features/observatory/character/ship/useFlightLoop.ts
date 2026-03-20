/**
 * useFlightLoop.ts — Phase 21 FLT-02
 *
 * useFrame physics loop that applies velocity + quaternion rotation to the ship
 * group ref each frame. All scratch objects are pre-allocated at module level to
 * avoid GC pressure inside useFrame.
 *
 * Physics model (per CONTEXT.md):
 *   - WASD/Space produce thrust in ship-local axes
 *   - Mouse delta accumulates yaw (world-Y) and pitch (local-X) rotation
 *   - Velocity damps smoothly: v *= 1 - dampingFactor * dt
 *   - Speed is capped at cruiseSpeed (Plan 03 adds boost tier logic)
 *   - Store update is throttled to ~100ms to avoid per-frame setState
 */

import { useRef } from "react";
import { useFrame } from "@react-three/fiber";
import * as THREE from "three";
import {
  DEFAULT_FLIGHT_CONFIG,
  DEFAULT_FLIGHT_STATE,
  type FlightConfig,
  type FlightIntent,
  type FlightState,
} from "./flight-types";

// ---------------------------------------------------------------------------
// Module-level scratch objects (never re-allocated inside useFrame)
// ---------------------------------------------------------------------------

const _yawQuat = new THREE.Quaternion();
const _pitchQuat = new THREE.Quaternion();
const _yawEuler = new THREE.Euler();
const _pitchEuler = new THREE.Euler();
const _forward = new THREE.Vector3();
const _right = new THREE.Vector3();
const _worldUp = new THREE.Vector3(0, 1, 0);
const _thrustVec = new THREE.Vector3();
const _velocity = new THREE.Vector3();

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export interface UseFlightLoopOptions {
  intentRef: React.RefObject<FlightIntent>;
  config?: FlightConfig;
  /** Ref to the ship Group — position/quaternion updated in-place each frame */
  shipRef: React.RefObject<THREE.Group | null>;
  /** Callback to push flight state to store (~100ms throttle, not every frame) */
  onStateChange?: (state: FlightState) => void;
}

// ---------------------------------------------------------------------------
// Hook
// ---------------------------------------------------------------------------

export function useFlightLoop({
  intentRef,
  config = DEFAULT_FLIGHT_CONFIG,
  shipRef,
  onStateChange,
}: UseFlightLoopOptions): void {
  // Internal velocity accumulated across frames (world space)
  const velRef = useRef<THREE.Vector3>(new THREE.Vector3(0, 0, 0));

  // Snapshot throttle: only push to store every ~100ms
  const lastSnapshotMsRef = useRef<number>(0);

  useFrame((_, delta) => {
    const ship = shipRef.current;
    if (!ship) return;

    const intent = intentRef.current;
    if (!intent) return;

    // Clamp delta to avoid huge jumps after tab-unfocus or pausing
    const dt = Math.min(delta, 1 / 20);

    // -----------------------------------------------------------------------
    // Read intent values; zero consumed one-shot fields after reading
    // -----------------------------------------------------------------------
    const thrust = intent.thrust;
    const strafe = intent.strafe;
    const vertical = intent.vertical;
    const mouseDeltaX = intent.mouseDeltaX;
    const mouseDeltaY = intent.mouseDeltaY;
    // Zero mouse deltas — they are accumulated-since-last-frame values
    intent.mouseDeltaX = 0;
    intent.mouseDeltaY = 0;
    // Zero one-shot flags
    intent.boostTriggered = false;
    intent.interactTriggered = false;

    // -----------------------------------------------------------------------
    // Rotation — yaw around world Y, pitch around ship-local X
    // -----------------------------------------------------------------------
    if (mouseDeltaX !== 0 || mouseDeltaY !== 0) {
      const yawAngle = -mouseDeltaX * config.yawSensitivity;
      const pitchAngle = -mouseDeltaY * config.pitchSensitivity;

      // Yaw: rotate around world up axis
      _yawEuler.set(0, yawAngle, 0);
      _yawQuat.setFromEuler(_yawEuler);
      ship.quaternion.premultiply(_yawQuat);

      // Pitch: rotate around ship-local X axis (applied after yaw)
      _pitchEuler.set(pitchAngle, 0, 0);
      _pitchQuat.setFromEuler(_pitchEuler);
      ship.quaternion.multiply(_pitchQuat);

      // Normalize to prevent floating-point drift
      ship.quaternion.normalize();
    }

    // -----------------------------------------------------------------------
    // Thrust — derive ship axes from current quaternion
    // -----------------------------------------------------------------------
    const vel = velRef.current;

    if (thrust !== 0 || strafe !== 0 || vertical !== 0) {
      // Forward: -Z in ship space (cone tip faces -Z per ShipMesh)
      _forward.set(0, 0, -1).applyQuaternion(ship.quaternion);
      // Right: +X in ship space
      _right.set(1, 0, 0).applyQuaternion(ship.quaternion);
      // Vertical: world up (not ship-relative for natural feel)
      _worldUp.set(0, 1, 0);

      // Build thrust vector and accumulate velocity
      _thrustVec
        .copy(_forward).multiplyScalar(thrust)
        .addScaledVector(_right, strafe)
        .addScaledVector(_worldUp, vertical);

      // Only normalize if non-zero (guard against zero-length normalize)
      const thrustLength = _thrustVec.length();
      if (thrustLength > 0.0001) {
        _thrustVec.multiplyScalar(1 / thrustLength); // normalize
        _thrustVec.multiplyScalar(config.thrustAcceleration * dt);
        vel.add(_thrustVec);
      }
    }

    // -----------------------------------------------------------------------
    // Damping — smooth coast-to-stop (dampingFactor=1.5 per CONTEXT.md)
    // -----------------------------------------------------------------------
    vel.multiplyScalar(Math.max(0, 1 - config.dampingFactor * dt));

    // -----------------------------------------------------------------------
    // Speed cap — clamp to cruise speed (boost tier handled in Plan 03)
    // -----------------------------------------------------------------------
    const currentSpeed = vel.length();
    const speedCap = config.cruiseSpeed;
    if (currentSpeed > speedCap) {
      vel.multiplyScalar(speedCap / currentSpeed);
    }

    // -----------------------------------------------------------------------
    // Position update
    // -----------------------------------------------------------------------
    ship.position.addScaledVector(vel, dt);

    // -----------------------------------------------------------------------
    // Store snapshot — throttled to ~100ms to avoid per-frame setState
    // -----------------------------------------------------------------------
    if (onStateChange) {
      const nowMs = performance.now();
      if (nowMs - lastSnapshotMsRef.current >= 100) {
        lastSnapshotMsRef.current = nowMs;

        const pos = ship.position;
        const q = ship.quaternion;
        const speed = vel.length();

        const snapshot: FlightState = {
          velocity: [vel.x, vel.y, vel.z],
          quaternion: [q.x, q.y, q.z, q.w],
          position: [pos.x, pos.y, pos.z],
          speedTier: "cruise", // Plan 03 adds boost tier detection
          boostActivatedAtMs: DEFAULT_FLIGHT_STATE.boostActivatedAtMs,
          boostOnCooldown: false,
          pointerLocked: document.pointerLockElement != null,
          currentSpeed: speed,
          nearestStationId: null, // Plan 03 adds proximity detection
        };

        onStateChange(snapshot);
      }
    }
  });
}
