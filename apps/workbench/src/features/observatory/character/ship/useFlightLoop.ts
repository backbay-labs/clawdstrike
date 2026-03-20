/**
 * useFlightLoop.ts — Phase 21 FLT-02/03
 *
 * useFrame physics loop that applies velocity + quaternion rotation to the ship
 * group ref each frame. All scratch objects are pre-allocated at module level to
 * avoid GC pressure inside useFrame.
 *
 * Physics model (per CONTEXT.md):
 *   - WASD/Space produce thrust in ship-local axes
 *   - Mouse delta accumulates yaw (world-Y) and pitch (local-X) rotation
 *   - Velocity damps smoothly: v *= 1 - dampingFactor * dt
 *   - Speed tier system: cruise (40 u/s), boost (120 u/s, 2s/4s), dock (8 u/s)
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
  type SpeedTier,
} from "./flight-types";
import { OBSERVATORY_STATION_POSITIONS } from "../../world/observatory-world-template";
import { HUNT_STATION_ORDER } from "../../world/stations";
import type { HuntStationId } from "../../world/types";
import { getObservatoryNowMs } from "../../utils/observatory-time";

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

// Pre-allocated vectors for dock proximity checks — avoids GC in hot path
const _stationPos = new THREE.Vector3();
const _shipPos = new THREE.Vector3();

// ---------------------------------------------------------------------------
// Dock proximity helper (pure, module-level — no allocations)
// ---------------------------------------------------------------------------

function findNearestStation(
  shipPosition: THREE.Vector3,
  proximityRadius: number,
): { stationId: HuntStationId; distance: number } | null {
  let nearest: { stationId: HuntStationId; distance: number } | null = null;
  for (const stationId of HUNT_STATION_ORDER) {
    const pos = OBSERVATORY_STATION_POSITIONS[stationId];
    _stationPos.set(pos[0], pos[1], pos[2]);
    const dist = shipPosition.distanceTo(_stationPos);
    if (dist <= proximityRadius && (nearest === null || dist < nearest.distance)) {
      nearest = { stationId, distance: dist };
    }
  }
  return nearest;
}

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
  /**
   * When this ref is false, thrust and rotation processing are skipped.
   * Damping and position updates still apply so the ship decelerates smoothly.
   * The docking system sets this to false during dock lock to take ownership.
   */
  flightInputEnabled?: React.RefObject<boolean>;
}

export interface UseFlightLoopResult {
  /** The internal velocity vector ref — exposed for docking system magnet-pull bias injection */
  velRef: React.RefObject<THREE.Vector3>;
}

// ---------------------------------------------------------------------------
// Hook
// ---------------------------------------------------------------------------

export function useFlightLoop({
  intentRef,
  config = DEFAULT_FLIGHT_CONFIG,
  shipRef,
  onStateChange,
  flightInputEnabled,
}: UseFlightLoopOptions): UseFlightLoopResult {
  // Internal velocity accumulated across frames (world space)
  const velRef = useRef<THREE.Vector3>(new THREE.Vector3(0, 0, 0));

  // Snapshot throttle: only push to store every ~100ms
  const lastSnapshotMsRef = useRef<number>(0);

  // Speed tier state machine
  const speedTierRef = useRef<SpeedTier>("cruise");
  const boostActivatedAtMsRef = useRef<number | null>(null);
  const boostOnCooldownRef = useRef(false);
  const nearestStationRef = useRef<{ stationId: HuntStationId; distance: number } | null>(null);

  useFrame((_, delta) => {
    const ship = shipRef.current;
    if (!ship) return;

    const intent = intentRef.current;
    if (!intent) return;

    // Clamp delta to avoid huge jumps after tab-unfocus or pausing
    const dt = Math.min(delta, 1 / 20);

    // Check whether the docking system has disabled flight input
    const inputActive = flightInputEnabled === undefined || flightInputEnabled.current !== false;

    // -----------------------------------------------------------------------
    // Read intent values; zero consumed one-shot fields after reading
    // -----------------------------------------------------------------------
    const thrust = intent.thrust;
    const strafe = intent.strafe;
    const vertical = intent.vertical;
    const mouseDeltaX = intent.mouseDeltaX;
    const mouseDeltaY = intent.mouseDeltaY;
    const boostTriggered = intent.boostTriggered;
    // Zero mouse deltas — they are accumulated-since-last-frame values
    intent.mouseDeltaX = 0;
    intent.mouseDeltaY = 0;
    // Zero one-shot flags (interactTriggered is consumed by useDockingSystem, not here)
    intent.boostTriggered = false;

    // -----------------------------------------------------------------------
    // Rotation — yaw around world Y, pitch around ship-local X
    // (Skipped when flight input is disabled by the docking system)
    // -----------------------------------------------------------------------
    if (inputActive && (mouseDeltaX !== 0 || mouseDeltaY !== 0)) {
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
    // (Skipped when flight input is disabled by the docking system)
    // -----------------------------------------------------------------------
    const vel = velRef.current;

    if (inputActive && (thrust !== 0 || strafe !== 0 || vertical !== 0)) {
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
    // Dock proximity check
    // -----------------------------------------------------------------------
    _shipPos.copy(ship.position);
    nearestStationRef.current = findNearestStation(_shipPos, config.dockProximityRadius);

    // -----------------------------------------------------------------------
    // Boost state machine
    // -----------------------------------------------------------------------
    const nowMs = getObservatoryNowMs();

    if (boostTriggered && !boostOnCooldownRef.current && speedTierRef.current !== "dock") {
      // Activate boost
      boostActivatedAtMsRef.current = nowMs;
      speedTierRef.current = "boost";
      boostOnCooldownRef.current = false;
    }

    if (speedTierRef.current === "boost" && boostActivatedAtMsRef.current !== null) {
      const elapsed = nowMs - boostActivatedAtMsRef.current;
      if (elapsed >= config.boostDurationMs) {
        // Boost expired — enter cooldown
        speedTierRef.current = "cruise";
        boostOnCooldownRef.current = true;
      }
    }

    if (boostOnCooldownRef.current && boostActivatedAtMsRef.current !== null) {
      const elapsed = nowMs - boostActivatedAtMsRef.current;
      if (elapsed >= config.boostDurationMs + config.boostCooldownMs) {
        // Cooldown expired
        boostOnCooldownRef.current = false;
        boostActivatedAtMsRef.current = null;
      }
    }

    // Dock override: if near a station, force dock tier regardless of boost
    if (nearestStationRef.current !== null) {
      if (speedTierRef.current === "boost") {
        // Cancel boost when entering dock zone
        boostOnCooldownRef.current = true;
      }
      speedTierRef.current = "dock";
    } else if (speedTierRef.current === "dock") {
      // Left dock zone — return to cruise
      speedTierRef.current = "cruise";
    }

    // -----------------------------------------------------------------------
    // Speed cap — smooth lerp transition (no hard velocity snap)
    // -----------------------------------------------------------------------
    const speedCap =
      speedTierRef.current === "boost"
        ? config.cruiseSpeed * config.boostMultiplier // 120
        : speedTierRef.current === "dock"
          ? config.dockSpeed // 8
          : config.cruiseSpeed; // 40

    const currentSpeed = vel.length();
    if (currentSpeed > speedCap) {
      // Smooth transition: lerp down over ~0.2s (dt*5) rather than hard-snap
      const lerpedSpeed = currentSpeed + (speedCap - currentSpeed) * Math.min(1, dt * 5);
      vel.normalize().multiplyScalar(lerpedSpeed);
    }

    // -----------------------------------------------------------------------
    // Position update
    // -----------------------------------------------------------------------
    ship.position.addScaledVector(vel, dt);

    // -----------------------------------------------------------------------
    // Store snapshot — throttled to ~100ms to avoid per-frame setState
    // -----------------------------------------------------------------------
    if (onStateChange) {
      if (nowMs - lastSnapshotMsRef.current >= 100) {
        lastSnapshotMsRef.current = nowMs;

        const pos = ship.position;
        const q = ship.quaternion;

        const snapshot: FlightState = {
          velocity: [vel.x, vel.y, vel.z],
          quaternion: [q.x, q.y, q.z, q.w],
          position: [pos.x, pos.y, pos.z],
          speedTier: speedTierRef.current,
          boostActivatedAtMs: boostActivatedAtMsRef.current,
          boostOnCooldown: boostOnCooldownRef.current,
          pointerLocked: document.pointerLockElement != null,
          currentSpeed: vel.length(),
          nearestStationId: nearestStationRef.current?.stationId ?? null,
        };

        onStateChange(snapshot);
      }
    }
  });

  // Return velRef so useDockingSystem can inject magnet-pull bias directly
  return { velRef };
}

// Suppress unused warning for _velocity — kept for future use (rollback/replay)
void _velocity;
