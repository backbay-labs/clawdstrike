/**
 * ChaseCamera.tsx — Phase 21 FLT-05
 *
 * Chase camera that follows the ship with smooth lerp-lagged tracking.
 * Rendered as a sibling to the ship group inside SpaceFlightController.
 *
 * Design:
 *   - Camera offset (0, 4, 14) in ship-local space, rotated by ship quaternion
 *   - Ship leads; camera follows with a configurable lerp factor (default 0.07)
 *   - Uses frame-rate independent exponential lerp so lag stays consistent at any fps
 *   - Camera looks slightly ahead of the ship (anticipatory look-at)
 *   - Fast convergence for first 0.8s after mount so camera snaps cleanly into chase position
 *   - Only mounts inside SpaceFlightController — OrbitControls (atlas mode) is unaffected
 */

import { useRef } from "react";
import { useFrame, useThree } from "@react-three/fiber";
import * as THREE from "three";
import { useObservatoryStore } from "../../stores/observatory-store";
import { DOCKING_CONFIG } from "./docking-types";
import { stationPosition } from "../../world/observatory-world-template";

// ---------------------------------------------------------------------------
// Module-level pre-allocated vectors — never recreated inside useFrame
// ---------------------------------------------------------------------------

const _desiredPos = new THREE.Vector3();
const _lookTarget = new THREE.Vector3();
const _offset = new THREE.Vector3();
const _shipForward = new THREE.Vector3();
const _dockPos = new THREE.Vector3();
const _dockCamOffset = new THREE.Vector3();

// ---------------------------------------------------------------------------
// Props
// ---------------------------------------------------------------------------

export interface ChaseCameraProps {
  /** Ref to the ship Group whose position/quaternion we follow */
  shipRef: React.RefObject<THREE.Group | null>;
  /**
   * Chase offset in ship-local space [x, y, z].
   * Default: (0, 4, 14) — behind and above the ship.
   * The offset is rotated by the ship's quaternion so it always stays behind+above
   * regardless of ship orientation.
   */
  offset?: [number, number, number];
  /**
   * Lerp follow factor per second (not per frame — see frame-rate independent lerp below).
   * Lower = more lag (camera trails further behind); higher = tighter tracking.
   * Default: 0.07 per CONTEXT.md guidance.
   */
  followFactor?: number;
  /**
   * Look-ahead distance — camera looks this many units ahead of the ship center
   * along the ship's forward direction. Creates an anticipatory feel.
   * Default: 8 units.
   */
  lookAheadDistance?: number;
}

// ---------------------------------------------------------------------------
// Component
// ---------------------------------------------------------------------------

export function ChaseCamera({
  shipRef,
  offset = [0, 4, 14],
  followFactor = 0.07,
  lookAheadDistance = 8,
}: ChaseCameraProps) {
  const { camera } = useThree();

  // mountedAtRef tracks when this component mounted so we can snap the camera
  // quickly into chase position during the first 0.8s (fast convergence window)
  const mountedAtRef = useRef<number | null>(null);

  useFrame((_state, delta) => {
    if (!shipRef.current) return;

    const ship = shipRef.current;
    const now = performance.now();

    // Record mount time on the first frame
    if (mountedAtRef.current === null) {
      mountedAtRef.current = now;
    }

    // Clamp delta to avoid huge jumps on tab focus restore
    const safeDelta = Math.min(delta, 1 / 20);

    // --- Check docking state for camera mode ----------------------------
    const { dockingState } = useObservatoryStore.getState();
    const isDocked = dockingState.zone === "dock" && dockingState.stationId != null;

    if (isDocked) {
      // DCK-03: Docked camera — lerp to a front-facing station view
      const dockStationPos = stationPosition(dockingState.stationId!);
      _dockPos.copy(dockStationPos);

      // Offset the camera: station position + dockedCameraOffset
      const [ox, oy, oz] = DOCKING_CONFIG.dockedCameraOffset;
      _dockCamOffset.set(
        _dockPos.x + ox,
        _dockPos.y + oy,
        _dockPos.z + oz,
      );

      // Smooth transition over cameraTransitionDurationMs (~1s)
      const dockAlpha = 1 - Math.exp(-3.0 * safeDelta); // ~1s convergence
      camera.position.lerp(_dockCamOffset, dockAlpha);
      camera.lookAt(_dockPos);
      camera.updateMatrixWorld();
      return;
    }

    // --- Chase camera (normal flight) -----------------------------------
    // During the first 0.8s after mount, use a much higher factor to snap
    // the camera into chase position quickly rather than drifting in slowly
    const elapsedSinceMount = (now - mountedAtRef.current) / 1000;
    const effectiveFollowFactor =
      elapsedSinceMount < 0.8 ? 2.0 : followFactor;

    // --- Desired camera position ------------------------------------------
    // Rotate the local-space offset by the ship's world quaternion to get the
    // world-space vector pointing behind+above the ship
    _offset.set(offset[0], offset[1], offset[2]);
    _offset.applyQuaternion(ship.quaternion);
    _desiredPos.copy(ship.position).add(_offset);

    // --- Look-at target ---------------------------------------------------
    // Ship forward is -Z in Three.js convention
    _shipForward.set(0, 0, -1).applyQuaternion(ship.quaternion);
    _lookTarget.copy(ship.position).addScaledVector(_shipForward, lookAheadDistance);

    // --- Frame-rate independent exponential lerp --------------------------
    const alpha = 1 - Math.exp(-effectiveFollowFactor * 60 * safeDelta);
    camera.position.lerp(_desiredPos, alpha);

    // --- Orient camera toward look target --------------------------------
    camera.lookAt(_lookTarget);
    camera.updateMatrixWorld();
  });

  // This component only mutates the camera — no DOM output
  return null;
}
