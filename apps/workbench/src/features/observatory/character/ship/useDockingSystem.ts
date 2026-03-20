/**
 * useDockingSystem.ts — Phase 23 DCK-02/03/04
 *
 * useFrame-driven three-zone docking lifecycle:
 *   approach (50-180 u) → magnet pull (15-50 u) → dock lock (<15 u at <12 u/s)
 *
 * Design:
 *   - All hot-path vectors pre-allocated at module level (zero GC inside useFrame)
 *   - Velocity bias is additive — player can still thrust away from magnet zone
 *   - Dock lock lerps ship to dock point over 0.8s using easeOutCubic; disables input
 *   - Undock (E key) pushes ship 20 units away at 15 u/s, re-enables flight after 0.5s grace
 *   - Store updates throttled to ~100ms (same pattern as useFlightLoop)
 */

import { useRef, useCallback } from "react";
import { useFrame } from "@react-three/fiber";
import * as THREE from "three";
import { OBSERVATORY_STATION_POSITIONS } from "../../world/observatory-world-template";
import { HUNT_STATION_ORDER } from "../../world/stations";
import type { HuntStationId } from "../../world/types";
import type { FlightIntent } from "./flight-types";
import {
  DOCKING_CONFIG,
  DEFAULT_DOCKING_STATE,
  type DockingState,
  type DockingZone,
} from "./docking-types";
import { getObservatoryNowMs } from "../../utils/observatory-time";

// ---------------------------------------------------------------------------
// Module-level scratch objects — never re-allocated inside useFrame
// ---------------------------------------------------------------------------

const _dockPoint = new THREE.Vector3();
const _shipToDock = new THREE.Vector3();
const _pushDir = new THREE.Vector3();
const _stationPos = new THREE.Vector3();
const _pullDir = new THREE.Vector3();

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export interface UseDockingSystemOptions {
  /** Ref to the ship Group — position read/written each frame */
  shipRef: React.RefObject<THREE.Group | null>;
  /** Ref to the current flight intent (for interactTriggered / E key) */
  intentRef: React.RefObject<FlightIntent>;
  /**
   * Ref to the velocity vector inside useFlightLoop.
   * Magnet-pull bias is added directly to this vector each frame — additive, not overriding.
   */
  velocityRef: React.RefObject<THREE.Vector3>;
  /** Callback to disable/enable flight physics input processing */
  setFlightInputEnabled: (enabled: boolean) => void;
  /** Throttled callback (~100ms) to push docking state to store */
  onDockingStateChange?: (state: DockingState) => void;
}

// ---------------------------------------------------------------------------
// Internal easing
// ---------------------------------------------------------------------------

/** easeOutCubic: fast start, gentle landing into dock point */
function easeOutCubic(t: number): number {
  return 1 - (1 - t) ** 3;
}

// ---------------------------------------------------------------------------
// Hook
// ---------------------------------------------------------------------------

export function useDockingSystem({
  shipRef,
  intentRef,
  velocityRef,
  setFlightInputEnabled,
  onDockingStateChange,
}: UseDockingSystemOptions): void {
  // Current docking state (ref — no React re-renders from this hook)
  const dockingRef = useRef<DockingState>({ ...DEFAULT_DOCKING_STATE });

  // Dock lock lerp progress helpers
  const dockLockStartPosRef = useRef<THREE.Vector3>(new THREE.Vector3());
  const dockLockTargetPosRef = useRef<THREE.Vector3>(new THREE.Vector3());

  // Undock grace period start timestamp
  const undockGraceStartMsRef = useRef<number | null>(null);

  // Snapshot throttle: push to store every ~100ms
  const lastSnapshotMsRef = useRef<number>(0);

  // Whether flight input was disabled by this hook (so we only re-enable what we disabled)
  const flightInputDisabledByDockingRef = useRef(false);

  // setFlightInputEnabled is a stable callback — store in ref to avoid stale closure
  const setFlightInputEnabledRef = useRef(setFlightInputEnabled);
  setFlightInputEnabledRef.current = setFlightInputEnabled;

  // -------------------------------------------------------------------------
  // Nearest-station scan (over HUNT_STATION_ORDER — matches useFlightLoop)
  // -------------------------------------------------------------------------

  const findNearestInRadius = useCallback(
    (
      shipPosition: THREE.Vector3,
      radius: number,
    ): { stationId: HuntStationId; distance: number } | null => {
      let nearest: { stationId: HuntStationId; distance: number } | null = null;
      for (const stationId of HUNT_STATION_ORDER) {
        const pos = OBSERVATORY_STATION_POSITIONS[stationId];
        _stationPos.set(pos[0], pos[1], pos[2]);
        const dist = shipPosition.distanceTo(_stationPos);
        if (dist <= radius && (nearest === null || dist < nearest.distance)) {
          nearest = { stationId, distance: dist };
        }
      }
      return nearest;
    },
    [],
  );

  useFrame((_, delta) => {
    const ship = shipRef.current;
    if (!ship) return;

    const intent = intentRef.current;
    if (!intent) return;

    const vel = velocityRef.current;
    if (!vel) return;

    const dt = Math.min(delta, 1 / 20);
    const nowMs = getObservatoryNowMs();
    const docking = dockingRef.current;

    // -----------------------------------------------------------------------
    // 1. Undock grace period expiry check
    // -----------------------------------------------------------------------
    if (docking.undockGracePeriodActive && undockGraceStartMsRef.current !== null) {
      const elapsed = nowMs - undockGraceStartMsRef.current;
      if (elapsed >= DOCKING_CONFIG.undockGracePeriodMs) {
        docking.undockGracePeriodActive = false;
        undockGraceStartMsRef.current = null;
      }
    }

    // -----------------------------------------------------------------------
    // 2. Docked state — hold position, listen for undock (E key)
    // -----------------------------------------------------------------------
    if (docking.zone === "dock" && docking.dockLockStartMs === null) {
      // Snap ship to dock target to prevent drift
      ship.position.copy(dockLockTargetPosRef.current);
      // Zero velocity while docked
      vel.set(0, 0, 0);

      // Check for undock trigger (interactTriggered = E key)
      if (intent.interactTriggered) {
        // Consume the intent flag
        intent.interactTriggered = false;

        // Push direction = away from station center
        const stPos = docking.stationId
          ? OBSERVATORY_STATION_POSITIONS[docking.stationId]
          : null;
        if (stPos) {
          _pushDir
            .set(
              ship.position.x - stPos[0],
              ship.position.y - stPos[1],
              ship.position.z - stPos[2],
            )
            .normalize();
        } else {
          // Fallback: push forward
          _pushDir.set(0, 0, -1).applyQuaternion(ship.quaternion);
        }

        // Small immediate separation to break out of dock point snap
        ship.position.addScaledVector(_pushDir, 2);

        // Set push velocity
        vel.copy(_pushDir).multiplyScalar(DOCKING_CONFIG.undockPushVelocity);

        // Re-enable flight input
        if (flightInputDisabledByDockingRef.current) {
          setFlightInputEnabledRef.current(true);
          flightInputDisabledByDockingRef.current = false;
        }

        // Enter undock grace period
        docking.zone = null;
        docking.stationId = null;
        docking.dockLockStartMs = null;
        docking.undockGracePeriodActive = true;
        undockGraceStartMsRef.current = nowMs;
      }

      // Throttled store push
      if (onDockingStateChange && nowMs - lastSnapshotMsRef.current >= 100) {
        lastSnapshotMsRef.current = nowMs;
        onDockingStateChange({ ...docking });
      }
      return;
    }

    // -----------------------------------------------------------------------
    // 3. Dock lock sequence in progress (lerp ship to dock point)
    // -----------------------------------------------------------------------
    if (docking.dockLockStartMs !== null) {
      const elapsed = nowMs - docking.dockLockStartMs;
      const progress = Math.min(1, elapsed / DOCKING_CONFIG.dockLockDurationMs);
      const easedProgress = easeOutCubic(progress);

      // Lerp position from start toward dock target
      ship.position.lerpVectors(
        dockLockStartPosRef.current,
        dockLockTargetPosRef.current,
        easedProgress,
      );

      // Zero velocity — docking system owns the ship during lock
      vel.set(0, 0, 0);

      if (progress >= 1) {
        // Snap to exact dock point and transition to full docked state
        ship.position.copy(dockLockTargetPosRef.current);
        docking.zone = "dock";
        docking.dockLockStartMs = null;
      }

      // Throttled store push
      if (onDockingStateChange && nowMs - lastSnapshotMsRef.current >= 100) {
        lastSnapshotMsRef.current = nowMs;
        onDockingStateChange({ ...docking });
      }
      return;
    }

    // -----------------------------------------------------------------------
    // 4. Free flight — zone detection, magnet-pull, dock-lock trigger
    // -----------------------------------------------------------------------

    // Scan for nearest station in approach range
    const nearestInApproach = findNearestInRadius(
      ship.position,
      DOCKING_CONFIG.approachRadius,
    );

    if (!nearestInApproach) {
      // No station nearby — clear zone
      if (docking.zone !== null || docking.stationId !== null) {
        docking.zone = null;
        docking.stationId = null;
      }
    } else {
      const { stationId, distance } = nearestInApproach;
      const stPos = OBSERVATORY_STATION_POSITIONS[stationId];
      _dockPoint.set(stPos[0], stPos[1], stPos[2]);

      const inMagnetZone = distance <= DOCKING_CONFIG.magnetRadius;
      const inDockLockZone = distance <= DOCKING_CONFIG.dockLockRadius;

      if (inDockLockZone && !docking.undockGracePeriodActive) {
        // Dock-lock trigger: check speed threshold
        const currentSpeed = vel.length();
        if (currentSpeed <= DOCKING_CONFIG.dockLockMaxSpeed) {
          // Begin dock lock sequence
          dockLockStartPosRef.current.copy(ship.position);
          dockLockTargetPosRef.current.copy(_dockPoint);

          docking.stationId = stationId;
          docking.zone = "dock"; // Will briefly show "dock" zone during lock sequence
          docking.dockLockStartMs = nowMs;

          // Disable flight input during dock lock
          if (!flightInputDisabledByDockingRef.current) {
            setFlightInputEnabledRef.current(false);
            flightInputDisabledByDockingRef.current = true;
          }
        } else {
          // Too fast — still in magnet zone behavior
          docking.zone = "magnet";
          docking.stationId = stationId;
        }
      } else if (inMagnetZone) {
        // Magnet zone — bias velocity toward dock point
        docking.zone = "magnet";
        docking.stationId = stationId;

        // Pull direction: normalize(dockPoint - ship.position)
        _shipToDock.subVectors(_dockPoint, ship.position);
        const distForPull = _shipToDock.length();
        if (distForPull > 0.001) {
          _pullDir.copy(_shipToDock).normalize();

          // Pull strength: 0 at 50 units, 0.3 at 15 units (linear)
          const pullStrength = THREE.MathUtils.mapLinear(
            distance,
            DOCKING_CONFIG.magnetRadius,
            DOCKING_CONFIG.dockLockRadius,
            0,
            DOCKING_CONFIG.magnetPullMaxStrength,
          );

          // Additive velocity bias — player can still thrust away
          vel.addScaledVector(_pullDir, pullStrength * 60 * dt);
        }
      } else {
        // Approach zone only (50-180 units)
        docking.zone = "approach";
        docking.stationId = stationId;
      }
    }

    // Throttled store push
    if (onDockingStateChange && nowMs - lastSnapshotMsRef.current >= 100) {
      lastSnapshotMsRef.current = nowMs;
      onDockingStateChange({ ...docking });
    }
  });
}
