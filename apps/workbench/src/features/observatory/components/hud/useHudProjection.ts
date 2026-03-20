/**
 * useHudProjection.ts — Phase 24 HUD-03, HUD-04, HUD-05
 *
 * Per-frame projection of station world positions to screen coordinates.
 * Reads camera matrices from hudCameraRef (written by HudCameraBridge inside the Canvas)
 * and writes results into a stable RefObject — zero allocations per frame, zero React state.
 *
 * Usage:
 *   const { projectionsRef } = useHudProjection(containerRef);
 *   // Pass projectionsRef to TargetBrackets and OffScreenArrows
 *
 * Performance contract:
 *   - Pre-allocated module-level scratch objects — no `new` in the rAF callback.
 *   - Reads store via getState() — no subscriptions, no re-renders.
 *   - Cancels rAF on unmount.
 */

import { useEffect, useRef, type RefObject } from "react";
import * as THREE from "three";
import { hudCameraRef } from "./camera-bridge";
import { STATION_COLORS_HEX } from "./hud-constants";
import { useObservatoryStore } from "../../stores/observatory-store";
import { getCurrentObservatoryMissionObjective } from "../../world/missionLoop";
import { OBSERVATORY_STATION_POSITIONS } from "../../world/observatory-world-template";
import { HUNT_STATION_ORDER, HUNT_STATION_LABELS } from "../../world/stations";
import type { HuntStationId } from "../../world/types";

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

export interface HudStationProjection {
  stationId: HuntStationId;
  label: string;
  colorHex: string;
  /** Screen-space X in pixels (0 = left edge) */
  screenX: number;
  /** Screen-space Y in pixels (0 = top edge) */
  screenY: number;
  /** World-space distance from ship in units */
  distance: number;
  /** True when the station is behind the camera or outside frustum */
  isOffScreen: boolean;
  /** Edge-clamped X for off-screen arrow placement */
  edgeX: number;
  /** Edge-clamped Y for off-screen arrow placement */
  edgeY: number;
  /** Rotation in radians for off-screen arrow pointing toward station */
  arrowRotation: number;
  /** Distance fade opacity: 0 at 500+ units, 1.0 at 100 units */
  distanceOpacity: number;
  /** Bracket size in px: clamp(800 / distance, 24, 80) */
  bracketSize: number;
  /** Whether this station is the selected/mission target */
  isSelected: boolean;
  /** Whether the ship is docked at this station */
  isDocked: boolean;
}

// ---------------------------------------------------------------------------
// Module-level scratch objects — allocated once, reused every frame
// ---------------------------------------------------------------------------

const _projVec = new THREE.Vector3();
const _viewProjectionMatrix = new THREE.Matrix4();

/** How many frames between rect re-reads (resize detection) */
const RECT_REFRESH_INTERVAL = 60;

// ---------------------------------------------------------------------------
// Hook
// ---------------------------------------------------------------------------

/**
 * useHudProjection — drives a single rAF loop that projects all 6 station
 * positions to screen-space each frame and writes results into projectionsRef.
 *
 * @param containerRef - Ref to the HUD overlay container div (for width/height).
 * @returns projectionsRef — a stable ref holding HudStationProjection[] with 6 entries.
 */
export function useHudProjection(
  containerRef: RefObject<HTMLDivElement | null>,
): { projectionsRef: RefObject<HudStationProjection[]> } {
  const projectionsRef = useRef<HudStationProjection[]>(
    // Pre-populate with placeholder entries (one per station)
    HUNT_STATION_ORDER.map((stationId) => ({
      stationId,
      label: HUNT_STATION_LABELS[stationId],
      colorHex: STATION_COLORS_HEX[stationId],
      screenX: 0,
      screenY: 0,
      distance: 0,
      isOffScreen: true,
      edgeX: 0,
      edgeY: 0,
      arrowRotation: 0,
      distanceOpacity: 0,
      bracketSize: 48,
      isSelected: false,
      isDocked: false,
    })),
  );

  useEffect(() => {
    let rafId = 0;
    let cachedWidth = 0;
    let cachedHeight = 0;
    let cachedCenterX = 0;
    let cachedCenterY = 0;
    let frameCount = 0;

    function loop() {
      rafId = requestAnimationFrame(loop);
      frameCount += 1;

      // Refresh container rect on mount and every RECT_REFRESH_INTERVAL frames
      if (frameCount === 1 || frameCount % RECT_REFRESH_INTERVAL === 0) {
        const rect = containerRef.current?.getBoundingClientRect();
        if (rect) {
          cachedWidth = rect.width;
          cachedHeight = rect.height;
          cachedCenterX = cachedWidth / 2;
          cachedCenterY = cachedHeight / 2;
        }
      }

      const width = cachedWidth;
      const height = cachedHeight;

      // No dimensions yet — skip frame
      if (width === 0 || height === 0) {
        return;
      }

      // Build view-projection matrix from camera bridge (no allocations — reuses _viewProjectionMatrix)
      const cam = hudCameraRef.current;
      _viewProjectionMatrix.copy(cam.projectionMatrix).multiply(cam.matrixWorldInverse);

      // Read store once via getState (zero subscriptions)
      const state = useObservatoryStore.getState();
      const { flightState, dockingState, mission, selectedStationId } = state;
      const shipPos = flightState.position;

      const missionObj = getCurrentObservatoryMissionObjective(mission);
      const missionTargetStationId = missionObj?.stationId ?? null;

      const projections = projectionsRef.current;
      const edgeMargin = 40;

      for (let i = 0; i < HUNT_STATION_ORDER.length; i += 1) {
        const stationId = HUNT_STATION_ORDER[i];
        const stationPos = OBSERVATORY_STATION_POSITIONS[stationId];
        const projection = projections[i];

        // Project station world position through view-projection matrix
        _projVec.set(stationPos[0], stationPos[1], stationPos[2]);
        _projVec.applyMatrix4(_viewProjectionMatrix);

        const isBehind = _projVec.z > 1;

        // NDC to screen pixels
        let screenX = ((_projVec.x + 1) / 2) * width;
        let screenY = ((1 - _projVec.y) / 2) * height;

        // If behind camera, flip coords around center so arrow still points in right direction
        if (isBehind) {
          screenX = width - screenX;
          screenY = height - screenY;
        }

        const isOffScreen =
          isBehind
          || screenX < 0
          || screenX > width
          || screenY < 0
          || screenY > height;

        // Edge-clamp with margin for arrow placement
        const edgeX = Math.max(edgeMargin, Math.min(width - edgeMargin, screenX));
        const edgeY = Math.max(edgeMargin, Math.min(height - edgeMargin, screenY));

        // Arrow rotation: angle from screen center toward station (before clamping)
        const centeredX = screenX - cachedCenterX;
        const centeredY = screenY - cachedCenterY;
        const arrowRotation = Math.atan2(centeredY, centeredX);

        // Distance from ship to station in world units
        const dx = stationPos[0] - shipPos[0];
        const dy = stationPos[1] - shipPos[1];
        const dz = stationPos[2] - shipPos[2];
        const distance = Math.hypot(dx, dy, dz);

        // Opacity: 0 at 500+ units, 1.0 at 100 units
        const distanceOpacity = Math.max(0, Math.min(1, (500 - distance) / 400));

        // Bracket size: inversely proportional to distance, clamped
        const bracketSize = Math.max(24, Math.min(80, 800 / Math.max(1, distance)));

        const isSelected =
          stationId === selectedStationId || stationId === missionTargetStationId;
        const isDocked =
          dockingState.zone === "dock" && dockingState.stationId === stationId;

        // Mutate in-place — no allocations
        projection.screenX = screenX;
        projection.screenY = screenY;
        projection.distance = distance;
        projection.isOffScreen = isOffScreen;
        projection.edgeX = edgeX;
        projection.edgeY = edgeY;
        projection.arrowRotation = arrowRotation;
        projection.distanceOpacity = distanceOpacity;
        projection.bracketSize = bracketSize;
        projection.isSelected = isSelected;
        projection.isDocked = isDocked;
      }
    }

    rafId = requestAnimationFrame(loop);

    return () => {
      cancelAnimationFrame(rafId);
    };
  }, [containerRef]);

  return { projectionsRef };
}
