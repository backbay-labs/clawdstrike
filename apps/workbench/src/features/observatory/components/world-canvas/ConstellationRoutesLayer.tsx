/**
 * ConstellationRoutesLayer.tsx — Phase 41 CNST-01 through CNST-05
 *
 * Renders completed mission routes as luminous CatmullRom curves elevated into
 * the star layer (y = 40–60), building a visible investigation history over time.
 *
 * Each constellation is a soft white line with 30% spirit accent tint, with
 * depth-write disabled and toneMapped off for bloom glow.
 */

import { useMemo } from "react";
import { Line } from "@react-three/drei";
import * as THREE from "three";
import type { ConstellationRoute } from "../../types";
import type { HuntStationId } from "../../world/types";
import { OBSERVATORY_STATION_POSITIONS } from "../../world/observatory-world-template";

// ---------------------------------------------------------------------------
// Constants (per CONTEXT.md locked decisions)
// ---------------------------------------------------------------------------

const CONSTELLATION_Y_BASE = 40;
const CONSTELLATION_Y_RANGE = 20;
const CONSTELLATION_CURVE_TENSION = 0.4;
const CONSTELLATION_SAMPLE_POINTS = 64;
const CONSTELLATION_MAX_COUNT = 12;

// Base color: soft white with slight lavender cast
const CONSTELLATION_BASE_COLOR = "#e8e4f0";

// ---------------------------------------------------------------------------
// Props
// ---------------------------------------------------------------------------

interface ConstellationRoutesLayerProps {
  constellations: ConstellationRoute[];
  spiritAccentColor?: string | null;
}

// ---------------------------------------------------------------------------
// Component
// ---------------------------------------------------------------------------

export function ConstellationRoutesLayer({
  constellations,
  spiritAccentColor,
}: ConstellationRoutesLayerProps) {
  // Respect the 12-constellation cap (display only up to CONSTELLATION_MAX_COUNT)
  const visibleConstellations = constellations.slice(0, CONSTELLATION_MAX_COUNT);

  const constellationKey = visibleConstellations.map((c) => c.id).join(",");

  const lineData = useMemo(() => {
    return visibleConstellations.map((route) => {
      const { stationPath } = route;

      // Build control points: map each station to its XZ world position,
      // elevate Y gradually from CONSTELLATION_Y_BASE to Y_BASE + Y_RANGE
      // to create a gentle arc through the star layer.
      const points = stationPath.map((stationId: HuntStationId, index: number) => {
        const pos = OBSERVATORY_STATION_POSITIONS[stationId];
        const y =
          CONSTELLATION_Y_BASE +
          (index / Math.max(stationPath.length - 1, 1)) * CONSTELLATION_Y_RANGE;
        return new THREE.Vector3(pos[0], y, pos[2]);
      });

      // Need at least 2 points to form a curve; skip degenerate constellations
      if (points.length < 2) {
        return null;
      }

      const curve = new THREE.CatmullRomCurve3(points, false, "catmullrom", CONSTELLATION_CURVE_TENSION);
      const sampledPoints = curve.getPoints(CONSTELLATION_SAMPLE_POINTS);

      // Compute line color: soft white blended with 30% spirit accent tint
      let lineColor: string | THREE.Color;
      if (spiritAccentColor) {
        const base = new THREE.Color(CONSTELLATION_BASE_COLOR);
        const accent = new THREE.Color(spiritAccentColor);
        lineColor = base.lerp(accent, 0.3);
      } else {
        lineColor = CONSTELLATION_BASE_COLOR;
      }

      return { id: route.id, points: sampledPoints, color: lineColor };
    }).filter((entry): entry is NonNullable<typeof entry> => entry !== null);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [constellationKey, spiritAccentColor]);

  if (lineData.length === 0) {
    return null;
  }

  return (
    <group name="constellation-routes">
      {lineData.map((entry) => (
        <Line
          key={entry.id}
          points={entry.points}
          color={entry.color}
          lineWidth={1.5}
          transparent
          opacity={0.65}
          depthWrite={false}
          toneMapped={false}
        />
      ))}
    </group>
  );
}
