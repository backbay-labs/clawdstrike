import { useMemo } from "react";
import { Line } from "@react-three/drei";
import * as THREE from "three";
import type { ConstellationRoute } from "../../types";
import type { HuntStationId } from "../../world/types";
import { OBSERVATORY_STATION_POSITIONS } from "../../world/observatory-world-template";

const Y_BASE = 40;
const Y_RANGE = 20;
const CURVE_TENSION = 0.4;
const SAMPLE_POINTS = 64;
const MAX_COUNT = 12;
const BASE_COLOR = "#e8e4f0";

interface ConstellationRoutesLayerProps {
  constellations: ConstellationRoute[];
  spiritAccentColor?: string | null;
}

export function ConstellationRoutesLayer({
  constellations,
  spiritAccentColor,
}: ConstellationRoutesLayerProps) {
  const visible = constellations.slice(0, MAX_COUNT);

  const cacheKey = useMemo(
    () => visible.map((c) => c.id).join(","),
    [visible],
  );

  const lineData = useMemo(() => {
    return visible.map((route) => {
      const points = route.stationPath.map((stationId: HuntStationId, i: number) => {
        const pos = OBSERVATORY_STATION_POSITIONS[stationId];
        const y = Y_BASE + (i / Math.max(route.stationPath.length - 1, 1)) * Y_RANGE;
        return new THREE.Vector3(pos[0], y, pos[2]);
      });

      if (points.length < 2) return null;

      const curve = new THREE.CatmullRomCurve3(points, false, "catmullrom", CURVE_TENSION);
      const sampledPoints = curve.getPoints(SAMPLE_POINTS);

      let color: string | THREE.Color = BASE_COLOR;
      if (spiritAccentColor) {
        color = new THREE.Color(BASE_COLOR).lerp(new THREE.Color(spiritAccentColor), 0.3);
      }

      return { id: route.id, points: sampledPoints, color };
    }).filter((entry): entry is NonNullable<typeof entry> => entry !== null);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [cacheKey, spiritAccentColor]);

  if (lineData.length === 0) return null;

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
