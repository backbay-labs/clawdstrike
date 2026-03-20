/**
 * StationDockingRing.tsx — STN-05 / DCK-01
 *
 * Docking ring torus + 4 guide point lights at cardinal positions.
 * - Torus rotates at 0.3 rad/s (visual landing approach guide).
 * - Guide lights pulse when ship is within 50 units (dockProximityRadius).
 * - Uses MeshBasicMaterial + toneMapped=false so bloom picks it up without scene lights.
 * - Station position read once from OBSERVATORY_STATION_POSITIONS at render time.
 * - flightState read inside useFrame via getState() — zero subscriptions, zero re-renders.
 */

import { useRef, type ReactElement } from "react";
import { useFrame } from "@react-three/fiber";
import * as THREE from "three";
import { useObservatoryStore } from "../stores/observatory-store";
import { OBSERVATORY_STATION_POSITIONS } from "./observatory-world-template";
import type { HuntStationId } from "./types";

// Module-level scratch vector — avoids GC churn in the hot useFrame path.
const _scratchPos = new THREE.Vector3();
const _stationPos = new THREE.Vector3();

// Cardinal positions on the docking ring (XZ plane, radius 6)
const GUIDE_OFFSETS: [number, number, number][] = [
  [6, 0, 0],
  [-6, 0, 0],
  [0, 0, 6],
  [0, 0, -6],
];

export interface StationDockingRingProps {
  colorHex: string;
  stationId: HuntStationId;
}

/**
 * Docking ring component — mounts as a child of StationLodWrapper near-tier.
 * The parent group already provides the station world-space position.
 */
export function StationDockingRing({
  colorHex,
  stationId,
}: StationDockingRingProps): ReactElement {
  const ringRef = useRef<THREE.Mesh>(null);
  const lightRefs = useRef<(THREE.PointLight | null)[]>([null, null, null, null]);

  // Pre-read station world position once (static — positions never change).
  const stationWorldPos = OBSERVATORY_STATION_POSITIONS[stationId];

  useFrame(({ clock }, delta) => {
    // --- Rotation ---
    if (ringRef.current) {
      ringRef.current.rotation.z += delta * 0.3;
    }

    // --- Proximity pulse ---
    // Read flight state imperatively — no subscription, no re-render.
    const { flightState } = useObservatoryStore.getState();
    _scratchPos.set(flightState.position[0], flightState.position[1], flightState.position[2]);
    _stationPos.set(stationWorldPos[0], stationWorldPos[1], stationWorldPos[2]);
    const dist = _scratchPos.distanceTo(_stationPos);

    const near = dist < 50;
    const pulsedIntensity = near
      ? 1.5 + Math.sin(clock.elapsedTime * 3) * 1.0
      : 0.3;

    for (const light of lightRefs.current) {
      if (light) {
        light.intensity = pulsedIntensity;
      }
    }
  });

  return (
    <group>
      {/* Docking ring — lies in XZ plane via rotation */}
      <mesh ref={ringRef} rotation={[Math.PI / 2, 0, 0]}>
        <torusGeometry args={[6, 0.15, 16, 48]} />
        <meshBasicMaterial
          color={colorHex}
          toneMapped={false}
          transparent
          opacity={0.8}
        />
      </mesh>

      {/* 4 guide point lights at cardinal positions */}
      {GUIDE_OFFSETS.map((offset, i) => (
        <pointLight
          key={`guide:${i}`}
          ref={(el) => {
            lightRefs.current[i] = el;
          }}
          position={offset}
          color={colorHex}
          intensity={0.3}
          distance={8}
        />
      ))}
    </group>
  );
}
