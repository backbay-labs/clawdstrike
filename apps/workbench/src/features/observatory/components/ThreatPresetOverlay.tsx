/** ThreatPresetOverlay.tsx — Phase 37, Plan 01 (APR-01) */

import { useRef, type ReactElement } from "react";
import { useFrame } from "@react-three/fiber";
import * as THREE from "three";
import type { ObservatoryDistrictRecipe } from "../world/deriveObservatoryWorld";
import { OBSERVATORY_STATION_POSITIONS } from "../world/observatory-world-template";

// ──────────────────────────────────────────────────────────────────────────────
// Pure helper (exported for unit tests)
// ──────────────────────────────────────────────────────────────────────────────

/**
 * Returns districts where active === true OR artifactCount >= 3.
 * These are the stations that receive the red threat wash + orbital motes.
 */
export function getThreatDistricts(
  districts: ObservatoryDistrictRecipe[],
): ObservatoryDistrictRecipe[] {
  return districts.filter((d) => d.active || d.artifactCount >= 3);
}

// ──────────────────────────────────────────────────────────────────────────────
// Constants
// ──────────────────────────────────────────────────────────────────────────────

const MOTE_COUNT = 5;
const MOTE_ORBIT_RADIUS = 5.5; // midpoint 4–7
const MOTE_ORBIT_Y = 1.5;
const MOTE_ANGULAR_SPEED = 0.7;

// ──────────────────────────────────────────────────────────────────────────────
// Sub-component: ThreatDistrictOverlay
// ──────────────────────────────────────────────────────────────────────────────

interface ThreatDistrictOverlayProps {
  position: [number, number, number];
  stationPhaseOffset: number;
}

function ThreatDistrictOverlay({ position, stationPhaseOffset }: ThreatDistrictOverlayProps): ReactElement {
  // One ref slot per mote group
  const moteRefs = useRef<(THREE.Group | null)[]>(
    Array.from({ length: MOTE_COUNT }, () => null),
  );

  useFrame(({ clock }) => {
    const t = clock.elapsedTime;
    for (let index = 0; index < MOTE_COUNT; index++) {
      const group = moteRefs.current[index];
      if (!group) continue;
      const phase = (index / MOTE_COUNT) * Math.PI * 2 + stationPhaseOffset;
      group.position.x = position[0] + Math.cos(t * MOTE_ANGULAR_SPEED + phase) * MOTE_ORBIT_RADIUS;
      group.position.z = position[2] + Math.sin(t * MOTE_ANGULAR_SPEED + phase) * MOTE_ORBIT_RADIUS;
    }
  });

  return (
    <>
      {/* Flat red wash disc — placed at ground plane y=0 */}
      <mesh position={[position[0], 0, position[2]]}>
        <circleGeometry args={[8, 32]} />
        <meshBasicMaterial
          color="#ff2222"
          transparent
          toneMapped={false}
          depthWrite={false}
          blending={THREE.AdditiveBlending}
          opacity={0.18}
          side={THREE.DoubleSide}
        />
      </mesh>

      {/* 5 orbital danger mote spheres */}
      {Array.from({ length: MOTE_COUNT }, (_, index) => {
        const initPhase = (index / MOTE_COUNT) * Math.PI * 2 + stationPhaseOffset;
        return (
          <group
            key={index}
            ref={(node) => {
              moteRefs.current[index] = node;
            }}
            position={[
              position[0] + Math.cos(initPhase) * MOTE_ORBIT_RADIUS,
              MOTE_ORBIT_Y,
              position[2] + Math.sin(initPhase) * MOTE_ORBIT_RADIUS,
            ]}
          >
            <mesh>
              <sphereGeometry args={[0.22, 8, 6]} />
              <meshBasicMaterial
                color="#ff4444"
                transparent
                toneMapped={false}
                depthWrite={false}
                blending={THREE.AdditiveBlending}
                opacity={0.55}
              />
            </mesh>
          </group>
        );
      })}
    </>
  );
}

// ──────────────────────────────────────────────────────────────────────────────
// Main export: ThreatPresetOverlay
// ──────────────────────────────────────────────────────────────────────────────

export interface ThreatPresetOverlayProps {
  districts: ObservatoryDistrictRecipe[];
}

/**
 * Renders a red additive wash disc + 5 orbital mote spheres at every
 * active or high-pressure district position (APR-01).
 * Returns null when no threat districts exist.
 */
export function ThreatPresetOverlay({ districts }: ThreatPresetOverlayProps): ReactElement | null {
  const threatDistricts = getThreatDistricts(districts);
  if (threatDistricts.length === 0) return null;

  return (
    <>
      {threatDistricts.map((district) => {
        const pos = OBSERVATORY_STATION_POSITIONS[district.id] ?? district.position;
        // Phase offset derived from station position for staggered animations
        const stationPhaseOffset = (pos[0] * 17 + pos[2] * 31) % (Math.PI * 2);
        return (
          <ThreatDistrictOverlay
            key={district.id}
            position={[pos[0], pos[1], pos[2]]}
            stationPhaseOffset={stationPhaseOffset}
          />
        );
      })}
    </>
  );
}
