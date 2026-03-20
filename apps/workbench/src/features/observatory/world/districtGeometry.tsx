/**
 * districtGeometry.tsx — STN-01
 *
 * Composable floating space station from Three.js primitives:
 * - Torus habitat ring (always present, radius 2-4 units)
 * - Cylinder hub (always present, height 1-3 units)
 * - Solar panel pairs (2-6 PlaneGeometry, angled outward, emissive blue)
 * - Docking bay arm (0-1 per station, BoxGeometry, seed-driven)
 * - Antenna array (1-3 thin CylinderGeometry with ConeGeometry dish tips)
 *
 * Total target: <5K triangles per station at near LOD.
 * Uses mulberry32 PRNG for deterministic variation per seed.
 */

import { useRef, useMemo, type ReactElement } from "react";
import { useFrame } from "@react-three/fiber";
import * as THREE from "three";
import { mulberry32, createSpaceStationSeed } from "./districtGeometryResources";

export { createSpaceStationSeed };

// ---------------------------------------------------------------------------
// Layout types + pure layout computation (testable without React)
// ---------------------------------------------------------------------------

export interface SpaceStationLayout {
  ringRadius: number;
  ringTube: number;
  hubRadius: number;
  hubHeight: number;
  panelCount: number;
  hasDockingBay: boolean;
  antennaCount: number;
}

export function createSpaceStationLayout(seed: number): SpaceStationLayout {
  const rng = mulberry32(seed);
  return {
    ringRadius: 2 + rng() * 2,
    ringTube: 0.15 + rng() * 0.1,
    hubRadius: 0.6 + rng() * 0.4,
    hubHeight: 1 + rng() * 2,
    panelCount: 2 + Math.floor(rng() * 5),
    hasDockingBay: rng() > 0.4,
    antennaCount: 1 + Math.floor(rng() * 3),
  };
}

// ---------------------------------------------------------------------------
// SpaceStationMesh component
// ---------------------------------------------------------------------------

export interface SpaceStationMeshProps {
  position: [number, number, number];
  colorHex: string;
  seed: number;
  floatAmplitude?: number;
  pulseSpeed?: number;
}

/**
 * Renders a composable floating space station using Three.js primitives.
 * Each station's geometry is driven by a seeded PRNG for deterministic variation.
 */
export function SpaceStationMesh({
  position,
  colorHex,
  seed,
  floatAmplitude = 0.12,
  pulseSpeed = 0.0018,
}: SpaceStationMeshProps): ReactElement {
  const ringGroupRef = useRef<THREE.Group>(null);
  const layout = useMemo(() => createSpaceStationLayout(seed), [seed]);

  // Slow rotation on the outer ring only
  useFrame((_state, delta) => {
    if (ringGroupRef.current) {
      ringGroupRef.current.rotation.y += delta * pulseSpeed * 0.5;
    }
  });

  // Derive per-panel transforms from a fresh PRNG (same seed, skip to panels)
  const panelTransforms = useMemo(() => {
    const rng = mulberry32(seed);
    // Consume same calls as createSpaceStationLayout to skip to the panel phase
    rng(); // ringRadius
    rng(); // ringTube
    rng(); // hubRadius
    rng(); // hubHeight
    rng(); // panelCount base
    rng(); // hasDockingBay
    rng(); // antennaCount

    const transforms: { angleDeg: number; tiltDeg: number }[] = [];
    for (let i = 0; i < layout.panelCount; i++) {
      transforms.push({
        angleDeg: (i / layout.panelCount) * 360,
        tiltDeg: 20 + rng() * 20,
      });
    }
    return transforms;
  }, [seed, layout.panelCount]);

  // Docking bay angle
  const dockingAngle = useMemo(() => {
    const rng = mulberry32(seed + 77);
    return rng() * Math.PI * 2;
  }, [seed]);

  // Antenna transforms
  const antennaTransforms = useMemo(() => {
    const rng = mulberry32(seed + 99);
    const transforms: { angle: number; height: number }[] = [];
    for (let i = 0; i < layout.antennaCount; i++) {
      transforms.push({
        angle: (i / layout.antennaCount) * Math.PI * 2 + rng() * 0.4,
        height: 1.5 + rng(),
      });
    }
    return transforms;
  }, [seed, layout.antennaCount]);

  const { ringRadius, ringTube, hubRadius, hubHeight, hasDockingBay } = layout;

  return (
    <group position={position}>
      {/* a) Habitat Ring — slow rotation */}
      <group ref={ringGroupRef}>
        <mesh rotation={[Math.PI / 2, 0, 0]}>
          <torusGeometry args={[ringRadius, ringTube, 24, 48]} />
          <meshStandardMaterial
            color={colorHex}
            emissive={colorHex}
            emissiveIntensity={0.3}
            metalness={0.6}
            roughness={0.35}
            toneMapped={false}
          />
        </mesh>
      </group>

      {/* b) Central Hub */}
      <mesh position={[0, hubHeight / 2, 0]}>
        <cylinderGeometry args={[hubRadius, hubRadius * 1.1, hubHeight, 16]} />
        <meshStandardMaterial color="#1a2030" metalness={0.5} roughness={0.6} />
      </mesh>

      {/* c) Solar Panels */}
      {panelTransforms.map((panel, i) => {
        const angleRad = (panel.angleDeg * Math.PI) / 180;
        const tiltRad = (panel.tiltDeg * Math.PI) / 180;
        const px = Math.cos(angleRad) * (ringRadius + 0.8);
        const pz = Math.sin(angleRad) * (ringRadius + 0.8);
        return (
          <mesh
            key={`panel:${i}`}
            position={[px, 0, pz]}
            rotation={[tiltRad, angleRad, 0]}
          >
            <planeGeometry args={[1.2, 0.4]} />
            <meshStandardMaterial
              color="#1a3050"
              emissive="#4488cc"
              emissiveIntensity={0.5}
              metalness={0.3}
              roughness={0.4}
              side={THREE.DoubleSide}
              toneMapped={false}
            />
          </mesh>
        );
      })}

      {/* d) Docking Bay Arm (~60% of stations) */}
      {hasDockingBay && (
        <mesh
          position={[
            Math.cos(dockingAngle) * (hubRadius + 1.2),
            hubHeight * 0.5,
            Math.sin(dockingAngle) * (hubRadius + 1.2),
          ]}
          rotation={[0, dockingAngle, 0]}
        >
          <boxGeometry args={[0.5, 0.4, 2]} />
          <meshStandardMaterial color="#1e2535" metalness={0.4} roughness={0.7} />
        </mesh>
      )}

      {/* e) Antenna Array */}
      {antennaTransforms.map((antenna, i) => {
        const ax = Math.cos(antenna.angle) * (hubRadius * 0.6);
        const az = Math.sin(antenna.angle) * (hubRadius * 0.6);
        const topY = hubHeight + antenna.height;
        return (
          <group key={`antenna:${i}`} position={[ax, 0, az]}>
            {/* Antenna shaft */}
            <mesh position={[0, hubHeight + antenna.height / 2, 0]}>
              <cylinderGeometry args={[0.03, 0.03, antenna.height, 6]} />
              <meshStandardMaterial
                color={colorHex}
                emissive={colorHex}
                emissiveIntensity={0.8}
                toneMapped={false}
              />
            </mesh>
            {/* Dish tip */}
            <mesh position={[0, topY, 0]}>
              <coneGeometry args={[0.12, 0.2, 8]} />
              <meshStandardMaterial
                color={colorHex}
                emissive={colorHex}
                emissiveIntensity={0.8}
                toneMapped={false}
              />
            </mesh>
          </group>
        );
      })}
    </group>
  );
}
