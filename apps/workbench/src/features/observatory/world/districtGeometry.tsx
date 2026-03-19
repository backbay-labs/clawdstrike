/**
 * districtGeometry.ts
 *
 * Pure geometry components for the observatory world — no store imports, no state.
 * Provides seeded procedural buildings, per-zone ground planes, and env props
 * (crates + cable runs) per station district.
 *
 * Requirements: WLD-01, WLD-02, WLD-03, WLD-04
 */

import { CatmullRomLine, RoundedBox, useTexture } from "@react-three/drei";
import { type ReactElement, Suspense, useMemo } from "react";
import * as THREE from "three";

// ---------------------------------------------------------------------------
// mulberry32 — inline seeded PRNG, no external dependency
// ---------------------------------------------------------------------------

export function mulberry32(seed: number): () => number {
  let s = seed;
  return () => {
    s |= 0;
    s = (s + 0x6d2b79f5) | 0;
    let t = Math.imul(s ^ (s >>> 15), 1 | s);
    t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

// ---------------------------------------------------------------------------
// StationBuilding — WLD-02
// ---------------------------------------------------------------------------

interface StationBuildingProps {
  seed: number;
  position: [number, number, number];
}

/**
 * Renders 4-6 seeded procedural RoundedBox buildings clustered around the
 * station's world position. The layout is deterministic: same seed = same layout.
 */
export function StationBuilding({ seed, position }: StationBuildingProps): ReactElement {
  const buildings = useMemo(() => {
    const rng = mulberry32(Math.abs(Math.floor(seed)) || 1);
    const count = Math.floor(rng() * 3) + 4; // 4-6 buildings
    const result: Array<{
      x: number;
      z: number;
      width: number;
      height: number;
      antennaColor: string;
    }> = [];

    for (let i = 0; i < count; i++) {
      const angle = (i / count) * Math.PI * 2 + seed * 0.01;
      const radius = 1.4 + rng() * 0.8; // 1.4-2.2 from center
      const x = Math.cos(angle) * radius;
      const z = Math.sin(angle) * radius;

      // Skip if too close to hero prop zone (radius < 0.8)
      if (Math.sqrt(x * x + z * z) < 0.8) continue;

      const width = 0.35 + rng() * 0.5; // 0.35-0.85 wide
      const height = 0.8 + rng() * 2.8; // 0.8-3.6 tall

      // Antenna color cycles through blue-green accent hues for variety
      const hue = Math.floor(rng() * 360);
      const antennaColor = `hsl(${hue}, 80%, 65%)`;

      result.push({ x, z, width, height, antennaColor });
    }

    return result;
  }, [seed]);

  return (
    <group position={position}>
      {buildings.map((b, i) => (
        <group key={i} position={[b.x, 0, b.z]}>
          {/* Main building block */}
          <RoundedBox
            args={[b.width, b.height, b.width]}
            radius={0.04}
            smoothness={2}
            position={[0, b.height / 2, 0]}
          >
            <meshStandardMaterial
              color="#1a1f2e"
              emissive="#0a0e1a"
              roughness={0.8}
              metalness={0.2}
            />
          </RoundedBox>
          {/* Antenna / tower accent — picks up bloom via toneMapped=false */}
          <mesh position={[0, b.height + 0.3, 0]}>
            <cylinderGeometry args={[0.02, 0.02, 0.5, 6]} />
            <meshStandardMaterial
              color={b.antennaColor}
              emissive={b.antennaColor}
              emissiveIntensity={0.5}
              toneMapped={false}
            />
          </mesh>
        </group>
      ))}
    </group>
  );
}

// ---------------------------------------------------------------------------
// DistrictGround — WLD-03
// ---------------------------------------------------------------------------

interface DistrictGroundProps {
  position: [number, number, number];
  colorHex: string;
}

function DistrictGroundInner({ position, colorHex }: DistrictGroundProps): ReactElement {
  const texture = useTexture("/textures/grid-floor.png", (t) => {
    t.wrapS = THREE.RepeatWrapping;
    t.wrapT = THREE.RepeatWrapping;
    t.repeat.set(6, 6);
  });

  return (
    <mesh
      rotation={[-Math.PI / 2, 0, 0]}
      position={[position[0], position[1] - 0.05, position[2]]}
    >
      <planeGeometry args={[10, 10, 1, 1]} />
      <meshStandardMaterial
        map={texture}
        color={colorHex}
        roughness={0.92}
        emissive={colorHex}
        emissiveIntensity={0.04}
      />
    </mesh>
  );
}

/**
 * Per-zone tinted ground plane beneath each station.
 * Wrapped in Suspense so a missing texture does not block scene render.
 */
export function DistrictGround(props: DistrictGroundProps): ReactElement {
  return (
    <Suspense fallback={null}>
      <DistrictGroundInner {...props} />
    </Suspense>
  );
}

// ---------------------------------------------------------------------------
// DistrictEnvProps — WLD-04
// ---------------------------------------------------------------------------

interface DistrictEnvPropsProps {
  position: [number, number, number];
  colorHex: string;
  seed: number;
}

/**
 * Small environmental storytelling props per station:
 * 2 crate boxes + 1 glowing cable run.
 */
export function DistrictEnvProps({ position, colorHex, seed }: DistrictEnvPropsProps): ReactElement {
  const props = useMemo(() => {
    const rng = mulberry32(Math.abs(Math.floor(seed)) || 7);

    // Two crates offset from station center at ~1.0 unit away
    const crate1Offset: [number, number, number] = [
      0.8 + rng() * 0.4 - 0.2,
      0.11,
      0.8 + rng() * 0.4 - 0.2,
    ];
    const crate2Offset: [number, number, number] = [
      -(0.7 + rng() * 0.3),
      0.11,
      0.9 + rng() * 0.3 - 0.15,
    ];

    // CatmullRomLine points weaving between crate cluster at Y=0
    const cablePoints: [number, number, number][] = [
      [crate1Offset[0] - 0.15, 0.05, crate1Offset[2]],
      [0, 0.15, 0.5 + rng() * 0.3],
      [crate2Offset[0] + 0.15, 0.05, crate2Offset[2]],
    ];

    return { crate1Offset, crate2Offset, cablePoints };
  }, [seed]);

  const [px, py, pz] = position;

  return (
    <group position={[px, py, pz]}>
      {/* Crate 1 */}
      <mesh position={props.crate1Offset}>
        <boxGeometry args={[0.22, 0.22, 0.22]} />
        <meshStandardMaterial
          color="#1e2535"
          emissive={colorHex}
          emissiveIntensity={0.06}
          roughness={0.85}
        />
      </mesh>
      {/* Crate 2 — slightly smaller */}
      <mesh position={props.crate2Offset} scale={[0.85, 0.85, 0.85]}>
        <boxGeometry args={[0.22, 0.22, 0.22]} />
        <meshStandardMaterial
          color="#1a2030"
          emissive={colorHex}
          emissiveIntensity={0.06}
          roughness={0.85}
        />
      </mesh>
      {/* Cable run — glowing line weaving between crates */}
      <CatmullRomLine
        points={props.cablePoints}
        color={colorHex}
        lineWidth={0.8}
        transparent
        opacity={0.5}
      />
    </group>
  );
}
