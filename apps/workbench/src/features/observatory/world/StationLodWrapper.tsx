/**
 * StationLodWrapper.tsx — STN-02
 *
 * Four-tier LOD system for space stations using drei's Detailed component.
 *
 * LOD tiers (distance thresholds):
 *   0  – 60  units  : Full SpaceStationMesh + Fresnel rim glow halo
 *   60 – 180 units  : Simplified hub + ring geometry (~500 tris)
 *   180 – 500 units : Billboard text label with station name
 *   500+    units   : Pulsing beacon sprite + point light
 */

import { type ReactElement } from "react";
import { Detailed, Billboard, Text } from "@react-three/drei";
import { SpaceStationMesh, type SpaceStationMeshProps } from "./districtGeometry";
import { StationBeacon } from "./StationBeacon";
import { StationFresnelGlow } from "./StationFresnelGlow";

export interface StationLodWrapperProps extends SpaceStationMeshProps {
  stationLabel: string;
}

/** LOD distance thresholds: near / mid / far / beacon */
const LOD_DISTANCES: [number, number, number, number] = [0, 60, 180, 500];

/**
 * Wraps a space station in a 4-tier LOD system.
 * Uses a local coordinate group so children use [0,0,0] for their own position.
 */
export function StationLodWrapper({
  position,
  colorHex,
  seed,
  floatAmplitude = 0.12,
  pulseSpeed = 0.0018,
  stationLabel,
}: StationLodWrapperProps): ReactElement {
  const stationProps: SpaceStationMeshProps = {
    position: [0, 0, 0],
    colorHex,
    seed,
    floatAmplitude,
    pulseSpeed,
  };

  return (
    <group position={position}>
      {/* drei Detailed switches between children based on camera distance */}
      <Detailed distances={LOD_DISTANCES}>
        {/* Tier 0 (near, 0–60 units): full geometry + Fresnel glow */}
        <group>
          <SpaceStationMesh {...stationProps} />
          <StationFresnelGlow colorHex={colorHex} radius={5} />
        </group>

        {/* Tier 1 (mid, 60–180 units): simplified hub + ring only */}
        <group>
          <mesh rotation={[Math.PI / 2, 0, 0]}>
            <torusGeometry args={[3, 0.2, 12, 32]} />
            <meshStandardMaterial
              color={colorHex}
              emissive={colorHex}
              emissiveIntensity={0.3}
              toneMapped={false}
              metalness={0.6}
              roughness={0.35}
            />
          </mesh>
          <mesh position={[0, 1, 0]}>
            <cylinderGeometry args={[0.7, 0.8, 2, 12]} />
            <meshStandardMaterial color="#1a2030" metalness={0.5} roughness={0.6} />
          </mesh>
        </group>

        {/* Tier 2 (far, 180–500 units): billboard label */}
        <group>
          <Billboard follow lockX={false} lockY={false} lockZ={false}>
            <Text
              fontSize={3}
              color={colorHex}
              anchorY="middle"
              outlineWidth={0.15}
              outlineColor="#000000"
            >
              {stationLabel}
            </Text>
          </Billboard>
        </group>

        {/* Tier 3 (beacon, 500+ units): sprite + point light */}
        <StationBeacon position={[0, 0, 0]} colorHex={colorHex} />
      </Detailed>
    </group>
  );
}
