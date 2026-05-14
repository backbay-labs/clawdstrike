/**
 * MissionObjectiveBeacons.tsx — Phase 36 MSN-01 MSN-02 MSN-03 MSN-04
 *
 * Renders vertical emissive beacon columns at mission objective stations.
 * Active objective pulses (~2s cycle). Completed objectives show static
 * muted desaturated glow. Returns null when no mission is active.
 *
 * Geometry: CylinderGeometry 180 units tall, tapered (top=0.8, base=2.0).
 * Material: MeshStandardMaterial pure emissive + AdditiveBlending for
 * fog-piercing visibility at 500+ units (MSN-01).
 */
import { useRef, useMemo } from "react";
import { useFrame } from "@react-three/fiber";
import * as THREE from "three";
import { OBSERVATORY_STATION_POSITIONS } from "../world/observatory-world-template";
import { STATION_COLORS_HEX } from "./hud/hud-constants";
import type { ObservatoryMissionLoopState } from "../world/missionLoop";
import type { HuntStationId } from "../world/types";

// ---------------------------------------------------------------------------
// Pure helper functions (exported for unit tests)
// ---------------------------------------------------------------------------

/**
 * Returns true when beacon columns should be rendered.
 * MSN-04: returns false when mission is null.
 * Returns true even for completed missions (static desaturated glow).
 */
export function shouldShowBeacons(mission: ObservatoryMissionLoopState | null): boolean {
  if (mission === null) return false;
  return mission.objectives.length > 0;
}

export interface BeaconStation {
  stationId: HuntStationId;
  isActive: boolean;
  isCompleted: boolean;
}

/**
 * Derives the beacon set from mission.objectives and mission.completedObjectiveIds.
 * The "active" station is the first non-completed objective's stationId.
 * Only returns stations that appear in mission.objectives.
 */
export function getBeaconStations(mission: ObservatoryMissionLoopState): BeaconStation[] {
  const completedSet = new Set(mission.completedObjectiveIds);

  // Find the first non-completed objective's stationId
  const firstActive = mission.objectives.find((o) => !completedSet.has(o.id));
  const activeStationId = firstActive?.stationId ?? null;

  return mission.objectives.map((obj) => {
    const isCompleted = completedSet.has(obj.id);
    const isActive = !isCompleted && obj.stationId === activeStationId;
    return {
      stationId: obj.stationId,
      isActive,
      isCompleted,
    };
  });
}

// ---------------------------------------------------------------------------
// Component props
// ---------------------------------------------------------------------------

export interface MissionObjectiveBeaconsProps {
  mission: ObservatoryMissionLoopState | null;
}

// ---------------------------------------------------------------------------
// Internal SingleBeacon component
// ---------------------------------------------------------------------------

interface SingleBeaconProps {
  stationId: HuntStationId;
  isActive: boolean;
  isCompleted: boolean;
}

function SingleBeacon({ stationId, isActive, isCompleted }: SingleBeaconProps) {
  const pos = OBSERVATORY_STATION_POSITIONS[stationId];
  const accentHex = STATION_COLORS_HEX[stationId];

  // Pre-compute colors — no allocations in useFrame
  const colorHex = useMemo(() => {
    if (isCompleted) {
      return "#" + new THREE.Color(accentHex).offsetHSL(0, -0.7, 0).getHexString();
    }
    return accentHex;
  }, [accentHex, isCompleted]);

  const materialRef = useRef<THREE.MeshStandardMaterial>(null);

  useFrame(({ clock }) => {
    if (!isActive) return;
    const mat = materialRef.current;
    if (!mat) return;
    // Animate emissiveIntensity: range 1.2–2.8, ~2s cycle via π multiplier
    mat.emissiveIntensity = 2.0 + Math.sin(clock.elapsedTime * Math.PI) * 0.8;
  });

  // Position group so the base of the 180-unit column sits at station Y
  const groupY = pos[1] + 90;

  const staticIntensity = isActive ? 2.5 : 0.8;

  return (
    <group position={[pos[0], groupY, pos[2]]}>
      <mesh>
        {/* 180 units tall, tapered: narrow top (0.8), wider base (2.0), 8 radial segments */}
        <cylinderGeometry args={[0.8, 2.0, 180, 8]} />
        <meshStandardMaterial
          ref={materialRef}
          color="#000000"
          emissive={colorHex}
          emissiveIntensity={staticIntensity}
          transparent
          opacity={isCompleted ? 0.25 : 1.0}
          depthWrite={false}
          toneMapped={false}
          blending={THREE.AdditiveBlending}
        />
      </mesh>
      <pointLight
        color={colorHex}
        intensity={isActive ? 4 : 1}
        distance={200}
        decay={2}
      />
    </group>
  );
}

// ---------------------------------------------------------------------------
// MissionObjectiveBeacons — main export
// ---------------------------------------------------------------------------

/**
 * Renders one emissive vertical column per objective station.
 * Active objective pulses (~2s sin cycle). Completed objectives show
 * static desaturated glow. Returns null when mission is null (MSN-04).
 */
export function MissionObjectiveBeacons({ mission }: MissionObjectiveBeaconsProps) {
  if (!shouldShowBeacons(mission)) return null;

  const stations = getBeaconStations(mission!);

  return (
    <>
      {stations.map((s) => (
        <SingleBeacon
          key={s.stationId}
          stationId={s.stationId}
          isActive={s.isActive}
          isCompleted={s.isCompleted}
        />
      ))}
    </>
  );
}
