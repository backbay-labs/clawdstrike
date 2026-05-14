// NPC crew module — instanced capsule figures (4 per station, 6 stations = 24 total)
// Patrol loops + proximity wave reaction. No React state in useFrame.
// NPC-01/02/03

import { Instance, Instances } from "@react-three/drei";
import { useFrame } from "@react-three/fiber";
import { useMemo, useRef } from "react";
import * as THREE from "three";
import type { ObservatoryLodTier } from "../utils/observatory-performance";
import type { ObservatoryVec3 } from "./deriveObservatoryWorld";

const PROXIMITY_THRESHOLD = 5.0;
const PATROL_SPEED = 0.5;
const WAYPOINT_ARRIVAL_DIST = 0.15;

// 4 NPCs per station. Each has 4 patrol waypoints as local [x, z] offsets from station center.
export const STATION_NPC_PATROL_DATA: Array<{
  spawnOffset: [number, number];
  waypointOffsets: [[number, number], [number, number], [number, number], [number, number]];
}> = [
  { spawnOffset: [1.2, 0.6],   waypointOffsets: [[1.2, 0.6],   [1.8, 1.1],   [2.0, 0.2],   [1.4, -0.4]] },
  { spawnOffset: [-1.1, 0.8],  waypointOffsets: [[-1.1, 0.8],  [-1.8, 1.4],  [-2.0, 0.4],  [-1.3, -0.2]] },
  { spawnOffset: [0.5, -1.4],  waypointOffsets: [[0.5, -1.4],  [1.1, -1.9],  [0.2, -2.1],  [-0.5, -1.5]] },
  { spawnOffset: [-0.7, -1.2], waypointOffsets: [[-0.7, -1.2], [-1.4, -1.8], [-1.8, -0.8], [-1.0, -0.4]] },
];

interface NpcInstanceProps {
  waypointOffsets: [[number, number], [number, number], [number, number], [number, number]];
  stationWorldPos: ObservatoryVec3;
  color: string;
  lodTier: ObservatoryLodTier;
}

export interface ObservatoryNpcCrewMotionMode {
  canLookAt: boolean;
  canWave: boolean;
  patrolEnabled: boolean;
  coarseStepSeconds: number | null;
}

export function resolveObservatoryNpcCrewMotionMode(
  lodTier: ObservatoryLodTier,
): ObservatoryNpcCrewMotionMode {
  switch (lodTier) {
    case "focus":
      return {
        canLookAt: true,
        canWave: true,
        coarseStepSeconds: null,
        patrolEnabled: true,
      };
    case "near":
      return {
        canLookAt: false,
        canWave: false,
        coarseStepSeconds: null,
        patrolEnabled: true,
      };
    case "far":
      return {
        canLookAt: false,
        canWave: false,
        coarseStepSeconds: 0.4,
        patrolEnabled: true,
      };
    case "dormant":
    default:
      return {
        canLookAt: false,
        canWave: false,
        coarseStepSeconds: null,
        patrolEnabled: false,
      };
  }
}

function NpcInstance({ waypointOffsets, stationWorldPos, color: _color, lodTier }: NpcInstanceProps) {
  const groupRef = useRef<THREE.Object3D | null>(null);
  const motionMode = useMemo(() => resolveObservatoryNpcCrewMotionMode(lodTier), [lodTier]);

  // World-space patrol waypoints (Y = station elevation, NPC floats at station level)
  const waypoints = useMemo(
    () =>
      waypointOffsets.map(
        ([ox, oz]) => new THREE.Vector3(stationWorldPos[0] + ox, stationWorldPos[1], stationWorldPos[2] + oz),
      ),
    // eslint-disable-next-line react-hooks/exhaustive-deps
    [stationWorldPos[0], stationWorldPos[1], stationWorldPos[2], waypointOffsets],
  );

  const posRef = useRef(waypoints[0].clone());
  const waypointIdxRef = useRef(0);
  const wavingRef = useRef(false);
  const waveTimerRef = useRef(0);
  const armOffsetRef = useRef(0);
  const coarseAccumulatorRef = useRef(0);

  useFrame(({ camera }, delta) => {
    const obj = groupRef.current;
    if (!obj) return;

    if (!motionMode.patrolEnabled) {
      obj.position.copy(posRef.current);
      return;
    }

    const dist = posRef.current.distanceTo(camera.position);
    if (motionMode.coarseStepSeconds !== null) {
      coarseAccumulatorRef.current += delta;
      if (coarseAccumulatorRef.current < motionMode.coarseStepSeconds) {
        obj.position.copy(posRef.current);
        return;
      }
      coarseAccumulatorRef.current = 0;
    }

    // --- Patrol lerp ---
    const target = waypoints[waypointIdxRef.current];
    if (posRef.current.distanceTo(target) < WAYPOINT_ARRIVAL_DIST) {
      waypointIdxRef.current = (waypointIdxRef.current + 1) % waypoints.length;
    } else {
      posRef.current.lerp(target, PATROL_SPEED * delta);
    }

    // --- Proximity check ---
    if (motionMode.canWave && dist < PROXIMITY_THRESHOLD) {
      wavingRef.current = true;
      waveTimerRef.current += delta;
    } else {
      wavingRef.current = false;
      waveTimerRef.current = 0;
    }

    // --- Arm wave offset (stored in ref; visual effect on scale.y) ---
    armOffsetRef.current = wavingRef.current
      ? Math.sin(waveTimerRef.current * 4) * 0.15
      : 0;

    // --- Apply world position ---
    obj.position.copy(posRef.current);

    // --- Look-at player when waving ---
    if (motionMode.canLookAt && wavingRef.current) {
      obj.lookAt(camera.position.x, posRef.current.y, camera.position.z);
    }
  });

  const spawnX = stationWorldPos[0] + waypointOffsets[0][0];
  const spawnZ = stationWorldPos[2] + waypointOffsets[0][1];

  return (
    <Instance
      ref={groupRef}
      position={[spawnX, stationWorldPos[1], spawnZ]}
    />
  );
}

export interface StationNpcCrewProps {
  stationWorldPos: ObservatoryVec3;
  colorHex: string;
  lodTier?: ObservatoryLodTier;
  /** TRN-05: Proximity-based opacity (0-1). NPCs fade in between 120-180 units. */
  proximityOpacity?: number;
}

export function StationNpcCrew({ stationWorldPos, colorHex, lodTier = "near", proximityOpacity = 1 }: StationNpcCrewProps) {
  const transparent = proximityOpacity < 1;
  return (
    <Instances limit={8} visible={proximityOpacity > 0}>
      <capsuleGeometry args={[0.12, 0.35, 4, 8]} />
      <meshStandardMaterial
        color={colorHex}
        roughness={0.7}
        transparent={transparent}
        opacity={proximityOpacity}
      />
      {STATION_NPC_PATROL_DATA.map((npc, i) => (
        <NpcInstance
          key={i}
          waypointOffsets={npc.waypointOffsets}
          stationWorldPos={stationWorldPos}
          color={colorHex}
          lodTier={lodTier}
        />
      ))}
    </Instances>
  );
}
