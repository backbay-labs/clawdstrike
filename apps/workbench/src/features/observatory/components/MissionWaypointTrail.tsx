/**
 * MissionWaypointTrail.tsx — Phase 26 DSC-03
 *
 * Glowing CatmullRom tube trail from the ship's current position to the active
 * mission objective station. Only visible when a mission is in-progress and the
 * character controller (flight mode) is active.
 *
 * Visual: emissive green #44ff88 with AdditiveBlending — distinct from the cyan-blue
 * #4488ff space lanes. Opacity fades to 0 within 60 units of the target station
 * (docking system takes over navigation at that range).
 *
 * Performance: geometry is rebuilt only when the ship moves more than 2 units since
 * the last rebuild, throttled to once per N frames.
 */

import { useRef, useEffect } from "react";
import { useFrame } from "@react-three/fiber";
import * as THREE from "three";
import { useObservatoryStore } from "../stores/observatory-store";
import { OBSERVATORY_STATION_POSITIONS } from "../world/observatory-world-template";
import {
  getCurrentObservatoryMissionObjective,
  type ObservatoryMissionLoopState,
} from "../world/missionLoop";

// ---------------------------------------------------------------------------
// Visibility gate — pure function, exported for unit-testing
// ---------------------------------------------------------------------------

export function shouldShowWaypointTrail(
  mission: ObservatoryMissionLoopState | null,
  characterControllerEnabled: boolean,
): boolean {
  if (!characterControllerEnabled) return false;
  if (!mission) return false;
  if (mission.status !== "in-progress") return false;
  const objective = getCurrentObservatoryMissionObjective(mission);
  return objective !== null;
}

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const TRAIL_COLOR = new THREE.Color("#44ff88");
const TUBE_RADIUS = 0.2;
const TUBE_SEGMENTS = 64;
const TUBE_RADIAL_SEGMENTS = 6;

// Distance threshold for geometry rebuild (units²)
const REBUILD_DISTANCE_SQ = 4; // 2 units

// Fade zone: trail fades to 0 opacity as ship enters within 60 units of target
const FADE_INNER = 10;
const FADE_OUTER = 60;
const FULL_OPACITY = 0.6;

// Module-level pre-allocated vectors (zero GC in hot path)
const _shipVec = new THREE.Vector3();
const _midVec = new THREE.Vector3();
const _targetVec = new THREE.Vector3();

// ---------------------------------------------------------------------------
// Props
// ---------------------------------------------------------------------------

export interface MissionWaypointTrailProps {
  mission: ObservatoryMissionLoopState | null;
  characterControllerEnabled: boolean;
}

// ---------------------------------------------------------------------------
// Component
// ---------------------------------------------------------------------------

export function MissionWaypointTrail({
  mission,
  characterControllerEnabled,
}: MissionWaypointTrailProps) {
  const meshRef = useRef<THREE.Mesh | null>(null);
  const materialRef = useRef<THREE.MeshBasicMaterial | null>(null);
  const lastShipPosRef = useRef<THREE.Vector3>(new THREE.Vector3(Infinity, Infinity, Infinity));
  const geometryRef = useRef<THREE.TubeGeometry | null>(null);

  // Cleanup geometry on unmount
  useEffect(() => {
    return () => {
      geometryRef.current?.dispose();
      geometryRef.current = null;
    };
  }, []);

  useFrame(() => {
    if (!shouldShowWaypointTrail(mission, characterControllerEnabled)) {
      if (meshRef.current) meshRef.current.visible = false;
      return;
    }

    const objective = getCurrentObservatoryMissionObjective(mission!);
    if (!objective) {
      if (meshRef.current) meshRef.current.visible = false;
      return;
    }

    const targetPos = OBSERVATORY_STATION_POSITIONS[objective.stationId];
    if (!targetPos) {
      if (meshRef.current) meshRef.current.visible = false;
      return;
    }

    const flightState = useObservatoryStore.getState().flightState;
    const pos = flightState.position;
    _shipVec.set(pos[0], pos[1], pos[2]);
    _targetVec.set(targetPos[0], targetPos[1], targetPos[2]);

    const distanceToTarget = _shipVec.distanceTo(_targetVec);

    // Compute opacity based on distance to target
    let opacity: number;
    if (distanceToTarget > FADE_OUTER) {
      opacity = FULL_OPACITY;
    } else {
      opacity = Math.max(0, Math.min(FULL_OPACITY, ((distanceToTarget - FADE_INNER) / (FADE_OUTER - FADE_INNER)) * FULL_OPACITY));
    }

    if (materialRef.current) {
      materialRef.current.opacity = opacity;
    }

    if (meshRef.current) {
      meshRef.current.visible = opacity > 0.001;
    }

    // Rebuild geometry only when ship has moved more than 2 units
    const movedSq = _shipVec.distanceToSquared(lastShipPosRef.current);
    if (movedSq < REBUILD_DISTANCE_SQ && geometryRef.current) return;

    // Update last rebuild position
    lastShipPosRef.current.copy(_shipVec);

    // Dispose previous geometry
    if (geometryRef.current) {
      geometryRef.current.dispose();
      geometryRef.current = null;
    }

    // Build 3-point CatmullRom arc: ship -> midpoint (Y+10 lift) -> target
    _midVec.set(
      (_shipVec.x + _targetVec.x) / 2,
      (_shipVec.y + _targetVec.y) / 2 + 10,
      (_shipVec.z + _targetVec.z) / 2,
    );

    const curve = new THREE.CatmullRomCurve3([
      _shipVec.clone(),
      _midVec.clone(),
      _targetVec.clone(),
    ]);

    const geometry = new THREE.TubeGeometry(
      curve,
      TUBE_SEGMENTS,
      TUBE_RADIUS,
      TUBE_RADIAL_SEGMENTS,
      false,
    );

    geometryRef.current = geometry;

    if (meshRef.current) {
      meshRef.current.geometry = geometry;
    }
  });

  return (
    <mesh ref={meshRef} name="mission-waypoint-trail">
      <meshBasicMaterial
        ref={materialRef}
        color={TRAIL_COLOR}
        toneMapped={false}
        transparent
        opacity={FULL_OPACITY}
        blending={THREE.AdditiveBlending}
        depthWrite={false}
      />
    </mesh>
  );
}
