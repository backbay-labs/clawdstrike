/**
 * WarpSpeedLines — TRN-02
 *
 * 40 instanced thin cylinder streaks radiating from the camera forward vector
 * during boost activation. Each streak:
 *   - Starts at a random position in a cone 2-4 units ahead of the camera
 *   - Has random azimuthal angle and polar offset (0.1–0.3 rad from center)
 *   - Renders as a thin CylinderGeometry (radius 0.025, height 3–6 units)
 *   - MeshBasicMaterial with toneMapped={false} so they are picked up by bloom
 *   - When !active, all instance scales set to 0 (existing instances fade out)
 *
 * Positioning is updated every frame in useFrame, attached to camera world position.
 * No setState — only ref mutation and InstancedMesh matrix updates.
 */

import { useRef } from "react";
import { useFrame } from "@react-three/fiber";
import * as THREE from "three";

/** Number of instanced speed-line streaks */
const LINE_COUNT = 40;

/** Geometry constants */
const LINE_RADIUS = 0.025;
const LINE_HEIGHT_MIN = 3;
const LINE_HEIGHT_MAX = 6;

/** Cone distribution: 0.1–0.3 radians off camera forward */
const CONE_POLAR_MIN = 0.1;
const CONE_POLAR_MAX = 0.3;

/** Offset ahead of camera: 2–4 units along forward */
const DEPTH_MIN = 2;
const DEPTH_MAX = 4;

// Pre-allocated scratch objects — avoids GC in hot useFrame path
const _cameraPos = new THREE.Vector3();
const _cameraForward = new THREE.Vector3();
const _cameraRight = new THREE.Vector3();
const _cameraUp = new THREE.Vector3();
const _linePos = new THREE.Vector3();
const _lineDir = new THREE.Vector3();
const _quat = new THREE.Quaternion();
const _alignQuat = new THREE.Quaternion();
const _scale = new THREE.Vector3();
const _matrix = new THREE.Matrix4();
const _yAxis = new THREE.Vector3(0, 1, 0);

/** Simple seeded pseudo-random using mulberry32-like pattern (per-instance stable) */
function seededRandom(seed: number): number {
  let s = seed ^ 0x1234_5678;
  s = ((s >>> 16) ^ s) * 0x45d9f3b;
  s = ((s >>> 16) ^ s) * 0x45d9f3b;
  s = (s >>> 16) ^ s;
  // Map to [0, 1)
  return (s >>> 0) / 0xffff_ffff;
}

export interface WarpSpeedLinesProps {
  /** TRN-02: true when flightState.speedTier === "boost" */
  active: boolean;
}

export function WarpSpeedLines({ active }: WarpSpeedLinesProps) {
  const meshRef = useRef<THREE.InstancedMesh | null>(null);
  const prevActiveRef = useRef(false);

  useFrame(({ camera }) => {
    const mesh = meshRef.current;
    if (!mesh) return;

    if (!active) {
      if (prevActiveRef.current) {
        // Boost just ended: zero out all scales to hide streaks
        _scale.set(0, 0, 0);
        for (let i = 0; i < LINE_COUNT; i++) {
          mesh.getMatrixAt(i, _matrix);
          const pos = new THREE.Vector3();
          pos.setFromMatrixPosition(_matrix);
          _matrix.compose(pos, _quat, _scale);
          mesh.setMatrixAt(i, _matrix);
        }
        mesh.instanceMatrix.needsUpdate = true;
      }
      prevActiveRef.current = false;
      return;
    }

    prevActiveRef.current = true;

    // Extract camera basis vectors
    _cameraPos.setFromMatrixPosition(camera.matrixWorld);
    _cameraForward.set(0, 0, -1).applyQuaternion(camera.quaternion).normalize();
    _cameraRight.set(1, 0, 0).applyQuaternion(camera.quaternion).normalize();
    _cameraUp.set(0, 1, 0).applyQuaternion(camera.quaternion).normalize();

    for (let i = 0; i < LINE_COUNT; i++) {
      // Stable per-instance random values derived from index
      const r0 = seededRandom(i * 7 + 1);
      const r1 = seededRandom(i * 7 + 2);
      const r2 = seededRandom(i * 7 + 3);
      const r3 = seededRandom(i * 7 + 4);

      // Random polar angle from camera forward (0.1–0.3 rad)
      const polar = CONE_POLAR_MIN + r0 * (CONE_POLAR_MAX - CONE_POLAR_MIN);
      // Random azimuthal angle (0–2*PI)
      const azimuth = r1 * Math.PI * 2;
      // Random depth ahead (2–4 units)
      const depth = DEPTH_MIN + r2 * (DEPTH_MAX - DEPTH_MIN);
      // Random height (3–6 units)
      const height = LINE_HEIGHT_MIN + r3 * (LINE_HEIGHT_MAX - LINE_HEIGHT_MIN);

      // Convert spherical to Cartesian in camera space
      const sinPolar = Math.sin(polar);
      const offsetRight = sinPolar * Math.cos(azimuth);
      const offsetUp = sinPolar * Math.sin(azimuth);
      const offsetFwd = Math.cos(polar);

      // World position of streak center
      _linePos
        .copy(_cameraPos)
        .addScaledVector(_cameraForward, depth + offsetFwd * 2)
        .addScaledVector(_cameraRight, offsetRight * 3)
        .addScaledVector(_cameraUp, offsetUp * 3);

      // Streak direction: predominantly along camera forward with slight polar offset
      _lineDir
        .copy(_cameraForward)
        .addScaledVector(_cameraRight, offsetRight * 0.3)
        .addScaledVector(_cameraUp, offsetUp * 0.3)
        .normalize();

      // Align cylinder (default axis = Y) to the streak direction
      _alignQuat.setFromUnitVectors(_yAxis, _lineDir);
      _scale.set(1, height, 1);
      _matrix.compose(_linePos, _alignQuat, _scale);
      mesh.setMatrixAt(i, _matrix);
    }

    mesh.instanceMatrix.needsUpdate = true;
  });

  return (
    <instancedMesh
      ref={meshRef}
      args={[undefined, undefined, LINE_COUNT]}
      frustumCulled={false}
    >
      <cylinderGeometry args={[LINE_RADIUS, LINE_RADIUS, 1, 4, 1]} />
      {/* toneMapped=false ensures bloom picks up these streaks even at MeshBasicMaterial */}
      <meshBasicMaterial color="#b8d4ff" toneMapped={false} transparent opacity={0.7} />
    </instancedMesh>
  );
}
