/**
 * ShipMesh.tsx — Phase 21 FLT-01
 *
 * Geometric low-poly ship built from Three.js primitives, ~3 units long.
 * Matches station geometry style (procedural primitives, no GLB).
 *
 * Structure:
 *  - Hull body: ConeGeometry (forward-pointing, ~3 units long)
 *  - Cockpit canopy: SphereGeometry (blue emissive)
 *  - Wing struts: 2x BoxGeometry (swept back, spirit-tinted emissive)
 *  - Thruster nozzles: 4x CylinderGeometry (orange emissive, bloom-ready)
 *
 * Idle animation: sinusoidal Y hover bob (amplitude 0.05, speed 1.2 rad/s).
 */

import { useRef, useMemo, type ReactElement } from "react";
import { useFrame } from "@react-three/fiber";
import * as THREE from "three";
import { SHIP_THRUSTER_LAYOUT } from "./flight-types";

// ---------------------------------------------------------------------------
// Pre-allocated scratch objects (no allocations inside useFrame)
// ---------------------------------------------------------------------------

const _idle = { t: 0 };

// ---------------------------------------------------------------------------
// Props
// ---------------------------------------------------------------------------

export interface ShipMeshProps {
  /** Spirit accent color — tints hull panels */
  accentColor?: string;
  /** Scale multiplier (default 1) */
  scale?: number;
}

// ---------------------------------------------------------------------------
// ShipMesh component
// ---------------------------------------------------------------------------

export function ShipMesh({ accentColor, scale = 1 }: ShipMeshProps): ReactElement {
  const groupRef = useRef<THREE.Group>(null);

  // -------------------------------------------------------------------------
  // Geometry — memoized so they are never re-created on re-render
  // -------------------------------------------------------------------------
  const hullGeo = useMemo(() => {
    // ConeGeometry(radius, height, radialSegments)
    // Cone points up by default (+Y). We rotate it so it points -Z (forward).
    const geo = new THREE.ConeGeometry(0.5, 3, 6);
    return geo;
  }, []);

  const cockpitGeo = useMemo(() => new THREE.SphereGeometry(0.35, 8, 8), []);

  const wingGeo = useMemo(() => new THREE.BoxGeometry(1.8, 0.06, 0.6), []);

  const nozzleGeo = useMemo(() => new THREE.CylinderGeometry(0.1, 0.14, 0.3, 8), []);

  // -------------------------------------------------------------------------
  // Materials — memoized; accent color triggers new material if changed
  // -------------------------------------------------------------------------
  const hullMat = useMemo(
    () =>
      new THREE.MeshStandardMaterial({
        color: "#c8d0dc",
        metalness: 0.4,
        roughness: 0.5,
      }),
    [],
  );

  const cockpitMat = useMemo(
    () =>
      new THREE.MeshStandardMaterial({
        color: "#44aaff",
        emissive: "#44aaff",
        emissiveIntensity: 0.6,
        metalness: 0.7,
        roughness: 0.2,
      }),
    [],
  );

  const wingMat = useMemo(() => {
    const mat = new THREE.MeshStandardMaterial({
      color: "#a0aab8",
      metalness: 0.5,
      roughness: 0.4,
    });
    if (accentColor) {
      mat.emissive = new THREE.Color(accentColor);
      mat.emissiveIntensity = 0.3;
    }
    return mat;
  }, [accentColor]);

  const nozzleMat = useMemo(
    () =>
      new THREE.MeshStandardMaterial({
        color: "#ff8844",
        emissive: "#ff6622",
        emissiveIntensity: 2.0,
        toneMapped: false,
      }),
    [],
  );

  // -------------------------------------------------------------------------
  // Idle hover bob (useFrame — ref mutation only, no setState)
  // -------------------------------------------------------------------------
  useFrame((_state, delta) => {
    const group = groupRef.current;
    if (!group) return;
    _idle.t += delta * 1.2;
    group.position.y = Math.sin(_idle.t) * 0.05;
  });

  // -------------------------------------------------------------------------
  // Nozzle transforms — derived from SHIP_THRUSTER_LAYOUT
  // CylinderGeometry points along +Y by default.
  // Nozzles point +Z (per nozzleDirection), so rotate -90° around X.
  // -------------------------------------------------------------------------
  const nozzleQuaternion = useMemo(() => {
    return new THREE.Quaternion().setFromEuler(new THREE.Euler(-Math.PI / 2, 0, 0));
  }, []);

  return (
    <group ref={groupRef} scale={scale}>
      {/* Hull body — ConeGeometry, rotated so tip faces -Z (forward) */}
      {/* Default cone: tip at +Y, base at -Y. Rotate 90° around X → tip at -Z */}
      <mesh
        geometry={hullGeo}
        material={hullMat}
        rotation={[Math.PI / 2, 0, 0]}
      />

      {/* Cockpit canopy — sphere at front of hull */}
      <mesh
        geometry={cockpitGeo}
        material={cockpitMat}
        position={[0, 0, -0.8]}
      />

      {/* Wing struts — symmetric pair, swept back */}
      <mesh
        geometry={wingGeo}
        material={wingMat}
        position={[-0.7, 0, 0.3]}
        rotation={[0, 0.15, 0]}
      />
      <mesh
        geometry={wingGeo}
        material={wingMat}
        position={[0.7, 0, 0.3]}
        rotation={[0, -0.15, 0]}
      />

      {/* Thruster nozzles — 4x CylinderGeometry matching SHIP_THRUSTER_LAYOUT */}
      {SHIP_THRUSTER_LAYOUT.nozzlePositions.map((pos, i) => (
        <mesh
          key={i}
          geometry={nozzleGeo}
          material={nozzleMat}
          position={pos}
          quaternion={nozzleQuaternion}
        />
      ))}
    </group>
  );
}
