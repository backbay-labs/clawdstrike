/**
 * GroundPlatform - Main platform for Cyber Nexus
 *
 * Adapted from Origin Realm terrain (`GroundPlatform.tsx`).
 */

import { useFrame } from "@react-three/fiber";
import { useMemo, useRef } from "react";
import * as THREE from "three";

export interface GroundPlatformProps {
  /** Platform radius */
  radius?: number;
  /** Primary color hue (0-360) */
  hue?: number;
  /** Show grid lines */
  showGrid?: boolean;
}

function createHexagonShape(radius: number): THREE.Shape {
  const shape = new THREE.Shape();
  const sides = 6;

  for (let i = 0; i <= sides; i++) {
    const angle = (i / sides) * Math.PI * 2 - Math.PI / 2;
    const x = Math.cos(angle) * radius;
    const y = Math.sin(angle) * radius;

    if (i === 0) {
      shape.moveTo(x, y);
    } else {
      shape.lineTo(x, y);
    }
  }

  return shape;
}

export function GroundPlatform({ radius = 16, hue = 45, showGrid = true }: GroundPlatformProps) {
  const glowRef = useRef<THREE.Mesh>(null);
  const edgeRef = useRef<THREE.LineLoop>(null);

  const colors = useMemo(
    () => ({
      base: `hsl(${hue}, 10%, 8%)`,
      grid: `hsl(${hue}, 40%, 25%)`,
      glow: `hsl(${hue}, 60%, 40%)`,
      edge: `hsl(${hue}, 70%, 50%)`,
    }),
    [hue],
  );

  const platformGeometry = useMemo(() => {
    const shape = createHexagonShape(radius);
    const geometry = new THREE.ShapeGeometry(shape);
    geometry.rotateX(-Math.PI / 2);
    return geometry;
  }, [radius]);

  const gridGeometry = useMemo(() => {
    if (!showGrid) return null;

    const points: THREE.Vector3[] = [];
    const gridSpacing = 1.5;
    const gridExtent = radius * 0.9;

    for (let z = -gridExtent; z <= gridExtent; z += gridSpacing) {
      const xExtent = Math.sqrt(gridExtent * gridExtent - z * z) * 0.95;
      points.push(new THREE.Vector3(-xExtent, 0.01, z));
      points.push(new THREE.Vector3(xExtent, 0.01, z));
    }

    for (
      let i = -Math.ceil(gridExtent / gridSpacing);
      i <= Math.ceil(gridExtent / gridSpacing);
      i++
    ) {
      const offset = i * gridSpacing;

      const angle1 = Math.PI / 3;
      const startX1 = offset - gridExtent * Math.cos(angle1);
      const startZ1 = -gridExtent * Math.sin(angle1);
      const endX1 = offset + gridExtent * Math.cos(angle1);
      const endZ1 = gridExtent * Math.sin(angle1);

      if (Math.abs(offset) < gridExtent) {
        points.push(new THREE.Vector3(startX1, 0.01, startZ1));
        points.push(new THREE.Vector3(endX1, 0.01, endZ1));
      }

      const angle2 = -Math.PI / 3;
      const startX2 = offset - gridExtent * Math.cos(angle2);
      const startZ2 = -gridExtent * Math.sin(angle2);
      const endX2 = offset + gridExtent * Math.cos(angle2);
      const endZ2 = gridExtent * Math.sin(angle2);

      if (Math.abs(offset) < gridExtent) {
        points.push(new THREE.Vector3(startX2, 0.01, startZ2));
        points.push(new THREE.Vector3(endX2, 0.01, endZ2));
      }
    }

    return new THREE.BufferGeometry().setFromPoints(points);
  }, [radius, showGrid]);

  const edgeGeometry = useMemo(() => {
    const points: THREE.Vector3[] = [];
    const sides = 6;

    for (let i = 0; i <= sides; i++) {
      const angle = (i / sides) * Math.PI * 2 - Math.PI / 2;
      const x = Math.cos(angle) * radius;
      const z = Math.sin(angle) * radius;
      points.push(new THREE.Vector3(x, 0.02, z));
    }

    return new THREE.BufferGeometry().setFromPoints(points);
  }, [radius]);

  useFrame(({ clock }) => {
    const t = clock.elapsedTime;

    if (edgeRef.current) {
      const material = edgeRef.current.material as THREE.LineBasicMaterial;
      material.opacity = 0.4 + Math.sin(t * 0.5) * 0.2;
    }

    if (glowRef.current) {
      glowRef.current.rotation.z = t * 0.02;
    }
  });

  return (
    <group>
      <mesh geometry={platformGeometry} receiveShadow>
        <meshStandardMaterial color={colors.base} roughness={0.9} metalness={0.1} />
      </mesh>

      <mesh position={[0, -0.05, 0]}>
        <cylinderGeometry args={[radius * 0.98, radius, 0.1, 6]} />
        <meshStandardMaterial color={colors.base} roughness={0.95} metalness={0.05} />
      </mesh>

      {gridGeometry ? (
        <lineSegments geometry={gridGeometry}>
          <lineBasicMaterial color={colors.grid} transparent opacity={0.3} />
        </lineSegments>
      ) : null}

      <lineLoop ref={edgeRef} geometry={edgeGeometry}>
        <lineBasicMaterial color={colors.edge} transparent opacity={0.5} />
      </lineLoop>

      <mesh ref={glowRef} position={[0, -0.5, 0]} rotation={[-Math.PI / 2, 0, 0]}>
        <ringGeometry args={[radius * 0.8, radius * 1.1, 6]} />
        <meshBasicMaterial color={colors.glow} transparent opacity={0.15} side={THREE.DoubleSide} />
      </mesh>

      <mesh position={[0, 0.01, 0]} rotation={[-Math.PI / 2, 0, 0]}>
        <ringGeometry args={[0.3, 0.5, 6]} />
        <meshBasicMaterial color={colors.edge} transparent opacity={0.4} />
      </mesh>

      <pointLight position={[0, -2, 0]} color={colors.glow} intensity={0.5} distance={radius * 2} />
    </group>
  );
}

export default GroundPlatform;
