import { useEffect, useRef, useMemo } from "react";
import { useFrame } from "@react-three/fiber";
import * as THREE from "three";

const PARTICLE_COUNT = 128;
const DISCHARGE_DURATION = 1.2; // seconds
const EXPAND_SPEED = 3.0; // world units per second (reaches radius ~3.6 at end)

// Pre-compute fibonacci sphere points — allocated once, never per-frame
function buildFibonacciSpherePoints(count: number): Float32Array {
  const positions = new Float32Array(count * 3);
  const goldenAngle = Math.PI * (3 - Math.sqrt(5));
  for (let i = 0; i < count; i++) {
    const y = 1 - (i / (count - 1)) * 2;
    const radius = Math.sqrt(1 - y * y);
    const theta = goldenAngle * i;
    positions[i * 3] = Math.cos(theta) * radius;
    positions[i * 3 + 1] = y;
    positions[i * 3 + 2] = Math.sin(theta) * radius;
  }
  return positions;
}

const FIBONACCI_POINTS = buildFibonacciSpherePoints(PARTICLE_COUNT);

export interface ProbeDischargeVFXProps {
  /** World position of probe target station (center of discharge) */
  position: [number, number, number];
  /** probeStatus from observatory-store — triggers discharge on "ready"→"active" */
  probeStatus: "ready" | "active" | "cooldown";
  /** Accent color matching the probe beam / spirit accent */
  color?: string;
}

/**
 * ProbeDischargeVFX — PFX-02
 *
 * Expands a particle shell of 128 spheres outward from the probe target station
 * on probe dispatch (probeStatus transitions to "active").
 * Shell completes and resets after 1.2 seconds.
 * Uses custom InstancedMesh (not wawa-vfx) because all 128 particles expand
 * simultaneously as a sphere surface — not a spray/burst pattern.
 */
export function ProbeDischargeVFX({
  position,
  probeStatus,
  color = "#00ff88",
}: ProbeDischargeVFXProps) {
  const meshRef = useRef<THREE.InstancedMesh | null>(null);
  const startTimeRef = useRef<number | null>(null);
  const prevStatusRef = useRef<string>("ready");
  const dummy = useMemo(() => new THREE.Object3D(), []);

  // Detect "ready" → "active" transition to start discharge
  useEffect(() => {
    if (prevStatusRef.current !== "active" && probeStatus === "active") {
      startTimeRef.current = null; // will be set on first useFrame tick
    }
    prevStatusRef.current = probeStatus;
  }, [probeStatus]);

  useFrame(({ clock }) => {
    const mesh = meshRef.current;
    if (!mesh) return;

    // Capture start time on first frame of active discharge
    if (probeStatus === "active" && startTimeRef.current === null) {
      startTimeRef.current = clock.elapsedTime;
    }

    if (startTimeRef.current === null) {
      // Not active — hide all instances
      mesh.count = 0;
      return;
    }

    const elapsed = clock.elapsedTime - startTimeRef.current;

    if (elapsed > DISCHARGE_DURATION) {
      // Discharge complete — hide and reset
      mesh.count = 0;
      startTimeRef.current = null;
      return;
    }

    const t = elapsed / DISCHARGE_DURATION;
    const radius = elapsed * EXPAND_SPEED;
    const opacity = 1.0 - t; // linear fade: opaque at start, transparent at end
    const particleScale = (0.06 + opacity * 0.08) * (1 - t * 0.4);

    mesh.count = PARTICLE_COUNT;

    for (let i = 0; i < PARTICLE_COUNT; i++) {
      const px = FIBONACCI_POINTS[i * 3];
      const py = FIBONACCI_POINTS[i * 3 + 1];
      const pz = FIBONACCI_POINTS[i * 3 + 2];

      dummy.position.set(
        position[0] + px * radius,
        position[1] + py * radius + 0.5, // +0.5 to center at station prop height
        position[2] + pz * radius,
      );
      dummy.scale.setScalar(particleScale);
      dummy.updateMatrix();
      mesh.setMatrixAt(i, dummy.matrix);
    }

    mesh.instanceMatrix.needsUpdate = true;

    // Update material opacity
    const mat = mesh.material as THREE.MeshBasicMaterial;
    mat.opacity = opacity * 0.8;
  });

  return (
    <instancedMesh
      ref={meshRef}
      args={[undefined, undefined, PARTICLE_COUNT]}
      frustumCulled={false}
    >
      <sphereGeometry args={[1, 4, 4]} />
      <meshBasicMaterial
        color={color}
        transparent
        opacity={0.8}
        depthWrite={false}
        toneMapped={false}
      />
    </instancedMesh>
  );
}
