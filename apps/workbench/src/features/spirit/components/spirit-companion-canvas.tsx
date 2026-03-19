// apps/workbench/src/features/spirit/components/spirit-companion-canvas.tsx

import { Canvas, useFrame, useThree } from "@react-three/fiber";
import { useRef, Suspense, useEffect } from "react";
import * as THREE from "three";
import { useSpiritStore } from "../stores/spirit-store";
import { useSpiritEvolutionStore } from "../stores/spirit-evolution-store";
import type { SpiritMood } from "../types";

// ── Level-gated geometry layers ──────────────────────────────────────────────

function ShadowRing({ color }: { color: THREE.Color }) {
  return (
    <group data-testid="shadow-ring">
      <mesh rotation={[-Math.PI / 2, 0, 0]} position={[0, -1.3, 0]}>
        <ringGeometry args={[0.7, 1.1, 32]} />
        <meshBasicMaterial
          color={color}
          transparent
          opacity={0.4}
          depthWrite={false}
        />
      </mesh>
    </group>
  );
}

function OrbitTorus({ color }: { color: THREE.Color }) {
  const ref = useRef<THREE.Mesh>(null);
  useFrame((_, delta) => {
    if (!ref.current) return;
    ref.current.rotation.x += delta * 0.4;
    ref.current.rotation.y += delta * 0.25;
  });
  return (
    <group data-testid="orbit-torus">
      <mesh ref={ref}>
        <torusGeometry args={[1.2, 0.08, 8, 32]} />
        <meshStandardMaterial
          color={color}
          emissive={color}
          emissiveIntensity={0.3}
          transparent
          opacity={0.7}
        />
      </mesh>
    </group>
  );
}

function PulseRing({ color }: { color: THREE.Color }) {
  const matRef = useRef<THREE.MeshBasicMaterial>(null);
  useFrame(({ clock }) => {
    if (!matRef.current) return;
    matRef.current.opacity =
      0.15 + 0.15 * Math.sin(clock.getElapsedTime() * 1.5);
  });
  return (
    <group data-testid="pulse-ring">
      <mesh rotation={[-Math.PI / 2, 0, 0]}>
        <ringGeometry args={[0.9, 1.4, 32]} />
        <meshBasicMaterial
          ref={matRef}
          color={color}
          transparent
          opacity={0.15}
          depthWrite={false}
        />
      </mesh>
    </group>
  );
}

const SHARD_PHASES = [0, (2 * Math.PI) / 3, (4 * Math.PI) / 3] as const;

function OrbitShards({ color }: { color: THREE.Color }) {
  const ref0 = useRef<THREE.Mesh>(null);
  const ref1 = useRef<THREE.Mesh>(null);
  const ref2 = useRef<THREE.Mesh>(null);
  const refs = [ref0, ref1, ref2];

  useFrame(({ clock }) => {
    const t = clock.getElapsedTime();
    refs.forEach((ref, i) => {
      if (!ref.current) return;
      const phase = SHARD_PHASES[i];
      ref.current.position.x = Math.cos(t * 0.7 + phase) * 1.4;
      ref.current.position.y = Math.sin(t * 0.5 + phase) * 0.4;
      ref.current.position.z = Math.sin(t * 0.7 + phase) * 1.1;
      ref.current.rotation.x += 0.02;
      ref.current.rotation.y += 0.03;
    });
  });

  return (
    <group data-testid="orbit-shards">
      {refs.map((ref, i) => (
        <mesh key={i} ref={ref}>
          <octahedronGeometry args={[0.12, 0]} />
          <meshStandardMaterial
            color={color}
            emissive={color}
            emissiveIntensity={0.5}
          />
        </mesh>
      ))}
    </group>
  );
}

// ── Inner scene — must be inside Canvas to use useFrame/useThree ──────────────

function SpiritOrbScene({
  accentColor,
  mood,
  level,
}: {
  accentColor: string;
  mood: SpiritMood;
  level: number;
}) {
  const meshRef = useRef<THREE.Mesh>(null);
  const { invalidate } = useThree();
  const burstRef = useRef<{ active: boolean; t: number }>({
    active: false,
    t: 0,
  });
  const levelRef = useRef<number>(level);

  // Trigger a render whenever spirit state changes (demand frameloop)
  useEffect(() => {
    invalidate();
  }, [accentColor, mood, level, invalidate]);

  useFrame((_, delta) => {
    if (!meshRef.current) return;
    // Rotation
    const speed = mood === "alert" ? 1.8 : mood === "active" ? 0.6 : 0.2;
    meshRef.current.rotation.y += delta * speed;
    meshRef.current.rotation.x += delta * speed * 0.3;

    // Level-up burst detection
    if (level > levelRef.current) {
      levelRef.current = level;
      burstRef.current = { active: true, t: 0 };
    }

    // Burst animation: scale orb up then back over 0.6s
    if (burstRef.current.active) {
      burstRef.current.t += delta;
      const progress = Math.min(burstRef.current.t / 0.6, 1);
      const scale = 1 + 0.5 * Math.sin(progress * Math.PI);
      meshRef.current.scale.setScalar(scale);
      if (progress >= 1) {
        burstRef.current.active = false;
        meshRef.current.scale.setScalar(1);
      }
    }
  });

  const color = new THREE.Color(accentColor);

  return (
    <>
      <mesh ref={meshRef}>
        <icosahedronGeometry args={[1, 1]} />
        <meshStandardMaterial
          color={color}
          emissive={color}
          emissiveIntensity={0.4 + (level - 1) * 0.12}
          roughness={0.2}
          metalness={0.8}
        />
      </mesh>
      {level >= 2 && <ShadowRing color={color} />}
      {level >= 3 && <OrbitTorus color={color} />}
      {level >= 4 && <PulseRing color={color} />}
      {level >= 5 && <OrbitShards color={color} />}
    </>
  );
}

export function SpiritCompanionCanvas() {
  const accentColor = useSpiritStore.use.accentColor();
  const mood = useSpiritStore.use.mood();
  const kind = useSpiritStore.use.kind();
  const evolution = useSpiritEvolutionStore.use.evolution();
  const level = kind ? (evolution[kind]?.level ?? 1) : 1;

  // No spirit bound — render nothing (null guard prevents wasted WebGL context)
  if (!accentColor) return null;

  return (
    <div style={{ width: 150, height: 150 }}>
      <Canvas
        frameloop="demand"
        dpr={[1, 1.8]}
        gl={{ antialias: true, alpha: false, powerPreference: "high-performance" }}
        camera={{ position: [0, 0, 3.5], fov: 40 }}
      >
        <Suspense fallback={null}>
          <ambientLight intensity={0.5} />
          <pointLight position={[2, 3, 2]} intensity={1.2} color={accentColor} />
          <SpiritOrbScene accentColor={accentColor} mood={mood} level={level} />
        </Suspense>
      </Canvas>
    </div>
  );
}
