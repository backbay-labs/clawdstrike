// apps/workbench/src/features/spirit/components/spirit-companion-canvas.tsx

import { Canvas, useFrame, useThree } from "@react-three/fiber";
import { useRef, Suspense, useEffect } from "react";
import * as THREE from "three";
import { useSpiritStore } from "../stores/spirit-store";
import type { SpiritMood } from "../types";

// Inner scene — must be inside Canvas to use useFrame/useThree
function SpiritOrbScene({
  accentColor,
  mood,
}: {
  accentColor: string;
  mood: SpiritMood;
}) {
  const meshRef = useRef<THREE.Mesh>(null);
  const { invalidate } = useThree();

  // Trigger a render whenever spirit state changes (demand frameloop)
  useEffect(() => {
    invalidate();
  }, [accentColor, mood, invalidate]);

  useFrame((_, delta) => {
    if (!meshRef.current) return;
    const speed = mood === "alert" ? 1.8 : mood === "active" ? 0.6 : 0.2;
    meshRef.current.rotation.y += delta * speed;
    meshRef.current.rotation.x += delta * speed * 0.3;
  });

  const color = new THREE.Color(accentColor);

  return (
    <mesh ref={meshRef}>
      <icosahedronGeometry args={[1, 1]} />
      <meshStandardMaterial
        color={color}
        emissive={color}
        emissiveIntensity={0.4}
        roughness={0.2}
        metalness={0.8}
      />
    </mesh>
  );
}

export function SpiritCompanionCanvas() {
  const accentColor = useSpiritStore.use.accentColor();
  const mood = useSpiritStore.use.mood();

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
          <SpiritOrbScene accentColor={accentColor} mood={mood} />
        </Suspense>
      </Canvas>
    </div>
  );
}
