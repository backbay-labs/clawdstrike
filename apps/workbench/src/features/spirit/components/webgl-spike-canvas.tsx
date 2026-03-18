// apps/workbench/src/features/spirit/components/webgl-spike-canvas.tsx
// SPIKE COMPONENT — used for WebGL context leak verification only.
// Not a user-facing feature. Remove or keep as dev utility after Phase 2.

import { Canvas, useFrame } from "@react-three/fiber";
import { useRef, Suspense, useEffect } from "react";
import * as THREE from "three";

function SpinningCube() {
  const meshRef = useRef<THREE.Mesh>(null);

  useEffect(() => {
    console.log("[WebGLSpike] SpinningCube mounted — WebGL context created");
    return () => {
      console.log("[WebGLSpike] SpinningCube unmounted — WebGL context should dispose");
    };
  }, []);

  useFrame((_, delta) => {
    if (!meshRef.current) return;
    meshRef.current.rotation.x += delta * 0.8;
    meshRef.current.rotation.y += delta * 0.5;
  });

  return (
    <mesh ref={meshRef}>
      <boxGeometry args={[1.2, 1.2, 1.2]} />
      <meshStandardMaterial color="#7b68ee" roughness={0.3} metalness={0.6} />
    </mesh>
  );
}

export function WebGLSpikeCanvas() {
  return (
    <div className="flex flex-1 flex-col items-center justify-center gap-4 bg-[#0b0d13]">
      <p className="text-[12px] text-[#6f7f9a] font-display">
        WebGL Spike — open DevTools console to confirm context lifecycle
      </p>
      <div style={{ width: 240, height: 240 }}>
        <Canvas
          frameloop="always"
          dpr={[1, 1.5]}
          gl={{ antialias: true, powerPreference: "high-performance" }}
          camera={{ position: [0, 0, 3], fov: 45 }}
          onCreated={() => {
            console.log("[WebGLSpike] Canvas onCreated — context acquired");
          }}
        >
          <Suspense fallback={null}>
            <ambientLight intensity={0.6} />
            <pointLight position={[3, 3, 3]} intensity={1.0} />
            <SpinningCube />
          </Suspense>
        </Canvas>
      </div>
      <p className="text-[11px] text-[#6f7f9a]">
        Close this tab — console should log "context should dispose"
      </p>
    </div>
  );
}
