import { CrystallineOrganism } from "@backbay/glia-three/three";
import { Canvas, useFrame } from "@react-three/fiber";
import { clsx } from "clsx";
import * as React from "react";
import * as THREE from "three";
import type { AgentGlyphState } from "@/features/forensics/hooks/useAgentCognitionState";

type AgentGlyphOverlayProps = {
  glyphs: AgentGlyphState[];
  className?: string;
};

function hashToPhase(input: string): number {
  let hash = 0;
  for (let index = 0; index < input.length; index += 1) {
    hash = (hash * 31 + input.charCodeAt(index)) >>> 0;
  }
  return (hash % 360) * (Math.PI / 180);
}

function AgentGlyphNode({ glyph }: { glyph: AgentGlyphState }) {
  const groupRef = React.useRef<THREE.Group | null>(null);
  const phase = React.useMemo(() => hashToPhase(glyph.id), [glyph.id]);
  const baseY = glyph.position[1];

  useFrame(({ clock }) => {
    const node = groupRef.current;
    if (!node) return;
    const elapsed = clock.elapsedTime + phase;
    node.position.y = baseY + Math.sin(elapsed * 1.08) * 0.09 + (glyph.isFocused ? 0.16 : 0);
    node.rotation.y += glyph.isFocused ? 0.0052 : 0.0032;
  });

  return (
    <group ref={groupRef} position={glyph.position} scale={glyph.isFocused ? 1.24 : 1}>
      <CrystallineOrganism.CrystallineOrganism
        id={`river:${glyph.id}`}
        type="agent"
        label={glyph.label}
        state={glyph.state}
        dimensions={glyph.dimensions}
        power={glyph.power}
        selected={glyph.isFocused}
        enableParticles
      />

      <mesh rotation={[-Math.PI / 2, 0, 0]} position={[0, -0.58, 0]}>
        <ringGeometry args={[0.4, 0.56, 36]} />
        <meshBasicMaterial
          color={glyph.isFocused ? "#d5ad57" : "#3f3120"}
          transparent
          opacity={glyph.isFocused ? 0.78 : 0.42}
        />
      </mesh>
    </group>
  );
}

export function AgentGlyphOverlay({ glyphs, className }: AgentGlyphOverlayProps) {
  if (glyphs.length === 0) return null;

  return (
    <div className={clsx("pointer-events-none absolute inset-0 z-[18]", className)}>
      <Canvas
        dpr={[1, 1.6]}
        camera={{ position: [0, 4.8, 15.6], fov: 46, near: 0.1, far: 120 }}
        gl={{ alpha: true, antialias: true, powerPreference: "high-performance" }}
        style={{ background: "transparent", pointerEvents: "none" }}
      >
        <ambientLight intensity={0.78} color="#f2e8ce" />
        <directionalLight position={[10, 14, 6]} intensity={1.22} color="#ffdd9a" />
        <pointLight position={[-8, 6, 5]} intensity={0.48} color="#7edbff" />
        <pointLight position={[8, 4, 4]} intensity={0.36} color="#c8a96b" />

        {glyphs.map((glyph) => (
          <AgentGlyphNode key={glyph.id} glyph={glyph} />
        ))}
      </Canvas>
    </div>
  );
}
