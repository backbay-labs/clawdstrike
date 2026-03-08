import { Canvas, useFrame } from "@react-three/fiber";
import { clsx } from "clsx";
import * as React from "react";
import * as THREE from "three";
import type { HuntSpiritSceneActor } from "./runtime";

type HuntSpiritOverlayProps = {
  actor: HuntSpiritSceneActor | null;
  className?: string;
};

function blendHex(base: string, mix: string, alpha: number): string {
  const color = new THREE.Color(base);
  color.lerp(new THREE.Color(mix), alpha);
  return `#${color.getHexString()}`;
}

function contourGeometry(contour: string) {
  switch (contour) {
    case "reticle-vector":
      return <octahedronGeometry args={[0.92, 1]} />;
    case "aperture-reveal":
      return <sphereGeometry args={[0.82, 28, 28]} />;
    case "chamber-bracket":
      return <dodecahedronGeometry args={[0.88, 0]} />;
    case "thread-arc":
      return <torusKnotGeometry args={[0.56, 0.18, 88, 14]} />;
    case "proof-stack":
      return <cylinderGeometry args={[0.72, 0.92, 1.1, 7]} />;
    default:
      return <icosahedronGeometry args={[0.86, 1]} />;
  }
}

function HuntSpiritNode({ actor }: { actor: HuntSpiritSceneActor }) {
  const groupRef = React.useRef<THREE.Group | null>(null);
  const ringRef = React.useRef<THREE.Mesh | null>(null);
  const pulseRef = React.useRef<THREE.Mesh | null>(null);
  const beamRef = React.useRef<THREE.Mesh | null>(null);
  const shardRefs = React.useRef<Array<THREE.Mesh | null>>([]);
  const accent = React.useMemo(() => new THREE.Color(actor.accentColor), [actor.accentColor]);
  const halo = React.useMemo(
    () => new THREE.Color(blendHex(actor.accentColor, "#f7edd0", 0.42)),
    [actor.accentColor],
  );
  const shadow = React.useMemo(
    () => new THREE.Color(blendHex(actor.accentColor, "#08101a", 0.7)),
    [actor.accentColor],
  );

  useFrame(({ clock }) => {
    const group = groupRef.current;
    if (!group) return;

    const elapsed = clock.elapsedTime;
    const cueKind = actor.cue?.kind ?? null;
    const bindPulse = cueKind === "bind" ? Math.sin(elapsed * 4.8) * 0.24 : 0;
    const focusLean = cueKind === "focus" || actor.stance === "focus" ? 0.18 : 0.05;
    const absorbPull = cueKind === "absorb" ? 0.24 : 0;
    const witnessLift = cueKind === "witness" ? 0.2 : 0;
    const transitOffset = actor.stance === "transit" ? Math.sin(elapsed * 1.6) * 0.35 : 0;

    group.position.x = actor.laneBias * 4.8 + Math.sin(elapsed * 0.4) * 0.1;
    group.position.y =
      actor.altitude +
      Math.sin(elapsed * 0.95) * (0.12 + actor.presenceStrength * 0.08) +
      witnessLift +
      transitOffset;
    group.position.z = -0.6 + Math.cos(elapsed * 0.55) * 0.12;
    group.rotation.y += 0.008 + actor.presenceStrength * 0.004;
    group.rotation.z = Math.sin(elapsed * 0.36) * focusLean;

    const scale = 1 + actor.presenceStrength * 0.18 + bindPulse;
    group.scale.setScalar(scale);

    if (ringRef.current) {
      ringRef.current.rotation.z += 0.012 + actor.presenceStrength * 0.01;
      ringRef.current.rotation.x = Math.sin(elapsed * 0.42) * 0.28;
      ringRef.current.scale.setScalar(1 + actor.presenceStrength * 0.12);
    }

    if (pulseRef.current) {
      const pulse =
        1 + Math.max(0, Math.sin(elapsed * 3.8)) * (0.4 + actor.presenceStrength * 0.25);
      pulseRef.current.scale.set(pulse, pulse, pulse);
    }

    if (beamRef.current) {
      beamRef.current.scale.y = 0.7 + actor.focusBeam * 1.3;
      beamRef.current.position.y = -1.3 - actor.focusBeam * 1.1;
      const material = beamRef.current.material as THREE.MeshBasicMaterial;
      material.opacity = 0.15 + actor.focusBeam * 0.38;
    }

    shardRefs.current.forEach((mesh, index) => {
      if (!mesh) return;
      const phase = elapsed * (1.2 + index * 0.18) + index * 2.1;
      const radius = actor.orbitRadius + index * 0.18 - absorbPull;
      mesh.position.set(
        Math.cos(phase) * radius,
        Math.sin(phase * 1.2) * 0.34,
        Math.sin(phase) * radius * 0.48,
      );
      mesh.rotation.x += 0.03;
      mesh.rotation.y += 0.04;
      const shardScale = cueKind === "witness" ? 0.18 : cueKind === "absorb" ? 0.22 : 0.14;
      mesh.scale.setScalar(shardScale + actor.presenceStrength * 0.05);
    });
  });

  return (
    <group ref={groupRef} position={[actor.laneBias * 4.8, actor.altitude, -0.6]}>
      <mesh>
        {contourGeometry(actor.contour)}
        <meshStandardMaterial
          color={accent}
          emissive={accent}
          emissiveIntensity={0.86 + actor.presenceStrength * 0.7}
          roughness={0.24}
          metalness={0.36}
          transparent
          opacity={0.92}
        />
      </mesh>

      <mesh rotation={[-Math.PI / 2, 0, 0]} position={[0, -1.34, 0]}>
        <ringGeometry args={[actor.orbitRadius * 0.72, actor.orbitRadius * 0.94, 56]} />
        <meshBasicMaterial
          color={shadow}
          transparent
          opacity={0.36 + actor.presenceStrength * 0.18}
        />
      </mesh>

      <mesh ref={ringRef} rotation={[Math.PI / 2.6, 0, 0]}>
        <torusGeometry args={[actor.orbitRadius, 0.07 + actor.presenceStrength * 0.04, 16, 64]} />
        <meshStandardMaterial
          color={halo}
          emissive={halo}
          emissiveIntensity={0.92}
          transparent
          opacity={0.84}
        />
      </mesh>

      <mesh ref={pulseRef} rotation={[-Math.PI / 2, 0, 0]} position={[0, -0.2, 0]}>
        <ringGeometry args={[0.98, 1.34, 44]} />
        <meshBasicMaterial
          color={halo}
          transparent
          opacity={actor.cue ? 0.34 : 0.16}
          depthWrite={false}
        />
      </mesh>

      <mesh ref={beamRef} rotation={[0, 0, 0]}>
        <cylinderGeometry args={[0.08, 0.32, 2.8, 20, 1, true]} />
        <meshBasicMaterial color={halo} transparent opacity={0.18} depthWrite={false} />
      </mesh>

      {[0, 1, 2].map((index) => (
        <mesh
          // eslint-disable-next-line react/no-array-index-key
          key={index}
          ref={(node) => {
            shardRefs.current[index] = node;
          }}
        >
          <boxGeometry args={[0.22, 0.22, 0.22]} />
          <meshStandardMaterial
            color={halo}
            emissive={accent}
            emissiveIntensity={0.72}
            transparent
            opacity={0.78}
          />
        </mesh>
      ))}
    </group>
  );
}

export function HuntSpiritOverlay({ actor, className }: HuntSpiritOverlayProps) {
  if (!actor) return null;

  return (
    <>
      <div className={clsx("pointer-events-none absolute inset-0 z-[17]", className)}>
        <Canvas
          dpr={[1, 1.6]}
          camera={{ position: [0, 4.5, 14.8], fov: 42, near: 0.1, far: 120 }}
          gl={{ alpha: true, antialias: true, powerPreference: "high-performance" }}
          style={{ background: "transparent", pointerEvents: "none" }}
        >
          <ambientLight intensity={0.36} color="#f6edd8" />
          <directionalLight position={[6, 10, 8]} intensity={1.18} color="#fff0c8" />
          <pointLight position={[-6, 5, 4]} intensity={0.52} color={actor.accentColor} />
          <pointLight position={[6, 5, -2]} intensity={0.34} color="#7cb8ff" />
          <HuntSpiritNode actor={actor} />
        </Canvas>
      </div>

      <div className="pointer-events-none absolute top-[132px] right-4 z-[19] max-w-[320px] rounded-xl border border-[rgba(212,168,75,0.28)] bg-[linear-gradient(180deg,rgba(11,14,21,0.92)_0%,rgba(7,10,15,0.95)_100%)] px-3 py-2 shadow-[0_18px_44px_rgba(0,0,0,0.46)]">
        <div className="flex items-center gap-2">
          <span
            className="h-2.5 w-2.5 rounded-full shadow-[0_0_14px_currentColor]"
            style={{ color: actor.accentColor, background: actor.accentColor }}
          />
          <div className="text-[10px] font-mono uppercase tracking-[0.16em] text-[rgba(212,168,75,0.94)]">
            Active Hunt Spirit
          </div>
        </div>

        <div className="mt-1 text-sm font-mono uppercase tracking-[0.08em] text-sdr-text-primary">
          {actor.label} · {actor.huntTitle}
        </div>

        <div className="mt-1 text-xs text-sdr-text-secondary">
          {actor.cue?.reason ?? actor.reason ?? "Holding field over the active river lane."}
        </div>

        <div className="mt-2 flex flex-wrap gap-1.5">
          <span className="rounded-full border border-white/10 px-2 py-0.5 text-[10px] font-mono uppercase tracking-[0.12em] text-white/68">
            {actor.stance}
          </span>
          {actor.activeStationId ? (
            <span className="rounded-full border border-white/10 px-2 py-0.5 text-[10px] font-mono uppercase tracking-[0.12em] text-white/56">
              {actor.activeStationId.replaceAll("-", " ")}
            </span>
          ) : null}
          {actor.emphasis.map((item) => (
            <span
              key={item}
              className="rounded-full border border-[rgba(212,168,75,0.22)] px-2 py-0.5 text-[10px] font-mono uppercase tracking-[0.12em] text-[rgba(244,225,177,0.82)]"
            >
              {item}
            </span>
          ))}
        </div>
      </div>
    </>
  );
}
