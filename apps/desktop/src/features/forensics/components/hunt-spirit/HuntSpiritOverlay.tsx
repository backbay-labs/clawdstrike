import { Canvas, useFrame } from "@react-three/fiber";
import { clsx } from "clsx";
import * as React from "react";
import * as THREE from "three";
import {
  blendHex,
  renderSpiritContourGeometry,
} from "@/shell/workbench/spirit/sceneVisuals";
import { SpiritAtmosphereLayer } from "@/shell/workbench/spirit-ritual/atmosphere";
import {
  SPIRIT_SURFACE_AFTERMATH_MS,
  SPIRIT_SURFACE_RECEIVE_MS,
  SpiritReleaseChoreography,
  type SpiritSurfaceReceiveState,
} from "@/shell/workbench/spirit-ritual/release";
import type { HuntSpiritSceneActor } from "./runtime";
import {
  projectForensicsSpiritRitualModel,
  resolveForensicsSpiritReleasePhase,
} from "./ritualProjection";

type HuntSpiritOverlayProps = {
  actor: HuntSpiritSceneActor | null;
  className?: string;
};

function HuntSpiritNode({
  actor,
  receiveState,
}: {
  actor: HuntSpiritSceneActor;
  receiveState: SpiritSurfaceReceiveState;
}) {
  const groupRef = React.useRef<THREE.Group | null>(null);
  const ringRef = React.useRef<THREE.Mesh | null>(null);
  const pulseRef = React.useRef<THREE.Mesh | null>(null);
  const beamRef = React.useRef<THREE.Mesh | null>(null);
  const receiveRef = React.useRef<THREE.Mesh | null>(null);
  const wakeRef = React.useRef<THREE.Mesh | null>(null);
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
    const isReceiving = receiveState === "receiving";
    const isAftermath = receiveState === "aftermath";
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
        1 +
        Math.max(0, Math.sin(elapsed * 3.8)) *
          (0.4 + actor.presenceStrength * 0.25 + (isReceiving ? 0.14 : 0.06));
      pulseRef.current.scale.set(pulse, pulse, pulse);
    }

    if (receiveRef.current) {
      const receiveVisible =
        cueKind === "bind" || cueKind === "witness" || cueKind === "absorb" || isReceiving || isAftermath;
      const receivePulse =
        1 +
        Math.max(0, Math.sin(elapsed * (cueKind === "bind" ? 4.2 : 3.1))) *
          (cueKind === "bind" ? 0.62 : cueKind === "witness" ? 0.34 : 0.28);
      receiveRef.current.scale.set(receivePulse, receivePulse, receivePulse);
      const material = receiveRef.current.material as THREE.MeshBasicMaterial;
      material.opacity = receiveVisible
        ? cueKind === "bind"
          ? 0.34
          : cueKind === "witness"
            ? 0.22
            : isReceiving
              ? 0.24
              : isAftermath
                ? 0.14
                : 0.18
        : 0.05;
    }

    if (wakeRef.current) {
      const wakeScale =
        isReceiving
          ? 1.1 + Math.max(0, Math.sin(elapsed * 2.8)) * 0.26
          : isAftermath
            ? 1.02 + Math.max(0, Math.sin(elapsed * 1.8)) * 0.12
            : 1;
      wakeRef.current.scale.set(wakeScale, wakeScale, wakeScale);
      const wakeMaterial = wakeRef.current.material as THREE.MeshBasicMaterial;
      wakeMaterial.opacity = isReceiving ? 0.22 : isAftermath ? 0.1 : 0.03;
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
        {renderSpiritContourGeometry(actor.contour, "overlay")}
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

      <mesh ref={receiveRef} rotation={[-Math.PI / 2, 0, 0]} position={[0, -1.28, 0]}>
        <ringGeometry args={[1.28, 1.62, 56]} />
        <meshBasicMaterial color={halo} transparent opacity={0.05} depthWrite={false} />
      </mesh>

      <mesh ref={wakeRef} rotation={[-Math.PI / 2, 0, 0]} position={[0, -1.26, 0]}>
        <ringGeometry args={[1.64, 2.04, 64]} />
        <meshBasicMaterial color={halo} transparent opacity={0.03} depthWrite={false} />
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

  const [receiveState, setReceiveState] = React.useState<SpiritSurfaceReceiveState>("idle");
  const receiveTimerRef = React.useRef<number | null>(null);
  const aftermathTimerRef = React.useRef<number | null>(null);
  const lastCueRef = React.useRef<number | null>(null);
  const ritualModel = projectForensicsSpiritRitualModel(actor);
  const releasePhase = resolveForensicsSpiritReleasePhase(actor);
  const cueStartedAt = actor.cue?.startedAt ?? null;

  React.useEffect(() => {
    if (!cueStartedAt) return undefined;
    if (lastCueRef.current === null) {
      lastCueRef.current = cueStartedAt;
      return undefined;
    }
    if (cueStartedAt <= lastCueRef.current) return undefined;
    lastCueRef.current = cueStartedAt;
    setReceiveState("receiving");
    if (receiveTimerRef.current) window.clearTimeout(receiveTimerRef.current);
    if (aftermathTimerRef.current) window.clearTimeout(aftermathTimerRef.current);
    receiveTimerRef.current = window.setTimeout(() => {
      setReceiveState("aftermath");
      receiveTimerRef.current = null;
    }, SPIRIT_SURFACE_RECEIVE_MS);
    aftermathTimerRef.current = window.setTimeout(() => {
      setReceiveState("idle");
      aftermathTimerRef.current = null;
    }, SPIRIT_SURFACE_RECEIVE_MS + SPIRIT_SURFACE_AFTERMATH_MS);
    return () => {
      if (receiveTimerRef.current) {
        window.clearTimeout(receiveTimerRef.current);
        receiveTimerRef.current = null;
      }
      if (aftermathTimerRef.current) {
        window.clearTimeout(aftermathTimerRef.current);
        aftermathTimerRef.current = null;
      }
    };
  }, [cueStartedAt]);
  return (
    <>
      <div className="pointer-events-none absolute inset-x-[18%] top-[12%] bottom-[18%] z-[16]">
        <SpiritAtmosphereLayer
          model={ritualModel}
          reducedMotion={!actor.cue || actor.cue.kind === "focus"}
        />
      </div>

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
          <HuntSpiritNode actor={actor} receiveState={receiveState} />
        </Canvas>
      </div>

      {releasePhase ? (
        <SpiritReleaseChoreography
          model={ritualModel}
          phase={releasePhase}
          className="z-[18]"
          reducedMotion={actor.cue?.kind === "focus"}
          variant="room"
        />
      ) : null}
    </>
  );
}
