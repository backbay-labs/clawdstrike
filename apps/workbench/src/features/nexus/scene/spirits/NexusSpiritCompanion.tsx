import { Html, Line } from "@react-three/drei";
import { useFrame } from "@react-three/fiber";
import { useMemo, useRef } from "react";
import * as THREE from "three";
import { blendHex } from "@/features/spirit/scene-math";
import type { StrikecellDomainId } from "../../types";
import { GlyphSentinel } from "../sentinels/GlyphSentinel";
import type { NexusSpiritSceneActor } from "./runtime";

// Inlined receive-state type (workbench does not export SpiritSurfaceReceiveState)
export type SpiritSurfaceReceiveState = "idle" | "receiving" | "aftermath";

// Inlined contour geometry renderer (workbench does not have renderSpiritContourGeometry)
// Returns a simple icosahedron geometry as the contour shape.
function renderSpiritContourGeometry(
  _contour: string,
  _variant: string,
): React.ReactElement {
  return <icosahedronGeometry args={[0.42, 1]} />;
}

interface NexusSpiritCompanionProps {
  actor: NexusSpiritSceneActor | null;
  receiveState: SpiritSurfaceReceiveState;
  strikecellPositions: Map<StrikecellDomainId, THREE.Vector3>;
}

export function NexusSpiritCompanion({
  actor,
  receiveState,
  strikecellPositions,
}: NexusSpiritCompanionProps) {
  const groupRef = useRef<THREE.Group | null>(null);
  const ringRef = useRef<THREE.Mesh | null>(null);
  const pulseRef = useRef<THREE.Mesh | null>(null);
  const anchorPulseRef = useRef<THREE.Mesh | null>(null);
  const wakePulseRef = useRef<THREE.Mesh | null>(null);
  const shardRefs = useRef<Array<THREE.Mesh | null>>([]);

  const anchorPosition = actor ? (strikecellPositions.get(actor.anchorStrikecellId) ?? null) : null;
  const likelyPosition = actor?.likelyStationId
    ? (strikecellPositions.get(actor.likelyStationId) ?? null)
    : null;

  const accent = useMemo(() => (actor ? new THREE.Color(actor.accentColor) : null), [actor]);
  const halo = useMemo(
    () => (actor ? new THREE.Color(blendHex(actor.accentColor, "#f6edd6", 0.42)) : null),
    [actor],
  );
  const tetherColor = actor?.accentColor ?? "#d4a84b";

  useFrame(({ clock }) => {
    const group = groupRef.current;
    if (!group || !actor || !anchorPosition) return;

    const elapsed = clock.elapsedTime;
    const isReceiving = receiveState === "receiving";
    const isAftermath = receiveState === "aftermath";
    const anchorOffsetX = actor.likelyStationId === actor.anchorStrikecellId ? 1.84 : 1.48;
    const anchorOffsetZ = actor.cue?.kind === "transit" ? 0.28 : 0.18;
    const transitLift = actor.cue?.kind === "transit" ? Math.sin(elapsed * 3.4) * 0.16 : 0;
    const recenterPulse = actor.cue?.kind === "recenter" ? Math.sin(elapsed * 5.2) * 0.12 : 0;

    group.position.set(
      anchorPosition.x + anchorOffsetX + Math.sin(elapsed * 0.55) * 0.14,
      anchorPosition.y + actor.altitude + Math.sin(elapsed * 1.1) * 0.12 + transitLift,
      anchorPosition.z + anchorOffsetZ + Math.cos(elapsed * 0.62) * 0.12,
    );
    group.rotation.y += 0.011 + actor.presenceStrength * 0.004;
    group.rotation.z = Math.sin(elapsed * 0.4) * (0.06 + actor.focusBeam * 0.08);
    group.scale.setScalar(1 + actor.presenceStrength * 0.14 + recenterPulse);

    if (ringRef.current) {
      ringRef.current.rotation.z += 0.016;
      ringRef.current.rotation.x = Math.sin(elapsed * 0.48) * 0.22;
    }

    if (pulseRef.current) {
      const pulse =
        1 + Math.max(0, Math.sin(elapsed * 3.6)) * (0.28 + actor.presenceStrength * 0.18);
      pulseRef.current.scale.set(pulse, pulse, pulse);
    }

    if (anchorPulseRef.current) {
      const anchorPulse =
        actor.cue?.kind === "bind" || actor.cue?.kind === "recenter"
          ? 1 + Math.max(0, Math.sin(elapsed * 4.2)) * 0.54
          : actor.cue?.kind === "transit"
            ? 1 + Math.max(0, Math.sin(elapsed * 3.2)) * 0.28
            : isReceiving
              ? 1 + Math.max(0, Math.sin(elapsed * 2.8)) * 0.24
              : isAftermath
                ? 1 + Math.max(0, Math.sin(elapsed * 1.8)) * 0.12
            : 1;
      anchorPulseRef.current.scale.set(anchorPulse, anchorPulse, anchorPulse);
      const material = anchorPulseRef.current.material as THREE.MeshBasicMaterial;
      material.opacity =
        actor.cue?.kind === "bind"
          ? 0.28
          : actor.cue?.kind === "recenter"
            ? 0.22
            : actor.cue?.kind === "transit"
              ? 0.14
              : isReceiving
                ? 0.18
                : isAftermath
                  ? 0.1
              : 0.06;
    }

    if (wakePulseRef.current) {
      const wakePulse =
        isReceiving
          ? 1.04 + Math.max(0, Math.sin(elapsed * 2.6)) * 0.2
          : isAftermath
            ? 1.01 + Math.max(0, Math.sin(elapsed * 1.5)) * 0.1
            : 1;
      wakePulseRef.current.scale.set(wakePulse, wakePulse, wakePulse);
      const wakeMaterial = wakePulseRef.current.material as THREE.MeshBasicMaterial;
      wakeMaterial.opacity = isReceiving ? 0.2 : isAftermath ? 0.1 : 0.03;
    }

    shardRefs.current.forEach((mesh, index) => {
      if (!mesh) return;
      const phase = elapsed * (1 + index * 0.15) + index * 2.3;
      const radius = actor.orbitRadius + index * 0.14;
      mesh.position.set(
        Math.cos(phase) * radius,
        Math.sin(phase * 1.4) * 0.22,
        Math.sin(phase) * radius * 0.42,
      );
      mesh.rotation.x += 0.03;
      mesh.rotation.y += 0.04;
      mesh.scale.setScalar(0.1 + actor.presenceStrength * 0.05);
    });
  });

  if (!actor || !anchorPosition || !accent || !halo) return null;

  const affinityRings = Object.entries(actor.stationAffinities)
    .map(([stationId, strength]) => ({
      stationId: stationId as StrikecellDomainId,
      strength: strength ?? 0,
      position: strikecellPositions.get(stationId as StrikecellDomainId) ?? null,
    }))
    .filter((entry) => entry.position && entry.strength > 0.12);

  const transitFromPosition = actor.cue?.fromStrikecellId
    ? (strikecellPositions.get(actor.cue.fromStrikecellId) ?? null)
    : null;
  const transitToPosition = actor.cue?.toStrikecellId
    ? (strikecellPositions.get(actor.cue.toStrikecellId) ?? null)
    : null;

  return (
    <group>
      {(actor.cue?.kind === "bind" ||
        actor.cue?.kind === "recenter" ||
        actor.cue?.kind === "transit" ||
        receiveState !== "idle") && anchorPosition ? (
        <group position={anchorPosition}>
          <mesh ref={anchorPulseRef} rotation={[-Math.PI / 2, 0, 0]} position={[0, -0.84, 0]}>
            <ringGeometry args={[1.88, 2.22, 56]} />
            <meshBasicMaterial color={actor.accentColor} transparent opacity={0.06} />
          </mesh>
          <mesh ref={wakePulseRef} rotation={[-Math.PI / 2, 0, 0]} position={[0, -0.84, 0]}>
            <ringGeometry args={[2.26, 2.56, 64]} />
            <meshBasicMaterial color={actor.accentColor} transparent opacity={0.03} />
          </mesh>
        </group>
      ) : null}

      {affinityRings.map((entry) => (
        <group key={entry.stationId} position={entry.position ?? [0, 0, 0]}>
          <mesh rotation={[-Math.PI / 2, 0, 0]} position={[0, -0.86, 0]}>
            <ringGeometry args={[1.58, 1.98 + entry.strength * 0.24, 48]} />
            <meshBasicMaterial
              color={actor.accentColor}
              transparent
              opacity={
                0.08 +
                entry.strength * 0.22 +
                (receiveState === "receiving" ? 0.12 : receiveState === "aftermath" ? 0.06 : 0)
              }
              depthWrite={false}
            />
          </mesh>
          {actor.likelyStationId === entry.stationId ? (
            <mesh position={[0, 0.42, 0]}>
              <cylinderGeometry args={[0.04, 0.16, 1.2 + entry.strength * 0.8, 18, 1, true]} />
              <meshBasicMaterial
                color={actor.accentColor}
                transparent
                opacity={
                  0.14 +
                  entry.strength * 0.22 +
                  (receiveState === "receiving" ? 0.1 : receiveState === "aftermath" ? 0.05 : 0)
                }
                depthWrite={false}
              />
            </mesh>
          ) : null}
        </group>
      ))}

      {likelyPosition && actor.likelyStationId !== actor.anchorStrikecellId ? (
        <Line
          points={[
            [anchorPosition.x + 1.1, anchorPosition.y + actor.altitude * 0.6, anchorPosition.z],
            [likelyPosition.x, likelyPosition.y + 0.8, likelyPosition.z],
          ]}
          color={tetherColor}
          transparent
          opacity={
            0.24 +
            actor.focusBeam * 0.22 +
            (receiveState === "receiving" ? 0.08 : receiveState === "aftermath" ? 0.04 : 0)
          }
          lineWidth={1.2}
        />
      ) : null}

      {actor.cue?.kind === "transit" && transitFromPosition && transitToPosition ? (
        <GlyphSentinel
          from={{
            x: transitFromPosition.x + 1.2,
            y: transitFromPosition.y + actor.altitude,
            z: transitFromPosition.z,
          }}
          to={{
            x: transitToPosition.x + 1.2,
            y: transitToPosition.y + actor.altitude,
            z: transitToPosition.z,
          }}
          hue={42}
        />
      ) : null}

      <group ref={groupRef}>
        <mesh>
          {renderSpiritContourGeometry(actor.contour, "companion")}
          <meshStandardMaterial
            color={accent}
            emissive={accent}
            emissiveIntensity={0.86 + actor.presenceStrength * 0.64}
            roughness={0.28}
            metalness={0.42}
            transparent
            opacity={0.94}
          />
        </mesh>

        <mesh rotation={[-Math.PI / 2, 0, 0]} position={[0, -0.82, 0]}>
          <ringGeometry args={[0.82, 1.14, 42]} />
          <meshBasicMaterial
            color={blendHex(actor.accentColor, "#091019", 0.64)}
            transparent
            opacity={0.42}
          />
        </mesh>

        <mesh ref={ringRef} rotation={[Math.PI / 2.6, 0, 0]}>
          <torusGeometry args={[actor.orbitRadius, 0.05 + actor.presenceStrength * 0.03, 16, 56]} />
          <meshStandardMaterial
            color={halo}
            emissive={halo}
            emissiveIntensity={0.9}
            transparent
            opacity={0.84}
          />
        </mesh>

        <mesh ref={pulseRef} rotation={[-Math.PI / 2, 0, 0]} position={[0, -0.1, 0]}>
          <ringGeometry args={[0.72, 0.96, 36]} />
          <meshBasicMaterial
            color={halo}
            transparent
            opacity={actor.cue ? 0.32 : 0.14}
            depthWrite={false}
          />
        </mesh>

        {[0, 1, 2].map((index) => (
          <mesh
            key={index}
            ref={(node) => {
              shardRefs.current[index] = node;
            }}
          >
            <boxGeometry args={[0.16, 0.16, 0.16]} />
            <meshStandardMaterial
              color={halo}
              emissive={accent}
              emissiveIntensity={0.66}
              transparent
              opacity={0.78}
            />
          </mesh>
        ))}
      </group>

      <Html
        center
        position={[
          anchorPosition.x + 1.8,
          anchorPosition.y + actor.altitude + 1.1,
          anchorPosition.z,
        ]}
        distanceFactor={11}
        style={{ pointerEvents: "none" }}
      >
        <div className="rounded-md border border-[rgba(212,168,75,0.22)] bg-[rgba(8,10,16,0.88)] px-2 py-1 text-[10px] font-mono uppercase tracking-[0.1em] text-sdr-text-primary whitespace-nowrap shadow-[0_10px_24px_rgba(0,0,0,0.32)]">
          {actor.label}
        </div>
      </Html>
    </group>
  );
}
