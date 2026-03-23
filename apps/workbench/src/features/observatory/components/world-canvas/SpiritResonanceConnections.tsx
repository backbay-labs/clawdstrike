/**
 * SpiritResonanceConnections.tsx — Phase 41 SPRT-04
 *
 * Renders hidden cross-ring dashed connections between non-adjacent stations,
 * revealed only when the spirit reaches level 5.
 *
 * Three pairs (from deriveSpiritResonanceConnections):
 *   signal <-> receipts
 *   targets <-> case-notes
 *   run <-> watch
 *
 * Visual: dashed luminous lines at Y=8, animated dash-offset flow.
 */

import { useMemo, useRef } from "react";
import { useFrame } from "@react-three/fiber";
import { Line } from "@react-three/drei";
import * as THREE from "three";
import { deriveSpiritResonanceConnections } from "../../utils/observatory-derivations";
import { OBSERVATORY_STATION_POSITIONS } from "../../world/observatory-world-template";

// ── Props ─────────────────────────────────────────────────────────────────────

export interface SpiritResonanceConnectionsProps {
  spiritLevel: number;
  spiritAccentColor: string;
}

// ── Component ─────────────────────────────────────────────────────────────────

export function SpiritResonanceConnections({
  spiritLevel,
  spiritAccentColor,
}: SpiritResonanceConnectionsProps) {
  const connections = useMemo(
    () => deriveSpiritResonanceConnections(spiritLevel),
    [spiritLevel],
  );

  // Animate dash offset for sparkle/flow effect
  const dashOffsetRef = useRef(0);
  // We store line material refs to mutate dashOffset each frame
  const lineRefs = useRef<(THREE.LineSegments | null)[]>([]);

  useFrame((_state, delta) => {
    dashOffsetRef.current += delta * 0.5;
  });

  if (connections.length === 0) return null;

  const color = new THREE.Color(spiritAccentColor);

  const connectionPoints = connections.map((conn) => {
    const fromPos = OBSERVATORY_STATION_POSITIONS[conn.from];
    const toPos = OBSERVATORY_STATION_POSITIONS[conn.to];
    return {
      key: `resonance-${conn.from}-${conn.to}`,
      points: [
        new THREE.Vector3(fromPos[0], 8, fromPos[2]),
        new THREE.Vector3(toPos[0], 8, toPos[2]),
      ] as [THREE.Vector3, THREE.Vector3],
    };
  });

  return (
    <group name="spirit-resonance-connections">
      {connectionPoints.map((conn, i) => (
        <Line
          key={conn.key}
          ref={(el: THREE.LineSegments | null) => {
            lineRefs.current[i] = el;
          }}
          points={conn.points}
          color={color}
          lineWidth={1.2}
          dashed
          dashSize={3}
          gapSize={2}
          transparent
          opacity={0.6}
          depthWrite={false}
          toneMapped={false}
        />
      ))}
    </group>
  );
}
