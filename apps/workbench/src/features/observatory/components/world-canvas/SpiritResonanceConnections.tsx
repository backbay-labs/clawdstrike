import { useEffect, useMemo, useRef } from "react";
import { useFrame } from "@react-three/fiber";
import { Line } from "@react-three/drei";
import * as THREE from "three";
import { deriveSpiritResonanceConnections } from "../../utils/observatory-derivations";
import { OBSERVATORY_STATION_POSITIONS } from "../../world/observatory-world-template";

export interface SpiritResonanceConnectionsProps {
  spiritLevel: number;
  spiritAccentColor: string;
}

export function SpiritResonanceConnections({
  spiritLevel,
  spiritAccentColor,
}: SpiritResonanceConnectionsProps) {
  const connections = useMemo(
    () => deriveSpiritResonanceConnections(spiritLevel),
    [spiritLevel],
  );

  const dashOffsetRef = useRef(0);
  const lineRefs = useRef<(THREE.Mesh | null)[]>([]);

  useEffect(() => {
    lineRefs.current = [];
  }, [connections.length]);

  useFrame((_state, delta) => {
    dashOffsetRef.current += delta * 0.5;
    for (const line of lineRefs.current) {
      if (line?.material) {
        (line.material as any).dashOffset = dashOffsetRef.current;
      }
    }
  });

  if (connections.length === 0) return null;

  const color = new THREE.Color(spiritAccentColor);

  return (
    <group name="spirit-resonance-connections">
      {connections.map((conn, i) => {
        const fromPos = OBSERVATORY_STATION_POSITIONS[conn.from];
        const toPos = OBSERVATORY_STATION_POSITIONS[conn.to];
        return (
          <Line
            key={`resonance-${conn.from}-${conn.to}`}
            ref={(el) => { lineRefs.current[i] = el; }}
            points={[
              new THREE.Vector3(fromPos[0], 8, fromPos[2]),
              new THREE.Vector3(toPos[0], 8, toPos[2]),
            ]}
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
        );
      })}
    </group>
  );
}
