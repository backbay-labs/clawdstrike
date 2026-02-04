/**
 * AgentNodes - 3D spheres representing agents
 */
import { useRef, useState } from "react";
import { useFrame } from "@react-three/fiber";
import { Html, Sphere } from "@react-three/drei";
import type { Mesh } from "three";
import type { AgentNode } from "@/types/agents";
import { TRUST_COLORS } from "@/types/agents";

interface AgentNodesProps {
  agents: AgentNode[];
  selectedId?: string;
  onSelect: (id: string | undefined) => void;
}

export function AgentNodes({ agents, selectedId, onSelect }: AgentNodesProps) {
  return (
    <group>
      {agents.map((agent) => (
        <AgentSphere
          key={agent.id}
          agent={agent}
          isSelected={agent.id === selectedId}
          onSelect={() => onSelect(agent.id === selectedId ? undefined : agent.id)}
        />
      ))}
    </group>
  );
}

interface AgentSphereProps {
  agent: AgentNode;
  isSelected: boolean;
  onSelect: () => void;
}

function AgentSphere({ agent, isSelected, onSelect }: AgentSphereProps) {
  const meshRef = useRef<Mesh>(null);
  const [hovered, setHovered] = useState(false);

  const color = TRUST_COLORS[agent.trust_level] ?? "#9090a0";
  const size = 0.3 + (agent.event_count ?? 0) * 0.01;
  const glowIntensity = agent.threat_score > 0.5 ? 1.5 : 1;

  // Animate pulse when selected or high threat
  useFrame((_, delta) => {
    if (!meshRef.current) return;

    if (isSelected || hovered) {
      meshRef.current.scale.setScalar(1 + Math.sin(Date.now() * 0.005) * 0.1);
    } else {
      meshRef.current.scale.setScalar(1);
    }

    // Subtle rotation
    meshRef.current.rotation.y += delta * 0.2;
  });

  return (
    <group position={agent.position}>
      {/* Main sphere */}
      <Sphere
        ref={meshRef}
        args={[size, 32, 32]}
        onClick={(e) => {
          e.stopPropagation();
          onSelect();
        }}
        onPointerOver={(e) => {
          e.stopPropagation();
          setHovered(true);
          document.body.style.cursor = "pointer";
        }}
        onPointerOut={() => {
          setHovered(false);
          document.body.style.cursor = "auto";
        }}
      >
        <meshStandardMaterial
          color={color}
          emissive={agent.threat_score > 0.3 ? "#ef4444" : color}
          emissiveIntensity={agent.threat_score > 0.3 ? agent.threat_score : 0.2}
          roughness={0.3}
          metalness={0.7}
        />
      </Sphere>

      {/* Glow effect */}
      <Sphere args={[size * 1.2, 16, 16]}>
        <meshBasicMaterial
          color={color}
          transparent
          opacity={isSelected || hovered ? 0.3 : 0.1}
        />
      </Sphere>

      {/* Selection ring */}
      {isSelected && (
        <mesh rotation={[Math.PI / 2, 0, 0]}>
          <ringGeometry args={[size * 1.5, size * 1.7, 32]} />
          <meshBasicMaterial color={color} transparent opacity={0.5} />
        </mesh>
      )}

      {/* Hover tooltip */}
      {(hovered || isSelected) && (
        <Html
          position={[0, size + 0.5, 0]}
          center
          distanceFactor={10}
          style={{ pointerEvents: "none" }}
        >
          <div className="px-2 py-1 bg-sdr-bg-secondary/90 border border-sdr-border rounded text-xs whitespace-nowrap backdrop-blur">
            <div className="font-medium text-sdr-text-primary">{agent.name}</div>
            <div className="text-sdr-text-muted">
              {agent.role} · {agent.trust_level}
            </div>
          </div>
        </Html>
      )}
    </group>
  );
}
