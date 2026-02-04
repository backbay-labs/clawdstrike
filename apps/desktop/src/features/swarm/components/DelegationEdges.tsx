/**
 * DelegationEdges - Lines connecting agents with delegation relationships
 */
import { useMemo } from "react";
import { Line } from "@react-three/drei";
import type { AgentNode, DelegationEdge } from "@/types/agents";

interface DelegationEdgesProps {
  edges: DelegationEdge[];
  agents: AgentNode[];
}

export function DelegationEdges({ edges, agents }: DelegationEdgesProps) {
  const agentMap = useMemo(() => {
    const map = new Map<string, AgentNode>();
    agents.forEach((agent) => map.set(agent.id, agent));
    return map;
  }, [agents]);

  return (
    <group>
      {edges.map((edge) => {
        const fromAgent = agentMap.get(edge.from);
        const toAgent = agentMap.get(edge.to);

        if (!fromAgent || !toAgent) return null;

        return (
          <DelegationLine
            key={edge.id}
            from={fromAgent.position}
            to={toAgent.position}
            revoked={edge.revoked}
            expired={edge.expires_at < Date.now() / 1000}
          />
        );
      })}
    </group>
  );
}

interface DelegationLineProps {
  from: [number, number, number];
  to: [number, number, number];
  revoked?: boolean;
  expired?: boolean;
}

function DelegationLine({ from, to, revoked, expired }: DelegationLineProps) {
  const color = revoked || expired ? "#ef4444" : "#3b82f6";
  const opacity = revoked || expired ? 0.3 : 0.6;

  // Create a curved line through a midpoint
  const midpoint: [number, number, number] = [
    (from[0] + to[0]) / 2,
    (from[1] + to[1]) / 2 + 0.5, // Slight curve upward
    (from[2] + to[2]) / 2,
  ];

  const points: [number, number, number][] = [from, midpoint, to];

  return (
    <Line
      points={points}
      color={color}
      lineWidth={1.5}
      opacity={opacity}
      transparent
      dashed={revoked || expired}
      dashScale={5}
      dashSize={0.3}
      gapSize={0.1}
    />
  );
}
