import { useState, useMemo, useCallback } from "react";
import { useFleetConnectionStore } from "@/features/fleet/use-fleet-connection";
import { usePaneStore } from "@/features/panes/pane-store";
import type { AgentInfo } from "@/features/fleet/fleet-client";

// ---------------------------------------------------------------------------
// FleetTopologyView — SVG canvas showing agents as circle nodes in a grid
// with edges between agents that share the same policy_version.
// ---------------------------------------------------------------------------

const NODE_RADIUS = 16;
const NODE_SPACING_X = 120;
const NODE_SPACING_Y = 100;
const COLS = 6;
const PADDING = 40;
const FONT_SIZE = 9;

const STATUS_COLORS: Record<string, string> = {
  online: "#3dbf84",
  stale: "#d4a84b",
  offline: "#c45c5c",
};

const STALE_THRESHOLD_SECS = 90;

function agentStatus(agent: AgentInfo): "online" | "stale" | "offline" {
  if (agent.drift.stale) return "stale";
  if (
    agent.seconds_since_heartbeat !== undefined &&
    agent.seconds_since_heartbeat > STALE_THRESHOLD_SECS
  )
    return "stale";
  if (!agent.online) return "offline";
  return "online";
}

interface NodeLayout {
  agent: AgentInfo;
  x: number;
  y: number;
  status: "online" | "stale" | "offline";
}

export function FleetTopologyView() {
  const agents = useFleetConnectionStore.use.agents();
  const [hoveredId, setHoveredId] = useState<string | null>(null);

  const nodes: NodeLayout[] = useMemo(() => {
    return agents.map((agent, i) => {
      const col = i % COLS;
      const row = Math.floor(i / COLS);
      return {
        agent,
        x: PADDING + col * NODE_SPACING_X + NODE_SPACING_X / 2,
        y: PADDING + row * NODE_SPACING_Y + NODE_SPACING_Y / 2,
        status: agentStatus(agent),
      };
    });
  }, [agents]);

  // Edges: connect agents with the same policy_version (trust group)
  const edges = useMemo(() => {
    const result: { from: NodeLayout; to: NodeLayout }[] = [];
    for (let i = 0; i < nodes.length; i++) {
      for (let j = i + 1; j < nodes.length; j++) {
        const a = nodes[i];
        const b = nodes[j];
        if (
          a.agent.policy_version &&
          b.agent.policy_version &&
          a.agent.policy_version === b.agent.policy_version
        ) {
          result.push({ from: a, to: b });
        }
      }
    }
    return result;
  }, [nodes]);

  // Auto-size the SVG viewBox
  const viewBox = useMemo(() => {
    if (nodes.length === 0) return `0 0 400 200`;
    const maxX = Math.max(...nodes.map((n) => n.x)) + NODE_SPACING_X / 2 + PADDING;
    const maxY = Math.max(...nodes.map((n) => n.y)) + NODE_SPACING_Y / 2 + PADDING;
    return `0 0 ${maxX} ${maxY}`;
  }, [nodes]);

  const handleNodeClick = useCallback((agentId: string) => {
    usePaneStore.getState().openApp("/fleet/" + agentId, agentId);
  }, []);

  if (agents.length === 0) {
    return (
      <div className="flex h-full items-center justify-center text-[11px] text-[#6f7f9a]/40">
        No agents to display
      </div>
    );
  }

  return (
    <div className="h-full w-full overflow-auto bg-[#05060a] p-4">
      <svg
        viewBox={viewBox}
        className="w-full h-full"
        style={{ minHeight: 200 }}
      >
        {/* Edges */}
        {edges.map(({ from, to }, i) => (
          <line
            key={`edge-${i}`}
            x1={from.x}
            y1={from.y}
            x2={to.x}
            y2={to.y}
            stroke="#2d3240"
            strokeWidth={1}
          />
        ))}

        {/* Nodes */}
        {nodes.map((node) => {
          const { agent, x, y, status } = node;
          const fillColor = STATUS_COLORS[status];
          const hasDrift = agent.drift.policy_drift;
          const isHovered = hoveredId === agent.endpoint_agent_id;

          return (
            <g
              key={agent.endpoint_agent_id}
              onClick={() => handleNodeClick(agent.endpoint_agent_id)}
              onMouseEnter={() => setHoveredId(agent.endpoint_agent_id)}
              onMouseLeave={() => setHoveredId(null)}
              style={{ cursor: "pointer" }}
              role="button"
              data-testid={`topology-node-${agent.endpoint_agent_id}`}
            >
              {/* Drift ring */}
              {hasDrift && (
                <circle
                  cx={x}
                  cy={y}
                  r={NODE_RADIUS + 4}
                  fill="none"
                  stroke="#d4a84b"
                  strokeWidth={2}
                  strokeDasharray="4 2"
                />
              )}

              {/* Main circle */}
              <circle
                cx={x}
                cy={y}
                r={NODE_RADIUS}
                fill={fillColor}
                opacity={isHovered ? 1 : 0.8}
                stroke={isHovered ? "#ece7dc" : "none"}
                strokeWidth={isHovered ? 2 : 0}
              />

              {/* Agent ID label */}
              <text
                x={x}
                y={y + NODE_RADIUS + 14}
                textAnchor="middle"
                fill="#ece7dc"
                opacity={0.6}
                fontSize={FONT_SIZE}
                fontFamily="monospace"
              >
                {agent.endpoint_agent_id.length > 14
                  ? agent.endpoint_agent_id.slice(0, 12) + "..."
                  : agent.endpoint_agent_id}
              </text>

              {/* Tooltip on hover */}
              {isHovered && (
                <g>
                  <rect
                    x={x - 80}
                    y={y - NODE_RADIUS - 48}
                    width={160}
                    height={38}
                    rx={4}
                    fill="#131721"
                    stroke="#2d3240"
                    strokeWidth={1}
                  />
                  <text
                    x={x}
                    y={y - NODE_RADIUS - 34}
                    textAnchor="middle"
                    fill="#ece7dc"
                    fontSize={10}
                    fontFamily="monospace"
                  >
                    {agent.endpoint_agent_id}
                  </text>
                  <text
                    x={x}
                    y={y - NODE_RADIUS - 20}
                    textAnchor="middle"
                    fill="#6f7f9a"
                    fontSize={9}
                    fontFamily="monospace"
                  >
                    {agent.posture ?? "---"} | {agent.policy_version ?? "---"}
                  </text>
                </g>
              )}
            </g>
          );
        })}
      </svg>
    </div>
  );
}
