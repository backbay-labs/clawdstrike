import { useRef, useEffect, useMemo } from "react";
import { createSimulation, tickSimulation, type ForceNode, type ForceEdge, type ForceSimulation } from "../../utils/forceLayout";
import type { SSEEvent } from "../../hooks/useSSE";

function hashPos(id: string, range: number): number {
  let h = 0;
  for (let i = 0; i < id.length; i++) h = (h * 31 + id.charCodeAt(i)) >>> 0;
  return ((h % 1000) / 1000) * range * 0.8 + range * 0.1; // keep within 10%-90% of range
}

function getPostureColor(events: SSEEvent[]): string {
  const violations = events.filter((e) => e.allowed === false).length;
  if (violations === 0) return "#2fa7a0";
  if (violations <= 3) return "#d6b15a";
  return "#c23b3b";
}

export function ForceGraph({ events, width, height }: { events: SSEEvent[]; width: number; height: number }) {
  const canvasRef = useRef<HTMLCanvasElement>(null);
  const simRef = useRef<ForceSimulation | null>(null);
  const animRef = useRef<number>(0);

  const { nodes, edges } = useMemo(() => {
    const agentMap = new Map<string, SSEEvent[]>();
    const sessionSet = new Set<string>();
    const edgeList: ForceEdge[] = [];

    for (const e of events) {
      if (!e.agent_id) continue;
      if (!agentMap.has(e.agent_id)) agentMap.set(e.agent_id, []);
      agentMap.get(e.agent_id)!.push(e);
      if (e.session_id) {
        const edgeKey = `${e.agent_id}-${e.session_id}`;
        if (!sessionSet.has(edgeKey)) {
          sessionSet.add(edgeKey);
          edgeList.push({ source: e.agent_id, target: e.session_id });
        }
      }
    }

    const nodeList: ForceNode[] = [];
    for (const [id, evts] of agentMap) {
      nodeList.push({
        id, x: hashPos(id, width), y: hashPos(id + "_y", height),
        vx: 0, vy: 0, color: getPostureColor(evts),
        label: id.slice(0, 8), radius: 16, type: "agent",
      });
    }

    const sessionIds = new Set<string>();
    for (const e of events) {
      if (e.session_id && !sessionIds.has(e.session_id)) {
        sessionIds.add(e.session_id);
        nodeList.push({
          id: e.session_id, x: hashPos(e.session_id, width), y: hashPos(e.session_id + "_y", height),
          vx: 0, vy: 0, color: "rgba(154,167,181,0.4)",
          label: "", radius: 6, type: "session",
        });
      }
    }

    return { nodes: nodeList, edges: edgeList };
  }, [events, width, height]);

  useEffect(() => {
    if (nodes.length === 0 || !canvasRef.current) return;
    simRef.current = createSimulation(nodes, edges);

    const canvas = canvasRef.current;
    const ctx = canvas.getContext("2d");
    if (!ctx) return;

    const draw = () => {
      if (!simRef.current) return;
      simRef.current = tickSimulation(simRef.current, width, height);
      const sim = simRef.current;

      ctx.clearRect(0, 0, width, height);

      // Edges
      const nodeMap = new Map(sim.nodes.map((n) => [n.id, n]));
      ctx.strokeStyle = "rgba(154,167,181,0.15)";
      ctx.lineWidth = 1;
      for (const edge of sim.edges) {
        const a = nodeMap.get(edge.source), b = nodeMap.get(edge.target);
        if (!a || !b) continue;
        ctx.beginPath();
        ctx.moveTo(a.x, a.y);
        ctx.lineTo(b.x, b.y);
        ctx.stroke();
      }

      // Nodes
      for (const node of sim.nodes) {
        ctx.beginPath();
        ctx.arc(node.x, node.y, node.radius, 0, Math.PI * 2);
        ctx.fillStyle = node.color;
        ctx.fill();
        if (node.type === "agent") {
          ctx.shadowColor = node.color;
          ctx.shadowBlur = 8;
          ctx.fill();
          ctx.shadowBlur = 0;
          // Label
          ctx.font = "9px 'JetBrains Mono', monospace";
          ctx.fillStyle = "#e7edf6";
          ctx.textAlign = "center";
          ctx.fillText(node.label, node.x, node.y + node.radius + 12);
        }
      }

      animRef.current = requestAnimationFrame(draw);
    };

    animRef.current = requestAnimationFrame(draw);
    return () => cancelAnimationFrame(animRef.current);
  }, [nodes, edges, width, height]);

  return <canvas ref={canvasRef} width={width} height={height} style={{ display: "block" }} />;
}
