// NexusForceCanvas — standalone R3F Canvas with force-directed graph layout.
// Uses r3f-forcegraph@1.1.1 (vasturiano) which depends only on three >=0.154 (no R3F peer dep).
// Peer dep verified: npm info r3f-forcegraph peerDependencies = { react: '*', three: '>=0.154' }
// Workbench has three ^0.170.0 — compatible.
//
// Note: r3f-forcegraph@1.1.1 does not expose onNodeDrag/onNodeDragEnd in its typed API.
// Drag-pin behavior is omitted; OrbitControls handle camera manipulation instead.
// The default export from the package is R3fGraph (the FCwithRef generic function).
// We use GraphProps directly with an eslint-disable for any-typed ref.

import { useRef, useCallback, useMemo } from "react";
import { Canvas } from "@react-three/fiber";
import { OrbitControls } from "@react-three/drei";
import ForceGraph from "r3f-forcegraph";
import type { GraphProps, GraphMethods, NodeObject, LinkObject } from "r3f-forcegraph";
import { useNexusStore } from "../stores/nexus-store";
import { usePaneStore } from "@/features/panes/pane-store";
import { STRIKECELL_ROUTE_MAP } from "../types";
import type { StrikecellDomainId } from "../types";

// Color palette by domain — distinct hues for visual separation
const DOMAIN_COLOR: Record<StrikecellDomainId, string> = {
  "security-overview": "#3dbf84",  // sentinel green
  "threat-radar":      "#c45c5c",  // specter red
  "attack-graph":      "#c45c5c",  // specter red (related)
  "network-map":       "#7b68ee",  // oracle purple
  "workflows":         "#7b68ee",  // oracle purple (related)
  "marketplace":       "#d4a84b",  // witness gold
  "events":            "#d4a84b",  // witness gold (related)
  "policies":          "#3dbf84",  // sentinel green (related)
  "forensics-river":   "#c45c5c",  // specter red (related)
};

interface GraphNode {
  id: string;
  name: string;
  color: string;
  val: number;
}

interface GraphLink {
  source: string;
  target: string;
  value: number;
}

// Typed ForceGraph props with our node/link shapes
type ForceGraphProps = GraphProps<NodeObject<GraphNode>, LinkObject<GraphNode, GraphLink>> & {
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  ref?: React.MutableRefObject<GraphMethods<any, any> | undefined>;
};

export function NexusForceCanvas() {
  const strikecells = useNexusStore.use.strikecells();
  const connections = useNexusStore.use.connections();
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const graphRef = useRef<GraphMethods<any, any> | undefined>(undefined);

  const graphData = useMemo(
    () => ({
      nodes: strikecells.map((sc) => ({
        id: sc.id,
        name: sc.name,
        color: DOMAIN_COLOR[sc.id] ?? "#888888",
        val: 1.5,
      })),
      links: connections.map((c) => ({
        source: c.sourceId,
        target: c.targetId,
        value: c.strength,
      })),
    }),
    [strikecells, connections],
  );

  const handleNodeClick = useCallback((node: NodeObject<GraphNode>) => {
    const domainId = node.id as StrikecellDomainId;
    const route = STRIKECELL_ROUTE_MAP[domainId];
    if (route) {
      usePaneStore.getState().openApp(route);
    }
  }, []);

  const forceGraphProps: ForceGraphProps = {
    ref: graphRef,
    graphData,
    nodeColor: (node: NodeObject<GraphNode>) => node.color ?? "#888888",
    nodeVal: (node: NodeObject<GraphNode>) => node.val ?? 1,
    linkColor: () => "rgba(255,255,255,0.2)",
    linkWidth: (link: LinkObject<GraphNode, GraphLink>) =>
      ((link as GraphLink).value ?? 0.5) * 2,
    onNodeClick: handleNodeClick,
    d3AlphaDecay: 0.02,
    d3VelocityDecay: 0.3,
    cooldownTicks: 150,
  };

  return (
    <div className="relative flex-1 overflow-hidden" data-testid="nexus-force-canvas">
      <div className="absolute inset-0">
        <Canvas
          camera={{ position: [0, 0, 200], fov: 60 }}
          frameloop="demand"
          dpr={[1, 1.8]}
        >
          <ambientLight intensity={0.6} />
          <pointLight position={[100, 100, 100]} intensity={0.8} />
          <OrbitControls makeDefault enablePan enableZoom enableRotate />
          {/* eslint-disable-next-line @typescript-eslint/no-explicit-any */}
          <ForceGraph {...(forceGraphProps as any)} />
        </Canvas>
      </div>
    </div>
  );
}
