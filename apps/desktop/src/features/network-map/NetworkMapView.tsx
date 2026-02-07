/**
 * NetworkMapView - 3D network infrastructure topology map
 *
 * Builds network topology from Hubble flow events. When connected to spine,
 * nodes and edges are dynamically created from observed network flows. Falls
 * back to demo mode with simulated Hubble-style events.
 */
import { Suspense, useState, useMemo } from "react";
import { Canvas } from "@react-three/fiber";
import { OrbitControls } from "@react-three/drei";
import { NetworkTopology } from "@backbay/glia/primitives";
import { GlassPanel } from "@backbay/glia/primitives";
import { Badge } from "@backbay/glia/primitives";
import type { NetworkNode, NetworkEdge } from "@backbay/glia/primitives";
import { useSpineEvents } from "@/hooks/useSpineEvents";
import type { SpineConnectionStatus, SDREvent } from "@/types/spine";

const STATUS_VARIANT: Record<string, "default" | "secondary" | "destructive" | "outline"> = {
  healthy: "default",
  warning: "secondary",
  compromised: "destructive",
  offline: "outline",
};

const NODE_TYPE_LABELS: Record<string, string> = {
  server: "Server",
  workstation: "Workstation",
  router: "Router",
  firewall: "Firewall",
  cloud: "Cloud",
  iot: "IoT Device",
  mobile: "Mobile",
};

function StatusIndicator({ status }: { status: SpineConnectionStatus }) {
  const config = {
    connected: { color: "bg-green-500", label: "Live" },
    demo: { color: "bg-amber-500", label: "Demo" },
    connecting: { color: "bg-blue-500 animate-pulse", label: "Connecting" },
    disconnected: { color: "bg-red-500", label: "Offline" },
  };
  const { color, label } = config[status];

  return (
    <span className="flex items-center gap-1.5 text-xs text-white/60">
      <span className={`w-1.5 h-1.5 rounded-full ${color}`} />
      {label}
    </span>
  );
}

export function NetworkMapView() {
  const [selectedNode, setSelectedNode] = useState<NetworkNode | null>(null);
  const { networkNodes, networkEdges, events, status } = useSpineEvents({ enabled: true });

  // Stats for the topology
  const stats = useMemo(() => {
    const suspiciousEdges = networkEdges.filter((e) => e.status === "suspicious").length;
    const compromisedNodes = networkNodes.filter((n) => n.status === "compromised" || n.status === "warning").length;
    return { suspiciousEdges, compromisedNodes };
  }, [networkNodes, networkEdges]);

  // Find edges for a selected node
  const selectedNodeEdges = useMemo(() => {
    if (!selectedNode) return [];
    return networkEdges.filter((e) => e.source === selectedNode.id || e.target === selectedNode.id);
  }, [selectedNode, networkEdges]);

  // Find recent events for a selected node
  const selectedNodeEvents = useMemo(() => {
    if (!selectedNode) return [];
    return events
      .filter((e) => {
        if (!e.network) return false;
        return e.network.srcIp === selectedNode.ip || e.network.dstIp === selectedNode.ip;
      })
      .slice(0, 10);
  }, [selectedNode, events]);

  return (
    <div className="relative h-full" style={{ background: "#0a0a0f" }}>
      {/* 3D Canvas */}
      <div className="absolute inset-0">
        <Canvas camera={{ position: [0, 6, 14], fov: 50 }}>
          <Suspense fallback={null}>
            <ambientLight intensity={0.3} />
            <pointLight position={[10, 10, 10]} intensity={0.6} />
            <pointLight position={[-8, 5, -8]} intensity={0.3} color="#00aaff" />

            <NetworkTopology
              nodes={networkNodes}
              edges={networkEdges}
              showTraffic={true}
              showLabels={true}
              selectedNode={selectedNode?.id}
              onNodeClick={(node) => setSelectedNode(node)}
            />

            <OrbitControls
              enablePan
              enableZoom
              enableRotate
              minDistance={5}
              maxDistance={30}
              autoRotate={!selectedNode}
              autoRotateSpeed={0.3}
            />
          </Suspense>
        </Canvas>
      </div>

      {/* Header overlay */}
      <div className="absolute top-0 left-0 right-0 flex items-center justify-between px-4 py-3 bg-gradient-to-b from-[#0a0a0f] to-transparent pointer-events-none">
        <div>
          <h1 className="text-lg font-semibold text-white">Network Map</h1>
          <p className="text-sm text-white/50">
            {networkNodes.length} nodes &middot; {networkEdges.length} connections
            {stats.suspiciousEdges > 0 && (
              <span className="text-amber-400"> &middot; {stats.suspiciousEdges} suspicious</span>
            )}
          </p>
        </div>
        <StatusIndicator status={status} />
      </div>

      {/* Empty state */}
      {networkNodes.length === 0 && (
        <div className="absolute inset-0 flex items-center justify-center pointer-events-none">
          <div className="text-center text-white/30">
            <p className="text-lg">Waiting for network flow data...</p>
            <p className="text-sm mt-1">Topology builds from Hubble flow events</p>
          </div>
        </div>
      )}

      {/* Floating node detail panel */}
      {selectedNode && (
        <div className="absolute bottom-4 right-4 w-80">
          <GlassPanel className="p-0 overflow-hidden" elevation="hud">
            <div className="flex items-center justify-between px-4 py-3 border-b border-white/10">
              <div className="flex items-center gap-2">
                <span className="text-sm font-semibold text-white/90">{selectedNode.hostname}</span>
                <Badge variant={STATUS_VARIANT[selectedNode.status]}>{selectedNode.status}</Badge>
              </div>
              <button
                onClick={() => setSelectedNode(null)}
                className="text-white/40 hover:text-white/80 text-sm"
              >
                x
              </button>
            </div>

            <div className="p-4 space-y-3">
              <div className="grid grid-cols-2 gap-3 text-xs">
                <div>
                  <div className="text-white/40 font-mono mb-0.5">TYPE</div>
                  <div className="text-white/80">{NODE_TYPE_LABELS[selectedNode.type] ?? selectedNode.type}</div>
                </div>
                <div>
                  <div className="text-white/40 font-mono mb-0.5">IP ADDRESS</div>
                  <div className="text-white/80 font-mono">{selectedNode.ip}</div>
                </div>
              </div>

              <div>
                <div className="text-xs text-white/40 font-mono mb-1">SERVICES</div>
                <div className="flex flex-wrap gap-1">
                  {selectedNode.services.length > 0 ? (
                    selectedNode.services.map((service) => (
                      <Badge key={service} variant="outline" className="text-[10px]">
                        {service}
                      </Badge>
                    ))
                  ) : (
                    <span className="text-xs text-white/30">No services detected</span>
                  )}
                </div>
              </div>

              {selectedNode.vulnerabilities !== undefined && selectedNode.vulnerabilities > 0 && (
                <div>
                  <div className="text-xs text-white/40 font-mono mb-1">VULNERABILITIES</div>
                  <Badge variant="destructive">{selectedNode.vulnerabilities} found</Badge>
                </div>
              )}

              <div>
                <div className="text-xs text-white/40 font-mono mb-1">CONNECTIONS</div>
                <div className="text-xs text-white/60">
                  {selectedNodeEdges.length} active links
                  {selectedNodeEdges.filter((e) => e.status === "suspicious").length > 0 && (
                    <span className="text-amber-400">
                      {" "}({selectedNodeEdges.filter((e) => e.status === "suspicious").length} suspicious)
                    </span>
                  )}
                </div>
              </div>

              {/* Recent flow events for this node */}
              {selectedNodeEvents.length > 0 && (
                <div className="border-t border-white/10 pt-3">
                  <div className="text-xs text-white/40 font-mono mb-2">RECENT FLOWS</div>
                  <div className="space-y-1 max-h-32 overflow-y-auto">
                    {selectedNodeEvents.map((event) => (
                      <div key={event.id} className="text-[10px] text-white/50 truncate font-mono">
                        {event.summary}
                      </div>
                    ))}
                  </div>
                </div>
              )}
            </div>
          </GlassPanel>
        </div>
      )}
    </div>
  );
}
