/**
 * NetworkMapView - 3D network infrastructure topology map
 */
import { Suspense, useState } from "react";
import { Canvas } from "@react-three/fiber";
import { Canvas3DErrorBoundary } from "@/components/Canvas3DErrorBoundary";
import { OrbitControls } from "@react-three/drei";
import { NetworkTopology } from "@backbay/glia/primitives";
import { GlassPanel } from "@backbay/glia/primitives";
import { Badge } from "@backbay/glia/primitives";
import type { NetworkNode } from "@backbay/glia/primitives";
import { useSocData } from "@/services/socDataService";
import { useConnection } from "@/context/ConnectionContext";

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

export function NetworkMapView() {
  const [selectedNode, setSelectedNode] = useState<NetworkNode | null>(null);
  const { status } = useConnection();
  const { data: topology, isLoading, refresh } = useSocData("network", 30000);

  const nodes = topology?.nodes ?? [];
  const edges = topology?.edges ?? [];

  if (status !== "connected") {
    return (
      <div className="flex items-center justify-center h-full" style={{ background: "#0a0a0f" }}>
        <div className="text-center space-y-3">
          <div className="text-white/40 text-sm font-mono">NETWORK MAP OFFLINE</div>
          <div className="text-white/25 text-xs">Connect to hushd daemon to enable</div>
        </div>
      </div>
    );
  }

  return (
    <div className="relative h-full" style={{ background: "#0a0a0f" }}>
      {/* 3D Canvas */}
      <div className="absolute inset-0">
        <Canvas3DErrorBoundary>
          <Canvas camera={{ position: [0, 6, 14], fov: 50 }} dpr={[1, 2]} gl={{ antialias: true, powerPreference: "high-performance" }}>
            <Suspense fallback={null}>
              <ambientLight intensity={0.3} />
              <pointLight position={[10, 10, 10]} intensity={0.6} />
              <pointLight position={[-8, 5, -8]} intensity={0.3} color="#00aaff" />

              <NetworkTopology
                nodes={nodes}
                edges={edges}
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
        </Canvas3DErrorBoundary>
      </div>

      {/* Header overlay */}
      <div className="absolute top-0 left-0 right-0 flex items-center justify-between px-4 py-3 bg-gradient-to-b from-[#0a0a0f] to-transparent pointer-events-none">
        <div>
          <h1 className="text-lg font-semibold text-white">Network Map</h1>
          <p className="text-sm text-white/50">
            {isLoading
              ? "Scanning topology..."
              : `${nodes.length} nodes \u00b7 ${edges.length} connections`}
          </p>
        </div>
        <button
          onClick={refresh}
          className="pointer-events-auto text-xs text-white/40 hover:text-white/70 font-mono px-2 py-1 border border-white/10 rounded"
        >
          REFRESH
        </button>
      </div>

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
                  {selectedNode.services.map((service) => (
                    <Badge key={service} variant="outline" className="text-[10px]">
                      {service}
                    </Badge>
                  ))}
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
                  {edges.filter((e) => e.source === selectedNode.id || e.target === selectedNode.id).length} active links
                </div>
              </div>
            </div>
          </GlassPanel>
        </div>
      )}
    </div>
  );
}
