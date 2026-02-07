/**
 * NetworkMapView - 3D network infrastructure topology map
 */
import { Suspense, useState } from "react";
import { Canvas } from "@react-three/fiber";
import { OrbitControls } from "@react-three/drei";
import { NetworkTopology } from "@backbay/glia/primitives";
import { GlassPanel } from "@backbay/glia/primitives";
import { Badge } from "@backbay/glia/primitives";
import type { NetworkNode, NetworkEdge } from "@backbay/glia/primitives";

const MOCK_NODES: NetworkNode[] = [
  { id: "fw-1", type: "firewall", hostname: "edge-fw-01", ip: "10.0.0.1", status: "healthy", services: ["iptables", "ids"], vulnerabilities: 0 },
  { id: "rt-1", type: "router", hostname: "core-rtr-01", ip: "10.0.1.1", status: "healthy", services: ["bgp", "ospf"], vulnerabilities: 0 },
  { id: "srv-1", type: "server", hostname: "web-prod-01", ip: "10.1.1.10", status: "healthy", services: ["nginx", "node"], vulnerabilities: 2 },
  { id: "srv-2", type: "server", hostname: "api-prod-01", ip: "10.1.1.11", status: "warning", services: ["fastapi", "redis"], vulnerabilities: 1 },
  { id: "srv-3", type: "server", hostname: "db-prod-01", ip: "10.1.2.10", status: "healthy", services: ["postgres", "pgbouncer"], vulnerabilities: 0 },
  { id: "srv-4", type: "server", hostname: "auth-prod-01", ip: "10.1.1.20", status: "compromised", services: ["keycloak"], vulnerabilities: 4 },
  { id: "ws-1", type: "workstation", hostname: "dev-ws-01", ip: "10.2.1.10", status: "healthy", services: ["ssh"], vulnerabilities: 0 },
  { id: "ws-2", type: "workstation", hostname: "dev-ws-02", ip: "10.2.1.11", status: "healthy", services: ["ssh"], vulnerabilities: 0 },
  { id: "cloud-1", type: "cloud", hostname: "aws-vpc-prod", ip: "172.31.0.1", status: "healthy", services: ["ec2", "s3", "rds"], vulnerabilities: 1 },
  { id: "iot-1", type: "iot", hostname: "sensor-array-01", ip: "10.3.1.5", status: "warning", services: ["mqtt"], vulnerabilities: 3 },
  { id: "mob-1", type: "mobile", hostname: "fleet-mdm", ip: "10.4.0.1", status: "healthy", services: ["mdm-agent"], vulnerabilities: 0 },
  { id: "srv-5", type: "server", hostname: "log-collector", ip: "10.1.3.10", status: "healthy", services: ["elasticsearch", "logstash"], vulnerabilities: 0 },
];

const MOCK_EDGES: NetworkEdge[] = [
  { id: "e1", source: "fw-1", target: "rt-1", protocol: "tcp", bandwidth: 8000, encrypted: true, status: "active" },
  { id: "e2", source: "rt-1", target: "srv-1", protocol: "https", port: 443, bandwidth: 5000, encrypted: true, status: "active" },
  { id: "e3", source: "rt-1", target: "srv-2", protocol: "https", port: 8080, bandwidth: 3200, encrypted: true, status: "active" },
  { id: "e4", source: "srv-2", target: "srv-3", protocol: "tcp", port: 5432, bandwidth: 2000, encrypted: true, status: "active" },
  { id: "e5", source: "srv-1", target: "srv-4", protocol: "https", port: 8443, bandwidth: 1500, encrypted: true, status: "suspicious" },
  { id: "e6", source: "rt-1", target: "ws-1", protocol: "ssh", port: 22, bandwidth: 100, encrypted: true, status: "active" },
  { id: "e7", source: "rt-1", target: "ws-2", protocol: "ssh", port: 22, bandwidth: 80, encrypted: true, status: "idle" },
  { id: "e8", source: "rt-1", target: "cloud-1", protocol: "https", port: 443, bandwidth: 6000, encrypted: true, status: "active" },
  { id: "e9", source: "cloud-1", target: "srv-3", protocol: "tcp", port: 5432, bandwidth: 1200, encrypted: true, status: "active" },
  { id: "e10", source: "rt-1", target: "iot-1", protocol: "udp", port: 1883, bandwidth: 200, encrypted: false, status: "active" },
  { id: "e11", source: "rt-1", target: "mob-1", protocol: "https", port: 443, bandwidth: 500, encrypted: true, status: "active" },
  { id: "e12", source: "srv-4", target: "fw-1", protocol: "tcp", port: 4444, bandwidth: 900, encrypted: false, status: "suspicious" },
  { id: "e13", source: "srv-1", target: "srv-5", protocol: "tcp", port: 9200, bandwidth: 1800, encrypted: true, status: "active" },
  { id: "e14", source: "srv-2", target: "srv-5", protocol: "tcp", port: 9200, bandwidth: 1500, encrypted: true, status: "active" },
];

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
              nodes={MOCK_NODES}
              edges={MOCK_EDGES}
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
            {MOCK_NODES.length} nodes &middot; {MOCK_EDGES.length} connections
          </p>
        </div>
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
                  <div className="text-white/80">{NODE_TYPE_LABELS[selectedNode.type]}</div>
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
                  {MOCK_EDGES.filter((e) => e.source === selectedNode.id || e.target === selectedNode.id).length} active links
                </div>
              </div>
            </div>
          </GlassPanel>
        </div>
      )}
    </div>
  );
}
