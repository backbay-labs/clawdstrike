/**
 * AttackGraphView - MITRE ATT&CK chain visualization
 */
import { Suspense, useState } from "react";
import { Canvas } from "@react-three/fiber";
import { Canvas3DErrorBoundary } from "@/components/Canvas3DErrorBoundary";
import { OrbitControls } from "@react-three/drei";
import { AttackGraph } from "@backbay/glia/primitives";
import { GlassPanel, GlassHeader } from "@backbay/glia/primitives";
import { Badge } from "@backbay/glia/primitives";
import type { AttackTechnique } from "@backbay/glia/primitives";
import { useSocData } from "@/services/socDataService";
import { useConnection } from "@/context/ConnectionContext";

const STATUS_VARIANT: Record<string, "default" | "secondary" | "destructive" | "outline"> = {
  active: "destructive",
  contained: "secondary",
  remediated: "outline",
};

const TACTIC_LABELS: Record<string, string> = {
  "initial-access": "Initial Access",
  execution: "Execution",
  persistence: "Persistence",
  "privilege-escalation": "Privilege Escalation",
  "defense-evasion": "Defense Evasion",
  "credential-access": "Credential Access",
  discovery: "Discovery",
  "lateral-movement": "Lateral Movement",
  collection: "Collection",
  "command-and-control": "Command & Control",
  exfiltration: "Exfiltration",
  impact: "Impact",
  reconnaissance: "Reconnaissance",
  "resource-development": "Resource Development",
};

export function AttackGraphView() {
  const [selectedTechnique, setSelectedTechnique] = useState<AttackTechnique | null>(null);
  const { status } = useConnection();
  const { data: chains, isLoading, refresh } = useSocData("attacks", 30000);

  const displayChains = chains ?? [];

  if (status !== "connected") {
    return (
      <div className="flex items-center justify-center h-full" style={{ background: "#0a0a0f" }}>
        <div className="text-center space-y-3">
          <div className="text-white/40 text-sm font-mono">ATTACK GRAPH OFFLINE</div>
          <div className="text-white/25 text-xs">Connect to hushd daemon to enable</div>
        </div>
      </div>
    );
  }

  return (
    <div className="flex h-full" style={{ background: "#0a0a0f" }}>
      {/* 3D Canvas */}
      <div className="flex-1 relative">
        <Canvas3DErrorBoundary>
          <Canvas camera={{ position: [0, 3, 10], fov: 55 }} dpr={[1, 2]} gl={{ antialias: true, powerPreference: "high-performance" }}>
            <Suspense fallback={null}>
              <ambientLight intensity={0.35} />
              <pointLight position={[10, 8, 5]} intensity={0.7} />
              <pointLight position={[-8, -4, -8]} intensity={0.3} color="#6622ff" />

              <AttackGraph
                chains={displayChains}
                layout="killchain"
                showMitreIds={true}
                highlightDetected={true}
                selectedTechnique={selectedTechnique?.id}
                onTechniqueClick={(technique) => setSelectedTechnique(technique)}
              />

              <gridHelper args={[20, 20, "#1a1a2a", "#1a1a2a"]} position={[0, -3, 0]} />

              <OrbitControls
                enablePan
                enableZoom
                enableRotate
                minDistance={5}
                maxDistance={25}
                autoRotate={!selectedTechnique}
                autoRotateSpeed={0.2}
              />
            </Suspense>
          </Canvas>
        </Canvas3DErrorBoundary>

        {/* Header overlay */}
        <div className="absolute top-0 left-0 right-0 flex items-center justify-between px-4 py-3 bg-gradient-to-b from-[#0a0a0f] to-transparent pointer-events-none">
          <div>
            <h1 className="text-lg font-semibold text-white">Attack Graph</h1>
            <p className="text-sm text-white/50">
              {isLoading
                ? "Analyzing chains..."
                : `${displayChains.length} attack chains \u00b7 MITRE ATT&CK mapping`}
            </p>
          </div>
          <button
            onClick={refresh}
            className="pointer-events-auto text-xs text-white/40 hover:text-white/70 font-mono px-2 py-1 border border-white/10 rounded"
          >
            REFRESH
          </button>
        </div>
      </div>

      {/* Sidebar */}
      <GlassPanel className="w-72 h-full overflow-y-auto border-l border-white/5" variant="flush">
        <GlassHeader>
          <span className="text-sm font-semibold text-white/90">Technique Detail</span>
        </GlassHeader>

        {selectedTechnique ? (
          <div className="p-4 space-y-4">
            <div>
              <div className="text-xs text-white/40 font-mono mb-1">MITRE ID</div>
              <div className="text-sm text-cyan-400 font-mono font-semibold">{selectedTechnique.id}</div>
            </div>

            <div>
              <div className="text-xs text-white/40 font-mono mb-1">TECHNIQUE</div>
              <div className="text-sm text-white/90 font-medium">{selectedTechnique.name}</div>
            </div>

            <div>
              <div className="text-xs text-white/40 font-mono mb-1">TACTIC</div>
              <div className="text-sm text-white/70">
                {TACTIC_LABELS[selectedTechnique.tactic] ?? selectedTechnique.tactic}
              </div>
            </div>

            <div>
              <div className="text-xs text-white/40 font-mono mb-1">CONFIDENCE</div>
              <div className="text-sm text-white/70">
                {Math.round(selectedTechnique.confidence * 100)}%
              </div>
            </div>

            <div>
              <div className="text-xs text-white/40 font-mono mb-1">DETECTION STATUS</div>
              <Badge variant={selectedTechnique.detected ? "default" : "destructive"}>
                {selectedTechnique.detected ? "Detected" : "Undetected"}
              </Badge>
            </div>

            <div className="border-t border-white/10 pt-3">
              <div className="text-xs text-white/40 font-mono mb-2">CHAINS USING THIS TECHNIQUE</div>
              {displayChains.filter((chain) =>
                chain.techniques.some((t) => t.id === selectedTechnique.id)
              ).map((chain) => (
                <div key={chain.id} className="flex items-center justify-between py-1.5">
                  <span className="text-xs text-white/70">{chain.name}</span>
                  <Badge variant={STATUS_VARIANT[chain.status]}>{chain.status}</Badge>
                </div>
              ))}
            </div>
          </div>
        ) : (
          <div className="p-4">
            <p className="text-sm text-white/40 text-center mt-8">
              Click a technique node to view details
            </p>

            <div className="mt-6 space-y-3">
              <div className="text-xs text-white/40 font-mono mb-2">ACTIVE CHAINS</div>
              {displayChains.length === 0 && !isLoading && (
                <div className="text-center text-white/30 text-xs py-4 font-mono">No attack chains detected</div>
              )}
              {isLoading && displayChains.length === 0 && (
                <div className="text-center text-white/30 text-xs py-4 font-mono">Loading...</div>
              )}
              {displayChains.map((chain) => (
                <div key={chain.id} className="p-2.5 rounded-lg border border-white/5 bg-white/[0.02]">
                  <div className="flex items-center justify-between mb-1">
                    <span className="text-xs text-white/80 font-medium">{chain.name}</span>
                    <Badge variant={STATUS_VARIANT[chain.status]}>{chain.status}</Badge>
                  </div>
                  <div className="text-xs text-white/40">
                    {chain.techniques.length} techniques &middot; {chain.actor ?? "Unknown actor"}
                  </div>
                </div>
              ))}
            </div>
          </div>
        )}
      </GlassPanel>
    </div>
  );
}
