/**
 * AttackGraphView - MITRE ATT&CK chain visualization
 */
import { Suspense, useState } from "react";
import { Canvas } from "@react-three/fiber";
import { OrbitControls } from "@react-three/drei";
import { AttackGraph } from "@backbay/glia/primitives";
import { GlassPanel, GlassHeader } from "@backbay/glia/primitives";
import { Badge } from "@backbay/glia/primitives";
import type { AttackChain, AttackTechnique } from "@backbay/glia/primitives";

const MOCK_CHAINS: AttackChain[] = [
  {
    id: "chain-1",
    name: "APT-29 Campaign",
    actor: "Cozy Bear",
    campaign: "SolarStorm",
    status: "active",
    techniques: [
      { id: "T1566.001", name: "Spearphishing Attachment", tactic: "initial-access", detected: true, confidence: 0.92 },
      { id: "T1059.001", name: "PowerShell Execution", tactic: "execution", detected: true, confidence: 0.88 },
      { id: "T1053.005", name: "Scheduled Task", tactic: "persistence", detected: true, confidence: 0.75 },
      { id: "T1071.001", name: "Web Protocols C2", tactic: "command-and-control", detected: false, confidence: 0.6 },
      { id: "T1048.003", name: "Exfil Over HTTPS", tactic: "exfiltration", detected: false, confidence: 0.45 },
    ],
  },
  {
    id: "chain-2",
    name: "Ransomware Intrusion",
    actor: "Unknown",
    status: "contained",
    techniques: [
      { id: "T1190", name: "Exploit Public App", tactic: "initial-access", detected: true, confidence: 0.95 },
      { id: "T1059.003", name: "Windows Cmd Shell", tactic: "execution", detected: true, confidence: 0.9 },
      { id: "T1547.001", name: "Registry Run Keys", tactic: "persistence", detected: true, confidence: 0.85 },
      { id: "T1078", name: "Valid Accounts", tactic: "privilege-escalation", detected: true, confidence: 0.72 },
      { id: "T1486", name: "Data Encrypted", tactic: "impact", detected: true, confidence: 0.98 },
    ],
  },
  {
    id: "chain-3",
    name: "Insider Threat",
    actor: "Internal",
    status: "remediated",
    techniques: [
      { id: "T1078.002", name: "Domain Accounts", tactic: "initial-access", detected: true, confidence: 0.7 },
      { id: "T1083", name: "File Discovery", tactic: "discovery", detected: true, confidence: 0.65 },
      { id: "T1560.001", name: "Archive via Utility", tactic: "collection", detected: true, confidence: 0.82 },
      { id: "T1041", name: "Exfil Over C2", tactic: "exfiltration", detected: true, confidence: 0.88 },
    ],
  },
];

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
};

export function AttackGraphView() {
  const [selectedTechnique, setSelectedTechnique] = useState<AttackTechnique | null>(null);

  return (
    <div className="flex h-full" style={{ background: "#0a0a0f" }}>
      {/* 3D Canvas */}
      <div className="flex-1 relative">
        <Canvas camera={{ position: [0, 3, 10], fov: 55 }}>
          <Suspense fallback={null}>
            <ambientLight intensity={0.35} />
            <pointLight position={[10, 8, 5]} intensity={0.7} />
            <pointLight position={[-8, -4, -8]} intensity={0.3} color="#6622ff" />

            <AttackGraph
              chains={MOCK_CHAINS}
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

        {/* Header overlay */}
        <div className="absolute top-0 left-0 right-0 flex items-center justify-between px-4 py-3 bg-gradient-to-b from-[#0a0a0f] to-transparent pointer-events-none">
          <div>
            <h1 className="text-lg font-semibold text-white">Attack Graph</h1>
            <p className="text-sm text-white/50">
              {MOCK_CHAINS.length} attack chains &middot; MITRE ATT&CK mapping
            </p>
          </div>
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
              {MOCK_CHAINS.filter((chain) =>
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
              {MOCK_CHAINS.map((chain) => (
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
