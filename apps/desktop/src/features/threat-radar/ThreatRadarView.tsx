/**
 * ThreatRadarView - Interactive 3D threat detection radar
 */
import { Suspense, useMemo } from "react";
import { Canvas } from "@react-three/fiber";
import { Canvas3DErrorBoundary } from "@/components/Canvas3DErrorBoundary";
import { OrbitControls } from "@react-three/drei";
import { ThreatRadar } from "@backbay/glia/primitives";
import { GlassPanel, GlassHeader } from "@backbay/glia/primitives";
import { Badge } from "@backbay/glia/primitives";
import { EnvironmentLayer } from "@backbay/glia/primitives";
import { useSessionState } from "@/shell/sessions";
import type { Threat, ThreatType } from "@backbay/glia/primitives";
import { useSocData } from "@/services/socDataService";
import { useConnection } from "@/context/ConnectionContext";

const SEVERITY_VARIANT: Record<string, "default" | "secondary" | "destructive" | "outline"> = {
  critical: "destructive",
  high: "destructive",
  medium: "secondary",
  low: "outline",
};

function getSeverityLabel(severity: number): string {
  if (severity >= 0.8) return "critical";
  if (severity >= 0.6) return "high";
  if (severity >= 0.3) return "medium";
  return "low";
}

const THREAT_TYPE_COLORS: Record<ThreatType, string> = {
  malware: "#ff3344",
  intrusion: "#ff6622",
  anomaly: "#ffcc11",
  ddos: "#ff0088",
  phishing: "#aa44ff",
};

function formatTime(offset: number): string {
  const minutes = Math.floor(offset);
  return `${minutes}m ago`;
}

export function ThreatRadarView() {
  const [selectedThreatId, setSelectedThreatId] = useSessionState<string | null>("radar:selectedThreatId", null);
  const { status } = useConnection();
  const { data: threats, isLoading, refresh } = useSocData("threats", 30000);

  const displayThreats = threats ?? [];

  const selectedThreat = useMemo(
    () => displayThreats.find((t) => t.id === selectedThreatId) ?? null,
    [selectedThreatId, displayThreats]
  );
  const setSelectedThreat = (threat: Threat | null) => setSelectedThreatId(threat?.id ?? null);

  if (status !== "connected") {
    return (
      <div className="flex items-center justify-center h-full" style={{ background: "#0a0a0f" }}>
        <div className="text-center space-y-3">
          <div className="text-white/40 text-sm font-mono">THREAT RADAR OFFLINE</div>
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
          <Canvas camera={{ position: [0, 8, 12], fov: 50 }} dpr={[1, 2]} gl={{ antialias: true, powerPreference: "high-performance" }}>
            <Suspense fallback={null}>
              <ambientLight intensity={0.3} />
              <pointLight position={[10, 10, 10]} intensity={0.6} />
              <pointLight position={[-5, 5, -5]} intensity={0.3} color="#00ff44" />

              <ThreatRadar
                threats={displayThreats}
                showStats={true}
                showLabels={true}
                enableGlow={true}
                onThreatClick={(threat) => setSelectedThreat(threat)}
              />

              <OrbitControls
                enablePan
                enableZoom
                enableRotate
                minDistance={6}
                maxDistance={25}
                autoRotate={!selectedThreat}
                autoRotateSpeed={0.3}
              />
            </Suspense>
          </Canvas>
        </Canvas3DErrorBoundary>

        {/* Header overlay */}
        <div className="absolute top-0 left-0 right-0 flex items-center justify-between px-4 py-3 bg-gradient-to-b from-[#0a0a0f] to-transparent pointer-events-none">
          <div>
            <h1 className="text-lg font-semibold text-white">Threat Radar</h1>
            <p className="text-sm text-white/50">
              {isLoading
                ? "Scanning..."
                : `${displayThreats.filter((t) => t.active).length} active threats detected`}
            </p>
          </div>
          <button
            onClick={refresh}
            className="pointer-events-auto text-xs text-white/40 hover:text-white/70 font-mono px-2 py-1 border border-white/10 rounded"
          >
            REFRESH
          </button>
        </div>

        {/* Environment Layer */}
        <div className="absolute inset-0 pointer-events-none -z-10">
          <EnvironmentLayer preset="cyberpunk-city" intensity={0.2} />
        </div>
      </div>

      {/* Sidebar */}
      <GlassPanel className="w-80 h-full overflow-y-auto border-l border-white/5" variant="flush">
        <GlassHeader>
          <span className="text-sm font-semibold text-white/90">Threat Feed</span>
          <Badge variant="destructive">
            {displayThreats.filter((t) => t.active).length} Active
          </Badge>
        </GlassHeader>

        <div className="p-3 space-y-2">
          {displayThreats.length === 0 && !isLoading && (
            <div className="text-center text-white/30 text-xs py-8 font-mono">No threats detected</div>
          )}
          {isLoading && displayThreats.length === 0 && (
            <div className="text-center text-white/30 text-xs py-8 font-mono">Loading...</div>
          )}
          {[...displayThreats].sort((a, b) => b.severity - a.severity).map((threat, index) => {
            const level = getSeverityLabel(threat.severity);
            return (
              <button
                key={threat.id}
                onClick={() => setSelectedThreat(threat)}
                className={`w-full text-left p-3 rounded-lg border transition-colors ${
                  selectedThreat?.id === threat.id
                    ? "border-cyan-500/40 bg-cyan-500/10"
                    : "border-white/5 bg-white/[0.02] hover:bg-white/[0.05]"
                }`}
              >
                <div className="flex items-center justify-between mb-1">
                  <span className="text-xs font-mono uppercase" style={{ color: THREAT_TYPE_COLORS[threat.type] }}>
                    {threat.type}
                  </span>
                  <Badge variant={SEVERITY_VARIANT[level]}>
                    {level}
                  </Badge>
                </div>
                <div className="text-sm text-white/80 font-medium">{threat.label}</div>
                <div className="flex items-center justify-between mt-1">
                  <span className="text-xs text-white/40">{formatTime(index * 3 + 2)}</span>
                  {threat.active && (
                    <span className="text-xs text-red-400 font-mono">ACTIVE</span>
                  )}
                </div>
              </button>
            );
          })}
        </div>
      </GlassPanel>
    </div>
  );
}
