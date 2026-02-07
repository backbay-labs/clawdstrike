/**
 * ThreatRadarView - Interactive 3D threat detection radar
 *
 * Consumes live SDR events via useSpineEvents and maps them to radar blips.
 * Falls back to demo mode when no spine/NATS connection is available.
 */
import { Suspense, useState } from "react";
import { Canvas } from "@react-three/fiber";
import { OrbitControls } from "@react-three/drei";
import { ThreatRadar } from "@backbay/glia/primitives";
import { GlassPanel, GlassHeader } from "@backbay/glia/primitives";
import { Badge } from "@backbay/glia/primitives";
import { EnvironmentLayer } from "@backbay/glia/primitives";
import type { Threat, ThreatType } from "@backbay/glia/primitives";
import { useSpineEvents } from "@/hooks/useSpineEvents";
import { SpineStatusIndicator } from "@/components/SpineStatusIndicator";

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

function formatTime(timestamp: string): string {
  const ms = Date.now() - new Date(timestamp).getTime();
  const minutes = Math.floor(ms / 60000);
  if (minutes < 1) return "just now";
  return `${minutes}m ago`;
}

export function ThreatRadarView() {
  const [selectedThreat, setSelectedThreat] = useState<Threat | null>(null);
  const { threats, events, status } = useSpineEvents({ enabled: true });

  // Find the original SDR event for a threat to get its timestamp
  const getEventTimestamp = (threatId: string): string => {
    const event = events.find((e) => e.id === threatId);
    return event?.timestamp ?? new Date().toISOString();
  };

  return (
    <div className="flex h-full" style={{ background: "#0a0a0f" }}>
      {/* 3D Canvas */}
      <div className="flex-1 relative">
        <Canvas camera={{ position: [0, 8, 12], fov: 50 }}>
          <Suspense fallback={null}>
            <ambientLight intensity={0.3} />
            <pointLight position={[10, 10, 10]} intensity={0.6} />
            <pointLight position={[-5, 5, -5]} intensity={0.3} color="#00ff44" />

            <ThreatRadar
              threats={threats}
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

        {/* Header overlay */}
        <div className="absolute top-0 left-0 right-0 flex items-center justify-between px-4 py-3 bg-gradient-to-b from-[#0a0a0f] to-transparent pointer-events-none">
          <div>
            <h1 className="text-lg font-semibold text-white">Threat Radar</h1>
            <p className="text-sm text-white/50">
              {threats.filter((t) => t.active).length} active threats detected
            </p>
          </div>
          <SpineStatusIndicator status={status} />
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
            {threats.filter((t) => t.active).length} Active
          </Badge>
        </GlassHeader>

        <div className="p-3 space-y-2">
          {threats.length === 0 ? (
            <div className="text-center text-white/30 text-sm py-8">
              Waiting for events...
            </div>
          ) : (
            [...threats].sort((a, b) => b.severity - a.severity).map((threat) => {
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
                  <div className="text-sm text-white/80 font-medium truncate">{threat.label}</div>
                  <div className="flex items-center justify-between mt-1">
                    <span className="text-xs text-white/40">{formatTime(getEventTimestamp(threat.id))}</span>
                    {threat.active && (
                      <span className="text-xs text-red-400 font-mono">ACTIVE</span>
                    )}
                  </div>
                </button>
              );
            })
          )}
        </div>
      </GlassPanel>
    </div>
  );
}
