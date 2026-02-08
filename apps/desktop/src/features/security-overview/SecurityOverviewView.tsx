/**
 * SecurityOverviewView - Composite security monitoring dashboard
 */
import { Suspense } from "react";
import { Canvas } from "@react-three/fiber";
import { Canvas3DErrorBoundary } from "@/components/Canvas3DErrorBoundary";
import { OrbitControls } from "@react-three/drei";
import { SecurityDashboard } from "@backbay/glia/primitives";
import { KPIStat } from "@backbay/glia/primitives";
import { HUDProgressRing } from "@backbay/glia/primitives";
import { GlassPanel } from "@backbay/glia/primitives";
import { useSocData } from "@/services/socDataService";
import { useConnection } from "@/context/ConnectionContext";

const DEFAULT_SHIELD = { level: 0, status: "offline" as const, threatsBlocked: 0 };

export function SecurityOverviewView() {
  const { status } = useConnection();
  const { data: overview, isLoading } = useSocData("overview", 30000);

  const shield = overview?.shield ?? DEFAULT_SHIELD;
  const threats = overview?.threats ?? [];
  const auditEvents = overview?.auditEvents ?? [];
  const kpis = overview?.kpis ?? null;

  if (status !== "connected") {
    return (
      <div className="flex items-center justify-center h-full" style={{ background: "#0a0a0f" }}>
        <div className="text-center space-y-3">
          <div className="text-white/40 text-sm font-mono">SECURITY OVERVIEW OFFLINE</div>
          <div className="text-white/25 text-xs">Connect to hushd daemon to enable</div>
        </div>
      </div>
    );
  }

  return (
    <div className="flex flex-col h-full" style={{ background: "#0a0a0f" }}>
      {/* KPI Stats Row */}
      <div className="grid grid-cols-4 gap-3 p-4 pb-2">
        <KPIStat
          title="Agents Protected"
          value={kpis?.activeAgents ?? 0}
          variant="accent"
          showTrend
        />
        <KPIStat
          title="Threats Blocked"
          value={kpis?.blockedCount ?? 0}
          variant="danger"
          showTrend
        />
        <KPIStat
          title="Total Checks"
          value={kpis?.totalChecks ?? 0}
          variant="success"
          description={isLoading ? "Loading..." : `${kpis?.avgResponseMs ?? 0}ms avg`}
        />
        <KPIStat
          title="Uptime"
          value={String(kpis?.uptimePercent ?? 0)}
          suffix="%"
          variant="default"
        />
      </div>

      {/* Main canvas row with shield health ring */}
      <div className="flex flex-1 min-h-0">
        {/* 3D Canvas */}
        <div className="flex-1 relative">
          <Canvas3DErrorBoundary>
            <Canvas camera={{ position: [0, 5, 14], fov: 50 }} dpr={[1, 2]} gl={{ antialias: true, powerPreference: "high-performance" }}>
              <Suspense fallback={null}>
                <ambientLight intensity={0.3} />
                <pointLight position={[10, 10, 10]} intensity={0.6} />
                <pointLight position={[-8, 5, -8]} intensity={0.3} color="#00ffaa" />

                <SecurityDashboard
                  shield={shield}
                  threats={threats}
                  auditEvents={auditEvents}
                  showStatusHUD={true}
                  showConnections={true}
                />

                <OrbitControls
                  enablePan
                  enableZoom
                  enableRotate
                  minDistance={6}
                  maxDistance={30}
                  autoRotateSpeed={0.2}
                />
              </Suspense>
            </Canvas>
          </Canvas3DErrorBoundary>

          {/* Header overlay */}
          <div className="absolute top-0 left-0 right-0 flex items-center justify-between px-4 py-3 bg-gradient-to-b from-[#0a0a0f] to-transparent pointer-events-none">
            <div>
              <h1 className="text-lg font-semibold text-white">Security Overview</h1>
              <p className="text-sm text-white/50">
                {isLoading ? "Loading..." : "Real-time composite monitoring"}
              </p>
            </div>
          </div>
        </div>

        {/* Shield Health Ring sidebar */}
        <GlassPanel className="w-48 flex flex-col items-center justify-center gap-4 border-l border-white/5" variant="flush">
          <HUDProgressRing
            value={shield.level}
            size={120}
            theme="emerald"
            label="Shield Health"
          />
          <div className="text-center space-y-2 px-3">
            <div className="text-xs text-white/40 font-mono uppercase">Status</div>
            <div className={`text-sm font-semibold ${shield.status === "active" ? "text-emerald-400" : shield.status === "breach" ? "text-red-400" : "text-white/40"}`}>
              {shield.status === "active" ? "Active" : shield.status === "breach" ? "Breach" : shield.status === "warning" ? "Warning" : "Offline"}
            </div>
            <div className="text-xs text-white/40 mt-2 font-mono uppercase">Blocked Today</div>
            <div className="text-lg text-white/90 font-bold tabular-nums">{shield.threatsBlocked}</div>
          </div>
        </GlassPanel>
      </div>
    </div>
  );
}
