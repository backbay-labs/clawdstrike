/**
 * SecurityOverviewView - Composite security monitoring dashboard
 */
import { Suspense } from "react";
import { Canvas } from "@react-three/fiber";
import { OrbitControls } from "@react-three/drei";
import { SecurityDashboard } from "@backbay/glia/primitives";
import { KPIStat } from "@backbay/glia/primitives";
import { HUDProgressRing } from "@backbay/glia/primitives";
import { GlassPanel } from "@backbay/glia/primitives";
import type { ShieldConfig, DashboardThreat, DashboardAuditEvent } from "@backbay/glia/primitives";

const SHIELD_DATA: ShieldConfig = {
  level: 0.85,
  status: "active",
  threatsBlocked: 892,
};

const THREAT_DATA: DashboardThreat[] = [
  { id: "dt-1", angle: 0.5, distance: 0.7, severity: 0.9, type: "malware", active: true, label: "Ransomware" },
  { id: "dt-2", angle: 1.8, distance: 0.4, severity: 0.6, type: "phishing", active: false, label: "Phishing Campaign" },
  { id: "dt-3", angle: 3.2, distance: 0.8, severity: 0.85, type: "intrusion", active: true, label: "Lateral Movement" },
  { id: "dt-4", angle: 4.5, distance: 0.3, severity: 0.4, type: "anomaly", active: false, label: "Traffic Anomaly" },
  { id: "dt-5", angle: 5.5, distance: 0.6, severity: 0.7, type: "ddos", active: true, label: "DDoS Amplification" },
];

const AUDIT_EVENTS: DashboardAuditEvent[] = [
  { id: "ae-1", timestamp: new Date(Date.now() - 120000), type: "alert", severity: "critical", actor: "ids-engine", resource: "fw-edge-01", action: "Blocked malicious payload", success: true },
  { id: "ae-2", timestamp: new Date(Date.now() - 300000), type: "access", severity: "warning", actor: "admin@corp", resource: "db-prod-01", action: "Elevated privilege access", success: true },
  { id: "ae-3", timestamp: new Date(Date.now() - 600000), type: "modify", severity: "info", actor: "ci-pipeline", resource: "policy-engine", action: "Policy ruleset updated", success: true },
  { id: "ae-4", timestamp: new Date(Date.now() - 900000), type: "login", severity: "warning", actor: "unknown@ext", resource: "vpn-gateway", action: "Failed authentication attempt", success: false },
  { id: "ae-5", timestamp: new Date(Date.now() - 1200000), type: "error", severity: "error", actor: "siem-collector", resource: "log-aggregator", action: "Log ingestion pipeline error", success: false },
  { id: "ae-6", timestamp: new Date(Date.now() - 1500000), type: "alert", severity: "critical", actor: "threat-intel", resource: "network-monitor", action: "C2 beacon pattern detected", success: true },
];

export function SecurityOverviewView() {
  return (
    <div className="flex flex-col h-full" style={{ background: "#0a0a0f" }}>
      {/* KPI Stats Row */}
      <div className="grid grid-cols-4 gap-3 p-4 pb-2">
        <KPIStat
          title="Agents Protected"
          value={1247}
          previousValue={1180}
          variant="accent"
          showTrend
        />
        <KPIStat
          title="Threats Blocked"
          value={892}
          previousValue={756}
          variant="danger"
          showTrend
        />
        <KPIStat
          title="Policy Checks/s"
          value="3,400"
          variant="success"
          description="Avg over 24h"
        />
        <KPIStat
          title="Uptime"
          value="99.97"
          suffix="%"
          variant="default"
          sparklineData={[99.95, 99.96, 99.97, 99.95, 99.98, 99.97, 99.97]}
        />
      </div>

      {/* Main canvas row with shield health ring */}
      <div className="flex flex-1 min-h-0">
        {/* 3D Canvas */}
        <div className="flex-1 relative">
          <Canvas camera={{ position: [0, 5, 14], fov: 50 }}>
            <Suspense fallback={null}>
              <ambientLight intensity={0.3} />
              <pointLight position={[10, 10, 10]} intensity={0.6} />
              <pointLight position={[-8, 5, -8]} intensity={0.3} color="#00ffaa" />

              <SecurityDashboard
                shield={SHIELD_DATA}
                threats={THREAT_DATA}
                auditEvents={AUDIT_EVENTS}
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

          {/* Header overlay */}
          <div className="absolute top-0 left-0 right-0 flex items-center justify-between px-4 py-3 bg-gradient-to-b from-[#0a0a0f] to-transparent pointer-events-none">
            <div>
              <h1 className="text-lg font-semibold text-white">Security Overview</h1>
              <p className="text-sm text-white/50">Real-time composite monitoring</p>
            </div>
          </div>
        </div>

        {/* Shield Health Ring sidebar */}
        <GlassPanel className="w-48 flex flex-col items-center justify-center gap-4 border-l border-white/5" variant="flush">
          <HUDProgressRing
            value={0.85}
            size={120}
            theme="emerald"
            label="Shield Health"
          />
          <div className="text-center space-y-2 px-3">
            <div className="text-xs text-white/40 font-mono uppercase">Status</div>
            <div className="text-sm text-emerald-400 font-semibold">Active</div>
            <div className="text-xs text-white/40 mt-2 font-mono uppercase">Blocked Today</div>
            <div className="text-lg text-white/90 font-bold tabular-nums">892</div>
          </div>
        </GlassPanel>
      </div>
    </div>
  );
}
