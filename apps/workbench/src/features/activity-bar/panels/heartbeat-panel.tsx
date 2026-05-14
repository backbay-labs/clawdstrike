import { useMemo } from "react";
import { IconRadar } from "@tabler/icons-react";
import { ScrollArea } from "@/components/ui/scroll-area";
import { useSentinelStore } from "@/features/sentinels/stores/sentinel-store";
import { useFindingStore } from "@/features/findings/stores/finding-store";
import { useFleetConnectionStore } from "@/features/fleet/use-fleet-connection";
import { usePaneStore } from "@/features/panes/pane-store";
import { derivePosture, POSTURE_CONFIG } from "@/features/shared/posture-utils";
import { GUARD_REGISTRY } from "@/lib/workbench/guard-registry";
import type { GuardId } from "@/lib/workbench/types";
import { usePolicyTabsStore } from "@/features/policy/stores/policy-tabs-store";
import { usePolicyEditStore } from "@/features/policy/stores/policy-edit-store";

// ---------------------------------------------------------------------------
// HeartbeatPanel — compact system status overview for the sidebar.
//
// Shows posture ring, stat counts, and quick links to primary workbench views.
// ---------------------------------------------------------------------------

/** Read enabled guard count from the active policy (mirrors home-page.tsx logic). */
function useEnabledGuardCount(): number {
  const activeTabId = usePolicyTabsStore(s => s.activeTabId);
  const activeTab = usePolicyTabsStore(s => s.tabs.find(t => t.id === s.activeTabId));
  const editState = usePolicyEditStore(s => s.editStates.get(activeTabId));
  const activePolicy = editState?.policy ?? { version: "1.1.0", name: "", description: "", guards: {}, settings: {} };

  return useMemo(() => {
    let count = 0;
    for (const guard of GUARD_REGISTRY) {
      const cfg = activePolicy.guards[guard.id as GuardId];
      if (cfg && "enabled" in cfg && cfg.enabled) count++;
    }
    return count;
  }, [activePolicy]);
}

// ---------------------------------------------------------------------------
// PostureRing -- compact 80px SVG posture visualization
// ---------------------------------------------------------------------------

function PostureRing({ posture, pct }: { posture: string; pct: number }) {
  const config = POSTURE_CONFIG[posture as keyof typeof POSTURE_CONFIG];
  if (!config) return null;

  const r = 32;
  const circumference = 2 * Math.PI * r;

  return (
    <div className="flex flex-col items-center gap-1.5 py-3">
      <div className="relative">
        <svg
          viewBox="0 0 80 80"
          className="w-[80px] h-[80px] -rotate-90"
          style={{ filter: `drop-shadow(0 0 8px ${config.glow})` }}
        >
          {/* Track */}
          <circle cx="40" cy="40" r={r} fill="none" stroke="#1a1d28" strokeWidth="3" />
          {/* Coverage arc */}
          <circle
            cx="40"
            cy="40"
            r={r}
            fill="none"
            stroke={config.ringStroke}
            strokeWidth="2.5"
            strokeLinecap="round"
            strokeDasharray={circumference}
            strokeDashoffset={circumference * (1 - pct)}
            style={{ transition: "stroke-dashoffset 1.2s ease-out" }}
          />
        </svg>
      </div>
      <span
        className="text-[9px] font-mono font-semibold tracking-[0.2em]"
        style={{ color: config.color }}
      >
        {config.label}
      </span>
    </div>
  );
}

// ---------------------------------------------------------------------------
// StatGrid -- 2x2 stat count display
// ---------------------------------------------------------------------------

function StatGrid({
  sentinelCount,
  findingCount,
  approvalCount,
  fleetCount,
}: {
  sentinelCount: number;
  findingCount: number;
  approvalCount: number;
  fleetCount: number | string;
}) {
  const cells = [
    { label: "SENTINELS", value: sentinelCount },
    { label: "FINDINGS", value: findingCount },
    { label: "APPROVALS", value: approvalCount },
    { label: "FLEET", value: fleetCount },
  ];

  return (
    <div className="grid grid-cols-2 border border-[#2d3240]/40 rounded">
      {cells.map((cell, i) => (
        <div
          key={cell.label}
          className={`flex flex-col items-center py-2 px-2 ${
            i % 2 === 0 ? "border-r border-[#2d3240]/40" : ""
          } ${i < 2 ? "border-b border-[#2d3240]/40" : ""}`}
        >
          <span className="text-[9px] font-mono uppercase text-[#6f7f9a] tracking-wider">
            {cell.label}
          </span>
          <span className="text-[20px] font-semibold font-mono text-[#ece7dc] leading-tight">
            {cell.value}
          </span>
        </div>
      ))}
    </div>
  );
}

// ---------------------------------------------------------------------------
// QuickLink -- navigation row
// ---------------------------------------------------------------------------

const QUICK_LINKS = [
  { route: "/missions", label: "Mission Control" },
  { route: "/approvals", label: "Approvals" },
  { route: "/audit", label: "Audit Log" },
  { route: "/receipts", label: "Receipts" },
] as const;

function QuickLink({ route, label }: { route: string; label: string }) {
  return (
    <button
      type="button"
      onClick={() => usePaneStore.getState().openApp(route, label)}
      className="flex items-center gap-2 w-full h-8 px-3 text-[11px] font-mono text-[#ece7dc]/70 hover:bg-[#131721]/40 transition-colors rounded"
    >
      <span className="text-[#6f7f9a] text-[10px]">&gt;</span>
      <span className="truncate">{label}</span>
    </button>
  );
}

// ---------------------------------------------------------------------------
// HeartbeatPanel
// ---------------------------------------------------------------------------

export function HeartbeatPanel() {
  const sentinels = useSentinelStore.use.sentinels();
  const findings = useFindingStore.use.findings();
  const connection = useFleetConnectionStore.use.connection();
  const enabledGuardCount = useEnabledGuardCount();

  // Derive finding stats
  const { criticalCount, emergingCount } = useMemo(() => {
    let critical = 0;
    let emerging = 0;
    for (const f of findings) {
      if (f.severity === "critical" && (f.status === "emerging" || f.status === "confirmed")) {
        critical++;
      }
      if (f.status === "emerging") emerging++;
    }
    return { criticalCount: critical, emergingCount: emerging };
  }, [findings]);

  const posture = derivePosture(
    connection.connected,
    criticalCount,
    emergingCount,
    enabledGuardCount,
  );

  const pct = GUARD_REGISTRY.length > 0
    ? enabledGuardCount / GUARD_REGISTRY.length
    : 0;

  // Empty state: no sentinels, no findings, not connected
  const isEmpty = sentinels.length === 0 && findings.length === 0 && !connection.connected;

  return (
    <div className="flex flex-col h-full">
      {/* Panel header */}
      <div className="h-8 shrink-0 flex items-center px-4 border-b border-[#2d3240]/40">
        <span className="font-display font-semibold text-sm text-[#ece7dc]">
          System Status
        </span>
      </div>

      <ScrollArea className="flex-1">
        <div className="px-3 py-2 flex flex-col gap-3">
          {isEmpty ? (
            /* Empty state */
            <div className="flex flex-col items-center justify-center py-8 text-center gap-1">
              <IconRadar size={28} stroke={1} className="text-[#6f7f9a]/30" />
              <span className="text-[11px] font-mono font-semibold text-[#6f7f9a]/70">
                System Idle
              </span>
              <p className="text-[11px] font-mono text-[#6f7f9a]/70 leading-relaxed max-w-[80%]">
                No sentinels deployed. Create a sentinel to begin monitoring.
              </p>
            </div>
          ) : (
            <>
              {/* Posture ring */}
              <PostureRing posture={posture} pct={pct} />

              {/* Stat grid */}
              <StatGrid
                sentinelCount={sentinels.length}
                findingCount={findings.length}
                approvalCount={0}
                fleetCount={connection.connected ? connection.agentCount : 0}
              />

              {/* Quick links */}
              <div className="flex flex-col gap-0.5">
                <span className="text-[10px] font-mono uppercase text-[#6f7f9a] tracking-wider px-3 py-1 font-semibold">
                  Quick Links
                </span>
                {QUICK_LINKS.map((link) => (
                  <QuickLink key={link.route} route={link.route} label={link.label} />
                ))}
              </div>
            </>
          )}
        </div>
      </ScrollArea>
    </div>
  );
}
