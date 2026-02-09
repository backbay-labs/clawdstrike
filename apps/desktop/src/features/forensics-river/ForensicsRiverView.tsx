/**
 * ForensicsRiverView - Forensic action-river timeline for SOC audit events.
 *
 * Converts live SOC telemetry (audit events, threats, policy decisions)
 * into a flowing 3D river visualization with replay controls.
 */
import { useMemo } from "react";
import { RiverView } from "@backbay/glia-three/three";
import { useConnection } from "@/context/ConnectionContext";
import { useSocData } from "@/services/socDataService";
import type { DashboardAuditEvent, DashboardThreat } from "@backbay/glia-three/three";

// ---------------------------------------------------------------------------
// Mapping helpers
// ---------------------------------------------------------------------------

type RiverAction = RiverView.RiverAction;
type ActionKind = RiverView.ActionKind;
type PolicyStatus = RiverView.PolicyStatus;

const EVENT_ACTION_KIND_MAP: Record<string, ActionKind> = {
  file_read: "fs",
  file_write: "fs",
  file_delete: "fs",
  network_connect: "network",
  network_request: "network",
  dns_query: "network",
  process_exec: "exec",
  code_patch: "codepatch",
  query: "query",
  api_call: "query",
  message: "message",
  notification: "message",
};

function eventToActionKind(action: string): ActionKind {
  const lower = action.toLowerCase().replace(/[\s-]/g, "_");
  for (const [prefix, kind] of Object.entries(EVENT_ACTION_KIND_MAP)) {
    if (lower.includes(prefix)) return kind;
  }
  return "exec";
}

function severityToRisk(severity: string): number {
  switch (severity) {
    case "critical":
      return 0.95;
    case "error":
      return 0.78;
    case "warning":
      return 0.5;
    case "info":
      return 0.2;
    default:
      return 0.3;
  }
}

function eventToPolicyStatus(event: DashboardAuditEvent): PolicyStatus {
  if (!event.success) return "denied";
  if (event.severity === "critical" || event.severity === "error") return "escalated";
  if (event.severity === "warning") return "pending";
  return "approved";
}

function auditEventsToActions(events: DashboardAuditEvent[]): RiverAction[] {
  const now = Date.now();
  return events.map((event, i) => {
    const risk = severityToRisk(event.severity);
    return {
      id: event.id,
      agentId: event.actor,
      kind: eventToActionKind(event.action),
      label: `${event.action} @ ${event.resource}`,
      timestamp: now - (events.length - i) * 8000,
      duration: Math.floor(Math.random() * 500 + 50),
      policyStatus: eventToPolicyStatus(event),
      riskScore: risk,
      noveltyScore: event.success ? risk * 0.4 : risk * 0.8,
      blastRadius: risk * 0.6,
      consequence: event.success ? undefined : `Blocked ${event.action} on ${event.resource}`,
    };
  });
}

function threatsToIncidents(threats: DashboardThreat[]): RiverView.IncidentData[] {
  return threats
    .filter((t) => t.severity === "critical" || t.severity === "high")
    .slice(0, 5)
    .map((threat) => ({
      id: `incident:${threat.id}`,
      label: threat.title ?? threat.id,
      severity: threat.severity as "critical" | "high" | "medium" | "low",
      position: [
        (Math.random() - 0.5) * 4,
        0.3,
        (Math.random() - 0.5) * 8,
      ] as [number, number, number],
      radius: threat.severity === "critical" ? 1.2 : 0.8,
    }));
}

function extractAgents(events: DashboardAuditEvent[]): Array<{ id: string; label: string; color?: string }> {
  const seen = new Map<string, number>();
  for (const event of events) {
    seen.set(event.actor, (seen.get(event.actor) ?? 0) + 1);
  }
  const sorted = [...seen.entries()].sort((a, b) => b[1] - a[1]);
  return sorted.slice(0, 6).map(([actor], i) => ({
    id: actor,
    label: actor,
    color: RiverView.AGENT_COLORS[i % RiverView.AGENT_COLORS.length],
  }));
}

// ---------------------------------------------------------------------------
// Component
// ---------------------------------------------------------------------------

export function ForensicsRiverView() {
  const { status } = useConnection();
  const { data: overview, isLoading } = useSocData("overview", 15000);

  const auditEvents = overview?.auditEvents ?? [];
  const dashThreats = overview?.threats ?? [];

  const actions = useMemo(() => auditEventsToActions(auditEvents), [auditEvents]);
  const agents = useMemo(() => extractAgents(auditEvents), [auditEvents]);
  const incidents = useMemo(() => threatsToIncidents(dashThreats), [dashThreats]);

  const timeRange = useMemo<[number, number]>(() => {
    if (actions.length === 0) {
      const now = Date.now();
      return [now - 60_000, now];
    }
    const timestamps = actions.map((a) => a.timestamp);
    const min = Math.min(...timestamps);
    const max = Math.max(...timestamps);
    const pad = (max - min) * 0.05 || 5000;
    return [min - pad, max + pad];
  }, [actions]);

  if (status !== "connected") {
    return (
      <div className="flex items-center justify-center h-full" style={{ background: "#0a0a0f" }}>
        <div className="text-center space-y-3">
          <div className="text-white/40 text-sm font-mono">FORENSICS RIVER OFFLINE</div>
          <div className="text-white/25 text-xs">Connect to hushd daemon to enable</div>
        </div>
      </div>
    );
  }

  return (
    <div className="relative h-full w-full" style={{ background: "#050510" }}>
      {/* Header overlay */}
      <div className="absolute top-0 left-0 right-0 z-10 flex items-center justify-between px-4 py-3 bg-gradient-to-b from-[#0a0a0f] to-transparent pointer-events-none">
        <div>
          <h1 className="text-lg font-semibold text-white">Forensics River</h1>
          <p className="text-sm text-white/50">
            {isLoading
              ? "Loading telemetry..."
              : `${actions.length} actions \u00B7 ${agents.length} agents \u00B7 ${incidents.length} incidents`}
          </p>
        </div>
      </div>

      {/* RiverView is self-contained (provides its own Canvas) */}
      <RiverView.RiverView
        actions={actions}
        agents={agents}
        incidents={incidents}
        timeRange={timeRange}
        autoPlay
        showPolicyRails
        showCausalThreads
        showSignals={false}
        showDetectors={false}
        showIncidents={incidents.length > 0}
      />
    </div>
  );
}
