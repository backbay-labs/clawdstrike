import { useState, useEffect } from "react";
import { useParams } from "react-router-dom";
import {
  IconServer,
  IconArrowLeft,
  IconAlertTriangle,
  IconLoader2,
} from "@tabler/icons-react";
import { cn } from "@/lib/utils";
import { PageHeader } from "../shared/page-header";
import { useFleetConnectionStore } from "@/features/fleet/use-fleet-connection";
import { usePaneStore } from "@/features/panes/pane-store";
import {
  fetchAuditEvents,
  type AuditEvent,
  type AgentInfo,
} from "@/features/fleet/fleet-client";

// ---------------------------------------------------------------------------
// Status / posture color constants (shared with fleet-dashboard.tsx)
// ---------------------------------------------------------------------------

const STATUS_DOT_COLORS: Record<string, string> = {
  online: "#3dbf84",
  stale: "#d4a84b",
  offline: "#c45c5c",
};

const POSTURE_COLORS: Record<string, string> = {
  strict: "#3dbf84",
  default: "#d4a84b",
  permissive: "#c45c5c",
};

const STALE_THRESHOLD_SECS = 90;

function agentStatus(agent: AgentInfo): "online" | "stale" | "offline" {
  if (agent.drift.stale) return "stale";
  if (
    agent.seconds_since_heartbeat !== undefined &&
    agent.seconds_since_heartbeat > STALE_THRESHOLD_SECS
  )
    return "stale";
  if (!agent.online) return "offline";
  return "online";
}

function relativeTime(isoDate: string): string {
  const now = Date.now();
  const then = new Date(isoDate).getTime();
  if (isNaN(then)) return "unknown";
  const diffSecs = Math.floor((now - then) / 1000);
  if (diffSecs < 60) return `${diffSecs}s ago`;
  if (diffSecs < 3600) return `${Math.floor(diffSecs / 60)}m ago`;
  if (diffSecs < 86400) return `${Math.floor(diffSecs / 3600)}h ago`;
  return `${Math.floor(diffSecs / 86400)}d ago`;
}

// ---------------------------------------------------------------------------
// FleetAgentDetail — full-page detail for a single fleet agent (/fleet/:id)
// ---------------------------------------------------------------------------

export function FleetAgentDetail() {
  const { id } = useParams<{ id: string }>();
  const agents = useFleetConnectionStore.use.agents();
  const remotePolicyInfo = useFleetConnectionStore.use.remotePolicyInfo();
  const actions = useFleetConnectionStore.use.actions();

  const agent = agents.find((a) => a.endpoint_agent_id === id) ?? null;

  // Audit events state
  const [auditEvents, setAuditEvents] = useState<AuditEvent[]>([]);
  const [auditLoading, setAuditLoading] = useState(false);
  const [auditError, setAuditError] = useState<string | null>(null);

  // Fetch audit events on mount / agent change
  useEffect(() => {
    if (!id) return;
    let cancelled = false;

    async function load() {
      setAuditLoading(true);
      setAuditError(null);
      try {
        const conn = actions.getAuthenticatedConnection();
        const events = await fetchAuditEvents(conn, {
          agent_id: id,
          limit: 20,
        });
        if (!cancelled) {
          setAuditEvents(events);
        }
      } catch (err) {
        if (!cancelled) {
          setAuditError(
            err instanceof Error ? err.message : "Failed to load audit events",
          );
        }
      } finally {
        if (!cancelled) setAuditLoading(false);
      }
    }

    load();
    return () => {
      cancelled = true;
    };
  }, [id, actions]);

  // Not found state
  if (!agent) {
    return (
      <div className="flex h-full w-full flex-col items-center justify-center gap-4 bg-[#05060a]">
        <IconAlertTriangle size={28} className="text-[#d4a84b]/50" />
        <div className="text-center">
          <p className="text-[13px] text-[#ece7dc]/70">Agent not found</p>
          <p className="mt-1 text-[11px] text-[#6f7f9a]/50">
            No agent with ID &quot;{id}&quot; in the current fleet
          </p>
        </div>
        <button
          type="button"
          onClick={() => usePaneStore.getState().openApp("/fleet", "Fleet")}
          className="mt-2 flex items-center gap-1.5 rounded-md border border-[#2d3240] px-3 py-1.5 text-[11px] text-[#6f7f9a] hover:text-[#ece7dc] hover:border-[#d4a84b]/30 transition-colors"
        >
          <IconArrowLeft size={12} stroke={1.5} />
          Back to Fleet
        </button>
      </div>
    );
  }

  const status = agentStatus(agent);
  const dotColor = STATUS_DOT_COLORS[status];
  const postureColor =
    POSTURE_COLORS[agent.posture?.toLowerCase() ?? ""] ?? "#6f7f9a";
  const absTime = new Date(agent.last_heartbeat_at).toLocaleString();

  return (
    <div className="flex h-full w-full flex-col overflow-hidden bg-[#05060a]">
      {/* Header */}
      <PageHeader
        title={agent.endpoint_agent_id}
        subtitle={
          <span className="flex items-center gap-2">
            <span
              className="inline-block h-2 w-2 rounded-full"
              style={{ backgroundColor: dotColor }}
            />
            <span className="capitalize">{status}</span>
            {agent.posture && (
              <>
                <span className="text-[#6f7f9a]/30">|</span>
                <span
                  className="rounded px-1.5 py-0.5 text-[9px] font-medium uppercase"
                  style={{
                    backgroundColor: postureColor + "15",
                    color: postureColor,
                  }}
                >
                  {agent.posture}
                </span>
              </>
            )}
          </span>
        }
        icon={IconServer}
        sectionAccent="#7b6b8b"
      >
        <button
          type="button"
          onClick={() => usePaneStore.getState().openApp("/fleet", "Fleet")}
          className="flex items-center gap-1.5 rounded-md border border-[#2d3240] px-3 py-1.5 text-[11px] text-[#6f7f9a] hover:text-[#ece7dc] hover:border-[#d4a84b]/30 transition-colors"
        >
          <IconArrowLeft size={12} stroke={1.5} />
          Back to Fleet
        </button>
      </PageHeader>

      {/* Content */}
      <div className="flex-1 overflow-auto px-6 py-4">
        <div className="flex flex-col gap-4 lg:flex-row lg:gap-6">
          {/* Agent Info card */}
          <div className="flex-1 rounded-lg border border-[#2d3240]/60 bg-[#0b0d13] p-4">
            <h3 className="text-[9px] font-semibold uppercase tracking-wider text-[#6f7f9a]/50 mb-3">
              Agent Info
            </h3>
            <div className="flex flex-col gap-2">
              <DetailRow
                label="Agent ID"
                value={agent.endpoint_agent_id}
                mono
              />
              <DetailRow
                label="Status"
                value={status}
                valueColor={dotColor}
              />
              <DetailRow
                label="Posture"
                value={agent.posture ?? "---"}
              />
              <DetailRow
                label="Policy Version"
                value={agent.policy_version ?? "---"}
                mono
              />
              <DetailRow
                label="Daemon Version"
                value={agent.daemon_version ?? "---"}
                mono
              />
              <DetailRow
                label="Last Seen IP"
                value={agent.last_seen_ip ?? "---"}
                mono
              />
              <DetailRow
                label="Session ID"
                value={agent.last_session_id ?? "---"}
                mono
              />
              <DetailRow
                label="Runtimes"
                value={String(agent.runtime_count ?? 0)}
              />
              <DetailRow
                label="Last Heartbeat"
                value={`${relativeTime(agent.last_heartbeat_at)} (${absTime})`}
              />
              <DetailRow
                label="Seconds Since HB"
                value={
                  agent.seconds_since_heartbeat !== undefined
                    ? `${agent.seconds_since_heartbeat}s`
                    : "---"
                }
              />
            </div>
          </div>

          {/* Drift Flags card */}
          <div className="flex-1 rounded-lg border border-[#2d3240]/60 bg-[#0b0d13] p-4">
            <h3 className="text-[9px] font-semibold uppercase tracking-wider text-[#6f7f9a]/50 mb-3">
              Drift Flags
            </h3>
            <div className="flex flex-col gap-2">
              <DetailRow
                label="Policy Drift"
                value={agent.drift.policy_drift ? "YES" : "No"}
                valueColor={agent.drift.policy_drift ? "#c45c5c" : "#3dbf84"}
              />
              <DetailRow
                label="Daemon Drift"
                value={agent.drift.daemon_drift ? "YES" : "No"}
                valueColor={agent.drift.daemon_drift ? "#d4a84b" : "#3dbf84"}
              />
              <DetailRow
                label="Stale"
                value={agent.drift.stale ? "YES" : "No"}
                valueColor={agent.drift.stale ? "#d4a84b" : "#3dbf84"}
              />
            </div>

            {/* Policy diff when policy_drift is true */}
            {agent.drift.policy_drift && (
              <div className="mt-4 rounded-md border border-[#c45c5c]/20 bg-[#c45c5c]/5 p-3">
                <p className="text-[9px] font-semibold uppercase tracking-wider text-[#c45c5c] mb-2">
                  Policy Version Mismatch
                </p>
                <div className="flex flex-col gap-1 text-[10px]">
                  <div className="flex items-baseline gap-2">
                    <span className="text-[#6f7f9a]/50 w-[70px] shrink-0">
                      Expected
                    </span>
                    <span className="font-mono text-[#3dbf84]">
                      {remotePolicyInfo?.policyHash ??
                        remotePolicyInfo?.version ??
                        "---"}
                    </span>
                  </div>
                  <div className="flex items-baseline gap-2">
                    <span className="text-[#6f7f9a]/50 w-[70px] shrink-0">
                      Actual
                    </span>
                    <span className="font-mono text-[#c45c5c]">
                      {agent.policy_version ?? "---"}
                    </span>
                  </div>
                </div>
              </div>
            )}

            {/* Quick Deploy button placeholder -- deploy logic wired in Task 2 */}
            {agent.drift.policy_drift && (
              <button
                type="button"
                data-testid="quick-deploy-btn"
                className="mt-3 flex items-center gap-1.5 rounded-md bg-[#d4a84b]/10 border border-[#d4a84b]/20 px-3 py-1.5 text-[10px] font-medium text-[#d4a84b] hover:bg-[#d4a84b]/15 transition-colors"
              >
                Quick Deploy
              </button>
            )}
          </div>
        </div>

        {/* Recent Activity card */}
        <div className="mt-4 rounded-lg border border-[#2d3240]/60 bg-[#0b0d13] p-4">
          <h3 className="text-[9px] font-semibold uppercase tracking-wider text-[#6f7f9a]/50 mb-3">
            Recent Activity
          </h3>

          {auditLoading && (
            <div className="flex items-center gap-2 py-6 justify-center text-[11px] text-[#6f7f9a]/50">
              <IconLoader2 size={14} className="animate-spin" />
              Loading audit events...
            </div>
          )}

          {auditError && (
            <div className="flex items-center gap-2 py-4 px-3 rounded-md bg-[#c45c5c]/5 border border-[#c45c5c]/15 text-[10px] text-[#c45c5c]">
              <IconAlertTriangle size={12} stroke={1.5} />
              {auditError}
            </div>
          )}

          {!auditLoading && !auditError && auditEvents.length === 0 && (
            <p className="text-[11px] text-[#6f7f9a]/40 py-4 text-center">
              No recent activity for this agent
            </p>
          )}

          {!auditLoading && !auditError && auditEvents.length > 0 && (
            <div className="overflow-auto">
              <table className="w-full min-w-[500px]">
                <thead>
                  <tr className="border-b border-[#2d3240]/40">
                    <th className="px-2 py-1.5 text-left text-[9px] uppercase tracking-wider text-[#6f7f9a]/50 font-semibold">
                      Timestamp
                    </th>
                    <th className="px-2 py-1.5 text-left text-[9px] uppercase tracking-wider text-[#6f7f9a]/50 font-semibold">
                      Action
                    </th>
                    <th className="px-2 py-1.5 text-left text-[9px] uppercase tracking-wider text-[#6f7f9a]/50 font-semibold">
                      Decision
                    </th>
                    <th className="px-2 py-1.5 text-left text-[9px] uppercase tracking-wider text-[#6f7f9a]/50 font-semibold">
                      Target
                    </th>
                  </tr>
                </thead>
                <tbody>
                  {auditEvents.map((evt) => (
                    <tr
                      key={evt.id}
                      className="border-b border-[#2d3240]/20 hover:bg-[#131721]/30"
                    >
                      <td className="px-2 py-1.5 text-[10px] font-mono text-[#6f7f9a]/60">
                        {relativeTime(evt.timestamp)}
                      </td>
                      <td className="px-2 py-1.5 text-[10px] font-mono text-[#ece7dc]/70">
                        {evt.action_type}
                      </td>
                      <td className="px-2 py-1.5">
                        <DecisionBadge decision={evt.decision} />
                      </td>
                      <td className="px-2 py-1.5 text-[10px] font-mono text-[#ece7dc]/50 truncate max-w-[200px]">
                        {evt.target ?? "---"}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}

// ---------------------------------------------------------------------------
// Subcomponents
// ---------------------------------------------------------------------------

function DetailRow({
  label,
  value,
  mono,
  valueColor,
}: {
  label: string;
  value: string;
  mono?: boolean;
  valueColor?: string;
}) {
  return (
    <div className="flex items-baseline gap-3 text-[10px]">
      <span className="text-[#6f7f9a]/50 shrink-0 w-[110px]">{label}</span>
      <span
        className={cn("text-[#ece7dc]/70 truncate", mono && "font-mono")}
        style={valueColor ? { color: valueColor } : undefined}
      >
        {value}
      </span>
    </div>
  );
}

function DecisionBadge({ decision }: { decision: string }) {
  const colorMap: Record<string, string> = {
    allow: "#3dbf84",
    deny: "#c45c5c",
    warn: "#d4a84b",
  };
  const color = colorMap[decision.toLowerCase()] ?? "#6f7f9a";

  return (
    <span
      className="rounded px-1.5 py-0.5 text-[8px] font-semibold uppercase"
      style={{
        backgroundColor: color + "15",
        color,
      }}
    >
      {decision}
    </span>
  );
}
