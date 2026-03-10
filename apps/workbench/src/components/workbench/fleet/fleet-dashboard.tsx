import { useState, useEffect, useCallback, useMemo } from "react";
import {
  IconServer,
  IconRefresh,
  IconChevronDown,
  IconChevronRight,
  IconArrowsSort,
} from "@tabler/icons-react";
import { cn } from "@/lib/utils";
import { useFleetConnection } from "@/lib/workbench/use-fleet-connection";
import type { AgentInfo } from "@/lib/workbench/fleet-client";
import { Link } from "react-router-dom";

const STALE_THRESHOLD_SECS = 90;
const AUTO_REFRESH_MS = 60_000;

type StatusFilter = "all" | "online" | "stale" | "drift";
type SortColumn =
  | "status"
  | "agent_id"
  | "posture"
  | "policy_version"
  | "daemon_version"
  | "last_heartbeat"
  | "runtimes"
  | "drift";

const POSTURE_COLORS: Record<string, string> = {
  strict: "#3dbf84",
  default: "#d4a84b",
  permissive: "#c45c5c",
};

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

const STATUS_DOT_COLORS: Record<string, string> = {
  online: "#3dbf84",
  stale: "#d4a84b",
  offline: "#c45c5c",
};

export function FleetDashboard() {
  const { connection, agents, refreshAgents } = useFleetConnection();

  const [filter, setFilter] = useState<StatusFilter>("all");
  const [sortCol, setSortCol] = useState<SortColumn>("agent_id");
  const [sortAsc, setSortAsc] = useState(true);
  const [expandedId, setExpandedId] = useState<string | null>(null);
  const [isRefreshing, setIsRefreshing] = useState(false);

  useEffect(() => {
    if (!connection.connected) return;
    const timer = setInterval(() => {
      refreshAgents();
    }, AUTO_REFRESH_MS);
    return () => clearInterval(timer);
  }, [connection.connected, refreshAgents]);

  const handleRefresh = useCallback(async () => {
    setIsRefreshing(true);
    await refreshAgents();
    setIsRefreshing(false);
  }, [refreshAgents]);

  const counts = useMemo(() => {
    let online = 0;
    let stale = 0;
    let policyDrift = 0;
    for (const a of agents) {
      const s = agentStatus(a);
      if (s === "online") online++;
      if (s === "stale") stale++;
      if (a.drift.policy_drift) policyDrift++;
    }
    return { total: agents.length, online, stale, policyDrift };
  }, [agents]);

  const activePolicyVersion = useMemo(() => {
    const freq = new Map<string, number>();
    for (const a of agents) {
      const v = a.policy_version ?? "unknown";
      freq.set(v, (freq.get(v) ?? 0) + 1);
    }
    let best = "---";
    let bestCount = 0;
    for (const [v, c] of freq) {
      if (c > bestCount) {
        best = v;
        bestCount = c;
      }
    }
    return best;
  }, [agents]);

  const filteredAgents = useMemo(() => {
    let list = [...agents];
    if (filter === "online")
      list = list.filter((a) => agentStatus(a) === "online");
    if (filter === "stale")
      list = list.filter((a) => agentStatus(a) === "stale");
    if (filter === "drift")
      list = list.filter((a) => a.drift.policy_drift || a.drift.daemon_drift);

    list.sort((a, b) => {
      let cmp = 0;
      switch (sortCol) {
        case "status": {
          const order = { online: 0, stale: 1, offline: 2 };
          cmp = order[agentStatus(a)] - order[agentStatus(b)];
          break;
        }
        case "agent_id":
          cmp = a.endpoint_agent_id.localeCompare(b.endpoint_agent_id);
          break;
        case "posture":
          cmp = (a.posture ?? "").localeCompare(b.posture ?? "");
          break;
        case "policy_version":
          cmp = (a.policy_version ?? "").localeCompare(b.policy_version ?? "");
          break;
        case "daemon_version":
          cmp = (a.daemon_version ?? "").localeCompare(b.daemon_version ?? "");
          break;
        case "last_heartbeat":
          cmp =
            new Date(a.last_heartbeat_at).getTime() -
            new Date(b.last_heartbeat_at).getTime();
          break;
        case "runtimes":
          cmp = (a.runtime_count ?? 0) - (b.runtime_count ?? 0);
          break;
        case "drift": {
          const driftScore = (x: AgentInfo) =>
            (x.drift.policy_drift ? 2 : 0) + (x.drift.daemon_drift ? 1 : 0);
          cmp = driftScore(a) - driftScore(b);
          break;
        }
      }
      return sortAsc ? cmp : -cmp;
    });

    return list;
  }, [agents, filter, sortCol, sortAsc]);

  const handleSort = useCallback(
    (col: SortColumn) => {
      if (sortCol === col) {
        setSortAsc((prev) => !prev);
      } else {
        setSortCol(col);
        setSortAsc(true);
      }
    },
    [sortCol],
  );

  if (!connection.connected) {
    return (
      <div className="flex h-full w-full flex-col items-center justify-center gap-4 bg-[#05060a]">
        <IconServer size={32} className="text-[#6f7f9a]/30" />
        <div className="text-center">
          <p className="text-[13px] text-[#ece7dc]/70">
            Connect to fleet to view agents
          </p>
          <p className="mt-1 text-[11px] text-[#6f7f9a]/50">
            Configure your hushd connection in{" "}
            <Link
              to="/settings"
              className="text-[#d4a84b] hover:text-[#d4a84b]/80 underline underline-offset-2"
            >
              Settings
            </Link>
          </p>
        </div>
      </div>
    );
  }

  return (
    <div className="flex h-full w-full flex-col overflow-hidden bg-[#05060a]">
      {/* Header */}
      <div className="shrink-0 border-b border-[#2d3240]/60 px-6 py-4">
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-3">
            <IconServer size={18} className="text-[#d4a84b]" stroke={1.5} />
            <div>
              <h1 className="text-sm font-semibold text-[#ece7dc] tracking-[-0.01em]">
                Fleet Dashboard
              </h1>
              <p className="text-[11px] text-[#6f7f9a] mt-0.5">
                {counts.total} agent{counts.total !== 1 ? "s" : ""} registered
              </p>
            </div>
          </div>
          <button
            onClick={handleRefresh}
            disabled={isRefreshing}
            className={cn(
              "flex items-center gap-1.5 rounded-md border border-[#2d3240] px-3 py-1.5 text-[11px] transition-colors",
              isRefreshing
                ? "text-[#6f7f9a]/40 cursor-not-allowed"
                : "text-[#6f7f9a] hover:text-[#ece7dc] hover:border-[#d4a84b]/30",
            )}
          >
            <IconRefresh
              size={13}
              stroke={1.5}
              className={isRefreshing ? "animate-spin" : ""}
            />
            Refresh
          </button>
        </div>
      </div>

      {/* Summary cards */}
      <div className="shrink-0 border-b border-[#2d3240]/60 px-6 py-4">
        <div className="flex items-stretch gap-3">
          <SummaryCard label="Total Agents" value={counts.total} />
          <SummaryCard
            label="Online"
            value={counts.online}
            dotColor="#3dbf84"
          />
          <SummaryCard
            label="Stale"
            value={counts.stale}
            dotColor="#d4a84b"
          />
          <SummaryCard
            label="Policy Drift"
            value={counts.policyDrift}
            dotColor="#c45c5c"
          />
          <SummaryCard
            label="Active Policy"
            value={activePolicyVersion}
            mono
          />
        </div>
      </div>

      {/* Filter bar */}
      <div className="shrink-0 border-b border-[#2d3240]/60 px-6 py-2.5 flex items-center gap-2">
        <span className="text-[10px] uppercase tracking-[0.08em] text-[#6f7f9a]/50 mr-1">
          Filter
        </span>
        {(["all", "online", "stale", "drift"] as StatusFilter[]).map((f) => (
          <button
            key={f}
            onClick={() => setFilter(f)}
            className={cn(
              "rounded-md px-2.5 py-1 text-[10px] font-medium capitalize transition-colors",
              filter === f
                ? "bg-[#d4a84b]/10 text-[#d4a84b]"
                : "text-[#6f7f9a]/60 hover:text-[#ece7dc] hover:bg-[#131721]/40",
            )}
          >
            {f}
          </button>
        ))}
        <span className="ml-auto text-[10px] text-[#6f7f9a]/40">
          {filteredAgents.length} result{filteredAgents.length !== 1 ? "s" : ""}
        </span>
      </div>

      {/* Agent table */}
      <div className="flex-1 overflow-auto">
        <table className="w-full min-w-[900px]">
          <thead className="sticky top-0 z-10 bg-[#0b0d13]">
            <tr className="border-b border-[#2d3240]/60">
              <SortableHeader
                label=""
                column="status"
                currentSort={sortCol}
                asc={sortAsc}
                onSort={handleSort}
                className="w-10"
              />
              <SortableHeader
                label="Agent ID"
                column="agent_id"
                currentSort={sortCol}
                asc={sortAsc}
                onSort={handleSort}
              />
              <SortableHeader
                label="Posture"
                column="posture"
                currentSort={sortCol}
                asc={sortAsc}
                onSort={handleSort}
              />
              <SortableHeader
                label="Policy"
                column="policy_version"
                currentSort={sortCol}
                asc={sortAsc}
                onSort={handleSort}
              />
              <SortableHeader
                label="Daemon"
                column="daemon_version"
                currentSort={sortCol}
                asc={sortAsc}
                onSort={handleSort}
              />
              <SortableHeader
                label="Last Heartbeat"
                column="last_heartbeat"
                currentSort={sortCol}
                asc={sortAsc}
                onSort={handleSort}
              />
              <SortableHeader
                label="Runtimes"
                column="runtimes"
                currentSort={sortCol}
                asc={sortAsc}
                onSort={handleSort}
              />
              <SortableHeader
                label="Drift"
                column="drift"
                currentSort={sortCol}
                asc={sortAsc}
                onSort={handleSort}
              />
            </tr>
          </thead>
          <tbody>
            {filteredAgents.map((agent) => {
              const status = agentStatus(agent);
              const isExpanded = expandedId === agent.endpoint_agent_id;

              return (
                <AgentRow
                  key={agent.endpoint_agent_id}
                  agent={agent}
                  status={status}
                  isExpanded={isExpanded}
                  onToggle={() =>
                    setExpandedId(
                      isExpanded ? null : agent.endpoint_agent_id,
                    )
                  }
                />
              );
            })}
            {filteredAgents.length === 0 && (
              <tr>
                <td
                  colSpan={8}
                  className="py-12 text-center text-[12px] text-[#6f7f9a]/40"
                >
                  No agents match the current filter
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
}

function SummaryCard({
  label,
  value,
  dotColor,
  mono,
}: {
  label: string;
  value: number | string;
  dotColor?: string;
  mono?: boolean;
}) {
  return (
    <div className="flex flex-col rounded-lg border border-[#2d3240]/60 bg-[#0b0d13] px-4 py-3 min-w-[120px]">
      <span className="text-[9px] uppercase tracking-[0.08em] text-[#6f7f9a]/50">
        {label}
      </span>
      <div className="mt-1.5 flex items-center gap-2">
        {dotColor && (
          <span
            className="h-2 w-2 rounded-full shrink-0"
            style={{ backgroundColor: dotColor }}
          />
        )}
        <span
          className={cn(
            "text-[18px] font-semibold text-[#ece7dc]",
            mono && "font-mono text-[14px]",
          )}
        >
          {value}
        </span>
      </div>
    </div>
  );
}

function SortableHeader({
  label,
  column,
  currentSort,
  asc,
  onSort,
  className,
}: {
  label: string;
  column: SortColumn;
  currentSort: SortColumn;
  asc: boolean;
  onSort: (col: SortColumn) => void;
  className?: string;
}) {
  const active = currentSort === column;

  return (
    <th
      className={cn(
        "px-3 py-2.5 text-left text-[9px] uppercase tracking-[0.08em] font-semibold select-none cursor-pointer transition-colors",
        active ? "text-[#d4a84b]" : "text-[#6f7f9a]/50 hover:text-[#6f7f9a]",
        className,
      )}
      onClick={() => onSort(column)}
    >
      <span className="flex items-center gap-1">
        {label}
        {active && (
          <IconArrowsSort
            size={10}
            className={cn("transition-transform", !asc && "rotate-180")}
          />
        )}
      </span>
    </th>
  );
}

function AgentRow({
  agent,
  status,
  isExpanded,
  onToggle,
}: {
  agent: AgentInfo;
  status: "online" | "stale" | "offline";
  isExpanded: boolean;
  onToggle: () => void;
}) {
  const dotColor = STATUS_DOT_COLORS[status];
  const postureColor =
    POSTURE_COLORS[agent.posture?.toLowerCase() ?? ""] ?? "#6f7f9a";

  return (
    <>
      <tr
        onClick={onToggle}
        className={cn(
          "border-b border-[#2d3240]/30 cursor-pointer transition-colors",
          isExpanded
            ? "bg-[#131721]"
            : "hover:bg-[#0b0d13]",
        )}
      >
        <td className="px-3 py-2.5 text-center">
          <span
            className="inline-block h-2 w-2 rounded-full"
            style={{ backgroundColor: dotColor }}
          />
        </td>

        <td className="px-3 py-2.5">
          <div className="flex items-center gap-1.5">
            {isExpanded ? (
              <IconChevronDown size={11} className="text-[#6f7f9a]/40 shrink-0" />
            ) : (
              <IconChevronRight size={11} className="text-[#6f7f9a]/40 shrink-0" />
            )}
            <span className="font-mono text-[11px] text-[#ece7dc]/80 truncate max-w-[200px]">
              {agent.endpoint_agent_id}
            </span>
          </div>
        </td>

        <td className="px-3 py-2.5">
          {agent.posture ? (
            <span
              className="rounded px-1.5 py-0.5 text-[9px] font-medium uppercase"
              style={{
                backgroundColor: postureColor + "15",
                color: postureColor,
              }}
            >
              {agent.posture}
            </span>
          ) : (
            <span className="text-[10px] text-[#6f7f9a]/30">---</span>
          )}
        </td>

        <td className="px-3 py-2.5 font-mono text-[10px] text-[#ece7dc]/50">
          {agent.policy_version ?? "---"}
        </td>

        <td className="px-3 py-2.5 font-mono text-[10px] text-[#ece7dc]/50">
          {agent.daemon_version ?? "---"}
        </td>

        <td className="px-3 py-2.5 font-mono text-[10px] text-[#6f7f9a]/60">
          {relativeTime(agent.last_heartbeat_at)}
        </td>

        <td className="px-3 py-2.5 text-center font-mono text-[10px] text-[#ece7dc]/50">
          {agent.runtime_count ?? 0}
        </td>

        <td className="px-3 py-2.5">
          <div className="flex gap-1">
            {agent.drift.policy_drift && (
              <DriftBadge label="policy" color="#c45c5c" />
            )}
            {agent.drift.daemon_drift && (
              <DriftBadge label="daemon" color="#d4a84b" />
            )}
            {agent.drift.stale && (
              <DriftBadge label="stale" color="#6f7f9a" />
            )}
            {!agent.drift.policy_drift &&
              !agent.drift.daemon_drift &&
              !agent.drift.stale && (
                <span className="text-[10px] text-[#6f7f9a]/20">---</span>
              )}
          </div>
        </td>
      </tr>

      {isExpanded && (
        <tr className="border-b border-[#2d3240]/30">
          <td colSpan={8} className="bg-[#0b0d13] px-6 py-4">
            <AgentDetail agent={agent} />
          </td>
        </tr>
      )}
    </>
  );
}

function AgentDetail({ agent }: { agent: AgentInfo }) {
  const absTime = new Date(agent.last_heartbeat_at).toLocaleString();

  return (
    <div className="flex gap-8">
      <div className="flex flex-col gap-2 min-w-[240px]">
        <DetailSectionLabel text="Agent Info" />
        <DetailRow label="Agent ID" value={agent.endpoint_agent_id} mono />
        <DetailRow label="Posture" value={agent.posture ?? "---"} />
        <DetailRow label="Policy Version" value={agent.policy_version ?? "---"} mono />
        <DetailRow label="Daemon Version" value={agent.daemon_version ?? "---"} mono />
        <DetailRow label="Session ID" value={agent.last_session_id ?? "---"} mono />
        <DetailRow label="Last Seen IP" value={agent.last_seen_ip ?? "---"} mono />
        <DetailRow
          label="Last Heartbeat"
          value={`${relativeTime(agent.last_heartbeat_at)} (${absTime})`}
        />
      </div>

      <div className="flex flex-col gap-2 min-w-[180px]">
        <DetailSectionLabel text="Drift Flags" />
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

      <div className="flex flex-col gap-2 min-w-[140px]">
        <DetailSectionLabel text="Runtimes" />
        <div className="text-[11px] text-[#ece7dc]/50 font-mono">
          {agent.runtime_count ?? 0} registered
        </div>
      </div>
    </div>
  );
}

function DriftBadge({ label, color }: { label: string; color: string }) {
  return (
    <span
      className="rounded px-1.5 py-0.5 text-[8px] font-semibold uppercase"
      style={{
        backgroundColor: color + "15",
        color,
      }}
    >
      {label}
    </span>
  );
}

function DetailSectionLabel({ text }: { text: string }) {
  return (
    <h4 className="text-[9px] font-semibold uppercase tracking-[0.1em] text-[#6f7f9a]/50 mb-1">
      {text}
    </h4>
  );
}

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
      <span className="text-[#6f7f9a]/50 shrink-0 w-[100px]">{label}</span>
      <span
        className={cn(
          "text-[#ece7dc]/70 truncate",
          mono && "font-mono",
        )}
        style={valueColor ? { color: valueColor } : undefined}
      >
        {value}
      </span>
    </div>
  );
}
