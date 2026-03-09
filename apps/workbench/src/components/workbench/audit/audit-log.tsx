import { useState, useEffect, useCallback, useMemo } from "react";
import {
  IconFileAnalytics,
  IconRefresh,
  IconChevronDown,
  IconChevronRight,
  IconDownload,
} from "@tabler/icons-react";
import { cn } from "@/lib/utils";
import { useFleetConnection } from "@/lib/workbench/use-fleet-connection";
import {
  fetchAuditEvents,
  type AuditEvent,
  type AuditFilters,
} from "@/lib/workbench/fleet-client";
import { Link } from "react-router-dom";

type TimeRange = "1h" | "24h" | "7d" | "30d";
type DecisionFilter = "all" | "allow" | "deny" | "warn";

const TIME_RANGE_MS: Record<TimeRange, number> = {
  "1h": 60 * 60 * 1000,
  "24h": 24 * 60 * 60 * 1000,
  "7d": 7 * 24 * 60 * 60 * 1000,
  "30d": 30 * 24 * 60 * 60 * 1000,
};

const ACTION_TYPES = [
  "all",
  "file_read",
  "file_write",
  "network_egress",
  "shell_command",
  "mcp_tool",
] as const;

const DECISION_COLORS: Record<string, string> = {
  allow: "#3dbf84",
  deny: "#c45c5c",
  warn: "#d4a84b",
};

const SEVERITY_COLORS: Record<string, string> = {
  critical: "#c45c5c",
  high: "#c45c5c",
  medium: "#d4a84b",
  low: "#3dbf84",
};

const TH =
  "px-3 py-2.5 text-left text-[9px] uppercase tracking-[0.08em] font-semibold text-[#6f7f9a]/50";

function formatTimestamp(iso: string): string {
  try {
    const d = new Date(iso);
    return d.toLocaleString(undefined, {
      month: "short",
      day: "numeric",
      hour: "2-digit",
      minute: "2-digit",
      second: "2-digit",
    });
  } catch {
    return iso;
  }
}

export function AuditLog() {
  const { connection, agents } = useFleetConnection();

  const [timeRange, setTimeRange] = useState<TimeRange>("24h");
  const [decisionFilter, setDecisionFilter] = useState<DecisionFilter>("all");
  const [actionFilter, setActionFilter] = useState<string>("all");
  const [agentFilter, setAgentFilter] = useState<string>("all");
  const [events, setEvents] = useState<AuditEvent[]>([]);
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [expandedId, setExpandedId] = useState<string | null>(null);

  const agentIds = useMemo(
    () => agents.map((a) => a.endpoint_agent_id),
    [agents],
  );

  const loadEvents = useCallback(async () => {
    if (!connection.connected) return;
    setIsLoading(true);
    setError(null);

    try {
      const since = new Date(
        Date.now() - TIME_RANGE_MS[timeRange],
      ).toISOString();

      const filters: AuditFilters = {
        since,
        limit: 500,
      };
      if (decisionFilter !== "all") filters.decision = decisionFilter;
      if (actionFilter !== "all") filters.action_type = actionFilter;
      if (agentFilter !== "all") filters.agent_id = agentFilter;

      const result = await fetchAuditEvents(connection, filters);
      setEvents(result);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to fetch events");
      setEvents([]);
    } finally {
      setIsLoading(false);
    }
  }, [connection, timeRange, decisionFilter, actionFilter, agentFilter]);

  useEffect(() => {
    if (connection.connected) {
      loadEvents();
    }
  }, [connection.connected, loadEvents]);

  const counts = useMemo(() => {
    let allow = 0;
    let deny = 0;
    let warn = 0;
    for (const e of events) {
      const d = e.decision.toLowerCase();
      if (d === "allow") allow++;
      else if (d === "deny") deny++;
      else if (d === "warn") warn++;
    }
    return { total: events.length, allow, deny, warn };
  }, [events]);

  const handleExport = useCallback(() => {
    const json = JSON.stringify(events, null, 2);
    const blob = new Blob([json], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const link = document.createElement("a");
    link.download = `audit-events-${timeRange}-${Date.now()}.json`;
    link.href = url;
    link.click();
    URL.revokeObjectURL(url);
  }, [events, timeRange]);

  if (!connection.connected) {
    return (
      <div className="flex h-full w-full flex-col items-center justify-center gap-4 bg-[#05060a]">
        <IconFileAnalytics size={32} className="text-[#6f7f9a]/30" />
        <div className="text-center">
          <p className="text-[13px] text-[#ece7dc]/70">
            Connect to fleet to view audit events
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
            <IconFileAnalytics
              size={18}
              className="text-[#d4a84b]"
              stroke={1.5}
            />
            <div>
              <h1 className="text-sm font-semibold text-[#ece7dc] tracking-[-0.01em]">
                Audit Log
              </h1>
              <p className="text-[11px] text-[#6f7f9a] mt-0.5">
                Policy evaluation events from the fleet
              </p>
            </div>
          </div>
          <div className="flex items-center gap-2">
            <button
              onClick={handleExport}
              disabled={events.length === 0}
              className={cn(
                "flex items-center gap-1.5 rounded-md border border-[#2d3240] px-3 py-1.5 text-[11px] transition-colors",
                events.length === 0
                  ? "text-[#6f7f9a]/20 cursor-not-allowed"
                  : "text-[#6f7f9a] hover:text-[#ece7dc] hover:border-[#d4a84b]/30",
              )}
            >
              <IconDownload size={13} stroke={1.5} />
              Export
            </button>
            <button
              onClick={loadEvents}
              disabled={isLoading}
              className={cn(
                "flex items-center gap-1.5 rounded-md border border-[#2d3240] px-3 py-1.5 text-[11px] transition-colors",
                isLoading
                  ? "text-[#6f7f9a]/40 cursor-not-allowed"
                  : "text-[#6f7f9a] hover:text-[#ece7dc] hover:border-[#d4a84b]/30",
              )}
            >
              <IconRefresh
                size={13}
                stroke={1.5}
                className={isLoading ? "animate-spin" : ""}
              />
              Fetch
            </button>
          </div>
        </div>
      </div>

      {/* Filter bar */}
      <div className="shrink-0 border-b border-[#2d3240]/60 px-6 py-3">
        <div className="flex flex-wrap items-center gap-4">
          <FilterGroup label="Time">
            {(["1h", "24h", "7d", "30d"] as TimeRange[]).map((tr) => (
              <FilterPill
                key={tr}
                label={tr}
                active={timeRange === tr}
                onClick={() => setTimeRange(tr)}
              />
            ))}
          </FilterGroup>

          <FilterGroup label="Decision">
            {(["all", "allow", "deny", "warn"] as DecisionFilter[]).map(
              (d) => (
                <FilterPill
                  key={d}
                  label={d}
                  active={decisionFilter === d}
                  onClick={() => setDecisionFilter(d)}
                />
              ),
            )}
          </FilterGroup>

          <FilterGroup label="Action">
            <select
              value={actionFilter}
              onChange={(e) => setActionFilter(e.target.value)}
              className="rounded border border-[#2d3240] bg-[#0b0d13] px-2 py-1 text-[10px] text-[#ece7dc] outline-none focus:border-[#d4a84b]/40"
            >
              {ACTION_TYPES.map((at) => (
                <option key={at} value={at}>
                  {at === "all" ? "All types" : at}
                </option>
              ))}
            </select>
          </FilterGroup>

          <FilterGroup label="Agent">
            <select
              value={agentFilter}
              onChange={(e) => setAgentFilter(e.target.value)}
              className="rounded border border-[#2d3240] bg-[#0b0d13] px-2 py-1 text-[10px] text-[#ece7dc] outline-none focus:border-[#d4a84b]/40 max-w-[180px] truncate"
            >
              <option value="all">All agents</option>
              {agentIds.map((id) => (
                <option key={id} value={id}>
                  {id}
                </option>
              ))}
            </select>
          </FilterGroup>
        </div>
      </div>

      {/* Summary stats */}
      <div className="shrink-0 border-b border-[#2d3240]/60 px-6 py-2 flex items-center gap-3">
        <StatBadge label="Total" count={counts.total} />
        <StatBadge label="Allow" count={counts.allow} color="#3dbf84" />
        <StatBadge label="Deny" count={counts.deny} color="#c45c5c" />
        <StatBadge label="Warn" count={counts.warn} color="#d4a84b" />
        {error && (
          <span className="ml-auto text-[10px] text-[#c45c5c]">{error}</span>
        )}
      </div>

      {/* Event table */}
      <div className="flex-1 overflow-auto">
        {isLoading && events.length === 0 ? (
          <div className="flex h-full items-center justify-center">
            <div className="flex flex-col items-center gap-3">
              <IconRefresh
                size={20}
                className="text-[#6f7f9a]/30 animate-spin"
              />
              <span className="text-[11px] text-[#6f7f9a]/40">
                Loading audit events...
              </span>
            </div>
          </div>
        ) : events.length === 0 ? (
          <div className="flex h-full items-center justify-center">
            <span className="text-[12px] text-[#6f7f9a]/40">
              No audit events found for the selected filters
            </span>
          </div>
        ) : (
          <table className="w-full min-w-[800px]">
            <thead className="sticky top-0 z-10 bg-[#0b0d13]">
              <tr className="border-b border-[#2d3240]/60">
                <th className={cn(TH, "w-8")} />
                <th className={TH}>Timestamp</th>
                <th className={TH}>Action</th>
                <th className={TH}>Target</th>
                <th className={TH}>Decision</th>
                <th className={TH}>Guard</th>
                <th className={TH}>Agent</th>
                <th className={TH}>Severity</th>
              </tr>
            </thead>
            <tbody>
              {events.map((event) => {
                const isExpanded = expandedId === event.id;

                return (
                  <EventRow
                    key={event.id}
                    event={event}
                    isExpanded={isExpanded}
                    onToggle={() =>
                      setExpandedId(isExpanded ? null : event.id)
                    }
                  />
                );
              })}
            </tbody>
          </table>
        )}
      </div>
    </div>
  );
}

function FilterGroup({
  label,
  children,
}: {
  label: string;
  children: React.ReactNode;
}) {
  return (
    <div className="flex items-center gap-1.5">
      <span className="text-[9px] uppercase tracking-[0.08em] text-[#6f7f9a]/40 mr-0.5">
        {label}
      </span>
      {children}
    </div>
  );
}

function FilterPill({
  label,
  active,
  onClick,
}: {
  label: string;
  active: boolean;
  onClick: () => void;
}) {
  return (
    <button
      onClick={onClick}
      className={cn(
        "rounded-md px-2 py-1 text-[10px] font-medium capitalize transition-colors",
        active
          ? "bg-[#d4a84b]/10 text-[#d4a84b]"
          : "text-[#6f7f9a]/50 hover:text-[#ece7dc] hover:bg-[#131721]/40",
      )}
    >
      {label}
    </button>
  );
}

function StatBadge({
  label,
  count,
  color,
}: {
  label: string;
  count: number;
  color?: string;
}) {
  return (
    <span
      className="flex items-center gap-1.5 rounded-md px-2 py-0.5 text-[10px]"
      style={{
        backgroundColor: color ? color + "10" : "#1a1f2e40",
        color: color ?? "#6f7f9a",
      }}
    >
      <span className="font-mono font-semibold">{count}</span>
      <span className="opacity-70">{label}</span>
    </span>
  );
}

function EventRow({
  event,
  isExpanded,
  onToggle,
}: {
  event: AuditEvent;
  isExpanded: boolean;
  onToggle: () => void;
}) {
  const decisionColor =
    DECISION_COLORS[event.decision.toLowerCase()] ?? "#6f7f9a";

  return (
    <>
      <tr
        onClick={onToggle}
        className={cn(
          "border-b border-[#2d3240]/30 cursor-pointer transition-colors",
          isExpanded ? "bg-[#131721]" : "hover:bg-[#0b0d13]",
        )}
      >
        <td className="px-3 py-2">
          {isExpanded ? (
            <IconChevronDown size={11} className="text-[#6f7f9a]/40" />
          ) : (
            <IconChevronRight size={11} className="text-[#6f7f9a]/40" />
          )}
        </td>

        <td className="px-3 py-2 font-mono text-[10px] text-[#ece7dc]/50 whitespace-nowrap">
          {formatTimestamp(event.timestamp)}
        </td>

        <td className="px-3 py-2">
          <span className="rounded border border-[#2d3240] bg-[#0b0d13] px-1.5 py-0.5 font-mono text-[9px] text-[#ece7dc]/60">
            {event.action_type}
          </span>
        </td>

        <td className="px-3 py-2 font-mono text-[10px] text-[#ece7dc]/50 truncate max-w-[200px]">
          {event.target ?? "---"}
        </td>

        <td className="px-3 py-2">
          <span
            className="rounded px-1.5 py-0.5 text-[9px] font-semibold uppercase"
            style={{
              backgroundColor: decisionColor + "15",
              color: decisionColor,
            }}
          >
            {event.decision}
          </span>
        </td>

        <td className="px-3 py-2 font-mono text-[10px] text-[#6f7f9a]/60 truncate max-w-[140px]">
          {event.guard ?? "---"}
        </td>

        <td className="px-3 py-2 font-mono text-[10px] text-[#6f7f9a]/60 truncate max-w-[140px]">
          {event.agent_id ?? "---"}
        </td>

        <td className="px-3 py-2">
          {event.severity ? (
            <SeverityBadge severity={event.severity} />
          ) : (
            <span className="text-[10px] text-[#6f7f9a]/20">---</span>
          )}
        </td>
      </tr>

      {isExpanded && (
        <tr className="border-b border-[#2d3240]/30">
          <td colSpan={8} className="bg-[#0b0d13] px-6 py-4">
            <EventDetail event={event} />
          </td>
        </tr>
      )}
    </>
  );
}

function SeverityBadge({ severity }: { severity: string }) {
  const color = SEVERITY_COLORS[severity.toLowerCase()] ?? "#6f7f9a";

  return (
    <span
      className="rounded px-1.5 py-0.5 text-[8px] font-semibold uppercase"
      style={{
        backgroundColor: color + "15",
        color,
      }}
    >
      {severity}
    </span>
  );
}

function EventDetail({ event }: { event: AuditEvent }) {
  return (
    <div className="flex gap-8">
      <div className="flex flex-col gap-2 min-w-[220px]">
        <h4 className="text-[9px] font-semibold uppercase tracking-[0.1em] text-[#6f7f9a]/50 mb-1">
          Event Info
        </h4>
        <DetailRow label="Event ID" value={event.id} mono />
        <DetailRow label="Timestamp" value={new Date(event.timestamp).toLocaleString()} />
        <DetailRow label="Action" value={event.action_type} mono />
        <DetailRow label="Target" value={event.target ?? "---"} mono />
        <DetailRow label="Decision" value={event.decision} />
        <DetailRow label="Guard" value={event.guard ?? "---"} mono />
        <DetailRow label="Agent" value={event.agent_id ?? "---"} mono />
        <DetailRow label="Session" value={event.session_id ?? "---"} mono />
        {event.severity && (
          <DetailRow label="Severity" value={event.severity} />
        )}
      </div>

      {event.metadata && Object.keys(event.metadata).length > 0 && (
        <div className="flex-1 min-w-[300px]">
          <h4 className="text-[9px] font-semibold uppercase tracking-[0.1em] text-[#6f7f9a]/50 mb-2">
            Metadata
          </h4>
          <pre className="rounded border border-[#2d3240]/60 bg-[#05060a] p-3 text-[10px] font-mono text-[#ece7dc]/50 overflow-auto max-h-[240px] whitespace-pre-wrap break-all">
            {JSON.stringify(event.metadata, null, 2)}
          </pre>
        </div>
      )}
    </div>
  );
}

function DetailRow({
  label,
  value,
  mono,
}: {
  label: string;
  value: string;
  mono?: boolean;
}) {
  return (
    <div className="flex items-baseline gap-3 text-[10px]">
      <span className="text-[#6f7f9a]/50 shrink-0 w-[80px]">{label}</span>
      <span
        className={cn("text-[#ece7dc]/70 truncate", mono && "font-mono")}
      >
        {value}
      </span>
    </div>
  );
}
