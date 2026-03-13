import { useState, useEffect, useCallback, useMemo } from "react";
import {
  IconFileAnalytics,
  IconRefresh,
  IconChevronDown,
  IconChevronRight,
  IconDownload,
  IconTrash,
  IconCircleDot,
  IconDeviceDesktop,
} from "@tabler/icons-react";
import { cn } from "@/lib/utils";
import {
  Select,
  SelectTrigger,
  SelectValue,
  SelectContent,
  SelectItem,
} from "@/components/ui/select";
import { useFleetConnection } from "@/lib/workbench/use-fleet-connection";
import {
  fetchAuditEvents,
  type AuditEvent,
  type AuditFilters,
} from "@/lib/workbench/fleet-client";
import { useLocalAudit, type LocalAuditEvent } from "@/lib/workbench/local-audit";
import { Link } from "react-router-dom";

type TimeRange = "1h" | "24h" | "7d" | "30d";
type DecisionFilter = "all" | "allow" | "deny" | "warn";
type EventSourceMode = "auto" | "local" | "fleet";

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

// Map local audit event types to decision-like badges for visual consistency
const LOCAL_EVENT_TYPE_COLORS: Record<string, string> = {
  "policy.validation.success": "#3dbf84",
  "policy.validation.failure": "#c45c5c",
  "policy.validation.warnings": "#d4a84b",
  "simulation.run": "#d4a84b",
  "simulation.batch": "#d4a84b",
  "receipt.sign": "#3dbf84",
  "receipt.generate": "#d4a84b",
  "receipt.import": "#3dbf84",
  "policy.export": "#3dbf84",
  "policy.import": "#3dbf84",
  "policy.import.file": "#3dbf84",
  "policy.import.paste": "#3dbf84",
  "fleet.connected": "#3dbf84",
  "fleet.disconnected": "#c45c5c",
  "fleet.deploy": "#d4a84b",
  "fleet.deploy.success": "#3dbf84",
  "fleet.deploy.failure": "#c45c5c",
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

// ---------------------------------------------------------------------------
// Unified event type used in the table (can be fleet or local)
// ---------------------------------------------------------------------------

interface UnifiedAuditEvent {
  id: string;
  timestamp: string;
  isLocal: boolean;
  // Fleet event fields (when isLocal=false)
  action_type?: string;
  target?: string;
  decision?: string;
  guard?: string;
  severity?: string;
  session_id?: string;
  agent_id?: string;
  metadata?: Record<string, unknown>;
  // Local event fields (when isLocal=true)
  eventType?: string;
  source?: string;
  summary?: string;
  details?: Record<string, unknown>;
}

function fleetToUnified(e: AuditEvent): UnifiedAuditEvent {
  return { ...e, isLocal: false };
}

function localToUnified(e: LocalAuditEvent): UnifiedAuditEvent {
  return {
    id: e.id,
    timestamp: e.timestamp,
    isLocal: true,
    eventType: e.eventType,
    source: e.source,
    summary: e.summary,
    details: e.details,
  };
}

// ---------------------------------------------------------------------------
// Main Component
// ---------------------------------------------------------------------------

export function AuditLog() {
  const { connection, agents } = useFleetConnection();
  const { events: localEvents, clear: clearLocalEvents } = useLocalAudit();

  const [sourceMode, setSourceMode] = useState<EventSourceMode>("auto");
  const [timeRange, setTimeRange] = useState<TimeRange>("24h");
  const [decisionFilter, setDecisionFilter] = useState<DecisionFilter>("all");
  const [actionFilter, setActionFilter] = useState<string>("all");
  const [agentFilter, setAgentFilter] = useState<string>("all");
  const [fleetEvents, setFleetEvents] = useState<AuditEvent[]>([]);
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [expandedId, setExpandedId] = useState<string | null>(null);

  const agentIds = useMemo(
    () => agents.map((a) => a.endpoint_agent_id),
    [agents],
  );

  // Determine which source to show
  const showFleet =
    sourceMode === "fleet" || (sourceMode === "auto" && connection.connected);
  const showLocal =
    sourceMode === "local" || (sourceMode === "auto" && !connection.connected);

  const loadFleetEvents = useCallback(async () => {
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
      setFleetEvents(result);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to fetch events");
      setFleetEvents([]);
    } finally {
      setIsLoading(false);
    }
  }, [connection, timeRange, decisionFilter, actionFilter, agentFilter]);

  useEffect(() => {
    if (connection.connected && showFleet) {
      loadFleetEvents();
    }
  }, [connection.connected, showFleet, loadFleetEvents]);

  // Build unified event list
  const unifiedEvents = useMemo(() => {
    if (showFleet) {
      return fleetEvents.map(fleetToUnified);
    }
    // Filter local events by time range
    const since = Date.now() - TIME_RANGE_MS[timeRange];
    return localEvents
      .filter((e) => new Date(e.timestamp).getTime() >= since)
      .map(localToUnified);
  }, [showFleet, fleetEvents, localEvents, timeRange]);

  const counts = useMemo(() => {
    if (showFleet) {
      let allow = 0;
      let deny = 0;
      let warn = 0;
      for (const e of unifiedEvents) {
        const d = (e.decision ?? "").toLowerCase();
        if (d === "allow") allow++;
        else if (d === "deny") deny++;
        else if (d === "warn") warn++;
      }
      return { total: unifiedEvents.length, allow, deny, warn };
    }
    // For local events, count by source
    const sources: Record<string, number> = {};
    for (const e of unifiedEvents) {
      const s = e.source ?? "unknown";
      sources[s] = (sources[s] ?? 0) + 1;
    }
    return { total: unifiedEvents.length, ...sources };
  }, [unifiedEvents, showFleet]);

  const handleExport = useCallback(() => {
    const data = showFleet ? fleetEvents : localEvents;
    const json = JSON.stringify(data, null, 2);
    const blob = new Blob([json], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const link = document.createElement("a");
    link.download = `audit-events-${showFleet ? "fleet" : "local"}-${timeRange}-${Date.now()}.json`;
    link.href = url;
    link.click();
    URL.revokeObjectURL(url);
  }, [showFleet, fleetEvents, localEvents, timeRange]);

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
                {showFleet
                  ? "Policy evaluation events from the fleet"
                  : "Local workbench activity events"}
              </p>
            </div>

            {/* Source mode indicator */}
            <SourceBadge
              mode={showFleet ? "fleet" : "local"}
              connected={connection.connected}
            />
          </div>
          <div className="flex items-center gap-2">
            {/* Source selector */}
            <div className="flex items-center rounded-md border border-[#2d3240] overflow-hidden">
              {(["auto", "local", "fleet"] as EventSourceMode[]).map((mode) => (
                <button
                  key={mode}
                  onClick={() => setSourceMode(mode)}
                  disabled={mode === "fleet" && !connection.connected}
                  className={cn(
                    "px-2.5 py-1 text-[10px] font-medium capitalize transition-colors",
                    sourceMode === mode
                      ? "bg-[#d4a84b]/10 text-[#d4a84b]"
                      : mode === "fleet" && !connection.connected
                        ? "text-[#6f7f9a]/20 cursor-not-allowed"
                        : "text-[#6f7f9a]/50 hover:text-[#ece7dc] hover:bg-[#131721]/40",
                  )}
                >
                  {mode}
                </button>
              ))}
            </div>

            {/* Clear local events */}
            {showLocal && localEvents.length > 0 && (
              <button
                onClick={clearLocalEvents}
                className="flex items-center gap-1.5 rounded-md border border-[#2d3240] px-3 py-1.5 text-[11px] text-[#6f7f9a] hover:text-[#c45c5c] hover:border-[#c45c5c]/30 transition-colors"
              >
                <IconTrash size={13} stroke={1.5} />
                Clear
              </button>
            )}

            <button
              onClick={handleExport}
              disabled={unifiedEvents.length === 0}
              className={cn(
                "flex items-center gap-1.5 rounded-md border border-[#2d3240] px-3 py-1.5 text-[11px] transition-colors",
                unifiedEvents.length === 0
                  ? "text-[#6f7f9a]/20 cursor-not-allowed"
                  : "text-[#6f7f9a] hover:text-[#ece7dc] hover:border-[#d4a84b]/30",
              )}
            >
              <IconDownload size={13} stroke={1.5} />
              Export
            </button>

            {showFleet && (
              <button
                onClick={loadFleetEvents}
                disabled={isLoading || !connection.connected}
                className={cn(
                  "flex items-center gap-1.5 rounded-md border border-[#2d3240] px-3 py-1.5 text-[11px] transition-colors",
                  isLoading || !connection.connected
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
            )}
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

          {showFleet && (
            <>
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
                <Select value={actionFilter} onValueChange={(v) => { if (v !== null) setActionFilter(v); }}>
                  <SelectTrigger className="h-7 text-xs bg-[#131721] border-[#2d3240] text-[#ece7dc]">
                    <SelectValue placeholder="All types" />
                  </SelectTrigger>
                  <SelectContent className="bg-[#131721] border-[#2d3240]">
                    {ACTION_TYPES.map((at) => (
                      <SelectItem key={at} value={at} className="text-xs text-[#ece7dc]">
                        {at === "all" ? "All types" : at}
                      </SelectItem>
                    ))}
                  </SelectContent>
                </Select>
              </FilterGroup>

              <FilterGroup label="Agent">
                <Select value={agentFilter} onValueChange={(v) => { if (v !== null) setAgentFilter(v); }}>
                  <SelectTrigger className="h-7 text-xs bg-[#131721] border-[#2d3240] text-[#ece7dc] max-w-[180px]">
                    <SelectValue placeholder="All agents" />
                  </SelectTrigger>
                  <SelectContent className="bg-[#131721] border-[#2d3240]">
                    <SelectItem value="all" className="text-xs text-[#ece7dc]">All agents</SelectItem>
                    {agentIds.map((id) => (
                      <SelectItem key={id} value={id} className="text-xs text-[#ece7dc]">
                        {id}
                      </SelectItem>
                    ))}
                  </SelectContent>
                </Select>
              </FilterGroup>
            </>
          )}
        </div>
      </div>

      {/* Summary stats */}
      <div className="shrink-0 border-b border-[#2d3240]/60 px-6 py-2 flex items-center gap-3">
        <StatBadge label="Total" count={counts.total} />
        {showFleet ? (
          <>
            <StatBadge label="Allow" count={(counts as Record<string, number>).allow ?? 0} color="#3dbf84" />
            <StatBadge label="Deny" count={(counts as Record<string, number>).deny ?? 0} color="#c45c5c" />
            <StatBadge label="Warn" count={(counts as Record<string, number>).warn ?? 0} color="#d4a84b" />
          </>
        ) : (
          <>
            {(counts as Record<string, number>).simulator != null && (
              <StatBadge label="Simulator" count={(counts as Record<string, number>).simulator} color="#d4a84b" />
            )}
            {(counts as Record<string, number>).editor != null && (
              <StatBadge label="Editor" count={(counts as Record<string, number>).editor} color="#3dbf84" />
            )}
            {(counts as Record<string, number>).receipt != null && (
              <StatBadge label="Receipt" count={(counts as Record<string, number>).receipt} color="#d4a84b" />
            )}
            {(counts as Record<string, number>).deploy != null && (
              <StatBadge label="Deploy" count={(counts as Record<string, number>).deploy} color="#c45c5c" />
            )}
            {(counts as Record<string, number>).settings != null && (
              <StatBadge label="Settings" count={(counts as Record<string, number>).settings} color="#6f7f9a" />
            )}
          </>
        )}
        {error && (
          <span className="ml-auto text-[10px] text-[#c45c5c]">{error}</span>
        )}
      </div>

      {/* Event table */}
      <div className="flex-1 overflow-auto">
        {isLoading && showFleet && unifiedEvents.length === 0 ? (
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
        ) : unifiedEvents.length === 0 ? (
          <div className="flex h-full items-center justify-center">
            <div className="flex flex-col items-center gap-3">
              <IconFileAnalytics size={24} className="text-[#6f7f9a]/20" />
              <span className="text-[12px] text-[#6f7f9a]/40">
                {showLocal
                  ? "No local events recorded yet. Events are captured as you use the workbench."
                  : "No audit events found for the selected filters"}
              </span>
              {showLocal && !connection.connected && (
                <p className="text-[10px] text-[#6f7f9a]/30 max-w-[340px] text-center">
                  Connect to fleet in{" "}
                  <Link
                    to="/settings"
                    className="text-[#d4a84b] hover:text-[#d4a84b]/80 underline underline-offset-2"
                  >
                    Settings
                  </Link>{" "}
                  to view fleet events, or use the workbench to generate local events.
                </p>
              )}
            </div>
          </div>
        ) : showFleet ? (
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
              {unifiedEvents.map((event) => {
                const isExpanded = expandedId === event.id;

                return (
                  <FleetEventRow
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
        ) : (
          <table className="w-full min-w-[700px]">
            <thead className="sticky top-0 z-10 bg-[#0b0d13]">
              <tr className="border-b border-[#2d3240]/60">
                <th className={cn(TH, "w-8")} />
                <th className={TH}>Timestamp</th>
                <th className={TH}>Source</th>
                <th className={TH}>Event</th>
                <th className={TH}>Summary</th>
              </tr>
            </thead>
            <tbody>
              {unifiedEvents.map((event) => {
                const isExpanded = expandedId === event.id;

                return (
                  <LocalEventRow
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

// ---------------------------------------------------------------------------
// Source Badge
// ---------------------------------------------------------------------------

function SourceBadge({
  mode,
  connected,
}: {
  mode: "fleet" | "local";
  connected: boolean;
}) {
  if (mode === "fleet") {
    return (
      <span className="flex items-center gap-1.5 rounded-full px-2.5 py-0.5 text-[9px] font-mono uppercase tracking-wider bg-[#3dbf84]/10 text-[#3dbf84] border border-[#3dbf84]/20">
        <IconCircleDot size={8} stroke={2} />
        Fleet Events
      </span>
    );
  }

  return (
    <span className="flex items-center gap-1.5 rounded-full px-2.5 py-0.5 text-[9px] font-mono uppercase tracking-wider bg-[#d4a84b]/10 text-[#d4a84b] border border-[#d4a84b]/20">
      <IconDeviceDesktop size={10} stroke={1.5} />
      Local Events
    </span>
  );
}

// ---------------------------------------------------------------------------
// Shared sub-components
// ---------------------------------------------------------------------------

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

// ---------------------------------------------------------------------------
// Fleet Event Row (original design)
// ---------------------------------------------------------------------------

function FleetEventRow({
  event,
  isExpanded,
  onToggle,
}: {
  event: UnifiedAuditEvent;
  isExpanded: boolean;
  onToggle: () => void;
}) {
  const decisionColor =
    DECISION_COLORS[(event.decision ?? "").toLowerCase()] ?? "#6f7f9a";

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
            <FleetEventDetail event={event} />
          </td>
        </tr>
      )}
    </>
  );
}

// ---------------------------------------------------------------------------
// Local Event Row
// ---------------------------------------------------------------------------

const SOURCE_COLORS: Record<string, string> = {
  simulator: "#d4a84b",
  receipt: "#3dbf84",
  deploy: "#c45c5c",
  editor: "#6f7f9a",
  settings: "#6f7f9a",
};

function LocalEventRow({
  event,
  isExpanded,
  onToggle,
}: {
  event: UnifiedAuditEvent;
  isExpanded: boolean;
  onToggle: () => void;
}) {
  const sourceColor = SOURCE_COLORS[event.source ?? ""] ?? "#6f7f9a";
  const eventColor = LOCAL_EVENT_TYPE_COLORS[event.eventType ?? ""] ?? "#6f7f9a";

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
          <span
            className="rounded px-1.5 py-0.5 text-[9px] font-semibold uppercase"
            style={{
              backgroundColor: sourceColor + "15",
              color: sourceColor,
            }}
          >
            {event.source}
          </span>
        </td>

        <td className="px-3 py-2">
          <span
            className="rounded border bg-[#0b0d13] px-1.5 py-0.5 font-mono text-[9px]"
            style={{
              borderColor: eventColor + "30",
              color: eventColor,
            }}
          >
            {event.eventType}
          </span>
        </td>

        <td className="px-3 py-2 text-[10px] text-[#ece7dc]/60 truncate max-w-[400px]">
          {event.summary}
        </td>
      </tr>

      {isExpanded && (
        <tr className="border-b border-[#2d3240]/30">
          <td colSpan={5} className="bg-[#0b0d13] px-6 py-4">
            <LocalEventDetail event={event} />
          </td>
        </tr>
      )}
    </>
  );
}

// ---------------------------------------------------------------------------
// Detail panels
// ---------------------------------------------------------------------------

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

function FleetEventDetail({ event }: { event: UnifiedAuditEvent }) {
  return (
    <div className="flex gap-8">
      <div className="flex flex-col gap-2 min-w-[220px]">
        <h4 className="text-[9px] font-semibold uppercase tracking-[0.1em] text-[#6f7f9a]/50 mb-1">
          Event Info
        </h4>
        <DetailRow label="Event ID" value={event.id} mono />
        <DetailRow label="Timestamp" value={new Date(event.timestamp).toLocaleString()} />
        <DetailRow label="Action" value={event.action_type ?? "---"} mono />
        <DetailRow label="Target" value={event.target ?? "---"} mono />
        <DetailRow label="Decision" value={event.decision ?? "---"} />
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

function LocalEventDetail({ event }: { event: UnifiedAuditEvent }) {
  return (
    <div className="flex gap-8">
      <div className="flex flex-col gap-2 min-w-[220px]">
        <h4 className="text-[9px] font-semibold uppercase tracking-[0.1em] text-[#6f7f9a]/50 mb-1">
          Event Info
        </h4>
        <DetailRow label="Event ID" value={event.id} mono />
        <DetailRow label="Timestamp" value={new Date(event.timestamp).toLocaleString()} />
        <DetailRow label="Source" value={event.source ?? "---"} />
        <DetailRow label="Event Type" value={event.eventType ?? "---"} mono />
        <DetailRow label="Summary" value={event.summary ?? "---"} />
      </div>

      {event.details && Object.keys(event.details).length > 0 && (
        <div className="flex-1 min-w-[300px]">
          <h4 className="text-[9px] font-semibold uppercase tracking-[0.1em] text-[#6f7f9a]/50 mb-2">
            Details
          </h4>
          <pre className="rounded border border-[#2d3240]/60 bg-[#05060a] p-3 text-[10px] font-mono text-[#ece7dc]/50 overflow-auto max-h-[240px] whitespace-pre-wrap break-all">
            {JSON.stringify(event.details, null, 2)}
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
