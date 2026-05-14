import { useState, useMemo, useCallback, useRef, useEffect } from "react";
import { motion } from "motion/react";
import {
  IconActivity,
  IconChevronDown,
  IconChevronRight,
  IconFile,
  IconFileText,
  IconNetwork,
  IconTerminal,
  IconTool,
  IconPencil,
  IconMessage,
  IconSearch,
  IconAlertTriangle,
  IconShieldPlus,
} from "@tabler/icons-react";
import { cn } from "@/lib/utils";
import { VerdictBadge } from "@/components/workbench/shared/verdict-badge";
import {
  Select,
  SelectTrigger,
  SelectValue,
  SelectContent,
  SelectItem,
} from "@/components/ui/select";
import type {
  AgentEvent,
  StreamFilters,
  StreamStats,
  EventFlag,
} from "@/lib/workbench/hunt-types";
import type { TestActionType, Verdict } from "@/lib/workbench/types";


interface ActivityStreamProps {
  events: AgentEvent[];
  onEscalate: (eventIds: string[], note: string) => void;
  onFilterChange: (filters: StreamFilters) => void;
  onDraftDetection?: (events: AgentEvent[]) => void;
  filters: StreamFilters;
  stats: StreamStats;
  live: boolean;
  onToggleLive: () => void;
}


const ACTION_TYPE_ICONS: Record<TestActionType, typeof IconFile> = {
  file_access: IconFile,
  file_write: IconFileText,
  network_egress: IconNetwork,
  shell_command: IconTerminal,
  mcp_tool_call: IconTool,
  patch_apply: IconPencil,
  user_input: IconMessage,
};

const ACTION_TYPE_LABELS: Record<TestActionType, string> = {
  file_access: "file",
  file_write: "write",
  network_egress: "egress",
  shell_command: "shell",
  mcp_tool_call: "mcp",
  patch_apply: "patch",
  user_input: "input",
};

const ALL_ACTION_TYPES: TestActionType[] = [
  "file_access",
  "file_write",
  "network_egress",
  "shell_command",
  "mcp_tool_call",
  "patch_apply",
  "user_input",
];

const ALL_VERDICTS: Verdict[] = ["allow", "deny", "warn"];

const TIME_RANGES = ["1h", "6h", "24h", "7d"] as const;

const MAX_VISIBLE_EVENTS = 500;


interface AgentFilterOption {
  id: string;
  name: string;
}

function formatTime(iso: string): string {
  try {
    const d = new Date(iso);
    return d.toLocaleTimeString(undefined, {
      hour: "2-digit",
      minute: "2-digit",
      second: "2-digit",
      hour12: false,
    });
  } catch {
    return iso;
  }
}

function formatFullTimestamp(iso: string): string {
  try {
    return new Date(iso).toISOString();
  } catch {
    return iso;
  }
}

function truncateTarget(target: string, maxLen: number = 40): string {
  if (target.length <= maxLen) return target;
  return target.slice(0, maxLen - 1) + "\u2026";
}

function getAnomalyColor(score: number): string {
  if (score >= 0.9) return "#c45c5c";
  if (score >= 0.7) return "#d4a84b";
  return "#3dbf84";
}

/** Stable agent filter options keyed by agent ID and labeled by agent name. */
function extractAgentOptions(events: AgentEvent[]): AgentFilterOption[] {
  const options = new Map<string, string>();
  for (const e of events) {
    if (!options.has(e.agentId)) {
      options.set(e.agentId, e.agentName);
    }
  }
  return Array.from(options, ([id, name]) => ({ id, name })).sort((a, b) => {
    const nameOrder = a.name.localeCompare(b.name);
    return nameOrder !== 0 ? nameOrder : a.id.localeCompare(b.id);
  });
}


interface AnomalyCluster {
  agentName: string;
  sessionId: string;
  eventIds: string[];
}

/**
 * Detect consecutive runs of 3+ flagged events from the same session.
 * Returns cluster markers keyed by the index of the first event in the run.
 */
function detectAnomalyClusters(events: AgentEvent[]): Map<number, AnomalyCluster> {
  const clusters = new Map<number, AnomalyCluster>();
  let runStart = -1;
  let runSession = "";
  let runAgent = "";
  let runIds: string[] = [];

  for (let i = 0; i < events.length; i++) {
    const ev = events[i];
    const isFlagged =
      ev.flags.some((f) => f.type === "anomaly") ||
      (ev.anomalyScore !== undefined && ev.anomalyScore >= 0.7);

    if (isFlagged && ev.sessionId === runSession && runStart >= 0) {
      runIds.push(ev.id);
    } else if (isFlagged) {
      // Flush previous run if qualifying
      if (runIds.length >= 3) {
        clusters.set(runStart, {
          agentName: runAgent,
          sessionId: runSession,
          eventIds: runIds,
        });
      }
      runStart = i;
      runSession = ev.sessionId;
      runAgent = ev.agentName;
      runIds = [ev.id];
    } else {
      // Flush previous run if qualifying
      if (runIds.length >= 3) {
        clusters.set(runStart, {
          agentName: runAgent,
          sessionId: runSession,
          eventIds: runIds,
        });
      }
      runStart = -1;
      runSession = "";
      runAgent = "";
      runIds = [];
    }
  }

  // Flush trailing run
  if (runIds.length >= 3) {
    clusters.set(runStart, {
      agentName: runAgent,
      sessionId: runSession,
      eventIds: runIds,
    });
  }

  return clusters;
}


function applyFilters(events: AgentEvent[], filters: StreamFilters): AgentEvent[] {
  let result = events;

  if (filters.agentId) {
    result = result.filter((e) => e.agentId === filters.agentId);
  }

  if (filters.actionType) {
    result = result.filter((e) => e.actionType === filters.actionType);
  }

  if (filters.verdict) {
    result = result.filter((e) => e.verdict === filters.verdict);
  }

  if (filters.minAnomalyScore !== undefined && filters.minAnomalyScore > 0) {
    const threshold = filters.minAnomalyScore;
    result = result.filter(
      (e) => e.anomalyScore !== undefined && e.anomalyScore >= threshold,
    );
  }

  if (filters.search) {
    const q = filters.search.toLowerCase();
    result = result.filter(
      (e) =>
        e.target.toLowerCase().includes(q) ||
        e.agentName.toLowerCase().includes(q) ||
        e.actionType.toLowerCase().includes(q) ||
        (e.content && e.content.toLowerCase().includes(q)),
    );
  }

  return result;
}


export function ActivityStream({
  events,
  onEscalate,
  onFilterChange,
  onDraftDetection,
  filters,
  stats,
  live,
  onToggleLive,
}: ActivityStreamProps) {
  const [expandedId, setExpandedId] = useState<string | null>(null);
  const scrollRef = useRef<HTMLDivElement>(null);
  const wasAtBottomRef = useRef(true);

  const agentOptions = useMemo(() => extractAgentOptions(events), [events]);

  const filteredEvents = useMemo(
    () => applyFilters(events, filters).slice(0, MAX_VISIBLE_EVENTS),
    [events, filters],
  );

  const clusters = useMemo(
    () => detectAnomalyClusters(filteredEvents),
    [filteredEvents],
  );

  // Auto-scroll when live and user is already at the bottom
  useEffect(() => {
    const el = scrollRef.current;
    if (!el) return;

    if (live && wasAtBottomRef.current) {
      el.scrollTop = 0; // newest at top
    }
  }, [filteredEvents.length, live]);

  const handleScroll = useCallback(() => {
    const el = scrollRef.current;
    if (!el) return;
    wasAtBottomRef.current = el.scrollTop <= 4;
  }, []);

  const handleEscalateCluster = useCallback(
    (cluster: AnomalyCluster) => {
      onEscalate(
        cluster.eventIds,
        `Anomaly cluster detected: ${cluster.agentName} session #${cluster.sessionId.slice(0, 8)}`,
      );
    },
    [onEscalate],
  );

  const handleDraftFromCluster = useCallback(
    (cluster: AnomalyCluster) => {
      if (!onDraftDetection) return;
      const clusterEvents = events.filter((e) => cluster.eventIds.includes(e.id));
      onDraftDetection(clusterEvents);
    },
    [events, onDraftDetection],
  );

  const updateFilter = useCallback(
    <K extends keyof StreamFilters>(key: K, value: StreamFilters[K]) => {
      onFilterChange({ ...filters, [key]: value });
    },
    [filters, onFilterChange],
  );

  // Anomaly score slider value (0-100 for display, 0-1 internally)
  const anomalySliderValue = (filters.minAnomalyScore ?? 0) * 100;

  return (
    <div className="flex h-full w-full flex-col overflow-hidden bg-[#05060a]">
      {/* ----------------------------------------------------------------- */}
      {/* Top Bar                                                           */}
      {/* ----------------------------------------------------------------- */}
      <div className="shrink-0 border-b border-[#2d3240]/60 px-5 py-3">
        <div className="flex items-center gap-6">
          {/* Left: title + count + live */}
          <div className="flex items-center gap-3 shrink-0">
            <IconActivity size={16} className="text-[#d4a84b]" stroke={1.5} />
            <span className="text-sm font-semibold text-[#ece7dc] tracking-[-0.01em]">
              Activity Stream
            </span>
            <span
              data-testid="activity-stream-visible-count"
              className="rounded-md bg-[#131721] px-2 py-0.5 font-mono text-[10px] text-[#6f7f9a]"
            >
              {filteredEvents.length.toLocaleString()}
            </span>

            {/* Live toggle */}
            <button
              onClick={onToggleLive}
              className={cn(
                "flex items-center gap-1.5 rounded-full px-2.5 py-1 text-[10px] font-medium transition-colors border",
                live
                  ? "bg-[#3dbf84]/10 text-[#3dbf84] border-[#3dbf84]/20"
                  : "bg-[#131721] text-[#6f7f9a] border-[#2d3240] hover:text-[#ece7dc]",
              )}
            >
              <span
                className={cn(
                  "inline-block w-1.5 h-1.5 rounded-full",
                  live ? "bg-[#3dbf84] animate-pulse" : "bg-[#6f7f9a]/40",
                )}
              />
              {live ? "LIVE" : "PAUSED"}
            </button>
          </div>

          {/* Center: Filter pills */}
          <div className="flex items-center gap-3 flex-1 min-w-0 overflow-x-auto">
            {/* Agent dropdown */}
            <FilterGroup label="Agent">
              <Select
                value={filters.agentId ?? "__all__"}
                onValueChange={(v) => {
                  if (v !== null) updateFilter("agentId", v === "__all__" ? undefined : v);
                }}
              >
                <SelectTrigger
                  data-testid="activity-stream-agent-filter"
                  className="h-6 text-[10px] bg-[#131721] border-[#2d3240] text-[#ece7dc] min-w-[100px]"
                >
                  <SelectValue placeholder="All agents" />
                </SelectTrigger>
                <SelectContent className="bg-[#131721] border-[#2d3240]">
                  <SelectItem value="__all__" className="text-[10px] text-[#ece7dc]">
                    All agents
                  </SelectItem>
                  {agentOptions.map((agent) => (
                    <SelectItem
                      key={agent.id}
                      value={agent.id}
                      className="text-[10px] text-[#ece7dc]"
                    >
                      {agent.name}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </FilterGroup>

            {/* Action Type dropdown */}
            <FilterGroup label="Action">
              <Select
                value={filters.actionType ?? "__all__"}
                onValueChange={(v) => {
                  if (v !== null) updateFilter("actionType", v === "__all__" ? undefined : (v as TestActionType));
                }}
              >
                <SelectTrigger className="h-6 text-[10px] bg-[#131721] border-[#2d3240] text-[#ece7dc] min-w-[100px]">
                  <SelectValue placeholder="All types" />
                </SelectTrigger>
                <SelectContent className="bg-[#131721] border-[#2d3240]">
                  <SelectItem value="__all__" className="text-[10px] text-[#ece7dc]">
                    All types
                  </SelectItem>
                  {ALL_ACTION_TYPES.map((at) => (
                    <SelectItem key={at} value={at} className="text-[10px] text-[#ece7dc]">
                      {at}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </FilterGroup>

            {/* Verdict dropdown */}
            <FilterGroup label="Verdict">
              <Select
                value={filters.verdict ?? "__all__"}
                onValueChange={(v) => {
                  if (v !== null) updateFilter("verdict", v === "__all__" ? undefined : (v as Verdict));
                }}
              >
                <SelectTrigger className="h-6 text-[10px] bg-[#131721] border-[#2d3240] text-[#ece7dc] min-w-[80px]">
                  <SelectValue placeholder="All" />
                </SelectTrigger>
                <SelectContent className="bg-[#131721] border-[#2d3240]">
                  <SelectItem value="__all__" className="text-[10px] text-[#ece7dc]">
                    All
                  </SelectItem>
                  {ALL_VERDICTS.map((v) => (
                    <SelectItem key={v} value={v} className="text-[10px] text-[#ece7dc] uppercase">
                      {v}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </FilterGroup>

            {/* Anomaly score slider */}
            <FilterGroup label="Min Anomaly">
              <div className="flex items-center gap-2 min-w-[120px]">
                <input
                  type="range"
                  min={0}
                  max={100}
                  step={5}
                  value={anomalySliderValue}
                  onChange={(e) =>
                    updateFilter("minAnomalyScore", Number(e.target.value) / 100)
                  }
                  className="w-16 h-1 accent-[#d4a84b] cursor-pointer"
                />
                <span className="font-mono text-[9px] text-[#6f7f9a] w-7 text-right">
                  {anomalySliderValue > 0 ? `${(anomalySliderValue / 100).toFixed(2)}` : "off"}
                </span>
              </div>
            </FilterGroup>
          </div>

          {/* Right: Time range + search */}
          <div className="flex items-center gap-2 shrink-0">
            {/* Time range segmented control */}
            <div className="flex items-center rounded-md border border-[#2d3240] overflow-hidden">
              {TIME_RANGES.map((tr) => (
                <button
                  key={tr}
                  onClick={() => updateFilter("timeRange", tr)}
                  className={cn(
                    "px-2.5 py-1 text-[10px] font-medium transition-colors",
                    filters.timeRange === tr
                      ? "bg-[#d4a84b]/10 text-[#d4a84b]"
                      : "text-[#6f7f9a]/50 hover:text-[#ece7dc] hover:bg-[#131721]/40",
                  )}
                >
                  {tr}
                </button>
              ))}
            </div>

            {/* Search */}
            <div className="relative">
              <IconSearch
                size={12}
                className="absolute left-2 top-1/2 -translate-y-1/2 text-[#6f7f9a]/40"
                stroke={1.5}
              />
              <input
                type="text"
                value={filters.search ?? ""}
                onChange={(e) => updateFilter("search", e.target.value || undefined)}
                placeholder="Search events..."
                className="h-7 w-40 rounded-md border border-[#2d3240] bg-[#131721] pl-7 pr-2 text-[10px] text-[#ece7dc] placeholder:text-[#6f7f9a]/30 outline-none focus:border-[#d4a84b]/40 transition-colors"
              />
            </div>
          </div>
        </div>
      </div>

      {/* ----------------------------------------------------------------- */}
      {/* Main Event List                                                   */}
      {/* ----------------------------------------------------------------- */}
      <div
        ref={scrollRef}
        onScroll={handleScroll}
        className="flex-1 overflow-auto"
      >
        {filteredEvents.length === 0 ? (
          <div className="flex h-full items-center justify-center">
            <div className="flex flex-col items-center gap-3">
              <IconActivity size={24} className="text-[#6f7f9a]/50" />
              <span className="text-[12px] text-[#6f7f9a]/40">
                No events match the current filters
              </span>
            </div>
          </div>
        ) : (
          <div className="min-w-[800px]">
            {/* Column headers */}
            <div className="sticky top-0 z-10 flex items-center gap-0 bg-[#0b0d13] border-b border-[#2d3240]/60 px-3 py-2">
              <span className={TH_CELL + " w-[72px]"}>Time</span>
              <span className={TH_CELL + " w-[140px]"}>Agent</span>
              <span className={TH_CELL + " w-[64px]"}>Type</span>
              <span className={TH_CELL + " flex-1"}>Target</span>
              <span className={TH_CELL + " w-[60px]"}>Verdict</span>
              <span className={TH_CELL + " w-[60px] text-right"}>Anomaly</span>
              <span className="w-5" />
            </div>

            {/* Event rows */}
            {filteredEvents.map((event, idx) => {
              const cluster = clusters.get(idx);

              return (
                <motion.div
                  key={event.id}
                  initial={{ opacity: 0, x: -12 }}
                  animate={{ opacity: 1, x: 0 }}
                  transition={{ duration: 0.25, delay: Math.min(idx * 0.03, 0.3) }}
                >
                  {/* Cluster separator - shown before the first event in a cluster */}
                  {cluster && (
                    <ClusterSeparator
                      cluster={cluster}
                      onInvestigate={handleEscalateCluster}
                      onDraftDetection={onDraftDetection ? handleDraftFromCluster : undefined}
                    />
                  )}
                  <EventRow
                    event={event}
                    isExpanded={expandedId === event.id}
                    onToggle={() =>
                      setExpandedId(expandedId === event.id ? null : event.id)
                    }
                  />
                </motion.div>
              );
            })}
          </div>
        )}
      </div>

      {/* ----------------------------------------------------------------- */}
      {/* Bottom Stats Bar                                                  */}
      {/* ----------------------------------------------------------------- */}
      <div className="shrink-0 border-t border-[#2d3240]/60 px-5 py-2.5">
        <div className="flex items-center gap-3">
          <BottomStatCard
            label="ALLOW"
            count={stats.allowed}
            total={stats.total}
            color="#3dbf84"
          />
          <BottomStatCard
            label="DENY"
            count={stats.denied}
            total={stats.total}
            color="#c45c5c"
          />
          <BottomStatCard
            label="WARN"
            count={stats.warned}
            total={stats.total}
            color="#d4a84b"
          />
          <BottomStatCard
            label="ANOMALIES"
            count={stats.anomalies}
            total={stats.total}
            color="#c45c5c"
            pulse={stats.anomalies > 0}
          />

          {/* Draft Detection button — drafts a rule from all visible events */}
          {onDraftDetection && filteredEvents.length > 0 && (
            <motion.button
              whileTap={{ scale: 0.95 }}
              transition={{ type: "spring", bounce: 0.4, duration: 0.2 }}
              data-testid="activity-stream-draft-detection"
              onClick={() => onDraftDetection(filteredEvents)}
              className="ml-auto flex items-center gap-1.5 rounded-md border border-[#7c9aef]/25 bg-[#7c9aef]/10 px-3 py-1.5 text-[10px] font-medium text-[#7c9aef] hover:bg-[#7c9aef]/20 transition-colors"
            >
              <IconShieldPlus size={13} stroke={1.5} />
              Draft Detection
            </motion.button>
          )}
        </div>
      </div>
    </div>
  );
}


const TH_CELL =
  "text-[9px] uppercase tracking-wider font-semibold text-[#6f7f9a]/50 select-none";


function EventRow({
  event,
  isExpanded,
  onToggle,
}: {
  event: AgentEvent;
  isExpanded: boolean;
  onToggle: () => void;
}) {
  const ActionIcon = ACTION_TYPE_ICONS[event.actionType] ?? IconFile;
  const actionLabel = ACTION_TYPE_LABELS[event.actionType] ?? event.actionType;
  const showAnomaly =
    event.anomalyScore !== undefined && event.anomalyScore >= 0.7;

  return (
    <>
      <button
        type="button"
        onClick={onToggle}
        className={cn(
          "flex w-full items-center gap-0 px-3 py-2 text-left border-b border-[#2d3240]/20 cursor-pointer transition-colors",
          isExpanded
            ? "bg-[#131721] border-l-2 border-l-[#d4a84b]"
            : "hover:bg-[#131721] border-l-2 border-l-transparent",
        )}
      >
        {/* Timestamp */}
        <span className="w-[72px] shrink-0 font-mono text-[10px] text-[#ece7dc]/50 whitespace-nowrap">
          {formatTime(event.timestamp)}
        </span>

        {/* Agent name */}
        <span className="w-[140px] shrink-0 text-[10px] text-[#ece7dc]/70 font-medium truncate pr-2">
          {event.agentName}
        </span>

        {/* Action type with icon */}
        <span className="w-[64px] shrink-0 flex items-center gap-1.5">
          <ActionIcon size={12} className="text-[#6f7f9a]/60" stroke={1.5} />
          <span className="font-mono text-[9px] text-[#6f7f9a]/60">
            {actionLabel}
          </span>
        </span>

        {/* Target */}
        <span className="flex-1 min-w-0 font-mono text-[10px] text-[#ece7dc]/50 truncate pr-3">
          {truncateTarget(event.target)}
        </span>

        {/* Verdict */}
        <span className="w-[60px] shrink-0">
          <VerdictBadge verdict={event.verdict} />
        </span>

        {/* Anomaly score */}
        <span className="w-[60px] shrink-0 flex items-center justify-end gap-1.5">
          {showAnomaly && event.anomalyScore !== undefined && (
            <>
              <span
                className="inline-block w-2 h-2 rounded-full"
                style={{ backgroundColor: getAnomalyColor(event.anomalyScore) }}
              />
              <span
                className="font-mono text-[10px] font-medium"
                style={{ color: getAnomalyColor(event.anomalyScore) }}
              >
                {event.anomalyScore.toFixed(2)}
              </span>
            </>
          )}
        </span>

        {/* Expand chevron */}
        <span className="w-5 shrink-0 flex justify-end">
          {isExpanded ? (
            <IconChevronDown size={11} className="text-[#6f7f9a]/40" />
          ) : (
            <IconChevronRight size={11} className="text-[#6f7f9a]/40" />
          )}
        </span>
      </button>

      {/* Expanded detail panel */}
      {isExpanded && <EventDetail event={event} />}
    </>
  );
}


function EventDetail({ event }: { event: AgentEvent }) {
  return (
    <div className="bg-[#0b0d13] border-b border-[#2d3240]/40 px-6 py-4">
      <div className="flex gap-8">
        {/* Left: core info */}
        <div className="flex flex-col gap-2 min-w-[240px]">
          <DetailSectionHeader>Event Info</DetailSectionHeader>
          <DetailRow label="Full Target" value={event.target} mono />
          <DetailRow
            label="Timestamp"
            value={formatFullTimestamp(event.timestamp)}
            mono
          />
          <DetailRow label="Agent ID" value={event.agentId} mono />
          <DetailRow label="Session" value={event.sessionId} mono />
          <DetailRow label="Action Type" value={event.actionType} mono />
          <DetailRow label="Policy Ver" value={event.policyVersion} mono />
          {event.receiptId && (
            <DetailRow label="Receipt ID" value={event.receiptId} mono />
          )}
          {event.anomalyScore !== undefined && (
            <DetailRow
              label="Anomaly Score"
              value={event.anomalyScore.toFixed(4)}
              mono
            />
          )}
          {event.trustprintScore !== undefined && (
            <DetailRow
              label="Trustprint"
              value={event.trustprintScore.toFixed(4)}
              mono
              title="Embedding-based threat screening using vector similarity against known patterns"
            />
          )}
        </div>

        {/* Center: guard results */}
        <div className="flex-1 min-w-[280px]">
          <DetailSectionHeader>Guard Results</DetailSectionHeader>
          {event.guardResults.length === 0 ? (
            <span className="text-[10px] text-[#6f7f9a]/30">
              No guard results
            </span>
          ) : (
            <div className="space-y-1.5 max-h-[200px] overflow-auto">
              {event.guardResults.map((gr, i) => (
                <div
                  key={`${gr.guardId}-${i}`}
                  className="flex items-start gap-2 rounded border border-[#2d3240]/40 bg-[#05060a] px-3 py-2"
                >
                  <VerdictBadge verdict={gr.verdict} />
                  <div className="flex-1 min-w-0">
                    <span className="text-[10px] font-medium text-[#ece7dc]/70">
                      {gr.guardName}
                    </span>
                    <p className="text-[9px] text-[#6f7f9a]/60 mt-0.5 truncate">
                      {gr.message}
                    </p>
                  </div>
                  {gr.engine && (
                    <span className="shrink-0 rounded bg-[#131721] px-1.5 py-0.5 font-mono text-[8px] text-[#6f7f9a]/40">
                      {gr.engine}
                    </span>
                  )}
                </div>
              ))}
            </div>
          )}
        </div>

        {/* Right: flags */}
        {event.flags.length > 0 && (
          <div className="min-w-[180px]">
            <DetailSectionHeader>Flags</DetailSectionHeader>
            <div className="space-y-1.5">
              {event.flags.map((flag, i) => (
                <FlagBadge key={i} flag={flag} />
              ))}
            </div>
          </div>
        )}
      </div>
    </div>
  );
}


function FlagBadge({ flag }: { flag: EventFlag }) {
  switch (flag.type) {
    case "anomaly":
      return (
        <div className="flex items-center gap-2 rounded border border-[#c45c5c]/20 bg-[#c45c5c]/5 px-2 py-1.5">
          <IconAlertTriangle size={10} className="text-[#c45c5c] shrink-0" stroke={1.5} />
          <div className="min-w-0">
            <span className="text-[9px] font-medium text-[#c45c5c]">
              Anomaly ({flag.score.toFixed(2)})
            </span>
            <p className="text-[8px] text-[#c45c5c]/60 truncate">{flag.reason}</p>
          </div>
        </div>
      );
    case "escalated":
      return (
        <div className="flex items-center gap-2 rounded border border-[#d4a84b]/20 bg-[#d4a84b]/5 px-2 py-1.5">
          <span className="text-[9px] font-medium text-[#d4a84b]">
            Escalated by {flag.by}
          </span>
          {flag.note && (
            <span className="text-[8px] text-[#d4a84b]/60">{flag.note}</span>
          )}
        </div>
      );
    case "tag":
      return (
        <span
          className="inline-block rounded px-2 py-0.5 text-[9px] font-medium border"
          style={{
            borderColor: (flag.color ?? "#6f7f9a") + "30",
            color: flag.color ?? "#6f7f9a",
            backgroundColor: (flag.color ?? "#6f7f9a") + "10",
          }}
        >
          {flag.label}
        </span>
      );
    case "pattern-match":
      return (
        <div className="flex items-center gap-1.5 rounded border border-[#d4a84b]/20 bg-[#d4a84b]/5 px-2 py-1">
          <span className="text-[9px] font-medium text-[#d4a84b]">
            Pattern: {flag.patternName}
          </span>
        </div>
      );
  }
}


function ClusterSeparator({
  cluster,
  onInvestigate,
  onDraftDetection,
}: {
  cluster: AnomalyCluster;
  onInvestigate: (cluster: AnomalyCluster) => void;
  onDraftDetection?: (cluster: AnomalyCluster) => void;
}) {
  return (
    <div className="flex items-center gap-3 px-3 py-2 bg-[#c45c5c]/5 border-y border-[#c45c5c]/15">
      <IconAlertTriangle size={13} className="text-[#c45c5c] shrink-0" stroke={1.5} />
      <span className="text-[10px] font-medium text-[#c45c5c]">
        anomaly cluster: {cluster.agentName} session #
        {cluster.sessionId.slice(0, 8)}
      </span>
      <span className="text-[9px] text-[#c45c5c]/50">
        {cluster.eventIds.length} flagged events
      </span>
      <div className="ml-auto flex items-center gap-2">
        {onDraftDetection && (
          <motion.button
            whileTap={{ scale: 0.92 }}
            transition={{ type: "spring", bounce: 0.4, duration: 0.2 }}
            onClick={(e) => {
              e.stopPropagation();
              onDraftDetection(cluster);
            }}
            className="flex items-center gap-1 rounded-md border border-[#7c9aef]/25 bg-[#7c9aef]/10 px-2.5 py-1 text-[10px] font-medium text-[#7c9aef] hover:bg-[#7c9aef]/20 transition-colors"
          >
            <IconShieldPlus size={11} stroke={1.5} />
            Draft
          </motion.button>
        )}
        <motion.button
          whileTap={{ scale: 0.92 }}
          transition={{ type: "spring", bounce: 0.4, duration: 0.2 }}
          onClick={(e) => {
            e.stopPropagation();
            onInvestigate(cluster);
          }}
          className="flex items-center gap-1 rounded-md border border-[#c45c5c]/25 bg-[#c45c5c]/10 px-2.5 py-1 text-[10px] font-medium text-[#c45c5c] hover:bg-[#c45c5c]/20 transition-colors"
        >
          Investigate
          <IconChevronRight size={11} stroke={1.5} />
        </motion.button>
      </div>
    </div>
  );
}


function BottomStatCard({
  label,
  count,
  total,
  color,
  pulse,
}: {
  label: string;
  count: number;
  total: number;
  color: string;
  pulse?: boolean;
}) {
  const pct = total > 0 ? ((count / total) * 100).toFixed(1) : "0.0";

  return (
    <div
      className="flex items-center gap-2.5 rounded-md border px-3 py-1.5"
      style={{
        borderColor: color + "20",
        backgroundColor: color + "08",
      }}
    >
      <span
        className={cn(
          "inline-block w-2 h-2 rounded-full",
          pulse && "animate-pulse",
        )}
        style={{ backgroundColor: color }}
      />
      <div className="flex flex-col">
        <span
          className="font-mono text-xs font-semibold leading-none"
          style={{ color }}
        >
          {count.toLocaleString()}
        </span>
        <span className="text-[8px] uppercase tracking-wider text-[#6f7f9a]/50 mt-0.5">
          {label}
        </span>
      </div>
      <span className="font-mono text-[9px] text-[#6f7f9a]/40 ml-1">
        {pct}%
      </span>
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
    <div className="flex items-center gap-1.5 shrink-0">
      <span className="text-[9px] uppercase tracking-wider text-[#6f7f9a]/40 mr-0.5">
        {label}
      </span>
      {children}
    </div>
  );
}

function DetailSectionHeader({ children }: { children: React.ReactNode }) {
  return (
    <h4 className="text-[9px] font-semibold uppercase tracking-wider text-[#6f7f9a]/50 mb-2">
      {children}
    </h4>
  );
}

function DetailRow({
  label,
  value,
  mono,
  title,
}: {
  label: string;
  value: string;
  mono?: boolean;
  title?: string;
}) {
  return (
    <div className="flex items-baseline gap-3 text-[10px]">
      <span className="text-[#6f7f9a]/50 shrink-0 w-[90px]" title={title}>{label}</span>
      <span
        className={cn(
          "text-[#ece7dc]/70 break-all",
          mono && "font-mono",
        )}
      >
        {value}
      </span>
    </div>
  );
}
