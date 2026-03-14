import { useState, useMemo, useCallback } from "react";
import {
  IconAlertTriangle,
  IconUsers,
  IconUser,
  IconActivity,
  IconArrowUpRight,
  IconArrowDownRight,
  IconSparkles,
  IconTarget,
} from "@tabler/icons-react";
import { cn } from "@/lib/utils";
import type { AgentBaseline, AgentEvent, DriftMetric } from "@/lib/workbench/hunt-types";


interface BaselinesProps {
  baselines: AgentBaseline[];
  events: AgentEvent[];
  onSensitivityChange: (sensitivity: "low" | "medium" | "high") => void;
  sensitivity: "low" | "medium" | "high";
}


const ACTION_TYPE_COLORS: Record<string, string> = {
  file_access: "#6ea8d9",
  file_write: "#a78bfa",
  network_egress: "#d4a84b",
  shell_command: "#c45c5c",
  mcp_tool_call: "#3dbf84",
  patch_apply: "#e08a5e",
  user_input: "#8b9dc3",
};

const SIGNIFICANCE_STYLES: Record<
  string,
  { bg: string; text: string; border: string; label: string }
> = {
  alert: {
    bg: "bg-[#c45c5c]/10",
    text: "text-[#c45c5c]",
    border: "border-[#c45c5c]/20",
    label: "alert",
  },
  notable: {
    bg: "bg-[#d4a84b]/10",
    text: "text-[#d4a84b]",
    border: "border-[#d4a84b]/20",
    label: "notable",
  },
  normal: {
    bg: "bg-[#6f7f9a]/10",
    text: "text-[#6f7f9a]",
    border: "border-[#6f7f9a]/20",
    label: "normal",
  },
};

const SENSITIVITY_THRESHOLDS: Record<"low" | "medium" | "high", number> = {
  low: 300,
  medium: 100,
  high: 50,
};

const DAY_LABELS = ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"];


function getDriftCount(baseline: AgentBaseline): number {
  return baseline.driftMetrics.filter(
    (m) => m.significance === "alert" || m.significance === "notable",
  ).length;
}

function getTeamMap(
  baselines: AgentBaseline[],
): Map<string, AgentBaseline[]> {
  const map = new Map<string, AgentBaseline[]>();
  for (const b of baselines) {
    const tid = b.teamId ?? "__unassigned__";
    const list = map.get(tid) ?? [];
    list.push(b);
    map.set(tid, list);
  }
  return map;
}

function aggregateBaselines(group: AgentBaseline[]): AgentBaseline {
  if (group.length === 1) return group[0];

  const mergedActionDist: Record<string, number> = {};
  const mergedHourly = new Array(24).fill(0);
  const mergedDaily = new Array(7).fill(0);
  const mergedTargets = new Map<
    string,
    { target: string; count: number; actionType: string }
  >();
  const allDrift: DriftMetric[] = [];

  let totalEvents = 0;
  let totalSessionLen = 0;

  for (const b of group) {
    for (const [action, count] of Object.entries(b.actionDistribution)) {
      mergedActionDist[action] = (mergedActionDist[action] ?? 0) + count;
    }
    for (let i = 0; i < 24; i++) mergedHourly[i] += b.hourlyActivity[i] ?? 0;
    for (let i = 0; i < 7; i++) mergedDaily[i] += b.dailyActivity[i] ?? 0;
    for (const t of b.topTargets) {
      const existing = mergedTargets.get(t.target);
      if (existing) {
        existing.count += t.count;
      } else {
        mergedTargets.set(t.target, { ...t });
      }
    }
    allDrift.push(...b.driftMetrics);
    totalEvents += b.avgDailyEvents;
    totalSessionLen += b.avgSessionLength;
  }

  const sortedTargets = Array.from(mergedTargets.values()).sort(
    (a, b) => b.count - a.count,
  );

  return {
    agentId: "__team_aggregate__",
    agentName: `Team (${group.length} agents)`,
    teamId: group[0].teamId,
    period: {
      start: group.reduce(
        (min, b) => (b.period.start < min ? b.period.start : min),
        group[0].period.start,
      ),
      end: group.reduce(
        (max, b) => (b.period.end > max ? b.period.end : max),
        group[0].period.end,
      ),
    },
    actionDistribution: mergedActionDist,
    hourlyActivity: mergedHourly,
    dailyActivity: mergedDaily,
    topTargets: sortedTargets.slice(0, 20),
    avgSessionLength: group.length > 0 ? totalSessionLen / group.length : 0,
    avgDailyEvents: group.length > 0 ? totalEvents / group.length : 0,
    anomalyThreshold: Math.min(...group.map((b) => b.anomalyThreshold)),
    driftSensitivity: group[0].driftSensitivity,
    driftMetrics: allDrift,
  };
}

/** Build a 24x7 heatmap matrix from hourly + daily distributions and events */
function buildHeatmap(
  baseline: AgentBaseline,
  events: AgentEvent[],
): number[][] {
  // Initialize 7 rows x 24 columns
  const matrix: number[][] = Array.from({ length: 7 }, () =>
    new Array(24).fill(0),
  );

  // If we have matching events, use them directly for precise hour x day
  const agentEvents = events.filter(
    (e) =>
      e.agentId === baseline.agentId ||
      baseline.agentId === "__team_aggregate__",
  );

  if (agentEvents.length > 0) {
    for (const ev of agentEvents) {
      try {
        const d = new Date(ev.timestamp);
        const hour = d.getHours();
        // getDay() returns 0=Sun; we want 0=Mon
        const rawDay = d.getDay();
        const day = rawDay === 0 ? 6 : rawDay - 1;
        matrix[day][hour]++;
      } catch {
        // skip unparseable timestamps
      }
    }
  } else {
        const totalHourly = baseline.hourlyActivity.reduce((s, v) => s + v, 0);
    const totalDaily = baseline.dailyActivity.reduce((s, v) => s + v, 0);
    if (totalHourly > 0 && totalDaily > 0) {
      for (let day = 0; day < 7; day++) {
        const dayWeight = baseline.dailyActivity[day] / totalDaily;
        for (let hour = 0; hour < 24; hour++) {
          matrix[day][hour] = Math.round(
            baseline.hourlyActivity[hour] * dayWeight,
          );
        }
      }
    }
  }

  return matrix;
}

/** Compute current action distribution from events for an agent */
function computeCurrentDistribution(
  baseline: AgentBaseline,
  events: AgentEvent[],
): Record<string, number> {
  const agentEvents = events.filter(
    (e) =>
      e.agentId === baseline.agentId ||
      baseline.agentId === "__team_aggregate__",
  );
  const dist: Record<string, number> = {};
  for (const ev of agentEvents) {
    dist[ev.actionType] = (dist[ev.actionType] ?? 0) + 1;
  }
  return dist;
}

/** Determine which top targets from events are new (not in baseline) */
function findNewTargets(
  baseline: AgentBaseline,
  events: AgentEvent[],
): Set<string> {
  const baseTargets = new Set(baseline.topTargets.map((t) => t.target));
  const agentEvents = events.filter(
    (e) =>
      e.agentId === baseline.agentId ||
      baseline.agentId === "__team_aggregate__",
  );
  const newTargets = new Set<string>();
  for (const ev of agentEvents) {
    if (!baseTargets.has(ev.target)) {
      newTargets.add(ev.target);
    }
  }
  return newTargets;
}


export function Baselines({
  baselines,
  events,
  onSensitivityChange,
  sensitivity,
}: BaselinesProps) {
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [selectionType, setSelectionType] = useState<"agent" | "team">(
    "agent",
  );

  const teamMap = useMemo(() => getTeamMap(baselines), [baselines]);

  const selectedBaseline = useMemo(() => {
    if (!selectedId) return null;
    if (selectionType === "agent") {
      return baselines.find((b) => b.agentId === selectedId) ?? null;
    }
    // Team selection: aggregate all baselines in that team
    const group = teamMap.get(selectedId);
    if (!group || group.length === 0) return null;
    return aggregateBaselines(group);
  }, [selectedId, selectionType, baselines, teamMap]);

  const handleSelectAgent = useCallback((agentId: string) => {
    setSelectedId(agentId);
    setSelectionType("agent");
  }, []);

  const handleSelectTeam = useCallback((teamId: string) => {
    setSelectedId(teamId);
    setSelectionType("team");
  }, []);

  return (
    <div className="flex h-full w-full overflow-hidden bg-[#05060a]">
      {/* Left sidebar */}
      <div className="w-64 shrink-0 border-r border-[#2d3240]/60 bg-[#0b0d13] overflow-y-auto">
        {/* Agents section */}
        <div className="px-3 pt-4 pb-2">
          <div className="flex items-center justify-between mb-2">
            <span className="text-[9px] font-semibold uppercase tracking-[0.08em] text-[#6f7f9a]/50">
              Agents
            </span>
            <span className="text-[9px] font-mono text-[#6f7f9a]/30">
              {baselines.length}
            </span>
          </div>
          <div className="flex flex-col gap-0.5">
            {baselines.map((b) => {
              const driftCount = getDriftCount(b);
              const isSelected =
                selectedId === b.agentId && selectionType === "agent";
              return (
                <button
                  key={b.agentId}
                  onClick={() => handleSelectAgent(b.agentId)}
                  className={cn(
                    "flex items-center gap-2 w-full rounded-md px-2.5 py-2 text-left transition-colors",
                    isSelected
                      ? "bg-[#131721] border border-[#d4a84b]/30"
                      : "border border-transparent hover:bg-[#131721]/60",
                  )}
                >
                  <IconUser
                    size={13}
                    stroke={1.5}
                    className={cn(
                      isSelected ? "text-[#d4a84b]" : "text-[#6f7f9a]/50",
                    )}
                  />
                  <span
                    className={cn(
                      "text-[11px] font-medium truncate flex-1",
                      isSelected ? "text-[#ece7dc]" : "text-[#ece7dc]/70",
                    )}
                  >
                    {b.agentName}
                  </span>
                  {driftCount > 0 && (
                    <span className="flex items-center gap-0.5 shrink-0">
                      <IconAlertTriangle
                        size={10}
                        stroke={2}
                        className="text-[#d4a84b]"
                      />
                      <span className="text-[9px] font-mono font-semibold text-[#d4a84b]">
                        {driftCount}
                      </span>
                    </span>
                  )}
                </button>
              );
            })}
          </div>
        </div>

        {/* Separator */}
        <div className="mx-3 my-2 border-t border-[#2d3240]/40" />

        {/* Teams section */}
        <div className="px-3 pb-4">
          <div className="flex items-center justify-between mb-2">
            <span className="text-[9px] font-semibold uppercase tracking-[0.08em] text-[#6f7f9a]/50">
              Teams
            </span>
            <span className="text-[9px] font-mono text-[#6f7f9a]/30">
              {teamMap.size}
            </span>
          </div>
          <div className="flex flex-col gap-0.5">
            {Array.from(teamMap.entries()).map(([teamId, members]) => {
              const isSelected =
                selectedId === teamId && selectionType === "team";
              const teamDrifts = members.reduce(
                (sum, m) => sum + getDriftCount(m),
                0,
              );
              const displayName =
                teamId === "__unassigned__" ? "Unassigned" : teamId;
              return (
                <button
                  key={teamId}
                  onClick={() => handleSelectTeam(teamId)}
                  className={cn(
                    "flex items-center gap-2 w-full rounded-md px-2.5 py-2 text-left transition-colors",
                    isSelected
                      ? "bg-[#131721] border border-[#d4a84b]/30"
                      : "border border-transparent hover:bg-[#131721]/60",
                  )}
                >
                  <IconUsers
                    size={13}
                    stroke={1.5}
                    className={cn(
                      isSelected ? "text-[#d4a84b]" : "text-[#6f7f9a]/50",
                    )}
                  />
                  <div className="flex flex-col flex-1 min-w-0">
                    <span
                      className={cn(
                        "text-[11px] font-medium truncate",
                        isSelected ? "text-[#ece7dc]" : "text-[#ece7dc]/70",
                      )}
                    >
                      {displayName}
                    </span>
                    <span className="text-[9px] text-[#6f7f9a]/40">
                      {members.length} agent{members.length !== 1 ? "s" : ""}
                    </span>
                  </div>
                  {teamDrifts > 0 && (
                    <span className="flex items-center gap-0.5 shrink-0">
                      <IconAlertTriangle
                        size={10}
                        stroke={2}
                        className="text-[#d4a84b]"
                      />
                      <span className="text-[9px] font-mono font-semibold text-[#d4a84b]">
                        {teamDrifts}
                      </span>
                    </span>
                  )}
                </button>
              );
            })}
          </div>
        </div>
      </div>

      {/* Right main panel */}
      <div className="flex-1 overflow-y-auto">
        {selectedBaseline ? (
          <BaselineDetail
            baseline={selectedBaseline}
            events={events}
            sensitivity={sensitivity}
            onSensitivityChange={onSensitivityChange}
          />
        ) : (
          <div className="flex h-full items-center justify-center">
            <div className="flex flex-col items-center gap-3">
              <IconActivity size={24} className="text-[#6f7f9a]/20" />
              <span className="text-[12px] text-[#6f7f9a]/40">
                Select an agent to view their behavioral baseline
              </span>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}


function BaselineDetail({
  baseline,
  events,
  sensitivity,
  onSensitivityChange,
}: {
  baseline: AgentBaseline;
  events: AgentEvent[];
  sensitivity: "low" | "medium" | "high";
  onSensitivityChange: (sensitivity: "low" | "medium" | "high") => void;
}) {
  const driftCount = getDriftCount(baseline);

  const currentDist = useMemo(
    () => computeCurrentDistribution(baseline, events),
    [baseline, events],
  );

  const heatmap = useMemo(
    () => buildHeatmap(baseline, events),
    [baseline, events],
  );

  const newTargets = useMemo(
    () => findNewTargets(baseline, events),
    [baseline, events],
  );

  // Filter drift metrics by sensitivity threshold
  const threshold = SENSITIVITY_THRESHOLDS[sensitivity];
  const filteredDrifts = useMemo(() => {
    return baseline.driftMetrics
      .map((m) => {
        // Re-classify significance based on sensitivity
        const absChange = Math.abs(m.percentChange);
        const sig: DriftMetric["significance"] =
          sensitivity === "high"
            ? absChange > 100 ? "alert" : absChange > 50 ? "notable" : "normal"
            : sensitivity === "medium"
              ? absChange > 200 ? "alert" : absChange > 100 ? "notable" : "normal"
              : absChange > 500 ? "alert" : absChange > 300 ? "notable" : "normal";
        return { ...m, significance: sig };
      })
      .filter((m) => Math.abs(m.percentChange) >= threshold || m.significance !== "normal")
      .sort((a, b) => Math.abs(b.percentChange) - Math.abs(a.percentChange));
  }, [baseline.driftMetrics, threshold, sensitivity]);

  // Compute top targets from events to merge with baseline
  const eventTargets = useMemo(() => {
    const agentEvents = events.filter(
      (e) =>
        e.agentId === baseline.agentId ||
        baseline.agentId === "__team_aggregate__",
    );
    const counts = new Map<
      string,
      { target: string; count: number; actionType: string }
    >();
    for (const ev of agentEvents) {
      const existing = counts.get(ev.target);
      if (existing) {
        existing.count++;
      } else {
        counts.set(ev.target, {
          target: ev.target,
          count: 1,
          actionType: ev.actionType,
        });
      }
    }
    return Array.from(counts.values()).sort((a, b) => b.count - a.count);
  }, [baseline, events]);

  // Use event targets if available, otherwise baseline topTargets
  const displayTargets =
    eventTargets.length > 0 ? eventTargets : baseline.topTargets;

  return (
    <div className="flex flex-col gap-0">
      {/* Header + Sensitivity Control */}
      <div className="shrink-0 border-b border-[#2d3240]/60 px-6 py-4">
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-3">
            <h2 className="text-sm font-semibold text-[#ece7dc] tracking-[-0.01em]">
              {baseline.agentName}
            </h2>
            {driftCount > 0 && (
              <span className="flex items-center gap-1.5 rounded-full px-2.5 py-0.5 text-[9px] font-mono uppercase tracking-wider bg-[#d4a84b]/10 text-[#d4a84b] border border-[#d4a84b]/20">
                <IconAlertTriangle size={9} stroke={2} />
                {driftCount} drift{driftCount !== 1 ? "s" : ""}
              </span>
            )}
          </div>

          {/* Sensitivity segmented control */}
          <div className="flex items-center gap-2">
            <span className="text-[9px] uppercase tracking-[0.08em] text-[#6f7f9a]/40">
              Sensitivity
            </span>
            <div className="flex items-center rounded-md border border-[#2d3240] overflow-hidden">
              {(["low", "medium", "high"] as const).map((level) => (
                <button
                  key={level}
                  onClick={() => onSensitivityChange(level)}
                  className={cn(
                    "px-2.5 py-1 text-[10px] font-medium capitalize transition-colors",
                    sensitivity === level
                      ? "bg-[#d4a84b]/10 text-[#d4a84b]"
                      : "text-[#6f7f9a]/50 hover:text-[#ece7dc] hover:bg-[#131721]/40",
                  )}
                >
                  {level}
                </button>
              ))}
            </div>
          </div>
        </div>
        <p className="text-[10px] text-[#6f7f9a] mt-1">
          Baseline period: {formatShortDate(baseline.period.start)} &mdash;{" "}
          {formatShortDate(baseline.period.end)} &middot;{" "}
          {baseline.avgDailyEvents.toFixed(1)} avg events/day &middot;{" "}
          {formatDuration(baseline.avgSessionLength)} avg session
        </p>
      </div>

      {/* Content sections */}
      <div className="flex-1 overflow-y-auto px-6 py-5 space-y-6">
        {/* Section 1: Action Distribution */}
        <section>
          <SectionHeader icon={IconActivity} title="Action Distribution" />
          <ActionDistributionChart
            baseline={baseline.actionDistribution}
            current={currentDist}
          />
        </section>

        {/* Section 2: Activity Heatmap */}
        <section>
          <SectionHeader icon={IconSparkles} title="Activity Heatmap" />
          <ActivityHeatmap matrix={heatmap} />
        </section>

        {/* Section 3: Drift Alerts */}
        <section>
          <SectionHeader
            icon={IconAlertTriangle}
            title="Drift Alerts"
            badge={
              filteredDrifts.length > 0
                ? `${filteredDrifts.length} flagged (>${threshold}%)`
                : undefined
            }
          />
          {filteredDrifts.length > 0 ? (
            <div className="flex flex-col gap-1.5">
              {filteredDrifts.map((m, i) => (
                <DriftRow key={`${m.metric}-${i}`} metric={m} />
              ))}
            </div>
          ) : (
            <p className="text-[11px] text-[#6f7f9a]/40 py-3">
              No drift metrics exceed the {sensitivity} sensitivity threshold (
              {">"}{threshold}% change).
            </p>
          )}
        </section>

        {/* Section 4: Top Targets */}
        <section>
          <SectionHeader icon={IconTarget} title="Top Targets" />
          {displayTargets.length > 0 ? (
            <TopTargetsTable targets={displayTargets} newTargets={newTargets} />
          ) : (
            <p className="text-[11px] text-[#6f7f9a]/40 py-3">
              No target data available.
            </p>
          )}
        </section>
      </div>
    </div>
  );
}


function SectionHeader({
  icon: Icon,
  title,
  badge,
}: {
  icon: typeof IconActivity;
  title: string;
  badge?: string;
}) {
  return (
    <div className="flex items-center gap-2 mb-3">
      <Icon size={14} stroke={1.5} className="text-[#d4a84b]" />
      <h3 className="text-[11px] font-semibold uppercase tracking-[0.06em] text-[#ece7dc]/80">
        {title}
      </h3>
      {badge && (
        <span className="text-[9px] font-mono text-[#6f7f9a]/50 ml-auto">
          {badge}
        </span>
      )}
    </div>
  );
}


function ActionDistributionChart({
  baseline,
  current,
}: {
  baseline: Record<string, number>;
  current: Record<string, number>;
}) {
  // Merge all action types from both baseline and current
  const allActions = useMemo(() => {
    const keys = new Set([...Object.keys(baseline), ...Object.keys(current)]);
    return Array.from(keys).sort();
  }, [baseline, current]);

  const baselineTotal = useMemo(
    () => Object.values(baseline).reduce((s, v) => s + v, 0),
    [baseline],
  );
  const currentTotal = useMemo(
    () => Object.values(current).reduce((s, v) => s + v, 0),
    [current],
  );

  const hasCurrent = currentTotal > 0;

  return (
    <div className="rounded-lg border border-[#2d3240]/60 bg-[#131721] p-4">
      <div className="flex flex-col gap-3">
        {allActions.map((action) => {
          const bVal = baseline[action] ?? 0;
          const cVal = current[action] ?? 0;
          const bPct = baselineTotal > 0 ? (bVal / baselineTotal) * 100 : 0;
          const cPct = currentTotal > 0 ? (cVal / currentTotal) * 100 : 0;
          const color = ACTION_TYPE_COLORS[action] ?? "#6f7f9a";

          return (
            <div key={action} className="flex items-center gap-3">
              <span className="w-[110px] shrink-0 text-[10px] font-mono text-[#ece7dc]/60 truncate">
                {action}
              </span>
              <div className="flex-1 relative h-5">
                {/* Baseline bar (outline) */}
                <div
                  className="absolute inset-y-0 left-0 rounded-sm border"
                  style={{
                    width: `${Math.max(bPct, 0.5)}%`,
                    borderColor: color + "60",
                    backgroundColor: "transparent",
                  }}
                />
                {/* Current bar (filled) */}
                {hasCurrent && (
                  <div
                    className="absolute inset-y-0.5 left-0 rounded-sm"
                    style={{
                      width: `${Math.max(cPct, 0.5)}%`,
                      backgroundColor: color + "40",
                    }}
                  />
                )}
              </div>
              <div className="flex items-center gap-1.5 shrink-0 w-[90px] justify-end">
                <span
                  className="text-[9px] font-mono"
                  style={{ color: color + "80" }}
                >
                  {bPct.toFixed(1)}%
                </span>
                {hasCurrent && (
                  <>
                    <span className="text-[#6f7f9a]/30 text-[8px]">/</span>
                    <span
                      className="text-[9px] font-mono font-semibold"
                      style={{ color }}
                    >
                      {cPct.toFixed(1)}%
                    </span>
                  </>
                )}
              </div>
            </div>
          );
        })}
      </div>
      {/* Legend */}
      <div className="flex items-center gap-4 mt-3 pt-3 border-t border-[#2d3240]/40">
        <span className="flex items-center gap-1.5 text-[9px] text-[#6f7f9a]/50">
          <span className="inline-block w-3 h-2 rounded-sm border border-[#6f7f9a]/40" />
          Baseline
        </span>
        {hasCurrent && (
          <span className="flex items-center gap-1.5 text-[9px] text-[#6f7f9a]/50">
            <span className="inline-block w-3 h-2 rounded-sm bg-[#6f7f9a]/30" />
            Current
          </span>
        )}
      </div>
    </div>
  );
}


function ActivityHeatmap({ matrix }: { matrix: number[][] }) {
  const maxVal = useMemo(() => {
    let max = 0;
    for (const row of matrix) {
      for (const v of row) {
        if (v > max) max = v;
      }
    }
    return max;
  }, [matrix]);

  const [hoverCell, setHoverCell] = useState<{
    day: number;
    hour: number;
    count: number;
  } | null>(null);

  return (
    <div className="rounded-lg border border-[#2d3240]/60 bg-[#131721] p-4">
      <div className="relative">
        {/* Hour labels */}
        <div className="flex ml-[36px] mb-1">
          {Array.from({ length: 24 }, (_, i) => (
            <div
              key={i}
              className="text-center text-[7px] font-mono text-[#6f7f9a]/30"
              style={{ width: 16, minWidth: 16 }}
            >
              {i % 3 === 0 ? i : ""}
            </div>
          ))}
        </div>

        {/* Grid */}
        <div className="flex flex-col gap-[2px]">
          {matrix.map((row, dayIdx) => (
            <div key={dayIdx} className="flex items-center gap-0">
              <span className="w-[36px] shrink-0 text-[8px] font-mono text-[#6f7f9a]/40 pr-1 text-right">
                {DAY_LABELS[dayIdx]}
              </span>
              <div className="flex gap-[2px]">
                {row.map((val, hourIdx) => {
                  const intensity =
                    maxVal > 0 ? Math.min(val / maxVal, 1) : 0;
                  return (
                    <div
                      key={hourIdx}
                      className="rounded-[2px] cursor-default transition-colors"
                      style={{
                        width: 16,
                        height: 16,
                        minWidth: 16,
                        minHeight: 16,
                        backgroundColor:
                          intensity > 0
                            ? `rgba(212, 168, 75, ${intensity * 0.8 + 0.05})`
                            : "rgba(45, 50, 64, 0.2)",
                      }}
                      onMouseEnter={() =>
                        setHoverCell({
                          day: dayIdx,
                          hour: hourIdx,
                          count: val,
                        })
                      }
                      onMouseLeave={() => setHoverCell(null)}
                    />
                  );
                })}
              </div>
            </div>
          ))}
        </div>

        {/* Tooltip */}
        {hoverCell && (
          <div className="absolute top-0 right-0 rounded-md border border-[#2d3240] bg-[#0b0d13] px-2.5 py-1.5 shadow-lg z-10">
            <span className="text-[9px] font-mono text-[#ece7dc]/70">
              {DAY_LABELS[hoverCell.day]}{" "}
              {String(hoverCell.hour).padStart(2, "0")}:00 &mdash;{" "}
              <span className="text-[#d4a84b] font-semibold">
                {hoverCell.count}
              </span>{" "}
              event{hoverCell.count !== 1 ? "s" : ""}
            </span>
          </div>
        )}
      </div>

      {/* Color ramp legend */}
      <div className="flex items-center gap-2 mt-3 pt-3 border-t border-[#2d3240]/40">
        <span className="text-[8px] text-[#6f7f9a]/40">Less</span>
        <div className="flex gap-[2px]">
          {[0, 0.2, 0.4, 0.6, 0.8, 1.0].map((v) => (
            <div
              key={v}
              className="rounded-[2px]"
              style={{
                width: 10,
                height: 10,
                backgroundColor:
                  v > 0
                    ? `rgba(212, 168, 75, ${v * 0.8 + 0.05})`
                    : "rgba(45, 50, 64, 0.2)",
              }}
            />
          ))}
        </div>
        <span className="text-[8px] text-[#6f7f9a]/40">More</span>
      </div>
    </div>
  );
}


function DriftRow({ metric }: { metric: DriftMetric }) {
  const styles = SIGNIFICANCE_STYLES[metric.significance] ?? SIGNIFICANCE_STYLES.normal;
  const isIncrease = metric.percentChange > 0;
  const absChange = Math.abs(metric.percentChange);
  const changeColor = isIncrease ? "#c45c5c" : "#3dbf84";

  // Magnitude bar: max out at 500% for visual capping
  const barWidth = Math.min(absChange / 500, 1) * 100;

  return (
    <div className="flex items-center gap-3 rounded-lg border border-[#2d3240]/60 bg-[#131721] px-4 py-2.5">
      {/* Metric name */}
      <span className="text-[11px] font-medium text-[#ece7dc]/70 w-[160px] shrink-0 truncate">
        {metric.metric}
      </span>

      {/* Percent change */}
      <div
        className="flex items-center gap-1 w-[80px] shrink-0"
        style={{ color: changeColor }}
      >
        {isIncrease ? (
          <IconArrowUpRight size={11} stroke={2} />
        ) : (
          <IconArrowDownRight size={11} stroke={2} />
        )}
        <span className="text-[11px] font-mono font-semibold">
          {isIncrease ? "+" : "-"}
          {absChange.toFixed(0)}%
        </span>
      </div>

      {/* Mini bar */}
      <div className="flex-1 h-2 rounded-full bg-[#2d3240]/30 overflow-hidden">
        <div
          className="h-full rounded-full transition-all duration-300"
          style={{
            width: `${barWidth}%`,
            backgroundColor: changeColor,
            opacity: 0.6,
          }}
        />
      </div>

      {/* Baseline → Current */}
      <span className="text-[9px] font-mono text-[#6f7f9a]/40 w-[100px] shrink-0 text-right">
        {metric.baseline.toFixed(1)} &rarr; {metric.current.toFixed(1)}
      </span>

      {/* Significance badge */}
      <span
        className={cn(
          "rounded px-1.5 py-0.5 text-[8px] font-semibold uppercase border shrink-0",
          styles.bg,
          styles.text,
          styles.border,
        )}
      >
        {styles.label}
      </span>
    </div>
  );
}


function TopTargetsTable({
  targets,
  newTargets,
}: {
  targets: { target: string; count: number; actionType: string }[];
  newTargets: Set<string>;
}) {
  const TH =
    "px-3 py-2 text-left text-[9px] uppercase tracking-[0.08em] font-semibold text-[#6f7f9a]/50";

  return (
    <div className="rounded-lg border border-[#2d3240]/60 bg-[#131721] overflow-hidden">
      <table className="w-full">
        <thead>
          <tr className="border-b border-[#2d3240]/60 bg-[#0b0d13]">
            <th className={TH}>Target</th>
            <th className={cn(TH, "w-[80px]")}>Count</th>
            <th className={cn(TH, "w-[120px]")}>Action Type</th>
            <th className={cn(TH, "w-[60px]")} />
          </tr>
        </thead>
        <tbody>
          {targets.slice(0, 20).map((t, i) => {
            const isNew = newTargets.has(t.target);
            const color = ACTION_TYPE_COLORS[t.actionType] ?? "#6f7f9a";

            return (
              <tr
                key={`${t.target}-${i}`}
                className="border-b border-[#2d3240]/30 last:border-0"
              >
                <td className="px-3 py-2 font-mono text-[10px] text-[#ece7dc]/60 truncate max-w-[300px]">
                  {t.target}
                </td>
                <td className="px-3 py-2 font-mono text-[10px] text-[#ece7dc]/50 text-right">
                  {t.count}
                </td>
                <td className="px-3 py-2">
                  <span
                    className="rounded border bg-[#0b0d13] px-1.5 py-0.5 font-mono text-[9px]"
                    style={{
                      borderColor: color + "30",
                      color,
                    }}
                  >
                    {t.actionType}
                  </span>
                </td>
                <td className="px-3 py-2">
                  {isNew && (
                    <span className="rounded px-1.5 py-0.5 text-[8px] font-semibold uppercase bg-[#d4a84b]/10 text-[#d4a84b] border border-[#d4a84b]/20">
                      NEW
                    </span>
                  )}
                </td>
              </tr>
            );
          })}
        </tbody>
      </table>
    </div>
  );
}


function formatShortDate(iso: string): string {
  try {
    const d = new Date(iso);
    return d.toLocaleDateString(undefined, {
      month: "short",
      day: "numeric",
      year: "numeric",
    });
  } catch {
    return iso;
  }
}

function formatDuration(ms: number): string {
  if (ms < 60_000) return `${Math.round(ms / 1000)}s`;
  if (ms < 3_600_000) return `${Math.round(ms / 60_000)}m`;
  return `${(ms / 3_600_000).toFixed(1)}h`;
}
