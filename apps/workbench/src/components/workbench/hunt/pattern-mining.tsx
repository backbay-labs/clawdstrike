import { useState, useCallback, useMemo } from "react";
import { cn } from "@/lib/utils";
import { ScrollArea } from "@/components/ui/scroll-area";
import type {
  HuntPattern,
  PatternStatus,
  PatternStep,
  AgentEvent,
} from "@/lib/workbench/hunt-types";
import { discoverPatterns } from "@/lib/workbench/hunt-engine";
import {
  IconArrowDown,
  IconFingerprint,
  IconTestPipe,
  IconSparkles,
  IconFile,
  IconFileText,
  IconWorld,
  IconTerminal2,
  IconTool,
  IconGitPullRequest,
  IconMessageCircle,
  IconClock,
  IconUsers,
  IconUser,
  IconHash,
  IconCalendar,
} from "@tabler/icons-react";


const STATUS_CONFIG: Record<
  PatternStatus,
  { icon: string; color: string; label: string }
> = {
  confirmed: { icon: "\u25CF", color: "#3dbf84", label: "Confirmed" },
  draft: { icon: "\u25CB", color: "#d4a84b", label: "Draft" },
  promoted: { icon: "\u25CF", color: "#8b7355", label: "Promoted" },
  dismissed: { icon: "\u25CC", color: "#6f7f9a", label: "Dismissed" },
};

const ACTION_ICONS: Record<string, typeof IconFile> = {
  file_access: IconFile,
  file_write: IconFileText,
  network_egress: IconWorld,
  shell_command: IconTerminal2,
  mcp_tool_call: IconTool,
  patch_apply: IconGitPullRequest,
  user_input: IconMessageCircle,
};


function hashString(str: string): number {
  let hash = 0;
  for (let i = 0; i < str.length; i++) {
    const ch = str.charCodeAt(i);
    hash = ((hash << 5) - hash + ch) | 0;
  }
  return Math.abs(hash);
}

function formatTimeWindow(ms: number): string {
  if (ms < 1000) return `< ${ms}ms`;
  if (ms < 60_000) return `< ${(ms / 1000).toFixed(0)}s`;
  if (ms < 3_600_000) return `< ${(ms / 60_000).toFixed(0)}m`;
  return `< ${(ms / 3_600_000).toFixed(1)}h`;
}

function formatDate(iso: string): string {
  const d = new Date(iso);
  return d.toLocaleDateString("en-US", {
    month: "short",
    day: "numeric",
    year: "numeric",
  });
}

function formatDateTime(iso: string): string {
  const d = new Date(iso);
  return d.toLocaleDateString("en-US", {
    month: "short",
    day: "numeric",
    hour: "2-digit",
    minute: "2-digit",
  });
}


function EmbeddingScatter({ events }: { events: AgentEvent[] }) {
  const WIDTH = 264;
  const HEIGHT = 180;
  const PAD = 16;

  const plotData = useMemo(() => {
    // Position each event using deterministic hash of target + actionType
    const points = events.slice(0, 200).map((e) => {
      const key = `${e.target}::${e.actionType}`;
      const h = hashString(key);
      const h2 = hashString(`${e.id}::${key}`);
      const x = PAD + ((h % 1000) / 1000) * (WIDTH - PAD * 2);
      const y = PAD + ((h2 % 1000) / 1000) * (HEIGHT - PAD * 2);

      const isAnomaly = (e.anomalyScore ?? 0) > 0.7;
      const isCluster = (e.anomalyScore ?? 0) > 0.4 && (e.anomalyScore ?? 0) <= 0.7;

      return { x, y, isAnomaly, isCluster, id: e.id };
    });

        const clustered = points.filter((p) => p.isCluster || p.isAnomaly);
    const centers: { cx: number; cy: number }[] = [];
    if (clustered.length > 0) {
      // Simple k-means-like bucketing: divide space into grid cells
      const cells = new Map<string, { sumX: number; sumY: number; count: number }>();
      const cellSize = 40;
      for (const p of clustered) {
        const cellKey = `${Math.floor(p.x / cellSize)},${Math.floor(p.y / cellSize)}`;
        const cell = cells.get(cellKey);
        if (cell) {
          cell.sumX += p.x;
          cell.sumY += p.y;
          cell.count++;
        } else {
          cells.set(cellKey, { sumX: p.x, sumY: p.y, count: 1 });
        }
      }
      for (const cell of cells.values()) {
        if (cell.count >= 2) {
          centers.push({ cx: cell.sumX / cell.count, cy: cell.sumY / cell.count });
        }
      }
    }

    return { points, centers };
  }, [events]);

  return (
    <div className="px-3 pb-3">
      <div className="text-[9px] font-mono text-[#6f7f9a] uppercase tracking-wider mb-2">
        Embedding Clusters
      </div>
      <svg
        viewBox={`0 0 ${WIDTH} ${HEIGHT}`}
        className="w-full h-48 rounded-lg bg-[#131721] border border-[#2d3240]"
        preserveAspectRatio="xMidYMid meet"
      >
        {/* Grid lines for context */}
        {[0.25, 0.5, 0.75].map((frac) => (
          <line
            key={`h-${frac}`}
            x1={PAD}
            y1={PAD + frac * (HEIGHT - PAD * 2)}
            x2={WIDTH - PAD}
            y2={PAD + frac * (HEIGHT - PAD * 2)}
            stroke="#2d3240"
            strokeWidth={0.5}
            strokeDasharray="2,4"
          />
        ))}
        {[0.25, 0.5, 0.75].map((frac) => (
          <line
            key={`v-${frac}`}
            x1={PAD + frac * (WIDTH - PAD * 2)}
            y1={PAD}
            x2={PAD + frac * (WIDTH - PAD * 2)}
            y2={HEIGHT - PAD}
            stroke="#2d3240"
            strokeWidth={0.5}
            strokeDasharray="2,4"
          />
        ))}

        {/* Cluster center halos */}
        {plotData.centers.map((c, i) => (
          <circle
            key={`halo-${i}`}
            cx={c.cx}
            cy={c.cy}
            r={18}
            fill="#d4a84b"
            fillOpacity={0.06}
            stroke="#d4a84b"
            strokeWidth={0.5}
            strokeOpacity={0.2}
          />
        ))}

        {/* Normal event dots */}
        {plotData.points
          .filter((p) => !p.isAnomaly && !p.isCluster)
          .map((p) => (
            <circle
              key={p.id}
              cx={p.x}
              cy={p.y}
              r={1.5}
              fill="#6f7f9a"
              fillOpacity={0.4}
            />
          ))}

        {/* Clustered event dots */}
        {plotData.points
          .filter((p) => p.isCluster)
          .map((p) => (
            <circle
              key={p.id}
              cx={p.x}
              cy={p.y}
              r={2}
              fill="#d4a84b"
              fillOpacity={0.7}
            />
          ))}

        {/* Anomalous event dots */}
        {plotData.points
          .filter((p) => p.isAnomaly)
          .map((p) => (
            <circle
              key={p.id}
              cx={p.x}
              cy={p.y}
              r={2.5}
              fill="#c45c5c"
              fillOpacity={0.85}
            />
          ))}

        {/* Cluster centers */}
        {plotData.centers.map((c, i) => (
          <circle
            key={`center-${i}`}
            cx={c.cx}
            cy={c.cy}
            r={5}
            fill="none"
            stroke="#d4a84b"
            strokeWidth={1.2}
            strokeOpacity={0.7}
          />
        ))}
      </svg>
      <div className="flex items-center gap-4 mt-1.5 justify-center">
        <div className="flex items-center gap-1">
          <svg width={8} height={8}>
            <circle cx={4} cy={4} r={3} fill="none" stroke="#d4a84b" strokeWidth={1} />
          </svg>
          <span className="text-[8px] font-mono text-[#6f7f9a]/60">= cluster</span>
        </div>
        <div className="flex items-center gap-1">
          <svg width={6} height={6}>
            <circle cx={3} cy={3} r={2} fill="#c45c5c" />
          </svg>
          <span className="text-[8px] font-mono text-[#6f7f9a]/60">= anomaly</span>
        </div>
        <div className="flex items-center gap-1">
          <svg width={6} height={6}>
            <circle cx={3} cy={3} r={1.5} fill="#6f7f9a" fillOpacity={0.5} />
          </svg>
          <span className="text-[8px] font-mono text-[#6f7f9a]/60">= event</span>
        </div>
      </div>
    </div>
  );
}


function PatternRow({
  pattern,
  isSelected,
  onSelect,
}: {
  pattern: HuntPattern;
  isSelected: boolean;
  onSelect: () => void;
}) {
  const status = STATUS_CONFIG[pattern.status];

  return (
    <button
      onClick={onSelect}
      className={cn(
        "w-full flex items-center gap-2 px-3 py-2.5 text-left transition-all duration-100",
        isSelected
          ? "bg-[#131721] border-l-2 border-l-[#d4a84b]"
          : "border-l-2 border-l-transparent hover:bg-[#131721]/50",
      )}
    >
      <span
        className="text-[10px] shrink-0 leading-none"
        style={{ color: status.color }}
        title={status.label}
      >
        {status.icon}
      </span>
      <div className="flex-1 min-w-0">
        <div
          className={cn(
            "text-[11px] truncate leading-tight",
            isSelected ? "text-[#ece7dc]" : "text-[#ece7dc]/80",
          )}
        >
          {pattern.name}
        </div>
      </div>
      <span className="text-[9px] font-mono text-[#6f7f9a]/70 shrink-0 px-1.5 py-0.5 rounded bg-[#0b0d13] border border-[#2d3240]/50">
        {pattern.matchCount}&times;
      </span>
    </button>
  );
}


function SequenceStep({
  step,
  isLast,
}: {
  step: PatternStep;
  isLast: boolean;
}) {
  const ActionIcon = ACTION_ICONS[step.actionType] ?? IconTerminal2;

  return (
    <div className="flex flex-col items-stretch">
      <div className="flex items-center gap-3 px-3 py-2.5 rounded-lg bg-[#131721] border border-[#2d3240]/60">
        {/* Step number */}
        <div className="w-6 h-6 rounded-full bg-[#d4a84b]/10 border border-[#d4a84b]/30 flex items-center justify-center shrink-0">
          <span className="text-[10px] font-mono font-bold text-[#d4a84b]">
            {step.step}
          </span>
        </div>

        {/* Action icon */}
        <ActionIcon size={16} stroke={1.5} className="text-[#6f7f9a] shrink-0" />

        {/* Details */}
        <div className="flex-1 min-w-0">
          <div className="text-[11px] text-[#ece7dc] font-medium">
            {step.actionType.replace(/_/g, " ")}
          </div>
          <div className="text-[10px] font-mono text-[#6f7f9a]/70 truncate">
            {step.targetPattern}
          </div>
        </div>

        {/* Time window constraint */}
        {step.timeWindow != null && (
          <div className="flex items-center gap-1 shrink-0 px-2 py-0.5 rounded bg-[#0b0d13] border border-[#2d3240]/50">
            <IconClock size={10} stroke={1.5} className="text-[#6f7f9a]/50" />
            <span className="text-[9px] font-mono text-[#6f7f9a]/70">
              {formatTimeWindow(step.timeWindow)}
            </span>
          </div>
        )}
      </div>

      {/* Arrow to next step */}
      {!isLast && (
        <div className="flex justify-center py-1">
          <IconArrowDown size={14} stroke={1.5} className="text-[#2d3240]" />
        </div>
      )}
    </div>
  );
}

function SequenceVisualization({ steps }: { steps: PatternStep[] }) {
  return (
    <div className="space-y-0">
      {steps.map((step, i) => (
        <SequenceStep key={step.step} step={step} isLast={i === steps.length - 1} />
      ))}
    </div>
  );
}


function EvidenceSection({ pattern, events }: { pattern: HuntPattern; events: AgentEvent[] }) {
  const agentCount = pattern.agentIds.length;
  const teamIds = new Set(
    events
      .filter((e) => pattern.agentIds.includes(e.agentId))
      .map((e) => e.teamId)
      .filter(Boolean),
  );
  const teamCount = teamIds.size;

  // Find first/last seen from matching sessions
  const matchingEvents = events.filter((e) =>
    pattern.exampleSessionIds.includes(e.sessionId),
  );
  const timestamps = matchingEvents.map((e) => new Date(e.timestamp).getTime());
  const firstSeen = timestamps.length > 0
    ? new Date(Math.min(...timestamps)).toISOString()
    : pattern.discoveredAt;
  const lastSeen = timestamps.length > 0
    ? new Date(Math.max(...timestamps)).toISOString()
    : pattern.discoveredAt;

  return (
    <div className="space-y-2">
      {/* Stats row */}
      <div className="flex items-center gap-4">
        <div className="flex items-center gap-1.5">
          <IconHash size={12} stroke={1.5} className="text-[#6f7f9a]/50" />
          <span className="text-[11px] font-mono text-[#ece7dc]">
            {pattern.matchCount}
          </span>
          <span className="text-[10px] text-[#6f7f9a]">matches</span>
        </div>
        <div className="flex items-center gap-1.5">
          <IconUser size={12} stroke={1.5} className="text-[#6f7f9a]/50" />
          <span className="text-[11px] font-mono text-[#ece7dc]">
            {agentCount}
          </span>
          <span className="text-[10px] text-[#6f7f9a]">
            {agentCount === 1 ? "agent" : "agents"}
          </span>
        </div>
        {teamCount > 0 && (
          <div className="flex items-center gap-1.5">
            <IconUsers size={12} stroke={1.5} className="text-[#6f7f9a]/50" />
            <span className="text-[11px] font-mono text-[#ece7dc]">
              {teamCount}
            </span>
            <span className="text-[10px] text-[#6f7f9a]">
              {teamCount === 1 ? "team" : "teams"}
            </span>
          </div>
        )}
      </div>

      {/* Date range */}
      <div className="flex items-center gap-4 text-[10px] font-mono text-[#6f7f9a]">
        <span>First seen: {formatDate(firstSeen)}</span>
        <span>Last seen: {formatDate(lastSeen)}</span>
      </div>
    </div>
  );
}


function ExampleSessions({
  pattern,
  events,
}: {
  pattern: HuntPattern;
  events: AgentEvent[];
}) {
  const [selectedSession, setSelectedSession] = useState<string | null>(null);

  const sessions = useMemo(() => {
    return pattern.exampleSessionIds.map((sessionId) => {
      const sessionEvents = events.filter((e) => e.sessionId === sessionId);
      const agentName = sessionEvents[0]?.agentName ?? "Unknown Agent";
      const date = sessionEvents[0]?.timestamp ?? pattern.discoveredAt;
      return { sessionId, agentName, date, eventCount: sessionEvents.length };
    });
  }, [pattern.exampleSessionIds, events, pattern.discoveredAt]);

  if (sessions.length === 0) {
    return (
      <div className="text-[11px] text-[#6f7f9a]/50 italic">
        No example sessions recorded
      </div>
    );
  }

  return (
    <div className="space-y-1">
      {sessions.map((s) => (
        <button
          key={s.sessionId}
          onClick={() =>
            setSelectedSession(
              selectedSession === s.sessionId ? null : s.sessionId,
            )
          }
          className={cn(
            "w-full flex items-center gap-2.5 px-3 py-2 rounded-lg border text-left transition-all duration-100",
            selectedSession === s.sessionId
              ? "bg-[#d4a84b]/5 border-[#d4a84b]/20"
              : "bg-[#131721] border-[#2d3240]/40 hover:border-[#2d3240]",
          )}
        >
          <IconUser size={12} stroke={1.5} className="text-[#6f7f9a]/50 shrink-0" />
          <div className="flex-1 min-w-0">
            <div className="text-[11px] text-[#ece7dc]/80 truncate">
              {s.agentName}
            </div>
            <div className="text-[9px] font-mono text-[#6f7f9a]/50 truncate">
              {s.sessionId.slice(0, 12)}...
            </div>
          </div>
          <div className="text-right shrink-0">
            <div className="text-[9px] font-mono text-[#6f7f9a]/60">
              {formatDateTime(s.date)}
            </div>
            {s.eventCount > 0 && (
              <div className="text-[8px] font-mono text-[#6f7f9a]/40">
                {s.eventCount} events
              </div>
            )}
          </div>
        </button>
      ))}
    </div>
  );
}


function PatternDetail({
  pattern,
  events,
  onUpdatePattern,
  onPromoteToTrustprint,
  onCreateScenario,
}: {
  pattern: HuntPattern;
  events: AgentEvent[];
  onUpdatePattern: (id: string, updates: Partial<HuntPattern>) => void;
  onPromoteToTrustprint: (patternId: string) => void;
  onCreateScenario: (patternId: string) => void;
}) {
  const status = STATUS_CONFIG[pattern.status];

  return (
    <div className="space-y-6 p-5">
      {/* Header */}
      <div>
        <div className="flex items-center gap-2.5 mb-1">
          <h2 className="text-sm font-syne font-semibold text-[#ece7dc]">
            {pattern.name}
          </h2>
          <span
            className="text-[8px] font-mono uppercase px-1.5 py-0.5 rounded border"
            style={{
              color: status.color,
              borderColor: `${status.color}33`,
              backgroundColor: `${status.color}10`,
            }}
          >
            {status.label}
          </span>
        </div>
        <div className="flex items-center gap-1.5">
          <IconCalendar size={11} stroke={1.5} className="text-[#6f7f9a]/50" />
          <span className="text-[10px] font-mono text-[#6f7f9a]">
            Discovered {formatDate(pattern.discoveredAt)}
          </span>
        </div>
        {pattern.description && (
          <p className="text-[11px] text-[#6f7f9a]/70 mt-2 leading-relaxed">
            {pattern.description}
          </p>
        )}
      </div>

      {/* Section 1: Sequence Visualization */}
      <div>
        <div className="text-[9px] font-mono text-[#6f7f9a] uppercase tracking-wider mb-3">
          Sequence ({pattern.sequence.length} steps)
        </div>
        <SequenceVisualization steps={pattern.sequence} />
      </div>

      {/* Section 2: Evidence */}
      <div>
        <div className="text-[9px] font-mono text-[#6f7f9a] uppercase tracking-wider mb-3">
          Evidence
        </div>
        <EvidenceSection pattern={pattern} events={events} />
      </div>

      {/* Section 3: Example Sessions */}
      <div>
        <div className="text-[9px] font-mono text-[#6f7f9a] uppercase tracking-wider mb-3">
          Example Sessions
        </div>
        <ExampleSessions pattern={pattern} events={events} />
      </div>

      {/* Section 4: Actions */}
      <div>
        <div className="text-[9px] font-mono text-[#6f7f9a] uppercase tracking-wider mb-3">
          Actions
        </div>
        <div className="space-y-2.5">
          {/* Promote to Trustprint */}
          <button
            onClick={() => onPromoteToTrustprint(pattern.id)}
            disabled={pattern.status === "promoted"}
            className={cn(
              "w-full flex items-center gap-3 px-4 py-3 rounded-lg border transition-all duration-150 text-left",
              pattern.status === "promoted"
                ? "bg-[#8b7355]/5 border-[#8b7355]/20 opacity-60 cursor-not-allowed"
                : "bg-[#d4a84b]/5 border-[#d4a84b]/20 hover:border-[#d4a84b]/40 hover:bg-[#d4a84b]/10 active:scale-[0.99]",
            )}
          >
            <div className="w-8 h-8 rounded-lg bg-[#d4a84b]/10 border border-[#d4a84b]/20 flex items-center justify-center shrink-0">
              <IconFingerprint
                size={16}
                stroke={1.5}
                className={
                  pattern.status === "promoted"
                    ? "text-[#8b7355]"
                    : "text-[#d4a84b]"
                }
              />
            </div>
            <div className="flex-1 min-w-0">
              <div
                className={cn(
                  "text-[12px] font-semibold",
                  pattern.status === "promoted"
                    ? "text-[#8b7355]"
                    : "text-[#d4a84b]",
                )}
              >
                {pattern.status === "promoted"
                  ? "Promoted to Trustprint"
                  : "Promote to Trustprint"}
              </div>
              <div className="text-[10px] text-[#6f7f9a]/60 leading-relaxed">
                {pattern.status === "promoted"
                  ? `Pattern signature added as ${pattern.promotedToTrustprint ?? "behavioral signature"}`
                  : `Adds ${pattern.sequence.length}-step sequence to Spider Sense pattern DB as a new behavioral signature`}
              </div>
            </div>
          </button>

          {/* Create Scenario */}
          <button
            onClick={() => onCreateScenario(pattern.id)}
            disabled={pattern.status === "dismissed"}
            className={cn(
              "w-full flex items-center gap-3 px-4 py-3 rounded-lg border transition-all duration-150 text-left",
              pattern.status === "dismissed"
                ? "bg-[#131721] border-[#2d3240]/40 opacity-50 cursor-not-allowed"
                : "bg-[#131721] border-[#2d3240]/60 hover:border-[#6f7f9a]/30 hover:bg-[#131721]/80 active:scale-[0.99]",
            )}
          >
            <div className="w-8 h-8 rounded-lg bg-[#131721] border border-[#2d3240] flex items-center justify-center shrink-0">
              <IconTestPipe size={16} stroke={1.5} className="text-[#6f7f9a]" />
            </div>
            <div className="flex-1 min-w-0">
              <div className="text-[12px] font-semibold text-[#ece7dc]/80">
                Create Scenario
              </div>
              <div className="text-[10px] text-[#6f7f9a]/60 leading-relaxed">
                Generates a test scenario in Threat Lab from the pattern steps
              </div>
            </div>
          </button>

          {/* Status dropdown */}
          <div className="flex items-center gap-3 pt-1">
            <span className="text-[10px] font-mono text-[#6f7f9a] uppercase tracking-wider shrink-0">
              Status
            </span>
            <select
              value={pattern.status}
              onChange={(e) =>
                onUpdatePattern(pattern.id, {
                  status: e.target.value as PatternStatus,
                })
              }
              className="flex-1 h-8 px-2.5 rounded-md bg-[#131721] border border-[#2d3240] text-[11px] font-mono text-[#ece7dc] outline-none focus:border-[#d4a84b]/40 transition-colors appearance-none cursor-pointer"
            >
              <option value="draft">Draft</option>
              <option value="confirmed">Confirmed</option>
              <option value="dismissed">Dismissed</option>
            </select>
          </div>
        </div>
      </div>
    </div>
  );
}


function EmptyDetail({ onDiscover }: { onDiscover: () => void }) {
  return (
    <div className="flex flex-col items-center justify-center h-full px-8 text-center">
      <div className="w-14 h-14 rounded-xl bg-[#131721] border border-[#2d3240]/60 flex items-center justify-center mb-4">
        <IconSparkles size={24} stroke={1.2} className="text-[#d4a84b]/40" />
      </div>
      <p className="text-[13px] font-syne font-semibold text-[#ece7dc]/70 mb-2">
        No Pattern Selected
      </p>
      <p className="text-[11px] text-[#6f7f9a]/60 max-w-[320px] leading-relaxed">
        Select a pattern to view its sequence and evidence, or click
        &ldquo;Rediscover Patterns&rdquo; to analyze recent sessions.
      </p>
      <button
        onClick={onDiscover}
        className="mt-5 flex items-center gap-2 px-4 py-2 rounded-lg bg-[#d4a84b]/10 border border-[#d4a84b]/20 text-[#d4a84b] text-[11px] font-medium hover:bg-[#d4a84b]/15 hover:border-[#d4a84b]/30 transition-all duration-150"
      >
        <IconSparkles size={14} stroke={1.5} />
        Rediscover Patterns
      </button>
    </div>
  );
}


interface PatternMiningProps {
  patterns: HuntPattern[];
  events: AgentEvent[];
  onPatternsChange: (patterns: HuntPattern[]) => void;
}

export function PatternMining({
  patterns,
  events,
  onPatternsChange,
}: PatternMiningProps) {
  const [selectedId, setSelectedId] = useState<string | null>(null);

  const selectedPattern = useMemo(
    () => patterns.find((p) => p.id === selectedId) ?? null,
    [patterns, selectedId],
  );

  // Status counts
  const statusCounts = useMemo(() => {
    const counts = { confirmed: 0, draft: 0, dismissed: 0, promoted: 0 };
    for (const p of patterns) {
      counts[p.status]++;
    }
    return counts;
  }, [patterns]);

  // Handlers
  const handleUpdatePattern = useCallback(
    (id: string, updates: Partial<HuntPattern>) => {
      onPatternsChange(
        patterns.map((p) => (p.id === id ? { ...p, ...updates } : p)),
      );
    },
    [patterns, onPatternsChange],
  );

  const handlePromoteToTrustprint = useCallback(
    (patternId: string) => {
      const pattern = patterns.find((p) => p.id === patternId);
      if (!pattern) return;

      const trustprintId = `tp-${patternId}-${Date.now().toString(36)}`;
      onPatternsChange(
        patterns.map((p) =>
          p.id === patternId
            ? { ...p, status: "promoted" as PatternStatus, promotedToTrustprint: trustprintId }
            : p,
        ),
      );
    },
    [patterns, onPatternsChange],
  );

  const handleCreateScenario = useCallback(
    (patternId: string) => {
      const pattern = patterns.find((p) => p.id === patternId);
      if (!pattern) return;

      const scenarioId = `scenario-${patternId}-${Date.now().toString(36)}`;
      onPatternsChange(
        patterns.map((p) =>
          p.id === patternId
            ? { ...p, promotedToScenario: scenarioId }
            : p,
        ),
      );
    },
    [patterns, onPatternsChange],
  );

  const handleDiscoverPatterns = useCallback(() => {
    const discovered = discoverPatterns(events, 2, 3);
    // Merge with existing: keep user-confirmed/promoted, add new drafts
    const existingIds = new Set(patterns.map((p) => p.id));
    const kept = patterns.filter(
      (p) => p.status === "confirmed" || p.status === "promoted",
    );
    const newPatterns = discovered.filter((p) => !existingIds.has(p.id));
    onPatternsChange([...kept, ...newPatterns]);

    // Auto-select the first pattern if none selected
    if (!selectedId && (kept.length > 0 || newPatterns.length > 0)) {
      setSelectedId((kept[0] ?? newPatterns[0])?.id ?? null);
    }
  }, [events, patterns, onPatternsChange, selectedId]);

  return (
    <div className="flex h-full min-h-0 bg-[#05060a]">
      {/* ---- Left Sidebar ---- */}
      <div className="w-72 shrink-0 border-r border-[#2d3240] bg-[#0b0d13] flex flex-col">
        {/* Pattern list header */}
        <div className="px-3 py-3 border-b border-[#2d3240]/50">
          <div className="text-[9px] font-mono text-[#6f7f9a] uppercase tracking-wider mb-2">
            Discovered Patterns
          </div>
          <div className="flex items-center gap-3 text-[9px] font-mono">
            {statusCounts.confirmed > 0 && (
              <span className="flex items-center gap-1">
                <span style={{ color: "#3dbf84" }}>{"\u25CF"}</span>
                <span className="text-[#6f7f9a]/60">
                  {statusCounts.confirmed} confirmed
                </span>
              </span>
            )}
            {statusCounts.draft > 0 && (
              <span className="flex items-center gap-1">
                <span style={{ color: "#d4a84b" }}>{"\u25CB"}</span>
                <span className="text-[#6f7f9a]/60">
                  {statusCounts.draft} draft
                </span>
              </span>
            )}
            {statusCounts.dismissed > 0 && (
              <span className="flex items-center gap-1">
                <span style={{ color: "#6f7f9a" }}>{"\u25CC"}</span>
                <span className="text-[#6f7f9a]/60">
                  {statusCounts.dismissed} dismissed
                </span>
              </span>
            )}
            {statusCounts.promoted > 0 && (
              <span className="flex items-center gap-1">
                <span style={{ color: "#8b7355" }}>{"\u25CF"}</span>
                <span className="text-[#6f7f9a]/60">
                  {statusCounts.promoted} promoted
                </span>
              </span>
            )}
            {patterns.length === 0 && (
              <span className="text-[#6f7f9a]/40">No patterns yet</span>
            )}
          </div>
        </div>

        {/* Pattern list */}
        <ScrollArea className="flex-1 min-h-0">
          {patterns.length > 0 ? (
            <div className="py-1">
              {patterns.map((p) => (
                <PatternRow
                  key={p.id}
                  pattern={p}
                  isSelected={selectedId === p.id}
                  onSelect={() => setSelectedId(p.id)}
                />
              ))}
            </div>
          ) : (
            <div className="flex flex-col items-center justify-center px-4 py-10 text-center">
              <IconSparkles
                size={20}
                stroke={1.2}
                className="text-[#6f7f9a]/30 mb-2"
              />
              <p className="text-[10px] text-[#6f7f9a]/40 leading-relaxed">
                No patterns discovered yet. Click below to analyze event sessions.
              </p>
            </div>
          )}
        </ScrollArea>

        {/* Rediscover button */}
        <div className="px-3 py-3 border-t border-[#2d3240]/50">
          <button
            onClick={handleDiscoverPatterns}
            className="w-full flex items-center justify-center gap-2 h-9 rounded-lg bg-[#d4a84b]/10 border border-[#d4a84b]/20 text-[#d4a84b] text-[11px] font-medium hover:bg-[#d4a84b]/15 hover:border-[#d4a84b]/30 transition-all duration-150 active:scale-[0.98]"
          >
            <IconSparkles size={14} stroke={1.5} />
            Rediscover Patterns
          </button>
        </div>

        {/* Embedding scatter plot */}
        {events.length > 0 && <EmbeddingScatter events={events} />}
      </div>

      {/* ---- Right Panel ---- */}
      <div className="flex-1 min-w-0 min-h-0">
        <ScrollArea className="h-full">
          {selectedPattern ? (
            <PatternDetail
              pattern={selectedPattern}
              events={events}
              onUpdatePattern={handleUpdatePattern}
              onPromoteToTrustprint={handlePromoteToTrustprint}
              onCreateScenario={handleCreateScenario}
            />
          ) : (
            <EmptyDetail onDiscover={handleDiscoverPatterns} />
          )}
        </ScrollArea>
      </div>
    </div>
  );
}
