/**
 * PostureSummaryBar + GuardHeatmapTable -- posture analytics display
 * for receipt comparison view.
 *
 * Consumes ReceiptPostureSummary and GuardPolicyHeatmapSummary types
 * from the swarm-board-store.
 */

import type {
  ReceiptPostureSummary,
  GuardPolicySummary,
  GuardPolicyHeatmapSummary,
} from "@/features/swarm/stores/swarm-board-store";

// ---------------------------------------------------------------------------
// Verdict colors
// ---------------------------------------------------------------------------

const VERDICT_COLORS = {
  allow: "#38a876",
  warn: "#c49a3c",
  deny: "#cc5555",
} as const;

// ---------------------------------------------------------------------------
// PostureSummaryBar
// ---------------------------------------------------------------------------

interface PostureSummaryBarProps {
  posture: ReceiptPostureSummary;
}

export function PostureSummaryBar({ posture }: PostureSummaryBarProps) {
  return (
    <div className="flex items-center gap-2 text-[10px] font-mono text-[#5c6a80]">
      <span className="text-[#2a2f3a] uppercase text-[9px]" style={{ letterSpacing: "0.12em" }}>
        Posture
      </span>
      <span className="flex items-center gap-1">
        <span className="inline-block w-1.5 h-1.5 rounded-full" style={{ backgroundColor: VERDICT_COLORS.allow }} />
        <span style={{ color: VERDICT_COLORS.allow }}>{posture.allowCount}</span> allow
      </span>
      <span className="text-[#2a2f3a]">/</span>
      <span className="flex items-center gap-1">
        <span className="inline-block w-1.5 h-1.5 rounded-full" style={{ backgroundColor: VERDICT_COLORS.warn }} />
        <span style={{ color: VERDICT_COLORS.warn }}>{posture.warnCount}</span> warn
      </span>
      <span className="text-[#2a2f3a]">/</span>
      <span className="flex items-center gap-1">
        <span className="inline-block w-1.5 h-1.5 rounded-full" style={{ backgroundColor: VERDICT_COLORS.deny }} />
        <span style={{ color: VERDICT_COLORS.deny }}>{posture.denyCount}</span> deny
      </span>
      <span className="text-[#2a2f3a] ml-1">
        (dominant: <span style={{ color: VERDICT_COLORS[posture.dominantState as keyof typeof VERDICT_COLORS] ?? "#5c6a80" }}>{posture.dominantState}</span>)
      </span>
    </div>
  );
}

// ---------------------------------------------------------------------------
// GuardHeatmapTable
// ---------------------------------------------------------------------------

interface GuardHeatmapTableProps {
  heatmap: GuardPolicyHeatmapSummary;
}

function formatLatency(ms: number | null): string {
  if (ms == null) return "--";
  return `${Math.round(ms)}ms`;
}

function formatPct(ratio: number): string {
  return `${Math.round(ratio * 100)}%`;
}

export function GuardHeatmapTable({ heatmap }: GuardHeatmapTableProps) {
  if (heatmap.guards.length === 0) return null;

  return (
    <div className="mt-2">
      <table className="w-full text-[9px] font-mono">
        <thead>
          <tr className="text-[#2a2f3a] uppercase" style={{ letterSpacing: "0.12em" }}>
            <th className="text-left font-normal py-0.5 pr-2">Guard</th>
            <th className="text-right font-normal py-0.5 px-1">Allow%</th>
            <th className="text-right font-normal py-0.5 px-1">Avg Lat</th>
            <th className="text-right font-normal py-0.5 pl-1">Max Lat</th>
          </tr>
        </thead>
        <tbody>
          {heatmap.guards.map((g: GuardPolicySummary) => (
            <tr key={g.guard} className="text-[#5c6a80]">
              <td className="text-left py-0.5 pr-2 text-[#ece7dc] truncate max-w-[140px]">
                {g.guard}
              </td>
              <td className="text-right py-0.5 px-1" style={{ color: g.allowRatio >= 1 ? "#38a876" : g.allowRatio >= 0.5 ? "#c49a3c" : "#cc5555" }}>
                {formatPct(g.allowRatio)}
              </td>
              <td className="text-right py-0.5 px-1">
                {formatLatency(g.averageLatencyMs)}
              </td>
              <td className="text-right py-0.5 pl-1">
                {formatLatency(g.maxLatencyMs)}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
