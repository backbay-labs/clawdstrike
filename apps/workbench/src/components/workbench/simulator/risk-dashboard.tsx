import { useMemo } from "react";
import { ScrollArea } from "@/components/ui/scroll-area";
import { cn } from "@/lib/utils";
import { REDTEAM_PLUGINS, GUARD_TO_PLUGINS } from "@/lib/workbench/redteam/plugin-registry";
import type { RedTeamSystemRiskScore, RedTeamPluginRiskScore } from "@/lib/workbench/redteam/types";
import type { GuardId } from "@/lib/workbench/types";
import {
  IconShieldExclamation,
  IconAlertTriangle,
  IconCheck,
  IconX,
} from "@tabler/icons-react";
import { ClaudeCodeHint } from "@/components/workbench/shared/claude-code-hint";

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const LEVEL_COLORS: Record<string, string> = {
  critical: "#c45c5c",
  high: "#c45c5c",
  medium: "#d4a84b",
  low: "#3dbf84",
  informational: "#6f7f9a",
};

const LEVEL_LABELS: Record<string, string> = {
  critical: "CRITICAL",
  high: "HIGH",
  medium: "MEDIUM",
  low: "LOW",
  informational: "INFO",
};

const DIST_KEYS = ["critical", "high", "medium", "low", "informational"] as const;

// ---------------------------------------------------------------------------
// Score Ring
// ---------------------------------------------------------------------------

function RiskScoreRing({ score, level }: { score: number; level: string }) {
  const color = LEVEL_COLORS[level] ?? "#6f7f9a";
  const radius = 42;
  const circumference = 2 * Math.PI * radius;
  const offset = circumference - (score / 100) * circumference;

  return (
    <div className="relative w-28 h-28">
      <svg viewBox="0 0 100 100" className="w-full h-full -rotate-90">
        <circle
          cx="50" cy="50" r={radius}
          fill="none" stroke="#2d3240" strokeWidth="6"
        />
        <circle
          cx="50" cy="50" r={radius}
          fill="none" stroke={color} strokeWidth="6"
          strokeLinecap="round"
          strokeDasharray={circumference}
          strokeDashoffset={offset}
          className="transition-all duration-700 ease-out"
        />
      </svg>
      <div className="absolute inset-0 flex flex-col items-center justify-center">
        <span className="text-2xl font-syne font-extrabold" style={{ color }}>
          {score}
        </span>
        <span className="text-[9px] font-mono uppercase tracking-wider text-[#6f7f9a]">
          Risk
        </span>
      </div>
    </div>
  );
}

// ---------------------------------------------------------------------------
// Distribution Bar
// ---------------------------------------------------------------------------

function DistributionBar({ distribution }: { distribution: Record<string, number> }) {
  const total = DIST_KEYS.reduce((sum, k) => sum + (distribution[k] ?? 0), 0);
  if (total === 0) return null;

  return (
    <div>
      <div className="flex items-center gap-1 mb-1.5">
        <span className="text-[10px] font-mono uppercase tracking-wider text-[#6f7f9a]">
          Distribution
        </span>
      </div>
      <div className="flex h-3 rounded-full overflow-hidden bg-[#2d3240]">
        {DIST_KEYS.map((key) => {
          const count = distribution[key] ?? 0;
          if (count === 0) return null;
          const pct = (count / total) * 100;
          return (
            <div
              key={key}
              className="h-full transition-all duration-500"
              style={{
                width: `${pct}%`,
                backgroundColor: LEVEL_COLORS[key],
              }}
              title={`${LEVEL_LABELS[key]}: ${count}`}
            />
          );
        })}
      </div>
      <div className="flex items-center gap-3 mt-1.5">
        {DIST_KEYS.map((key) => {
          const count = distribution[key] ?? 0;
          if (count === 0) return null;
          return (
            <span key={key} className="flex items-center gap-1 text-[9px] font-mono">
              <span
                className="w-1.5 h-1.5 rounded-full shrink-0"
                style={{ backgroundColor: LEVEL_COLORS[key] }}
              />
              <span style={{ color: LEVEL_COLORS[key] }}>
                {count} {LEVEL_LABELS[key]}
              </span>
            </span>
          );
        })}
      </div>
    </div>
  );
}

// ---------------------------------------------------------------------------
// Per-guard risk summary
// ---------------------------------------------------------------------------

interface GuardRiskEntry {
  guardId: GuardId;
  pluginCount: number;
  avgRiskScore: number;
  level: string;
}

function computeGuardRisks(pluginScores: RedTeamPluginRiskScore[]): GuardRiskEntry[] {
  const guardMap = new Map<GuardId, { total: number; count: number }>();

  for (const ps of pluginScores) {
    const plugin = REDTEAM_PLUGINS[ps.pluginId];
    if (!plugin) continue;
    for (const gid of plugin.guardMapping) {
      const entry = guardMap.get(gid) ?? { total: 0, count: 0 };
      entry.total += ps.riskScore.score;
      entry.count++;
      guardMap.set(gid, entry);
    }
  }

  const entries: GuardRiskEntry[] = [];
  for (const [gid, { total, count }] of guardMap) {
    const avg = Math.round(total / count);
    const level =
      avg >= 80 ? "critical" : avg >= 60 ? "high" : avg >= 40 ? "medium" : avg >= 20 ? "low" : "informational";
    entries.push({ guardId: gid, pluginCount: count, avgRiskScore: avg, level });
  }

  return entries.sort((a, b) => b.avgRiskScore - a.avgRiskScore);
}

// ---------------------------------------------------------------------------
// Main Component
// ---------------------------------------------------------------------------

interface RiskDashboardProps {
  systemScore: RedTeamSystemRiskScore | null;
  pluginScores: RedTeamPluginRiskScore[];
}

export function RiskDashboard({ systemScore, pluginScores }: RiskDashboardProps) {
  const guardRisks = useMemo(() => computeGuardRisks(pluginScores), [pluginScores]);

  if (!systemScore) {
    return (
      <div className="flex flex-col items-center justify-center h-full text-[#6f7f9a] px-8">
        <IconShieldExclamation size={24} stroke={1.2} className="mb-3" />
        <span className="text-[12px] mb-5">Run red team scenarios to see risk analysis</span>
        <ClaudeCodeHint
          hintId="risk.assess"
          className="max-w-md w-full"
        />
      </div>
    );
  }

  const levelColor = LEVEL_COLORS[systemScore.level] ?? "#6f7f9a";

  return (
    <ScrollArea className="h-full">
      <div className="p-5 space-y-5">
        {/* System risk header */}
        <div className="flex items-start gap-5">
          <RiskScoreRing score={systemScore.score} level={systemScore.level} />
          <div className="flex-1 pt-2">
            <h3 className="font-syne font-bold text-base text-[#ece7dc] mb-1">
              System Risk Score
            </h3>
            <span
              className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-md border text-[10px] font-mono font-semibold uppercase tracking-wider"
              style={{
                color: levelColor,
                borderColor: `${levelColor}33`,
                backgroundColor: `${levelColor}0d`,
              }}
            >
              <IconAlertTriangle size={11} stroke={1.5} />
              {LEVEL_LABELS[systemScore.level] ?? systemScore.level}
            </span>
            <p className="text-[10px] text-[#6f7f9a] mt-2 leading-relaxed">
              Based on {pluginScores.length} plugin{pluginScores.length !== 1 ? "s" : ""} with test results.
              Higher scores indicate greater exposure to adversarial attack vectors.
            </p>
          </div>
        </div>

        {/* Distribution bar */}
        <DistributionBar distribution={systemScore.distribution} />

        {/* Per-guard risk */}
        {guardRisks.length > 0 && (
          <div>
            <h4 className="text-[10px] font-mono uppercase tracking-wider text-[#6f7f9a] mb-2">
              Guard Exposure
            </h4>
            <div className="space-y-1">
              {guardRisks.map((gr) => {
                const color = LEVEL_COLORS[gr.level] ?? "#6f7f9a";
                return (
                  <div
                    key={gr.guardId}
                    className="flex items-center gap-2.5 px-3 py-2 rounded-md bg-[#0b0d13] border border-[#2d3240]"
                  >
                    <span
                      className="w-2 h-2 rounded-full shrink-0"
                      style={{ backgroundColor: color }}
                    />
                    <span className="text-[11px] font-mono text-[#ece7dc] flex-1 truncate">
                      {gr.guardId}
                    </span>
                    <span className="text-[10px] font-mono text-[#6f7f9a]">
                      {gr.pluginCount} plugin{gr.pluginCount !== 1 ? "s" : ""}
                    </span>
                    <span
                      className="text-[10px] font-mono font-semibold"
                      style={{ color }}
                    >
                      {gr.avgRiskScore}
                    </span>
                  </div>
                );
              })}
            </div>
          </div>
        )}

        {/* Per-plugin breakdown table */}
        <div>
          <h4 className="text-[10px] font-mono uppercase tracking-wider text-[#6f7f9a] mb-2">
            Plugin Breakdown
          </h4>
          <div className="border border-[#2d3240] rounded-lg overflow-hidden">
            <table className="w-full text-left">
              <thead>
                <tr className="border-b border-[#2d3240] bg-[#0b0d13]">
                  <th className="text-[9px] font-mono uppercase tracking-wider text-[#6f7f9a] px-3 py-2">
                    Plugin
                  </th>
                  <th className="text-[9px] font-mono uppercase tracking-wider text-[#6f7f9a] px-2 py-2 text-center">
                    Sev
                  </th>
                  <th className="text-[9px] font-mono uppercase tracking-wider text-[#6f7f9a] px-2 py-2 text-center">
                    Pass/Fail
                  </th>
                  <th className="text-[9px] font-mono uppercase tracking-wider text-[#6f7f9a] px-3 py-2 text-right">
                    Risk
                  </th>
                </tr>
              </thead>
              <tbody>
                {pluginScores
                  .sort((a, b) => b.riskScore.score - a.riskScore.score)
                  .map((ps) => {
                    const sevColor = LEVEL_COLORS[ps.severity] ?? "#6f7f9a";
                    const riskColor = LEVEL_COLORS[ps.riskScore.level] ?? "#6f7f9a";
                    const failCount = ps.testCount - ps.passCount;
                    return (
                      <tr
                        key={ps.pluginId}
                        className="border-b border-[#2d3240]/40 last:border-b-0"
                      >
                        <td className="px-3 py-1.5">
                          <span className="text-[11px] font-mono text-[#ece7dc]">
                            {ps.pluginId}
                          </span>
                        </td>
                        <td className="px-2 py-1.5 text-center">
                          <span
                            className="text-[8px] font-mono uppercase px-1 py-0 rounded border"
                            style={{
                              color: sevColor,
                              borderColor: `${sevColor}33`,
                              backgroundColor: `${sevColor}0d`,
                            }}
                          >
                            {ps.severity}
                          </span>
                        </td>
                        <td className="px-2 py-1.5 text-center">
                          <span className="flex items-center justify-center gap-1.5">
                            <span className="flex items-center gap-0.5 text-[10px] font-mono text-[#3dbf84]">
                              <IconCheck size={10} stroke={2} />
                              {ps.passCount}
                            </span>
                            <span className="text-[#2d3240]">/</span>
                            <span className="flex items-center gap-0.5 text-[10px] font-mono text-[#c45c5c]">
                              <IconX size={10} stroke={2} />
                              {failCount}
                            </span>
                          </span>
                        </td>
                        <td className="px-3 py-1.5 text-right">
                          <span
                            className="text-[11px] font-mono font-semibold"
                            style={{ color: riskColor }}
                          >
                            {ps.riskScore.score}
                          </span>
                        </td>
                      </tr>
                    );
                  })}
              </tbody>
            </table>
          </div>
        </div>
      </div>
    </ScrollArea>
  );
}
