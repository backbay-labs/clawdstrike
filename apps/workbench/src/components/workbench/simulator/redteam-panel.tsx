import { useState, useMemo, useCallback } from "react";
import { ScrollArea } from "@/components/ui/scroll-area";
import { cn } from "@/lib/utils";
import type { WorkbenchPolicy, TestScenario, SimulationResult, GuardId } from "@/lib/workbench/types";
import type { RedTeamPlugin, RedTeamPluginRiskScore, RedTeamSystemRiskScore } from "@/lib/workbench/redteam/types";
import { REDTEAM_PLUGINS, GUARD_TO_PLUGINS } from "@/lib/workbench/redteam/plugin-registry";
import { RiskDashboard } from "./risk-dashboard";
import {
  IconFlask,
  IconShieldBolt,
  IconPlayerPlay,
  IconSparkles,
  IconChevronDown,
  IconChevronRight,
  IconCheck,
  IconAlertTriangle,
} from "@tabler/icons-react";

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const SEVERITY_COLORS: Record<string, string> = {
  critical: "#c45c5c",
  high: "#c45c5c",
  medium: "#d4a84b",
  low: "#6f7f9a",
};

const CATEGORY_LABELS: Record<string, string> = {
  prompt_injection: "Prompt Injection",
  jailbreak: "Jailbreak",
  pii: "PII / Secrets",
  injection: "Code Injection",
  network: "Network / SSRF",
  authorization: "Authorization",
  harmful: "Harmful Content",
  integrity: "Integrity",
  tools: "MCP Tools",
  exfiltration: "Data Exfiltration",
  agentic: "Agentic Threats",
};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function groupPluginsByCategory(): Record<string, RedTeamPlugin[]> {
  const groups: Record<string, RedTeamPlugin[]> = {};
  for (const plugin of Object.values(REDTEAM_PLUGINS)) {
    if (!groups[plugin.category]) groups[plugin.category] = [];
    groups[plugin.category].push(plugin);
  }
  return groups;
}

function computeCoverage(
  enabledPlugins: Set<string>,
  scenarios: TestScenario[],
): { covered: number; total: number; uncoveredPlugins: string[] } {
  const total = enabledPlugins.size;
  if (total === 0) return { covered: 0, total: 0, uncoveredPlugins: [] };

  const scenarioPlugins = new Set<string>();
  for (const s of scenarios) {
    const rt = s as TestScenario & { redteamPluginId?: string };
    if (rt.redteamPluginId) scenarioPlugins.add(rt.redteamPluginId);
  }

  const uncoveredPlugins: string[] = [];
  let covered = 0;
  for (const pid of enabledPlugins) {
    if (scenarioPlugins.has(pid)) {
      covered++;
    } else {
      uncoveredPlugins.push(pid);
    }
  }

  return { covered, total, uncoveredPlugins };
}

function computeSystemRisk(
  enabledPlugins: Set<string>,
  scenarios: TestScenario[],
  results: SimulationResult[],
): RedTeamSystemRiskScore | null {
  if (results.length === 0) return null;

  const resultMap = new Map(results.map((r) => [r.scenarioId, r]));
  const pluginScores: RedTeamPluginRiskScore[] = [];
  const distribution: Record<string, number> = {
    critical: 0,
    high: 0,
    medium: 0,
    low: 0,
    informational: 0,
  };

  for (const pluginId of enabledPlugins) {
    const plugin = REDTEAM_PLUGINS[pluginId];
    if (!plugin) continue;

    const pluginScenarios = scenarios.filter((s) => {
      const rt = s as TestScenario & { redteamPluginId?: string };
      return rt.redteamPluginId === pluginId;
    });

    if (pluginScenarios.length === 0) continue;

    let passCount = 0;
    let testCount = 0;
    for (const sc of pluginScenarios) {
      const result = resultMap.get(sc.id);
      if (!result) continue;
      testCount++;
      if (sc.expectedVerdict && sc.expectedVerdict === result.overallVerdict) {
        passCount++;
      } else if (!sc.expectedVerdict && result.overallVerdict === "deny") {
        passCount++;
      }
    }

    if (testCount === 0) continue;

    const successRate = 1 - passCount / testCount;
    let riskScore: number;
    let level: RedTeamPluginRiskScore["riskScore"]["level"];

    const sevMultiplier = plugin.severity === "critical" ? 4 : plugin.severity === "high" ? 3 : plugin.severity === "medium" ? 2 : 1;
    riskScore = Math.round(successRate * sevMultiplier * 25);
    riskScore = Math.min(100, riskScore);

    if (riskScore >= 80) level = "critical";
    else if (riskScore >= 60) level = "high";
    else if (riskScore >= 40) level = "medium";
    else if (riskScore >= 20) level = "low";
    else level = "informational";

    distribution[level]++;
    pluginScores.push({
      pluginId,
      severity: plugin.severity,
      successRate,
      riskScore: { score: riskScore, level },
      testCount,
      passCount,
    });
  }

  if (pluginScores.length === 0) return null;

  const avgScore = Math.round(
    pluginScores.reduce((sum, p) => sum + p.riskScore.score, 0) / pluginScores.length,
  );
  const systemLevel =
    avgScore >= 80 ? "critical" : avgScore >= 60 ? "high" : avgScore >= 40 ? "medium" : avgScore >= 20 ? "low" : "informational";

  return { score: avgScore, level: systemLevel, plugins: pluginScores, distribution };
}

// ---------------------------------------------------------------------------
// Plugin Category Group
// ---------------------------------------------------------------------------

export function PluginCategoryGroup({
  category,
  plugins,
  enabledPlugins,
  onTogglePlugin,
}: {
  category: string;
  plugins: RedTeamPlugin[];
  enabledPlugins: Set<string>;
  onTogglePlugin: (id: string) => void;
}) {
  const [expanded, setExpanded] = useState(false);
  const enabledCount = plugins.filter((p) => enabledPlugins.has(p.id)).length;

  return (
    <div className="border border-[#2d3240] rounded-lg bg-[#0b0d13] overflow-hidden">
      <button
        onClick={() => setExpanded(!expanded)}
        className="flex items-center gap-2 w-full px-3 py-2 hover:bg-[#131721]/40 transition-colors text-left"
      >
        {expanded ? (
          <IconChevronDown size={12} stroke={2} className="text-[#6f7f9a] shrink-0" />
        ) : (
          <IconChevronRight size={12} stroke={2} className="text-[#6f7f9a] shrink-0" />
        )}
        <span className="text-[11px] font-medium text-[#ece7dc] flex-1">
          {CATEGORY_LABELS[category] ?? category}
        </span>
        <span className="text-[10px] font-mono text-[#6f7f9a]">
          {enabledCount}/{plugins.length}
        </span>
      </button>

      {expanded && (
        <div className="border-t border-[#2d3240] divide-y divide-[#2d3240]/40">
          {plugins.map((plugin) => {
            const isEnabled = enabledPlugins.has(plugin.id);
            const sevColor = SEVERITY_COLORS[plugin.severity] ?? "#6f7f9a";

            return (
              <label
                key={plugin.id}
                className="flex items-start gap-2.5 px-3 py-2 cursor-pointer hover:bg-[#131721]/30 transition-colors"
              >
                <input
                  type="checkbox"
                  checked={isEnabled}
                  onChange={() => onTogglePlugin(plugin.id)}
                  className="mt-0.5 accent-[#d4a84b]"
                />
                <div className="flex-1 min-w-0">
                  <div className="flex items-center gap-2">
                    <span className="text-[11px] font-mono text-[#ece7dc] truncate">
                      {plugin.id}
                    </span>
                    <span
                      className="text-[8px] font-mono uppercase px-1 py-0 rounded border shrink-0"
                      style={{
                        color: sevColor,
                        borderColor: `${sevColor}33`,
                        backgroundColor: `${sevColor}0d`,
                      }}
                    >
                      {plugin.severity}
                    </span>
                  </div>
                  <p className="text-[10px] text-[#6f7f9a] mt-0.5 leading-relaxed">
                    {plugin.description}
                  </p>
                </div>
              </label>
            );
          })}
        </div>
      )}
    </div>
  );
}

// ---------------------------------------------------------------------------
// Coverage Indicator
// ---------------------------------------------------------------------------

export function CoverageIndicator({
  covered,
  total,
}: {
  covered: number;
  total: number;
}) {
  if (total === 0) return null;
  const pct = Math.round((covered / total) * 100);
  const color = pct >= 80 ? "#3dbf84" : pct >= 50 ? "#d4a84b" : "#c45c5c";

  return (
    <div className="px-3 py-2.5 border border-[#2d3240] rounded-lg bg-[#0b0d13]">
      <div className="flex items-center justify-between mb-1.5">
        <span className="text-[10px] font-mono uppercase tracking-wider text-[#6f7f9a]">
          Plugin Coverage
        </span>
        <span className="text-[11px] font-mono font-semibold" style={{ color }}>
          {pct}%
        </span>
      </div>
      <div className="h-1.5 rounded-full bg-[#2d3240] overflow-hidden">
        <div
          className="h-full rounded-full transition-all duration-500"
          style={{ width: `${pct}%`, backgroundColor: color }}
        />
      </div>
      <div className="flex items-center justify-between mt-1">
        <span className="text-[9px] text-[#6f7f9a]/60">
          {covered} of {total} plugins have scenarios
        </span>
      </div>
    </div>
  );
}

// ---------------------------------------------------------------------------
// useRedTeamPlugins hook
// ---------------------------------------------------------------------------

export interface UseRedTeamPluginsResult {
  enabledPlugins: Set<string>;
  togglePlugin: (id: string) => void;
  grouped: Record<string, RedTeamPlugin[]>;
  categoryOrder: string[];
  coverage: { covered: number; total: number; uncoveredPlugins: string[] };
  generating: boolean;
  handleGenerate: () => Promise<void>;
  handleFillGaps: () => Promise<void>;
}

export function useRedTeamPlugins(
  policy: WorkbenchPolicy,
  scenarios: TestScenario[],
  onScenariosGenerated: (scenarios: TestScenario[]) => void,
): UseRedTeamPluginsResult {
  const [enabledPlugins, setEnabledPlugins] = useState<Set<string>>(() => {
    const initial = new Set<string>();
    const enabledGuards: GuardId[] = [];

    for (const [gid, cfg] of Object.entries(policy.guards)) {
      if (cfg && (cfg as { enabled?: boolean }).enabled !== false) {
        enabledGuards.push(gid as GuardId);
      }
    }

    for (const gid of enabledGuards) {
      const pluginIds = GUARD_TO_PLUGINS[gid];
      if (pluginIds) {
        for (const pid of pluginIds) initial.add(pid);
      }
    }

    return initial;
  });

  const [generating, setGenerating] = useState(false);

  const grouped = useMemo(() => groupPluginsByCategory(), []);

  const coverage = useMemo(
    () => computeCoverage(enabledPlugins, scenarios),
    [enabledPlugins, scenarios],
  );

  const togglePlugin = useCallback((id: string) => {
    setEnabledPlugins((prev) => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });
  }, []);

  const handleGenerate = useCallback(async () => {
    setGenerating(true);
    try {
      const generated: TestScenario[] = [];
      for (const pluginId of enabledPlugins) {
        const plugin = REDTEAM_PLUGINS[pluginId];
        if (!plugin) continue;

        const actionType =
          plugin.category === "injection" || plugin.category === "network" ? "shell_command" as const
            : plugin.category === "pii" || plugin.category === "exfiltration" ? "file_write" as const
            : plugin.category === "tools" ? "mcp_tool_call" as const
            : "user_input" as const;

        const scenario: TestScenario & { redteamPluginId: string } = {
          id: crypto.randomUUID(),
          name: `[RT] ${plugin.id}`,
          description: `Red team probe: ${plugin.description}`,
          category: "attack",
          actionType,
          payload: { _redteamPlugin: pluginId },
          expectedVerdict: "deny",
          severity: plugin.severity,
          redteamPluginId: pluginId,
        };
        generated.push(scenario);
      }
      onScenariosGenerated(generated);
    } finally {
      setGenerating(false);
    }
  }, [enabledPlugins, onScenariosGenerated]);

  const handleFillGaps = useCallback(async () => {
    setGenerating(true);
    try {
      const generated: TestScenario[] = [];
      for (const pluginId of coverage.uncoveredPlugins) {
        const plugin = REDTEAM_PLUGINS[pluginId];
        if (!plugin) continue;

        const actionType =
          plugin.category === "injection" || plugin.category === "network" ? "shell_command" as const
            : plugin.category === "pii" || plugin.category === "exfiltration" ? "file_write" as const
            : plugin.category === "tools" ? "mcp_tool_call" as const
            : "user_input" as const;

        const scenario: TestScenario & { redteamPluginId: string } = {
          id: crypto.randomUUID(),
          name: `[RT] ${plugin.id} (gap-fill)`,
          description: `Auto-generated to cover gap: ${plugin.description}`,
          category: "attack",
          actionType,
          payload: { _redteamPlugin: pluginId },
          expectedVerdict: "deny",
          severity: plugin.severity,
          redteamPluginId: pluginId,
        };
        generated.push(scenario);
      }
      onScenariosGenerated(generated);
    } finally {
      setGenerating(false);
    }
  }, [coverage.uncoveredPlugins, onScenariosGenerated]);

  const categoryOrder = useMemo(
    () =>
      Object.keys(grouped).sort((a, b) => {
        const aLabel = CATEGORY_LABELS[a] ?? a;
        const bLabel = CATEGORY_LABELS[b] ?? b;
        return aLabel.localeCompare(bLabel);
      }),
    [grouped],
  );

  return {
    enabledPlugins,
    togglePlugin,
    grouped,
    categoryOrder,
    coverage,
    generating,
    handleGenerate,
    handleFillGaps,
  };
}

// ---------------------------------------------------------------------------
// Main Component
// ---------------------------------------------------------------------------

interface RedTeamPanelProps {
  policy: WorkbenchPolicy;
  scenarios: TestScenario[];
  results: SimulationResult[];
  onScenariosGenerated: (scenarios: TestScenario[]) => void;
}

export function RedTeamPanel({
  policy,
  scenarios,
  results,
  onScenariosGenerated,
}: RedTeamPanelProps) {
  const {
    enabledPlugins,
    togglePlugin,
    grouped,
    categoryOrder,
    coverage,
    generating,
    handleGenerate,
    handleFillGaps,
  } = useRedTeamPlugins(policy, scenarios, onScenariosGenerated);

  const systemRisk = useMemo(
    () => computeSystemRisk(enabledPlugins, scenarios, results),
    [enabledPlugins, scenarios, results],
  );

  const pluginScores = useMemo(
    () => systemRisk?.plugins ?? [],
    [systemRisk],
  );

  return (
    <div className="flex h-full min-h-0">
      {/* Left: Plugin selector */}
      <div className="w-80 shrink-0 border-r border-[#2d3240] bg-[#0b0d13] flex flex-col">
        <div className="px-4 py-3 border-b border-[#2d3240] shrink-0">
          <div className="flex items-center gap-2 mb-2">
            <IconFlask size={14} stroke={1.5} className="text-[#d4a84b]" />
            <h3 className="font-syne font-bold text-sm text-[#ece7dc]">
              Attack Plugins
            </h3>
          </div>
          <p className="text-[10px] text-[#6f7f9a] leading-relaxed">
            Select plugins to generate adversarial test scenarios against your policy.
          </p>
        </div>

        <ScrollArea className="flex-1 overflow-y-auto">
          <div className="p-3 space-y-2">
            {categoryOrder.map((cat) => (
              <PluginCategoryGroup
                key={cat}
                category={cat}
                plugins={grouped[cat]}
                enabledPlugins={enabledPlugins}
                onTogglePlugin={togglePlugin}
              />
            ))}
          </div>
        </ScrollArea>

        {/* Actions */}
        <div className="px-3 py-3 border-t border-[#2d3240] shrink-0 space-y-2">
          <CoverageIndicator covered={coverage.covered} total={coverage.total} />

          <button
            onClick={handleGenerate}
            disabled={enabledPlugins.size === 0 || generating}
            className={cn(
              "w-full flex items-center justify-center gap-1.5 px-3 py-2 rounded-md text-[11px] font-medium transition-colors",
              enabledPlugins.size > 0 && !generating
                ? "bg-[#d4a84b]/10 text-[#d4a84b] hover:bg-[#d4a84b]/20"
                : "bg-[#131721] text-[#6f7f9a]/40 cursor-not-allowed",
            )}
          >
            <IconPlayerPlay size={13} stroke={1.5} />
            {generating ? "Generating..." : `Generate ${enabledPlugins.size} Scenarios`}
          </button>

          {coverage.uncoveredPlugins.length > 0 && (
            <button
              onClick={handleFillGaps}
              disabled={generating}
              className={cn(
                "w-full flex items-center justify-center gap-1.5 px-3 py-1.5 rounded-md text-[11px] font-medium transition-colors",
                !generating
                  ? "bg-[#c45c5c]/10 text-[#c45c5c] hover:bg-[#c45c5c]/20"
                  : "bg-[#131721] text-[#6f7f9a]/40 cursor-not-allowed",
              )}
            >
              <IconSparkles size={13} stroke={1.5} />
              Fill {coverage.uncoveredPlugins.length} Gaps
            </button>
          )}
        </div>
      </div>

      {/* Right: Risk dashboard */}
      <div className="flex-1 min-w-0 bg-[#05060a] overflow-auto">
        {systemRisk ? (
          <RiskDashboard
            systemScore={systemRisk}
            pluginScores={pluginScores}
          />
        ) : (
          <div className="flex flex-col items-center justify-center h-full text-[#6f7f9a] px-8">
            <div className="w-16 h-16 rounded-2xl bg-[#131721] border border-[#2d3240]/60 flex items-center justify-center mb-5">
              <IconShieldBolt size={24} stroke={1.2} className="text-[#6f7f9a]" />
            </div>
            <span className="text-[14px] font-medium text-[#6f7f9a] mb-1.5">
              No red team results yet
            </span>
            <span className="text-[12px] text-[#6f7f9a]/60 text-center leading-relaxed max-w-[300px]">
              Generate scenarios from the plugin selector, then run them in the Scenarios tab to see risk analysis
            </span>
          </div>
        )}
      </div>
    </div>
  );
}
