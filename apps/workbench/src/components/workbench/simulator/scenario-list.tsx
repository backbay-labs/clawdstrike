import { useState, useCallback } from "react";
import {
  IconFile,
  IconFileText,
  IconNetwork,
  IconTerminal,
  IconTool,
  IconPencil,
  IconMessage,
  IconPlus,
  IconPlayerPlay,
  IconSkull,
  IconShieldCheck,
  IconAlertTriangle,
  IconWand,
  IconTarget,
  IconCircleCheck,
  IconCircleX,
  IconCircleDashed,
  IconFlask,
  IconSparkles,
  IconTestPipe,
} from "@tabler/icons-react";
import { ScrollArea } from "@/components/ui/scroll-area";
import { VerdictBadge } from "@/components/workbench/shared/verdict-badge";
import { cn } from "@/lib/utils";
import type { TestScenario, TestActionType, ThreatSeverity, WorkbenchPolicy } from "@/lib/workbench/types";
import type { CoverageReport, GuardCoverageStatus } from "@/lib/workbench/coverage-analyzer";
import { useRedTeamPlugins, PluginCategoryGroup, CoverageIndicator } from "./redteam-panel";

const ACTION_TYPE_ICONS: Record<TestActionType, typeof IconFile> = {
  file_access: IconFile,
  file_write: IconFileText,
  network_egress: IconNetwork,
  shell_command: IconTerminal,
  mcp_tool_call: IconTool,
  patch_apply: IconPencil,
  user_input: IconMessage,
};

const SEVERITY_STYLES: Record<ThreatSeverity, { label: string; dotClass: string; textClass: string }> = {
  critical: { label: "CRIT", dotClass: "bg-[#c45c5c]", textClass: "text-[#c45c5c]" },
  high: { label: "HIGH", dotClass: "bg-[#e07c4f]", textClass: "text-[#e07c4f]" },
  medium: { label: "MED", dotClass: "bg-[#d4a84b]", textClass: "text-[#d4a84b]" },
  low: { label: "LOW", dotClass: "bg-[#3dbf84]", textClass: "text-[#3dbf84]" },
  informational: { label: "INFO", dotClass: "bg-[#1976d2]", textClass: "text-[#1976d2]" },
};

const CATEGORY_META: Record<string, {
  label: string;
  description: string;
  Icon: typeof IconSkull;
  iconClass: string;
}> = {
  attack: {
    label: "Adversarial Probes",
    description: "Simulated adversarial actions targeting known attack surfaces",
    Icon: IconSkull,
    iconClass: "text-[#c45c5c]",
  },
  benign: {
    label: "Legitimate Operations",
    description: "Sanctioned agent actions that should pass all guards",
    Icon: IconShieldCheck,
    iconClass: "text-[#3dbf84]",
  },
  edge_case: {
    label: "Boundary Conditions",
    description: "Ambiguous inputs testing guard threshold behavior",
    Icon: IconAlertTriangle,
    iconClass: "text-[#d4a84b]",
  },
};

function SeverityIndicator({ severity }: { severity?: ThreatSeverity }) {
  if (!severity) return null;
  const style = SEVERITY_STYLES[severity];
  return (
    <span className={cn("inline-flex items-center gap-1 shrink-0")}>
      <span className={cn("w-1.5 h-1.5 rounded-full shrink-0", style.dotClass)} />
      <span className={cn("text-[8px] font-mono uppercase tracking-wider", style.textClass)}>
        {style.label}
      </span>
    </span>
  );
}

function ThreatPostureSummary({ scenarios }: { scenarios: TestScenario[] }) {
  const total = scenarios.length;
  const withExpectation = scenarios.filter((s) => s.expectedVerdict != null);
  const covered = withExpectation.length;
  const criticalGaps = scenarios.filter(
    (s) => s.severity === "critical" && !s.expectedVerdict,
  ).length;
  const criticalCount = scenarios.filter((s) => s.severity === "critical").length;
  const highCount = scenarios.filter((s) => s.severity === "high").length;

  return (
    <div className="px-4 py-2.5 border-b border-[#2d3240] bg-[#0b0d13]">
      <div className="flex items-center justify-between mb-1.5">
        <span className="text-[10px] font-mono uppercase tracking-wider text-[#6f7f9a]" title="Resource usage limits and automated state transitions for agent capabilities">
          Threat Posture
        </span>
        <span className="text-[10px] font-mono text-[#d4a84b]">
          {covered}/{total} covered
        </span>
      </div>
      <div className="flex items-center gap-2">
        <div className="flex-1 h-1.5 rounded-full bg-[#131721] overflow-hidden">
          <div
            className="h-full rounded-full bg-[#d4a84b] transition-all duration-500"
            style={{ width: `${total > 0 ? (covered / total) * 100 : 0}%` }}
          />
        </div>
      </div>
      <div className="flex items-center gap-3 mt-1.5">
        {criticalCount > 0 && (
          <span className="text-[9px] font-mono text-[#c45c5c]">
            {criticalCount} critical
          </span>
        )}
        {highCount > 0 && (
          <span className="text-[9px] font-mono text-[#e07c4f]">
            {highCount} high
          </span>
        )}
        {criticalGaps > 0 && (
          <span className="text-[9px] font-mono text-[#c45c5c]/70">
            {criticalGaps} gap{criticalGaps !== 1 ? "s" : ""}
          </span>
        )}
      </div>
    </div>
  );
}


const COVERAGE_STATUS_ICONS: Record<
  GuardCoverageStatus,
  { Icon: typeof IconCircleCheck; className: string }
> = {
  covered: { Icon: IconCircleCheck, className: "text-[#3dbf84]" },
  uncovered: { Icon: IconCircleX, className: "text-[#c45c5c]" },
  disabled: { Icon: IconCircleDashed, className: "text-[#6f7f9a]/40" },
};


export type ScenarioSource = "library" | "redteam";

interface ScenarioListProps {
  scenarios: TestScenario[];
  autoScenarios?: TestScenario[];
  selectedId: string | null;
  onSelect: (id: string) => void;
  onAdd: () => void;
  onRunAll: () => void;
  onGenerate?: () => void;
  onRunAutoScenarios?: () => void;
  onScenariosGenerated?: (scenarios: TestScenario[]) => void;
  coverageReport?: CoverageReport | null;
  policy?: WorkbenchPolicy;
  horizontal?: boolean;
}

export function ScenarioList({
  scenarios,
  autoScenarios,
  selectedId,
  onSelect,
  onAdd,
  onRunAll,
  onGenerate,
  onRunAutoScenarios,
  onScenariosGenerated,
  coverageReport,
  policy,
  horizontal,
}: ScenarioListProps) {
  const [source, setSource] = useState<ScenarioSource>("library");

  const attacks = scenarios.filter((s) => s.category === "attack");
  const benign = scenarios.filter((s) => s.category === "benign");
  const edgeCases = scenarios.filter((s) => s.category === "edge_case");

  // Auto-generated scenarios grouped by category
  const autoAttacks = autoScenarios?.filter((s) => s.category === "attack") ?? [];
  const autoBenign = autoScenarios?.filter((s) => s.category === "benign") ?? [];
  const autoEdgeCases = autoScenarios?.filter((s) => s.category === "edge_case") ?? [];
  const hasAutoScenarios = (autoScenarios?.length ?? 0) > 0;
  const canUseRedTeamSource = Boolean(policy && onScenariosGenerated);

  // Wrap onScenariosGenerated to auto-switch back to library after generation
  const handleRedTeamGenerated = useCallback(
    (generated: TestScenario[]) => {
      onScenariosGenerated?.(generated);
      setSource("library");
    },
    [onScenariosGenerated],
  );

  const renderSourceToggle = (className?: string) => {
    if (!canUseRedTeamSource) return null;

    return (
      <div className={cn("flex items-center gap-1 bg-[#0b0d13]", className)}>
        <button
          onClick={() => setSource("library")}
          className={cn(
            "flex-1 flex items-center justify-center gap-1.5 px-2 py-1.5 rounded-md text-[11px] font-medium transition-colors",
            source === "library"
              ? "bg-[#131721] text-[#ece7dc] border border-[#2d3240]"
              : "text-[#6f7f9a] hover:text-[#ece7dc] hover:bg-[#131721]/40",
          )}
        >
          <IconTestPipe size={12} stroke={1.5} />
          Library
        </button>
        <button
          onClick={() => setSource("redteam")}
          className={cn(
            "flex-1 flex items-center justify-center gap-1.5 px-2 py-1.5 rounded-md text-[11px] font-medium transition-colors",
            source === "redteam"
              ? "bg-[#d4a84b]/10 text-[#d4a84b] border border-[#d4a84b]/25"
              : "text-[#6f7f9a] hover:text-[#d4a84b] hover:bg-[#d4a84b]/5",
          )}
        >
          <IconFlask size={12} stroke={1.5} />
          Red Team
        </button>
      </div>
    );
  };

  const renderHorizontalLibraryContent = () => (
    <div className="flex items-center gap-2 p-3 overflow-x-auto">
      {scenarios.map((s) => {
        const Icon = ACTION_TYPE_ICONS[s.actionType];
        const active = s.id === selectedId;
        return (
          <button
            key={s.id}
            onClick={() => onSelect(s.id)}
            className={cn(
              "shrink-0 flex items-center gap-1.5 px-2.5 py-1.5 rounded-md text-xs transition-colors",
              active
                ? "bg-[#131721] text-[#ece7dc]"
                : "text-[#6f7f9a] hover:text-[#ece7dc] hover:bg-[#131721]/50",
            )}
          >
            <Icon size={13} stroke={1.5} />
            <span className="truncate max-w-[120px]">{s.name}</span>
            {s.severity && <SeverityIndicator severity={s.severity} />}
          </button>
        );
      })}
      {hasAutoScenarios && (
        <>
          <div className="w-px h-6 bg-[#7c5cbf]/30 shrink-0" />
          {autoScenarios!.map((s) => {
            const Icon = ACTION_TYPE_ICONS[s.actionType];
            const active = s.id === selectedId;
            return (
              <button
                key={s.id}
                onClick={() => onSelect(s.id)}
                className={cn(
                  "shrink-0 flex items-center gap-1.5 px-2.5 py-1.5 rounded-md text-xs transition-colors",
                  active
                    ? "bg-[#7c5cbf]/20 text-[#ece7dc]"
                    : "text-[#6f7f9a] hover:text-[#ece7dc] hover:bg-[#7c5cbf]/10",
                )}
              >
                <Icon size={13} stroke={1.5} />
                <span className="truncate max-w-[120px]">{s.name}</span>
              </button>
            );
          })}
        </>
      )}
    </div>
  );

  const renderRedTeamContent = () => {
    if (!policy || !onScenariosGenerated) return null;

    return (
      <RedTeamContent
        policy={policy}
        scenarios={scenarios}
        autoScenarios={autoScenarios}
        onScenariosGenerated={handleRedTeamGenerated}
      />
    );
  };

  if (horizontal) {
    return (
      <div className="bg-[#0b0d13]">
        <div className="flex items-center gap-2 p-3 overflow-x-auto border-b border-[#2d3240]">
          <button
            onClick={onRunAll}
            className="shrink-0 flex items-center gap-1.5 px-3 py-1.5 rounded-md bg-[#d4a84b]/10 text-[#d4a84b] text-xs font-medium hover:bg-[#d4a84b]/20 transition-colors"
            title="Execute all probes (Ctrl+Shift+Enter)"
          >
            <IconPlayerPlay size={14} stroke={1.5} />
            Execute All
          </button>
          {onGenerate && (
            <button
              onClick={onGenerate}
              className="shrink-0 flex items-center gap-1.5 px-3 py-1.5 rounded-md bg-[#7c5cbf]/10 text-[#a78bda] text-xs font-medium hover:bg-[#7c5cbf]/20 transition-colors"
              title="Generate smart scenarios from policy"
            >
              <IconWand size={14} stroke={1.5} />
              Smart
            </button>
          )}
          <button
            onClick={onAdd}
            className="shrink-0 flex items-center gap-1.5 px-3 py-1.5 rounded-md bg-[#131721] text-[#6f7f9a] text-xs font-medium hover:text-[#ece7dc] transition-colors"
          >
            <IconPlus size={14} stroke={1.5} />
            Add
          </button>
        </div>

        {renderSourceToggle("px-3 py-2 border-b border-[#2d3240]")}

        {source === "redteam" && canUseRedTeamSource ? (
          <div className="flex flex-col h-[24rem]">
            {renderRedTeamContent()}
          </div>
        ) : (
          renderHorizontalLibraryContent()
        )}
      </div>
    );
  }

  return (
    <>
      {/* Header */}
      <div className="flex items-center justify-between px-4 py-3 border-b border-[#2d3240] shrink-0">
        <h2 className="font-syne font-bold text-sm text-[#ece7dc]">
          Scenarios
        </h2>
        <div className="flex items-center gap-1.5">
          <button
            onClick={onRunAll}
            className="flex items-center gap-1 px-2 py-1 rounded-md bg-[#d4a84b]/10 text-[#d4a84b] text-[11px] font-medium hover:bg-[#d4a84b]/20 transition-colors"
            title="Execute all probes (Ctrl+Shift+Enter)"
          >
            <IconPlayerPlay size={12} stroke={1.5} />
            Execute All
          </button>
          <button
            onClick={onAdd}
            className="flex items-center gap-1 px-2 py-1 rounded-md bg-[#131721] text-[#6f7f9a] text-[11px] font-medium hover:text-[#ece7dc] transition-colors"
          >
            <IconPlus size={12} stroke={1.5} />
            Add
          </button>
        </div>
      </div>

      {/* Source mode toggle */}
      {renderSourceToggle("px-3 py-2 border-b border-[#2d3240] shrink-0")}

      {!canUseRedTeamSource || source === "library" ? (
        <LibraryContent
          scenarios={scenarios}
          autoScenarios={autoScenarios}
          attacks={attacks}
          benign={benign}
          edgeCases={edgeCases}
          autoAttacks={autoAttacks}
          autoBenign={autoBenign}
          autoEdgeCases={autoEdgeCases}
          hasAutoScenarios={hasAutoScenarios}
          selectedId={selectedId}
          onSelect={onSelect}
          onGenerate={onGenerate}
          onRunAutoScenarios={onRunAutoScenarios}
          coverageReport={coverageReport}
        />
      ) : renderRedTeamContent()}
    </>
  );
}


function LibraryContent({
  scenarios,
  autoScenarios,
  attacks,
  benign,
  edgeCases,
  autoAttacks,
  autoBenign,
  autoEdgeCases,
  hasAutoScenarios,
  selectedId,
  onSelect,
  onGenerate,
  onRunAutoScenarios,
  coverageReport,
}: {
  scenarios: TestScenario[];
  autoScenarios?: TestScenario[];
  attacks: TestScenario[];
  benign: TestScenario[];
  edgeCases: TestScenario[];
  autoAttacks: TestScenario[];
  autoBenign: TestScenario[];
  autoEdgeCases: TestScenario[];
  hasAutoScenarios: boolean;
  selectedId: string | null;
  onSelect: (id: string) => void;
  onGenerate?: () => void;
  onRunAutoScenarios?: () => void;
  coverageReport?: CoverageReport | null;
}) {
  return (
    <>
      {/* Threat posture summary */}
      <ThreatPostureSummary scenarios={scenarios} />

      {/* Scenario groups */}
      <ScrollArea className="flex-1 overflow-y-auto">
        <div className="py-2">
          <ScenarioGroup
            categoryKey="attack"
            scenarios={attacks}
            selectedId={selectedId}
            onSelect={onSelect}
          />
          <ScenarioGroup
            categoryKey="benign"
            scenarios={benign}
            selectedId={selectedId}
            onSelect={onSelect}
          />
          <ScenarioGroup
            categoryKey="edge_case"
            scenarios={edgeCases}
            selectedId={selectedId}
            onSelect={onSelect}
          />

          {/* Smart Scenarios section */}
          <div className="mt-3 border-t border-[#2d3240]/60 pt-2">
            <div className="flex items-center justify-between px-4 py-2">
              <div className="flex items-center gap-1.5">
                <IconWand size={12} stroke={1.5} className="text-[#a78bda]" />
                <span className="text-[10px] font-mono uppercase tracking-wider text-[#a78bda]">
                  Smart Scenarios
                </span>
                {hasAutoScenarios && (
                  <span className="text-[9px] font-mono text-[#a78bda]/50 ml-1">
                    {autoScenarios!.length}
                  </span>
                )}
              </div>
              {coverageReport && (
                <CoverageBadge report={coverageReport} />
              )}
            </div>

            {!hasAutoScenarios ? (
              <div className="px-4 pb-2">
                <button
                  onClick={onGenerate}
                  className="w-full flex items-center justify-center gap-1.5 px-3 py-2 rounded-md bg-[#7c5cbf]/10 text-[#a78bda] text-[11px] font-medium hover:bg-[#7c5cbf]/20 transition-colors border border-[#7c5cbf]/20 hover:border-[#7c5cbf]/40"
                >
                  <IconWand size={13} stroke={1.5} />
                  Generate from Policy
                </button>
                <p className="text-[9px] text-[#6f7f9a]/50 text-center mt-1.5 leading-relaxed">
                  Analyze your policy and generate targeted test scenarios for each enabled guard
                </p>
              </div>
            ) : (
              <>
                {/* Coverage details */}
                {coverageReport && (
                  <CoverageDetails report={coverageReport} />
                )}

                {/* Run auto scenarios + regenerate buttons */}
                <div className="flex items-center gap-1.5 px-4 pb-2">
                  {onRunAutoScenarios && (
                    <button
                      onClick={onRunAutoScenarios}
                      className="flex-1 flex items-center justify-center gap-1 px-2 py-1 rounded-md bg-[#7c5cbf]/10 text-[#a78bda] text-[11px] font-medium hover:bg-[#7c5cbf]/20 transition-colors"
                    >
                      <IconPlayerPlay size={11} stroke={1.5} />
                      Run Smart
                    </button>
                  )}
                  {onGenerate && (
                    <button
                      onClick={onGenerate}
                      className="flex items-center justify-center gap-1 px-2 py-1 rounded-md bg-[#131721] text-[#6f7f9a] text-[11px] font-medium hover:text-[#a78bda] transition-colors"
                      title="Regenerate scenarios from current policy"
                    >
                      <IconWand size={11} stroke={1.5} />
                      Regen
                    </button>
                  )}
                </div>

                {/* Auto-generated scenario groups */}
                <AutoScenarioGroup
                  categoryKey="attack"
                  scenarios={autoAttacks}
                  selectedId={selectedId}
                  onSelect={onSelect}
                />
                <AutoScenarioGroup
                  categoryKey="benign"
                  scenarios={autoBenign}
                  selectedId={selectedId}
                  onSelect={onSelect}
                />
                <AutoScenarioGroup
                  categoryKey="edge_case"
                  scenarios={autoEdgeCases}
                  selectedId={selectedId}
                  onSelect={onSelect}
                />
              </>
            )}
          </div>
        </div>
      </ScrollArea>
    </>
  );
}


function RedTeamContent({
  policy,
  scenarios,
  autoScenarios,
  onScenariosGenerated,
}: {
  policy: WorkbenchPolicy;
  scenarios: TestScenario[];
  autoScenarios?: TestScenario[];
  onScenariosGenerated: (scenarios: TestScenario[]) => void;
}) {
  const allScenarios = [...scenarios, ...(autoScenarios ?? [])];

  const {
    enabledPlugins,
    togglePlugin,
    grouped,
    categoryOrder,
    coverage,
    generating,
    handleGenerate,
    handleFillGaps,
  } = useRedTeamPlugins(policy, allScenarios, onScenariosGenerated);

  return (
    <>
      {/* Plugin header */}
      <div className="px-4 py-2.5 border-b border-[#2d3240] bg-[#0b0d13] shrink-0">
        <div className="flex items-center gap-2 mb-1">
          <IconFlask size={12} stroke={1.5} className="text-[#d4a84b]" />
          <span className="text-[10px] font-mono uppercase tracking-wider text-[#d4a84b]">
            Attack Plugins
          </span>
        </div>
        <p className="text-[9px] text-[#6f7f9a] leading-relaxed">
          Select plugins to generate adversarial test scenarios against your policy.
        </p>
      </div>

      {/* Plugin category list */}
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
    </>
  );
}

function ScenarioGroup({
  categoryKey,
  scenarios,
  selectedId,
  onSelect,
}: {
  categoryKey: string;
  scenarios: TestScenario[];
  selectedId: string | null;
  onSelect: (id: string) => void;
}) {
  if (scenarios.length === 0) return null;

  const meta = CATEGORY_META[categoryKey] ?? {
    label: categoryKey,
    description: "",
    Icon: IconAlertTriangle,
    iconClass: "text-[#6f7f9a]",
  };

  return (
    <div className="mb-1">
      <div className="px-4 py-1.5">
        <div className="flex items-center gap-1.5 mb-0.5">
          <meta.Icon size={11} stroke={1.5} className={cn("shrink-0", meta.iconClass)} />
          <span className="text-[10px] font-mono uppercase tracking-wider text-[#6f7f9a]">
            {meta.label}
          </span>
          <span className="text-[9px] font-mono text-[#6f7f9a]/40 ml-auto">
            {scenarios.length}
          </span>
        </div>
        {meta.description && (
          <p className="text-[9px] text-[#6f7f9a]/50 leading-relaxed pl-[17px]">
            {meta.description}
          </p>
        )}
      </div>
      {scenarios.map((s) => {
        const Icon = ACTION_TYPE_ICONS[s.actionType];
        const active = s.id === selectedId;

        return (
          <button
            key={s.id}
            onClick={() => onSelect(s.id)}
            className={cn(
              "w-full flex items-center gap-2.5 px-4 py-2.5 text-left transition-all duration-150",
              active
                ? "bg-[#131721] text-[#ece7dc] border-l-2 border-l-[#d4a84b]"
                : "text-[#6f7f9a] hover:text-[#ece7dc] hover:bg-[#131721]/40 border-l-2 border-l-transparent",
            )}
          >
            <Icon size={14} stroke={1.5} className="shrink-0" />
            <div className="flex-1 min-w-0">
              <span className="text-xs font-medium truncate block">{s.name}</span>
              {s.threatRef && (
                <span className="text-[8px] font-mono text-[#6f7f9a]/40 truncate block mt-0.5">
                  {s.threatRef.split(" — ")[0]}
                </span>
              )}
            </div>
            <div className="flex items-center gap-1.5 shrink-0">
              <SeverityIndicator severity={s.severity} />
              {s.expectedVerdict && (
                <VerdictBadge verdict={s.expectedVerdict} className="shrink-0" />
              )}
            </div>
          </button>
        );
      })}
    </div>
  );
}


function CoverageBadge({ report }: { report: CoverageReport }) {
  const pct = report.coveragePercent;
  const colorClass =
    pct >= 80
      ? "text-[#3dbf84] bg-[#3dbf84]/10 border-[#3dbf84]/25"
      : pct >= 50
        ? "text-[#d4a84b] bg-[#d4a84b]/10 border-[#d4a84b]/25"
        : "text-[#c45c5c] bg-[#c45c5c]/10 border-[#c45c5c]/25";

  return (
    <span
      className={cn(
        "inline-flex items-center gap-1 px-1.5 py-0.5 text-[9px] font-mono border rounded select-none",
        colorClass,
      )}
    >
      <IconTarget size={9} stroke={1.5} />
      {pct}%
    </span>
  );
}

function CoverageDetails({ report }: { report: CoverageReport }) {
  return (
    <div className="px-4 pb-2">
      <div className="rounded-md bg-[#131721]/60 border border-[#2d3240]/60 p-2">
        <div className="flex items-center justify-between mb-1.5">
          <span className="text-[9px] font-mono text-[#6f7f9a]">
            Guard Coverage
          </span>
          <span className="text-[9px] font-mono text-[#a78bda]">
            {report.coveredGuards}/{report.enabledGuards} guards
          </span>
        </div>
        <div className="w-full h-1.5 rounded-full bg-[#0b0d13] overflow-hidden mb-2">
          <div
            className="h-full rounded-full bg-[#7c5cbf] transition-all duration-500"
            style={{ width: `${report.coveragePercent}%` }}
          />
        </div>
        <div className="grid grid-cols-2 gap-x-2 gap-y-0.5">
          {report.guards.map((g) => {
            const { Icon, className } = COVERAGE_STATUS_ICONS[g.status];
            return (
              <div key={g.guardId} className="flex items-center gap-1 min-w-0">
                <Icon size={9} stroke={1.5} className={cn("shrink-0", className)} />
                <span
                  className={cn(
                    "text-[8px] font-mono truncate",
                    g.status === "disabled"
                      ? "text-[#6f7f9a]/30"
                      : g.status === "covered"
                        ? "text-[#6f7f9a]"
                        : "text-[#c45c5c]/80",
                  )}
                >
                  {g.guardName}
                </span>
                {g.scenarioCount > 0 && (
                  <span className="text-[7px] font-mono text-[#6f7f9a]/30 ml-auto shrink-0">
                    {g.scenarioCount}
                  </span>
                )}
              </div>
            );
          })}
        </div>
        {report.gaps.length > 0 && (
          <div className="mt-1.5 pt-1.5 border-t border-[#2d3240]/40">
            <span className="text-[8px] font-mono text-[#c45c5c]/70">
              Untested: {report.gaps.length} enabled guard{report.gaps.length !== 1 ? "s" : ""}
            </span>
          </div>
        )}
      </div>
    </div>
  );
}

function AutoScenarioGroup({
  categoryKey,
  scenarios,
  selectedId,
  onSelect,
}: {
  categoryKey: string;
  scenarios: TestScenario[];
  selectedId: string | null;
  onSelect: (id: string) => void;
}) {
  if (scenarios.length === 0) return null;

  const meta = CATEGORY_META[categoryKey] ?? {
    label: categoryKey,
    description: "",
    Icon: IconAlertTriangle,
    iconClass: "text-[#6f7f9a]",
  };

  return (
    <div className="mb-1">
      <div className="px-4 py-1">
        <div className="flex items-center gap-1.5">
          <meta.Icon size={10} stroke={1.5} className={cn("shrink-0 opacity-60", meta.iconClass)} />
          <span className="text-[9px] font-mono uppercase tracking-wider text-[#6f7f9a]/60">
            {meta.label}
          </span>
          <span className="text-[8px] font-mono text-[#6f7f9a]/30 ml-auto">
            {scenarios.length}
          </span>
        </div>
      </div>
      {scenarios.map((s) => {
        const Icon = ACTION_TYPE_ICONS[s.actionType];
        const active = s.id === selectedId;

        return (
          <button
            key={s.id}
            onClick={() => onSelect(s.id)}
            className={cn(
              "w-full flex items-center gap-2.5 px-4 py-2 text-left transition-all duration-150",
              active
                ? "bg-[#7c5cbf]/10 text-[#ece7dc] border-l-2 border-l-[#a78bda]"
                : "text-[#6f7f9a] hover:text-[#ece7dc] hover:bg-[#7c5cbf]/5 border-l-2 border-l-transparent",
            )}
          >
            <Icon size={13} stroke={1.5} className="shrink-0" />
            <div className="flex-1 min-w-0">
              <div className="flex items-center gap-1.5">
                <span className="text-[11px] font-medium truncate">{s.name}</span>
                <span className="text-[7px] font-mono text-[#a78bda]/40 uppercase shrink-0">
                  auto
                </span>
              </div>
            </div>
            {s.expectedVerdict && (
              <VerdictBadge verdict={s.expectedVerdict} className="shrink-0" />
            )}
          </button>
        );
      })}
    </div>
  );
}
