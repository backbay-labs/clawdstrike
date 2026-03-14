import { useState, useMemo, useCallback } from "react";
import { ScrollArea } from "@/components/ui/scroll-area";
import { VerdictBadge } from "@/components/workbench/shared/verdict-badge";
import { useWorkbench } from "@/lib/workbench/multi-policy-store";
import { cn } from "@/lib/utils";
import {
  computeThreatMatrix,
  findScenariosForCell,
  ATTACK_CATEGORIES,
  type AttackCategory,
  type CoverageLevel,
  type CriticalGap,
  type MatrixCell,
} from "@/lib/workbench/threat-matrix-data";
import type { GuardId, TestScenario, SimulationResult } from "@/lib/workbench/types";
import {
  IconShieldCheck,
  IconShieldOff,
  IconAlertTriangle,
  IconChevronRight,
  IconX,
  IconTarget,
  IconArrowRight,
  IconBulb,
} from "@tabler/icons-react";


const COVERAGE_COLORS: Record<CoverageLevel, { bg: string; text: string; border: string }> = {
  full: { bg: "bg-[#3dbf84]", text: "text-[#3dbf84]", border: "border-[#3dbf84]/30" },
  partial: { bg: "bg-[#d4a84b]", text: "text-[#d4a84b]", border: "border-[#d4a84b]/30" },
  none: { bg: "bg-[#c45c5c]", text: "text-[#c45c5c]", border: "border-[#c45c5c]/30" },
  na: { bg: "bg-[#2d3240]", text: "text-[#6f7f9a]/30", border: "border-[#2d3240]" },
};


function ScoreGauge({ score }: { score: number }) {
  const color = score >= 80 ? "#3dbf84" : score >= 50 ? "#d4a84b" : "#c45c5c";
  const circumference = 2 * Math.PI * 42;
  const strokeDashoffset = circumference - (score / 100) * circumference;

  return (
    <div className="relative w-28 h-28">
      <svg viewBox="0 0 100 100" className="w-full h-full -rotate-90">
        {/* Background circle */}
        <circle
          cx="50"
          cy="50"
          r="42"
          fill="none"
          stroke="#2d3240"
          strokeWidth="6"
        />
        {/* Score arc */}
        <circle
          cx="50"
          cy="50"
          r="42"
          fill="none"
          stroke={color}
          strokeWidth="6"
          strokeLinecap="round"
          strokeDasharray={circumference}
          strokeDashoffset={strokeDashoffset}
          className="transition-all duration-700 ease-out"
        />
      </svg>
      <div className="absolute inset-0 flex flex-col items-center justify-center">
        <span className="text-2xl font-syne font-extrabold" style={{ color }}>
          {score}
        </span>
        <span className="text-[9px] font-mono uppercase tracking-wider text-[#6f7f9a]">
          Coverage
        </span>
      </div>
    </div>
  );
}

function CategoryBar({
  category,
  coverage,
  onClick,
  isSelected,
}: {
  category: string;
  coverage: number;
  onClick: () => void;
  isSelected: boolean;
}) {
  const color = coverage >= 80 ? "#3dbf84" : coverage >= 50 ? "#d4a84b" : "#c45c5c";

  return (
    <button
      onClick={onClick}
      className={cn(
        "flex items-center gap-2 w-full px-3 py-2 rounded-lg transition-all duration-150 text-left",
        isSelected
          ? "bg-[#131721] border border-[#d4a84b]/30"
          : "hover:bg-[#131721]/40 border border-transparent",
      )}
    >
      <div className="flex-1 min-w-0">
        <div className="flex items-center justify-between mb-1">
          <span className="text-[11px] text-[#ece7dc] font-medium truncate">{category}</span>
          <span className="text-[10px] font-mono ml-2 shrink-0" style={{ color }}>
            {coverage}%
          </span>
        </div>
        <div className="h-1.5 rounded-full bg-[#2d3240] overflow-hidden">
          <div
            className="h-full rounded-full transition-all duration-500"
            style={{ width: `${coverage}%`, backgroundColor: color }}
          />
        </div>
      </div>
      <IconChevronRight size={12} stroke={2} className="text-[#6f7f9a]/40 shrink-0" />
    </button>
  );
}

function GapCard({ gap }: { gap: CriticalGap }) {
  return (
    <div
      className={cn(
        "p-3 rounded-lg border",
        gap.severity === "high"
          ? "border-[#c45c5c]/20 bg-[#c45c5c]/5"
          : "border-[#d4a84b]/20 bg-[#d4a84b]/5",
      )}
    >
      <div className="flex items-start gap-2">
        <IconAlertTriangle
          size={13}
          stroke={1.5}
          className={cn(
            "shrink-0 mt-0.5",
            gap.severity === "high" ? "text-[#c45c5c]" : "text-[#d4a84b]",
          )}
        />
        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-2 mb-1">
            <span className="text-[11px] font-medium text-[#ece7dc]">
              {gap.categoryLabel}
            </span>
            <span
              className={cn(
                "text-[9px] font-mono uppercase px-1.5 py-0 border rounded",
                gap.severity === "high"
                  ? "text-[#c45c5c] border-[#c45c5c]/20 bg-[#c45c5c]/10"
                  : "text-[#d4a84b] border-[#d4a84b]/20 bg-[#d4a84b]/10",
              )}
            >
              {gap.severity}
            </span>
          </div>
          <p className="text-[10px] text-[#6f7f9a] mb-1.5">
            {gap.description}
          </p>
          <div className="flex items-start gap-1.5">
            <IconBulb size={11} stroke={1.5} className="text-[#d4a84b] shrink-0 mt-0.5" />
            <p className="text-[10px] text-[#d4a84b]/80">
              {gap.recommendation}
            </p>
          </div>
        </div>
      </div>
    </div>
  );
}

function CellDrillDown({
  guardId,
  attackCategory,
  scenarios,
  results,
  onClose,
}: {
  guardId: GuardId;
  attackCategory: AttackCategory;
  scenarios: TestScenario[];
  results: SimulationResult[];
  onClose: () => void;
}) {
  const matches = useMemo(
    () => findScenariosForCell(guardId, attackCategory, scenarios, results),
    [guardId, attackCategory, scenarios, results],
  );

  const catMeta = ATTACK_CATEGORIES.find((c) => c.id === attackCategory);

  return (
    <div className="border border-[#2d3240] rounded-lg bg-[#0b0d13] overflow-hidden">
      <div className="flex items-center justify-between px-4 py-2.5 border-b border-[#2d3240]">
        <div className="flex items-center gap-2">
          <IconTarget size={13} stroke={1.5} className="text-[#d4a84b]" />
          <span className="text-xs font-mono text-[#ece7dc]">{guardId}</span>
          <IconArrowRight size={10} stroke={2} className="text-[#6f7f9a]/40" />
          <span className="text-xs text-[#6f7f9a]">{catMeta?.label ?? attackCategory}</span>
        </div>
        <button
          onClick={onClose}
          className="text-[#6f7f9a] hover:text-[#ece7dc] transition-colors"
        >
          <IconX size={14} stroke={1.5} />
        </button>
      </div>

      {matches.length === 0 ? (
        <div className="px-4 py-6 text-center">
          <p className="text-[11px] text-[#6f7f9a]">
            No test scenarios match this guard/attack combination.
          </p>
          <p className="text-[10px] text-[#6f7f9a]/50 mt-1">
            Create a scenario to test this specific intersection.
          </p>
        </div>
      ) : (
        <div className="divide-y divide-[#2d3240]/40">
          {matches.map(({ scenario, result }) => (
            <div
              key={scenario.id}
              className="flex items-center gap-2.5 px-4 py-2"
            >
              <span className="text-[11px] text-[#ece7dc] flex-1 min-w-0 truncate">
                {scenario.name}
              </span>
              {result && (
                <VerdictBadge verdict={result.overallVerdict} />
              )}
              {scenario.expectedVerdict && !result && (
                <span className="text-[9px] font-mono text-[#6f7f9a]">
                  expects: {scenario.expectedVerdict}
                </span>
              )}
            </div>
          ))}
        </div>
      )}
    </div>
  );
}


function MatrixGrid({
  matrix,
  onCellClick,
  selectedCell,
}: {
  matrix: ReturnType<typeof computeThreatMatrix>;
  onCellClick: (guardId: GuardId, category: AttackCategory) => void;
  selectedCell: { guardId: GuardId; category: AttackCategory } | null;
}) {
  return (
    <div className="overflow-x-auto">
      <table className="w-full border-collapse min-w-[700px]">
        <thead>
          <tr>
            <th className="text-left text-[9px] font-mono uppercase tracking-wider text-[#6f7f9a] pb-2 pr-2 w-[140px] sticky left-0 bg-[#05060a] z-10">
              Guard
            </th>
            {ATTACK_CATEGORIES.map((cat) => (
              <th
                key={cat.id}
                className="text-center text-[8px] font-mono uppercase tracking-wider text-[#6f7f9a] pb-2 px-1"
                title={cat.description}
              >
                <span className="block leading-tight">{cat.shortLabel}</span>
              </th>
            ))}
          </tr>
        </thead>
        <tbody>
          {matrix.rows.map((row) => (
            <tr key={row.guardId} className="group">
              <td className="text-[10px] font-mono text-[#ece7dc] py-1.5 pr-2 sticky left-0 bg-[#05060a] z-10">
                <div className="flex items-center gap-1.5">
                  <span
                    className={cn(
                      "w-1.5 h-1.5 rounded-full shrink-0",
                      row.cells.some((c) => c.guardEnabled) ? "bg-[#3dbf84]" : "bg-[#6f7f9a]/30",
                    )}
                  />
                  <span className="truncate">{row.guardName}</span>
                </div>
              </td>
              {row.cells.map((cell) => {
                const colors = COVERAGE_COLORS[cell.effectiveLevel];
                const isSelected =
                  selectedCell?.guardId === cell.guardId &&
                  selectedCell?.category === cell.attackCategory;

                return (
                  <td key={`${cell.guardId}-${cell.attackCategory}`} className="px-0.5 py-1">
                    <button
                      onClick={() => {
                        if (cell.effectiveLevel !== "na") {
                          onCellClick(cell.guardId, cell.attackCategory);
                        }
                      }}
                      disabled={cell.effectiveLevel === "na"}
                      className={cn(
                        "w-full h-7 rounded-sm border transition-all duration-150",
                        colors.border,
                        cell.effectiveLevel === "na"
                          ? "cursor-default opacity-30"
                          : "cursor-pointer hover:scale-105 hover:shadow-md",
                        isSelected && "ring-1 ring-[#d4a84b] scale-105",
                      )}
                    >
                      <div
                        className={cn(
                          "w-full h-full rounded-sm",
                          cell.effectiveLevel === "full" && "bg-[#3dbf84]/40",
                          cell.effectiveLevel === "partial" && "bg-[#d4a84b]/30",
                          cell.effectiveLevel === "none" && "bg-[#c45c5c]/25",
                          cell.effectiveLevel === "na" && "bg-[#2d3240]/20",
                        )}
                      />
                    </button>
                  </td>
                );
              })}
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}


interface ThreatMatrixProps {
  scenarios: TestScenario[];
  results: SimulationResult[];
}

export function ThreatMatrix({ scenarios, results }: ThreatMatrixProps) {
  const { state } = useWorkbench();
  const [selectedCell, setSelectedCell] = useState<{ guardId: GuardId; category: AttackCategory } | null>(null);
  const [selectedCategory, setSelectedCategory] = useState<AttackCategory | null>(null);

  const matrix = useMemo(
    () => computeThreatMatrix(state.activePolicy),
    [state.activePolicy],
  );

  const handleCellClick = useCallback((guardId: GuardId, category: AttackCategory) => {
    setSelectedCell((prev) =>
      prev?.guardId === guardId && prev?.category === category
        ? null
        : { guardId, category },
    );
  }, []);

  const handleCategoryClick = useCallback((category: AttackCategory) => {
    setSelectedCategory((prev) => (prev === category ? null : category));
  }, []);

  const highGaps = matrix.criticalGaps.filter((g) => g.severity === "high");
  const mediumGaps = matrix.criticalGaps.filter((g) => g.severity === "medium");

  return (
    <div className="flex flex-col h-full">
      {/* Header */}
      <div className="px-6 py-4 border-b border-[#2d3240] bg-[#0b0d13] shrink-0">
        <div className="flex items-start gap-6">
          {/* Score gauge */}
          <div className="shrink-0">
            <ScoreGauge score={matrix.overallScore} />
          </div>

          {/* Summary */}
          <div className="flex-1 min-w-0 pt-1">
            <h3 className="font-syne font-bold text-base text-[#ece7dc] mb-2">
              Threat Coverage Matrix
            </h3>
            <p className="text-[11px] text-[#6f7f9a] leading-relaxed mb-3 max-w-md">
              Visual mapping of your policy's 13 guards against 8 attack categories.
              Green cells indicate active coverage. Red cells indicate gaps.
            </p>

            {/* Legend */}
            <div className="flex items-center gap-4 text-[10px] font-mono">
              <span className="flex items-center gap-1.5">
                <span className="w-3 h-3 rounded-sm bg-[#3dbf84]/40 border border-[#3dbf84]/30" />
                <span className="text-[#6f7f9a]">Covered</span>
              </span>
              <span className="flex items-center gap-1.5">
                <span className="w-3 h-3 rounded-sm bg-[#d4a84b]/30 border border-[#d4a84b]/30" />
                <span className="text-[#6f7f9a]">Partial</span>
              </span>
              <span className="flex items-center gap-1.5">
                <span className="w-3 h-3 rounded-sm bg-[#c45c5c]/25 border border-[#c45c5c]/30" />
                <span className="text-[#6f7f9a]">Gap</span>
              </span>
              <span className="flex items-center gap-1.5">
                <span className="w-3 h-3 rounded-sm bg-[#2d3240]/20 border border-[#2d3240] opacity-30" />
                <span className="text-[#6f7f9a]">N/A</span>
              </span>
            </div>
          </div>

          {/* Quick stats */}
          <div className="shrink-0 flex flex-col gap-1.5 text-right">
            <div className="flex items-center gap-2 justify-end">
              <IconShieldCheck size={13} stroke={1.5} className="text-[#3dbf84]" />
              <span className="text-[11px] font-mono text-[#3dbf84]">
                {matrix.rows.filter((r) => r.cells.some((c) => c.guardEnabled)).length} active guards
              </span>
            </div>
            {highGaps.length > 0 && (
              <div className="flex items-center gap-2 justify-end">
                <IconShieldOff size={13} stroke={1.5} className="text-[#c45c5c]" />
                <span className="text-[11px] font-mono text-[#c45c5c]">
                  {highGaps.length} critical gap{highGaps.length !== 1 ? "s" : ""}
                </span>
              </div>
            )}
            {mediumGaps.length > 0 && (
              <div className="flex items-center gap-2 justify-end">
                <IconAlertTriangle size={13} stroke={1.5} className="text-[#d4a84b]" />
                <span className="text-[11px] font-mono text-[#d4a84b]">
                  {mediumGaps.length} warning{mediumGaps.length !== 1 ? "s" : ""}
                </span>
              </div>
            )}
          </div>
        </div>
      </div>

      {/* Content */}
      <div className="flex-1 min-h-0 flex">
        {/* Left: Category bars + gaps */}
        <div className="w-64 shrink-0 border-r border-[#2d3240] bg-[#0b0d13] flex flex-col">
          <div className="px-3 py-2.5 border-b border-[#2d3240] shrink-0">
            <h4 className="text-[10px] font-mono uppercase tracking-wider text-[#6f7f9a]">
              Category Coverage
            </h4>
          </div>
          <ScrollArea className="flex-1 overflow-y-auto">
            <div className="p-2 space-y-0.5">
              {ATTACK_CATEGORIES.map((cat) => (
                <CategoryBar
                  key={cat.id}
                  category={cat.label}
                  coverage={matrix.categoryCoverage[cat.id]}
                  onClick={() => handleCategoryClick(cat.id)}
                  isSelected={selectedCategory === cat.id}
                />
              ))}
            </div>

            {/* Critical gaps */}
            {matrix.criticalGaps.length > 0 && (
              <div className="px-3 pb-3">
                <h4 className="text-[10px] font-mono uppercase tracking-wider text-[#c45c5c] mb-2 mt-3 flex items-center gap-1.5">
                  <IconAlertTriangle size={11} stroke={1.5} />
                  Security Gaps
                </h4>
                <div className="space-y-2">
                  {matrix.criticalGaps.map((gap) => (
                    <GapCard key={gap.category} gap={gap} />
                  ))}
                </div>
              </div>
            )}
          </ScrollArea>
        </div>

        {/* Center: Matrix grid */}
        <div className="flex-1 min-w-0 flex flex-col">
          <ScrollArea className="flex-1 overflow-auto">
            <div className="p-4">
              <MatrixGrid
                matrix={matrix}
                onCellClick={handleCellClick}
                selectedCell={selectedCell}
              />

              {/* Cell drill-down */}
              {selectedCell && (
                <div className="mt-4">
                  <CellDrillDown
                    guardId={selectedCell.guardId}
                    attackCategory={selectedCell.category}
                    scenarios={scenarios}
                    results={results}
                    onClose={() => setSelectedCell(null)}
                  />
                </div>
              )}

              {/* Category detail */}
              {selectedCategory && !selectedCell && (
                <div className="mt-4 border border-[#2d3240] rounded-lg bg-[#0b0d13] p-4">
                  <div className="flex items-center justify-between mb-3">
                    <div>
                      <h4 className="text-xs font-medium text-[#ece7dc]">
                        {ATTACK_CATEGORIES.find((c) => c.id === selectedCategory)?.label}
                      </h4>
                      <p className="text-[10px] text-[#6f7f9a] mt-0.5">
                        {ATTACK_CATEGORIES.find((c) => c.id === selectedCategory)?.description}
                      </p>
                    </div>
                    <button
                      onClick={() => setSelectedCategory(null)}
                      className="text-[#6f7f9a] hover:text-[#ece7dc] transition-colors"
                    >
                      <IconX size={14} stroke={1.5} />
                    </button>
                  </div>

                  {/* Guards for this category */}
                  <div className="space-y-1.5">
                    {matrix.rows
                      .filter((row) =>
                        row.cells.some(
                          (c) =>
                            c.attackCategory === selectedCategory &&
                            c.staticLevel !== "na",
                        ),
                      )
                      .map((row) => {
                        const cell = row.cells.find(
                          (c) => c.attackCategory === selectedCategory,
                        );
                        if (!cell) return null;
                        const colors = COVERAGE_COLORS[cell.effectiveLevel];
                        return (
                          <div
                            key={row.guardId}
                            className="flex items-center gap-2.5 px-3 py-2 rounded-md bg-[#131721]/40"
                          >
                            <span
                              className={cn(
                                "w-2 h-2 rounded-full shrink-0",
                                cell.effectiveLevel === "full" && "bg-[#3dbf84]",
                                cell.effectiveLevel === "partial" && "bg-[#d4a84b]",
                                cell.effectiveLevel === "none" && "bg-[#c45c5c]",
                              )}
                            />
                            <span className="text-[11px] font-mono text-[#ece7dc] flex-1">
                              {row.guardName}
                            </span>
                            <span
                              className={cn(
                                "text-[9px] font-mono uppercase",
                                colors.text,
                              )}
                            >
                              {cell.effectiveLevel}
                            </span>
                            {!cell.guardEnabled && cell.staticLevel !== "na" && (
                              <span className="text-[9px] font-mono text-[#c45c5c]/60">
                                (disabled)
                              </span>
                            )}
                          </div>
                        );
                      })}
                  </div>
                </div>
              )}
            </div>
          </ScrollArea>
        </div>
      </div>
    </div>
  );
}
