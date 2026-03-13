import { useMemo, useState } from "react";
import {
  IconArrowRight,
  IconEqual,
  IconArrowsExchange,
  IconChevronDown,
  IconChevronRight,
} from "@tabler/icons-react";
import { cn } from "@/lib/utils";

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

interface GuardResult {
  guard: string;
  verdict: string;
  message: string;
}

interface TestDiffPanelProps {
  baselineResults: Map<string, { verdict: string; guard: string | null; guardResults?: GuardResult[] }>;
  candidateResults: Map<string, { verdict: string; guard: string | null; guardResults?: GuardResult[] }>;
  scenarios: Array<{ id: string; name: string; action: string; target: string }>;
}

interface GuardDiff {
  guard: string;
  oldVerdict: string;
  newVerdict: string;
  /** True if this guard's change is the likely cause of the overall verdict change. */
  causedVerdictChange: boolean;
}

interface ChangedScenario {
  id: string;
  name: string;
  action: string;
  target: string;
  oldVerdict: string | null;
  newVerdict: string | null;
  guardDiffs: GuardDiff[];
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function verdictColor(v: string): string {
  if (v === "allow") return "#3dbf84";
  if (v === "deny") return "#c45c5c";
  if (v === "removed" || v === "added") return "#6f7f9a";
  return "#d4a84b";
}

function VerdictBadge({ verdict }: { verdict: string }) {
  return (
    <span
      className="inline-block px-1.5 py-0.5 rounded text-[9px] font-mono font-bold uppercase"
      style={{
        color: verdictColor(verdict),
        backgroundColor: `${verdictColor(verdict)}15`,
        border: `1px solid ${verdictColor(verdict)}30`,
      }}
    >
      {verdict}
    </span>
  );
}

function changeDirectionColor(oldV: string, newV: string): string {
  // allow -> deny = regression (red)
  if (oldV === "allow" && newV === "deny") return "#c45c5c";
  // deny -> allow = improvement (green)
  if (oldV === "deny" && newV === "allow") return "#3dbf84";
  // other transitions are neutral
  return "#d4a84b";
}

// ---------------------------------------------------------------------------
// Component
// ---------------------------------------------------------------------------

export function TestDiffPanel({
  baselineResults,
  candidateResults,
  scenarios,
}: TestDiffPanelProps) {
  const [expandedRows, setExpandedRows] = useState<Set<string>>(new Set());

  const toggleRow = (id: string) => {
    setExpandedRows((prev) => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });
  };

  // Compute changed scenarios with guard-level diffs
  const changedScenarios = useMemo<ChangedScenario[]>(() => {
    return scenarios
      .map((s) => {
        const baseline = baselineResults.get(s.id);
        const candidate = candidateResults.get(s.id);

        // Only include scenarios where the overall verdict changed
        if (baseline && candidate && baseline.verdict === candidate.verdict) {
          return null;
        }

        // Compute guard-level diffs
        const guardDiffs: GuardDiff[] = [];
        const oldGuardMap = new Map(
          (baseline?.guardResults ?? []).map((g) => [g.guard, g.verdict]),
        );
        const newGuardMap = new Map(
          (candidate?.guardResults ?? []).map((g) => [g.guard, g.verdict]),
        );

        // Find the guard that likely caused the overall verdict change
        const newDenyGuard = candidate?.guard ?? null;

        // Guards that changed or were removed
        for (const [guard, oldV] of oldGuardMap) {
          const newV = newGuardMap.get(guard);
          if (newV === undefined) {
            guardDiffs.push({
              guard,
              oldVerdict: oldV,
              newVerdict: "removed",
              causedVerdictChange: false,
            });
          } else if (oldV !== newV) {
            guardDiffs.push({
              guard,
              oldVerdict: oldV,
              newVerdict: newV,
              causedVerdictChange: guard === newDenyGuard,
            });
          }
        }

        // Guards that were added
        for (const [guard, newV] of newGuardMap) {
          if (!oldGuardMap.has(guard)) {
            guardDiffs.push({
              guard,
              oldVerdict: "added",
              newVerdict: newV,
              causedVerdictChange: guard === newDenyGuard,
            });
          }
        }

        return {
          id: s.id,
          name: s.name,
          action: s.action,
          target: s.target,
          oldVerdict: baseline?.verdict ?? null,
          newVerdict: candidate?.verdict ?? null,
          guardDiffs,
        };
      })
      .filter((s): s is ChangedScenario => s !== null);
  }, [scenarios, baselineResults, candidateResults]);

  if (changedScenarios.length === 0) {
    return (
      <div className="flex flex-col items-center justify-center h-full py-8">
        <IconEqual size={20} stroke={1.5} className="text-[#3dbf84]/50 mb-2" />
        <p className="text-[11px] font-mono text-[#6f7f9a]">
          No behavior changes detected.
        </p>
        <p className="text-[9px] font-mono text-[#6f7f9a]/50 mt-1">
          Both policy versions produce identical verdicts for all {scenarios.length} scenario(s).
        </p>
      </div>
    );
  }

  return (
    <div className="h-full flex flex-col bg-[#05060a]">
      {/* Header */}
      <div className="flex items-center gap-2 px-3 py-1.5 border-b border-[#2d3240] bg-[#0b0d13] shrink-0">
        <IconArrowsExchange size={12} stroke={1.5} className="text-[#d4a84b]" />
        <span className="text-[9px] font-mono text-[#6f7f9a] uppercase tracking-wider">
          Test Diff
        </span>
        <span className="text-[9px] font-mono text-[#d4a84b] ml-auto">
          {changedScenarios.length} changed
        </span>
        <span className="text-[9px] font-mono text-[#6f7f9a]/50">
          / {scenarios.length} total
        </span>
      </div>

      {/* Diff table */}
      <div className="flex-1 overflow-auto">
        <table className="w-full text-[10px] font-mono">
          <thead>
            <tr className="border-b border-[#2d3240] text-[#6f7f9a] text-left">
              <th className="px-3 py-1.5 w-6" />
              <th className="px-3 py-1.5">Scenario</th>
              <th className="px-3 py-1.5 w-20 text-center">Baseline</th>
              <th className="px-3 py-1.5 w-8 text-center" />
              <th className="px-3 py-1.5 w-20 text-center">Candidate</th>
              <th className="px-3 py-1.5 w-16 text-center">Delta</th>
            </tr>
          </thead>
          <tbody>
            {changedScenarios.map((scenario) => {
              const isExpanded = expandedRows.has(scenario.id);
              const hasGuardDiffs = scenario.guardDiffs.length > 0;

              return (
                <>
                  <tr
                    key={scenario.id}
                    className={cn(
                      "border-b border-[#2d3240]/50 transition-colors",
                      hasGuardDiffs
                        ? "hover:bg-[#131721]/50 cursor-pointer"
                        : "hover:bg-[#131721]/50",
                    )}
                    onClick={hasGuardDiffs ? () => toggleRow(scenario.id) : undefined}
                  >
                    <td className="px-1 py-1.5 text-center">
                      {hasGuardDiffs ? (
                        isExpanded ? (
                          <IconChevronDown size={10} stroke={1.5} className="text-[#6f7f9a] mx-auto" />
                        ) : (
                          <IconChevronRight size={10} stroke={1.5} className="text-[#6f7f9a] mx-auto" />
                        )
                      ) : (
                        <span className="w-[10px] block" />
                      )}
                    </td>
                    <td className="px-3 py-1.5">
                      <div className="flex flex-col">
                        <span className="text-[#ece7dc] truncate">
                          {scenario.name}
                        </span>
                        <span className="text-[8px] text-[#6f7f9a]/50 truncate">
                          {scenario.action}: {scenario.target}
                        </span>
                      </div>
                    </td>
                    <td className="px-3 py-1.5 text-center">
                      {scenario.oldVerdict ? (
                        <VerdictBadge verdict={scenario.oldVerdict} />
                      ) : (
                        <span className="text-[#6f7f9a]/30">-</span>
                      )}
                    </td>
                    <td className="px-3 py-1.5 text-center">
                      <IconArrowRight
                        size={10}
                        stroke={1.5}
                        className="text-[#6f7f9a]/40 mx-auto"
                      />
                    </td>
                    <td className="px-3 py-1.5 text-center">
                      {scenario.newVerdict ? (
                        <VerdictBadge verdict={scenario.newVerdict} />
                      ) : (
                        <span className="text-[#6f7f9a]/30">-</span>
                      )}
                    </td>
                    <td className="px-3 py-1.5 text-center">
                      <span
                        className={cn(
                          "inline-block px-1 py-0.5 rounded text-[8px] font-bold uppercase",
                          "bg-[#d4a84b]/10 text-[#d4a84b] border border-[#d4a84b]/20",
                        )}
                      >
                        changed
                      </span>
                    </td>
                  </tr>
                  {/* Expanded guard-level diff sub-table */}
                  {isExpanded && hasGuardDiffs && (
                    <tr key={`${scenario.id}-guards`}>
                      <td colSpan={6} className="bg-[#0b0d13] border-b border-[#2d3240]">
                        <div className="px-6 py-1.5">
                          <div className="text-[8px] font-mono text-[#6f7f9a]/50 uppercase tracking-wider mb-1">
                            Guard-Level Changes
                          </div>
                          <table className="w-full text-[9px] font-mono">
                            <thead>
                              <tr className="text-[#6f7f9a]/60 text-left">
                                <th className="py-0.5 pr-3">Guard</th>
                                <th className="py-0.5 w-16 text-center">Old</th>
                                <th className="py-0.5 w-6 text-center" />
                                <th className="py-0.5 w-16 text-center">New</th>
                              </tr>
                            </thead>
                            <tbody>
                              {scenario.guardDiffs.map((gd) => (
                                <tr
                                  key={gd.guard}
                                  className={cn(
                                    "transition-colors",
                                    gd.causedVerdictChange && "bg-[#d4a84b]/5",
                                  )}
                                >
                                  <td className="py-0.5 pr-3">
                                    <span
                                      className={cn(
                                        "truncate",
                                        gd.causedVerdictChange
                                          ? "text-[#d4a84b] font-medium"
                                          : "text-[#6f7f9a]",
                                      )}
                                    >
                                      {gd.guard}
                                      {gd.causedVerdictChange && (
                                        <span className="text-[7px] text-[#d4a84b]/60 ml-1">
                                          (trigger)
                                        </span>
                                      )}
                                    </span>
                                  </td>
                                  <td className="py-0.5 text-center">
                                    <span
                                      className="uppercase font-bold"
                                      style={{ color: verdictColor(gd.oldVerdict) }}
                                    >
                                      {gd.oldVerdict}
                                    </span>
                                  </td>
                                  <td className="py-0.5 text-center">
                                    <IconArrowRight
                                      size={8}
                                      stroke={1.5}
                                      style={{ color: changeDirectionColor(gd.oldVerdict, gd.newVerdict) }}
                                      className="mx-auto"
                                    />
                                  </td>
                                  <td className="py-0.5 text-center">
                                    <span
                                      className="uppercase font-bold"
                                      style={{ color: verdictColor(gd.newVerdict) }}
                                    >
                                      {gd.newVerdict}
                                    </span>
                                  </td>
                                </tr>
                              ))}
                            </tbody>
                          </table>
                        </div>
                      </td>
                    </tr>
                  )}
                </>
              );
            })}
          </tbody>
        </table>
      </div>
    </div>
  );
}
