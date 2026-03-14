import { useState } from "react";
import { cn } from "@/lib/utils";
import type { EvaluationPathStep } from "@/lib/workbench/types";
import { IconChevronDown, IconChevronRight, IconScan } from "@tabler/icons-react";

interface EvaluationPathProps {
  steps: EvaluationPathStep[];
}

const resultColor: Record<string, string> = {
  allow: "#3dbf84",
  deny: "#c45c5c",
  warn: "#d4a84b",
  skip: "#6f7f9a",
};

const resultBg: Record<string, string> = {
  allow: "bg-[#3dbf84]",
  deny: "bg-[#c45c5c]",
  warn: "bg-[#d4a84b]",
  skip: "bg-[#6f7f9a]",
};

const stageLabel: Record<string, string> = {
  fast_path: "Fast",
  std_path: "Std",
  deep_path: "Deep",
};

export function EvaluationPath({ steps }: EvaluationPathProps) {
  const [expanded, setExpanded] = useState(false);

  if (steps.length === 0) return null;

  // Compute the maximum stage duration so bar widths are proportional.
  const maxDuration = Math.max(...steps.map((s) => s.stage_duration_ms), 0.001);
  const totalDurationMs = Object.values(
    steps.reduce<Record<string, number>>((acc, s) => {
            if (!(s.stage in acc)) acc[s.stage] = s.stage_duration_ms;
      return acc;
    }, {}),
  ).reduce((a, b) => a + b, 0);

  // Identify the critical path guard — the one that determined the final verdict.
  // If any guard denied, the first deny is the critical guard.
  // Otherwise, the last guard in the pipeline is the critical one.
  const criticalIdx = (() => {
    const denyIdx = steps.findIndex((s) => s.result === "deny");
    if (denyIdx >= 0) return denyIdx;
    const warnIdx = steps.findIndex((s) => s.result === "warn");
    if (warnIdx >= 0) return warnIdx;
    return steps.length - 1;
  })();

  // Compute cumulative confidence through the pipeline
  const totalSteps = steps.length;

  return (
    <div className="mb-4">
      <button
        onClick={() => setExpanded((prev) => !prev)}
        className="flex items-center gap-1.5 w-full text-left group"
      >
        {expanded ? (
          <IconChevronDown size={12} stroke={2} className="text-[#6f7f9a] shrink-0" />
        ) : (
          <IconChevronRight size={12} stroke={2} className="text-[#6f7f9a] shrink-0" />
        )}
        <IconScan size={12} stroke={1.5} className="text-[#d4a84b] shrink-0" />
        <h3 className="text-[10px] font-mono uppercase tracking-wider text-[#6f7f9a] group-hover:text-[#ece7dc] transition-colors">
          Guard Execution Trace
        </h3>
        <span className="text-[9px] font-mono text-[#6f7f9a]/50 ml-auto">
          {formatDuration(totalDurationMs)}
        </span>
      </button>

      {expanded && (
        <div className="mt-2 ml-1 relative">
          {/* Vertical timeline connector */}
          <div className="absolute left-[5px] top-1 bottom-1 w-px bg-[#2d3240]" />

          <div className="space-y-0.5">
            {steps.map((step, i) => {
              // Minimum bar width of 15% so very fast guards are still visible.
              const barPct = Math.max(
                15,
                (step.stage_duration_ms / maxDuration) * 100,
              );
              const color = resultColor[step.result] ?? resultColor.skip;
              const bgClass = resultBg[step.result] ?? resultBg.skip;
              const isLast = i === steps.length - 1;
              const isCritical = i === criticalIdx;
              const stageName = stageLabel[step.stage] ?? step.stage;
              const cumulativeConfidence = Math.round(((i + 1) / totalSteps) * 100);

              return (
                <div
                  key={`${step.guard}-${i}`}
                  className={cn(
                    "flex items-center gap-2 pl-4 relative",
                    isCritical && "critical-path-node",
                  )}
                >
                  {/* Timeline dot */}
                  <div
                    className={cn(
                      "absolute left-0 w-[11px] h-[11px] rounded-full border-2 shrink-0",
                      isCritical
                        ? "border-[#d4a84b] bg-[#d4a84b]/20"
                        : isLast
                          ? "border-[#d4a84b] bg-[#05060a]"
                          : "border-[#2d3240] bg-[#0b0d13]",
                    )}
                    style={
                      !isCritical
                        ? step.result === "deny"
                          ? { borderColor: "#c45c5c" }
                          : step.result === "allow"
                            ? { borderColor: "#3dbf84" }
                            : undefined
                        : undefined
                    }
                  />

                  {/* Guard name */}
                  <span className="text-[10px] font-mono text-[#ece7dc] w-[110px] truncate shrink-0">
                    {step.guard}
                  </span>

                  {/* Stage badge */}
                  <span className="text-[8px] font-mono uppercase tracking-wider text-[#6f7f9a]/70 w-8 shrink-0 text-center">
                    {stageName}
                  </span>

                  {/* Duration bar */}
                  <div className="flex-1 min-w-0 h-3 bg-[#131721] rounded-sm overflow-hidden relative border border-[#2d3240]/30">
                    <div
                      className={cn("h-full rounded-sm opacity-50 transition-all duration-500", bgClass)}
                      style={{ width: `${barPct}%` }}
                    />
                  </div>

                  {/* Result badge + timing */}
                  <span
                    className="text-[9px] font-mono uppercase shrink-0 w-[34px] text-right"
                    style={{ color }}
                  >
                    {step.result}
                  </span>
                  <span className="text-[9px] font-mono text-[#6f7f9a]/60 shrink-0 w-[40px] text-right">
                    {formatDuration(step.stage_duration_ms)}
                  </span>

                  {/* Cumulative confidence */}
                  <span className="text-[8px] font-mono text-[#6f7f9a]/30 shrink-0 w-[28px] text-right">
                    {cumulativeConfidence}%
                  </span>
                </div>
              );
            })}
          </div>

          {/* Total row + critical path indicator */}
          <div className="flex items-center justify-between mt-2 pt-1.5 border-t border-[#2d3240]/50 ml-4">
            <div className="flex items-center gap-2">
              <span className="text-[9px] font-mono text-[#6f7f9a]/70 uppercase tracking-wider">
                Total
              </span>
              {criticalIdx >= 0 && (
                <span className="text-[8px] font-mono text-[#d4a84b]/60">
                  Critical: {steps[criticalIdx]?.guard}
                </span>
              )}
            </div>
            <span className="text-[10px] font-mono text-[#d4a84b]">
              {formatDuration(totalDurationMs)}
            </span>
          </div>
        </div>
      )}
    </div>
  );
}

/** Format a millisecond duration into a human-readable string. */
function formatDuration(ms: number): string {
  if (ms < 0.001) return "<1us";
  if (ms < 1) return `${(ms * 1000).toFixed(0)}us`;
  if (ms < 1000) return `${ms.toFixed(2)}ms`;
  return `${(ms / 1000).toFixed(2)}s`;
}
