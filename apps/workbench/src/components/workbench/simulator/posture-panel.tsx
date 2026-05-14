import { useCallback, useRef, useMemo, useEffect } from "react";
import { cn } from "@/lib/utils";
import type { PostureBudget, PostureReport } from "@/lib/workbench/types";
import {
  IconGauge,
  IconAlertTriangle,
  IconRotateClockwise,
  IconShieldCheck,
  IconShieldOff,
  IconTrendingUp,
} from "@tabler/icons-react";


function budgetPercent(budget: PostureBudget): number {
  if (budget.limit === 0) return 0;
  return Math.min((budget.consumed / budget.limit) * 100, 100);
}

function budgetOverflow(budget: PostureBudget): boolean {
  return budget.consumed > budget.limit;
}

function budgetColor(budget: PostureBudget): string {
  if (budgetOverflow(budget)) return "bg-[#c45c5c]";
  const pct = budgetPercent(budget);
  if (pct >= 80) return "bg-[#c45c5c]";
  if (pct >= 60) return "bg-[#d4a84b]";
  return "bg-[#3dbf84]";
}

function budgetTextColor(budget: PostureBudget): string {
  if (budgetOverflow(budget)) return "text-[#c45c5c]";
  const pct = budgetPercent(budget);
  if (pct >= 80) return "text-[#c45c5c]";
  if (pct >= 60) return "text-[#d4a84b]";
  return "text-[#3dbf84]";
}

/** CSS-only mini sparkline showing budget consumption trend. */
function MiniSparkline({ values }: { values: number[] }) {
  if (values.length < 2) return null;
  const max = Math.max(...values, 1);
  return (
    <div className="flex items-end gap-px h-3">
      {values.slice(-8).map((v, i) => (
        <div
          key={i}
          className={cn(
            "w-1 rounded-t-sm sparkline-bar",
            v / max >= 0.8 ? "bg-[#c45c5c]/60" : v / max >= 0.5 ? "bg-[#d4a84b]/60" : "bg-[#3dbf84]/40",
          )}
          style={{ height: `${Math.max(2, (v / max) * 12)}px` }}
        />
      ))}
    </div>
  );
}

function BudgetBar({ budget, history }: { budget: PostureBudget; history?: number[] }) {
  const pct = budgetPercent(budget);
  const overflow = budgetOverflow(budget);

  return (
    <div className="space-y-1">
      <div className="flex items-center justify-between">
        <span className="text-[11px] text-[#ece7dc] font-mono">
          {budget.name.replace(/_/g, " ")}
        </span>
        <div className="flex items-center gap-2">
          {history && <MiniSparkline values={history} />}
          <span className={cn("text-[10px] font-mono", budgetTextColor(budget))}>
            {budget.consumed}/{budget.limit}
            {overflow && " (exceeded)"}
          </span>
        </div>
      </div>
      <div className="h-2 rounded-full bg-[#131721] border border-[#2d3240] overflow-hidden">
        <div
          className={cn(
            "h-full rounded-full budget-bar-fill",
            budgetColor(budget),
            overflow && "animate-pulse",
          )}
          style={{ width: `${overflow ? 100 : pct}%` }}
        />
      </div>
    </div>
  );
}


function RiskVelocityIndicator({ budgets }: { budgets: PostureBudget[] }) {
  const avgConsumption = useMemo(() => {
    if (budgets.length === 0) return 0;
    const totalPct = budgets.reduce((sum, b) => {
      if (b.limit === 0) return sum;
      return sum + (b.consumed / b.limit) * 100;
    }, 0);
    return Math.round(totalPct / budgets.length);
  }, [budgets]);

  const riskLevel = avgConsumption >= 80 ? "high" : avgConsumption >= 40 ? "moderate" : "low";
  const colors: Record<string, string> = {
    high: "text-[#c45c5c]",
    moderate: "text-[#d4a84b]",
    low: "text-[#3dbf84]",
  };

  return (
    <div className="flex items-center gap-2 px-3 py-1.5 rounded-md bg-[#131721] border border-[#2d3240]/50">
      <IconTrendingUp size={12} stroke={1.5} className={colors[riskLevel]} />
      <span className="text-[10px] font-mono text-[#6f7f9a]">Risk Velocity</span>
      <span className={cn("text-[10px] font-mono ml-auto", colors[riskLevel])}>
        {avgConsumption}% avg
      </span>
      <span className={cn("text-[8px] font-mono uppercase", colors[riskLevel])}>
        {riskLevel}
      </span>
    </div>
  );
}


function StateBadge({ state, transitioned }: { state: string; transitioned?: boolean }) {
  const isRestricted = /restrict|quarantine|locked|deny/i.test(state);
  return (
    <div
      className={cn(
        "inline-flex items-center gap-1.5 px-2 py-1 rounded text-xs font-mono border",
        isRestricted
          ? "bg-[#c45c5c]/10 border-[#c45c5c]/30 text-[#c45c5c]"
          : "bg-[#3dbf84]/10 border-[#3dbf84]/30 text-[#3dbf84]",
      )}
    >
      {isRestricted ? (
        <IconShieldOff size={12} stroke={1.5} />
      ) : (
        <IconShieldCheck size={12} stroke={1.5} />
      )}
      {state}
      {transitioned && (
        <span className="text-[9px] text-[#d4a84b] ml-1">(transitioned)</span>
      )}
    </div>
  );
}


interface PosturePanelProps {
  /** Current cumulative posture report (null = no posture config). */
  postureReport: PostureReport | null;
  /** Whether the active policy has a posture config. */
  hasPostureConfig: boolean;
  /** Reset cumulative budget tracking. */
  onReset: () => void;
}

export function PosturePanel({ postureReport, hasPostureConfig, onReset }: PosturePanelProps) {
  // Track budget history for sparklines (simple in-memory via ref)
  const budgetHistory = useRef<Map<string, number[]>>(new Map());

  // Update history when posture report changes
  useEffect(() => {
    if (!postureReport) return;
    for (const b of postureReport.budgets) {
      const hist = budgetHistory.current.get(b.name) ?? [];
      // Only push if value changed from last entry
      if (hist.length === 0 || hist[hist.length - 1] !== b.consumed) {
        hist.push(b.consumed);
        // Keep last 8 values
        if (hist.length > 8) hist.shift();
        budgetHistory.current.set(b.name, hist);
      }
    }
  }, [postureReport]);

  const handleReset = useCallback(() => {
    budgetHistory.current.clear();
    onReset();
  }, [onReset]);

  if (!hasPostureConfig) {
    return (
      <div className="px-4 py-4 border-t border-[#2d3240]/60">
        <div className="flex items-center gap-2.5 text-[#6f7f9a]/60">
          <IconGauge size={14} stroke={1.5} />
          <span className="text-[11px]">No capability budget config in this policy</span>
        </div>
      </div>
    );
  }

  if (!postureReport) {
    return (
      <div className="px-4 py-4 border-t border-[#2d3240]/60">
        <div className="flex items-center gap-2.5">
          <IconGauge size={14} stroke={1.5} className="text-[#6f7f9a]/50" />
          <span className="text-[11px] text-[#6f7f9a]/60">
            Execute a probe to see budget consumption
          </span>
        </div>
      </div>
    );
  }

  return (
    <div className="border-t border-[#2d3240]">
      {/* Header */}
      <div className="px-4 py-2.5 flex items-center justify-between border-b border-[#2d3240]">
        <div className="flex items-center gap-2">
          <IconGauge size={14} stroke={1.5} className="text-[#d4a84b]" />
          <h3 className="font-syne font-bold text-xs text-[#ece7dc]">
            Capability Budget Monitor
          </h3>
        </div>
        <button
          onClick={handleReset}
          className="flex items-center gap-1 text-[10px] font-mono text-[#6f7f9a] hover:text-[#ece7dc] transition-colors"
          title="Reset cumulative budget tracking"
        >
          <IconRotateClockwise size={12} stroke={1.5} />
          Reset
        </button>
      </div>

      <div className="px-4 py-3 space-y-3">
        {/* Current state */}
        <div>
          <span className="text-[10px] font-mono uppercase tracking-wider text-[#6f7f9a] block mb-1.5">
            State
          </span>
          <StateBadge
            state={postureReport.state}
            transitioned={postureReport.transitioned}
          />
        </div>

        {/* Risk velocity */}
        {postureReport.budgets.length > 0 && (
          <RiskVelocityIndicator budgets={postureReport.budgets} />
        )}

        {/* Budget bars with sparklines */}
        {postureReport.budgets.length > 0 && (
          <div>
            <span className="text-[10px] font-mono uppercase tracking-wider text-[#6f7f9a] block mb-2">
              Capability Budgets
            </span>
            <div className="space-y-2.5">
              {postureReport.budgets.map((b) => (
                <BudgetBar
                  key={b.name}
                  budget={b}
                  history={budgetHistory.current.get(b.name)}
                />
              ))}
            </div>
          </div>
        )}

        {/* Violations */}
        {postureReport.violations.length > 0 && (
          <div>
            <span className="text-[10px] font-mono uppercase tracking-wider text-[#6f7f9a] block mb-1.5">
              Violations
            </span>
            <div className="space-y-1">
              {postureReport.violations.map((v, i) => (
                <div
                  key={i}
                  className="flex items-start gap-1.5 text-[11px] text-[#c45c5c]"
                >
                  <IconAlertTriangle
                    size={12}
                    stroke={1.5}
                    className="shrink-0 mt-0.5"
                  />
                  <span>{v}</span>
                </div>
              ))}
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
