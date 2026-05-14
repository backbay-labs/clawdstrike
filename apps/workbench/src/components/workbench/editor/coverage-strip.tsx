import type { CoverageReport } from "@/lib/workbench/coverage-analyzer";
import { cn } from "@/lib/utils";
import { IconShieldCheck, IconPlus } from "@tabler/icons-react";


interface CoverageStripProps {
  report: CoverageReport | null;
  onGenerateForGuard?: (guardId: string) => void;
}


function progressColor(percent: number): string {
  if (percent >= 80) return "#3dbf84";
  if (percent >= 50) return "#d4a84b";
  return "#c45c5c";
}

function statusDot(status: "covered" | "uncovered" | "disabled"): string {
  if (status === "covered") return "bg-[#3dbf84]";
  if (status === "uncovered") return "border border-[#c45c5c] bg-transparent";
  return "bg-[#6f7f9a]/30";
}


export function CoverageStrip({ report, onGenerateForGuard }: CoverageStripProps) {
  if (!report) {
    return (
      <div className="flex items-center gap-2 px-3 py-2">
        <IconShieldCheck size={10} stroke={1.5} className="text-[#6f7f9a]/40" />
        <span className="text-[9px] font-mono text-[#6f7f9a]/40">
          Run tests to see coverage
        </span>
      </div>
    );
  }

  const displayCoveragePercent = Math.round(report.coveragePercent);

  return (
    <div className="px-3 py-1.5 bg-[#0b0d13]/50">
      {/* Overall coverage bar */}
      <div className="flex items-center gap-2 mb-1.5">
        <IconShieldCheck size={10} stroke={1.5} className="text-[#6f7f9a] shrink-0" />
        <span className="text-[9px] font-mono text-[#6f7f9a] shrink-0">
          {report.coveredGuards}/{report.enabledGuards} guards covered
        </span>
        <div className="flex-1 h-1.5 bg-[#2d3240] rounded-full overflow-hidden">
          <div
            className="h-full rounded-full transition-all duration-300"
            style={{
              width: `${report.coveragePercent}%`,
              backgroundColor: progressColor(report.coveragePercent),
            }}
          />
        </div>
        <span
          className="text-[9px] font-mono font-bold shrink-0"
          style={{ color: progressColor(report.coveragePercent) }}
        >
          {displayCoveragePercent}%
        </span>
      </div>

      {/* Per-guard compact grid */}
      <div className="grid grid-cols-2 gap-x-3 gap-y-0.5">
        {report.guards
          .filter((g) => g.status !== "disabled")
          .map((g) => (
            <div key={g.guardId} className="flex items-center gap-1.5 min-w-0">
              <span
                className={cn(
                  "w-1.5 h-1.5 rounded-full shrink-0",
                  statusDot(g.status),
                )}
              />
              <span
                className={cn(
                  "text-[9px] font-mono truncate flex-1",
                  g.status === "covered" ? "text-[#6f7f9a]" : "text-[#c45c5c]/70",
                )}
              >
                {g.guardName}
              </span>
              <span className="text-[8px] font-mono text-[#6f7f9a]/40 shrink-0">
                {g.scenarioCount}
              </span>
              {g.status === "uncovered" && onGenerateForGuard && (
                <button
                  onClick={() => onGenerateForGuard(g.guardId)}
                  className="p-0 text-[#d4a84b]/60 hover:text-[#d4a84b] transition-colors shrink-0"
                  title={`Generate test scenarios for ${g.guardName}`}
                >
                  <IconPlus size={9} stroke={1.5} />
                </button>
              )}
            </div>
          ))}
      </div>

      {/* Generate All Missing button */}
      {report.gaps.length > 0 && onGenerateForGuard && (
        <div className="mt-1.5 pt-1.5 border-t border-[#2d3240]/50">
          <button
            onClick={() => {
              for (const guardId of report.gaps) {
                onGenerateForGuard(guardId);
              }
            }}
            className="inline-flex items-center gap-1 px-2 py-0.5 text-[8px] font-mono text-[#d4a84b] hover:text-[#d4a84b] border border-dashed border-[#d4a84b]/30 hover:border-[#d4a84b]/50 rounded transition-colors"
          >
            <IconPlus size={8} stroke={1.5} />
            Generate All Missing ({report.gaps.length})
          </button>
        </div>
      )}
    </div>
  );
}
