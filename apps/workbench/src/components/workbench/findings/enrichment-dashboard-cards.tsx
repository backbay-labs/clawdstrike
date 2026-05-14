import type { IndicatorAggregation, VerdictSummary, SourceHealthStatus } from "@/lib/workbench/enrichment-aggregator";
import { IOC_TYPE_COLORS } from "@/lib/workbench/ioc-constants";

const VERDICT_COLORS = {
  malicious: "#c45c5c",
  suspicious: "#d4784b",
  unknown: "#6f7f9a",
  benign: "#3dbf84",
} as const;

const HEALTH_COLORS: Record<string, string> = {
  healthy: "#3dbf84",
  degraded: "#d4a84b",
  unhealthy: "#c45c5c",
};

interface CrossFindingIndicatorsCardProps {
  aggregations: IndicatorAggregation[];
}

export function CrossFindingIndicatorsCard({ aggregations }: CrossFindingIndicatorsCardProps) {
  return (
    <div className="rounded-lg border border-[#2d3240]/40 bg-[#131721] p-4">
      <div className="flex items-center gap-2 mb-3">
        <h3 className="text-[10px] font-semibold uppercase tracking-[0.08em] text-[#6f7f9a]/50">
          Cross-Finding Indicators
        </h3>
        {aggregations.length > 0 && (
          <span className="rounded-full bg-[#2d3240]/60 px-1.5 py-0.5 text-[9px] font-mono text-[#ece7dc]/40">
            {aggregations.length}
          </span>
        )}
      </div>

      {aggregations.length === 0 ? (
        <p className="text-[10px] text-[#6f7f9a]/30 text-center py-4">
          No indicators shared across findings
        </p>
      ) : (
        <div className="flex flex-col gap-1.5 max-h-[280px] overflow-y-auto">
          {aggregations.map((agg) => {
            const typeColor = IOC_TYPE_COLORS[agg.iocType] ?? "#6f7f9a";
            const isHighlighted = agg.count >= 3;
            return (
              <div
                key={`${agg.iocType}:${agg.indicator}`}
                className="flex items-center gap-2 rounded border bg-[#05060a] px-2.5 py-1.5"
                style={{
                  borderColor: isHighlighted ? "#d4a84b30" : "#2d324030",
                }}
              >
                <span
                  className="shrink-0 rounded px-1.5 py-0.5 text-[8px] font-semibold uppercase border"
                  style={{
                    color: typeColor,
                    borderColor: typeColor + "30",
                    backgroundColor: typeColor + "10",
                  }}
                >
                  {agg.iocType}
                </span>

                <span className="font-mono text-[10px] text-[#ece7dc]/60 truncate flex-1 min-w-0">
                  {agg.indicator}
                </span>

                <span
                  className="shrink-0 rounded-full px-1.5 py-0.5 text-[9px] font-semibold border"
                  style={{
                    color: isHighlighted ? "#d4a84b" : "#ece7dc60",
                    borderColor: isHighlighted ? "#d4a84b30" : "#2d324040",
                    backgroundColor: isHighlighted ? "#d4a84b10" : "#2d324020",
                  }}
                >
                  {agg.count} finding{agg.count !== 1 ? "s" : ""}
                </span>
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
}

interface VerdictsBySourceCardProps {
  summaries: VerdictSummary[];
}

export function VerdictsBySourceCard({ summaries }: VerdictsBySourceCardProps) {
  return (
    <div className="rounded-lg border border-[#2d3240]/40 bg-[#131721] p-4">
      <div className="flex items-center gap-2 mb-3">
        <h3 className="text-[10px] font-semibold uppercase tracking-[0.08em] text-[#6f7f9a]/50">
          Verdicts by Source
        </h3>
      </div>

      {summaries.length === 0 ? (
        <p className="text-[10px] text-[#6f7f9a]/30 text-center py-4">
          No enrichment data available
        </p>
      ) : (
        <div className="flex flex-col gap-3">
          {summaries.map((summary) => (
            <VerdictSourceRow key={summary.sourceId} summary={summary} />
          ))}
        </div>
      )}
    </div>
  );
}

function VerdictSourceRow({ summary }: { summary: VerdictSummary }) {
  const total = summary.total;
  if (total === 0) return null;

  const segments = [
    { key: "malicious" as const, count: summary.malicious, color: VERDICT_COLORS.malicious },
    { key: "suspicious" as const, count: summary.suspicious, color: VERDICT_COLORS.suspicious },
    { key: "unknown" as const, count: summary.unknown, color: VERDICT_COLORS.unknown },
    { key: "benign" as const, count: summary.benign, color: VERDICT_COLORS.benign },
  ].filter((s) => s.count > 0);

  return (
    <div>
      <div className="flex items-center justify-between mb-1.5">
        <span className="text-[10px] font-medium text-[#ece7dc]/60">
          {summary.sourceName}
        </span>
        <span className="font-mono text-[9px] text-[#6f7f9a]/40">
          {total} total
        </span>
      </div>

      <div className="flex h-2 rounded-full overflow-hidden bg-[#2d3240]/30">
        {segments.map((seg) => (
          <div
            key={seg.key}
            className="h-full transition-all duration-300"
            style={{
              width: `${(seg.count / total) * 100}%`,
              backgroundColor: seg.color,
            }}
            title={`${seg.key}: ${seg.count}`}
          />
        ))}
      </div>

      <div className="flex gap-3 mt-1.5">
        {segments.map((seg) => (
          <span
            key={seg.key}
            className="text-[8px] font-mono"
            style={{ color: seg.color + "99" }}
          >
            {seg.count} {seg.key}
          </span>
        ))}
      </div>
    </div>
  );
}

interface SourceHealthCardProps {
  statuses: SourceHealthStatus[];
}

export function SourceHealthCard({ statuses }: SourceHealthCardProps) {
  return (
    <div className="rounded-lg border border-[#2d3240]/40 bg-[#131721] p-4">
      <div className="flex items-center gap-2 mb-3">
        <h3 className="text-[10px] font-semibold uppercase tracking-[0.08em] text-[#6f7f9a]/50">
          Source Health
        </h3>
      </div>

      {statuses.length === 0 ? (
        <p className="text-[10px] text-[#6f7f9a]/30 text-center py-4">
          No sources configured
        </p>
      ) : (
        <div className="flex flex-col gap-2.5">
          {statuses.map((status) => (
            <SourceHealthRow key={status.id} status={status} />
          ))}
        </div>
      )}
    </div>
  );
}

function SourceHealthRow({ status }: { status: SourceHealthStatus }) {
  const healthColor = HEALTH_COLORS[status.health] ?? "#6f7f9a";

  return (
    <div className="rounded border border-[#2d3240]/30 bg-[#05060a] px-2.5 py-2">
      <div className="flex items-center gap-2 mb-1.5">
        <span
          className="shrink-0 w-2 h-2 rounded-full"
          style={{ backgroundColor: healthColor }}
        />
        <span className="text-[10px] font-medium text-[#ece7dc]/60 flex-1 min-w-0 truncate">
          {status.name}
        </span>
        <span
          className="text-[8px] font-semibold uppercase"
          style={{ color: healthColor }}
        >
          {status.health}
        </span>
      </div>

      <div className="flex items-center gap-2 mb-1">
        <span className="text-[9px] text-[#6f7f9a]/40 shrink-0 w-[40px]">Quota</span>
        <div className="flex-1 h-1.5 rounded-full bg-[#2d3240]/30 overflow-hidden">
          <div
            className="h-full rounded-full transition-all duration-300"
            style={{
              width: `${Math.min(status.quotaPercent, 100)}%`,
              backgroundColor: healthColor,
            }}
          />
        </div>
        <span className="font-mono text-[9px] text-[#ece7dc]/40 shrink-0 w-[32px] text-right">
          {status.quotaPercent}%
        </span>
      </div>

      <div className="flex items-center gap-3 text-[8px] text-[#6f7f9a]/30">
        <span>
          {status.quotaUsed}/{status.quotaTotal} used
        </span>
        <span>{status.rateLimit.maxPerMinute}/min</span>
        {status.lastErrorMessage && (
          <span className="text-[#c45c5c]/50 truncate flex-1 min-w-0">
            {status.lastErrorMessage}
          </span>
        )}
      </div>
    </div>
  );
}
