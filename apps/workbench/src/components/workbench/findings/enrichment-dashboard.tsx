import { useMemo } from "react";
import type { Finding } from "@/lib/workbench/finding-engine";
import {
  aggregateIndicators,
  aggregateVerdictsBySource,
  getSourceHealthSummary,
  type SourceHealthInput,
} from "@/lib/workbench/enrichment-aggregator";
import {
  CrossFindingIndicatorsCard,
  VerdictsBySourceCard,
  SourceHealthCard,
} from "./enrichment-dashboard-cards";

interface EnrichmentDashboardProps {
  findings: Finding[];
  sourceHealthInputs?: SourceHealthInput[];
}

export function EnrichmentDashboard({
  findings,
  sourceHealthInputs,
}: EnrichmentDashboardProps) {
  const indicatorAggregations = useMemo(
    () => aggregateIndicators(findings),
    [findings],
  );

  const verdictSummaries = useMemo(
    () => aggregateVerdictsBySource(findings),
    [findings],
  );

  const sourceHealthStatuses = useMemo(
    () => getSourceHealthSummary(sourceHealthInputs ?? []),
    [sourceHealthInputs],
  );

  return (
    <div className="flex flex-col h-full overflow-y-auto">
      <div className="shrink-0 px-4 py-3 border-b border-[#2d3240]/60">
        <h2 className="text-[10px] font-semibold uppercase tracking-[0.08em] text-[#6f7f9a]/50">
          Intelligence Dashboard
        </h2>
        <span className="text-[9px] font-mono text-[#6f7f9a]/30 mt-0.5 block">
          {findings.length} finding{findings.length !== 1 ? "s" : ""} analyzed
        </span>
      </div>

      <div className="flex-1 p-4">
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
          <CrossFindingIndicatorsCard aggregations={indicatorAggregations} />
          <VerdictsBySourceCard summaries={verdictSummaries} />
          <SourceHealthCard statuses={sourceHealthStatuses} />
        </div>
      </div>
    </div>
  );
}
