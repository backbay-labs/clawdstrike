import { useMemo, useState } from "react";
import {
  IconSearch,
  IconChevronRight,
  IconAlertTriangle,
} from "@tabler/icons-react";
import { ScrollArea } from "@/components/ui/scroll-area";
import { useFindingStore } from "@/features/findings/stores/finding-store";
import { useIntelStore } from "@/features/findings/stores/intel-store";
import { usePaneStore } from "@/features/panes/pane-store";
import {
  SEVERITY_COLORS,
  SEVERITY_LABELS_SHORT,
  STATUS_CONFIG,
} from "@/lib/workbench/finding-constants";
import type { Finding } from "@/lib/workbench/finding-engine";
import type { Intel } from "@/lib/workbench/sentinel-types";
import type { Severity } from "@/lib/workbench/hunt-types";

// ---------------------------------------------------------------------------
// FindingsPanel — findings list with severity badges and collapsible intel.
//
// Shows findings grouped under a "FINDINGS" section with severity badges and
// status labels. Below a dashed divider, shows intel items under a collapsible
// "INTEL" section. Both sections are independently collapsible.
// ---------------------------------------------------------------------------

function listUniqueSwarmIntel(
  records: Array<{ intel: Intel }>,
): Intel[] {
  const seen = new Set<string>();
  const unique: Intel[] = [];
  for (const record of records) {
    if (seen.has(record.intel.id)) continue;
    seen.add(record.intel.id);
    unique.push(record.intel);
  }
  return unique;
}

export function FindingsPanel() {
  const findings = useFindingStore.use.findings();
  const localIntel = useIntelStore.use.localIntel();
  const swarmIntelRecords = useIntelStore.use.swarmIntel();

  const [filter, setFilter] = useState("");
  const [collapsedSections, setCollapsedSections] = useState<Set<string>>(new Set());

  // Combine intel sources
  const allIntel = useMemo(() => {
    const swarmIntel = listUniqueSwarmIntel(swarmIntelRecords);
    return [...localIntel, ...swarmIntel];
  }, [localIntel, swarmIntelRecords]);

  // Filter both findings and intel
  const filteredFindings = useMemo(() => {
    if (!filter) return findings;
    const lower = filter.toLowerCase();
    return findings.filter((f) => f.title.toLowerCase().includes(lower));
  }, [findings, filter]);

  const filteredIntel = useMemo(() => {
    if (!filter) return allIntel;
    const lower = filter.toLowerCase();
    return allIntel.filter((i) => i.title.toLowerCase().includes(lower));
  }, [allIntel, filter]);

  const toggleSection = (section: string) => {
    setCollapsedSections((prev) => {
      const next = new Set(prev);
      if (next.has(section)) {
        next.delete(section);
      } else {
        next.add(section);
      }
      return next;
    });
  };

  const findingsCollapsed = collapsedSections.has("findings");
  const intelCollapsed = collapsedSections.has("intel");

  const handleFindingClick = (finding: Finding) => {
    usePaneStore.getState().openApp(`/findings/${finding.id}`, finding.title);
  };

  const handleIntelClick = (intel: Intel) => {
    usePaneStore.getState().openApp(`/intel/${intel.id}`, intel.title);
  };

  const hasNoData = findings.length === 0 && allIntel.length === 0;
  const hasNoFilterMatch = filter && filteredFindings.length === 0 && filteredIntel.length === 0;

  return (
    <div className="flex flex-col h-full">
      {/* Panel header */}
      <div className="h-8 shrink-0 flex items-center px-4 border-b border-[#2d3240]/40">
        <span className="font-display font-semibold text-sm text-[#ece7dc]">
          Findings &amp; Intel
        </span>
      </div>

      {/* Filter input */}
      <div className="shrink-0 px-3 py-2 border-b border-[#2d3240]/40">
        <div className="relative">
          <IconSearch
            size={12}
            stroke={1.5}
            className="absolute left-2 top-1/2 -translate-y-1/2 text-[#6f7f9a]/40 pointer-events-none"
          />
          <input
            type="text"
            value={filter}
            onChange={(e) => setFilter(e.target.value)}
            placeholder="Filter findings..."
            aria-label="Filter findings"
            className="w-full bg-[#0b0d13] border border-[#2d3240] rounded text-[11px] font-mono text-[#ece7dc] pl-7 pr-2 py-1 outline-none transition-colors placeholder:text-[#6f7f9a]/40 focus:border-[#d4a84b]/40"
          />
        </div>
      </div>

      {/* Content */}
      <ScrollArea className="flex-1">
        {hasNoData ? (
          /* No findings at all */
          <div className="flex flex-col items-center justify-center py-8 text-center gap-1">
            <IconAlertTriangle size={28} stroke={1} className="text-[#6f7f9a]/30" />
            <span className="text-[11px] font-mono font-semibold text-[#6f7f9a]/70">
              No Findings
            </span>
            <p className="text-[11px] font-mono text-[#6f7f9a]/70 leading-relaxed max-w-[80%]">
              Findings appear here when sentinels detect potential threats.
            </p>
          </div>
        ) : hasNoFilterMatch ? (
          /* No filter matches */
          <div className="flex flex-col items-center justify-center py-8 text-center">
            <p className="text-[10px] font-mono text-[#6f7f9a]/50">
              No findings match the current filter
            </p>
          </div>
        ) : (
          <div className="py-1">
            {/* FINDINGS section */}
            {filteredFindings.length > 0 && (
              <div>
                {/* Section header */}
                <button
                  type="button"
                  role="button"
                  aria-expanded={!findingsCollapsed}
                  onClick={() => toggleSection("findings")}
                  className="flex items-center gap-1 w-full px-3 py-1.5 text-[10px] font-mono font-semibold text-[#6f7f9a] uppercase tracking-wider hover:bg-[#131721]/20 transition-colors"
                >
                  <IconChevronRight
                    size={8}
                    stroke={2}
                    className={`transition-transform ${findingsCollapsed ? "" : "rotate-90"}`}
                  />
                  <span>FINDINGS</span>
                  <span className="text-[#6f7f9a]/50 ml-0.5">({filteredFindings.length})</span>
                </button>

                {/* Finding items */}
                {!findingsCollapsed &&
                  filteredFindings.map((finding) => {
                    const sev = finding.severity as Severity;
                    const sevColor = SEVERITY_COLORS[sev] ?? "#6f7f9a";
                    const sevLabel = SEVERITY_LABELS_SHORT[sev] ?? sev?.toUpperCase();
                    const statusCfg = STATUS_CONFIG[finding.status as keyof typeof STATUS_CONFIG];

                    return (
                      <button
                        key={finding.id}
                        type="button"
                        role="option"
                        onClick={() => handleFindingClick(finding as Finding)}
                        className="flex items-center gap-2 w-full h-8 px-3 text-left hover:bg-[#131721]/40 transition-colors"
                      >
                        {/* Severity badge */}
                        <span
                          className="inline-flex items-center justify-center px-1.5 py-0.5 rounded text-[9px] font-mono font-semibold shrink-0"
                          style={{
                            color: sevColor,
                            backgroundColor: `${sevColor}20`,
                            height: 16,
                            borderRadius: 3,
                          }}
                        >
                          {sevLabel}
                        </span>
                        {/* Title */}
                        <span className="text-[11px] font-mono text-[#ece7dc]/70 truncate flex-1">
                          {finding.title}
                        </span>
                        {/* Status label */}
                        {statusCfg && (
                          <span
                            className="text-[9px] font-mono shrink-0"
                            style={{ color: statusCfg.color }}
                          >
                            {statusCfg.label}
                          </span>
                        )}
                      </button>
                    );
                  })}
              </div>
            )}

            {/* Dashed divider between findings and intel */}
            {filteredFindings.length > 0 && filteredIntel.length > 0 && (
              <div className="mx-3 my-1 border-t border-dashed border-[#2d3240]/40" />
            )}

            {/* INTEL section */}
            {filteredIntel.length > 0 && (
              <div>
                {/* Section header */}
                <button
                  type="button"
                  role="button"
                  aria-expanded={!intelCollapsed}
                  onClick={() => toggleSection("intel")}
                  className="flex items-center gap-1 w-full px-3 py-1.5 text-[10px] font-mono font-semibold text-[#6f7f9a] uppercase tracking-wider hover:bg-[#131721]/20 transition-colors"
                >
                  <IconChevronRight
                    size={8}
                    stroke={2}
                    className={`transition-transform ${intelCollapsed ? "" : "rotate-90"}`}
                  />
                  <span>INTEL</span>
                  <span className="text-[#6f7f9a]/50 ml-0.5">({filteredIntel.length})</span>
                </button>

                {/* Intel items */}
                {!intelCollapsed &&
                  filteredIntel.map((intel) => (
                    <button
                      key={intel.id}
                      type="button"
                      role="option"
                      onClick={() => handleIntelClick(intel)}
                      className="flex items-center gap-2 w-full h-8 px-3 text-left hover:bg-[#131721]/40 transition-colors"
                    >
                      {/* Type label */}
                      <span className="text-[9px] font-mono text-[#6f7f9a] shrink-0 w-6">
                        {intel.type}
                      </span>
                      {/* Intel label */}
                      <span className="text-[11px] font-mono text-[#ece7dc]/70 truncate flex-1">
                        {intel.title}
                      </span>
                      {/* Shareability */}
                      <span className="text-[9px] font-mono text-[#6f7f9a] shrink-0">
                        {intel.shareability}
                      </span>
                    </button>
                  ))}
              </div>
            )}
          </div>
        )}
      </ScrollArea>

      {/* Footer */}
      <div className="shrink-0 px-3 py-1.5 border-t border-[#2d3240]">
        <span className="text-[9px] font-mono text-[#6f7f9a]/40">
          {findings.length} findings, {allIntel.length} intel
        </span>
      </div>
    </div>
  );
}
