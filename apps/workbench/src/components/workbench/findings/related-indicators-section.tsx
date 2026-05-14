import { useState } from "react";
import {
  IconChevronDown,
  IconChevronRight,
  IconFlask,
} from "@tabler/icons-react";
import type { RelatedIndicator } from "@/lib/workbench/pivot-enrichment";
import { IOC_TYPE_COLORS } from "@/lib/workbench/ioc-constants";

interface RelatedIndicatorsSectionProps {
  indicators: RelatedIndicator[];
  onEnrich: (indicator: RelatedIndicator) => void;
}

export function RelatedIndicatorsSection({
  indicators,
  onEnrich,
}: RelatedIndicatorsSectionProps) {
  const [collapsed, setCollapsed] = useState(false);

  if (indicators.length === 0) return null;

  return (
    <div className="border-b border-[#2d3240]/40">
      <button
        onClick={() => setCollapsed(!collapsed)}
        className="flex items-center gap-2 w-full px-4 py-2.5 text-left hover:bg-[#131721]/40 transition-colors"
      >
        {collapsed ? (
          <IconChevronRight size={11} className="text-[#6f7f9a]/40 shrink-0" />
        ) : (
          <IconChevronDown size={11} className="text-[#6f7f9a]/40 shrink-0" />
        )}
        <span className="text-[10px] font-semibold uppercase tracking-[0.04em] text-[#d4a84b]">
          Related Indicators
        </span>
        <span className="text-[9px] font-mono text-[#6f7f9a]/30 ml-auto">
          {indicators.length}
        </span>
      </button>

      {!collapsed && (
        <div className="px-4 pb-3 flex flex-col gap-1.5">
          {indicators.map((indicator) => {
            const typeColor =
              IOC_TYPE_COLORS[indicator.type] ?? "#6f7f9a";
            return (
              <div
                key={`${indicator.type}:${indicator.value}`}
                className="flex items-center gap-2 rounded border border-[#2d3240]/30 bg-[#131721] px-2.5 py-1.5"
              >
                <span
                  className="shrink-0 rounded px-1.5 py-0.5 text-[8px] font-semibold uppercase border"
                  style={{
                    color: typeColor,
                    borderColor: typeColor + "30",
                    backgroundColor: typeColor + "10",
                  }}
                >
                  {indicator.type}
                </span>
                <span className="font-mono text-[10px] text-[#ece7dc]/60 truncate flex-1 min-w-0">
                  {indicator.value}
                </span>
                <button
                  onClick={() => onEnrich(indicator)}
                  className="shrink-0 flex items-center gap-1 rounded px-1.5 py-0.5 text-[9px] font-medium text-[#d4a84b] bg-[#d4a84b]/10 border border-[#d4a84b]/20 hover:bg-[#d4a84b]/20 transition-colors"
                  title={`Enrich ${indicator.type}: ${indicator.value}`}
                >
                  <IconFlask size={10} stroke={1.5} />
                  Enrich
                </button>
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
}
