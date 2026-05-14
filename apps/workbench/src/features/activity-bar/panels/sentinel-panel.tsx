import { useMemo, useState } from "react";
import {
  IconPlus,
  IconSearch,
  IconChevronRight,
  IconRadar,
} from "@tabler/icons-react";
import { ScrollArea } from "@/components/ui/scroll-area";
import { useSentinelStore } from "@/features/sentinels/stores/sentinel-store";
import { usePaneStore } from "@/features/panes/pane-store";
import type { Sentinel, SentinelStatus } from "@/lib/workbench/sentinel-types";

// ---------------------------------------------------------------------------
// SentinelPanel — filterable sentinel list grouped by status.
//
// Shows active/paused/retired sentinels with status dots, group headers,
// a create button, and clickable items that open sentinel detail views.
// ---------------------------------------------------------------------------

const STATUS_ORDER: SentinelStatus[] = ["active", "paused", "retired"];

const STATUS_DOT_COLORS: Record<SentinelStatus, string> = {
  active: "#4ade80",
  paused: "#d4a84b",
  retired: "#6f7f9a",
};

const STATUS_LABELS: Record<SentinelStatus, string> = {
  active: "ACTIVE",
  paused: "PAUSED",
  retired: "RETIRED",
};

function groupByStatus(sentinels: Sentinel[]): Record<SentinelStatus, Sentinel[]> {
  const groups: Record<SentinelStatus, Sentinel[]> = {
    active: [],
    paused: [],
    retired: [],
  };
  for (const s of sentinels) {
    const bucket = groups[s.status as SentinelStatus];
    if (bucket) bucket.push(s);
  }
  return groups;
}

// ---------------------------------------------------------------------------
// SentinelPanel
// ---------------------------------------------------------------------------

export function SentinelPanel() {
  const sentinels = useSentinelStore.use.sentinels();
  const [filter, setFilter] = useState("");
  const [collapsed, setCollapsed] = useState<Set<string>>(new Set());

  const filtered = useMemo(() => {
    if (!filter) return sentinels;
    const lower = filter.toLowerCase();
    return sentinels.filter((s) =>
      s.name.toLowerCase().includes(lower),
    );
  }, [sentinels, filter]);

  const groups = useMemo(() => groupByStatus(filtered as Sentinel[]), [filtered]);

  const toggleGroup = (status: string) => {
    setCollapsed((prev) => {
      const next = new Set(prev);
      if (next.has(status)) {
        next.delete(status);
      } else {
        next.add(status);
      }
      return next;
    });
  };

  const handleItemClick = (sentinel: Sentinel) => {
    usePaneStore.getState().openApp(`/sentinels/${sentinel.id}`, sentinel.name);
  };

  const handleCreate = () => {
    usePaneStore.getState().openApp("/sentinels/create", "New Sentinel");
  };

  return (
    <div className="flex flex-col h-full">
      {/* Panel header */}
      <div className="h-8 shrink-0 flex items-center px-4 border-b border-[#2d3240]/40">
        <span className="font-display font-semibold text-sm text-[#ece7dc]">
          Sentinels
        </span>
        <div className="ml-auto flex items-center gap-0.5">
          <button
            type="button"
            title="New Sentinel"
            onClick={handleCreate}
            className="p-1 rounded text-[#6f7f9a]/60 hover:text-[#ece7dc] hover:bg-[#131721]/40 transition-colors"
          >
            <IconPlus size={12} stroke={1.5} />
          </button>
        </div>
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
            placeholder="Filter sentinels..."
            aria-label="Filter sentinels"
            className="w-full bg-[#0b0d13] border border-[#2d3240] rounded text-[11px] font-mono text-[#ece7dc] pl-7 pr-2 py-1 outline-none transition-colors placeholder:text-[#6f7f9a]/40 focus:border-[#d4a84b]/40"
          />
        </div>
      </div>

      {/* List */}
      <ScrollArea className="flex-1">
        {sentinels.length === 0 ? (
          /* No sentinels at all */
          <div className="flex flex-col items-center justify-center py-8 text-center gap-1">
            <IconRadar size={28} stroke={1} className="text-[#6f7f9a]/30" />
            <span className="text-[11px] font-mono font-semibold text-[#6f7f9a]/70">
              No Sentinels
            </span>
            <p className="text-[11px] font-mono text-[#6f7f9a]/70 leading-relaxed max-w-[80%]">
              Create a sentinel to deploy autonomous threat monitoring.
            </p>
            <button
              type="button"
              onClick={handleCreate}
              className="inline-flex items-center gap-1.5 px-3 py-1.5 mt-2 text-[10px] font-mono rounded border border-[#d4a84b]/20 text-[#d4a84b] bg-[#d4a84b]/5 hover:bg-[#d4a84b]/10 transition-colors"
            >
              <IconPlus size={12} stroke={1.5} />
              New Sentinel
            </button>
          </div>
        ) : filtered.length === 0 && filter ? (
          /* No matches for filter */
          <div className="flex flex-col items-center justify-center py-8 text-center">
            <p className="text-[10px] font-mono text-[#6f7f9a]/50">
              No sentinels match the current filter
            </p>
          </div>
        ) : (
          <div className="py-1">
            {STATUS_ORDER.map((status) => {
              const group = groups[status];
              if (group.length === 0) return null;
              const isCollapsed = collapsed.has(status);

              return (
                <div key={status}>
                  {/* Group header */}
                  <button
                    type="button"
                    role="button"
                    aria-expanded={!isCollapsed}
                    onClick={() => toggleGroup(status)}
                    className="flex items-center gap-1 w-full px-3 py-1.5 text-[10px] font-mono font-semibold text-[#6f7f9a] uppercase tracking-wider hover:bg-[#131721]/20 transition-colors"
                  >
                    <IconChevronRight
                      size={8}
                      stroke={2}
                      className={`transition-transform ${isCollapsed ? "" : "rotate-90"}`}
                    />
                    <span>{STATUS_LABELS[status]}</span>
                    <span className="text-[#6f7f9a]/50 ml-0.5">({group.length})</span>
                  </button>

                  {/* Group items */}
                  {!isCollapsed &&
                    group.map((sentinel) => (
                      <button
                        key={sentinel.id}
                        type="button"
                        role="option"
                        onClick={() => handleItemClick(sentinel as Sentinel)}
                        className="flex items-center gap-1.5 w-full h-8 px-3 text-left hover:bg-[#131721]/40 transition-colors"
                      >
                        {/* Status dot */}
                        <span
                          className="w-1.5 h-1.5 rounded-full shrink-0"
                          style={{ backgroundColor: STATUS_DOT_COLORS[status] }}
                          aria-hidden="true"
                        />
                        {/* Sentinel name */}
                        <span className="text-[11px] font-mono text-[#ece7dc]/70 truncate flex-1">
                          {sentinel.name}
                        </span>
                        {/* Mode label */}
                        <span className="text-[9px] font-mono text-[#6f7f9a] shrink-0">
                          {sentinel.mode}
                        </span>
                      </button>
                    ))}
                </div>
              );
            })}
          </div>
        )}
      </ScrollArea>

      {/* Footer */}
      <div className="shrink-0 px-3 py-1.5 border-t border-[#2d3240]">
        <span className="text-[9px] font-mono text-[#6f7f9a]/40">
          {sentinels.length} sentinels
        </span>
      </div>
    </div>
  );
}
