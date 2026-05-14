import { useMemo, useState } from "react";
import {
  IconSearch,
  IconShield,
  IconChevronRight,
  IconLibrary,
} from "@tabler/icons-react";
import { ScrollArea } from "@/components/ui/scroll-area";
import {
  POLICY_CATALOG,
  CATALOG_CATEGORIES,
  type CatalogEntry,
  type CatalogCategory,
} from "@/features/policy/policy-catalog";
import { usePaneStore } from "@/features/panes/pane-store";

// ---------------------------------------------------------------------------
// LibraryPanel -- filterable policy catalog list grouped by category.
//
// Shows built-in and user policies with shield icons, category groups,
// a filter input, and clickable items that open the library view.
// ---------------------------------------------------------------------------

function getCategoryLabel(category: CatalogCategory): string {
  return (
    CATALOG_CATEGORIES.find((c) => c.id === category)?.label ?? category
  );
}

function groupByCategory(
  entries: CatalogEntry[],
): Map<CatalogCategory, CatalogEntry[]> {
  const groups = new Map<CatalogCategory, CatalogEntry[]>();
  for (const entry of entries) {
    const bucket = groups.get(entry.category);
    if (bucket) {
      bucket.push(entry);
    } else {
      groups.set(entry.category, [entry]);
    }
  }
  return groups;
}

// ---------------------------------------------------------------------------
// LibraryPanel
// ---------------------------------------------------------------------------

export function LibraryPanel() {
  const [filter, setFilter] = useState("");
  const [collapsed, setCollapsed] = useState<Set<string>>(new Set());

  const filtered = useMemo(() => {
    if (!filter) return POLICY_CATALOG;
    const lower = filter.toLowerCase();
    return POLICY_CATALOG.filter(
      (entry) =>
        entry.name.toLowerCase().includes(lower) ||
        entry.tags.join(" ").toLowerCase().includes(lower),
    );
  }, [filter]);

  const groups = useMemo(() => groupByCategory(filtered), [filtered]);

  const toggleGroup = (category: string) => {
    setCollapsed((prev) => {
      const next = new Set(prev);
      if (next.has(category)) {
        next.delete(category);
      } else {
        next.add(category);
      }
      return next;
    });
  };

  const handleItemClick = (entry: CatalogEntry) => {
    usePaneStore.getState().openApp("/library", entry.name);
  };

  return (
    <div className="flex flex-col h-full">
      {/* Panel header */}
      <div className="h-8 shrink-0 flex items-center px-4 border-b border-[#2d3240]/40">
        <span className="font-display font-semibold text-sm text-[#ece7dc]">
          Library
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
            placeholder="Search policies..."
            aria-label="Search policies"
            className="w-full bg-[#0b0d13] border border-[#2d3240] rounded text-[11px] font-mono text-[#ece7dc] pl-7 pr-2 py-1 outline-none transition-colors placeholder:text-[#6f7f9a]/40 focus:border-[#d4a84b]/40"
          />
        </div>
      </div>

      {/* List */}
      <ScrollArea className="flex-1">
        {POLICY_CATALOG.length === 0 ? (
          /* Empty state */
          <div className="flex flex-col items-center justify-center py-8 text-center gap-1">
            <IconLibrary size={28} stroke={1} className="text-[#6f7f9a]/30" />
            <span className="text-[11px] font-mono font-semibold text-[#6f7f9a]/70">
              Library Empty
            </span>
            <p className="text-[11px] font-mono text-[#6f7f9a]/70 leading-relaxed max-w-[80%]">
              No policies loaded. Import or create a policy to get started.
            </p>
          </div>
        ) : filtered.length === 0 && filter ? (
          /* No matches */
          <div className="flex flex-col items-center justify-center py-8 text-center">
            <p className="text-[10px] font-mono text-[#6f7f9a]/50">
              No policies match the current filter
            </p>
          </div>
        ) : (
          <div className="py-1">
            {Array.from(groups.entries()).map(([category, entries]) => {
              const isCollapsed = collapsed.has(category);

              return (
                <div key={category}>
                  {/* Category header */}
                  <button
                    type="button"
                    role="button"
                    aria-expanded={!isCollapsed}
                    onClick={() => toggleGroup(category)}
                    className="flex items-center gap-1 w-full px-3 py-1.5 text-[10px] font-mono font-semibold text-[#6f7f9a] uppercase tracking-wider hover:bg-[#131721]/20 transition-colors"
                  >
                    <IconChevronRight
                      size={8}
                      stroke={2}
                      className={`transition-transform ${isCollapsed ? "" : "rotate-90"}`}
                    />
                    <span>{getCategoryLabel(category)}</span>
                    <span className="text-[#6f7f9a]/50 ml-0.5">
                      ({entries.length})
                    </span>
                  </button>

                  {/* Category items */}
                  {!isCollapsed &&
                    entries.map((entry) => (
                      <button
                        key={entry.id}
                        type="button"
                        role="option"
                        onClick={() => handleItemClick(entry)}
                        className="flex items-center gap-1.5 w-full h-8 px-3 text-left hover:bg-[#131721]/40 transition-colors"
                      >
                        {/* Shield icon */}
                        <IconShield
                          size={14}
                          stroke={1.5}
                          className="text-[#6f7f9a] shrink-0"
                        />
                        {/* Policy name */}
                        <span className="text-[11px] font-mono text-[#ece7dc]/70 truncate flex-1">
                          {entry.name}
                        </span>
                        {/* Source label */}
                        <span className="text-[9px] font-mono text-[#6f7f9a] shrink-0">
                          {entry.author === "Clawdstrike Team" ? "built-in" : entry.author}
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
          {POLICY_CATALOG.length} policies
        </span>
      </div>
    </div>
  );
}
