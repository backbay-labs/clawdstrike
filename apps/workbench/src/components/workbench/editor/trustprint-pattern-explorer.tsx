import { useState, useMemo, useCallback } from "react";
import { cn } from "@/lib/utils";
import {
  type PatternEntry,
  type PatternCategory,
  type PatternStage,
  ALL_STAGES,
  ALL_CATEGORIES,
  STAGE_LABELS,
  CATEGORY_LABELS,
  CATEGORY_SHORT_LABELS,
  buildHeatmap,
  detectGaps,
  computeCoverageStats,
} from "@/lib/workbench/trustprint-patterns";
import {
  IconX,
  IconAlertTriangle,
  IconCircleCheck,
  IconSearch,
  IconChevronUp,
  IconChevronDown,
} from "@tabler/icons-react";

// ---------------------------------------------------------------------------
// Props
// ---------------------------------------------------------------------------

interface TrustprintPatternExplorerProps {
  /** Pattern entries from the loaded DB */
  patterns: PatternEntry[];
  /** Currently selected pattern ID (for detail view) */
  selectedPatternId?: string;
  onSelectPattern?: (id: string) => void;
  /** Compact mode for embedding in guard card */
  compact?: boolean;
}

// ---------------------------------------------------------------------------
// Color helpers
// ---------------------------------------------------------------------------

/** Category color gradient from gold (#d4a84b) to green (#3dbf84). */
function getCategoryColor(index: number): string {
  const colors = [
    "#d4a84b", // 0: prompt_injection
    "#c9ad52", // 1: jailbreak
    "#beb259", // 2: social_engineering
    "#a9b862", // 3: data_poisoning
    "#94bd6b", // 4: evasion
    "#7fc274", // 5: reconnaissance
    "#6ac77d", // 6: supply_chain
    "#54c382", // 7: data_exfiltration (slightly adjusted)
    "#3dbf84", // 8: privilege_escalation
  ];
  return colors[index] ?? "#6f7f9a";
}

function getCellBackground(count: number, categoryIndex: number): string {
  if (count === 0) return "#2d3240";
  const color = getCategoryColor(categoryIndex);
  if (count === 1) return `${color}40`; // muted
  return `${color}80`; // bright
}

// ---------------------------------------------------------------------------
// Sorting
// ---------------------------------------------------------------------------

type SortKey = "id" | "category" | "stage" | "label" | "dims";
type SortDir = "asc" | "desc";

function comparePatterns(a: PatternEntry, b: PatternEntry, key: SortKey, dir: SortDir): number {
  let cmp = 0;
  switch (key) {
    case "id":
      cmp = a.id.localeCompare(b.id);
      break;
    case "category":
      cmp = a.category.localeCompare(b.category);
      break;
    case "stage":
      cmp = a.stage.localeCompare(b.stage);
      break;
    case "label":
      cmp = a.label.localeCompare(b.label);
      break;
    case "dims":
      cmp = a.embedding.length - b.embedding.length;
      break;
  }
  return dir === "asc" ? cmp : -cmp;
}

// ---------------------------------------------------------------------------
// Compact heatmap
// ---------------------------------------------------------------------------

/** Short 1-letter stage labels for compact grid header */
const STAGE_INITIALS: Record<PatternStage, string> = {
  perception: "P",
  cognition: "C",
  action: "A",
  feedback: "F",
};

/** Abbreviated category labels for compact grid rows */
const CATEGORY_ABBR: Record<PatternCategory, string> = {
  prompt_injection: "PI",
  jailbreak: "JB",
  social_engineering: "SE",
  data_poisoning: "DP",
  evasion: "EV",
  reconnaissance: "RC",
  supply_chain: "SC",
  data_exfiltration: "DE",
  privilege_escalation: "PE",
};

function CompactHeatmap({
  patterns,
}: {
  patterns: PatternEntry[];
}) {
  const heatmap = useMemo(() => buildHeatmap(patterns), [patterns]);
  const stats = useMemo(() => computeCoverageStats(patterns), [patterns]);
  const [selectedCell, setSelectedCell] = useState<{
    stage: PatternStage;
    category: PatternCategory;
  } | null>(null);
  const [expanded, setExpanded] = useState(false);

  // Patterns matching the selected cell
  const cellPatterns = useMemo(() => {
    if (!selectedCell) return [];
    return patterns.filter(
      (p) => p.stage === selectedCell.stage && p.category === selectedCell.category,
    );
  }, [patterns, selectedCell]);

  const handleCellClick = useCallback(
    (stage: PatternStage, category: PatternCategory) => {
      if (selectedCell?.stage === stage && selectedCell?.category === category) {
        setSelectedCell(null);
      } else {
        setSelectedCell({ stage, category });
      }
    },
    [selectedCell],
  );

  if (expanded) {
    return (
      <div className="flex flex-col gap-2">
        <FullExplorer patterns={patterns} />
        <button
          type="button"
          className="self-start text-[9px] font-mono text-[#6f7f9a] hover:text-[#d4a84b] transition-colors"
          onClick={() => setExpanded(false)}
        >
          ← Collapse
        </button>
      </div>
    );
  }

  return (
    <div className="flex flex-col gap-1.5">
      {/* Grid with row/column labels */}
      <div className="flex gap-0">
        {/* Category row labels */}
        <div className="flex flex-col gap-px mr-1 pt-[14px]">
          {ALL_CATEGORIES.map((cat) => (
            <div
              key={cat}
              className="h-5 flex items-center justify-end"
              title={CATEGORY_LABELS[cat]}
            >
              <span className={cn(
                "text-[7px] font-mono leading-none transition-colors",
                selectedCell?.category === cat ? "text-[#d4a84b]" : "text-[#6f7f9a]/40",
              )}>
                {CATEGORY_ABBR[cat]}
              </span>
            </div>
          ))}
        </div>

        <div className="flex flex-col gap-0">
          {/* Stage column headers */}
          <div
            className="grid gap-px mb-0.5"
            style={{
              gridTemplateColumns: `repeat(${ALL_STAGES.length}, 1fr)`,
              width: "200px",
            }}
          >
            {ALL_STAGES.map((stage) => (
              <div key={stage} className="flex items-center justify-center" title={STAGE_LABELS[stage]}>
                <span className={cn(
                  "text-[7px] font-mono transition-colors",
                  selectedCell?.stage === stage ? "text-[#d4a84b]" : "text-[#6f7f9a]/40",
                )}>{STAGE_INITIALS[stage]}</span>
              </div>
            ))}
          </div>

          {/* Heatmap cells */}
          <div
            className="grid gap-px"
            style={{
              gridTemplateColumns: `repeat(${ALL_STAGES.length}, 1fr)`,
              width: "200px",
            }}
            role="grid"
            aria-label="Pattern coverage heatmap"
          >
            {ALL_CATEGORIES.map((category, catIdx) =>
              ALL_STAGES.map((stage) => {
                const cell = heatmap.find(
                  (c) => c.category === category && c.stage === stage,
                );
                const count = cell?.count ?? 0;
                const isSelected =
                  selectedCell?.stage === stage && selectedCell?.category === category;

                return (
                  <button
                    key={`${category}-${stage}`}
                    type="button"
                    role="gridcell"
                    className={cn(
                      "h-5 rounded-sm transition-all cursor-pointer flex items-center justify-center text-[8px] font-mono font-medium",
                      count === 0
                        ? "border border-dashed border-[#c45c5c]/40 text-[#c45c5c]/40 hover:border-[#c45c5c]/60"
                        : "text-[#ece7dc]/70 hover:brightness-125",
                      isSelected && "ring-1 ring-[#d4a84b] ring-offset-1 ring-offset-[#0b0d13]",
                    )}
                    style={{
                      backgroundColor: getCellBackground(count, catIdx),
                    }}
                    title={`${STAGE_LABELS[stage]} + ${CATEGORY_LABELS[category]}: ${count} pattern${count !== 1 ? "s" : ""}`}
                    onClick={() => handleCellClick(stage, category)}
                  >
                    {count}
                  </button>
                );
              }),
            )}
          </div>
        </div>
      </div>

      {/* Cell detail panel */}
      {selectedCell && (
        <div className="mt-1 border border-[#2d3240] rounded-md bg-[#131721]/60 overflow-hidden">
          <div className="flex items-center justify-between px-2 py-1.5 border-b border-[#2d3240]/50">
            <span className="text-[9px] font-mono text-[#d4a84b]">
              {(STAGE_LABELS as Record<string, string>)[selectedCell.stage]} ×{" "}
              {(CATEGORY_LABELS as Record<string, string>)[selectedCell.category]}
            </span>
            <button
              type="button"
              className="text-[#6f7f9a] hover:text-[#ece7dc] transition-colors"
              onClick={() => setSelectedCell(null)}
              aria-label="Close detail panel"
            >
              <IconX size={10} stroke={2} />
            </button>
          </div>
          {cellPatterns.length === 0 ? (
            <div className="px-2 py-2.5 flex items-center gap-1.5">
              <IconAlertTriangle size={10} stroke={1.5} className="text-[#c45c5c]/60 shrink-0" />
              <span className="text-[9px] font-mono text-[#c45c5c]/80">
                Coverage gap — no patterns defined for this cell
              </span>
            </div>
          ) : (
            <div className="flex flex-col">
              {cellPatterns.map((p, i) => (
                <div
                  key={p.id}
                  className={cn(
                    "flex items-start gap-2 px-2 py-1.5 text-[9px]",
                    i < cellPatterns.length - 1 && "border-b border-[#2d3240]/30",
                  )}
                >
                  <span className="font-mono text-[#6f7f9a]/50 shrink-0 mt-px">{p.id}</span>
                  <span className="text-[#ece7dc] leading-snug">{p.label}</span>
                  <span className="font-mono text-[#6f7f9a]/40 shrink-0 ml-auto whitespace-nowrap">
                    {p.embedding.length}d
                  </span>
                </div>
              ))}
            </div>
          )}
        </div>
      )}

      {/* Footer: coverage badge + explore link */}
      <div className="flex items-center justify-between">
        <span
          className={cn(
            "text-[9px] font-mono",
            stats.gapCount === 0 ? "text-[#3dbf84]" : "text-[#6f7f9a]",
          )}
          data-testid="compact-coverage-badge"
        >
          {stats.coveredCells}/{stats.totalCells} cells covered
          {stats.gapCount > 0 && ` (${stats.gapCount} gap${stats.gapCount !== 1 ? "s" : ""})`}
        </span>
        <button
          type="button"
          className="text-[9px] font-mono text-[#6f7f9a] hover:text-[#d4a84b] transition-colors"
          onClick={() => setExpanded(true)}
        >
          Explore database →
        </button>
      </div>
    </div>
  );
}

// ---------------------------------------------------------------------------
// Full explorer
// ---------------------------------------------------------------------------

function SortableHeader({
  label,
  sortKey,
  currentKey,
  currentDir,
  onSort,
  className,
}: {
  label: string;
  sortKey: SortKey;
  currentKey: SortKey;
  currentDir: SortDir;
  onSort: (key: SortKey) => void;
  className?: string;
}) {
  const isActive = currentKey === sortKey;
  return (
    <button
      type="button"
      className={cn(
        "flex items-center gap-1 text-[10px] font-mono font-medium uppercase tracking-wider text-left",
        isActive ? "text-[#d4a84b]" : "text-[#6f7f9a] hover:text-[#ece7dc]",
        "transition-colors",
        className,
      )}
      onClick={() => onSort(sortKey)}
    >
      {label}
      {isActive && (currentDir === "asc" ? (
        <IconChevronUp size={10} stroke={1.5} />
      ) : (
        <IconChevronDown size={10} stroke={1.5} />
      ))}
    </button>
  );
}

function FullExplorer({
  patterns,
  selectedPatternId,
  onSelectPattern,
}: {
  patterns: PatternEntry[];
  selectedPatternId?: string;
  onSelectPattern?: (id: string) => void;
}) {
  const [filterStage, setFilterStage] = useState<PatternStage | "all">("all");
  const [filterCategory, setFilterCategory] = useState<PatternCategory | "all">("all");
  const [searchText, setSearchText] = useState("");
  const [heatmapFilter, setHeatmapFilter] = useState<{
    stage: PatternStage;
    category: PatternCategory;
  } | null>(null);
  const [sortKey, setSortKey] = useState<SortKey>("id");
  const [sortDir, setSortDir] = useState<SortDir>("asc");

  const heatmap = useMemo(() => buildHeatmap(patterns), [patterns]);
  const gaps = useMemo(() => detectGaps(patterns), [patterns]);
  const stats = useMemo(() => computeCoverageStats(patterns), [patterns]);

  const handleSort = useCallback(
    (key: SortKey) => {
      if (key === sortKey) {
        setSortDir((d) => (d === "asc" ? "desc" : "asc"));
      } else {
        setSortKey(key);
        setSortDir("asc");
      }
    },
    [sortKey],
  );

  const handleCellClick = useCallback(
    (stage: PatternStage, category: PatternCategory) => {
      if (
        heatmapFilter &&
        heatmapFilter.stage === stage &&
        heatmapFilter.category === category
      ) {
        setHeatmapFilter(null);
      } else {
        setHeatmapFilter({ stage, category });
      }
    },
    [heatmapFilter],
  );

  const clearHeatmapFilter = useCallback(() => {
    setHeatmapFilter(null);
  }, []);

  // Apply filters
  const filteredPatterns = useMemo(() => {
    let result = patterns;

    // Heatmap filter takes precedence
    if (heatmapFilter) {
      result = result.filter(
        (p) =>
          p.stage === heatmapFilter.stage &&
          p.category === heatmapFilter.category,
      );
    } else {
      if (filterStage !== "all") {
        result = result.filter((p) => p.stage === filterStage);
      }
      if (filterCategory !== "all") {
        result = result.filter((p) => p.category === filterCategory);
      }
    }

    if (searchText.trim()) {
      const q = searchText.toLowerCase();
      result = result.filter(
        (p) =>
          p.id.toLowerCase().includes(q) ||
          p.label.toLowerCase().includes(q) ||
          p.category.toLowerCase().includes(q) ||
          p.stage.toLowerCase().includes(q),
      );
    }

    // Sort
    result = [...result].sort((a, b) => comparePatterns(a, b, sortKey, sortDir));

    return result;
  }, [patterns, filterStage, filterCategory, searchText, heatmapFilter, sortKey, sortDir]);

  return (
    <div className="flex flex-col gap-4">
      {/* Stats line */}
      <div className="text-[11px] font-mono text-[#6f7f9a]" data-testid="stats-line">
        {patterns.length} pattern{patterns.length !== 1 ? "s" : ""} across {ALL_STAGES.length} stages, {ALL_CATEGORIES.length} categories.{" "}
        {stats.gapCount === 0 ? (
          <span className="text-[#3dbf84]">0 gaps.</span>
        ) : (
          <span className="text-[#c45c5c]">{stats.gapCount} gap{stats.gapCount !== 1 ? "s" : ""}.</span>
        )}
      </div>

      {/* Heatmap */}
      <div className="overflow-x-auto">
        <div className="min-w-0">
          {/* Stage column headers */}
          <div
            className="grid gap-1 mb-1"
            style={{
              gridTemplateColumns: `100px repeat(${ALL_STAGES.length}, 1fr)`,
            }}
          >
            <div />
            {ALL_STAGES.map((stage) => (
              <div
                key={stage}
                className="text-[9px] font-syne font-semibold text-[#6f7f9a] text-center uppercase tracking-wider"
              >
                {STAGE_LABELS[stage]}
              </div>
            ))}
          </div>

          {/* Heatmap rows */}
          <div
            className="grid gap-1"
            role="grid"
            aria-label="Pattern coverage heatmap"
          >
            {ALL_CATEGORIES.map((category, catIdx) => (
              <div
                key={category}
                className="grid gap-1"
                style={{
                  gridTemplateColumns: `100px repeat(${ALL_STAGES.length}, 1fr)`,
                }}
                role="row"
              >
                {/* Row label */}
                <div
                  className="text-[9px] font-mono text-[#6f7f9a] flex items-center truncate pr-1"
                  title={CATEGORY_LABELS[category]}
                >
                  {CATEGORY_SHORT_LABELS[category]}
                </div>

                {/* Cells */}
                {ALL_STAGES.map((stage) => {
                  const cell = heatmap.find(
                    (c) => c.category === category && c.stage === stage,
                  );
                  const count = cell?.count ?? 0;
                  const isSelected =
                    heatmapFilter?.stage === stage &&
                    heatmapFilter?.category === category;

                  return (
                    <button
                      key={`${category}-${stage}`}
                      type="button"
                      role="gridcell"
                      className={cn(
                        "h-7 rounded-sm flex items-center justify-center text-[10px] font-mono font-medium transition-all cursor-pointer",
                        count === 0 &&
                          "border border-dashed border-[#c45c5c]/40 text-[#c45c5c]/60",
                        count > 0 && "text-[#ece7dc] hover:brightness-125",
                        isSelected && "ring-1 ring-[#d4a84b] ring-offset-1 ring-offset-[#0b0d13]",
                      )}
                      style={{
                        backgroundColor: getCellBackground(count, catIdx),
                      }}
                      onClick={() => handleCellClick(stage, category)}
                      title={`${STAGE_LABELS[stage]} + ${CATEGORY_LABELS[category]}: ${count} pattern${count !== 1 ? "s" : ""}`}
                      aria-label={`${STAGE_LABELS[stage]} ${CATEGORY_LABELS[category]} ${count} patterns`}
                    >
                      {count}
                    </button>
                  );
                })}
              </div>
            ))}
          </div>
        </div>
      </div>

      {/* Filter bar + Heatmap filter badge */}
      <div className="flex flex-wrap items-center gap-2">
        {heatmapFilter && (
          <span
            className="inline-flex items-center gap-1.5 px-2 py-0.5 text-[10px] font-mono bg-[#d4a84b]/10 text-[#d4a84b] border border-[#d4a84b]/20 rounded"
            data-testid="heatmap-filter-badge"
          >
            Filtered: {STAGE_LABELS[heatmapFilter.stage]} x{" "}
            {CATEGORY_LABELS[heatmapFilter.category]}
            <button
              type="button"
              className="hover:text-[#ece7dc] transition-colors"
              onClick={clearHeatmapFilter}
              aria-label="Clear heatmap filter"
            >
              <IconX size={10} stroke={2} />
            </button>
          </span>
        )}

        {!heatmapFilter && (
          <>
            <select
              value={filterStage}
              onChange={(e) => setFilterStage(e.target.value as PatternStage | "all")}
              className="h-6 px-1.5 text-[10px] font-mono bg-[#131721] border border-[#2d3240] rounded text-[#ece7dc] focus:border-[#d4a84b] focus:outline-none"
              aria-label="Filter by stage"
            >
              <option value="all">All Stages</option>
              {ALL_STAGES.map((s) => (
                <option key={s} value={s}>
                  {STAGE_LABELS[s]}
                </option>
              ))}
            </select>

            <select
              value={filterCategory}
              onChange={(e) => setFilterCategory(e.target.value as PatternCategory | "all")}
              className="h-6 px-1.5 text-[10px] font-mono bg-[#131721] border border-[#2d3240] rounded text-[#ece7dc] focus:border-[#d4a84b] focus:outline-none"
              aria-label="Filter by category"
            >
              <option value="all">All Categories</option>
              {ALL_CATEGORIES.map((c) => (
                <option key={c} value={c}>
                  {CATEGORY_LABELS[c]}
                </option>
              ))}
            </select>
          </>
        )}

        <div className="relative flex-1 min-w-[120px]">
          <IconSearch
            size={12}
            stroke={1.5}
            className="absolute left-1.5 top-1/2 -translate-y-1/2 text-[#6f7f9a] pointer-events-none"
          />
          <input
            type="text"
            value={searchText}
            onChange={(e) => setSearchText(e.target.value)}
            placeholder="Search patterns..."
            className="w-full h-6 pl-6 pr-2 text-[10px] font-mono bg-[#131721] border border-[#2d3240] rounded text-[#ece7dc] placeholder:text-[#6f7f9a]/50 focus:border-[#d4a84b] focus:outline-none"
            aria-label="Search patterns"
          />
        </div>
      </div>

      {/* Pattern table */}
      <div className="overflow-x-auto border border-[#2d3240] rounded-lg">
        <table className="w-full text-left" role="table">
          <thead>
            <tr className="border-b border-[#2d3240]">
              <th className="px-2 py-1.5">
                <SortableHeader
                  label="ID"
                  sortKey="id"
                  currentKey={sortKey}
                  currentDir={sortDir}
                  onSort={handleSort}
                />
              </th>
              <th className="px-2 py-1.5">
                <SortableHeader
                  label="Category"
                  sortKey="category"
                  currentKey={sortKey}
                  currentDir={sortDir}
                  onSort={handleSort}
                />
              </th>
              <th className="px-2 py-1.5">
                <SortableHeader
                  label="Stage"
                  sortKey="stage"
                  currentKey={sortKey}
                  currentDir={sortDir}
                  onSort={handleSort}
                />
              </th>
              <th className="px-2 py-1.5">
                <SortableHeader
                  label="Label"
                  sortKey="label"
                  currentKey={sortKey}
                  currentDir={sortDir}
                  onSort={handleSort}
                />
              </th>
              <th className="px-2 py-1.5">
                <SortableHeader
                  label="Dims"
                  sortKey="dims"
                  currentKey={sortKey}
                  currentDir={sortDir}
                  onSort={handleSort}
                />
              </th>
            </tr>
          </thead>
          <tbody>
            {filteredPatterns.map((p) => {
              const isSelected = p.id === selectedPatternId;
              return (
                <tr
                  key={p.id}
                  className={cn(
                    "border-b border-[#2d3240]/50 cursor-pointer transition-colors",
                    isSelected
                      ? "bg-[#d4a84b]/10 border-l-2 border-l-[#d4a84b]"
                      : "hover:bg-[#131721]/80",
                  )}
                  onClick={() => onSelectPattern?.(p.id)}
                  data-testid={`pattern-row-${p.id}`}
                  role="row"
                >
                  <td className="px-2 py-1.5 text-[10px] font-mono text-[#ece7dc] whitespace-nowrap">
                    {p.id}
                  </td>
                  <td className="px-2 py-1.5 text-[10px] font-mono text-[#6f7f9a]">
                    {CATEGORY_SHORT_LABELS[p.category]}
                  </td>
                  <td className="px-2 py-1.5 text-[10px] font-mono text-[#6f7f9a]">
                    {STAGE_LABELS[p.stage]}
                  </td>
                  <td className="px-2 py-1.5 text-[10px] text-[#ece7dc]">
                    {p.label}
                  </td>
                  <td className="px-2 py-1.5 text-[10px] font-mono text-[#6f7f9a] whitespace-nowrap">
                    {p.embedding.length}-dim
                  </td>
                </tr>
              );
            })}
            {filteredPatterns.length === 0 && (
              <tr>
                <td
                  colSpan={5}
                  className="px-2 py-4 text-[10px] font-mono text-[#6f7f9a] text-center"
                >
                  No patterns match the current filters.
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>

      {/* Gap detection panel */}
      <div className="border border-[#2d3240] rounded-lg p-3">
        <div className="flex items-center gap-2 mb-2">
          {gaps.length === 0 ? (
            <span className="inline-flex items-center gap-1 text-[10px] font-mono font-medium text-[#3dbf84]">
              <IconCircleCheck size={12} stroke={1.5} />
              Full coverage
            </span>
          ) : (
            <span className="inline-flex items-center gap-1 text-[10px] font-mono font-medium text-[#c45c5c]">
              <IconAlertTriangle size={12} stroke={1.5} />
              {gaps.length} gap{gaps.length !== 1 ? "s" : ""} detected
            </span>
          )}
        </div>

        {gaps.length > 0 && (
          <div className="flex flex-col gap-1.5">
            {gaps.map((gap) => (
              <div
                key={`${gap.stage}-${gap.category}`}
                className="flex items-start gap-2 px-2 py-1.5 text-[10px] font-mono bg-[#c45c5c]/5 border border-[#c45c5c]/10 rounded"
                data-testid={`gap-card-${gap.stage}-${gap.category}`}
              >
                <span className="text-[#c45c5c]/80 shrink-0">--</span>
                <div>
                  <span className="text-[#ece7dc]">
                    No patterns for {gap.stageLabel} + {gap.categoryLabel}
                  </span>
                  <p className="text-[#6f7f9a] mt-0.5">
                    Add patterns to improve coverage
                  </p>
                </div>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
}

// ---------------------------------------------------------------------------
// Main export
// ---------------------------------------------------------------------------

export function TrustprintPatternExplorer({
  patterns,
  selectedPatternId,
  onSelectPattern,
  compact = false,
}: TrustprintPatternExplorerProps) {
  if (compact) {
    return <CompactHeatmap patterns={patterns} />;
  }

  return (
    <FullExplorer
      patterns={patterns}
      selectedPatternId={selectedPatternId}
      onSelectPattern={onSelectPattern}
    />
  );
}
