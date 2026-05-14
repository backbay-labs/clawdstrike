import { useEffect, useRef, useCallback } from "react";
import { IconSearch } from "@tabler/icons-react";
import { ScrollArea } from "@/components/ui/scroll-area";
import { cn } from "@/lib/utils";
import { useSearchStore } from "@/features/search/stores/search-store";
import type {
  SearchMatch,
  SearchOptions,
  SearchResultGroup,
} from "@/features/search/stores/search-store";
import { useProjectStore } from "@/features/project/stores/project-store";
import { resolveProjectPath } from "@/features/project/utils/resolve-project-path";
import { usePaneStore } from "@/features/panes/pane-store";
import { useWorkbenchState } from "@/features/policy/hooks/use-policy-actions";
import { usePolicyEditStore } from "@/features/policy/stores/policy-edit-store";
import { usePolicyTabsStore } from "@/features/policy/stores/policy-tabs-store";
import { requestEditorReveal } from "@/lib/workbench/editor-reveal";
import {
  characterOffsetToCodeUnitIndex,
  getLineTextAt,
} from "@/features/search/utils/search-offsets";

// ---- Types ----

interface SearchPanelProps {
  query: string;
  options: SearchOptions;
  resultGroups: SearchResultGroup[];
  fileCount: number;
  totalMatches: number;
  truncated: boolean;
  loading: boolean;
  error: string | null;
  onQueryChange: (query: string) => void;
  onOptionToggle: (key: keyof SearchOptions) => void;
  onSearch: () => void;
  onResultClick: (match: SearchMatch) => void;
}

// ---- Option toggle button ----

function OptionToggle({
  label,
  tooltip,
  active,
  onClick,
}: {
  label: string;
  tooltip: string;
  active: boolean;
  onClick: () => void;
}) {
  return (
    <button
      type="button"
      title={tooltip}
      onClick={onClick}
      className={cn(
        "h-6 px-1.5 text-[10px] font-mono rounded border transition-colors",
        active
          ? "bg-[#d4a84b]/15 text-[#d4a84b] border-[#d4a84b]/30"
          : "bg-transparent text-[#6f7f9a] border-[#2d3240] hover:text-[#ece7dc]",
      )}
    >
      {label}
    </button>
  );
}

// ---- Highlighted match line ----

function getOpenDocumentLineText(filePath: string, lineNumber: number): string | null {
  const tab = usePolicyTabsStore
    .getState()
    .tabs.find((candidate) => candidate.filePath === filePath);

  if (!tab) {
    return null;
  }

  const yaml = usePolicyEditStore.getState().editStates.get(tab.id)?.yaml;
  return typeof yaml === "string" ? getLineTextAt(yaml, lineNumber) : null;
}

function HighlightedLine({
  lineContent,
  matchStart,
  matchEnd,
}: {
  lineContent: string;
  matchStart: number;
  matchEnd: number;
}) {
  const previewMatchStart = characterOffsetToCodeUnitIndex(lineContent, matchStart);
  const previewMatchEnd = Math.max(
    previewMatchStart,
    characterOffsetToCodeUnitIndex(lineContent, matchEnd),
  );
  const before = lineContent.slice(0, previewMatchStart);
  const match = lineContent.slice(previewMatchStart, previewMatchEnd);
  const after = lineContent.slice(previewMatchEnd);

  return (
    <span className="overflow-hidden text-ellipsis whitespace-nowrap">
      <span className="text-[#ece7dc]/60">{before}</span>
      <mark className="bg-[#d4a84b]/25 text-[#d4a84b] rounded-sm">{match}</mark>
      <span className="text-[#ece7dc]/60">{after}</span>
    </span>
  );
}

// ---- File result group ----

function FileGroup({
  group,
  onResultClick,
}: {
  group: SearchResultGroup;
  onResultClick: (match: SearchMatch) => void;
}) {
  return (
    <div>
      {/* File header */}
      <div
        className="sticky top-0 z-10 flex items-center justify-between px-3 py-1 bg-[#0b0d13] cursor-pointer hover:bg-[#131721]/60"
        onClick={() => onResultClick(group.matches[0])}
        onKeyDown={(e) => {
          if (e.key === "Enter") onResultClick(group.matches[0]);
        }}
        role="button"
        tabIndex={0}
      >
        <span className="text-[10px] font-mono text-[#ece7dc]/70 truncate min-w-0 flex-1 direction-rtl text-left">
          {group.filePath}
        </span>
        <div className="ml-2 shrink-0 flex items-center gap-1.5">
          <span className="max-w-[120px] truncate text-[9px] font-mono text-[#6f7f9a]/45">
            {group.rootPath.split("/").pop() ?? group.rootPath}
          </span>
          <span className="text-[9px] font-mono text-[#6f7f9a]/50 bg-[#131721] px-1.5 py-0.5 rounded">
            {group.matches.length}
          </span>
        </div>
      </div>

      {/* Match rows */}
      {group.matches.map((match, i) => (
        <button
          type="button"
          key={`${match.filePath}:${match.lineNumber}:${i}`}
          className="flex items-baseline gap-2 w-full px-3 py-0.5 text-left hover:bg-[#131721]/60 transition-colors"
          onClick={() => onResultClick(match)}
        >
          <span className="w-[40px] shrink-0 text-right text-[11px] font-mono text-[#6f7f9a]/40">
            {match.lineNumber}
          </span>
          <span className="text-[11px] font-mono overflow-hidden text-ellipsis whitespace-nowrap min-w-0 flex-1">
            <HighlightedLine
              lineContent={match.lineContent}
              matchStart={match.matchStart}
              matchEnd={match.matchEnd}
            />
          </span>
        </button>
      ))}
    </div>
  );
}

// ---- Presentational SearchPanel ----

export function SearchPanel({
  query,
  options,
  resultGroups,
  fileCount,
  totalMatches,
  truncated,
  loading,
  error,
  onQueryChange,
  onOptionToggle,
  onSearch,
  onResultClick,
}: SearchPanelProps) {
  const inputRef = useRef<HTMLInputElement>(null);
  const debounceRef = useRef<ReturnType<typeof setTimeout> | null>(null);

  // Focus input on mount
  useEffect(() => {
    inputRef.current?.focus();
  }, []);

  const handleInputChange = useCallback(
    (value: string) => {
      onQueryChange(value);
      if (debounceRef.current) clearTimeout(debounceRef.current);
      debounceRef.current = setTimeout(() => {
        onSearch();
      }, 300);
    },
    [onQueryChange, onSearch],
  );

  // Cleanup debounce on unmount
  useEffect(() => {
    return () => {
      if (debounceRef.current) clearTimeout(debounceRef.current);
    };
  }, []);

  const hasQuery = query.trim().length > 0;
  const hasResults = resultGroups.length > 0;

  return (
    <div className="flex flex-col h-full bg-[#05060a]">
      {/* Header */}
      <div className="shrink-0 px-3 py-2.5 border-b border-[#2d3240]">
        <div className="flex items-center gap-1.5 mb-2">
          <span className="text-[10px] font-mono uppercase tracking-wider text-[#6f7f9a]">
            Search
          </span>
        </div>

        {/* Search input */}
        <div className="relative mb-2">
          <IconSearch
            size={11}
            stroke={1.5}
            className="absolute left-2 top-1/2 -translate-y-1/2 text-[#6f7f9a]/40 pointer-events-none"
          />
          <input
            ref={inputRef}
            type="text"
            value={query}
            onChange={(e) => handleInputChange(e.target.value)}
            onKeyDown={(e) => {
              if (e.key === "Enter") {
                if (debounceRef.current) clearTimeout(debounceRef.current);
                onSearch();
              }
            }}
            placeholder="Search files..."
            className="w-full bg-[#0b0d13] border border-[#2d3240] rounded text-[11px] font-mono text-[#ece7dc] pl-7 pr-2 py-1 outline-none transition-colors placeholder:text-[#6f7f9a]/40 focus:border-[#d4a84b]/40"
          />
        </div>

        {/* Option toggles */}
        <div className="flex items-center gap-1">
          <OptionToggle
            label="Aa"
            tooltip="Match Case"
            active={options.caseSensitive}
            onClick={() => onOptionToggle("caseSensitive")}
          />
          <OptionToggle
            label="|ab|"
            tooltip="Match Whole Word"
            active={options.wholeWord}
            onClick={() => onOptionToggle("wholeWord")}
          />
          <OptionToggle
            label=".*"
            tooltip="Use Regular Expression"
            active={options.useRegex}
            onClick={() => onOptionToggle("useRegex")}
          />
        </div>
      </div>

      {/* Results status */}
      <div className="shrink-0 px-3 py-1.5 border-b border-[#2d3240]/50">
        {loading && (
          <span className="text-[10px] font-mono text-[#6f7f9a]/60">
            Searching...
          </span>
        )}
        {error && (
          <span className="text-[10px] font-mono text-red-400/80">
            {error}
          </span>
        )}
        {!loading && !error && hasResults && (
          <span className="text-[10px] font-mono text-[#6f7f9a]/60">
            {totalMatches} results in {fileCount} files
          </span>
        )}
        {!loading && !error && hasQuery && !hasResults && (
          <span className="text-[10px] font-mono text-[#6f7f9a]/40">
            No results found
          </span>
        )}
        {!loading && !error && !hasQuery && (
          <span className="text-[10px] font-mono text-[#6f7f9a]/40">
            &nbsp;
          </span>
        )}
      </div>

      {/* Results or empty state */}
      {!hasQuery && !loading ? (
        <div className="flex-1 flex flex-col items-center justify-center p-4 text-center gap-3">
          <IconSearch size={28} stroke={1} className="text-[#6f7f9a]/30" />
          <p className="text-[11px] font-mono text-[#6f7f9a]/70 leading-relaxed">
            Type to search across all workspace files
          </p>
        </div>
      ) : (
        <ScrollArea className="flex-1">
          <div className="py-1">
            {resultGroups.map((group) => (
              <FileGroup
                key={`${group.rootPath}::${group.filePath}`}
                group={group}
                onResultClick={onResultClick}
              />
            ))}
          </div>
        </ScrollArea>
      )}

      {/* Truncation warning */}
      {truncated && (
        <div className="shrink-0 px-3 py-1.5 border-t border-[#2d3240]">
          <span className="text-[9px] font-mono text-[#d4a84b]/60">
            Results capped at 10,000 matches. Refine your search.
          </span>
        </div>
      )}
    </div>
  );
}

// ---- Connected component ----

export function SearchPanelConnected() {
  const query = useSearchStore.use.query();
  const options = useSearchStore.use.options();
  const resultGroups = useSearchStore.use.resultGroups();
  const fileCount = useSearchStore.use.fileCount();
  const totalMatches = useSearchStore.use.totalMatches();
  const truncated = useSearchStore.use.truncated();
  const loading = useSearchStore.use.loading();
  const error = useSearchStore.use.error();
  const actions = useSearchStore.use.actions();
  const projectRoots = useProjectStore.use.projectRoots();
  const { openFileByPath } = useWorkbenchState();
  const latestResultClickTokenRef = useRef(0);

  return (
    <SearchPanel
      query={query}
      options={options}
      resultGroups={resultGroups}
      fileCount={fileCount}
      totalMatches={totalMatches}
      truncated={truncated}
      loading={loading}
      error={error}
      onQueryChange={actions.setQuery}
      onOptionToggle={(key) => actions.setOption(key, !options[key], projectRoots)}
      onSearch={() => actions.performSearch(projectRoots)}
      onResultClick={async (match) => {
        latestResultClickTokenRef.current += 1;
        const clickToken = latestResultClickTokenRef.current;
        const filePath = resolveProjectPath(match.rootPath, match.filePath);
        await openFileByPath(filePath, {
          shouldApply: () => latestResultClickTokenRef.current === clickToken,
        });
        if (latestResultClickTokenRef.current !== clickToken) {
          return;
        }
        const sourceLine = getOpenDocumentLineText(filePath, match.lineNumber) ?? match.lineContent;
        const startColumn =
          characterOffsetToCodeUnitIndex(sourceLine, match.sourceMatchStart) + 1;
        const endColumn = Math.max(
          startColumn,
          characterOffsetToCodeUnitIndex(sourceLine, match.sourceMatchEnd) + 1,
        );
        requestEditorReveal({
          filePath,
          lineNumber: match.lineNumber,
          startColumn,
          endColumn,
        });
        usePaneStore
          .getState()
          .openFile(filePath, match.filePath.split("/").pop() ?? match.filePath);
      }}
    />
  );
}
