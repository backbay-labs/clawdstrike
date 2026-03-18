import { clsx } from "clsx";
import { useEffect, useState } from "react";
import {
  searchWorkspaceContent,
  searchWorkspacePaths,
  type WorkspaceContentSearchMatch,
  type WorkspacePathSearchMatch,
} from "@/services/workspace";

export type WorkspaceSearchMode = "paths" | "content";

export interface WorkspaceSearchSelection {
  relativePath: string;
  lineNumber?: number;
  column?: number;
  mode: WorkspaceSearchMode;
}

interface WorkspaceSearchPanelProps {
  rootId?: string;
  initialMode?: WorkspaceSearchMode;
  onOpenResult?: (selection: WorkspaceSearchSelection) => void;
  searchPaths?: (rootId: string, query: string) => Promise<WorkspacePathSearchMatch[]>;
  searchContent?: (rootId: string, query: string) => Promise<WorkspaceContentSearchMatch[]>;
}

export function WorkspaceSearchPanel({
  rootId,
  initialMode = "paths",
  onOpenResult,
  searchPaths = searchWorkspacePaths,
  searchContent = searchWorkspaceContent,
}: WorkspaceSearchPanelProps) {
  const [mode, setMode] = useState<WorkspaceSearchMode>(initialMode);
  const [query, setQuery] = useState("");
  const [pathMatches, setPathMatches] = useState<WorkspacePathSearchMatch[]>([]);
  const [contentMatches, setContentMatches] = useState<WorkspaceContentSearchMatch[]>([]);
  const [isLoading, setIsLoading] = useState(false);
  const [errorMessage, setErrorMessage] = useState<string>();

  useEffect(() => {
    let cancelled = false;
    const trimmed = query.trim();

    if (!rootId || !trimmed) {
      setPathMatches([]);
      setContentMatches([]);
      setErrorMessage(undefined);
      setIsLoading(false);
      return () => {
        cancelled = true;
      };
    }

    async function runSearch() {
      const activeRootId = rootId;
      if (!activeRootId) return;

      setIsLoading(true);
      setErrorMessage(undefined);

      try {
        if (mode === "paths") {
          const matches = await searchPaths(activeRootId, trimmed);
          if (cancelled) return;
          setPathMatches(matches);
          setContentMatches([]);
          return;
        }

        const matches = await searchContent(activeRootId, trimmed);
        if (cancelled) return;
        setContentMatches(matches);
        setPathMatches([]);
      } catch (error) {
        if (cancelled) return;
        setPathMatches([]);
        setContentMatches([]);
        setErrorMessage(error instanceof Error ? error.message : "Workspace search failed.");
      } finally {
        if (!cancelled) {
          setIsLoading(false);
        }
      }
    }

    void runSearch();
    return () => {
      cancelled = true;
    };
  }, [mode, query, rootId, searchContent, searchPaths]);

  const hasResults = mode === "paths" ? pathMatches.length > 0 : contentMatches.length > 0;

  return (
    <div className="flex h-full flex-col gap-4" data-testid="workspace-search-panel">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div>
          <div className="text-sm font-medium text-sdr-text-primary">Quick open and content search</div>
          <p className="mt-1 text-xs text-sdr-text-muted">
            WS6 consumes `fd` and `rg` style results through lane-owned search modules.
          </p>
        </div>
        <div className="inline-flex rounded-full border border-sdr-border bg-sdr-bg-primary/20 p-1">
          {(["paths", "content"] as const).map((candidate) => (
            <button
              key={candidate}
              type="button"
              onClick={() => setMode(candidate)}
              className={clsx(
                "rounded-full px-3 py-1.5 text-xs uppercase tracking-[0.12em]",
                mode === candidate
                  ? "bg-[rgba(213,173,87,0.14)] text-sdr-text-primary"
                  : "text-sdr-text-muted",
              )}
            >
              {candidate === "paths" ? "Quick Open" : "Content"}
            </button>
          ))}
        </div>
      </div>

      <label className="block">
        <span className="sr-only">{mode === "paths" ? "Search paths" : "Search contents"}</span>
        <input
          data-testid="workspace-search-input"
          type="text"
          value={query}
          onChange={(event) => setQuery(event.target.value)}
          placeholder={mode === "paths" ? "Find a file by path..." : "Find text across the trusted root..."}
          className="w-full rounded-xl border border-sdr-border bg-sdr-bg-primary/40 px-3 py-2 text-sm text-sdr-text-primary placeholder:text-sdr-text-muted"
        />
      </label>

      {!rootId ? (
        <SearchState title="No trusted root selected" description="Register a workspace root before quick-open or content search can run." />
      ) : isLoading ? (
        <SearchState title="Searching workspace" description={mode === "paths" ? "Resolving path matches." : "Scanning content matches."} />
      ) : errorMessage ? (
        <SearchState title="Search failed" description={errorMessage} tone="error" />
      ) : !query.trim() ? (
        <SearchState title="Search ready" description={mode === "paths" ? "Type a path fragment to open files fast." : "Type text to stream content matches into the editor."} />
      ) : !hasResults ? (
        <SearchState title="No matches" description="Try a broader term or switch between quick-open and content search." />
      ) : mode === "paths" ? (
        <div className="space-y-2 overflow-auto" data-testid="workspace-search-path-results">
          {pathMatches.map((match) => (
            <button
              key={match.relativePath}
              type="button"
              onClick={() =>
                onOpenResult?.({
                  relativePath: match.relativePath,
                  mode: "paths",
                })
              }
              className="flex w-full items-center justify-between gap-3 rounded-xl border border-sdr-border bg-sdr-bg-primary/20 px-3 py-3 text-left hover:border-[color:rgba(213,173,87,0.38)]"
            >
              <div className="min-w-0">
                <div className="truncate text-sm font-medium text-sdr-text-primary">{match.name}</div>
                <div className="mt-1 truncate text-xs text-sdr-text-muted">{match.relativePath}</div>
              </div>
              <span className="rounded-full border border-sdr-border px-2 py-1 text-[11px] uppercase tracking-[0.12em] text-sdr-text-muted">
                Open
              </span>
            </button>
          ))}
        </div>
      ) : (
        <div className="space-y-2 overflow-auto" data-testid="workspace-search-content-results">
          {contentMatches.map((match) => (
            <button
              key={`${match.relativePath}:${match.lineNumber}:${match.column}`}
              type="button"
              onClick={() =>
                onOpenResult?.({
                  relativePath: match.relativePath,
                  lineNumber: match.lineNumber,
                  column: match.column,
                  mode: "content",
                })
              }
              className="block w-full rounded-xl border border-sdr-border bg-sdr-bg-primary/20 px-3 py-3 text-left hover:border-[color:rgba(213,173,87,0.38)]"
            >
              <div className="flex items-center justify-between gap-3">
                <div className="truncate text-sm font-medium text-sdr-text-primary">{match.relativePath}</div>
                <div className="text-xs text-sdr-text-muted">
                  L{match.lineNumber}:C{match.column}
                </div>
              </div>
              <div className="mt-2 text-xs text-sdr-text-secondary">{match.lineText}</div>
            </button>
          ))}
        </div>
      )}
    </div>
  );
}

function SearchState({
  title,
  description,
  tone = "default",
}: {
  title: string;
  description: string;
  tone?: "default" | "error";
}) {
  return (
    <div
      className={clsx(
        "rounded-xl border p-4 text-sm",
        tone === "error"
          ? "border-red-500/40 bg-red-500/10 text-red-100"
          : "border-dashed border-sdr-border bg-sdr-bg-primary/20 text-sdr-text-secondary",
      )}
    >
      <div className="font-medium">{title}</div>
      <p className="mt-2 text-xs opacity-80">{description}</p>
    </div>
  );
}
