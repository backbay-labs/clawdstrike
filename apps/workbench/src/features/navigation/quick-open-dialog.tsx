/**
 * QuickOpenDialog -- Cmd+P file picker with fuzzy matching and recent files.
 *
 * Provides a modal overlay for quickly opening project files by name.
 * When the input is empty, recent files are shown. As the user types,
 * fuzzy matching filters and ranks files from the project tree.
 */
import { useState, useCallback, useEffect, useRef, useMemo, useSyncExternalStore } from "react";
import { motion } from "motion/react";
import { IconSearch, IconFile, IconClock } from "@tabler/icons-react";
import { cn } from "@/lib/utils";
import {
  useProjectStore,
  type DetectionProject,
  type ProjectFile,
} from "@/features/project/stores/project-store";
import { getRecentFiles } from "@/features/policy/stores/policy-store";
import { usePolicyTabsStore, pushRecentFile } from "@/features/policy/stores/policy-tabs-store";
import { readDetectionFileByPath } from "@/lib/tauri-bridge";
import { usePaneStore } from "@/features/panes/pane-store";
import { joinWorkspacePath, normalizeWorkspacePath } from "@/lib/workbench/path-utils";

// ---- Visibility state (module-level, no separate store file) ----

let _quickOpenVisible = false;
const _listeners = new Set<() => void>();

function notify() {
  for (const listener of _listeners) listener();
}

export function openQuickOpen(): void {
  _quickOpenVisible = true;
  notify();
}

export function closeQuickOpen(): void {
  _quickOpenVisible = false;
  notify();
}

export function useQuickOpenVisible(): boolean {
  return useSyncExternalStore(
    (cb) => {
      _listeners.add(cb);
      return () => _listeners.delete(cb);
    },
    () => _quickOpenVisible,
  );
}

// ---- Fuzzy matching helpers ----

/** Recursively flatten a ProjectFile tree into leaf (non-directory) entries. */
export function flattenProjectFiles(files: ProjectFile[]): ProjectFile[] {
  const result: ProjectFile[] = [];
  for (const file of files) {
    if (file.isDirectory) {
      if (file.children) {
        result.push(...flattenProjectFiles(file.children));
      }
    } else {
      result.push(file);
    }
  }
  return result;
}

interface QuickOpenFile {
  path: string;
  displayPath: string;
  name: string;
  fileType: ProjectFile["fileType"];
}

function flattenWorkspaceFiles(projects: DetectionProject[]): QuickOpenFile[] {
  const multiRoot = projects.length > 1;
  const result: QuickOpenFile[] = [];

  for (const project of projects) {
    for (const file of flattenProjectFiles(project.files)) {
      result.push({
        path: joinWorkspacePath(project.rootPath, file.path),
        displayPath: multiRoot ? `${project.name}/${file.path}` : file.path,
        name: file.name,
        fileType: file.fileType,
      });
    }
  }

  return result;
}

interface FuzzyResult {
  file: QuickOpenFile;
  score: number;
}

/**
 * Simple fuzzy match: check if all query characters appear in order
 * in the file name (case-insensitive). Score by consecutive matches,
 * start-of-name bonus, and shorter name preference.
 */
function fuzzyMatch(query: string, fileName: string): number | null {
  const lowerQuery = query.toLowerCase();
  const lowerName = fileName.toLowerCase();

  let queryIndex = 0;
  let score = 0;
  let lastMatchIndex = -2; // Track consecutive matches

  for (let i = 0; i < lowerName.length && queryIndex < lowerQuery.length; i++) {
    if (lowerName[i] === lowerQuery[queryIndex]) {
      // Consecutive character bonus
      if (i === lastMatchIndex + 1) {
        score += 10;
      }
      // Start of name bonus
      if (i === 0) {
        score += 15;
      }
      // Start of word bonus (after separator)
      if (i > 0 && (lowerName[i - 1] === "-" || lowerName[i - 1] === "_" || lowerName[i - 1] === ".")) {
        score += 8;
      }
      score += 1;
      lastMatchIndex = i;
      queryIndex++;
    }
  }

  // All query characters must match
  if (queryIndex < lowerQuery.length) return null;

  // Shorter names rank higher (closer match)
  score -= fileName.length * 0.5;

  return score;
}

function fuzzySearch(files: QuickOpenFile[], query: string): FuzzyResult[] {
  const results: FuzzyResult[] = [];
  for (const file of files) {
    const score = fuzzyMatch(query, file.name);
    if (score !== null) {
      results.push({ file, score });
    }
  }
  results.sort((a, b) => b.score - a.score);
  return results;
}

// ---- Component ----

export function QuickOpenDialog() {
  const visible = useQuickOpenVisible();
  const [query, setQuery] = useState("");
  const [selectedIndex, setSelectedIndex] = useState(0);
  const inputRef = useRef<HTMLInputElement>(null);
  const listRef = useRef<HTMLDivElement>(null);

  const projectRoots = useProjectStore.use.projectRoots();
  const projectsMap = useProjectStore.use.projects();

  const projects = useMemo(() => {
    return projectRoots
      .map((rootPath) => projectsMap.get(rootPath))
      .filter((project): project is DetectionProject => project != null);
  }, [projectRoots, projectsMap]);

  // Flatten the project file tree
  const flatFiles = useMemo(() => {
    return flattenWorkspaceFiles(projects);
  }, [projects]);

  // Build result list
  const results = useMemo(() => {
    if (!query.trim()) {
      // Show recent files when input is empty
      const recentPaths = getRecentFiles().slice(0, 10);
      return {
        isRecent: true,
        items: recentPaths.map((path) => {
          const name = path.split("/").pop() ?? path;
          const normalizedPath = normalizeWorkspacePath(path);
          const match = flatFiles.find((file) => normalizeWorkspacePath(file.path) === normalizedPath);
          return {
            path: match?.path ?? normalizedPath,
            name: match?.name ?? name,
            displayPath: match?.displayPath ?? path,
            fileType: match?.fileType ?? ("clawdstrike_policy" as const),
          };
        }),
      };
    }
    const fuzzyResults = fuzzySearch(flatFiles, query);
    return {
      isRecent: false,
      items: fuzzyResults.map((r) => ({
        path: r.file.path,
        name: r.file.name,
        displayPath: r.file.displayPath,
        fileType: r.file.fileType,
      })),
    };
  }, [query, flatFiles]);

  // Focus input when opened
  useEffect(() => {
    if (visible) {
      setQuery("");
      setSelectedIndex(0);
      setTimeout(() => inputRef.current?.focus(), 50);
    }
  }, [visible]);

  // Clamp selected index when list changes
  useEffect(() => {
    setSelectedIndex((i) =>
      results.items.length === 0 ? 0 : Math.min(i, results.items.length - 1),
    );
  }, [results.items.length]);

  // Global Escape listener
  useEffect(() => {
    if (!visible) return;
    const handler = (e: KeyboardEvent) => {
      if (e.key === "Escape") {
        e.preventDefault();
        closeQuickOpen();
      }
    };
    window.addEventListener("keydown", handler);
    return () => window.removeEventListener("keydown", handler);
  }, [visible]);

  const selectItem = useCallback(
    async (item: { path: string; name: string; fileType: string }) => {
      closeQuickOpen();

      let result: Awaited<ReturnType<typeof readDetectionFileByPath>> | null = null;
      try {
        result = await readDetectionFileByPath(item.path);
      } catch {
        // Fall through to the fallback path below
      }

      if (result) {
        usePolicyTabsStore
          .getState()
          .openTabOrSwitch(result.path, result.fileType, result.content, item.name);
        pushRecentFile(result.path);
      } else {
        // Fallback: try opening with path and empty content
        // (for files that may only exist in the project tree structure)
        usePolicyTabsStore
          .getState()
          .openTabOrSwitch(item.path, item.fileType as import("@/lib/workbench/file-type-registry").FileType, "", item.name);
      }

      usePaneStore.getState().openFile(item.path, item.name);
    },
    [],
  );

  // Keyboard navigation
  const handleKeyDown = useCallback(
    (e: React.KeyboardEvent) => {
      if (e.key === "ArrowDown") {
        e.preventDefault();
        setSelectedIndex((i) => Math.min(i + 1, results.items.length - 1));
        // Scroll into view
        setTimeout(() => {
          const active = listRef.current?.querySelector("[data-active='true']");
          active?.scrollIntoView({ block: "nearest" });
        }, 0);
      } else if (e.key === "ArrowUp") {
        e.preventDefault();
        setSelectedIndex((i) => Math.max(i - 1, 0));
        setTimeout(() => {
          const active = listRef.current?.querySelector("[data-active='true']");
          active?.scrollIntoView({ block: "nearest" });
        }, 0);
      } else if (e.key === "Enter") {
        const clamped = Math.min(selectedIndex, results.items.length - 1);
        const item = results.items[clamped];
        if (item) void selectItem(item);
      }
    },
    [results.items, selectedIndex, selectItem],
  );

  if (!visible) return null;

  return (
    <div
      className="fixed inset-0 z-[100] flex items-start justify-center"
      onClick={() => closeQuickOpen()}
    >
      <div className="fixed inset-0 bg-[#05060a]/60 backdrop-blur-sm" />
      <motion.div
        initial={{ opacity: 0, scale: 0.95, y: -10 }}
        animate={{ opacity: 1, scale: 1, y: 0 }}
        transition={{ duration: 0.15 }}
        className="relative mt-[15vh] w-full max-w-[560px] rounded-xl border border-[#2d3240] bg-[#0b0d13] shadow-2xl overflow-hidden"
        onClick={(e) => e.stopPropagation()}
      >
        {/* Search input */}
        <div className="flex items-center gap-3 px-4 py-3 border-b border-[#2d3240]">
          <IconSearch size={16} stroke={1.5} className="text-[#6f7f9a]/50" />
          <input
            ref={inputRef}
            value={query}
            onChange={(e) => {
              setQuery(e.target.value);
              setSelectedIndex(0);
            }}
            onKeyDown={handleKeyDown}
            placeholder="Search files by name..."
            aria-label="Search files by name"
            className="flex-1 bg-transparent text-[13px] text-[#ece7dc] placeholder-[#6f7f9a]/40 outline-none caret-[#d4a84b]"
          />
          <kbd className="text-[9px] font-mono text-[#6f7f9a]/40 border border-[#2d3240]/60 rounded px-1.5 py-0.5">
            ESC
          </kbd>
        </div>

        {/* Results */}
        <div ref={listRef} className="max-h-[300px] overflow-y-auto py-2">
          {results.items.length === 0 ? (
            <p className="px-4 py-6 text-center text-[12px] text-[#6f7f9a]/40">
              {query.trim() ? "No matching files" : "No recent files"}
            </p>
          ) : (
            <>
              {results.isRecent && (
                <div className="px-4 pt-1 pb-1.5">
                  <span className="text-[9px] uppercase tracking-wider text-[#6f7f9a]/40 font-semibold flex items-center gap-1.5">
                    <IconClock size={10} stroke={1.5} />
                    Recent Files
                  </span>
                </div>
              )}
              {results.items.map((item, idx) => (
                <button
                  key={item.path}
                  data-active={idx === selectedIndex}
                  onClick={() => void selectItem(item)}
                  className={cn(
                    "flex items-center gap-2.5 w-full px-4 py-2 text-left transition-colors",
                    idx === selectedIndex
                      ? "bg-[#131721]/60 text-[#ece7dc] border-l-[3px] border-l-[#d4a84b]"
                      : "text-[#6f7f9a] hover:bg-[#0b0d13] border-l-[3px] border-l-transparent",
                  )}
                >
                  <IconFile size={14} stroke={1.5} className="shrink-0 opacity-50" />
                  <div className="flex flex-col min-w-0">
                    <span className="text-[12px] truncate">{item.name}</span>
                    <span className="text-[10px] text-[#6f7f9a]/40 truncate">
                      {item.displayPath}
                    </span>
                  </div>
                </button>
              ))}
            </>
          )}
        </div>
      </motion.div>
    </div>
  );
}
