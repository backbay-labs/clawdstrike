import { create } from "zustand";
import { createSelectors } from "@/lib/create-selectors";
import {
  cancelSearchInProjectNative,
  searchInProjectNative,
  type TauriSearchMatch,
} from "@/lib/tauri-commands";

// ---- Types ----

export interface SearchMatch {
  /** Absolute workspace root that produced this match. */
  rootPath: string;
  /** Relative path within the project root. */
  filePath: string;
  /** 1-indexed line number. */
  lineNumber: number;
  /** Preview line text. */
  lineContent: string;
  /** Char offset of match start within `lineContent`. */
  matchStart: number;
  /** Char offset of match end within `lineContent`. */
  matchEnd: number;
  /** Char offset of match start within the full source line. */
  sourceMatchStart: number;
  /** Char offset of match end within the full source line. */
  sourceMatchEnd: number;
}

export interface SearchOptions {
  caseSensitive: boolean;
  wholeWord: boolean;
  useRegex: boolean;
}

export interface SearchResultGroup {
  rootPath: string;
  filePath: string;
  matches: SearchMatch[];
}

interface SearchState {
  query: string;
  options: SearchOptions;
  results: SearchMatch[];
  resultGroups: SearchResultGroup[];
  fileCount: number;
  totalMatches: number;
  truncated: boolean;
  loading: boolean;
  error: string | null;
  actions: {
    setQuery: (query: string) => void;
    setOption: <K extends keyof SearchOptions>(
      key: K,
      value: SearchOptions[K],
      rootPaths: string[],
    ) => void;
    performSearch: (rootPaths: string[]) => Promise<void>;
    clearResults: () => void;
  };
}

function mapTauriMatch(rootPath: string, m: TauriSearchMatch): SearchMatch {
  return {
    rootPath,
    filePath: m.file_path,
    lineNumber: m.line_number,
    lineContent: m.line_content,
    matchStart: m.match_start,
    matchEnd: m.match_end,
    sourceMatchStart: m.source_match_start ?? m.match_start,
    sourceMatchEnd: m.source_match_end ?? m.match_end,
  };
}

function groupByFile(matches: SearchMatch[]): SearchResultGroup[] {
  const map = new Map<string, SearchResultGroup>();
  for (const m of matches) {
    const key = `${m.rootPath}::${m.filePath}`;
    const existing = map.get(key);
    if (existing) {
      existing.matches.push(m);
    } else {
      map.set(key, {
        rootPath: m.rootPath,
        filePath: m.filePath,
        matches: [m],
      });
    }
  }
  return Array.from(map.values());
}

const DEFAULT_OPTIONS: SearchOptions = {
  caseSensitive: false,
  wholeWord: false,
  useRegex: false,
};

let activeSearchController: AbortController | null = null;
let activeSearchRequestId: string | null = null;
let latestSearchRequestToken = 0;

function nextSearchRequestToken(): number {
  latestSearchRequestToken += 1;
  return latestSearchRequestToken;
}

function finishSearch(searchRequestId: string): void {
  if (activeSearchRequestId !== searchRequestId) {
    return;
  }

  activeSearchController = null;
  activeSearchRequestId = null;
}

function cancelActiveSearch(): void {
  if (activeSearchController) {
    activeSearchController.abort();
    activeSearchController = null;
  }

  const searchRequestId = activeSearchRequestId;
  activeSearchRequestId = null;

  if (searchRequestId) {
    void cancelSearchInProjectNative(searchRequestId);
  }
}

const useSearchStoreBase = create<SearchState>((set, get) => ({
  query: "",
  options: { ...DEFAULT_OPTIONS },
  results: [],
  resultGroups: [],
  fileCount: 0,
  totalMatches: 0,
  truncated: false,
  loading: false,
  error: null,
  actions: {
    setQuery: (query: string) => {
      cancelActiveSearch();
      nextSearchRequestToken();
      set({ query });
    },

    setOption: <K extends keyof SearchOptions>(
      key: K,
      value: SearchOptions[K],
      rootPaths: string[],
    ) => {
      let shouldSearch = false;

      cancelActiveSearch();
      nextSearchRequestToken();
      set((state) => {
        if (state.options[key] === value) {
          return state;
        }

        shouldSearch = true;
        return {
          options: { ...state.options, [key]: value },
        };
      });

      if (shouldSearch) {
        void get().actions.performSearch(rootPaths);
      }
    },

    performSearch: async (rootPaths: string[]) => {
      const requestToken = nextSearchRequestToken();
      const { query, options } = get();

      cancelActiveSearch();
      const controller = new AbortController();
      activeSearchController = controller;
      const searchRequestId = crypto.randomUUID();
      activeSearchRequestId = searchRequestId;
      const queryAtDispatch = query;
      const optionsAtDispatch = { ...options };

      set({ loading: true, error: null });

      if (!query.trim() || rootPaths.length === 0) {
        if (requestToken !== latestSearchRequestToken) {
          return;
        }
        finishSearch(searchRequestId);
        set({
          results: [],
          resultGroups: [],
          fileCount: 0,
          totalMatches: 0,
          truncated: false,
          loading: false,
        });
        return;
      }

      try {
        const results = await Promise.all(
          rootPaths.map((rootPath) =>
            searchInProjectNative(
              rootPath,
              query,
              options.caseSensitive,
              options.wholeWord,
              options.useRegex,
              searchRequestId,
            ).then((result) => ({ rootPath, result })),
          ),
        );

        if (controller.signal.aborted || requestToken !== latestSearchRequestToken) {
          return;
        }

        const latestState = get();
        if (
          queryAtDispatch !== latestState.query ||
          optionsAtDispatch.caseSensitive !== latestState.options.caseSensitive ||
          optionsAtDispatch.wholeWord !== latestState.options.wholeWord ||
          optionsAtDispatch.useRegex !== latestState.options.useRegex
        ) {
          return;
        }

        const resolvedResults = results.filter(
          ({ result }) => result !== null,
        ) as Array<{ rootPath: string; result: NonNullable<(typeof results)[number]["result"]> }>;

        if (resolvedResults.length > 0) {
          const matches = resolvedResults.flatMap(({ rootPath, result }) =>
            result.matches.map((match) => mapTauriMatch(rootPath, match)),
          );
          const resultGroups = groupByFile(matches);
          set({
            results: matches,
            resultGroups,
            fileCount: resolvedResults.reduce(
              (count, { result }) => count + result.file_count,
              0,
            ),
            totalMatches: resolvedResults.reduce(
              (count, { result }) => count + result.total_matches,
              0,
            ),
            truncated: resolvedResults.some(({ result }) => result.truncated),
            loading: false,
          });
        } else {
          set({
            results: [],
            resultGroups: [],
            fileCount: 0,
            totalMatches: 0,
            truncated: false,
            error: "Search is not available outside Tauri desktop",
            loading: false,
          });
        }

        finishSearch(searchRequestId);
      } catch (err) {
        if (controller.signal.aborted || requestToken !== latestSearchRequestToken) {
          return;
        }

        set({
          results: [],
          resultGroups: [],
          fileCount: 0,
          totalMatches: 0,
          truncated: false,
          error: err instanceof Error ? err.message : "Search failed",
          loading: false,
        });
        finishSearch(searchRequestId);
      }
    },

    clearResults: () => {
      cancelActiveSearch();
      nextSearchRequestToken();
      set({
        results: [],
        resultGroups: [],
        fileCount: 0,
        totalMatches: 0,
        truncated: false,
        error: null,
      });
    },
  },
}));

export const useSearchStore = createSelectors(useSearchStoreBase);
