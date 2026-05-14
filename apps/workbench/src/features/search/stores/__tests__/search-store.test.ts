import { beforeEach, describe, expect, it, vi } from "vitest";
import { useSearchStore } from "../search-store";

const { cancelSearchInProjectNativeMock, searchInProjectNativeMock } = vi.hoisted(() => ({
  cancelSearchInProjectNativeMock: vi.fn(),
  searchInProjectNativeMock: vi.fn(),
}));

vi.mock("@/lib/tauri-commands", () => ({
  cancelSearchInProjectNative: cancelSearchInProjectNativeMock,
  searchInProjectNative: searchInProjectNativeMock,
}));

function createDeferred<T>() {
  let resolve!: (value: T) => void;
  let reject!: (reason?: unknown) => void;
  const promise = new Promise<T>((res, rej) => {
    resolve = res;
    reject = rej;
  });
  return { promise, resolve, reject };
}

describe("useSearchStore", () => {
  beforeEach(() => {
    useSearchStore.getState().actions.clearResults();
    cancelSearchInProjectNativeMock.mockReset();
    searchInProjectNativeMock.mockReset();

    useSearchStore.setState({
      query: "needle",
      options: {
        caseSensitive: false,
        wholeWord: false,
        useRegex: false,
      },
      results: [],
      resultGroups: [],
      fileCount: 0,
      totalMatches: 0,
      truncated: false,
      loading: false,
      error: null,
      actions: useSearchStore.getState().actions,
    });
  });

  it("aggregates matches across workspace roots and preserves root context", async () => {
    searchInProjectNativeMock
      .mockResolvedValueOnce({
        matches: [
          {
            file_path: "shared/default.yaml",
            line_number: 3,
            line_content: "alpha needle",
            match_start: 6,
            match_end: 12,
          },
        ],
        file_count: 1,
        total_matches: 1,
        truncated: false,
      })
      .mockResolvedValueOnce({
        matches: [
          {
            file_path: "shared/default.yaml",
            line_number: 7,
            line_content: "bravo needle",
            match_start: 6,
            match_end: 12,
          },
        ],
        file_count: 1,
        total_matches: 1,
        truncated: true,
      });

    await useSearchStore
      .getState()
      .actions.performSearch(["/workspace/alpha", "/workspace/bravo"]);

    expect(searchInProjectNativeMock).toHaveBeenNthCalledWith(
      1,
      "/workspace/alpha",
      "needle",
      false,
      false,
      false,
      expect.any(String),
    );
    expect(searchInProjectNativeMock).toHaveBeenNthCalledWith(
      2,
      "/workspace/bravo",
      "needle",
      false,
      false,
      false,
      expect.any(String),
    );

    const firstSearchId = searchInProjectNativeMock.mock.calls[0]?.[5];
    expect(firstSearchId).toBe(searchInProjectNativeMock.mock.calls[1]?.[5]);

    const state = useSearchStore.getState();
    expect(state.results.map((match) => `${match.rootPath}:${match.filePath}`)).toEqual([
      "/workspace/alpha:shared/default.yaml",
      "/workspace/bravo:shared/default.yaml",
    ]);
    expect(
      state.resultGroups.map((group) => `${group.rootPath}:${group.filePath}`),
    ).toEqual([
      "/workspace/alpha:shared/default.yaml",
      "/workspace/bravo:shared/default.yaml",
    ]);
    expect(state.fileCount).toBe(2);
    expect(state.totalMatches).toBe(2);
    expect(state.truncated).toBe(true);
    expect(state.error).toBeNull();
  });

  it("ignores stale search completions after the query changes", async () => {
    const firstSearch = createDeferred<{
      matches: Array<{
        file_path: string;
        line_number: number;
        line_content: string;
        match_start: number;
        match_end: number;
      }>;
      file_count: number;
      total_matches: number;
      truncated: boolean;
    }>();
    const secondSearch = createDeferred<{
      matches: Array<{
        file_path: string;
        line_number: number;
        line_content: string;
        match_start: number;
        match_end: number;
      }>;
      file_count: number;
      total_matches: number;
      truncated: boolean;
    }>();

    searchInProjectNativeMock
      .mockReturnValueOnce(firstSearch.promise)
      .mockReturnValueOnce(secondSearch.promise);

    const actions = useSearchStore.getState().actions;

    actions.setQuery("first");
    const firstRun = actions.performSearch(["/workspace/project"]);
    const firstSearchId = searchInProjectNativeMock.mock.calls[0]?.[5];

    actions.setQuery("second");
    expect(cancelSearchInProjectNativeMock).toHaveBeenCalledWith(firstSearchId);

    const secondRun = actions.performSearch(["/workspace/project"]);

    secondSearch.resolve({
      matches: [
        {
          file_path: "second.yml",
          line_number: 3,
          line_content: "second",
          match_start: 0,
          match_end: 6,
        },
      ],
      file_count: 1,
      total_matches: 1,
      truncated: false,
    });
    await secondRun;

    expect(useSearchStore.getState().results).toEqual([
      {
        rootPath: "/workspace/project",
        filePath: "second.yml",
        lineNumber: 3,
        lineContent: "second",
        matchStart: 0,
        matchEnd: 6,
        sourceMatchStart: 0,
        sourceMatchEnd: 6,
      },
    ]);

    firstSearch.resolve({
      matches: [
        {
          file_path: "first.yml",
          line_number: 1,
          line_content: "first",
          match_start: 0,
          match_end: 5,
        },
      ],
      file_count: 1,
      total_matches: 1,
      truncated: false,
    });
    await firstRun;

    expect(useSearchStore.getState().query).toBe("second");
    expect(useSearchStore.getState().results).toEqual([
      {
        rootPath: "/workspace/project",
        filePath: "second.yml",
        lineNumber: 3,
        lineContent: "second",
        matchStart: 0,
        matchEnd: 6,
        sourceMatchStart: 0,
        sourceMatchEnd: 6,
      },
    ]);
  });
});
