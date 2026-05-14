import { beforeEach, describe, expect, it, vi } from "vitest";
import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { SearchPanelConnected } from "../search-panel";
import { usePaneStore } from "@/features/panes/pane-store";
import { useProjectStore } from "@/features/project/stores/project-store";
import { useSearchStore } from "@/features/search/stores/search-store";

const openFileByPath = vi.fn<(...args: [string]) => Promise<void>>();

vi.mock("@/features/policy/hooks/use-policy-actions", () => ({
  useWorkbenchState: () => ({
    openFileByPath,
  }),
}));

describe("SearchPanelConnected", () => {
  beforeEach(() => {
    const projectActions = useProjectStore.getState().actions;
    const searchActions = useSearchStore.getState().actions;

    openFileByPath.mockReset();
    openFileByPath.mockResolvedValue();
    usePaneStore.getState()._reset();
    useProjectStore.setState({
      project: null,
      loading: false,
      error: null,
      filter: "",
      formatFilter: null,
      fileStatuses: new Map(),
      projectRoots: ["/workspace/alpha", "/workspace/bravo"],
      projects: new Map(),
      actions: projectActions,
    });
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
      actions: searchActions,
    });
  });

  it("searches every mounted workspace root", () => {
    const performSearch = vi.fn();

    useSearchStore.setState((state) => ({
      actions: {
        ...state.actions,
        performSearch,
      },
    }));

    render(<SearchPanelConnected />);

    fireEvent.keyDown(screen.getByPlaceholderText("Search files..."), {
      key: "Enter",
    });

    expect(performSearch).toHaveBeenCalledWith([
      "/workspace/alpha",
      "/workspace/bravo",
    ]);
  });

  it("opens search results against the owning workspace root", async () => {
    const openFile = vi.fn();

    usePaneStore.setState({ openFile });
    useSearchStore.setState({
      resultGroups: [
        {
          rootPath: "/workspace/bravo",
          filePath: "shared/default.yaml",
          matches: [
            {
              rootPath: "/workspace/bravo",
              filePath: "shared/default.yaml",
              lineNumber: 7,
              lineContent: "needle in bravo",
              matchStart: 0,
              matchEnd: 6,
              sourceMatchStart: 0,
              sourceMatchEnd: 6,
            },
          ],
        },
      ],
      results: [
        {
          rootPath: "/workspace/bravo",
          filePath: "shared/default.yaml",
          lineNumber: 7,
          lineContent: "needle in bravo",
          matchStart: 0,
          matchEnd: 6,
          sourceMatchStart: 0,
          sourceMatchEnd: 6,
        },
      ],
      fileCount: 1,
      totalMatches: 1,
    });

    render(<SearchPanelConnected />);

    fireEvent.click(screen.getByText("shared/default.yaml"));

    await waitFor(() => {
      expect(openFileByPath).toHaveBeenCalledWith(
        "/workspace/bravo/shared/default.yaml",
        expect.objectContaining({
          shouldApply: expect.any(Function),
        }),
      );
      expect(openFile).toHaveBeenCalledWith(
        "/workspace/bravo/shared/default.yaml",
        "default.yaml",
      );
    });
  });
});
