import { MemoryRouter } from "react-router-dom";
import type { ReactNode } from "react";
import { act, render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { SearchPanelConnected } from "../components/search-panel";
import { useSearchStore } from "../stores/search-store";
import { useProjectStore } from "@/features/project/stores/project-store";
import { usePaneStore } from "@/features/panes/pane-store";
import { emptyNativeValidation, usePolicyEditStore } from "@/features/policy/stores/policy-edit-store";
import { usePolicyTabsStore } from "@/features/policy/stores/policy-tabs-store";
import { DEFAULT_POLICY } from "@/features/policy/stores/policy-store";
import { consumePendingEditorReveal } from "@/lib/workbench/editor-reveal";

type OpenFileByPathOptions = {
  shouldApply?: () => boolean;
};

const openFileByPath = vi.fn<
  (filePath: string, options?: OpenFileByPathOptions) => Promise<void>
>();
const { searchInProjectNative } = vi.hoisted(() => ({
  searchInProjectNative: vi.fn(),
}));

vi.mock("@/lib/tauri-commands", () => ({
  searchInProjectNative,
}));

vi.mock("@/components/ui/scroll-area", () => ({
  ScrollArea: ({ children }: { children: ReactNode }) => <div>{children}</div>,
}));

vi.mock("@/features/policy/hooks/use-policy-actions", () => ({
  useWorkbenchState: () => ({
    openFileByPath,
  }),
}));

function makeDocumentWithLine(lineNumber: number, lineContent: string): string {
  return Array.from({ length: lineNumber }, (_, index) =>
    index === lineNumber - 1 ? lineContent : `line ${index + 1}`,
  ).join("\n");
}

function seedOpenDocument(filePath: string, lineNumber: number, lineContent: string): void {
  usePolicyTabsStore.setState({
    tabs: [
      {
        id: "tab-search-result",
        documentId: "doc-search-result",
        name: "example.yml",
        filePath,
        dirty: false,
        fileType: "clawdstrike_policy",
      },
    ],
    activeTabId: "tab-search-result",
  });
  usePolicyEditStore.setState({
    editStates: new Map([
      [
        "tab-search-result",
        {
          policy: DEFAULT_POLICY,
          yaml: makeDocumentWithLine(lineNumber, lineContent),
          validation: { valid: true, errors: [], warnings: [] },
          nativeValidation: emptyNativeValidation(),
          undoStack: { past: [], future: [] },
          cleanSnapshot: null,
        },
      ],
    ]),
  });
}

const syntheticProjectFiles = [
  {
    path: "policies",
    name: "policies",
    fileType: "clawdstrike_policy" as const,
    isDirectory: true,
    depth: 0,
    children: [
      {
        path: "policies/example.yml",
        name: "example.yml",
        fileType: "clawdstrike_policy" as const,
        isDirectory: false,
        depth: 1,
      },
    ],
  },
  {
    path: "rules",
    name: "rules",
    fileType: "clawdstrike_policy" as const,
    isDirectory: true,
    depth: 0,
    children: [
      {
        path: "rules/other.yml",
        name: "other.yml",
        fileType: "clawdstrike_policy" as const,
        isDirectory: false,
        depth: 1,
      },
    ],
  },
];

describe("SearchPanelConnected", () => {
  beforeEach(() => {
    openFileByPath.mockReset();
    openFileByPath.mockResolvedValue();
    searchInProjectNative.mockReset();
    searchInProjectNative.mockResolvedValue({
      matches: [],
      file_count: 0,
      total_matches: 0,
      truncated: false,
    });
    seedOpenDocument("/workspace/project/policies/example.yml", 12, "  name: needle");
    usePaneStore.getState()._reset();
    useProjectStore.setState({
      projectRoots: ["/workspace/project"],
      projects: new Map([
        [
          "/workspace/project",
          {
            rootPath: "/workspace/project",
            name: "project",
            files: [],
            expandedDirs: new Set<string>(),
          },
        ],
      ]),
      project: {
        rootPath: "/workspace/project",
        name: "project",
        files: [],
        expandedDirs: new Set<string>(),
      },
    });
    useSearchStore.setState({
      query: "needle",
      options: {
        caseSensitive: false,
        wholeWord: false,
        useRegex: false,
      },
      resultGroups: [
        {
          rootPath: "/workspace/project",
          filePath: "policies/example.yml",
          matches: [
            {
              rootPath: "/workspace/project",
              filePath: "policies/example.yml",
              lineNumber: 12,
              lineContent: "  name: needle",
              matchStart: 8,
              matchEnd: 14,
              sourceMatchStart: 8,
              sourceMatchEnd: 14,
            },
          ],
        },
      ],
      fileCount: 1,
      totalMatches: 1,
      truncated: false,
      loading: false,
      error: null,
    });
  });

  it("opens the matched file and queues an editor reveal", async () => {
    useProjectStore.setState({
      project: {
        rootPath: "workspace",
        name: "Workspace",
        files: [],
        expandedDirs: new Set<string>(),
      },
    });

    render(
      <MemoryRouter>
        <SearchPanelConnected />
      </MemoryRouter>,
    );

    await userEvent.click(screen.getByRole("button", { name: /12/i }));

    await waitFor(() => {
      expect(openFileByPath).toHaveBeenCalledWith(
        "/workspace/project/policies/example.yml",
        expect.objectContaining({
          shouldApply: expect.any(Function),
        }),
      );
    });

    expect(usePaneStore.getState().paneCount()).toBe(1);
    expect(consumePendingEditorReveal("/workspace/project/policies/example.yml")).toEqual({
      filePath: "/workspace/project/policies/example.yml",
      lineNumber: 12,
      startColumn: 9,
      endColumn: 15,
    });
  });

  it("preserves the real match columns when the preview line is truncated", async () => {
    useSearchStore.setState({
      resultGroups: [
        {
          rootPath: "/workspace/project",
          filePath: "policies/example.yml",
          matches: [
            {
              rootPath: "/workspace/project",
              filePath: "policies/example.yml",
              lineNumber: 27,
              lineContent: "x".repeat(500),
              matchStart: 500,
              matchEnd: 500,
              sourceMatchStart: 612,
              sourceMatchEnd: 618,
            },
          ],
        },
      ],
      fileCount: 1,
      totalMatches: 1,
      truncated: false,
    });
    seedOpenDocument("/workspace/project/policies/example.yml", 27, "x".repeat(700));

    render(
      <MemoryRouter>
        <SearchPanelConnected />
      </MemoryRouter>,
    );

    await userEvent.click(screen.getByRole("button", { name: /27/i }));

    expect(consumePendingEditorReveal("/workspace/project/policies/example.yml")).toEqual({
      filePath: "/workspace/project/policies/example.yml",
      lineNumber: 27,
      startColumn: 613,
      endColumn: 619,
    });
  });

  it("highlights preview matches after astral unicode characters", () => {
    useSearchStore.setState({
      resultGroups: [
        {
          rootPath: "/workspace/project",
          filePath: "policies/example.yml",
          matches: [
            {
              rootPath: "/workspace/project",
              filePath: "policies/example.yml",
              lineNumber: 7,
              lineContent: "😀😀needle tail",
              matchStart: 2,
              matchEnd: 8,
              sourceMatchStart: 2,
              sourceMatchEnd: 8,
            },
          ],
        },
      ],
      fileCount: 1,
      totalMatches: 1,
      truncated: false,
    });

    render(
      <MemoryRouter>
        <SearchPanelConnected />
      </MemoryRouter>,
    );

    expect(screen.getByText("needle", { selector: "mark" })).toBeTruthy();
  });

  it("converts source match columns to editor utf-16 columns", async () => {
    useSearchStore.setState({
      resultGroups: [
        {
          rootPath: "/workspace/project",
          filePath: "policies/example.yml",
          matches: [
            {
              rootPath: "/workspace/project",
              filePath: "policies/example.yml",
              lineNumber: 12,
              lineContent: "😀😀needle tail",
              matchStart: 2,
              matchEnd: 8,
              sourceMatchStart: 2,
              sourceMatchEnd: 8,
            },
          ],
        },
      ],
      fileCount: 1,
      totalMatches: 1,
      truncated: false,
    });
    seedOpenDocument("/workspace/project/policies/example.yml", 12, "😀😀needle tail");

    render(
      <MemoryRouter>
        <SearchPanelConnected />
      </MemoryRouter>,
    );

    await userEvent.click(screen.getByRole("button", { name: /12/i }));

    expect(consumePendingEditorReveal("/workspace/project/policies/example.yml")).toEqual({
      filePath: "/workspace/project/policies/example.yml",
      lineNumber: 12,
      startColumn: 5,
      endColumn: 11,
    });
  });

  it("derives a real search root when the workspace uses a synthetic project path", async () => {
    useProjectStore.setState({
      project: {
        rootPath: "workspace",
        name: "Workspace",
        files: syntheticProjectFiles,
        expandedDirs: new Set<string>(),
      },
    });

    render(
      <MemoryRouter>
        <SearchPanelConnected />
      </MemoryRouter>,
    );

    const input = screen.getByPlaceholderText("Search files...");
    await userEvent.click(input);
    await userEvent.keyboard("{Enter}");

    await waitFor(() => {
      expect(searchInProjectNative).toHaveBeenCalledWith(
        "/workspace/project",
        "needle",
        false,
        false,
        false,
        expect.any(String),
      );
    });
  });

  it("keeps the workspace root when only one absolute tab is open", async () => {
    useProjectStore.setState({
      project: {
        rootPath: "workspace",
        name: "Workspace",
        files: syntheticProjectFiles,
        expandedDirs: new Set<string>(),
      },
    });

    render(
      <MemoryRouter>
        <SearchPanelConnected />
      </MemoryRouter>,
    );

    const input = screen.getByPlaceholderText("Search files...");
    await userEvent.click(input);
    await userEvent.keyboard("{Enter}");

    await waitFor(() => {
      expect(searchInProjectNative).toHaveBeenCalledWith(
        "/workspace/project",
        "needle",
        false,
        false,
        false,
        expect.any(String),
      );
    });
  });

  it("reruns the active search when options change", async () => {
    render(
      <MemoryRouter>
        <SearchPanelConnected />
      </MemoryRouter>,
    );

    await userEvent.click(screen.getByRole("button", { name: "Aa" }));

    await waitFor(() => {
      expect(searchInProjectNative).toHaveBeenCalledWith(
        "/workspace/project",
        "needle",
        true,
        false,
        false,
        expect.any(String),
      );
    });
  });

  it("ignores stale search clicks that resolve after a newer selection", async () => {
    let resolveFirst: (() => void) | null = null;
    let resolveSecond: (() => void) | null = null;

    openFileByPath.mockImplementationOnce(
      async (_filePath, options) =>
        await new Promise<void>((resolve) => {
          resolveFirst = () => {
            if (options?.shouldApply?.()) {
              resolve();
              return;
            }

            resolve();
          };
        }),
    );
    openFileByPath.mockImplementationOnce(
      async (_filePath, options) =>
        await new Promise<void>((resolve) => {
          resolveSecond = () => {
            if (options?.shouldApply?.()) {
              resolve();
              return;
            }

            resolve();
          };
        }),
    );

    useSearchStore.setState({
      resultGroups: [
        {
          rootPath: "/workspace/project",
          filePath: "policies/example.yml",
          matches: [
            {
              rootPath: "/workspace/project",
              filePath: "policies/example.yml",
              lineNumber: 12,
              lineContent: "  name: first",
              matchStart: 8,
              matchEnd: 13,
              sourceMatchStart: 8,
              sourceMatchEnd: 13,
            },
          ],
        },
        {
          rootPath: "/workspace/project",
          filePath: "rules/other.yml",
          matches: [
            {
              rootPath: "/workspace/project",
              filePath: "rules/other.yml",
              lineNumber: 3,
              lineContent: "  name: second",
              matchStart: 8,
              matchEnd: 14,
              sourceMatchStart: 8,
              sourceMatchEnd: 14,
            },
          ],
        },
      ],
      fileCount: 2,
      totalMatches: 2,
      truncated: false,
    });
    seedOpenDocument("/workspace/project/rules/other.yml", 3, "  name: second");

    render(
      <MemoryRouter>
        <SearchPanelConnected />
      </MemoryRouter>,
    );

    const user = userEvent.setup();
    await user.click(screen.getByRole("button", { name: /12/i }));
    await user.click(screen.getByRole("button", { name: /3/i }));

    await act(async () => {
      resolveSecond?.();
    });

    expect(consumePendingEditorReveal("/workspace/project/rules/other.yml")).toEqual({
      filePath: "/workspace/project/rules/other.yml",
      lineNumber: 3,
      startColumn: 9,
      endColumn: 15,
    });

    await act(async () => {
      resolveFirst?.();
    });

    expect(consumePendingEditorReveal("/workspace/project/policies/example.yml")).toBeNull();
    expect(usePaneStore.getState().paneCount()).toBe(1);
  });
});
