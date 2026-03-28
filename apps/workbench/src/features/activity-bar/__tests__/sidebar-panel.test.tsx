import { MemoryRouter } from "react-router-dom";
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { SidebarPanel } from "../components/sidebar-panel";
import { useActivityBarStore } from "../stores/activity-bar-store";
import { usePaneStore } from "@/features/panes/pane-store";
import {
  useProjectStore,
  type FileStatus,
} from "@/features/project/stores/project-store";

const openFileByPath = vi.fn<(...args: [string]) => Promise<void>>();
const createFile = vi.fn<(...args: [string, string, string]) => Promise<string | null>>();
const renameFile = vi.fn<(...args: [string, string]) => Promise<boolean>>();
const deleteFile = vi.fn<(...args: [string]) => Promise<boolean>>();
const setFileStatus = vi.fn<(...args: [string, FileStatus]) => void>();
let lastExplorerPanelProps: Record<string, unknown> | null = null;

vi.mock("@/features/policy/hooks/use-policy-actions", () => ({
  useWorkbenchState: () => ({
    openFileByPath,
  }),
}));

vi.mock("@/components/workbench/explorer/explorer-panel", () => ({
  ExplorerPanel: ({
    rootStates,
    onOpenFile,
    onCreateFile,
    onRenameFile,
    onDeleteFile,
  }: {
    rootStates?: Map<string, unknown>;
    onOpenFile: (
      rootPath: string,
      file: {
        path: string;
        name: string;
        fileType: string;
        isDirectory: boolean;
        depth: number;
      },
    ) => Promise<void>;
    onCreateFile: (parentPath: string, fileName: string) => Promise<void>;
    onRenameFile: (
      rootPath: string,
      file: {
        path: string;
      },
      newName: string,
    ) => Promise<void>;
    onDeleteFile: (
      rootPath: string,
      file: {
        path: string;
      },
    ) => Promise<void>;
  }) => {
    lastExplorerPanelProps = { rootStates };
    return (
      <div>
        <button
          type="button"
          onClick={() =>
            void onOpenFile("/workspace/project", {
              path: "policies/example.yml",
              name: "example.yml",
              fileType: "clawdstrike_policy",
              isDirectory: false,
              depth: 1,
            })
          }
        >
          open file
        </button>
        <button
          type="button"
          onClick={() => void onCreateFile("/workspace/project/policies", "new.yml")}
        >
          create file
        </button>
        <button
          type="button"
          onClick={() =>
            void onRenameFile("/workspace/project", { path: "policies/example.yml" }, "renamed.yml")
          }
        >
          rename file
        </button>
        <button
          type="button"
          onClick={() => void onDeleteFile("/workspace/project", { path: "policies/example.yml" })}
        >
          delete file
        </button>
      </div>
    );
  },
}));

vi.mock("../panels/findings-panel", () => ({
  FindingsPanel: () => <div>Findings Panel</div>,
}));

describe("SidebarPanel explorer wiring", () => {
  beforeEach(() => {
    openFileByPath.mockReset();
    openFileByPath.mockResolvedValue();
    createFile.mockReset();
    createFile.mockResolvedValue("/workspace/project/policies/new.yml");
    renameFile.mockReset();
    renameFile.mockResolvedValue(true);
    deleteFile.mockReset();
    deleteFile.mockResolvedValue(true);
    setFileStatus.mockReset();
    lastExplorerPanelProps = null;

    usePaneStore.getState()._reset();
    useActivityBarStore.setState({
      activeItem: "explorer",
      sidebarVisible: true,
      sidebarWidth: 320,
    });
    useProjectStore.setState((state) => ({
      ...state,
      defaultRootId: null,
      orderedRootIds: ["root-project"],
      rootsById: new Map([
        [
          "root-project",
          {
            rootId: "root-project",
            canonicalPath: "/workspace/project",
            displayPath: "/workspace/project",
            label: "project",
            kind: "default_home",
            provenance: "bootstrap",
            isDefault: true,
            aliases: [],
          },
        ],
      ]),
      rootStatusById: new Map([["root-project", "ready"]]),
      rootErrorById: new Map([["root-project", null]]),
      rootRequestedVersionById: new Map([["root-project", 1]]),
      rootCommittedVersionById: new Map([["root-project", 1]]),
      rootMutationById: new Map([["root-project", null]]),
      projectsById: new Map([
        [
          "root-project",
          {
            rootId: "root-project",
            rootPath: "/workspace/project",
            name: "project",
            files: [],
            expandedDirs: new Set<string>(),
          },
        ],
      ]),
      projectRoots: ["/workspace/project"],
      projects: new Map([
        [
          "/workspace/project",
          {
            rootId: "root-project",
            rootPath: "/workspace/project",
            name: "project",
            files: [],
            expandedDirs: new Set<string>(),
          },
        ],
      ]),
      project: {
        rootId: "root-project",
        rootPath: "/workspace/project",
        name: "project",
        files: [],
        expandedDirs: new Set<string>(),
      },
      actions: {
        ...state.actions,
        createFile,
        renameFile,
        deleteFile,
        setFileStatus,
      },
    }));
  });

  it("loads the selected explorer file before focusing the editor", async () => {
    render(
      <MemoryRouter>
        <SidebarPanel />
      </MemoryRouter>,
    );

    await userEvent.click(screen.getByRole("button", { name: "open file" }));

    await waitFor(() => {
      expect(openFileByPath).toHaveBeenCalledWith("/workspace/project/policies/example.yml");
    });
    expect(usePaneStore.getState().paneCount()).toBe(1);
  });

  it("loads newly created files and resolves rename/delete paths against the project root", async () => {
    render(
      <MemoryRouter>
        <SidebarPanel />
      </MemoryRouter>,
    );

    await userEvent.click(screen.getByRole("button", { name: "create file" }));
    await userEvent.click(screen.getByRole("button", { name: "rename file" }));
    await userEvent.click(screen.getByRole("button", { name: "delete file" }));

    await waitFor(() => {
      expect(openFileByPath).toHaveBeenCalledWith("/workspace/project/policies/new.yml");
    });
    expect(renameFile).toHaveBeenCalledWith(
      "/workspace/project/policies/example.yml",
      "renamed.yml",
    );
    expect(deleteFile).toHaveBeenCalledWith("/workspace/project/policies/example.yml");
  });

  it("normalizes created-file status keys for Windows project paths", async () => {
    createFile.mockResolvedValueOnce("C:\\workspace\\project\\policies\\new.yml");
    useProjectStore.setState((state) => ({
      ...state,
      defaultRootId: "root-project",
      orderedRootIds: ["root-project"],
      rootsById: new Map([
        [
          "root-project",
          {
            rootId: "root-project",
            canonicalPath: "C:\\workspace\\project",
            displayPath: "C:\\workspace\\project",
            label: "project",
            kind: "default_home",
            provenance: "bootstrap",
            isDefault: true,
            aliases: [],
          },
        ],
      ]),
      rootStatusById: new Map([["root-project", "ready"]]),
      rootErrorById: new Map([["root-project", null]]),
      rootRequestedVersionById: new Map([["root-project", 1]]),
      rootCommittedVersionById: new Map([["root-project", 1]]),
      projectsById: new Map([
        [
          "root-project",
          {
            rootId: "root-project",
            rootPath: "C:\\workspace\\project",
            name: "project",
            files: [],
            expandedDirs: new Set<string>(),
          },
        ],
      ]),
      projectRoots: ["C:\\workspace\\project"],
      projects: new Map([
        [
          "C:\\workspace\\project",
          {
            rootId: "root-project",
            rootPath: "C:\\workspace\\project",
            name: "project",
            files: [],
            expandedDirs: new Set<string>(),
          },
        ],
      ]),
      project: {
        rootId: "root-project",
        rootPath: "C:\\workspace\\project",
        name: "project",
        files: [],
        expandedDirs: new Set<string>(),
      },
      actions: {
        ...state.actions,
        createFile,
        renameFile,
        deleteFile,
        setFileStatus,
      },
    }));

    render(
      <MemoryRouter>
        <SidebarPanel />
      </MemoryRouter>,
    );

    await userEvent.click(screen.getByRole("button", { name: "create file" }));

    await waitFor(() => {
      expect(setFileStatus).toHaveBeenCalledWith(
        "C:\\workspace\\project\\policies\\new.yml",
        { modified: true },
      );
    });
    expect(openFileByPath).toHaveBeenCalledWith("C:\\workspace\\project\\policies\\new.yml");
  });

  it("uses the saved absolute path when flagging created files in multi-root workspaces", async () => {
    createFile.mockResolvedValueOnce("/workspace/other/policies/new.yml");
    useProjectStore.setState((state) => ({
      ...state,
      defaultRootId: "root-project",
      orderedRootIds: ["root-project", "root-other"],
      rootsById: new Map([
        [
          "root-project",
          {
            rootId: "root-project",
            canonicalPath: "/workspace/project",
            displayPath: "/workspace/project",
            label: "project",
            kind: "default_home",
            provenance: "bootstrap",
            isDefault: true,
            aliases: [],
          },
        ],
        [
          "root-other",
          {
            rootId: "root-other",
            canonicalPath: "/workspace/other",
            displayPath: "/workspace/other",
            label: "other",
            kind: "mounted_folder",
            provenance: "user_added",
            isDefault: false,
            aliases: [],
          },
        ],
      ]),
      rootStatusById: new Map([
        ["root-project", "ready"],
        ["root-other", "ready"],
      ]),
      rootErrorById: new Map([
        ["root-project", null],
        ["root-other", null],
      ]),
      rootRequestedVersionById: new Map([
        ["root-project", 1],
        ["root-other", 1],
      ]),
      rootCommittedVersionById: new Map([
        ["root-project", 1],
        ["root-other", 1],
      ]),
      projectsById: new Map([
        [
          "root-project",
          {
            rootId: "root-project",
            rootPath: "/workspace/project",
            name: "project",
            files: [],
            expandedDirs: new Set<string>(),
          },
        ],
        [
          "root-other",
          {
            rootId: "root-other",
            rootPath: "/workspace/other",
            name: "other",
            files: [],
            expandedDirs: new Set<string>(),
          },
        ],
      ]),
      projectRoots: ["/workspace/project", "/workspace/other"],
      projects: new Map([
        [
          "/workspace/project",
          {
            rootId: "root-project",
            rootPath: "/workspace/project",
            name: "project",
            files: [],
            expandedDirs: new Set<string>(),
          },
        ],
        [
          "/workspace/other",
          {
            rootId: "root-other",
            rootPath: "/workspace/other",
            name: "other",
            files: [],
            expandedDirs: new Set<string>(),
          },
        ],
      ]),
      actions: {
        ...state.actions,
        createFile,
        renameFile,
        deleteFile,
        setFileStatus,
      },
    }));

    render(
      <MemoryRouter>
        <SidebarPanel />
      </MemoryRouter>,
    );

    await userEvent.click(screen.getByRole("button", { name: "create file" }));

    await waitFor(() => {
      expect(setFileStatus).toHaveBeenCalledWith("/workspace/other/policies/new.yml", {
        modified: true,
      });
    });
  });

  it("renders the findings panel for the hunt activity-bar entry", () => {
    useActivityBarStore.setState({
      activeItem: "hunt",
      sidebarVisible: true,
      sidebarWidth: 320,
    });

    render(
      <MemoryRouter>
        <SidebarPanel />
      </MemoryRouter>,
    );

    expect(screen.getByText("Findings Panel")).toBeTruthy();
  });

  it("shows the bootstrap loading shell only before workspace roots are hydrated", () => {
    useProjectStore.setState((state) => ({
      ...state,
      loading: true,
      project: null,
      defaultRootId: null,
      orderedRootIds: [],
      rootsById: new Map(),
      rootStatusById: new Map(),
      rootErrorById: new Map(),
      rootRequestedVersionById: new Map(),
      rootCommittedVersionById: new Map(),
      projectsById: new Map(),
      projectRoots: [],
      projects: new Map(),
    }));

    render(
      <MemoryRouter>
        <SidebarPanel />
      </MemoryRouter>,
    );

    expect(screen.getByText("Loading workspace...")).toBeTruthy();
  });

  it("renders the explorer once root placeholders exist, even if they are still loading", () => {
    useProjectStore.setState((state) => ({
      ...state,
      loading: true,
      defaultRootId: "root-project",
      orderedRootIds: ["root-project"],
      rootsById: new Map([
        [
          "root-project",
          {
            rootId: "root-project",
            canonicalPath: "/workspace/project",
            displayPath: "/workspace/project",
            label: "project",
            kind: "default_home",
            provenance: "bootstrap",
            isDefault: true,
            aliases: [],
          },
        ],
      ]),
      rootStatusById: new Map([["root-project", "loading"]]),
      rootErrorById: new Map([["root-project", null]]),
      rootRequestedVersionById: new Map([["root-project", 1]]),
      rootCommittedVersionById: new Map([["root-project", 0]]),
      projectsById: new Map([
        [
          "root-project",
          {
            rootId: "root-project",
            rootPath: "/workspace/project",
            name: "project",
            files: [],
            expandedDirs: new Set<string>(),
          },
        ],
      ]),
      projectRoots: ["/workspace/project"],
      projects: new Map([
        [
          "/workspace/project",
          {
            rootId: "root-project",
            rootPath: "/workspace/project",
            name: "project",
            files: [],
            expandedDirs: new Set<string>(),
          },
        ],
      ]),
    }));

    render(
      <MemoryRouter>
        <SidebarPanel />
      </MemoryRouter>,
    );

    expect(screen.queryByText("Loading workspace...")).toBeNull();
    expect(screen.getByRole("button", { name: "open file" })).toBeTruthy();
  });

  it("passes root provenance metadata through to the explorer", () => {
    useProjectStore.setState((state) => ({
      ...state,
      defaultRootId: null,
      orderedRootIds: ["root-project"],
      rootsById: new Map([
        [
          "root-project",
          {
            rootId: "root-project",
            canonicalPath: "/workspace/project",
            displayPath: "/workspace/project",
            label: ".clawdstrike",
            kind: "mounted_folder",
            provenance: "local_storage_migration",
            isDefault: false,
            aliases: [],
          },
        ],
      ]),
    }));

    render(
      <MemoryRouter>
        <SidebarPanel />
      </MemoryRouter>,
    );

    const rootStates = lastExplorerPanelProps?.rootStates as Map<string, {
      label?: string;
      kind?: string;
      provenance?: string;
      isDefault?: boolean;
    }> | null;
    const state = rootStates?.get("/workspace/project");

    expect(state).toMatchObject({
      label: ".clawdstrike",
      kind: "mounted_folder",
      provenance: "local_storage_migration",
      isDefault: false,
    });
  });

  it("passes root mutation metadata through to the explorer", () => {
    useProjectStore.setState((state) => ({
      ...state,
      rootMutationById: new Map([
        [
          "root-project",
          {
            kind: "delete",
            status: "error",
            rootId: "root-project",
            rootPath: "/workspace/project",
            targetRelativePath: "policies/example.yml",
            targetLabel: "example.yml",
            message: "disk offline",
            updatedAt: 1,
          },
        ],
      ]),
    }));

    render(
      <MemoryRouter>
        <SidebarPanel />
      </MemoryRouter>,
    );

    const rootStates = lastExplorerPanelProps?.rootStates as Map<string, {
      mutation?: { kind?: string; status?: string; message?: string } | null;
    }> | null;
    const state = rootStates?.get("/workspace/project");

    expect(state?.mutation).toMatchObject({
      kind: "delete",
      status: "error",
      message: "disk offline",
    });
  });
});
