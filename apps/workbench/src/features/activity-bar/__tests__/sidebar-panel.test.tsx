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

vi.mock("@/features/policy/hooks/use-policy-actions", () => ({
  useWorkbenchState: () => ({
    openFileByPath,
  }),
}));

vi.mock("@/components/workbench/explorer/explorer-panel", () => ({
  ExplorerPanel: ({
    onOpenFile,
    onCreateFile,
    onRenameFile,
    onDeleteFile,
  }: {
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
  }) => (
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
  ),
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

    usePaneStore.getState()._reset();
    useActivityBarStore.setState({
      activeItem: "explorer",
      sidebarVisible: true,
      sidebarWidth: 320,
    });
    useProjectStore.setState((state) => ({
      ...state,
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
      projectRoots: ["C:\\workspace\\project"],
      projects: new Map([
        [
          "C:\\workspace\\project",
          {
            rootPath: "C:\\workspace\\project",
            name: "project",
            files: [],
            expandedDirs: new Set<string>(),
          },
        ],
      ]),
      project: {
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
      projectRoots: ["/workspace/project", "/workspace/other"],
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
        [
          "/workspace/other",
          {
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
});
