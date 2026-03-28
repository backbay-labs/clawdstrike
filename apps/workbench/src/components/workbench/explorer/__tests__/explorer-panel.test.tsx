import React from "react";
import { fireEvent, render, screen } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";
import { ExplorerPanel } from "../explorer-panel";
import type { DetectionProject, ProjectFile } from "@/features/project/stores/project-store";

function makeProject(rootPath: string, ...fileNames: string[]): DetectionProject {
  const resolvedFileNames = fileNames.length > 0 ? fileNames : ["default.yaml"];
  const files: ProjectFile[] = resolvedFileNames.map((fileName) => ({
    path: `policies/${fileName}`,
    name: fileName,
    fileType: "clawdstrike_policy",
    isDirectory: false,
    depth: 1,
  }));

  return {
    rootId: rootPath,
    rootPath,
    name: rootPath.split("/").pop() ?? rootPath,
    expandedDirs: new Set(["policies"]),
    files: [
      {
        path: "policies",
        name: "policies",
        fileType: "clawdstrike_policy",
        isDirectory: true,
        depth: 0,
        children: files,
      },
    ],
  };
}

function makeCollapsedProject(rootPath: string, ...fileNames: string[]): DetectionProject {
  return {
    ...makeProject(rootPath, ...fileNames),
    expandedDirs: new Set<string>(),
  };
}

function makeDefaultWorkspaceProject(): DetectionProject {
  return {
    rootId: "root-default",
    rootPath: "/Users/test/.clawdstrike",
    name: ".clawdstrike",
    expandedDirs: new Set(["workspace/policies"]),
    files: [
      {
        path: "workspace",
        name: "workspace",
        fileType: "clawdstrike_policy",
        isDirectory: true,
        depth: 0,
        children: [
          {
            path: "workspace/policies",
            name: "policies",
            fileType: "clawdstrike_policy",
            isDirectory: true,
            depth: 1,
            children: [
              {
                path: "workspace/policies/default.yaml",
                name: "default.yaml",
                fileType: "clawdstrike_policy",
                isDirectory: false,
                depth: 2,
              },
            ],
          },
        ],
      },
      {
        path: "workspace-root-registry.v1.json",
        name: "workspace-root-registry.v1.json",
        fileType: "clawdstrike_policy",
        isDirectory: false,
        depth: 0,
      },
    ],
  };
}

function makeLargeProject(rootPath: string, fileCount: number): DetectionProject {
  const files: ProjectFile[] = Array.from({ length: fileCount }, (_, index) => ({
    path: `policies/bulk-${index.toString().padStart(3, "0")}.yaml`,
    name: `bulk-${index.toString().padStart(3, "0")}.yaml`,
    fileType: "clawdstrike_policy",
    isDirectory: false,
    depth: 1,
  }));

  return {
    rootId: rootPath,
    rootPath,
    name: rootPath.split("/").pop() ?? rootPath,
    expandedDirs: new Set(["policies"]),
    files: [
      {
        path: "policies",
        name: "policies",
        fileType: "clawdstrike_policy",
        isDirectory: true,
        depth: 0,
        children: files,
      },
    ],
  };
}

function makeEmptyDirectoryRootProject(rootPath: string): DetectionProject {
  return {
    rootId: rootPath,
    rootPath,
    name: rootPath.split("/").pop() ?? rootPath,
    expandedDirs: new Set<string>(),
    files: [
      {
        path: "policies",
        name: "policies",
        fileType: "clawdstrike_policy",
        isDirectory: true,
        depth: 0,
        children: [],
      },
    ],
  };
}

function ExplorerHarness({
  initialProjects,
  activeFileKey,
  onCreateFile,
}: {
  initialProjects: DetectionProject[];
  activeFileKey?: string | null;
  onCreateFile?: (parentPath: string, fileName: string) => void;
}) {
  const [projects, setProjects] = React.useState(initialProjects);

  return (
    <ExplorerPanel
      projects={projects}
      activeFileKey={activeFileKey}
      onToggleDir={(rootId, dirPath) => {
        setProjects((current) => current.map((project) => {
          if (project.rootId !== rootId) {
            return project;
          }
          const nextExpandedDirs = new Set(project.expandedDirs);
          if (nextExpandedDirs.has(dirPath)) {
            nextExpandedDirs.delete(dirPath);
          } else {
            nextExpandedDirs.add(dirPath);
          }
          return {
            ...project,
            expandedDirs: nextExpandedDirs,
          };
        }));
      }}
      onOpenFile={() => {}}
      onExpandAll={() => {}}
      onCollapseAll={() => {}}
      filter=""
      onFilterChange={() => {}}
      formatFilter={null}
      onFormatFilterChange={() => {}}
      onCreateFile={onCreateFile}
    />
  );
}

describe("ExplorerPanel", () => {
  it("transitions from empty state to a loaded tree without changing hook order", () => {
    const props = {
      onToggleDir: () => {},
      onOpenFile: () => {},
      onExpandAll: () => {},
      onCollapseAll: () => {},
      filter: "",
      onFilterChange: () => {},
      formatFilter: null,
      onFormatFilterChange: () => {},
    } as const;

    const { rerender } = render(
      <ExplorerPanel
        {...props}
        projects={[]}
      />,
    );

    expect(screen.getByText("No folder open")).toBeInTheDocument();

    rerender(
      <ExplorerPanel
        {...props}
        projects={[makeProject("/workspace/alpha", "default.yaml")]}
      />,
    );

    expect(screen.getByRole("tree", { name: "Workspace explorer" })).toBeInTheDocument();
    expect(screen.getByText("alpha")).toBeInTheDocument();
  });

  it("preserves the clicked root when duplicate relative paths exist", () => {
    const onOpenFile = vi.fn();

    render(
      <ExplorerPanel
        projects={[
          makeProject("/workspace/alpha", "default.yaml"),
          makeProject("/workspace/bravo", "default.yaml"),
        ]}
        onToggleDir={() => {}}
        onOpenFile={onOpenFile}
        onExpandAll={() => {}}
        onCollapseAll={() => {}}
        filter=""
        onFilterChange={() => {}}
        formatFilter={null}
        onFormatFilterChange={() => {}}
      />,
    );

    const fileItems = screen.getAllByRole("treeitem", { name: /default\.yaml, file/i });
    fireEvent.click(fileItems[1]);

    expect(onOpenFile).toHaveBeenCalledWith(
      "/workspace/bravo",
      expect.objectContaining({ path: "policies/default.yaml" }),
    );
  });

  it("renders an explicit loading state for an empty root that is still indexing", () => {
    render(
      <ExplorerPanel
        projects={[{ ...makeProject("/workspace/alpha", "default.yaml"), files: [] }]}
        rootStates={new Map([
          [
            "/workspace/alpha",
            {
              status: "loading",
              error: null,
              isDefault: true,
            },
          ],
        ])}
        onToggleDir={() => {}}
        onOpenFile={() => {}}
        onExpandAll={() => {}}
        onCollapseAll={() => {}}
        filter=""
        onFilterChange={() => {}}
        formatFilter={null}
        onFormatFilterChange={() => {}}
      />,
    );

    expect(screen.getByText("Indexing workspace...")).toBeTruthy();
    expect(screen.getByText("Workspace")).toBeTruthy();
    expect(screen.getByText("Indexing")).toBeTruthy();
  });

  it("renders a stale-state banner instead of the generic empty copy", () => {
    render(
      <ExplorerPanel
        projects={[{ ...makeProject("/workspace/alpha", "default.yaml"), files: [] }]}
        rootStates={new Map([
          [
            "/workspace/alpha",
            {
              status: "stale",
              error: "disk offline",
            },
          ],
        ])}
        onToggleDir={() => {}}
        onOpenFile={() => {}}
        onExpandAll={() => {}}
        onCollapseAll={() => {}}
        filter=""
        onFilterChange={() => {}}
        formatFilter={null}
        onFormatFilterChange={() => {}}
      />,
    );

    expect(screen.getByText("Refresh failed")).toBeTruthy();
    expect(screen.getByText("disk offline")).toBeTruthy();
    expect(screen.queryByText("No files yet")).toBeNull();
  });

  it("surfaces mutation feedback near the affected root and row", () => {
    const onRefreshRoot = vi.fn();
    const onRevealInFinder = vi.fn();

    render(
      <ExplorerPanel
        projects={[makeProject("/workspace/alpha", "default.yaml")]}
        rootStates={new Map([
          [
            "/workspace/alpha",
            {
              status: "ready",
              error: null,
              mutation: {
                kind: "rename",
                status: "error",
                rootId: "root-alpha",
                rootPath: "/workspace/alpha",
                targetRelativePath: "policies/default.yaml",
                targetLabel: "default.yaml",
                message: "disk offline",
                updatedAt: 1,
              },
            },
          ],
        ])}
        onToggleDir={() => {}}
        onOpenFile={() => {}}
        onExpandAll={() => {}}
        onCollapseAll={() => {}}
        filter=""
        onFilterChange={() => {}}
        formatFilter={null}
        onFormatFilterChange={() => {}}
        onRefreshRoot={onRefreshRoot}
        onRevealInFinder={onRevealInFinder}
      />,
    );

    expect(screen.getByText("Rename needs review for default.yaml")).toBeTruthy();
    expect(screen.getByText("disk offline")).toBeTruthy();
    expect(screen.getByText("Retry")).toBeTruthy();

    fireEvent.click(screen.getByRole("button", { name: "Refresh" }));
    fireEvent.click(screen.getByRole("button", { name: "Reveal" }));

    expect(onRefreshRoot).toHaveBeenCalledWith("/workspace/alpha");
    expect(onRevealInFinder).toHaveBeenCalledWith("/workspace/alpha", "/workspace/alpha");
  });

  it("curates the default root into a clean workspace-first tree", () => {
    render(
      <ExplorerPanel
        projects={[makeDefaultWorkspaceProject()]}
        rootStates={new Map([
          [
            "root-default",
            {
              status: "ready",
              error: null,
              isDefault: true,
              label: ".clawdstrike",
              kind: "default_home",
              provenance: "bootstrap",
            },
          ],
        ])}
        onToggleDir={() => {}}
        onOpenFile={() => {}}
        onExpandAll={() => {}}
        onCollapseAll={() => {}}
        filter=""
        onFilterChange={() => {}}
        formatFilter={null}
        onFormatFilterChange={() => {}}
      />,
    );

    expect(screen.getByText("Workspace")).toBeTruthy();
    expect(screen.getByText("default.yaml")).toBeTruthy();
    expect(screen.queryByText("workspace-root-registry.v1.json")).toBeNull();
    expect(screen.queryByText("Workbench-managed default workspace root")).toBeNull();
  });

  it("keeps curated default-root descendants at their real tree depth", () => {
    render(
      <ExplorerPanel
        projects={[makeDefaultWorkspaceProject()]}
        rootStates={new Map([
          [
            "root-default",
            {
              status: "ready",
              error: null,
              isDefault: true,
              label: ".clawdstrike",
              kind: "default_home",
              provenance: "bootstrap",
            },
          ],
        ])}
        onToggleDir={() => {}}
        onOpenFile={() => {}}
        onExpandAll={() => {}}
        onCollapseAll={() => {}}
        filter=""
        onFilterChange={() => {}}
        formatFilter={null}
        onFormatFilterChange={() => {}}
      />,
    );

    const folderRow = screen.getByRole("treeitem", { name: /policies, expanded folder/i });
    const fileRow = screen.getByRole("treeitem", { name: /default\.yaml, file/i });

    expect(folderRow.getAttribute("aria-level")).toBe("2");
    expect(fileRow.getAttribute("aria-level")).toBe("3");
    expect(folderRow).toHaveStyle({ paddingLeft: "22px" });
    expect(fileRow).toHaveStyle({ paddingLeft: "40px" });
  });

  it("keeps non-default roots simple without curated workspace chrome", () => {
    render(
      <ExplorerPanel
        projects={[makeProject("/workspace/alpha", "default.yaml")]}
        rootStates={new Map([
          [
            "/workspace/alpha",
            {
              status: "ready",
              error: null,
              isDefault: false,
              label: "alpha",
              kind: "mounted_folder",
              provenance: "user_added",
            },
          ],
        ])}
        onToggleDir={() => {}}
        onOpenFile={() => {}}
        onExpandAll={() => {}}
        onCollapseAll={() => {}}
        filter=""
        onFilterChange={() => {}}
        formatFilter={null}
        onFormatFilterChange={() => {}}
      />,
    );

    expect(screen.getByText("alpha")).toBeTruthy();
    expect(screen.queryByText("Workspace")).toBeNull();
    expect(screen.queryByText("Mounted")).toBeNull();
    expect(screen.queryByText("Added")).toBeNull();
  });

  it("exposes tree semantics and roving keyboard navigation across visible rows", () => {
    const onOpenFile = vi.fn();

    render(
      <ExplorerPanel
        projects={[makeProject("/workspace/alpha", "default.yaml", "override.yaml")]}
        onToggleDir={() => {}}
        onOpenFile={onOpenFile}
        onExpandAll={() => {}}
        onCollapseAll={() => {}}
        filter=""
        onFilterChange={() => {}}
        formatFilter={null}
        onFormatFilterChange={() => {}}
      />,
    );

    const tree = screen.getByRole("tree", { name: "Workspace explorer" });
    const rootRow = screen.getByRole("treeitem", { name: /alpha, workspace root/i });
    const folderRow = screen.getByRole("treeitem", { name: /policies, expanded folder/i });
    const firstFile = screen.getByRole("treeitem", { name: /default\.yaml, file/i });
    const lastFile = screen.getByRole("treeitem", { name: /override\.yaml, file/i });

    expect(tree).toBeTruthy();

    rootRow.focus();
    expect(document.activeElement).toBe(rootRow);

    fireEvent.keyDown(rootRow, { key: "ArrowDown" });
    expect(document.activeElement).toBe(folderRow);

    fireEvent.keyDown(folderRow, { key: "ArrowDown" });
    expect(document.activeElement).toBe(firstFile);

    fireEvent.keyDown(firstFile, { key: "End" });
    expect(document.activeElement).toBe(lastFile);

    fireEvent.keyDown(lastFile, { key: "Home" });
    expect(document.activeElement).toBe(rootRow);

    fireEvent.keyDown(rootRow, { key: "ArrowDown" });
    fireEvent.keyDown(folderRow, { key: "ArrowDown" });
    fireEvent.keyDown(firstFile, { key: "Enter" });

    expect(onOpenFile).toHaveBeenCalledWith(
      "/workspace/alpha",
      expect.objectContaining({ path: "policies/default.yaml" }),
    );
  });

  it("reveals matching descendants while filtering even when their ancestors are collapsed", () => {
    render(
      <ExplorerPanel
        projects={[makeCollapsedProject("/workspace/alpha", "default.yaml")]}
        onToggleDir={() => {}}
        onOpenFile={() => {}}
        onExpandAll={() => {}}
        onCollapseAll={() => {}}
        filter="default"
        onFilterChange={() => {}}
        formatFilter={null}
        onFormatFilterChange={() => {}}
      />,
    );

    expect(screen.getByRole("treeitem", { name: /policies, expanded folder/i })).toBeTruthy();
    expect(screen.getByRole("treeitem", { name: /default\.yaml, file/i })).toBeTruthy();
  });

  it("auto-reveals the active file even when its ancestors are collapsed", async () => {
    render(
      <ExplorerHarness
        initialProjects={[makeCollapsedProject("/workspace/alpha", "default.yaml")]}
        activeFileKey="/workspace/alpha::policies/default.yaml"
      />,
    );

    expect(await screen.findByRole("treeitem", { name: /policies, expanded folder/i })).toBeTruthy();
    expect(await screen.findByRole("treeitem", { name: /default\.yaml, file, active/i })).toBeTruthy();
  });

  it("keeps mutation banners visible for empty non-curated roots", () => {
    render(
      <ExplorerPanel
        projects={[{ ...makeProject("/workspace/alpha", "default.yaml"), files: [] }]}
        rootStates={new Map([
          [
            "/workspace/alpha",
            {
              status: "ready",
              error: null,
              mutation: {
                kind: "delete",
                status: "pending",
                rootId: "/workspace/alpha",
                rootPath: "/workspace/alpha",
                targetRelativePath: "policies/orphan.yaml",
                targetLabel: "orphan.yaml",
                message: null,
                updatedAt: 1,
              },
            },
          ],
        ])}
        onToggleDir={() => {}}
        onOpenFile={() => {}}
        onExpandAll={() => {}}
        onCollapseAll={() => {}}
        filter=""
        onFilterChange={() => {}}
        formatFilter={null}
        onFormatFilterChange={() => {}}
      />,
    );

    expect(screen.getByText("Delete pending for orphan.yaml")).toBeTruthy();
    expect(screen.getByText("No files yet")).toBeTruthy();
  });

  it("allows manual root collapse after auto-revealing the active file", async () => {
    render(
      <ExplorerHarness
        initialProjects={[makeCollapsedProject("/workspace/alpha", "default.yaml")]}
        activeFileKey="/workspace/alpha::policies/default.yaml"
      />,
    );

    const rootRow = await screen.findByRole("treeitem", { name: /alpha, workspace root/i });
    expect(await screen.findByRole("treeitem", { name: /policies, expanded folder/i })).toBeTruthy();
    expect(await screen.findByRole("treeitem", { name: /default\.yaml, file/i })).toBeTruthy();

    fireEvent.click(rootRow);

    expect(screen.queryByRole("treeitem", { name: /default\.yaml, file/i })).toBeNull();
  });

  it("targets the focused root when creating a new file from the toolbar", () => {
    const onCreateFile = vi.fn();

    render(
      <ExplorerPanel
        projects={[
          makeProject("/workspace/alpha", "alpha.yaml"),
          makeProject("/workspace/bravo", "bravo.yaml"),
        ]}
        onToggleDir={() => {}}
        onOpenFile={() => {}}
        onExpandAll={() => {}}
        onCollapseAll={() => {}}
        filter=""
        onFilterChange={() => {}}
        formatFilter={null}
        onFormatFilterChange={() => {}}
        onCreateFile={onCreateFile}
      />,
    );

    const bravoRoot = screen.getByRole("treeitem", { name: /bravo, workspace root/i });
    bravoRoot.focus();
    fireEvent.focus(bravoRoot);

    fireEvent.click(screen.getByTitle("New File"));

    const input = screen.getByPlaceholderText("filename.yaml");
    fireEvent.change(input, { target: { value: "investigate.yaml" } });
    fireEvent.keyDown(input, { key: "Enter" });

    expect(onCreateFile).toHaveBeenCalledWith("/workspace/bravo", "investigate.yaml");
  });

  it("opens the explorer context menu from the keyboard on the focused row", () => {
    render(
      <ExplorerPanel
        projects={[makeProject("/workspace/alpha", "default.yaml")]}
        onToggleDir={() => {}}
        onOpenFile={() => {}}
        onExpandAll={() => {}}
        onCollapseAll={() => {}}
        filter=""
        onFilterChange={() => {}}
        formatFilter={null}
        onFormatFilterChange={() => {}}
      />,
    );

    const rootRow = screen.getByRole("treeitem", { name: /alpha, workspace root/i });
    rootRow.focus();

    fireEvent.keyDown(rootRow, { key: "F10", shiftKey: true });

    expect(screen.getByRole("menu", { name: "Explorer context menu" })).toBeTruthy();
    expect(screen.getByRole("menuitem", { name: "Refresh" })).toBeTruthy();
  });

  it("preserves mutation banners when a non-curated root becomes empty", () => {
    render(
      <ExplorerPanel
        projects={[{ ...makeProject("/workspace/alpha", "default.yaml"), files: [] }]}
        rootStates={new Map([
          [
            "/workspace/alpha",
            {
              status: "ready",
              error: null,
              mutation: {
                kind: "delete",
                status: "error",
                rootId: "/workspace/alpha",
                rootPath: "/workspace/alpha",
                targetRelativePath: "policies/default.yaml",
                targetLabel: "default.yaml",
                message: "delete needs retry",
                updatedAt: 1,
              },
            },
          ],
        ])}
        onToggleDir={() => {}}
        onOpenFile={() => {}}
        onExpandAll={() => {}}
        onCollapseAll={() => {}}
        filter=""
        onFilterChange={() => {}}
        formatFilter={null}
        onFormatFilterChange={() => {}}
      />,
    );

    expect(screen.getByText("Delete needs review for default.yaml")).toBeTruthy();
    expect(screen.getByText("delete needs retry")).toBeTruthy();
  });

  it("falls back focus deterministically when the current row disappears", () => {
    const props = {
      onToggleDir: () => {},
      onOpenFile: () => {},
      onExpandAll: () => {},
      onCollapseAll: () => {},
      onFilterChange: () => {},
      onFormatFilterChange: () => {},
    };
    const { rerender } = render(
      <ExplorerPanel
        {...props}
        projects={[makeProject("/workspace/alpha", "default.yaml", "override.yaml")]}
        filter=""
        formatFilter={null}
      />,
    );

    const rootRow = screen.getByRole("treeitem", { name: /alpha, workspace root/i });
    const folderRow = screen.getByRole("treeitem", { name: /policies, expanded folder/i });
    const firstFile = screen.getByRole("treeitem", { name: /default\.yaml, file/i });
    const disappearingRow = screen.getByRole("treeitem", { name: /override\.yaml, file/i });

    rootRow.focus();
    fireEvent.keyDown(rootRow, { key: "ArrowDown" });
    fireEvent.keyDown(folderRow, { key: "ArrowDown" });
    fireEvent.keyDown(firstFile, { key: "ArrowDown" });

    expect(document.activeElement).toBe(disappearingRow);

    rerender(
      <ExplorerPanel
        {...props}
        projects={[makeProject("/workspace/alpha", "default.yaml", "override.yaml")]}
        filter="default"
        formatFilter={null}
      />,
    );

    const fallbackRow = screen.getByRole("treeitem", { name: /default\.yaml, file/i });
    expect(screen.queryByRole("treeitem", { name: /override\.yaml, file/i })).toBeNull();
    expect(document.activeElement).toBe(fallbackRow);
  });

  it("targets the focused root from the toolbar New File action", () => {
    const onCreateFile = vi.fn();

    render(
      <ExplorerPanel
        projects={[
          makeProject("/workspace/alpha", "default.yaml"),
          makeProject("/workspace/bravo", "default.yaml"),
        ]}
        onToggleDir={() => {}}
        onOpenFile={() => {}}
        onExpandAll={() => {}}
        onCollapseAll={() => {}}
        filter=""
        onFilterChange={() => {}}
        formatFilter={null}
        onFormatFilterChange={() => {}}
        onCreateFile={onCreateFile}
      />,
    );

    const bravoRoot = screen.getByRole("treeitem", { name: /bravo, workspace root/i });
    fireEvent.focus(bravoRoot);
    fireEvent.click(screen.getByRole("button", { name: "New File" }));

    const input = screen.getByPlaceholderText("filename.yaml");
    fireEvent.change(input, { target: { value: "focused.yaml" } });
    fireEvent.keyDown(input, { key: "Enter" });

    expect(onCreateFile).toHaveBeenCalledWith("/workspace/bravo", "focused.yaml");
  });

  it("treats directory-only roots as expandable from the keyboard", () => {
    render(
      <ExplorerPanel
        projects={[makeEmptyDirectoryRootProject("/workspace/alpha")]}
        onToggleDir={() => {}}
        onOpenFile={() => {}}
        onExpandAll={() => {}}
        onCollapseAll={() => {}}
        filter=""
        onFilterChange={() => {}}
        formatFilter={null}
        onFormatFilterChange={() => {}}
      />,
    );

    const rootRow = screen.getByRole("treeitem", { name: /alpha, workspace root/i });
    expect(screen.getByRole("treeitem", { name: /policies, collapsed folder/i })).toBeTruthy();

    fireEvent.click(rootRow);
    expect(screen.queryByRole("treeitem", { name: /policies, collapsed folder/i })).toBeNull();

    rootRow.focus();
    fireEvent.keyDown(rootRow, { key: "ArrowRight" });

    expect(screen.getByRole("treeitem", { name: /policies, collapsed folder/i })).toBeTruthy();
  });

  it("bounds large tree rendering and reveals more rows on demand", () => {
    render(
      <ExplorerPanel
        projects={[makeLargeProject("/workspace/alpha", 260)]}
        onToggleDir={() => {}}
        onOpenFile={() => {}}
        onExpandAll={() => {}}
        onCollapseAll={() => {}}
        filter=""
        onFilterChange={() => {}}
        formatFilter={null}
        onFormatFilterChange={() => {}}
      />,
    );

    expect(screen.queryByText("bulk-259.yaml")).toBeNull();
    expect(screen.getByRole("button", { name: /show 61 more rows/i })).toBeTruthy();

    fireEvent.click(screen.getByRole("button", { name: /show 61 more rows/i }));

    expect(screen.getByText("bulk-259.yaml")).toBeTruthy();
  });

  it("keeps an active file visible even when it lands past the default render cap", () => {
    render(
      <ExplorerPanel
        projects={[makeLargeProject("/workspace/alpha", 260)]}
        activeFileKey={"/workspace/alpha::policies/bulk-259.yaml"}
        onToggleDir={() => {}}
        onOpenFile={() => {}}
        onExpandAll={() => {}}
        onCollapseAll={() => {}}
        filter=""
        onFilterChange={() => {}}
        formatFilter={null}
        onFormatFilterChange={() => {}}
      />,
    );

    expect(screen.getByText("bulk-259.yaml")).toBeTruthy();
  });
});
