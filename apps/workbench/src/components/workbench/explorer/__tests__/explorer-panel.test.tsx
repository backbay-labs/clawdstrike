import { fireEvent, render, screen } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";
import { ExplorerPanel } from "../explorer-panel";
import type { DetectionProject, ProjectFile } from "@/features/project/stores/project-store";
import { getProjectFileStatusKey } from "@/features/project/stores/project-store";

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

describe("ExplorerPanel", () => {
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
    expect(screen.getByText("Default")).toBeTruthy();
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

    expect(screen.getByText("Workspace refresh failed")).toBeTruthy();
    expect(screen.getByText("disk offline")).toBeTruthy();
    expect(screen.queryByText("No detection files found")).toBeNull();
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
    expect(onRevealInFinder).toHaveBeenCalledWith("/workspace/alpha");
  });

  it("curates the default root into workspace-first and revealable system sections", () => {
    render(
      <ExplorerPanel
        projects={[makeDefaultWorkspaceProject()]}
        rootStates={new Map([
          [
            "/Users/test/.clawdstrike",
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

    expect(screen.getByText("Detection Workspace")).toBeTruthy();
    expect(screen.getByText("Workbench-managed default workspace root")).toBeTruthy();
    expect(screen.getByRole("button", { name: "Show System (1)" })).toBeTruthy();
    expect(screen.queryByText("workspace-root-registry.v1.json")).toBeNull();

    fireEvent.click(screen.getByRole("button", { name: "Show System (1)" }));

    expect(screen.getByText("workspace-root-registry.v1.json")).toBeTruthy();
  });

  it("shows mounted-root provenance badges without curating non-default roots", () => {
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

    expect(screen.getByText("Mounted")).toBeTruthy();
    expect(screen.getByText("Added")).toBeTruthy();
    expect(screen.queryByText("Detection Workspace")).toBeNull();
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

    expect(
      screen.getByText("Filtered view reveals matching descendants even when their ancestor folders are collapsed."),
    ).toBeTruthy();
    expect(screen.getByRole("treeitem", { name: /policies, expanded folder/i })).toBeTruthy();
    expect(screen.getByRole("treeitem", { name: /default\.yaml, file/i })).toBeTruthy();
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
        activeFileKey={getProjectFileStatusKey("/workspace/alpha", "policies/bulk-259.yaml")}
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
