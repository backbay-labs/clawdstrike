import { describe, expect, it } from "vitest";
import { createMockWorkspaceShellSnapshot } from "@/services/workspace";
import {
  applyWorkspaceRootSnapshot,
  closeWorkspaceTab,
  createWorkspaceSurfaceState,
  parseWorkspaceRouteState,
  selectWorkspacePath,
  serializeWorkspaceRouteState,
  toggleWorkspaceTreePath,
  upsertWorkspaceTab,
} from "./workspaceShellState";

describe("workspaceShellState", () => {
  it("hydrates from a workspace snapshot", () => {
    const state = createWorkspaceSurfaceState(createMockWorkspaceShellSnapshot());

    expect(state.access).toBe("ready");
    expect(state.activeRootId).toBe("mock-root-huntronomer");
    expect(state.tabs).toHaveLength(2);
    expect(state.tree.selectedPath).toBe("README.md");
  });

  it("toggles tree expansion", () => {
    const state = createWorkspaceSurfaceState(createMockWorkspaceShellSnapshot());
    const path = "briefs";

    const collapsed = toggleWorkspaceTreePath(state, path);
    expect(collapsed.tree.expandedPaths).not.toContain(path);

    const expanded = toggleWorkspaceTreePath(collapsed, path);
    expect(expanded.tree.expandedPaths).toContain(path);
  });

  it("selects a file path and upserts tabs", () => {
    const state = createWorkspaceSurfaceState(createMockWorkspaceShellSnapshot());
    const selected = selectWorkspacePath(state, "rules/sigma/outbound-spike.yml");
    const withTab = upsertWorkspaceTab(selected, {
      id: "workspace-tab-sigma",
      title: "outbound-spike.yml",
      relativePath: "rules/sigma/outbound-spike.yml",
      kind: "file",
    });

    expect(withTab.route.section).toBe("file");
    expect(withTab.route.activeFilePath).toBe("rules/sigma/outbound-spike.yml");
    expect(withTab.tabs[withTab.tabs.length - 1]?.id).toBe("workspace-tab-sigma");
  });

  it("closes tabs and falls back to workspace overview", () => {
    const state = createWorkspaceSurfaceState({
      roots: createMockWorkspaceShellSnapshot().roots,
      activeRootId: "mock-root-huntronomer",
      tree: createMockWorkspaceShellSnapshot().tree,
      suggestedTabs: [
        {
          id: "tab-1",
          title: "README.md",
          relativePath: "README.md",
          kind: "file",
        },
      ],
    });

    const nextState = closeWorkspaceTab(state, "tab-1");
    expect(nextState.tabs).toHaveLength(0);
    expect(nextState.route.section).toBe("workspace");
  });

  it("serializes and parses route state", () => {
    const encoded = serializeWorkspaceRouteState({
      section: "file",
      activeFilePath: "briefs/hunt-plan.md",
    });

    expect(encoded).toBe("?section=file&file=briefs%2Fhunt-plan.md");
    expect(parseWorkspaceRouteState(encoded)).toEqual({
      section: "file",
      activeFilePath: "briefs/hunt-plan.md",
    });
  });

  it("replaces root state when the active trusted root changes", () => {
    const roots = [
      {
        id: "root-1",
        name: "alpha",
        canonicalPath: "/alpha",
        createdAt: "2026-03-07T12:00:00.000Z",
        lastOpenedAt: "2026-03-07T12:00:00.000Z",
      },
      {
        id: "root-2",
        name: "beta",
        canonicalPath: "/beta",
        createdAt: "2026-03-07T12:00:00.000Z",
        lastOpenedAt: "2026-03-07T12:00:00.000Z",
      },
    ];
    const initial = createWorkspaceSurfaceState({
      roots,
      activeRootId: "root-1",
      tree: [
        {
          rootId: "root-1",
          relativePath: "alpha.txt",
          name: "alpha.txt",
          kind: "file",
        },
      ],
      suggestedTabs: [
        {
          id: "alpha-tab",
          title: "alpha.txt",
          relativePath: "alpha.txt",
          kind: "file",
        },
      ],
    });

    const nextState = applyWorkspaceRootSnapshot(
      { ...initial, route: { section: "search" } },
      {
        roots,
        activeRootId: "root-2",
        tree: [
          {
            rootId: "root-2",
            relativePath: "beta.txt",
            name: "beta.txt",
            kind: "file",
          },
        ],
        suggestedTabs: [
          {
            id: "beta-tab",
            title: "beta.txt",
            relativePath: "beta.txt",
            kind: "file",
          },
        ],
      },
    );

    expect(nextState.activeRootId).toBe("root-2");
    expect(nextState.rootTree[0]?.rootId).toBe("root-2");
    expect(nextState.tabs[0]?.relativePath).toBe("beta.txt");
    expect(nextState.route.section).toBe("search");
    expect(nextState.route.activeFilePath).toBe("beta.txt");
  });
});
