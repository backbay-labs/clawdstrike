import { describe, expect, it } from "vitest";
import { createWorkspacePaletteCommands, getEligibleWorkspaceCommands } from "./workspaceCommands";

const baseContext = {
  activeScope: "workspace" as const,
  workspaceRootId: "root-1",
  activeSurfaceRoute: "/workspace",
  selectedObjectIds: [],
  focusedPane: "main" as const,
  connectivity: {
    daemon: "connected" as const,
    openclaw: "connected" as const,
  },
};

describe("workspaceCommands", () => {
  it("exposes required workspace actions when a trusted root is active", () => {
    const commands = getEligibleWorkspaceCommands(baseContext);
    const ids = commands.map((command) => command.id);

    expect(ids).toContain("workspace.open");
    expect(ids).toContain("workspace.open-folder");
    expect(ids).toContain("workspace.quick-open");
    expect(ids).toContain("workspace.search");
    expect(ids).toContain("workspace.terminal");
    expect(ids).toContain("workspace.git-status");
    expect(ids).toContain("workspace.save-file");
  });

  it("hides root-dependent commands when no trusted root is active", () => {
    const commands = getEligibleWorkspaceCommands({
      ...baseContext,
      workspaceRootId: undefined,
      focusedPane: "workspace-tree",
    });
    const ids = commands.map((command) => command.id);

    expect(ids).toContain("workspace.open");
    expect(ids).toContain("workspace.open-folder");
    expect(ids).not.toContain("workspace.quick-open");
    expect(ids).not.toContain("workspace.search");
    expect(ids).not.toContain("workspace.terminal");
  });

  it("adapts eligible commands to palette entries", async () => {
    const seen: string[] = [];
    const paletteCommands = createWorkspacePaletteCommands(baseContext, (result, command) => {
      seen.push(`${command.id}:${result.kind}`);
    });

    const openWorkspace = paletteCommands.find((command) => command.id === "workspace.open");
    expect(openWorkspace).toBeTruthy();

    await openWorkspace?.action();
    expect(seen).toContain("workspace.open:navigate");
  });
});
