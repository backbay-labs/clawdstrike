import { fireEvent, render, screen } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";
import { ExplorerPanel } from "../explorer-panel";
import type { DetectionProject, ProjectFile } from "@/features/project/stores/project-store";

function makeProject(rootPath: string, fileName: string): DetectionProject {
  const file: ProjectFile = {
    path: `policies/${fileName}`,
    name: fileName,
    fileType: "clawdstrike_policy",
    isDirectory: false,
    depth: 1,
  };

  return {
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
        children: [file],
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

    const fileButtons = screen.getAllByRole("button", { name: /default\.yaml/i });
    fireEvent.click(fileButtons[1]);

    expect(onOpenFile).toHaveBeenCalledWith(
      "/workspace/bravo",
      expect.objectContaining({ path: "policies/default.yaml" }),
    );
  });
});
