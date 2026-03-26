import React from "react";
import { render, screen } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";

import type { SwarmBoardNodeData } from "@/features/swarm/swarm-board-types";

vi.mock("@xyflow/react", () => ({
  Handle: ({ type, position }: { type: string; position: string }) => (
    <div data-testid={`handle-${type}-${position}`} />
  ),
  Position: { Left: "left", Right: "right", Top: "top", Bottom: "bottom" },
  useStore: (selector: (s: any) => any) => selector({ transform: [0, 0, 1] }),
}));

import { ArtifactNode } from "../nodes/artifact-node";

function renderNode(data: Partial<SwarmBoardNodeData>, selected = false) {
  const fullData: SwarmBoardNodeData = {
    title: "auth.rs",
    status: "idle",
    nodeType: "artifact",
    filePath: "src/middleware/auth.rs",
    fileType: "rust",
    ...data,
  };

  return render(
    <ArtifactNode
      {...({
        id: "artifact-node",
        data: fullData,
        selected,
        type: "artifact",
        isConnectable: true,
        positionAbsoluteX: 0,
        positionAbsoluteY: 0,
        zIndex: 0,
        dragging: false,
        deletable: true,
        selectable: true,
        width: 96,
        height: 96,
      } as any)}
    />,
  );
}

describe("ArtifactNode", () => {
  it("renders the extracted filename", () => {
    renderNode({});
    expect(screen.getByText("auth.rs")).toBeInTheDocument();
  });

  it("uses the title when filePath is missing", () => {
    renderNode({ title: "orphaned.txt", filePath: undefined });
    expect(screen.getByText("orphaned.txt")).toBeInTheDocument();
  });

  it("removes the redundant file type badge from the node", () => {
    renderNode({ fileType: "rust" });
    expect(screen.queryByText(/^rust$/i)).toBeNull();
  });

  it("renders source and target handles", () => {
    renderNode({});
    expect(screen.getByTestId("handle-target-top")).toBeInTheDocument();
    expect(screen.getByTestId("handle-source-bottom")).toBeInTheDocument();
  });
});
