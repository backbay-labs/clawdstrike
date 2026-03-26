import React from "react";
import { render, screen } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";

import type { SwarmBoardNodeData } from "@/features/swarm/swarm-board-types";

vi.mock("@xyflow/react", () => ({
  Handle: ({ type, position }: { type: string; position: string }) => (
    <div data-testid={`handle-${type}-${position}`} />
  ),
  Position: { Left: "left", Right: "right", Top: "top", Bottom: "bottom" },
  NodeResizer: () => null,
  useStore: (selector: (s: any) => any) => selector({ transform: [0, 0, 1] }),
}));

vi.mock("@/lib/tauri-bridge", () => ({
  readTextFileFromDisk: vi.fn().mockResolvedValue(null),
}));

vi.mock("react-syntax-highlighter", () => ({
  Prism: ({ children }: { children?: React.ReactNode }) => <div>{children}</div>,
}));

vi.mock("react-syntax-highlighter/dist/cjs/styles/prism", () => ({
  atomDark: {},
}));

import { DiffNode } from "../nodes/diff-node";

function renderNode(data: Partial<SwarmBoardNodeData>, selected = false) {
  const fullData: SwarmBoardNodeData = {
    title: "Auth changes",
    status: "idle",
    nodeType: "diff",
    ...data,
  };

  return render(
    <DiffNode
      {...({
        id: "test-node",
        data: fullData,
        selected,
        type: "diff",
        isConnectable: true,
        positionAbsoluteX: 0,
        positionAbsoluteY: 0,
        zIndex: 0,
        dragging: false,
        deletable: true,
        selectable: true,
        parentId: undefined,
        sourcePosition: undefined,
        targetPosition: undefined,
        dragHandle: undefined,
        width: 320,
        height: 220,
      } as any)}
    />,
  );
}

describe("DiffNode", () => {
  it("shows added and removed counts", () => {
    renderNode({
      diffSummary: { added: 47, removed: 12, files: [] },
    });

    expect(screen.getByText("+47")).toBeInTheDocument();
    expect(screen.getByText("-12")).toBeInTheDocument();
  });

  it("shows file count instead of the old changed-file list", () => {
    renderNode({
      diffSummary: {
        added: 10,
        removed: 5,
        files: ["src/a.rs", "src/b.rs", "src/c.rs", "src/d.rs", "src/e.rs", "src/f.rs"],
      },
    });

    expect(screen.getByText("6 files")).toBeInTheDocument();
    expect(screen.queryByText("src/a.rs")).toBeNull();
    expect(screen.queryByText("src/d.rs")).toBeNull();
  });

  it("computes summary counts from inline diff content when diffSummary is missing", () => {
    renderNode({
      diffContent: `diff --git a/src/auth.rs b/src/auth.rs
--- a/src/auth.rs
+++ b/src/auth.rs
@@ -1,3 +1,4 @@
 export const auth = true;
-export const stale = false;
+export const stale = true;
+export const hardened = true;`,
    });

    expect(screen.getByText("+2")).toBeInTheDocument();
    expect(screen.getByText("-1")).toBeInTheDocument();
    expect(screen.getByText("1 file")).toBeInTheDocument();
  });

  it("renders a preview when diff content is attached", () => {
    renderNode(
      {
        diffSummary: { added: 2, removed: 1, files: ["src/auth.rs"] },
        diffContent: `diff --git a/src/auth.rs b/src/auth.rs
--- a/src/auth.rs
+++ b/src/auth.rs
@@ -1,2 +1,3 @@
 export const auth = true;
-export const stale = false;
+export const stale = true;`,
      },
      true,
    );

    expect(screen.getByTestId("diff-preview-pane")).toBeInTheDocument();
    expect(screen.getByText("@@ -1,2 +1,3 @@")).toBeInTheDocument();
    expect(screen.getByText("+export const stale = true;")).toBeInTheDocument();
  });

  it("renders source and target handles", () => {
    renderNode({});
    expect(screen.getByTestId("handle-target-top")).toBeInTheDocument();
    expect(screen.getByTestId("handle-source-bottom")).toBeInTheDocument();
  });
});
