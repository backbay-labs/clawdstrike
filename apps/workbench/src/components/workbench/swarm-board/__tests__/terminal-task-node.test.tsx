import React from "react";
import { render, screen } from "@testing-library/react";
import { describe, expect, it, vi, beforeEach, afterEach } from "vitest";

import type { SwarmBoardNodeData, SessionStatus } from "@/features/swarm/swarm-board-types";

// ---------------------------------------------------------------------------
// Mock @xyflow/react — Handle is used by the real component
// ---------------------------------------------------------------------------

vi.mock("@xyflow/react", () => ({
  Handle: ({ type, position }: { type: string; position: string }) => (
    <div data-testid={`handle-${type}-${position}`} />
  ),
  Position: { Left: "left", Right: "right", Top: "top", Bottom: "bottom" },
  NodeResizer: () => null,
}));

// Import the real component after mock
import { TerminalTaskNode } from "../nodes/terminal-task-node";

// ---------------------------------------------------------------------------
// Helper to render the node (NodeProps shape)
// ---------------------------------------------------------------------------

function renderNode(data: Partial<SwarmBoardNodeData>, selected = false) {
  const fullData: SwarmBoardNodeData = {
    title: "Test Task",
    status: "idle",
    nodeType: "terminalTask",
    ...data,
  };

  return render(
    <TerminalTaskNode
      // Cast to satisfy NodeProps — only data and selected matter here
      {...({
        id: "test-node",
        data: fullData,
        selected,
        type: "terminalTask",
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
        width: 300,
        height: 180,
      } as any)}
    />,
  );
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe("TerminalTaskNode", () => {
  describe("title rendering", () => {
    it("renders the title", () => {
      renderNode({ title: "Run integration tests" });
      expect(screen.getByText("Run integration tests")).toBeInTheDocument();
    });

    it("renders a different title", () => {
      renderNode({ title: "Deploy to staging" });
      expect(screen.getByText("Deploy to staging")).toBeInTheDocument();
    });
  });

  describe("status badge", () => {
    const statusTests: [SessionStatus, string][] = [
      ["idle", "IDLE"],
      ["running", "RUN"],
      ["blocked", "WAIT"],
      ["completed", "DONE"],
      ["failed", "FAIL"],
    ];

    it.each(statusTests)(
      "shows '%s' status as badge text '%s'",
      (status, expectedLabel) => {
        renderNode({ status });
        expect(screen.getByText(expectedLabel)).toBeInTheDocument();
      },
    );

    it("defaults to IDLE when status is undefined", () => {
      renderNode({ status: undefined as any });
      // The component defaults: const status = d.status ?? "idle"
      expect(screen.getByText("IDLE")).toBeInTheDocument();
    });
  });

  describe("task prompt text", () => {
    it("shows task prompt text", () => {
      renderNode({ taskPrompt: "Execute the full integration test suite and report failures" });
      expect(screen.getByText("Execute the full integration test suite and report failures")).toBeInTheDocument();
    });

    it("shows 'No task description' when taskPrompt is undefined", () => {
      renderNode({ taskPrompt: undefined });
      expect(screen.getByText("No task description")).toBeInTheDocument();
    });

    it("truncates long prompts via line-clamp CSS class", () => {
      const longPrompt = "A".repeat(500);
      renderNode({ taskPrompt: longPrompt });

      // The text still renders in the DOM, but line-clamp CSS truncates visually.
      // We verify the full text is in the DOM (CSS handles visual truncation).
      const el = screen.getByText(longPrompt);
      expect(el).toBeInTheDocument();
      expect(el.className).toContain("line-clamp-2");
    });
  });

  describe("elapsed time", () => {
    let now: number;

    beforeEach(() => {
      now = Date.now();
      vi.useFakeTimers();
      vi.setSystemTime(now);
    });

    afterEach(() => {
      vi.useRealTimers();
    });

    it("shows elapsed time in seconds when < 60s", () => {
      renderNode({ createdAt: now - 30_000 }); // 30 seconds ago
      expect(screen.getByText("30s")).toBeInTheDocument();
    });

    it("shows elapsed time in minutes when >= 60s", () => {
      renderNode({ createdAt: now - 125_000 }); // 2m 5s
      expect(screen.getByText("2m 5s")).toBeInTheDocument();
    });

    it("shows elapsed time in hours when >= 3600s", () => {
      renderNode({ createdAt: now - 7500_000 }); // 2h 5m
      expect(screen.getByText("2h 5m")).toBeInTheDocument();
    });

    it("does not show elapsed time when createdAt is missing", () => {
      renderNode({ createdAt: undefined });
      // No time element should be rendered
      expect(screen.queryByText(/\d+[smh]/)).toBeNull();
    });
  });

  describe("session ID", () => {
    it("shows session ID when present", () => {
      renderNode({ sessionId: "sess-task-1" });
      expect(screen.getByText("sess-task-1")).toBeInTheDocument();
    });

    it("does not show session ID when absent", () => {
      renderNode({ sessionId: undefined });
      expect(screen.queryByText(/sess-/)).toBeNull();
    });
  });

  describe("handles", () => {
    it("renders source and target handles", () => {
      renderNode({});
      expect(screen.getByTestId("handle-target-top")).toBeInTheDocument();
      expect(screen.getByTestId("handle-source-bottom")).toBeInTheDocument();
    });
  });

  describe("missing/empty data handling", () => {
    it("renders with minimal data", () => {
      renderNode({
        title: "Minimal Task",
        status: "idle",
      });
      expect(screen.getByText("Minimal Task")).toBeInTheDocument();
      expect(screen.getByText("IDLE")).toBeInTheDocument();
      expect(screen.getByText("No task description")).toBeInTheDocument();
    });
  });
});
