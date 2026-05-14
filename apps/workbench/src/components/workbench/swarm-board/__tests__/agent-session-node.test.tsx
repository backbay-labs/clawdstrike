import React from "react";
import { render, screen } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";

import type { SwarmBoardNodeData, SessionStatus, RiskLevel } from "@/features/swarm/swarm-board-types";

// ---------------------------------------------------------------------------
// Mock @xyflow/react — Handle, Position, NodeResizer used by the real component
// ---------------------------------------------------------------------------

vi.mock("@xyflow/react", () => ({
  Handle: ({ type, position }: { type: string; position: string }) => (
    <div data-testid={`handle-${type}-${position}`} />
  ),
  Position: { Left: "left", Right: "right", Top: "top", Bottom: "bottom" },
  NodeResizer: () => null,
}));

// ---------------------------------------------------------------------------
// Mock useSwarmBoard — provides updateNode, removeNode, killSession
// ---------------------------------------------------------------------------

const mockUpdateNode = vi.fn();
const mockRemoveNode = vi.fn();
const mockKillSession = vi.fn().mockResolvedValue(undefined);

vi.mock("@/features/swarm/stores/swarm-board-store", () => ({
  useSwarmBoard: () => ({
    updateNode: mockUpdateNode,
    removeNode: mockRemoveNode,
    killSession: mockKillSession,
  }),
}));

// ---------------------------------------------------------------------------
// Mock TerminalRenderer — the real one requires Tauri + ghostty-web WASM
// ---------------------------------------------------------------------------

vi.mock("../terminal-renderer", () => ({
  TerminalRenderer: ({ sessionId }: { sessionId: string }) => (
    <div data-testid="terminal-renderer">{sessionId}</div>
  ),
}));

// ---------------------------------------------------------------------------
// Import the real component after mocks are set up
// ---------------------------------------------------------------------------

import { AgentSessionNode } from "../nodes/agent-session-node";

// ---------------------------------------------------------------------------
// Helper to render the node with NodeProps shape
// ---------------------------------------------------------------------------

function renderNode(data: Partial<SwarmBoardNodeData>, selected = false) {
  const fullData: SwarmBoardNodeData = {
    title: "Fix auth middleware",
    status: "running",
    nodeType: "agentSession",
    branch: "feat/fix-auth",
    previewLines: [
      "$ cargo test -p auth",
      "running 12 tests...",
      "test validate_token ... ok",
    ],
    receiptCount: 7,
    risk: "medium",
    agentModel: "opus-4.6",
    ...data,
  };

  return render(
    <AgentSessionNode
      {...({
        id: "test-node",
        data: fullData,
        selected,
        type: "agentSession",
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
        width: 400,
        height: 300,
      } as any)}
    />,
  );
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe("AgentSessionNode", () => {
  it("renders agent model in the title bar", () => {
    renderNode({ agentModel: "opus-4.6" });
    expect(screen.getByText("opus-4.6")).toBeInTheDocument();
  });

  it("renders branch name", () => {
    renderNode({ branch: "feat/fix-auth" });
    expect(screen.getByText("feat/fix-auth")).toBeInTheDocument();
  });

  it("does not render branch when undefined", () => {
    renderNode({ branch: undefined });
    expect(screen.queryByText("feat/fix-auth")).toBeNull();
  });

  describe("status label", () => {
    const statusLabels: [SessionStatus, string][] = [
      ["idle", "IDLE"],
      ["running", "RUN"],
      ["blocked", "WAIT"],
      ["completed", "DONE"],
      ["failed", "FAIL"],
      ["evaluating", "EVAL"],
    ];

    it.each(statusLabels)(
      "status '%s' renders label '%s'",
      (status, expectedLabel) => {
        renderNode({ status });
        expect(screen.getByText(expectedLabel)).toBeInTheDocument();
      },
    );
  });

  it("shows preview lines when no session is active", () => {
    renderNode({
      sessionId: undefined,
      previewLines: ["$ cargo test -p auth", "running 12 tests...", "test validate_token ... ok"],
    });
    expect(screen.getByText("$ cargo test -p auth")).toBeInTheDocument();
    expect(screen.getByText("test validate_token ... ok")).toBeInTheDocument();
  });

  it("shows TerminalRenderer when sessionId is present", () => {
    renderNode({ sessionId: "sess-123" });
    expect(screen.getByTestId("terminal-renderer")).toBeInTheDocument();
    expect(screen.getByTestId("terminal-renderer").textContent).toBe("sess-123");
  });

  it("shows awaiting output when no previewLines and no session", () => {
    renderNode({ sessionId: undefined, previewLines: [] });
    expect(screen.getByText("awaiting output")).toBeInTheDocument();
  });

  it("shows receipt count in footer metrics", () => {
    renderNode({ receiptCount: 7 });
    expect(screen.getByText("7")).toBeInTheDocument();
  });

  it("shows risk level in footer", () => {
    renderNode({ risk: "medium" });
    expect(screen.getByText("medium")).toBeInTheDocument();
  });

  describe("risk levels", () => {
    const risks: RiskLevel[] = ["low", "medium", "high"];

    it.each(risks)("renders risk level '%s'", (risk) => {
      renderNode({ risk });
      expect(screen.getByText(risk)).toBeInTheDocument();
    });
  });

  it("renders source and target handles", () => {
    renderNode({});
    expect(screen.getByTestId("handle-target-top")).toBeInTheDocument();
    expect(screen.getByTestId("handle-source-bottom")).toBeInTheDocument();
  });

  it("shows close session button", () => {
    renderNode({});
    const closeBtn = screen.getByRole("button", { name: "Close session" });
    expect(closeBtn).toBeInTheDocument();
  });

  it("shows maximize button", () => {
    renderNode({});
    const maxBtn = screen.getByRole("button", { name: "Maximize session" });
    expect(maxBtn).toBeInTheDocument();
  });

  it("shows policy mode when provided", () => {
    renderNode({ policyMode: "strict" });
    expect(screen.getByText("strict")).toBeInTheDocument();
  });

  it("shows exit code for non-running statuses", () => {
    renderNode({ status: "completed", exitCode: 0 });
    expect(screen.getByText("(0)")).toBeInTheDocument();
  });

  it("does not show exit code for running status", () => {
    renderNode({ status: "running", exitCode: 0 });
    expect(screen.queryByText("(0)")).toBeNull();
  });
});
