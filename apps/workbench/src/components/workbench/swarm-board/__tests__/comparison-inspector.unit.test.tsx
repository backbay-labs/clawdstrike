/**
 * ComparisonInspector unit tests — verifies routing logic by mocking
 * all comparison sub-components and checking which one renders.
 */
import React from "react";
import { render, screen } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";
import type { Node } from "@xyflow/react";
import type { SwarmBoardNodeData } from "@/features/swarm/swarm-board-types";

// ---------------------------------------------------------------------------
// Mock all comparison sub-components
// ---------------------------------------------------------------------------

vi.mock("../comparison/comparison-session", () => ({
  SessionComparison: () => <div data-testid="session-comparison" />,
}));

vi.mock("../comparison/comparison-receipt", () => ({
  ReceiptComparison: () => <div data-testid="receipt-comparison" />,
}));

vi.mock("../comparison/comparison-diff", () => ({
  DiffComparison: () => <div data-testid="diff-comparison" />,
}));

vi.mock("../comparison/comparison-task", () => ({
  TaskComparison: () => <div data-testid="task-comparison" />,
}));

vi.mock("../comparison/comparison-artifact", () => ({
  ArtifactComparison: () => <div data-testid="artifact-comparison" />,
}));

vi.mock("../comparison/comparison-mixed", () => ({
  MixedComparison: () => <div data-testid="mixed-comparison" />,
}));

// ---------------------------------------------------------------------------
// Import after mocks
// ---------------------------------------------------------------------------

import { ComparisonInspector, MAX_COMPARISON_NODES } from "../comparison-inspector";

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function makeNode(
  id: string,
  nodeType: SwarmBoardNodeData["nodeType"],
): Node<SwarmBoardNodeData> {
  return {
    id,
    type: nodeType,
    position: { x: 0, y: 0 },
    data: {
      title: `${nodeType} ${id}`,
      status: "idle",
      nodeType,
    },
  };
}

const noop = () => {};

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe("ComparisonInspector routing", () => {
  it("routes 2 agentSession nodes to SessionComparison", () => {
    const nodes = [
      makeNode("a1", "agentSession"),
      makeNode("a2", "agentSession"),
    ];
    render(<ComparisonInspector nodes={nodes} onClose={noop} />);
    expect(screen.getByTestId("session-comparison")).toBeInTheDocument();
  });

  it("routes 2 receipt nodes to ReceiptComparison", () => {
    const nodes = [
      makeNode("r1", "receipt"),
      makeNode("r2", "receipt"),
    ];
    render(<ComparisonInspector nodes={nodes} onClose={noop} />);
    expect(screen.getByTestId("receipt-comparison")).toBeInTheDocument();
  });

  it("routes 2 diff nodes to DiffComparison", () => {
    const nodes = [
      makeNode("d1", "diff"),
      makeNode("d2", "diff"),
    ];
    render(<ComparisonInspector nodes={nodes} onClose={noop} />);
    expect(screen.getByTestId("diff-comparison")).toBeInTheDocument();
  });

  it("routes 2 terminalTask nodes to TaskComparison", () => {
    const nodes = [
      makeNode("t1", "terminalTask"),
      makeNode("t2", "terminalTask"),
    ];
    render(<ComparisonInspector nodes={nodes} onClose={noop} />);
    expect(screen.getByTestId("task-comparison")).toBeInTheDocument();
  });

  it("routes 2 artifact nodes to ArtifactComparison", () => {
    const nodes = [
      makeNode("ar1", "artifact"),
      makeNode("ar2", "artifact"),
    ];
    render(<ComparisonInspector nodes={nodes} onClose={noop} />);
    expect(screen.getByTestId("artifact-comparison")).toBeInTheDocument();
  });

  it("routes mixed types to MixedComparison", () => {
    const nodes = [
      makeNode("a1", "agentSession"),
      makeNode("r1", "receipt"),
    ];
    render(<ComparisonInspector nodes={nodes} onClose={noop} />);
    expect(screen.getByTestId("mixed-comparison")).toBeInTheDocument();
  });

  it("routes unknown/note type to MixedComparison (default case)", () => {
    const nodes = [
      makeNode("n1", "note"),
      makeNode("n2", "note"),
    ];
    render(<ComparisonInspector nodes={nodes} onClose={noop} />);
    expect(screen.getByTestId("mixed-comparison")).toBeInTheDocument();
  });

  it("shows overflow warning for 7+ nodes", () => {
    const nodes = Array.from({ length: 7 }, (_, i) =>
      makeNode(`n${i}`, "agentSession"),
    );
    render(<ComparisonInspector nodes={nodes} onClose={noop} />);

    // Should NOT show any comparison sub-component
    expect(screen.queryByTestId("session-comparison")).toBeNull();
    expect(screen.queryByTestId("mixed-comparison")).toBeNull();

    // Should show overflow message
    expect(screen.getByText("Too many nodes")).toBeInTheDocument();
    expect(
      screen.getByText(`Select ${MAX_COMPARISON_NODES} or fewer nodes to compare (7 selected)`),
    ).toBeInTheDocument();
  });

  it("allows exactly MAX_COMPARISON_NODES (6) without overflow", () => {
    const nodes = Array.from({ length: 6 }, (_, i) =>
      makeNode(`n${i}`, "receipt"),
    );
    render(<ComparisonInspector nodes={nodes} onClose={noop} />);
    expect(screen.getByTestId("receipt-comparison")).toBeInTheDocument();
    expect(screen.queryByText("Too many nodes")).toBeNull();
  });
});
