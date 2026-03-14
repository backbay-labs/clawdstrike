import React from "react";
import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";

import type { SwarmBoardNodeData, SessionStatus, RiskLevel } from "@/lib/workbench/swarm-board-types";

// ---------------------------------------------------------------------------
// Since the node components may not exist yet (test-first approach), we
// define a minimal component that exercises the contract. When the real
// component is built, swap the import and delete this stub.
// ---------------------------------------------------------------------------

function AgentSessionNode({ data }: { data: SwarmBoardNodeData }) {
  const statusColorMap: Record<SessionStatus, string> = {
    idle: "#6f7f9a",
    running: "#3dbf84",
    blocked: "#d4a84b",
    completed: "#5b8def",
    failed: "#ef4444",
  };

  const riskColorMap: Record<RiskLevel, string> = {
    low: "#3dbf84",
    medium: "#d4a84b",
    high: "#ef4444",
  };

  return (
    <div data-testid="agent-session-node">
      <h3 data-testid="node-title">{data.title}</h3>
      {data.branch && <span data-testid="node-branch">{data.branch}</span>}
      <span data-testid="node-status">{data.status}</span>
      <span
        data-testid="status-dot"
        style={{ backgroundColor: statusColorMap[data.status] }}
      />
      {data.previewLines && data.previewLines.length > 0 && (
        <div data-testid="preview-lines">
          {data.previewLines.map((line, i) => (
            <div key={i} data-testid="preview-line">
              {line}
            </div>
          ))}
        </div>
      )}
      {data.receiptCount !== undefined && data.receiptCount > 0 && (
        <span data-testid="receipt-count-badge">{data.receiptCount}</span>
      )}
      {data.risk && (
        <span
          data-testid="risk-indicator"
          style={{ color: riskColorMap[data.risk] }}
        >
          {data.risk}
        </span>
      )}
    </div>
  );
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe("AgentSessionNode", () => {
  const defaultData: SwarmBoardNodeData = {
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
  };

  it("renders with correct title", () => {
    render(<AgentSessionNode data={defaultData} />);
    expect(screen.getByTestId("node-title").textContent).toBe("Fix auth middleware");
  });

  it("renders with correct branch", () => {
    render(<AgentSessionNode data={defaultData} />);
    expect(screen.getByTestId("node-branch").textContent).toBe("feat/fix-auth");
  });

  it("renders with correct status", () => {
    render(<AgentSessionNode data={defaultData} />);
    expect(screen.getByTestId("node-status").textContent).toBe("running");
  });

  it("shows preview lines", () => {
    render(<AgentSessionNode data={defaultData} />);
    const lines = screen.getAllByTestId("preview-line");
    expect(lines).toHaveLength(3);
    expect(lines[0].textContent).toBe("$ cargo test -p auth");
    expect(lines[2].textContent).toBe("test validate_token ... ok");
  });

  it("shows receipt count badge", () => {
    render(<AgentSessionNode data={defaultData} />);
    expect(screen.getByTestId("receipt-count-badge").textContent).toBe("7");
  });

  it("hides receipt badge when count is zero", () => {
    render(
      <AgentSessionNode data={{ ...defaultData, receiptCount: 0 }} />,
    );
    expect(screen.queryByTestId("receipt-count-badge")).toBeNull();
  });

  it("hides receipt badge when count is undefined", () => {
    render(
      <AgentSessionNode data={{ ...defaultData, receiptCount: undefined }} />,
    );
    expect(screen.queryByTestId("receipt-count-badge")).toBeNull();
  });

  it("shows risk indicator with correct text", () => {
    render(<AgentSessionNode data={defaultData} />);
    expect(screen.getByTestId("risk-indicator").textContent).toBe("medium");
  });

  it("hides risk indicator when risk is undefined", () => {
    render(
      <AgentSessionNode data={{ ...defaultData, risk: undefined }} />,
    );
    expect(screen.queryByTestId("risk-indicator")).toBeNull();
  });

  describe("status dot colors", () => {
    const statusColors: [SessionStatus, string][] = [
      ["idle", "rgb(111, 127, 154)"],
      ["running", "rgb(61, 191, 132)"],
      ["blocked", "rgb(212, 168, 75)"],
      ["completed", "rgb(91, 141, 239)"],
      ["failed", "rgb(239, 68, 68)"],
    ];

    it.each(statusColors)(
      "status '%s' has correct dot color %s",
      (status, expectedColor) => {
        render(
          <AgentSessionNode data={{ ...defaultData, status }} />,
        );
        const dot = screen.getByTestId("status-dot");
        expect(dot.style.backgroundColor).toBe(expectedColor);
      },
    );
  });

  describe("risk indicator colors", () => {
    const riskColors: [RiskLevel, string][] = [
      ["low", "rgb(61, 191, 132)"],
      ["medium", "rgb(212, 168, 75)"],
      ["high", "rgb(239, 68, 68)"],
    ];

    it.each(riskColors)(
      "risk '%s' has correct indicator color %s",
      (risk, expectedColor) => {
        render(
          <AgentSessionNode data={{ ...defaultData, risk }} />,
        );
        const indicator = screen.getByTestId("risk-indicator");
        expect(indicator.style.color).toBe(expectedColor);
      },
    );
  });

  it("handles empty preview lines", () => {
    render(
      <AgentSessionNode data={{ ...defaultData, previewLines: [] }} />,
    );
    expect(screen.queryByTestId("preview-lines")).toBeNull();
  });

  it("handles undefined preview lines", () => {
    render(
      <AgentSessionNode data={{ ...defaultData, previewLines: undefined }} />,
    );
    expect(screen.queryByTestId("preview-lines")).toBeNull();
  });

  it("does not render branch when undefined", () => {
    render(
      <AgentSessionNode data={{ ...defaultData, branch: undefined }} />,
    );
    expect(screen.queryByTestId("node-branch")).toBeNull();
  });
});
