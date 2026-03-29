import React from "react";
import { render, screen } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import type { SwarmBoardNodeData } from "@/features/swarm/swarm-board-types";

vi.mock("@xyflow/react", () => ({
  Handle: ({ type, position }: { type: string; position: string }) => (
    <div data-testid={`handle-${type}-${position}`} />
  ),
  Position: { Left: "left", Right: "right", Top: "top", Bottom: "bottom" },
  NodeResizer: () => null,
  useStore: (selector: (s: any) => any) => selector({ transform: [0, 0, 1] }),
}));

import { ReceiptNode } from "../nodes/receipt-node";

function renderNode(data: Partial<SwarmBoardNodeData>, selected = false) {
  const fullData: SwarmBoardNodeData = {
    title: "File write check",
    status: "completed",
    nodeType: "receipt",
    verdict: "allow",
    createdAt: Date.parse("2026-03-25T15:39:00Z"),
    guardResults: [
      { guard: "ForbiddenPathGuard", allowed: true, duration_ms: 2 },
      { guard: "SecretLeakGuard", allowed: false, duration_ms: 8 },
    ],
    ...data,
  };

  return render(
    <ReceiptNode
      {...({
        id: "receipt-node",
        data: fullData,
        selected,
        type: "receipt",
        isConnectable: true,
        positionAbsoluteX: 0,
        positionAbsoluteY: 0,
        zIndex: 0,
        dragging: false,
        deletable: true,
        selectable: true,
        width: 260,
        height: 160,
      } as any)}
    />,
  );
}

describe("ReceiptNode", () => {
  beforeEach(() => {
    vi.useFakeTimers();
    vi.setSystemTime(new Date("2026-03-25T15:41:00Z"));
  });

  afterEach(() => {
    vi.useRealTimers();
  });

  it("renders the verdict label in uppercase", () => {
    renderNode({ verdict: "deny" });
    expect(screen.getByText("DENY")).toBeInTheDocument();
  });

  it("keeps the timestamp visible in relative form", () => {
    renderNode({});
    expect(screen.getByText("2m ago")).toBeInTheDocument();
  });

  it("shows guard summary counts without listing individual guards", () => {
    renderNode({});
    expect(screen.getByText("ALLOW").parentElement).toHaveTextContent("1 passed / 1 failed");
    expect(screen.getByText("2 guards")).toBeInTheDocument();
    expect(screen.queryByText("ForbiddenPathGuard")).toBeNull();
    expect(screen.queryByText("SecretLeakGuard")).toBeNull();
  });

  it("shows signature verification state without the raw signature preview", () => {
    renderNode({
      signature: "abc123",
      publicKey: "pub123",
      signatureVerified: true,
    });

    expect(screen.getByText("Verified")).toBeInTheDocument();
    expect(screen.queryByText(/sig /)).toBeNull();
  });

  it("renders source and target handles", () => {
    renderNode({});
    expect(screen.getByTestId("handle-target-top")).toBeInTheDocument();
    expect(screen.getByTestId("handle-source-bottom")).toBeInTheDocument();
  });
});
